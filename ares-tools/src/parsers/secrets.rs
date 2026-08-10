//! Secretsdump, Kerberoast, and AS-REP roast output parsers.

use serde_json::{json, Value};

/// Strip the `SMB <IP> <PORT> <HOST>` framing that `nxc smb` prepends to every
/// line of pass-through output. If the line doesn't have the framing, return it
/// untouched. Needed because `forge_inter_realm_and_dump` shells out to
/// `nxc smb --ntds` instead of `impacket-secretsdump` (the latter's DRSUAPI
/// bind rejects cross-realm Kerberos credentials), so the secretsdump parser
/// has to handle nxc-framed lines too.
fn strip_nxc_framing(line: &str) -> &str {
    let trimmed = line.trim_start();
    if !trimmed.starts_with("SMB ") && !trimmed.starts_with("SMB\t") {
        return line;
    }
    // Walk through the first 4 whitespace-delimited tokens (SMB, IP, PORT, HOST)
    // and return everything after the 4th token's trailing whitespace.
    let mut rest = trimmed;
    for _ in 0..4 {
        rest = rest.trim_start();
        match rest.find(char::is_whitespace) {
            Some(end) => rest = &rest[end..],
            None => return line,
        }
    }
    rest.trim_start()
}

/// Section context tracked while scanning secretsdump output. The dump emits
/// `[*] Dumping local SAM hashes ...` for the local SAM section, then
/// `[*] Dumping Domain Credentials ...` (or NTDS markers) for AD accounts.
/// Lines without an explicit `DOMAIN\` prefix in the local SAM section are
/// machine-local accounts and must NOT be attributed to the AD `target_domain`
/// — doing so creates phantom AD records (e.g. an `Administrator` hash from
/// each DC's local SAM tagged with that DC's AD domain, which then collides
/// across domains in lab environments where local creds are seeded uniformly).
#[derive(Clone, Copy, PartialEq, Eq)]
enum DumpSection {
    Unknown,
    LocalSam,
    Domain,
}

/// True for a 32-character all-hex string (an LM or NT hash). Used to tell a
/// numeric RID apart from a hash when deciding whether a secretsdump row is the
/// RID-less `$MACHINE.ACC` shape.
fn is_hash32(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub const DCC2_HASH_TYPE: &str = "dcc2";

pub const DPAPI_SYSTEM_HASH_TYPE: &str = "dpapi_system";

const MAX_DCC2_PER_DUMP: usize = 12;

pub fn is_dcc2_hash_value(s: &str) -> bool {
    let Some(body) = s.strip_prefix("$DCC2$") else {
        return false;
    };
    let mut parts = body.split('#');
    let (Some(iterations), Some(salt), Some(digest), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    !iterations.is_empty()
        && iterations.bytes().all(|b| b.is_ascii_digit())
        && !salt.is_empty()
        && is_hash32(digest)
}

fn split_principal(raw: &str) -> (String, String) {
    let raw = raw.trim();
    if let Some((prefix, user)) = raw.rsplit_once(['\\', '/']) {
        return (prefix.trim().to_string(), user.trim().to_string());
    }
    if let Some((user, realm)) = raw.rsplit_once('@') {
        return (realm.trim().to_string(), user.trim().to_string());
    }
    (String::new(), raw.to_string())
}

fn is_builtin_service_principal(domain: &str, username: &str) -> bool {
    let d = domain.trim().to_ascii_lowercase();
    let u = username.trim().to_ascii_lowercase();
    if matches!(d.as_str(), "nt authority" | "nt service" | "builtin") {
        return true;
    }
    matches!(
        u.as_str(),
        "localsystem"
            | "system"
            | "localservice"
            | "local service"
            | "networkservice"
            | "network service"
            | "(unknown user)"
    )
}

fn trim_secret_value(s: &str) -> &str {
    s.trim_end_matches(['\0', '\r', '\n'])
}

fn parse_cached_domain_logons(output: &str, target_domain: &str) -> Vec<Value> {
    let mut hashes = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for raw_line in output.lines() {
        if hashes.len() >= MAX_DCC2_PER_DUMP {
            break;
        }
        let line = strip_nxc_framing(raw_line).trim();
        let Some(idx) = line.find(":$DCC2$") else {
            continue;
        };
        let hash_value = line[idx + 1..].split(':').next().unwrap_or("").trim();
        if !is_dcc2_hash_value(hash_value) {
            continue;
        }
        let (raw_domain, username) = split_principal(&line[..idx]);
        if username.is_empty() || username.ends_with('$') {
            continue;
        }
        let user_domain = if raw_domain.is_empty() {
            target_domain.to_string()
        } else {
            let resolved = resolve_netbios_to_fqdn(&raw_domain, target_domain);
            if resolved.contains('.') {
                resolved.to_lowercase()
            } else {
                resolved
            }
        };
        let key = format!(
            "{}\\{}\\{}",
            user_domain.to_lowercase(),
            username.to_lowercase(),
            hash_value.to_lowercase()
        );
        if !seen.insert(key) {
            continue;
        }
        hashes.push(json!({
            "username": username,
            "domain": user_domain,
            "hash_value": hash_value,
            "hash_type": DCC2_HASH_TYPE,
            "source": "secretsdump",
        }));
    }

    hashes
}

fn parse_lsa_secrets(output: &str, target_domain: &str) -> (Vec<Value>, Vec<Value>) {
    let mut hashes = Vec::new();
    let mut creds = Vec::new();
    let mut in_lsa = false;
    let mut current: String = String::new();
    let mut machine_key: Option<String> = None;
    let mut user_key: Option<String> = None;

    for raw_line in output.lines() {
        let line = strip_nxc_framing(raw_line).trim();
        if line.starts_with('[') {
            let lower = line.to_ascii_lowercase();
            if lower.contains("dumping lsa secrets") {
                in_lsa = true;
                current.clear();
            } else if lower.contains("dumping local sam")
                || lower.contains("dumping sam")
                || lower.contains("dumping cached domain")
                || lower.contains("dumping domain credentials")
                || lower.contains("ntds")
                || lower.contains("searching for peklist")
                || lower.contains("reading and decrypting hashes from")
                || lower.contains("cleaning up")
            {
                in_lsa = false;
                current.clear();
            } else if in_lsa {
                current = line
                    .trim_start_matches(['[', '*', '+', '-', ']'])
                    .trim()
                    .to_string();
            }
            continue;
        }
        if !in_lsa || line.is_empty() {
            continue;
        }

        let upper = current.to_ascii_uppercase();
        if upper.ends_with("_HISTORY") {
            continue;
        }

        if upper.starts_with("DPAPI_SYSTEM") {
            if let Some(hex) = line
                .strip_prefix("dpapi_machinekey:")
                .and_then(|v| v.trim().strip_prefix("0x"))
            {
                machine_key = Some(hex.trim().to_string());
            } else if let Some(hex) = line
                .strip_prefix("dpapi_userkey:")
                .and_then(|v| v.trim().strip_prefix("0x"))
            {
                user_key = Some(hex.trim().to_string());
            }
            continue;
        }

        if !upper.starts_with("_SC_") && !upper.starts_with("DEFAULTPASSWORD") {
            continue;
        }
        let Some((account, password)) = line.split_once(':') else {
            continue;
        };
        let password = trim_secret_value(password);
        if password.is_empty() {
            continue;
        }
        let (raw_domain, username) = split_principal(account);
        if username.is_empty() || is_builtin_service_principal(&raw_domain, &username) {
            continue;
        }
        let user_domain = if raw_domain.is_empty() || raw_domain == "." {
            String::new()
        } else {
            resolve_netbios_to_fqdn(&raw_domain, target_domain)
        };
        creds.push(json!({
            "username": username,
            "password": password,
            "domain": user_domain,
            "source": "lsa_secrets",
        }));
    }

    if let (Some(machine), Some(user)) = (machine_key, user_key) {
        hashes.push(json!({
            "username": "DPAPI_SYSTEM",
            "domain": "",
            "hash_value": format!("{machine}:{user}"),
            "hash_type": DPAPI_SYSTEM_HASH_TYPE,
            "source": "dpapi",
        }));
    }

    (hashes, creds)
}

pub fn parse_secretsdump(output: &str, params: &Value) -> (Vec<Value>, Vec<Value>) {
    // Prefer target_domain (the domain being dumped) over domain (auth credential's domain)
    // to correctly attribute hashes when authenticating cross-domain.
    let domain = params
        .get("target_domain")
        .or_else(|| params.get("domain"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let mut hashes = Vec::new();
    let mut creds = Vec::new();
    let mut section = DumpSection::Unknown;

    // First pass: collect AES256 trust/account keys keyed by lowercase username.
    // Win2016+ DCs reject RC4-only inter-realm tickets (KDC_ERR_TGT_REVOKED), so
    // we attach the AES256 key to the matching NTLM hash entry below.
    // Format: "DOMAIN\\user:aes256-cts-hmac-sha1-96:<hex>" or
    //         "contoso.local/user:aes256-cts-hmac-sha1-96:<hex>"
    let mut aes_keys: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for raw_line in output.lines() {
        let line = strip_nxc_framing(raw_line).trim();
        if line.is_empty() || line.starts_with('[') {
            continue;
        }
        if let Some(rest) = line.split_once(":aes256-cts-hmac-sha1-96:") {
            let raw_user = rest.0;
            let aes_hex = rest.1.trim();
            if aes_hex.is_empty() || !aes_hex.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            let username = raw_user
                .rsplit_once(['\\', '/'])
                .map(|(_, u)| u)
                .unwrap_or(raw_user)
                .to_string();
            aes_keys.insert(username.to_lowercase(), aes_hex.to_lowercase());
        }
    }

    let mut prefix_counts: std::collections::HashMap<String, u32> =
        std::collections::HashMap::new();
    let mut scan_section = DumpSection::Unknown;
    for raw_line in output.lines() {
        let line = strip_nxc_framing(raw_line).trim();
        if line.starts_with('[') {
            let lower = line.to_ascii_lowercase();
            if lower.contains("dumping local sam") || lower.contains("dumping sam") {
                scan_section = DumpSection::LocalSam;
            } else if lower.contains("dumping domain credentials")
                || lower.contains("dumping cached domain")
                || lower.contains("ntds")
                || lower.contains("searching for peklist")
                || lower.contains("reading and decrypting hashes from")
            {
                scan_section = DumpSection::Domain;
            }
            continue;
        }
        if scan_section == DumpSection::LocalSam || line.starts_with('#') || !line.contains(":::") {
            continue;
        }
        let raw_user = line.split(':').next().unwrap_or("");
        let Some(idx) = raw_user.find(['\\', '/']) else {
            continue;
        };
        let prefix = &raw_user[..idx];
        if prefix.is_empty() {
            continue;
        }
        *prefix_counts
            .entry(resolve_netbios_to_fqdn(prefix, domain))
            .or_insert(0) += 1;
    }
    let mut ranked: Vec<(String, u32)> = prefix_counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let unprefixed_domain = ranked.first().map_or(domain, |(d, _)| d.as_str());

    for raw_line in output.lines() {
        let line = strip_nxc_framing(raw_line).trim();

        // Section markers — secretsdump and nxc emit these informational lines
        // before each block. Recognize them so we can tell SAM rows from NTDS
        // rows when the row itself has no `DOMAIN\` prefix. Match liberally:
        // impacket says "Dumping local SAM", nxc says "Dumping SAM hashes",
        // both should land us in LocalSam.
        if line.starts_with('[') {
            let lower = line.to_ascii_lowercase();
            if lower.contains("dumping local sam") || lower.contains("dumping sam") {
                section = DumpSection::LocalSam;
            } else if lower.contains("dumping domain credentials")
                || lower.contains("dumping cached domain")
                || lower.contains("ntds")
                || lower.contains("searching for peklist")
                || lower.contains("reading and decrypting hashes from")
            {
                section = DumpSection::Domain;
            }
            continue;
        }

        // NTLM hash format: "username:RID:LMhash:NThash:::"
        // or "DOMAIN\username:RID:LMhash:NThash:::"
        if line.contains(":::") && !line.starts_with('#') {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 4 {
                let raw_user = parts[0];
                let rid = parts.get(1).copied().unwrap_or("");
                // Standard NTDS/SAM rows are `user:RID:LM:NT:::` with a numeric
                // RID. The LSA `$MACHINE.ACC` secret for the dumped host is
                // RID-less — `DOMAIN\HOST$:LM:NT:::` — so LM/NT sit one field to
                // the left and the old `parts[3]` NT slot is empty, silently
                // dropping the host's own machine account (the key that unlocks
                // gMSA reads / RBCD on member servers). Detect the RID-less shape
                // (field 1 is a 32-hex hash, not a numeric RID) and read LM/NT
                // from the shifted positions.
                let rid_is_numeric = !rid.is_empty() && rid.bytes().all(|b| b.is_ascii_digit());
                let ridless_machine_acct =
                    !rid_is_numeric && is_hash32(parts[1]) && is_hash32(parts[2]);
                let (lm_hash, nt_hash) = if ridless_machine_acct {
                    (parts[1], parts[2])
                } else {
                    (parts[2], parts[3])
                };
                let (user_domain, username) = if section == DumpSection::LocalSam {
                    // In the local SAM section, any `\` prefix is the host's
                    // own computer name (or workgroup), never an AD realm.
                    // Strip it and leave the domain empty — otherwise a
                    // standalone host whose computer name happens to share its
                    // first label with `target_domain` (e.g. WIN-XXXX with a
                    // self-named WIN-XXXX.WGRP.LOCAL workgroup) gets attributed
                    // to that workgroup as if it were an AD domain.
                    let user = raw_user.split_once('\\').map_or(raw_user, |(_, u)| u);
                    (String::new(), user.to_string())
                } else if let Some(idx) = raw_user.find(['\\', '/']) {
                    let prefix = &raw_user[..idx];
                    let user = &raw_user[idx + 1..];
                    // Resolve NetBIOS prefix to FQDN using target_domain.
                    // Impacket emits FQDN/user (slash) when invoked with a
                    // domain target; standard secretsdump on Windows output
                    // is DOMAIN\user (backslash + NetBIOS).
                    let resolved = resolve_netbios_to_fqdn(prefix, domain);
                    (resolved, user.to_string())
                } else if is_local_sam_account(raw_user, rid, section) {
                    // Local SAM account dumped without a domain prefix —
                    // leave domain empty so it doesn't masquerade as AD.
                    (String::new(), raw_user.to_string())
                } else {
                    (unprefixed_domain.to_string(), raw_user.to_string())
                };

                if is_hash32(nt_hash) && nt_hash != "31d6cfe0d16ae931b73c59d7e0c089c0" {
                    // Skip empty/disabled hashes
                    let hash_value = format!("{}:{}", lm_hash, nt_hash);

                    // NTDS exposes rotated-out credentials as
                    // `<name>_history0`, `<name>_history1`, ... and some
                    // dumps use `<name>_prev`. Strip the suffix and stamp
                    // `is_previous=true` so the trust-key forge path can
                    // prefer the current key.
                    let (username_clean, is_previous) = strip_history_suffix(&username);

                    // Trust-key detection: a row whose username ends in `$`
                    // and whose stripped label differs from the realm's
                    // first NetBIOS label is the *trust partner's* machine
                    // account — the inter-realm forging key, not the
                    // dumping machine's own computer-account. e.g. dumping
                    // contoso.local and seeing `FABRIKAM$` means FABRIKAM
                    // is on the other side of a trust we can forge across.
                    // A RID-less `$MACHINE.ACC` row is always the dumped host's
                    // OWN computer account (from LSA secrets), never a trust
                    // partner — skip the label-mismatch heuristic that would
                    // otherwise flag it as inter-realm forging material.
                    let (is_trust_key, trust_pair_label) = if ridless_machine_acct {
                        (false, None)
                    } else {
                        classify_trust_key(&username_clean, &user_domain)
                    };

                    let mut entry = json!({
                        "username": username_clean,
                        "domain": user_domain,
                        "hash_value": hash_value,
                        "hash_type": "ntlm",
                        "source": "secretsdump",
                    });
                    if is_previous {
                        entry["is_previous"] = json!(true);
                    }
                    if is_trust_key {
                        entry["is_trust_key"] = json!(true);
                        if let Some(label) = trust_pair_label {
                            entry["trust_pair_label"] = json!(label);
                        }
                    }
                    if let Some(aes) = aes_keys.get(&username_clean.to_lowercase()) {
                        entry["aes_key"] = json!(aes);
                    }
                    hashes.push(entry);
                }
            }
        }
    }

    hashes.extend(parse_cached_domain_logons(output, domain));
    let (lsa_hashes, lsa_creds) = parse_lsa_secrets(output, domain);
    hashes.extend(lsa_hashes);
    creds.extend(lsa_creds);

    (hashes, creds)
}

/// Decide whether an unprefixed dump row is a local SAM account.
///
/// Three signals, in order: (1) the dump section we're currently parsing,
/// (2) the well-known RID/name pairs that are always machine-local
/// (Administrator/500, Guest/501, DefaultAccount/503, WDAGUtilityAccount/504,
/// plus secretsdump's LSA pseudo-rows like `$MACHINE.ACC` and `_SC_*`), and
/// (3) the safe default for `Unknown` section: treat as local SAM unless the
/// user is `krbtgt` (always AD). NTDS dumps reliably emit pekList/NTDS markers
/// before the rows, so an unmarked dump is almost certainly a SAM dump from
/// `secretsdump @host` or `nxc smb --sam`. Defaulting unmarked custom RIDs to
/// `target_domain` (the prior behavior) silently mis-attributes local-only
/// users like `ansible`/`devops`/etc. to the operator's AD scope.
fn is_local_sam_account(raw_user: &str, rid: &str, section: DumpSection) -> bool {
    if section == DumpSection::LocalSam {
        return true;
    }
    let name = raw_user.to_ascii_lowercase();
    // LSA pseudo-rows from `[*] Dumping LSA Secrets` are always machine-local,
    // even if a prior NTDS marker left us in `DumpSection::Domain`.
    if raw_user.starts_with('$') || raw_user.starts_with("_SC_") || raw_user.starts_with("NL$") {
        return true;
    }
    // In an explicit NTDS/domain section, unprefixed rows are AD accounts.
    // This is the load-bearing distinction for `Administrator:500` from
    // `-just-dc-ntlm` / `nxc smb --ntds` output: treating RID 500 as "always
    // local SAM" drops the realm and breaks child->parent trust escalation,
    // which requires a same-domain Administrator hash.
    if section == DumpSection::Domain {
        return false;
    }
    // RID-based: 500/501/503/504 are well-known built-ins. Don't include 502
    // (krbtgt) — it's a domain account that happens to share a fixed RID.
    if matches!(rid, "500" | "501" | "503" | "504")
        && matches!(
            name.as_str(),
            "administrator" | "guest" | "defaultaccount" | "wdagutilityaccount"
        )
    {
        return true;
    }
    // Safe default for unmarked dumps: treat as local SAM. krbtgt and machine
    // accounts (`ENDS_WITH$`) are never local — let those fall through to the
    // target_domain branch.
    if section == DumpSection::Unknown && name != "krbtgt" && !raw_user.ends_with('$') {
        return true;
    }
    false
}

/// Resolve a NetBIOS domain name to FQDN using the target domain as reference.
///
/// When secretsdump outputs `CONTOSO\username`, the domain prefix is the NetBIOS
/// Detect NTDS rotated-out credential rows. NTDS emits `<name>_history0`,
/// `<name>_history1`, ... and some impacket builds use `<name>_prev`. Returns
/// the stripped name and a boolean indicating whether the suffix was present.
///
/// `_history0` is the most recent rotated-out copy; higher indices are older.
/// For our purposes we collapse them all to "previous" — the forge path only
/// needs to know "not current".
fn strip_history_suffix(username: &str) -> (String, bool) {
    if let Some(base) = username.strip_suffix("_prev") {
        return (base.to_string(), true);
    }
    if let Some(idx) = username.rfind("_history") {
        // Suffix from idx must be `_history` followed by all digits.
        let tail = &username[idx + "_history".len()..];
        if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) {
            return (username[..idx].to_string(), true);
        }
    }
    (username.to_string(), false)
}

/// Classify a hash row as a trust-key (forging material) when the username
/// is a machine account (`<LABEL>$`) AND the label doesn't match the realm's
/// first NetBIOS-style label. Returns `(is_trust_key, Some(label))` for trust
/// keys; `(false, None)` for own-machine accounts or non-machine users.
///
/// Example: dumping `contoso.local` and finding `FABRIKAM$` — FABRIKAM ≠ CONTOSO
/// so this is the forging key for an outbound trust to fabrikam. Conversely,
/// dumping `contoso.local` and finding `DC01$` — DC01 IS part of contoso so
/// this is a member-server machine account, not trust material.
///
/// When `user_domain` is empty (local SAM rows), we can't make this judgment
/// — those should never end in `$` anyway, but if they do, treat as
/// non-trust to avoid false positives.
fn classify_trust_key(username: &str, user_domain: &str) -> (bool, Option<String>) {
    if !username.ends_with('$') || user_domain.is_empty() {
        return (false, None);
    }
    let label = username.trim_end_matches('$');
    if label.is_empty() {
        return (false, None);
    }
    let realm_first_label = user_domain.split('.').next().unwrap_or("");
    if label.eq_ignore_ascii_case(realm_first_label) {
        // The dumping realm's own computer account — not forging material.
        return (false, None);
    }
    // Heuristic guard: short single-word usernames (DC01, WS01, etc.) are
    // member-server accounts, not trust accounts. Trust accounts typically
    // match a known domain label; we can't enumerate trusted domains from
    // the parser, so we approximate by length + character composition.
    // A safer cross-check happens at the renderer (which has access to
    // state.trusted_domains and dominated_domains).
    (true, Some(label.to_string()))
}

/// name. If we know the target FQDN is `contoso.local`, we can resolve it by
/// matching the first label. Returns the original name if no match is found.
fn resolve_netbios_to_fqdn(netbios: &str, target_domain: &str) -> String {
    if target_domain.is_empty() || netbios.is_empty() {
        return netbios.to_string();
    }

    // If the NetBIOS name already looks like an FQDN, keep it
    if netbios.contains('.') {
        return netbios.to_string();
    }

    // Match NetBIOS against the first label of the target FQDN.
    // e.g. "CONTOSO" matches "contoso.local", "CHILD" matches "child.contoso.local"
    let first_label = target_domain.split('.').next().unwrap_or("");
    if netbios.eq_ignore_ascii_case(first_label) {
        return target_domain.to_string();
    }

    // No match — keep the raw NetBIOS name (recovery normalization will resolve it later)
    netbios.to_string()
}

pub fn parse_local_auth_reuse(output: &str, params: &Value) -> (Vec<Value>, Vec<Value>) {
    let arg = |key: &str| {
        params
            .get(key)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
    };
    let username = arg("username");
    let hash = arg("hash");
    let target = arg("target");
    if username.is_empty() || hash.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let mut accepted = false;
    let mut admin = false;
    for raw_line in output.lines() {
        let line = strip_ansi(raw_line);
        let line = line.trim();
        if !line.contains("[+]") || line.contains("STATUS_") {
            continue;
        }
        accepted = true;
        if line.contains("(Pwn3d!)") {
            admin = true;
        }
    }
    if !accepted {
        return (Vec::new(), Vec::new());
    }

    let mut entry = json!({
        "username": username,
        "domain": "",
        "hash_value": hash,
        "hash_type": "ntlm",
        "source": "smb_local_auth",
    });
    if !target.is_empty() {
        entry["source_host"] = json!(target);
    }

    let mut hosts = Vec::new();
    if admin && !target.is_empty() && target.parse::<std::net::IpAddr>().is_ok() {
        hosts.push(json!({
            "ip": target,
            "hostname": "",
            "os": "",
            "roles": [],
            "services": ["445/tcp (microsoft-ds)"],
            "is_dc": false,
            "owned": true,
        }));
    }

    (vec![entry], hosts)
}

pub fn parse_kerberoast(output: &str, params: &Value) -> Vec<Value> {
    let domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");

    let mut hashes = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        // "$krb5tgs$23$*username$DOMAIN$..." format
        if line.starts_with("$krb5tgs$") {
            // Extract username from the hash
            let parts: Vec<&str> = line.split('$').collect();
            let username = if parts.len() > 3 {
                parts[3].trim_start_matches('*').to_string()
            } else {
                "unknown".to_string()
            };

            hashes.push(json!({
                "username": username,
                "domain": domain,
                "hash_value": line,
                "hash_type": "kerberoast",
                "source": "kerberoast",
            }));
        }
    }

    hashes
}

/// Extract MSSQL host records from kerberoast (`GetUserSPNs`) output.
///
/// An `MSSQLSvc/<fqdn>` SPN is definitive proof the named host runs SQL
/// Server on 1433 — independent of whether a port scan ever reached it.
/// Hosts discovered only via kerberoasting or share-spidering otherwise
/// never get `1433` into `host.services`, so `auto_mssql_detection` never
/// emits `mssql_access` and the entire MSSQL automation tree stays dark.
///
/// We scan the raw output for `MSSQLSvc/` tokens — this covers both the
/// `ServicePrincipalName` column of the `GetUserSPNs` table AND the SPN
/// embedded inside each `$krb5tgs$...$MSSQLSvc/<host>*$...` hash, so a roast
/// that captured a ticket always yields the host even when the table header
/// is absent. Each emitted host carries an empty `ip` and the SPN's FQDN as
/// `hostname`; `publish_host` merges it by hostname into the existing
/// IP-bearing record (or seeds a hostname-only record the later scan fills
/// in), folding `1433` into its service list.
pub fn extract_mssql_hosts_from_kerberoast(output: &str) -> Vec<Value> {
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut hosts = Vec::new();

    for token in output.split(|c: char| c.is_whitespace() || c == '*' || c == '$') {
        // Case-insensitive prefix match — impacket prints `MSSQLSvc` but the
        // embedded-hash form preserves whatever case the SPN used.
        let Some(spn_host) = token
            .get(..8)
            .filter(|p| p.eq_ignore_ascii_case("MSSQLSvc"))
            .and_then(|_| token.get(8..))
            .and_then(|rest| rest.strip_prefix('/'))
        else {
            continue;
        };
        // Strip the port-or-instance suffix. The table form uses `:1433` /
        // `:INSTANCE`; the SPN embedded in the krb5tgs hash blob uses impacket's
        // `~` separator (`MSSQLSvc/host~1433`). A real FQDN contains neither.
        let fqdn = spn_host
            .split([':', '~'])
            .next()
            .unwrap_or(spn_host)
            .to_lowercase();
        // Require a dotted FQDN so a malformed/short token can't seed a
        // junk hostname that would never match a real host record.
        if !fqdn.contains('.') || fqdn.is_empty() {
            continue;
        }
        if !seen.insert(fqdn.clone()) {
            continue;
        }
        hosts.push(json!({
            "ip": "",
            "hostname": fqdn,
            "os": "",
            "roles": ["mssql"],
            "services": ["1433/tcp (ms-sql-s)"],
            "is_dc": false,
            "owned": false,
        }));
    }

    hosts
}

pub fn parse_asrep_roast(output: &str, params: &Value) -> Vec<Value> {
    let domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");

    let mut hashes = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("$krb5asrep$") {
            let parts: Vec<&str> = line.split('$').collect();
            let username = if parts.len() > 3 {
                parts[3]
                    .trim_start_matches('*')
                    .split('@')
                    .next()
                    .unwrap_or("unknown")
                    .to_string()
            } else {
                "unknown".to_string()
            };

            hashes.push(json!({
                "username": username,
                "domain": domain,
                "hash_value": line,
                "hash_type": "asrep",
                "source": "asrep_roast",
            }));
        }
    }

    hashes
}

/// Extract NetNTLMv2 hashes from coercion / Responder / relay tool output.
///
/// The canonical hashcat-5600 format is `USER::DOMAIN:CHALLENGE:NT_PROOF:BLOB`,
/// which `split(':')` decomposes into exactly 6 parts (the empty string between
/// the `::` after the username is one of them). Responder, ntlmrelayx, and
/// impacket-smbserver all print the hash in this layout; Responder additionally
/// wraps it with a `[SMB] NTLMv2-SSP Hash : ` / `[HTTP] NTLMv2 Hash : ` prefix
/// and may colorize the line with ANSI SGR codes.
///
/// Without this parser, a `coercer` / `petitpotam` / `start_responder` tool
/// call against a vulnerable DC produces output that the LLM sees as text
/// (and may even quote in its summary), but the captured machine-account hash
/// never lands in the orchestrator's `Hash` state — so `auto_crack_dispatch`
/// never enqueues it, hashcat / the ouroboros backend never get a shot, and a
/// primary path to DC compromise stays closed.
///
/// `source_tag` lets the caller mark the discovery (e.g. `"start_responder"`,
/// `"petitpotam"`, `"coercer"`) so blue/red post-op queries can correlate the
/// hash with the capture surface.
pub fn parse_netntlmv2(output: &str, params: &Value, source_tag: &str) -> Vec<Value> {
    let target_domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");

    let mut hashes = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for raw_line in output.lines() {
        // Strip ANSI (Responder colorizes [SMB]/[HTTP] tags) and trim.
        let line = strip_ansi(raw_line).trim().to_string();
        if line.is_empty() {
            continue;
        }

        // Strip Responder's wrappers:
        //   [SMB]  NTLMv2-SSP Hash     : USER::DOMAIN:...
        //   [HTTP] NTLMv2 Hash         : USER::DOMAIN:...
        //   [MSSQL] NTLMv2 Client Hash : USER::DOMAIN:...
        // Locate the `Hash` token (case-insensitive), then advance past the
        // first single `:` (the label terminator) to the hash payload.
        let lc = line.to_ascii_lowercase();
        let payload: &str = if let Some(idx) = lc.find("ntlmv2") {
            // The substring starts at "ntlmv2-ssp hash" or "ntlmv2 hash" etc.
            // Find the first colon AFTER the word "hash". split_once(':') may
            // catch the `[SMB]` bracket's `:` (none) or the label colon. To
            // be robust, find the first colon at-or-after the word `hash`.
            let after = &line[idx..];
            // Locate `hash` (case-insensitive); fall back to position 0.
            let after_lc = lc[idx..].to_string();
            let hash_off = after_lc.find("hash").map(|p| p + 4).unwrap_or(0);
            let tail = &after[hash_off..];
            // Skip leading spaces / colons until we hit the username's first char.
            let tail = tail.trim_start_matches(|c: char| c.is_whitespace() || c == ':');
            tail
        } else {
            line.as_str()
        };

        if let Some(hash_value) = extract_netntlmv2_value(payload) {
            // Dedup: Responder prints the same hash multiple times (e.g. once
            // per protocol when the client tried both SMB and HTTP). Same
            // physical capture, same crack work — emit it once.
            if !seen.insert(hash_value.clone()) {
                continue;
            }

            let parts: Vec<&str> = hash_value.split(':').collect();
            let username = parts[0].to_string();
            let captured_domain = parts.get(2).copied().unwrap_or("").to_string();

            // Domain attribution: prefer the realm Responder logged inside the
            // hash itself; fall back to the operation `domain` param. The
            // Responder-captured domain may be a NetBIOS name (e.g. `CONTOSO`),
            // which downstream cracking + state normalization tolerate.
            let domain = if !captured_domain.is_empty() {
                captured_domain
            } else {
                target_domain.to_string()
            };

            hashes.push(json!({
                "username": username,
                "domain": domain,
                "hash_value": hash_value,
                "hash_type": "netntlmv2",
                "source": source_tag,
            }));
        }
    }

    hashes
}

/// Verify a candidate hash string matches the NetNTLMv2 hashcat-5600 layout
/// and return the full string if it does.
///
/// Layout:  `USER::DOMAIN:CHALLENGE:NT_PROOF:BLOB`
/// split(':') yields 6 parts; the empty between `::` is parts[1].
/// CHALLENGE = 16 hex (8-byte server challenge)
/// NT_PROOF  = 32 hex (16-byte NTProofStr)
/// BLOB      = >= 16 hex (variable, ends with AV_PAIR list)
fn extract_netntlmv2_value(s: &str) -> Option<String> {
    let s = s.trim_end_matches(|c: char| c.is_whitespace() || c == '\r' || c == '\0');
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let user = parts[0];
    if user.is_empty() {
        return None;
    }
    // parts[1] MUST be the empty between `::`.
    if !parts[1].is_empty() {
        return None;
    }
    let challenge = parts[3];
    let nt_proof = parts[4];
    let blob = parts[5];
    if challenge.len() != 16 || !challenge.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    if nt_proof.len() != 32 || !nt_proof.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    if blob.len() < 16 || !blob.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(s.to_string())
}

/// Strip ANSI CSI escapes Responder embeds around protocol tags / hash lines.
/// Not a general decoder — just enough to keep the layout intact: walk past
/// `\x1b[ ... <letter>` runs and drop them.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && matches!(chars.peek(), Some('[')) {
            chars.next();
            for inner in chars.by_ref() {
                if inner.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_secretsdump_ntlm_hashes() {
        // Local SAM section: rows must NOT inherit `target_domain` — these
        // are machine-local accounts, not AD. Tagging them with the AD domain
        // creates phantom AD records that collide cross-domain in seeded labs.
        let output = "\
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
svc_sql:1001:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::
[*] Cleaning up...";
        let params = json!({"domain": "contoso.local"});
        let (hashes, creds) = parse_secretsdump(output, &params);

        // Guest hash (31d6cf...) should be skipped (empty/disabled)
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0]["username"], "Administrator");
        assert_eq!(hashes[0]["domain"], "");
        assert_eq!(hashes[0]["hash_type"], "ntlm");
        assert!(hashes[0]["hash_value"]
            .as_str()
            .unwrap()
            .contains("e19ccf75"));
        assert_eq!(hashes[1]["username"], "svc_sql");
        assert_eq!(hashes[1]["domain"], "");
        assert!(creds.is_empty());
    }

    #[test]
    fn parse_secretsdump_ridless_machine_acct_captures_nt_hash() {
        // The LSA `$MACHINE.ACC` secret for a dumped member server is RID-less
        // — `DOMAIN\HOST$:LM:NT:::` — so the NT hash sits one field earlier than
        // in NTDS/SAM rows. Before the fix `parts[3]` was empty and the row was
        // silently dropped; the machine account (which unlocks gMSA reads / RBCD
        // on member servers) must be captured, attributed to the dumped domain,
        // and NOT flagged as inter-realm trust material — it's the host's own.
        let output = "\
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
CONTOSO\\WEB01$:aes256-cts-hmac-sha1-96:1111111111111111111111111111111111111111111111111111111111111111
CONTOSO\\WEB01$:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::
[*] Cleaning up...";
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 1, "machine account row must be captured");
        assert_eq!(hashes[0]["username"], "WEB01$");
        assert_eq!(hashes[0]["domain"], "contoso.local");
        assert_eq!(
            hashes[0]["hash_value"],
            "aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890"
        );
        // Own machine account — never trust-forge material.
        assert!(hashes[0].get("is_trust_key").is_none());
        // The preceding AES256 line still attaches.
        assert_eq!(
            hashes[0]["aes_key"],
            "1111111111111111111111111111111111111111111111111111111111111111"
        );
    }

    #[test]
    fn parse_secretsdump_standard_rid_rows_unaffected_by_ridless_path() {
        // Regression guard: numeric-RID rows must still read LM/NT from
        // parts[2]/parts[3] exactly as before the RID-less machine-acct fix.
        let output = "\
[*] Dumping the NTDS
[*] Reading and decrypting hashes from /tmp/ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::";
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "Administrator");
        assert_eq!(
            hashes[0]["hash_value"],
            "aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890"
        );
    }

    #[test]
    fn parse_secretsdump_ntds_section_uses_target_domain() {
        // NTDS section: unprefixed rows (e.g. from `-just-dc-ntlm` output)
        // are AD accounts and SHOULD inherit target_domain. Distinguished
        // from the local SAM case by the section marker emitted earlier.
        let output = "\
[*] Dumping the NTDS, this could take a while
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: abcdef
[*] Reading and decrypting hashes from /tmp/ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:22222222222222222222222222222222:::
alice:1103:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::
WIN-XYZ$:1001:aad3b435b51404eeaad3b435b51404ee:1234567890abcdef1234567890abcdef:::
[*] Kerberos keys grabbed";
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 3);
        assert_eq!(hashes[0]["username"], "Administrator");
        assert_eq!(hashes[0]["domain"], "contoso.local");
        assert_eq!(hashes[1]["username"], "alice");
        assert_eq!(hashes[1]["domain"], "contoso.local");
        assert_eq!(hashes[2]["username"], "WIN-XYZ$");
        assert_eq!(hashes[2]["domain"], "contoso.local");
    }

    #[test]
    fn parse_secretsdump_unknown_section_defaults_to_local_sam() {
        // No section marker before the rows — safe default is local SAM
        // attribution (empty domain). NTDS dumps reliably emit pekList/NTDS
        // markers; an unmarked dump is almost always a SAM dump from
        // `secretsdump @host` or `nxc smb --sam`. Custom RIDs like 1001 must
        // not silently inherit `target_domain` — that's how Ansible-provisioned
        // local users (e.g. on standalone hosts) leak into AD scope.
        let output = "\
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::
ansible:1001:aad3b435b51404eeaad3b435b51404ee:1234567890abcdef1234567890abcdef:::";
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 3);
        for h in &hashes {
            assert_eq!(
                h["domain"], "",
                "{} should not inherit target_domain",
                h["username"]
            );
        }
    }

    #[test]
    fn parse_secretsdump_nxc_style_sam_marker() {
        // nxc/netexec emits `[*] Dumping SAM hashes` (no "local") before rows.
        // The parser must recognize this variant and still treat the section
        // as LocalSam — otherwise unmarked custom users fall through to
        // target_domain attribution.
        let output = "\
[*] Dumping SAM hashes
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
ansible:1001:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::";
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0]["username"], "Administrator");
        assert_eq!(hashes[0]["domain"], "");
        assert_eq!(hashes[1]["username"], "ansible");
        assert_eq!(hashes[1]["domain"], "");
    }

    #[test]
    fn parse_secretsdump_local_sam_strips_computer_name_prefix() {
        // Standalone host with self-named workgroup dumps rows like
        // `WIN-ABCDEFGHIJK\ansible:1001:...`. The prefix is the host's own
        // computer name, NOT an AD NetBIOS realm — even when the operator's
        // `target_domain` happens to be `win-abcdefghijk.wgrp.local` (which
        // would otherwise pass the first-label match in
        // `resolve_netbios_to_fqdn`). In LocalSam section, the prefix is
        // always stripped and the domain is left empty.
        let output = "\
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
WIN-ABCDEFGHIJK\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
WIN-ABCDEFGHIJK\\ansible:1001:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::";
        let params = json!({"target_domain": "win-abcdefghijk.wgrp.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 2);
        for h in &hashes {
            assert_eq!(h["domain"], "");
        }
        assert_eq!(hashes[0]["username"], "Administrator");
        assert_eq!(hashes[1]["username"], "ansible");
    }

    #[test]
    fn parse_secretsdump_machine_account_unmarked_keeps_target_domain() {
        // Machine accounts (ending in `$`) are AD-only, never local SAM.
        // Even with no section marker, they must inherit target_domain so a
        // partial NTDS dump doesn't lose its computer-account hashes.
        let output =
            "WIN-XYZ$:1001:aad3b435b51404eeaad3b435b51404ee:1234567890abcdef1234567890abcdef:::";
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "WIN-XYZ$");
        assert_eq!(hashes[0]["domain"], "contoso.local");
    }

    #[test]
    fn parse_secretsdump_lsa_pseudo_rows_unattributed() {
        // LSA secrets emit `$MACHINE.ACC`, `NL$KM`, `_SC_*` rows — none of
        // these are AD principals; they must not inherit target_domain.
        let output = "\
[*] Dumping LSA Secrets
$MACHINE.ACC:plain_password:aad3b435b51404eeaad3b435b51404ee:1111111111111111aaaaaaaaaaaaaaaa:::
[*] DPAPI_SYSTEM
NL$KM:0:aad3b435b51404eeaad3b435b51404ee:2222222222222222bbbbbbbbbbbbbbbb:::";
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 2);
        for h in &hashes {
            assert_eq!(h["domain"], "");
        }
    }

    #[test]
    fn parse_secretsdump_krbtgt_keeps_target_domain() {
        // krbtgt has the well-known RID 502 but is ALWAYS an AD account, never
        // local SAM. Don't strip target_domain from unprefixed krbtgt rows.
        let output = "\
[*] Dumping the NTDS, this could take a while
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:8c6d94541dbc90f085e86828428d2cbf:::";
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "krbtgt");
        assert_eq!(hashes[0]["domain"], "contoso.local");
    }

    #[test]
    fn parse_secretsdump_unprefixed_rows_follow_dump_evidence_over_task_domain() {
        let output = "\
[*] Dumping the NTDS, this could take a while
[*] Reading and decrypting hashes from /tmp/ntds.dit
CHILD\\alice:1103:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::
CHILD\\bob:1104:aad3b435b51404eeaad3b435b51404ee:1234567890abcdef1234567890abcdef:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:8c6d94541dbc90f085e86828428d2cbf:::";
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 3);
        let krbtgt = hashes
            .iter()
            .find(|h| h["username"] == "krbtgt")
            .expect("krbtgt row present");
        assert_eq!(krbtgt["domain"], "CHILD");
        assert_ne!(krbtgt["domain"], "contoso.local");
    }

    #[test]
    fn parse_secretsdump_local_sam_prefix_does_not_retarget_ntds_rows() {
        let output = "\
[*] Dumping local SAM hashes
WS01\\admin:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
[*] Dumping the NTDS, this could take a while
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:8c6d94541dbc90f085e86828428d2cbf:::";
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        let krbtgt = hashes
            .iter()
            .find(|h| h["username"] == "krbtgt")
            .expect("krbtgt row present");
        assert_eq!(krbtgt["domain"], "contoso.local");
    }

    #[test]
    fn parse_secretsdump_domain_prefix() {
        let output = "CONTOSO\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::";
        let params = json!({"domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "Administrator");
        // NetBIOS "CONTOSO" resolved to FQDN "contoso.local" via target_domain
        assert_eq!(hashes[0]["domain"], "contoso.local");
    }

    #[test]
    fn parse_secretsdump_netbios_resolved_to_fqdn() {
        // NetBIOS prefix should be resolved to FQDN via target_domain
        let output = "\
FABRIKAM\\alice:1103:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::
FABRIKAM\\bob:1104:aad3b435b51404eeaad3b435b51404ee:1234567890abcdef1234567890abcdef:::";
        let params = json!({"target_domain": "fabrikam.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0]["username"], "alice");
        assert_eq!(hashes[0]["domain"], "fabrikam.local");
        assert_eq!(hashes[1]["username"], "bob");
        assert_eq!(hashes[1]["domain"], "fabrikam.local");
    }

    #[test]
    fn parse_secretsdump_target_domain_preferred() {
        // target_domain should take precedence over domain for attribution
        let output = "FABRIKAM\\svc_sql:1105:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::";
        let params = json!({"domain": "contoso.local", "target_domain": "fabrikam.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["domain"], "fabrikam.local");
    }

    #[test]
    fn parse_secretsdump_mismatched_netbios_kept() {
        // If NetBIOS doesn't match target_domain's first label, keep it raw
        let output = "CHILD\\jsmith:1001:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::";
        let params = json!({"target_domain": "fabrikam.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "jsmith");
        // "CHILD" doesn't match "fabrikam" so it stays as-is
        assert_eq!(hashes[0]["domain"], "CHILD");
    }

    #[test]
    fn resolves_netbios_to_fqdn() {
        assert_eq!(
            resolve_netbios_to_fqdn("FABRIKAM", "fabrikam.local"),
            "fabrikam.local"
        );
        assert_eq!(
            resolve_netbios_to_fqdn("CHILD", "child.contoso.local"),
            "child.contoso.local"
        );
        assert_eq!(resolve_netbios_to_fqdn("CHILD", "fabrikam.local"), "CHILD"); // no match
        assert_eq!(
            resolve_netbios_to_fqdn("fabrikam.local", "fabrikam.local"),
            "fabrikam.local"
        ); // already FQDN
        assert_eq!(resolve_netbios_to_fqdn("", "fabrikam.local"), "");
        assert_eq!(resolve_netbios_to_fqdn("FABRIKAM", ""), "FABRIKAM");
    }

    #[test]
    fn strip_history_suffix_recognizes_history_indices() {
        assert_eq!(
            strip_history_suffix("CONTOSO$_history0"),
            ("CONTOSO$".to_string(), true)
        );
        assert_eq!(
            strip_history_suffix("alice_history3"),
            ("alice".to_string(), true)
        );
    }

    #[test]
    fn strip_history_suffix_recognizes_prev_suffix() {
        assert_eq!(
            strip_history_suffix("FABRIKAM$_prev"),
            ("FABRIKAM$".to_string(), true)
        );
    }

    #[test]
    fn strip_history_suffix_leaves_non_history_alone() {
        assert_eq!(strip_history_suffix("alice"), ("alice".to_string(), false));
        assert_eq!(
            strip_history_suffix("alice_smith"),
            ("alice_smith".to_string(), false)
        );
        // `_history` without digits is not a history marker.
        assert_eq!(
            strip_history_suffix("svc_history"),
            ("svc_history".to_string(), false)
        );
    }

    #[test]
    fn classify_trust_key_flags_foreign_machine_account() {
        // FABRIKAM$ dumped from contoso.local: the dumping realm's first
        // label is `contoso`, not `fabrikam`, so this IS a trust key.
        let (is_trust, label) = classify_trust_key("FABRIKAM$", "contoso.local");
        assert!(is_trust);
        assert_eq!(label.as_deref(), Some("FABRIKAM"));
    }

    #[test]
    fn classify_trust_key_skips_own_realm_machine_account() {
        // CONTOSO$ dumped from contoso.local: this is the dumping realm's
        // OWN computer account, not trust material.
        let (is_trust, label) = classify_trust_key("CONTOSO$", "contoso.local");
        assert!(!is_trust);
        assert!(label.is_none());
    }

    #[test]
    fn classify_trust_key_skips_non_machine_accounts() {
        // Non-`$` usernames are users, never trust keys.
        let (is_trust, _) = classify_trust_key("alice", "contoso.local");
        assert!(!is_trust);
        let (is_trust, _) = classify_trust_key("krbtgt", "contoso.local");
        assert!(!is_trust);
    }

    #[test]
    fn classify_trust_key_requires_non_empty_realm() {
        // Local SAM rows (empty user_domain) can't be classified as trust
        // material — the parser leaves them alone.
        let (is_trust, label) = classify_trust_key("FABRIKAM$", "");
        assert!(!is_trust);
        assert!(label.is_none());
    }

    #[test]
    fn parse_secretsdump_marks_trust_account_row() {
        // Dumping contoso.local NTDS and seeing FABRIKAM$ — FABRIKAM is the
        // outbound trust partner, the parser must stamp `is_trust_key` and
        // surface the NetBIOS label in `trust_pair_label`.
        let output = "\
[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)
contoso.local/FABRIKAM$:1107:aad3b435b51404eeaad3b435b51404ee:33333333333333333333333333333333:::
contoso.local/CONTOSO$:1108:aad3b435b51404eeaad3b435b51404ee:44444444444444444444444444444444:::";
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 2);
        // FABRIKAM$ is the foreign trust account.
        assert_eq!(hashes[0]["username"], "FABRIKAM$");
        assert_eq!(hashes[0]["is_trust_key"], true);
        assert_eq!(hashes[0]["trust_pair_label"], "FABRIKAM");
        // CONTOSO$ is the home machine account — NOT a trust key.
        assert_eq!(hashes[1]["username"], "CONTOSO$");
        assert!(hashes[1].get("is_trust_key").is_none());
    }

    #[test]
    fn parse_secretsdump_marks_history_rows_as_previous() {
        let output = "\
[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)
CONTOSO\\FABRIKAM$:1107:aad3b435b51404eeaad3b435b51404ee:33333333333333333333333333333333:::
CONTOSO\\FABRIKAM$_history0:1107:aad3b435b51404eeaad3b435b51404ee:44444444444444444444444444444444:::";
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0]["username"], "FABRIKAM$");
        assert!(hashes[0].get("is_previous").is_none());
        assert_eq!(hashes[1]["username"], "FABRIKAM$");
        assert_eq!(hashes[1]["is_previous"], true);
    }

    #[test]
    fn parse_secretsdump_slash_separator() {
        // Impacket emits FQDN/user (slash) for domain-scoped dumps; parser
        // must accept both slash and backslash NetBIOS forms.
        let output = "\
contoso.local/krbtgt:502:aad3b435b51404eeaad3b435b51404ee:11111111111111111111111111111111:::
contoso.local/Administrator:500:aad3b435b51404eeaad3b435b51404ee:22222222222222222222222222222222:::";
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0]["username"], "krbtgt");
        assert_eq!(hashes[0]["domain"], "contoso.local");
        assert_eq!(hashes[1]["username"], "Administrator");
    }

    #[test]
    fn parse_secretsdump_attaches_aes256_key_to_trust_account() {
        let output = "\
[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)
FABRIKAM\\CONTOSO$:1107:aad3b435b51404eeaad3b435b51404ee:33333333333333333333333333333333:::
[*] Kerberos keys grabbed
FABRIKAM\\CONTOSO$:aes256-cts-hmac-sha1-96:4444444444444444444444444444444444444444444444444444444444444444
FABRIKAM\\CONTOSO$:aes128-cts-hmac-sha1-96:55555555555555555555555555555555
[*] Cleaning up...";
        let params = json!({"target_domain": "fabrikam.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "CONTOSO$");
        assert_eq!(hashes[0]["domain"], "fabrikam.local");
        assert_eq!(
            hashes[0]["aes_key"],
            "4444444444444444444444444444444444444444444444444444444444444444"
        );
    }

    #[test]
    fn parse_secretsdump_skips_comments_and_brackets() {
        let output = "\
[*] Service RemoteRegistry is in stopped state
# This is a comment
[*] SAM hashes extracted";
        let params = json!({"domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert!(hashes.is_empty());
    }

    #[test]
    fn parse_secretsdump_empty_output() {
        let (hashes, creds) = parse_secretsdump("", &json!({}));
        assert!(hashes.is_empty());
        assert!(creds.is_empty());
    }

    fn member_server_dump() -> &'static str {
        "\
[*] Service RemoteRegistry is in stopped state
[*] Target system bootKey: 0x1122334455667788990011223344556677
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
contoso.local/alice:$DCC2$10240#alice#e2829c8af2232fa53797e2f0e35e4626: (2026-07-30 21:12:03.123456+00:00)
contoso.local/admin:$DCC2$10240#admin#a1b2c3d4e5f60718293a4b5c6d7e8f90: (2026-07-29 08:00:00.000000+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
CONTOSO\\WEB01$:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::
CONTOSO\\WEB01$:aes256-cts-hmac-sha1-96:1111111111111111111111111111111111111111111111111111111111111111
CONTOSO\\WEB01$:plain_password_hex:00112233445566778899aabbccddeeff
[*] DPAPI_SYSTEM
dpapi_machinekey:0x1111111111111111111111111111111111111111
dpapi_userkey:0x2222222222222222222222222222222222222222
[*] NL$KM
 0000   AA BB CC DD EE FF 00 11  22 33 44 55 66 77 88 99   ................
[*] _SC_MSSQLSERVER
CONTOSO\\svc_sql:P@ssw0rd!
[*] _SC_BackupSvc
.\\svc_backup:P@ssw0rd!
[*] _SC_Spooler
NT AUTHORITY\\LocalSystem:(Unknown)
[*] DefaultPassword
CONTOSO\\bob:P@ssw0rd!
[*] Cleaning up...
"
    }

    #[test]
    fn parse_secretsdump_captures_cached_domain_logons_as_dcc2() {
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(member_server_dump(), &params);
        let dcc2: Vec<_> = hashes
            .iter()
            .filter(|h| h["hash_type"] == DCC2_HASH_TYPE)
            .collect();
        assert_eq!(dcc2.len(), 2, "both cached logons must be captured");
        assert_eq!(dcc2[0]["username"], "alice");
        assert_eq!(dcc2[0]["domain"], "contoso.local");
        assert_eq!(
            dcc2[0]["hash_value"],
            "$DCC2$10240#alice#e2829c8af2232fa53797e2f0e35e4626"
        );
        assert_eq!(dcc2[1]["username"], "admin");
        assert_eq!(
            dcc2[1]["hash_value"],
            "$DCC2$10240#admin#a1b2c3d4e5f60718293a4b5c6d7e8f90"
        );
    }

    #[test]
    fn parse_secretsdump_dcc2_rows_never_labelled_ntlm() {
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(member_server_dump(), &params);
        for h in &hashes {
            let value = h["hash_value"].as_str().unwrap();
            if value.starts_with("$DCC2$") {
                assert_eq!(h["hash_type"], DCC2_HASH_TYPE);
            } else {
                assert_ne!(h["hash_type"], DCC2_HASH_TYPE);
            }
        }
    }

    #[test]
    fn parse_secretsdump_captures_lsa_service_account_plaintext() {
        let params = json!({"target_domain": "contoso.local"});
        let (_, creds) = parse_secretsdump(member_server_dump(), &params);
        assert_eq!(creds.len(), 3, "two _SC_ secrets plus DefaultPassword");
        assert_eq!(creds[0]["username"], "svc_sql");
        assert_eq!(creds[0]["domain"], "contoso.local");
        assert_eq!(creds[0]["password"], "P@ssw0rd!");
        assert_eq!(creds[0]["source"], "lsa_secrets");
        assert_eq!(creds[1]["username"], "svc_backup");
        assert_eq!(
            creds[1]["domain"], "",
            "`.\\user` is machine-local, never the AD realm"
        );
        assert_eq!(creds[2]["username"], "bob");
        assert_eq!(creds[2]["domain"], "contoso.local");
    }

    #[test]
    fn parse_secretsdump_skips_builtin_service_principals() {
        let params = json!({"target_domain": "contoso.local"});
        let (_, creds) = parse_secretsdump(member_server_dump(), &params);
        assert!(
            !creds.iter().any(|c| c["username"]
                .as_str()
                .unwrap()
                .eq_ignore_ascii_case("LocalSystem")),
            "NT AUTHORITY\\LocalSystem has no stored password"
        );
    }

    #[test]
    fn parse_secretsdump_captures_dpapi_system_key_pair() {
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(member_server_dump(), &params);
        let dpapi: Vec<_> = hashes
            .iter()
            .filter(|h| h["hash_type"] == DPAPI_SYSTEM_HASH_TYPE)
            .collect();
        assert_eq!(dpapi.len(), 1);
        assert_eq!(dpapi[0]["username"], "DPAPI_SYSTEM");
        assert_eq!(dpapi[0]["domain"], "");
        assert_eq!(
            dpapi[0]["hash_value"],
            "1111111111111111111111111111111111111111:2222222222222222222222222222222222222222"
        );
    }

    #[test]
    fn parse_secretsdump_machine_account_stays_ntlm_and_local_sam_unattributed() {
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(member_server_dump(), &params);
        let machine = hashes
            .iter()
            .find(|h| h["username"] == "WEB01$")
            .expect("$MACHINE.ACC row captured");
        assert_eq!(machine["hash_type"], "ntlm");
        assert_eq!(machine["domain"], "contoso.local");
        assert_eq!(
            machine["aes_key"],
            "1111111111111111111111111111111111111111111111111111111111111111"
        );
        let sam_admin = hashes
            .iter()
            .find(|h| h["username"] == "Administrator")
            .expect("local SAM row captured");
        assert_eq!(sam_admin["domain"], "");
    }

    #[test]
    fn is_dcc2_hash_value_accepts_hashcat_example_layout() {
        assert!(is_dcc2_hash_value(
            "$DCC2$10240#6848#e2829c8af2232fa53797e2f0e35e4626"
        ));
    }

    #[test]
    fn is_dcc2_hash_value_rejects_malformed_and_foreign_shapes() {
        for bad in [
            "$DCC2$10240#alice#e2829c8af2232fa53797e2f0e35e46",
            "$DCC2$#alice#e2829c8af2232fa53797e2f0e35e4626",
            "$DCC2$abcd#alice#e2829c8af2232fa53797e2f0e35e4626",
            "$DCC2$10240##e2829c8af2232fa53797e2f0e35e4626",
            "$DCC2$10240#alice#e2829c8af2232fa53797e2f0e35e4626#extra",
            "aad3b435b51404eeaad3b435b51404ee",
            "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$abcd",
            "",
        ] {
            assert!(!is_dcc2_hash_value(bad), "must reject {bad:?}");
        }
    }

    #[test]
    fn parse_secretsdump_rejects_malformed_dcc2_rows() {
        let output = "\
[*] Dumping cached domain logon information (domain/username:hash)
contoso.local/alice:$DCC2$10240#alice#nothexnothexnothexnothexnothex12: (2026-07-30 21:12:03+00:00)
contoso.local/WS01$:$DCC2$10240#WS01$#e2829c8af2232fa53797e2f0e35e4626: (2026-07-30 21:12:03+00:00)";
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert!(
            hashes.is_empty(),
            "non-hex digest and machine accounts must both be dropped"
        );
    }

    #[test]
    fn parse_secretsdump_caps_dcc2_capture_per_dump() {
        let mut output =
            String::from("[*] Dumping cached domain logon information (domain/username:hash)\n");
        for i in 0..(MAX_DCC2_PER_DUMP + 8) {
            output.push_str(&format!(
                "contoso.local/user{i}:$DCC2$10240#user{i}#{:032x}: (2026-07-30 21:12:03+00:00)\n",
                i + 1
            ));
        }
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(&output, &params);
        assert_eq!(hashes.len(), MAX_DCC2_PER_DUMP);
    }

    #[test]
    fn parse_secretsdump_dcc2_survives_nxc_framing() {
        let output = "\
SMB         192.168.58.30   445    WEB01            [*] Dumping cached domain logon information (domain/username:hash)
SMB         192.168.58.30   445    WEB01            contoso.local/alice:$DCC2$10240#alice#e2829c8af2232fa53797e2f0e35e4626: (2026-07-30 21:12:03+00:00)";
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "alice");
        assert_eq!(hashes[0]["hash_type"], DCC2_HASH_TYPE);
    }

    #[test]
    fn parse_secretsdump_dcc2_keeps_foreign_realm_of_cached_user() {
        let output = "\
[*] Dumping cached domain logon information (domain/username:hash)
FABRIKAM.LOCAL/admin:$DCC2$10240#admin#e2829c8af2232fa53797e2f0e35e4626: (2026-07-30 21:12:03+00:00)";
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 1);
        assert_eq!(
            hashes[0]["domain"], "fabrikam.local",
            "cached logons carry the logging-on user's realm, not the dumped host's"
        );
    }

    #[test]
    fn parse_secretsdump_lsa_section_ends_at_next_banner() {
        let output = "\
[*] Dumping LSA Secrets
[*] _SC_MSSQLSERVER
CONTOSO\\svc_sql:P@ssw0rd!
[*] Dumping the NTDS, this could take a while
[*] Reading and decrypting hashes from /tmp/ntds.dit
CONTOSO\\carol:1104:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::";
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, creds) = parse_secretsdump(output, &params);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "svc_sql");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "carol");
        assert_eq!(hashes[0]["hash_type"], "ntlm");
    }

    #[test]
    fn parse_secretsdump_ignores_lsa_history_secrets() {
        let output = "\
[*] Dumping LSA Secrets
[*] _SC_MSSQLSERVER_history
CONTOSO\\svc_sql:OldP@ssw0rd!";
        let params = json!({"target_domain": "contoso.local"});
        let (_, creds) = parse_secretsdump(output, &params);
        assert!(creds.is_empty());
    }

    #[test]
    fn parse_secretsdump_lsa_password_may_contain_colons() {
        let output = "\
[*] Dumping LSA Secrets
[*] _SC_MSSQLSERVER
CONTOSO\\svc_sql:P@ss:w0rd!";
        let params = json!({"target_domain": "contoso.local"});
        let (_, creds) = parse_secretsdump(output, &params);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["password"], "P@ss:w0rd!");
    }

    #[test]
    fn parse_local_auth_reuse_records_validated_local_hash() {
        let output = "\
SMB         192.168.58.31   445    WS01             [*] Windows 10 / Server 2019 Build 17763 x64
SMB         192.168.58.31   445    WS01             [+] WS01\\admin:abcdef1234567890abcdef1234567890 (Pwn3d!)";
        let params = json!({
            "target": "192.168.58.31",
            "username": "admin",
            "hash": "abcdef1234567890abcdef1234567890",
        });
        let (hashes, hosts) = parse_local_auth_reuse(output, &params);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "admin");
        assert_eq!(
            hashes[0]["domain"], "",
            "local SAM reuse must never claim a realm"
        );
        assert_eq!(hashes[0]["hash_type"], "ntlm");
        assert_eq!(hashes[0]["source"], "smb_local_auth");
        assert_eq!(hashes[0]["source_host"], "192.168.58.31");
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0]["ip"], "192.168.58.31");
        assert_eq!(hosts[0]["owned"], true);
    }

    #[test]
    fn parse_local_auth_reuse_without_pwn3d_records_no_host_takeover() {
        let output =
            "SMB  192.168.58.31  445  WS01  [+] WS01\\admin:abcdef1234567890abcdef1234567890";
        let params = json!({
            "target": "192.168.58.31",
            "username": "admin",
            "hash": "abcdef1234567890abcdef1234567890",
        });
        let (hashes, hosts) = parse_local_auth_reuse(output, &params);
        assert_eq!(hashes.len(), 1);
        assert!(hosts.is_empty());
    }

    #[test]
    fn parse_local_auth_reuse_rejects_failed_login() {
        let output = "\
SMB         192.168.58.31   445    WS01             [-] WS01\\admin:abcdef1234567890abcdef1234567890 STATUS_LOGON_FAILURE";
        let params = json!({
            "target": "192.168.58.31",
            "username": "admin",
            "hash": "abcdef1234567890abcdef1234567890",
        });
        let (hashes, hosts) = parse_local_auth_reuse(output, &params);
        assert!(hashes.is_empty());
        assert!(hosts.is_empty());
    }

    #[test]
    fn parse_kerberoast_hashes() {
        let output = "\
[*] Getting TGS for SPN accounts
$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$contoso.local/svc_sql*$abc123def456
$krb5tgs$23$*svc_http$CONTOSO.LOCAL$contoso.local/svc_http*$789xyz
[*] Done";
        let params = json!({"domain": "contoso.local"});
        let hashes = parse_kerberoast(output, &params);
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0]["username"], "svc_sql");
        assert_eq!(hashes[0]["hash_type"], "kerberoast");
        assert_eq!(hashes[0]["domain"], "contoso.local");
        assert!(hashes[0]["hash_value"]
            .as_str()
            .unwrap()
            .starts_with("$krb5tgs$"));
        assert_eq!(hashes[1]["username"], "svc_http");
    }

    #[test]
    fn parse_kerberoast_no_hashes() {
        let hashes = parse_kerberoast("[*] No SPN accounts found", &json!({}));
        assert!(hashes.is_empty());
    }

    #[test]
    fn mssql_hosts_from_getuserspns_table() {
        // The ServicePrincipalName column of the GetUserSPNs table carries the
        // MSSQLSvc SPN with a `:1433` port suffix — strip it and emit the host.
        let output = "\
ServicePrincipalName                    Name     MemberOf  PasswordLastSet
--------------------------------------  -------  --------  ------------------
MSSQLSvc/sql01.contoso.local:1433       svc_sql            2024-01-02 03:04:05
HTTP/web01.contoso.local                svc_web            2024-01-02 03:04:05";
        let hosts = extract_mssql_hosts_from_kerberoast(output);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0]["hostname"], "sql01.contoso.local");
        assert_eq!(hosts[0]["ip"], "");
        let services: Vec<&str> = hosts[0]["services"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(services.iter().any(|s| s.contains("1433")));
        assert!(hosts[0]["roles"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .any(|x| x == "mssql"));
    }

    #[test]
    fn mssql_hosts_from_embedded_hash_spn() {
        // The SPN is also embedded in the krb5tgs hash blob — a roast that
        // captured a ticket yields the host even without the table header.
        let output =
            "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$MSSQLSvc/sql01.contoso.local~1433*$aabb$ccdd";
        let hosts = extract_mssql_hosts_from_kerberoast(output);
        assert_eq!(hosts.len(), 1);
        // `~1433` is impacket's port separator in the embedded-hash SPN form;
        // it must be stripped so the FQDN matches the real host record.
        assert_eq!(hosts[0]["hostname"], "sql01.contoso.local");
    }

    #[test]
    fn mssql_hosts_dedup_and_case_insensitive() {
        let output = "\
MSSQLSvc/sql01.fabrikam.local:1433 svc_sql
mssqlsvc/SQL01.FABRIKAM.LOCAL svc_sql2";
        let hosts = extract_mssql_hosts_from_kerberoast(output);
        assert_eq!(hosts.len(), 1, "same host in different case must dedupe");
        assert_eq!(hosts[0]["hostname"], "sql01.fabrikam.local");
    }

    #[test]
    fn mssql_hosts_skips_non_mssql_and_short_names() {
        let output = "\
HTTP/web01.contoso.local svc_web
CIFS/dc01.contoso.local svc_cifs
MSSQLSvc/localhost svc_sql";
        // No MSSQLSvc SPN with a dotted FQDN → nothing emitted.
        let hosts = extract_mssql_hosts_from_kerberoast(output);
        assert!(hosts.is_empty());
    }

    #[test]
    fn mssql_hosts_empty_output() {
        assert!(extract_mssql_hosts_from_kerberoast("").is_empty());
        assert!(extract_mssql_hosts_from_kerberoast("[*] No SPN accounts found").is_empty());
    }

    #[test]
    fn parses_asrep_roast() {
        let output = "\
$krb5asrep$23$jdoe@CONTOSO.LOCAL:abc123def456
$krb5asrep$23$svc_backup@CONTOSO.LOCAL:789xyz";
        let params = json!({"domain": "contoso.local"});
        let hashes = parse_asrep_roast(output, &params);
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0]["username"], "jdoe");
        assert_eq!(hashes[0]["hash_type"], "asrep");
        assert_eq!(hashes[0]["source"], "asrep_roast");
        assert_eq!(hashes[1]["username"], "svc_backup");
    }

    #[test]
    fn parse_asrep_roast_empty() {
        let hashes = parse_asrep_roast("[-] No AS-REP roastable accounts", &json!({}));
        assert!(hashes.is_empty());
    }

    #[test]
    fn strip_nxc_framing_removes_smb_prefix() {
        let line = "SMB         192.168.58.10   445    DC01             contoso.local/krbtgt:502:aad3b435b51404eeaad3b435b51404ee:11111111111111111111111111111111:::";
        assert_eq!(
            strip_nxc_framing(line),
            "contoso.local/krbtgt:502:aad3b435b51404eeaad3b435b51404ee:11111111111111111111111111111111:::"
        );
    }

    #[test]
    fn strip_nxc_framing_passes_through_unframed() {
        let line = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:99999999999999999999999999999999:::";
        assert_eq!(strip_nxc_framing(line), line);
    }

    #[test]
    fn strip_nxc_framing_handles_status_lines() {
        let line = "SMB         192.168.58.10   445    DC01             [+] Dumped 111 NTDS hashes";
        assert_eq!(strip_nxc_framing(line), "[+] Dumped 111 NTDS hashes");
    }

    #[test]
    fn strip_nxc_framing_short_line_kept() {
        // Less than 4 tokens — return original.
        let line = "SMB only-three tokens";
        assert_eq!(strip_nxc_framing(line), line);
    }

    #[test]
    fn parse_secretsdump_strips_nxc_framing() {
        // nxc smb --ntds vss output: every line gets "SMB <IP> <PORT> <HOST>" prefix.
        let output = "\
SMB         192.168.58.10   445    DC01             [*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)
SMB         192.168.58.10   445    DC01             contoso.local/krbtgt:502:aad3b435b51404eeaad3b435b51404ee:11111111111111111111111111111111:::
SMB         192.168.58.10   445    DC01             contoso.local/Administrator:500:aad3b435b51404eeaad3b435b51404ee:22222222222222222222222222222222:::
SMB         192.168.58.10   445    DC01             [+] Dumped 2 NTDS hashes";
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0]["username"], "krbtgt");
        assert_eq!(hashes[0]["domain"], "contoso.local");
        assert!(hashes[0]["hash_value"]
            .as_str()
            .unwrap()
            .contains("11111111111111111111111111111111"));
        assert_eq!(hashes[1]["username"], "Administrator");
    }

    #[test]
    fn parse_secretsdump_strips_nxc_framing_with_aes_keys() {
        // nxc-framed output should still let AES-key collection work.
        let output = "\
SMB         192.168.58.20   445    DC02             FABRIKAM\\CONTOSO$:1107:aad3b435b51404eeaad3b435b51404ee:33333333333333333333333333333333:::
SMB         192.168.58.20   445    DC02             FABRIKAM\\CONTOSO$:aes256-cts-hmac-sha1-96:4444444444444444444444444444444444444444444444444444444444444444";
        let params = json!({"target_domain": "fabrikam.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "CONTOSO$");
        assert_eq!(
            hashes[0]["aes_key"],
            "4444444444444444444444444444444444444444444444444444444444444444"
        );
    }

    #[test]
    fn parse_netntlmv2_responder_smb() {
        // Canonical Responder SMB capture: a CONTOSO dc01$ machine-account
        // round-tripped through coercion. CHALLENGE=16 hex, NT_PROOF=32 hex,
        // BLOB long-form. The leading `[SMB]` prefix and `NTLMv2-SSP Hash`
        // label must be stripped without consuming the `::` inside the hash.
        let output = "\
[+] Listening for events...
[SMB] NTLMv2-SSP Client   : 192.168.58.20
[SMB] NTLMv2-SSP Username : CONTOSO\\dc01$
[SMB] NTLMv2-SSP Hash     : dc01$::CONTOSO:1122334455667788:9c8e64ac5db4e4a72b1cd2e1cd2e1cd2:0101000000000000c0653150de09d201aabbccddeeff00112233";
        let params = json!({"domain": "contoso.local"});
        let hashes = parse_netntlmv2(output, &params, "start_responder");
        assert_eq!(hashes.len(), 1, "expected exactly one captured hash");
        assert_eq!(hashes[0]["username"], "dc01$");
        assert_eq!(hashes[0]["domain"], "CONTOSO");
        assert_eq!(hashes[0]["hash_type"], "netntlmv2");
        assert_eq!(hashes[0]["source"], "start_responder");
        let hv = hashes[0]["hash_value"].as_str().unwrap();
        assert!(hv.starts_with("dc01$::CONTOSO:"));
        assert!(hv.ends_with("aabbccddeeff00112233"));
    }

    #[test]
    fn parse_netntlmv2_http_label() {
        // Responder HTTP capture (e.g. WebDAV coerce -> /printers/) uses a
        // slightly different label. The parser must not require the dash form.
        let output = "[HTTP] NTLMv2 Hash : alice::CONTOSO:aaaaaaaaaaaaaaaa:11111111111111111111111111111111:0202020202020202";
        let params = json!({"domain": "contoso.local"});
        let hashes = parse_netntlmv2(output, &params, "petitpotam");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "alice");
        assert_eq!(hashes[0]["domain"], "CONTOSO");
        assert_eq!(hashes[0]["source"], "petitpotam");
    }

    #[test]
    fn parse_netntlmv2_raw_line_no_label() {
        // Some Responder builds dump the bare hash line into the log (and
        // tools like impacket-smbserver emit it raw). The parser should
        // accept a bare 6-field line without the [SMB]/[HTTP] wrapper.
        let output =
            "svc_sql::CONTOSO:1122334455667788:aabbccddeeff00112233445566778899:9988776655443322";
        let params = json!({});
        let hashes = parse_netntlmv2(output, &params, "coercer");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "svc_sql");
        assert_eq!(hashes[0]["domain"], "CONTOSO");
        // No `domain` param → falls back to captured realm.
        assert_eq!(hashes[0]["source"], "coercer");
    }

    #[test]
    fn parse_netntlmv2_dedup_repeated_captures() {
        // Responder commonly prints the same hash twice when the client
        // negotiates both SMB and HTTP. Same physical credential, single
        // crack-worth — emit once.
        let line = "dc01$::CONTOSO:1122334455667788:9c8e64ac5db4e4a72b1cd2e1cd2e1cd2:0101000000000000aabbccdd";
        let output = format!("[SMB] NTLMv2-SSP Hash : {line}\n[HTTP] NTLMv2 Hash : {line}\n",);
        let params = json!({"domain": "contoso.local"});
        let hashes = parse_netntlmv2(&output, &params, "start_responder");
        assert_eq!(hashes.len(), 1);
    }

    #[test]
    fn parse_netntlmv2_rejects_non_hex_fields() {
        // A line that *looks* like the hash format but has non-hex content
        // in CHALLENGE / NT_PROOF / BLOB must not be silently coerced.
        let output =
            "alice::CONTOSO:notahexstring1234:00000000000000000000000000000000:0101000000000000";
        let hashes = parse_netntlmv2(output, &json!({}), "test");
        assert!(hashes.is_empty(), "non-hex challenge must be rejected");
    }

    #[test]
    fn parse_netntlmv2_rejects_wrong_field_count() {
        // Adjacent system noise that happens to contain `::` and `:` should
        // not be misclassified. Three checks: too few fields, too many fields,
        // and a kerberoast-style hash (which has its own dedicated parser).
        for noise in [
            "user::DOMAIN:short",
            "user::DOMAIN:1122334455667788:00000000000000000000000000000000:0101:trailing_field",
            "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$contoso/svc_sql*$abcd1234",
        ] {
            let hashes = parse_netntlmv2(noise, &json!({}), "test");
            assert!(
                hashes.is_empty(),
                "should not match malformed line: {noise:?}",
            );
        }
    }

    #[test]
    fn parse_netntlmv2_falls_back_to_param_domain_when_realm_empty() {
        // Captured realm is empty (`USER:::CHALL:PROOF:BLOB` — three colons
        // after the username because parts[1] AND parts[2] are empty).
        // The 6-field structure requires parts[1] is empty (the `::`) AND
        // exactly 6 parts; an empty domain field is still 6 parts overall.
        let output = "alice:::1122334455667788:11111111111111111111111111111111:0202020202020202";
        let hashes = parse_netntlmv2(output, &json!({"domain": "fallback.local"}), "test");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["domain"], "fallback.local");
    }

    #[test]
    fn parse_netntlmv2_strips_ansi_color() {
        // Responder colorizes the protocol tag and hash with SGR sequences.
        // The parser must drop them before pattern-matching, or the line
        // simply won't match the 6-field shape.
        let output =
            "\x1b[1;33m[SMB]\x1b[0m NTLMv2-SSP Hash : dc01$::CONTOSO:1122334455667788:11111111111111111111111111111111:0101000000000000aabbcc";
        let hashes = parse_netntlmv2(output, &json!({}), "start_responder");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "dc01$");
    }
}
