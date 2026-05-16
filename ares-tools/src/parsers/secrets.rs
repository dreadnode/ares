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

pub fn parse_secretsdump(output: &str, params: &Value) -> (Vec<Value>, Vec<Value>) {
    // Prefer target_domain (the domain being dumped) over domain (auth credential's domain)
    // to correctly attribute hashes when authenticating cross-domain.
    let domain = params
        .get("target_domain")
        .or_else(|| params.get("domain"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let mut hashes = Vec::new();
    let creds = Vec::new();
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
                    // raiseChild emits FQDN/user (slash separator),
                    // standard secretsdump emits DOMAIN\user (backslash + NetBIOS).
                    let resolved = resolve_netbios_to_fqdn(prefix, domain);
                    (resolved, user.to_string())
                } else if is_local_sam_account(raw_user, rid, section) {
                    // Local SAM account dumped without a domain prefix —
                    // leave domain empty so it doesn't masquerade as AD.
                    (String::new(), raw_user.to_string())
                } else {
                    (domain.to_string(), raw_user.to_string())
                };

                let nt_hash = parts[3];
                if nt_hash.len() == 32 && nt_hash != "31d6cfe0d16ae931b73c59d7e0c089c0" {
                    // Skip empty/disabled hashes
                    let lm_hash = parts[2];
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
                    let (is_trust_key, trust_pair_label) =
                        classify_trust_key(&username_clean, &user_domain);

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

        // Cleartext passwords: "[*] Dumping DPAPI creds..." then "username:password"
        // or from LSA: "[*] DefaultPassword\n  username = ...\n  password = ..."
    }

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
        // raiseChild.py emits FQDN/user with a slash; parser must accept both.
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
}
