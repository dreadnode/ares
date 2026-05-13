//! Publishing methods — add credentials, hashes, hosts, and vulnerabilities
//! to both in-memory state and Redis.

mod credentials;
mod domains;
mod entities;
mod hosts;
mod kerberos;
mod milestones;

pub use domains::DomainPublishOutcome;

use ares_core::models::{OpStateEvent, OpStateEventPayload};
use ares_core::op_state_log::OpStateRecorder;
use regex::Regex;
use std::sync::LazyLock;

/// Emit a single op-state event through the recorder. No-op when the recorder
/// is disabled; otherwise builds an [`OpStateEvent`] and forwards to the
/// recorder. Publish failures are logged at WARN — Phase 2 keeps Redis
/// authoritative so a transient broker outage must not abort the call.
pub(super) async fn emit_op_state(
    recorder: &OpStateRecorder,
    op_id: &str,
    payload: OpStateEventPayload,
) {
    if !recorder.is_active() {
        return;
    }
    let event = OpStateEvent::new(op_id, payload);
    if let Err(e) = recorder.record(event).await {
        tracing::warn!(err = %e, "op-state event publish failed");
    }
}

/// Regex matching `Password` (case-insensitive) followed by optional `:` and space.
pub(super) static PASSWORD_PREFIX_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^password\s*:\s*").unwrap());

/// Trust ranking for a credential source.
///
/// Used by `publish_credential` to decide whether a new (user, password)
/// pair claiming a different realm than an existing entry should be treated
/// as authoritative or as a phantom. Higher value = more trusted.
///
/// - **High (3)**: deterministic, host-bound dumps where the realm is
///   pinned by the source DC's NTDS / LSA storage.
/// - **Medium (2)**: realm validated by an actual authentication round-trip
///   or by a cracking pipeline whose input was already realm-pinned.
/// - **Low (1)**: heuristic / format-fragile sources where the realm is
///   inferred from surrounding tool output and can bleed across forests
///   (description fields, registry autologon, SYSVOL scripts).
/// - **Unknown (0)**: anything not classified — treated as least trusted.
pub(super) fn credential_source_trust(source: &str) -> u8 {
    match source {
        "secretsdump" | "lsa_secrets" | "dpapi" | "kerberos_extracted" | "initial" => 3,
        "netexec_auth" | "cracked:hashcat" | "cracked:john" | "cracked" => 2,
        "description_field"
        | "autologon_registry"
        | "sysvol_script"
        | "user_description_leak"
        | "netexec_password" => 1,
        _ => 0,
    }
}

/// Regex matching trailing parenthetical metadata like ` (Guest)`, ` (Pwn3d!)`.
pub(super) static TRAILING_PAREN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\s+\([^)]+\)\s*$").unwrap());

/// Sanitize and validate a credential before storage.
///
/// Mirrors Python's `add_credential()` — strips noise from password values,
/// normalizes `user@domain@domain` usernames, resolves NetBIOS domains to FQDN,
/// and rejects invalid entries. Returns `None` if the credential should be dropped.
///
/// `known_domains` is the set of FQDNs already trusted by the operation
/// (state.domains plus state.domain_controllers keys). When supplied, an
/// FQDN domain on the incoming credential whose first label matches a
/// known FQDN is normalized to that known FQDN — this catches LLM-supplied
/// typos like `child.contososo.local` getting amplified by
/// NetBIOS-to-FQDN expansion in upstream parsers.
pub(super) fn sanitize_credential(
    mut cred: ares_core::models::Credential,
    netbios_to_fqdn: &std::collections::HashMap<String, String>,
    known_domains: &[String],
) -> Option<ares_core::models::Credential> {
    use crate::orchestrator::output_extraction::strip_ansi;

    // Strip ANSI escape codes (tools like NetExec emit colored output)
    cred.username = strip_ansi(&cred.username);
    cred.password = strip_ansi(&cred.password);
    cred.domain = strip_ansi(&cred.domain);

    // Trim whitespace
    cred.username = cred.username.trim().to_string();
    cred.password = cred.password.trim().to_string();
    cred.domain = cred.domain.trim().to_string();

    // Strip "Password: " / "Password:" prefix from password
    if PASSWORD_PREFIX_RE.is_match(&cred.password) {
        cred.password = PASSWORD_PREFIX_RE.replace(&cred.password, "").to_string();
    }

    // Strip trailing parenthetical metadata: "svc_test (Guest)" → "svc_test"
    if TRAILING_PAREN_RE.is_match(&cred.password) {
        cred.password = TRAILING_PAREN_RE.replace(&cred.password, "").to_string();
    }

    // Strip ellipsis truncation artifacts (matches Python add_credential)
    while cred.password.ends_with("...") {
        cred.password = cred.password[..cred.password.len() - 3].trim().to_string();
    }
    while cred.password.ends_with('\u{2026}') {
        cred.password.pop();
        cred.password = cred.password.trim().to_string();
    }

    // Normalize username with embedded @domain suffixes
    // e.g. "sam.wilson@child.contoso.local@fabrikam.local"
    //   → username="sam.wilson", domain="child.contoso.local"
    if cred.username.contains('@') {
        let username_clone = cred.username.clone();
        let parts: Vec<&str> = username_clone.splitn(2, '@').collect();
        if parts.len() == 2 && !parts[0].is_empty() {
            let base_username = parts[0].to_string();
            let domain_part = parts[1].split('@').next().unwrap_or(parts[1]).to_string();
            if domain_part.contains('.') {
                cred.username = base_username;
                cred.domain = domain_part;
            }
        }
    }

    // Resolve NetBIOS domain to FQDN (e.g. "CHILD" → "child.contoso.local")
    if !cred.domain.is_empty() && !cred.domain.contains('.') {
        let domain_upper = cred.domain.to_uppercase();
        if let Some(fqdn) = netbios_to_fqdn.get(&domain_upper) {
            // netbios_to_fqdn maps SHORTNAME → host.contoso.local
            // Extract the domain suffix
            let parts: Vec<&str> = fqdn.split('.').collect();
            if parts.len() >= 3 {
                cred.domain = parts[1..].join(".");
            } else {
                cred.domain = fqdn.clone();
            }
        } else {
            // Try matching domain as prefix of any FQDN domain suffix
            let domain_lower = cred.domain.to_lowercase();
            for fqdn in netbios_to_fqdn.values() {
                let fqdn_parts: Vec<&str> = fqdn.split('.').collect();
                if fqdn_parts.len() >= 3 {
                    let domain_suffix = fqdn_parts[1..].join(".");
                    let first_label = fqdn_parts[1].to_lowercase();
                    if first_label == domain_lower {
                        cred.domain = domain_suffix;
                        break;
                    }
                }
            }
        }
    }

    // Normalize an FQDN domain against known domains by first-label match.
    // Defends against the upstream spider parser amplifying an LLM-supplied
    // typo when expanding a NetBIOS prefix (e.g. file says `CHILD\user`,
    // the LLM passed `domain="child.contososo.local"`, and the parser
    // emitted that typo; here we snap to the known canonical FQDN).
    if cred.domain.contains('.') && !known_domains.is_empty() {
        let cred_domain_lower = cred.domain.to_lowercase();
        let already_known = known_domains
            .iter()
            .any(|d| d.eq_ignore_ascii_case(&cred_domain_lower));
        if !already_known {
            if let Some(first_label) = cred_domain_lower.split('.').next() {
                if let Some(canonical) = known_domains.iter().find(|d| {
                    d.split('.')
                        .next()
                        .is_some_and(|fl| fl.eq_ignore_ascii_case(first_label))
                }) {
                    tracing::warn!(
                        original = %cred.domain,
                        canonical = %canonical,
                        "Normalizing credential domain to known FQDN (likely LLM tool-arg typo)"
                    );
                    cred.domain = canonical.clone();
                }
            }
        }
    }

    // Canonicalize realm casing. AD realms are case-insensitive; storing them
    // mixed-case (`CONTOSO.LOCAL` from one tool, `contoso.local` from another)
    // splits the same identity into two state entries and slips past dedup
    // keys built with `format!("{domain}\\{user}:{pass}")`.
    cred.domain = cred.domain.to_lowercase();

    // Validate after sanitization
    if !crate::orchestrator::output_extraction::is_valid_credential(&cred.username, &cred.password)
    {
        return None;
    }

    Some(cred)
}

/// Strip the trailing "0." artifact that NetExec sometimes appends to domain
/// names (e.g. `dc01.contoso.local0.` → `dc01.contoso.local`,
/// `contoso.local0` → `contoso.local`).
pub(super) fn strip_netexec_artifact(s: &str) -> &str {
    let s = s.trim_end_matches('.');
    // "0." already collapsed to "0" after trimming "."; strip if preceded by a label
    match s.strip_suffix("0.") {
        Some(clean) => clean.trim_end_matches('.'),
        None => match s.strip_suffix('0') {
            // Avoid stripping a real trailing 0 from e.g. "host10" —
            // only strip if the char before the 0 is alphabetic (TLD-like).
            Some(clean) if clean.ends_with(|c: char| c.is_ascii_alphabetic()) => clean,
            _ => s,
        },
    }
}

/// Check if a label matches a known default-OS auto-generated hostname
/// (Windows OOBE, Win10/11 OOBE, AWS EC2 default). These appear on hosts
/// that haven't been renamed or domain-joined; they are never valid AD
/// domain labels.
///
/// Matches:
/// - `WIN-XXXXXXXX` (Win Server / older Win, 8–15 alphanumeric tail)
/// - `DESKTOP-XXXXXXX` / `LAPTOP-XXXXXXX` (Win10/11 OOBE, exactly 7 alphanumerics)
/// - `ip-A-B-C-D` (AWS EC2 default)
pub(super) fn is_default_os_label(label: &str) -> bool {
    let lower = label.to_lowercase();
    if let Some(suffix) = lower.strip_prefix("win-") {
        let len = suffix.len();
        return (8..=15).contains(&len) && suffix.chars().all(|c| c.is_ascii_alphanumeric());
    }
    if let Some(suffix) = lower
        .strip_prefix("desktop-")
        .or_else(|| lower.strip_prefix("laptop-"))
    {
        return suffix.len() == 7 && suffix.chars().all(|c| c.is_ascii_alphanumeric());
    }
    if let Some(rest) = lower.strip_prefix("ip-") {
        let octets: Vec<&str> = rest.split('-').collect();
        if octets.len() == 4
            && octets
                .iter()
                .all(|o| !o.is_empty() && o.chars().all(|c| c.is_ascii_digit()))
        {
            return true;
        }
    }
    false
}

/// Single predicate for "this multi-label DNS name could plausibly be a real
/// AD-style FQDN." Used both as a pre-filter on candidate domains
/// (`publish_candidate_domain`) and as a hostname-normalization gate on
/// `Host.hostname` (`publish_host`, `register_dc`) — every cloud / mDNS /
/// default-OS / bare-TLD rejection lives here so call sites don't have to
/// know the rules.
///
/// Rejects shapes that are *never* AD domains across OS families:
/// - Empty / whitespace, or single-label (`local`, `workgroup`)
/// - Pure mDNS link-local TLDs (`localhost`, `localdomain`)
/// - Cloud / hypervisor internal suffixes (AWS `compute.internal`,
///   `amazonaws.com`; Azure `internal.cloudapp.net`; GCP `c.<project>.internal`)
/// - Any label (in any position) matching a known default-OS auto-name
///   (`WIN-XXXX`, `DESKTOP-XXXX`, `LAPTOP-XXXX`, `ip-A-B-C-D`) — an unrenamed
///   host can't be trusted as a source of AD domain truth even if its suffix
///   looks plausible.
pub(super) fn looks_like_real_domain(name: &str) -> bool {
    let trimmed = name.trim().trim_end_matches('.').to_lowercase();
    if trimmed.is_empty() {
        return false;
    }
    let labels: Vec<&str> = trimmed.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    if matches!(trimmed.as_str(), "localhost" | "localdomain") {
        return false;
    }
    if labels
        .last()
        .map(|l| matches!(*l, "localhost" | "localdomain"))
        .unwrap_or(false)
    {
        return false;
    }
    if trimmed.contains("compute.internal")
        || trimmed.ends_with(".amazonaws.com")
        || trimmed.ends_with(".internal.cloudapp.net")
        || (trimmed.starts_with("c.") && trimmed.ends_with(".internal"))
    {
        return false;
    }
    if labels.iter().any(|l| is_default_os_label(l)) {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::Credential;
    use std::collections::HashMap;

    fn make_cred(username: &str, password: &str, domain: &str) -> Credential {
        Credential {
            id: "test-id".to_string(),
            username: username.to_string(),
            password: password.to_string(),
            domain: domain.to_string(),
            source: "test".to_string(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    // --- sanitize_credential ---

    #[test]
    fn valid_credential_passes_through() {
        let cred = make_cred("alice", "P@ssw0rd!", "contoso.local");
        let result = sanitize_credential(cred, &HashMap::new(), &[]).unwrap();
        assert_eq!(result.username, "alice");
        assert_eq!(result.password, "P@ssw0rd!");
        assert_eq!(result.domain, "contoso.local");
    }

    #[test]
    fn ansi_codes_stripped() {
        let cred = make_cred(
            "\x1b[32malice\x1b[0m",
            "\x1b[31mP@ssw0rd!\x1b[0m",
            "\x1b[34mcontoso.local\x1b[0m",
        );
        let result = sanitize_credential(cred, &HashMap::new(), &[]).unwrap();
        assert_eq!(result.username, "alice");
        assert_eq!(result.password, "P@ssw0rd!");
        assert_eq!(result.domain, "contoso.local");
    }

    #[test]
    fn whitespace_trimmed() {
        let cred = make_cred("  alice  ", "  P@ssw0rd!  ", "  contoso.local  ");
        let result = sanitize_credential(cred, &HashMap::new(), &[]).unwrap();
        assert_eq!(result.username, "alice");
        assert_eq!(result.password, "P@ssw0rd!");
        assert_eq!(result.domain, "contoso.local");
    }

    #[test]
    fn password_prefix_with_space_stripped() {
        let cred = make_cred("alice", "Password: Secret123", "contoso.local");
        let result = sanitize_credential(cred, &HashMap::new(), &[]).unwrap();
        assert_eq!(result.password, "Secret123");
    }

    #[test]
    fn password_prefix_without_space_stripped() {
        let cred = make_cred("alice", "Password:Secret123", "contoso.local");
        let result = sanitize_credential(cred, &HashMap::new(), &[]).unwrap();
        assert_eq!(result.password, "Secret123");
    }

    #[test]
    fn trailing_parenthetical_stripped() {
        let cred = make_cred("alice", "P@ssw0rd! (Guest)", "contoso.local");
        let result = sanitize_credential(cred, &HashMap::new(), &[]).unwrap();
        assert_eq!(result.password, "P@ssw0rd!");
    }

    #[test]
    fn trailing_ascii_ellipsis_stripped() {
        let cred = make_cred("alice", "P@ssw0rd!......", "contoso.local");
        let result = sanitize_credential(cred, &HashMap::new(), &[]).unwrap();
        assert_eq!(result.password, "P@ssw0rd!");
    }

    #[test]
    fn trailing_unicode_ellipsis_stripped() {
        let cred = make_cred("alice", "P@ssw0rd!\u{2026}", "contoso.local");
        let result = sanitize_credential(cred, &HashMap::new(), &[]).unwrap();
        assert_eq!(result.password, "P@ssw0rd!");
    }

    #[test]
    fn username_at_domain_normalized() {
        let cred = make_cred("sam.wilson@child.contoso.local", "P@ssw0rd!", "");
        let result = sanitize_credential(cred, &HashMap::new(), &[]).unwrap();
        assert_eq!(result.username, "sam.wilson");
        assert_eq!(result.domain, "child.contoso.local");
    }

    #[test]
    fn username_double_at_takes_first_domain() {
        let cred = make_cred(
            "sam.wilson@child.contoso.local@other.local",
            "P@ssw0rd!",
            "",
        );
        let result = sanitize_credential(cred, &HashMap::new(), &[]).unwrap();
        assert_eq!(result.username, "sam.wilson");
        assert_eq!(result.domain, "child.contoso.local");
    }

    #[test]
    fn realm_case_canonicalized_to_lowercase() {
        // Tools surface realm in mixed/upper case (`CONTOSO.LOCAL` from
        // rpcclient, `Contoso.Local` from LDAP). Without canonicalization, the
        // same identity ends up split across multiple state entries and
        // realm-strict credential lookups miss matches.
        let cred = make_cred("alice", "P@ssw0rd!", "CONTOSO.LOCAL");
        let result = sanitize_credential(cred, &HashMap::new(), &[]).unwrap();
        assert_eq!(result.domain, "contoso.local");
    }

    #[test]
    fn netbios_domain_resolved_to_fqdn() {
        let mut map = HashMap::new();
        map.insert("CHILD".to_string(), "dc01.child.contoso.local".to_string());
        let cred = make_cred("alice", "P@ssw0rd!", "CHILD");
        let result = sanitize_credential(cred, &map, &[]).unwrap();
        assert_eq!(result.domain, "child.contoso.local");
    }

    #[test]
    fn netbios_domain_prefix_match() {
        let mut map = HashMap::new();
        map.insert(
            "CONTOSO".to_string(),
            "dc01.child.contoso.local".to_string(),
        );
        // "child" is not a direct key, but matches the first label after hostname in a value
        let cred = make_cred("alice", "P@ssw0rd!", "child");
        let result = sanitize_credential(cred, &map, &[]).unwrap();
        assert_eq!(result.domain, "child.contoso.local");
    }

    #[test]
    fn returns_none_for_empty_username() {
        let cred = make_cred("", "P@ssw0rd!", "contoso.local");
        assert!(sanitize_credential(cred, &HashMap::new(), &[]).is_none());
    }

    #[test]
    fn returns_none_for_empty_password() {
        let cred = make_cred("alice", "", "contoso.local");
        assert!(sanitize_credential(cred, &HashMap::new(), &[]).is_none());
    }

    #[test]
    fn returns_none_for_password_with_path_separator() {
        let cred = make_cred("alice", "/etc/passwd", "contoso.local");
        assert!(sanitize_credential(cred, &HashMap::new(), &[]).is_none());
    }

    #[test]
    fn returns_none_for_short_password() {
        let cred = make_cred("alice", "ab", "contoso.local");
        assert!(sanitize_credential(cred, &HashMap::new(), &[]).is_none());
    }

    #[test]
    fn typo_fqdn_normalized_to_known_domain() {
        // Regression: spider parser expanded `CHILD\alice.jones` using an
        // LLM-supplied typo'd `domain` param, producing a credential with
        // domain `child.contososo.local`. Snap to the known canonical.
        let cred = make_cred("alice.jones", "P@ssw0rd!", "child.contososo.local");
        let known = vec![
            "contoso.local".to_string(),
            "child.contoso.local".to_string(),
        ];
        let result = sanitize_credential(cred, &HashMap::new(), &known).unwrap();
        assert_eq!(result.domain, "child.contoso.local");
    }

    #[test]
    fn unknown_fqdn_with_no_first_label_match_kept_as_is() {
        // A genuine new domain — not a typo of anything known — should pass
        // through untouched so the auto-extract path can pick it up.
        let cred = make_cred("alice", "P@ssw0rd!", "fabrikam.local");
        let known = vec!["contoso.local".to_string()];
        let result = sanitize_credential(cred, &HashMap::new(), &known).unwrap();
        assert_eq!(result.domain, "fabrikam.local");
    }

    #[test]
    fn known_fqdn_passes_through_unchanged() {
        let cred = make_cred("alice", "P@ssw0rd!", "contoso.local");
        let known = vec!["contoso.local".to_string()];
        let result = sanitize_credential(cred, &HashMap::new(), &known).unwrap();
        assert_eq!(result.domain, "contoso.local");
    }

    // --- is_default_os_label ---

    #[test]
    fn default_os_label_detects_windows_oobe() {
        assert!(is_default_os_label("WIN-HVTT4F8YN5N"));
        assert!(is_default_os_label("win-hvtt4f8yn5n"));
        assert!(is_default_os_label("WIN-ABCDEFGH"));
    }

    #[test]
    fn default_os_label_detects_win10_11_oobe() {
        assert!(is_default_os_label("DESKTOP-ABC1234"));
        assert!(is_default_os_label("desktop-abc1234"));
        assert!(is_default_os_label("LAPTOP-XYZ7890"));
        // Wrong tail length (Win10/11 OOBE is exactly 7).
        assert!(!is_default_os_label("DESKTOP-ABCDEFGH"));
        assert!(!is_default_os_label("DESKTOP-ABC"));
    }

    #[test]
    fn default_os_label_detects_aws_default() {
        assert!(is_default_os_label("ip-10-0-1-50"));
        assert!(is_default_os_label("ip-192-168-1-1"));
        // Not 4 octets:
        assert!(!is_default_os_label("ip-10-0-1"));
        // Non-numeric:
        assert!(!is_default_os_label("ip-foo-bar-baz-qux"));
    }

    #[test]
    fn default_os_label_rejects_legitimate_names() {
        assert!(!is_default_os_label("dc01"));
        assert!(!is_default_os_label("contoso"));
        assert!(!is_default_os_label("local"));
        // Too short
        assert!(!is_default_os_label("WIN-ABC"));
        // Too long
        assert!(!is_default_os_label("WIN-ABCDEFGHIJKLMNOP"));
        // Wrong prefix
        assert!(!is_default_os_label("LIN-ABCDEFGH"));
        // Contains non-alphanumerics
        assert!(!is_default_os_label("WIN-HVTT4F8.YN5N"));
    }

    #[test]
    fn looks_like_real_domain_accepts_typical_ad() {
        assert!(looks_like_real_domain("contoso.local"));
        assert!(looks_like_real_domain("child.contoso.local"));
        assert!(looks_like_real_domain("eu.contoso.local"));
        assert!(looks_like_real_domain("contoso.com"));
    }

    #[test]
    fn looks_like_real_domain_rejects_bare_tld_and_mdns() {
        assert!(!looks_like_real_domain("local"));
        assert!(!looks_like_real_domain(""));
        assert!(!looks_like_real_domain("localhost"));
        assert!(!looks_like_real_domain("foo.localhost"));
        assert!(!looks_like_real_domain("foo.localdomain"));
    }

    #[test]
    fn looks_like_real_domain_rejects_cloud_internals() {
        assert!(!looks_like_real_domain("us-west-2.compute.internal"));
        assert!(!looks_like_real_domain("eu-west-1.amazonaws.com"));
        assert!(!looks_like_real_domain("vm123.internal.cloudapp.net"));
        assert!(!looks_like_real_domain("c.myproject.internal"));
    }

    #[test]
    fn looks_like_real_domain_rejects_default_os_labels_anywhere() {
        assert!(!looks_like_real_domain("win-hvtt4f8yn5n.ttb0.local"));
        assert!(!looks_like_real_domain("desktop-abc1234.workgroup.local"));
        assert!(!looks_like_real_domain("ip-10-0-0-1.something.com"));
        assert!(!looks_like_real_domain("dc01.win-abc12345.contoso.local"));
        assert!(!looks_like_real_domain(
            "ip-10-0-0-1.us-west-2.compute.internal"
        ));
    }

    // --- strip_netexec_artifact ---

    #[test]
    fn strip_netexec_zero_dot() {
        assert_eq!(
            strip_netexec_artifact("dc01.contoso.local0."),
            "dc01.contoso.local"
        );
    }

    #[test]
    fn strip_netexec_zero_no_dot() {
        assert_eq!(
            strip_netexec_artifact("dc01.contoso.local0"),
            "dc01.contoso.local"
        );
    }

    #[test]
    fn strip_netexec_preserves_clean_hostname() {
        assert_eq!(
            strip_netexec_artifact("dc01.contoso.local"),
            "dc01.contoso.local"
        );
    }

    #[test]
    fn strip_netexec_preserves_numeric_suffix() {
        // Must NOT strip the 0 from "host10" or "dc10"
        assert_eq!(strip_netexec_artifact("host10"), "host10");
        assert_eq!(
            strip_netexec_artifact("dc10.contoso.local"),
            "dc10.contoso.local"
        );
    }

    #[test]
    fn strip_netexec_child_domain() {
        assert_eq!(
            strip_netexec_artifact("dc02.child.contoso.local0."),
            "dc02.child.contoso.local"
        );
    }
}
