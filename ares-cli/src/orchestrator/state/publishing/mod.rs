//! Publishing methods — add credentials, hashes, hosts, and vulnerabilities
//! to both in-memory state and Redis.

mod credentials;
mod entities;
mod hosts;
mod milestones;

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

    // Validate after sanitization
    if !crate::orchestrator::output_extraction::is_valid_credential(&cred.username, &cred.password)
    {
        return None;
    }

    Some(cred)
}

/// Check if a hostname is an AWS internal PTR name.
pub(super) fn is_aws_hostname(hostname: &str) -> bool {
    let lower = hostname.to_lowercase();
    lower.starts_with("ip-") && lower.contains("compute.internal")
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

    #[test]
    fn aws_hostname_detected() {
        assert!(is_aws_hostname("ip-10-0-0-1.ec2.compute.internal"));
    }

    #[test]
    fn aws_hostname_case_insensitive() {
        assert!(is_aws_hostname("IP-10-0-0-1.EC2.COMPUTE.INTERNAL"));
    }

    #[test]
    fn non_aws_hostname_rejected() {
        assert!(!is_aws_hostname("webserver01.contoso.local"));
    }

    #[test]
    fn ip_prefix_without_compute_internal_rejected() {
        assert!(!is_aws_hostname("ip-missing-suffix.local"));
    }
}
