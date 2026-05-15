//! Pure parsing functions for result payloads -- no IO, no Redis.

use serde_json::Value;

use ares_core::models::{Credential, Hash, Host, Share, User, VulnerabilityInfo};

/// Parsed discoveries from a JSON result payload.
#[derive(Debug, Default)]
pub(crate) struct ParsedDiscoveries {
    pub credentials: Vec<Credential>,
    pub hashes: Vec<Hash>,
    pub hosts: Vec<Host>,
    pub users: Vec<User>,
    pub vulnerabilities: Vec<VulnerabilityInfo>,
    pub shares: Vec<Share>,
}

/// Resolve the parent credential or hash for a newly discovered item.
pub(crate) fn resolve_parent_id(
    credentials: &[Credential],
    hashes: &[Hash],
    source: &str,
    username: &str,
    domain: &str,
    input_username: Option<&str>,
    input_domain: Option<&str>,
) -> (Option<String>, i32) {
    if source.starts_with("cracked") {
        if let Some(h) = hashes.iter().rev().find(|h| {
            h.username.eq_ignore_ascii_case(username)
                && (domain.is_empty() || h.domain.eq_ignore_ascii_case(domain))
        }) {
            return (Some(h.id.clone()), h.attack_step + 1);
        }
    }
    if let Some(in_user) = input_username.filter(|u| !u.is_empty()) {
        let in_domain = input_domain.unwrap_or("");
        let is_same = in_user.eq_ignore_ascii_case(username)
            && (in_domain.eq_ignore_ascii_case(domain)
                || in_domain.is_empty()
                || domain.is_empty());
        if !is_same {
            if let Some(c) = credentials.iter().rev().find(|c| {
                c.username.eq_ignore_ascii_case(in_user)
                    && (in_domain.is_empty()
                        || c.domain.is_empty()
                        || c.domain.eq_ignore_ascii_case(in_domain))
            }) {
                return (Some(c.id.clone()), c.attack_step + 1);
            }
            if let Some(h) = hashes.iter().rev().find(|h| {
                h.username.eq_ignore_ascii_case(in_user)
                    && (in_domain.is_empty()
                        || h.domain.is_empty()
                        || h.domain.eq_ignore_ascii_case(in_domain))
            }) {
                return (Some(h.id.clone()), h.attack_step + 1);
            }
        }
    }
    (None, 0)
}

pub(crate) fn parse_discoveries(payload: &Value) -> ParsedDiscoveries {
    let mut result = ParsedDiscoveries::default();

    if let Some(creds) = payload.get("credentials").and_then(|v| v.as_array()) {
        for cred_val in creds {
            if let Ok(cred) = serde_json::from_value::<Credential>(cred_val.clone()) {
                result.credentials.push(cred);
            }
        }
    }
    if let Some(cred_val) = payload.get("credential") {
        if let Ok(cred) = serde_json::from_value::<Credential>(cred_val.clone()) {
            result.credentials.push(cred);
        }
    }
    if let Some(cracked) = payload.get("cracked_password").and_then(|v| v.as_str()) {
        if let Some(username) = payload.get("username").and_then(|v| v.as_str()) {
            let domain = payload.get("domain").and_then(|v| v.as_str()).unwrap_or("");
            result.credentials.push(Credential {
                id: uuid::Uuid::new_v4().to_string(),
                username: username.to_string(),
                password: cracked.to_string(),
                domain: domain.to_string(),
                source: "cracked".to_string(),
                discovered_at: Some(chrono::Utc::now()),
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            });
        }
    }
    if let Some(hashes) = payload.get("hashes").and_then(|v| v.as_array()) {
        for hash_val in hashes {
            if let Ok(hash) = serde_json::from_value::<Hash>(hash_val.clone()) {
                result.hashes.push(hash);
            }
        }
    }
    if let Some(hosts) = payload.get("hosts").and_then(|v| v.as_array()) {
        for host_val in hosts {
            if let Ok(host) = serde_json::from_value::<Host>(host_val.clone()) {
                result.hosts.push(host);
            }
        }
    }
    // Users -- defense-in-depth: only accept entries with a parser-verified source.
    const TRUSTED_USER_SOURCES: &[&str] = &[
        "kerberos_enum",
        "netexec_user_enum",
        "ldap_group_enumeration",
        "acl_discovery",
        "foreign_group_enumeration",
        "ldap_enumeration",
    ];
    if let Some(users) = payload.get("discovered_users").and_then(|v| v.as_array()) {
        for user_val in users {
            if let Ok(user) = serde_json::from_value::<User>(user_val.clone()) {
                if TRUSTED_USER_SOURCES.contains(&user.source.as_str()) {
                    result.users.push(user);
                }
            }
        }
    }
    if let Some(vulns) = payload.get("vulnerabilities").and_then(|v| v.as_array()) {
        for vuln_val in vulns {
            if let Ok(vuln) = serde_json::from_value::<VulnerabilityInfo>(vuln_val.clone()) {
                result.vulnerabilities.push(vuln);
            }
        }
    }
    if result.vulnerabilities.is_empty() {
        if let Some(vuln_val) = payload.get("vulnerability") {
            if let Ok(vuln) = serde_json::from_value::<VulnerabilityInfo>(vuln_val.clone()) {
                result.vulnerabilities.push(vuln);
            }
        }
    }
    if let Some(shares) = payload.get("shares").and_then(|v| v.as_array()) {
        for share_val in shares {
            if let Ok(share) = serde_json::from_value::<Share>(share_val.clone()) {
                result.shares.push(share);
            }
        }
    }
    result
}

/// Check if a payload contains domain admin indicators. Pure function.
pub(crate) fn has_domain_admin_indicator(payload: &Value) -> bool {
    // Only trust tool-output-backed evidence: a krbtgt hash in the payload.
    // Agent self-reporting via `has_domain_admin: true` is not accepted —
    // LLMs hallucinate domain admin routinely and it breaks post-DA automation.
    if let Some(hashes) = payload.get("hashes").and_then(|v| v.as_array()) {
        for hash_val in hashes {
            if let Some(username) = hash_val.get("username").and_then(|v| v.as_str()) {
                if username.to_lowercase() == "krbtgt" {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── has_domain_admin_indicator ──

    #[test]
    fn domain_admin_flag_true_ignored() {
        // Agent self-reporting is not accepted — must have a krbtgt hash.
        let payload = json!({"has_domain_admin": true});
        assert!(!has_domain_admin_indicator(&payload));
    }

    #[test]
    fn domain_admin_flag_false() {
        let payload = json!({"has_domain_admin": false});
        assert!(!has_domain_admin_indicator(&payload));
    }

    #[test]
    fn domain_admin_flag_missing() {
        let payload = json!({"some_field": "value"});
        assert!(!has_domain_admin_indicator(&payload));
    }

    #[test]
    fn domain_admin_empty_payload() {
        let payload = json!({});
        assert!(!has_domain_admin_indicator(&payload));
    }

    #[test]
    fn domain_admin_krbtgt_hash() {
        let payload = json!({
            "hashes": [
                {"username": "krbtgt", "hash_value": "aad3b435..."}
            ]
        });
        assert!(has_domain_admin_indicator(&payload));
    }

    #[test]
    fn domain_admin_krbtgt_mixed_case() {
        let payload = json!({
            "hashes": [
                {"username": "KRBTGT", "hash_value": "aad3b435..."}
            ]
        });
        assert!(has_domain_admin_indicator(&payload));
    }

    #[test]
    fn domain_admin_non_krbtgt_hashes() {
        let payload = json!({
            "hashes": [
                {"username": "admin", "hash_value": "abc123"}
            ]
        });
        assert!(!has_domain_admin_indicator(&payload));
    }

    #[test]
    fn domain_admin_empty_hashes_array() {
        let payload = json!({"hashes": []});
        assert!(!has_domain_admin_indicator(&payload));
    }

    #[test]
    fn domain_admin_flag_not_bool() {
        let payload = json!({"has_domain_admin": "true"});
        assert!(!has_domain_admin_indicator(&payload));
    }

    #[test]
    fn domain_admin_flag_and_krbtgt_both() {
        let payload = json!({
            "has_domain_admin": true,
            "hashes": [{"username": "krbtgt", "hash_value": "abc"}]
        });
        assert!(has_domain_admin_indicator(&payload));
    }

    // ── resolve_parent_id ──

    fn make_credential(id: &str, username: &str, domain: &str, step: i32) -> Credential {
        Credential {
            id: id.to_string(),
            username: username.to_string(),
            password: String::new(),
            domain: domain.to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: step,
        }
    }

    fn make_hash(id: &str, username: &str, domain: &str, step: i32) -> Hash {
        Hash {
            id: id.to_string(),
            username: username.to_string(),
            hash_value: "deadbeef".to_string(),
            hash_type: "ntlm".to_string(),
            domain: domain.to_string(),
            cracked_password: None,
            source: String::new(),
            discovered_at: None,
            parent_id: None,
            attack_step: step,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        }
    }

    #[test]
    fn resolve_parent_no_match() {
        let (parent, step) = resolve_parent_id(&[], &[], "smb", "admin", "CONTOSO", None, None);
        assert!(parent.is_none());
        assert_eq!(step, 0);
    }

    #[test]
    fn resolve_parent_cracked_source_matches_hash() {
        let hashes = vec![make_hash("h1", "admin", "CONTOSO", 2)];
        let (parent, step) =
            resolve_parent_id(&[], &hashes, "cracked_ntlm", "admin", "CONTOSO", None, None);
        assert_eq!(parent.as_deref(), Some("h1"));
        assert_eq!(step, 3);
    }

    #[test]
    fn resolve_parent_cracked_case_insensitive() {
        let hashes = vec![make_hash("h1", "Admin", "contoso", 1)];
        let (parent, step) =
            resolve_parent_id(&[], &hashes, "cracked_pw", "admin", "CONTOSO", None, None);
        assert_eq!(parent.as_deref(), Some("h1"));
        assert_eq!(step, 2);
    }

    #[test]
    fn resolve_parent_cracked_empty_domain_matches() {
        let hashes = vec![make_hash("h1", "admin", "CONTOSO", 5)];
        let (parent, step) = resolve_parent_id(&[], &hashes, "cracked_pw", "admin", "", None, None);
        assert_eq!(parent.as_deref(), Some("h1"));
        assert_eq!(step, 6);
    }

    #[test]
    fn resolve_parent_input_user_maps_to_credential() {
        let creds = vec![make_credential("c1", "alice", "CONTOSO", 3)];
        let (parent, step) = resolve_parent_id(
            &creds,
            &[],
            "smb",
            "bob",
            "CONTOSO",
            Some("alice"),
            Some("CONTOSO"),
        );
        assert_eq!(parent.as_deref(), Some("c1"));
        assert_eq!(step, 4);
    }

    #[test]
    fn resolve_parent_input_user_same_as_discovered_skips() {
        // When input user == discovered user, it's the same identity; no parent link.
        let creds = vec![make_credential("c1", "admin", "CONTOSO", 2)];
        let (parent, step) = resolve_parent_id(
            &creds,
            &[],
            "smb",
            "admin",
            "CONTOSO",
            Some("admin"),
            Some("CONTOSO"),
        );
        assert!(parent.is_none());
        assert_eq!(step, 0);
    }

    #[test]
    fn resolve_parent_input_user_falls_back_to_hash() {
        let hashes = vec![make_hash("h1", "alice", "CONTOSO", 1)];
        let (parent, step) = resolve_parent_id(
            &[],
            &hashes,
            "smb",
            "bob",
            "CONTOSO",
            Some("alice"),
            Some("CONTOSO"),
        );
        assert_eq!(parent.as_deref(), Some("h1"));
        assert_eq!(step, 2);
    }

    #[test]
    fn resolve_parent_input_user_empty_is_ignored() {
        let creds = vec![make_credential("c1", "admin", "CONTOSO", 1)];
        let (parent, step) =
            resolve_parent_id(&creds, &[], "smb", "bob", "CONTOSO", Some(""), None);
        assert!(parent.is_none());
        assert_eq!(step, 0);
    }

    #[test]
    fn resolve_parent_cracked_preferred_over_input_user() {
        let hashes = vec![make_hash("h1", "admin", "CONTOSO", 2)];
        let creds = vec![make_credential("c1", "alice", "CONTOSO", 1)];
        let (parent, step) = resolve_parent_id(
            &creds,
            &hashes,
            "cracked_ntlm",
            "admin",
            "CONTOSO",
            Some("alice"),
            Some("CONTOSO"),
        );
        // cracked source matches hash first
        assert_eq!(parent.as_deref(), Some("h1"));
        assert_eq!(step, 3);
    }

    #[test]
    fn resolve_parent_picks_last_matching_credential() {
        let creds = vec![
            make_credential("c1", "alice", "CONTOSO", 1),
            make_credential("c2", "alice", "CONTOSO", 3),
        ];
        let (parent, step) = resolve_parent_id(
            &creds,
            &[],
            "smb",
            "bob",
            "CONTOSO",
            Some("alice"),
            Some("CONTOSO"),
        );
        // .rev() means c2 is found first
        assert_eq!(parent.as_deref(), Some("c2"));
        assert_eq!(step, 4);
    }

    #[test]
    fn resolve_parent_input_domain_empty_still_matches() {
        let creds = vec![make_credential("c1", "alice", "CONTOSO", 2)];
        let (parent, step) = resolve_parent_id(
            &creds,
            &[],
            "smb",
            "bob",
            "CONTOSO",
            Some("alice"),
            Some(""),
        );
        assert_eq!(parent.as_deref(), Some("c1"));
        assert_eq!(step, 3);
    }
}
