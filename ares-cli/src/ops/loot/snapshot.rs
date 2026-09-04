use std::collections::HashSet;

use chrono::Utc;

use ares_core::models::SharedRedTeamState;

#[derive(Default)]
pub(crate) struct LootSnapshot {
    pub domains: HashSet<String>,
    pub host_keys: HashSet<(String, String)>,
    pub user_keys: HashSet<(String, String)>,
    pub cred_keys: HashSet<(String, String, String)>,
    pub hash_keys: HashSet<(String, String, String, String)>,
    pub share_keys: HashSet<(String, String)>,
}

pub(crate) fn loot_snapshot(state: &SharedRedTeamState) -> LootSnapshot {
    LootSnapshot {
        domains: state
            .all_domains
            .iter()
            .map(|d| d.trim().to_lowercase())
            .filter(|d| !d.is_empty())
            .collect(),
        host_keys: state
            .all_hosts
            .iter()
            .map(|h| (h.hostname.clone(), h.ip.clone()))
            .collect(),
        user_keys: state
            .all_users
            .iter()
            .map(|u| {
                (
                    u.domain.trim().to_lowercase(),
                    u.username.trim().to_lowercase(),
                )
            })
            .collect(),
        cred_keys: state
            .all_credentials
            .iter()
            .map(|c| {
                (
                    c.domain.trim().to_lowercase(),
                    c.username.trim().to_lowercase(),
                    c.password.clone(),
                )
            })
            .collect(),
        hash_keys: state
            .all_hashes
            .iter()
            .map(|h| {
                (
                    h.domain.trim().to_lowercase(),
                    h.username.trim().to_lowercase(),
                    h.hash_type.trim().to_lowercase(),
                    h.hash_value.trim().to_lowercase(),
                )
            })
            .collect(),
        share_keys: state
            .all_shares
            .iter()
            .map(|s| (s.host.clone(), s.name.clone()))
            .collect(),
    }
}

pub(crate) fn print_diff(prev: &LootSnapshot, curr: &LootSnapshot) {
    let new_domains: Vec<_> = curr.domains.difference(&prev.domains).collect();
    let new_hosts: Vec<_> = curr.host_keys.difference(&prev.host_keys).collect();
    let new_users: Vec<_> = curr.user_keys.difference(&prev.user_keys).collect();
    let new_creds: Vec<_> = curr.cred_keys.difference(&prev.cred_keys).collect();
    let new_hashes: Vec<_> = curr.hash_keys.difference(&prev.hash_keys).collect();
    let new_shares: Vec<_> = curr.share_keys.difference(&prev.share_keys).collect();

    let total = new_domains.len()
        + new_hosts.len()
        + new_users.len()
        + new_creds.len()
        + new_hashes.len()
        + new_shares.len();

    if total == 0 {
        return;
    }

    let ts = Utc::now().format("%H:%M:%S");
    println!("\n--- New loot at {ts} ({total} items) ---");

    for d in &new_domains {
        println!("  [domain] {d}");
    }
    for (hostname, ip) in &new_hosts {
        let parts: Vec<&str> = [hostname.as_str(), ip.as_str()]
            .iter()
            .copied()
            .filter(|s| !s.is_empty())
            .collect();
        println!("  [host] {}", parts.join(" / "));
    }
    for (domain, username) in &new_users {
        let prefix = if domain.is_empty() {
            username.clone()
        } else {
            format!("{domain}\\{username}")
        };
        println!("  [user] {prefix}");
    }
    for (domain, username, password) in &new_creds {
        let prefix = if domain.is_empty() {
            username.clone()
        } else {
            format!("{domain}\\{username}")
        };
        println!("  [cred] {prefix}:{password}");
    }
    for (domain, username, hash_type, hash_value) in &new_hashes {
        let prefix = if domain.is_empty() {
            username.clone()
        } else {
            format!("{domain}\\{username}")
        };
        println!("  [hash] {prefix}:{hash_type}:{hash_value}");
    }
    for (host, name) in &new_shares {
        println!("  [share] {host}/{name}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ares_core::models::{Credential, Hash, Host, Share, User};
    use serde_json::json;

    fn state() -> SharedRedTeamState {
        SharedRedTeamState::new("op-test-001".to_string())
    }

    fn host(hostname: &str, ip: &str) -> Host {
        serde_json::from_value(json!({ "hostname": hostname, "ip": ip })).unwrap()
    }

    fn user(username: &str, domain: &str) -> User {
        serde_json::from_value(json!({ "username": username, "domain": domain })).unwrap()
    }

    fn credential(username: &str, domain: &str, password: &str) -> Credential {
        serde_json::from_value(
            json!({ "username": username, "domain": domain, "password": password }),
        )
        .unwrap()
    }

    fn hash(username: &str, domain: &str, hash_type: &str, hash_value: &str) -> Hash {
        serde_json::from_value(json!({
            "username": username,
            "domain": domain,
            "hash_type": hash_type,
            "hash_value": hash_value,
        }))
        .unwrap()
    }

    fn share(host: &str, name: &str) -> Share {
        serde_json::from_value(json!({ "host": host, "name": name })).unwrap()
    }

    #[test]
    fn empty_state_yields_an_empty_snapshot() {
        let snap = loot_snapshot(&state());
        assert!(snap.domains.is_empty());
        assert!(snap.host_keys.is_empty());
        assert!(snap.user_keys.is_empty());
        assert!(snap.cred_keys.is_empty());
        assert!(snap.hash_keys.is_empty());
        assert!(snap.share_keys.is_empty());
    }

    #[test]
    fn domains_are_trimmed_lowercased_and_deduped() {
        let mut s = state();
        s.all_domains = vec![
            "CONTOSO.local".to_string(),
            "  contoso.local  ".to_string(),
            "fabrikam.local".to_string(),
        ];

        let snap = loot_snapshot(&s);
        assert_eq!(snap.domains.len(), 2);
        assert!(snap.domains.contains("contoso.local"));
        assert!(snap.domains.contains("fabrikam.local"));
    }

    #[test]
    fn blank_domains_are_dropped() {
        let mut s = state();
        s.all_domains = vec![
            String::new(),
            "   ".to_string(),
            "contoso.local".to_string(),
        ];

        let snap = loot_snapshot(&s);
        assert_eq!(
            snap.domains,
            HashSet::from(["contoso.local".to_string()]),
            "whitespace-only domains must not become empty-string keys"
        );
    }

    #[test]
    fn user_keys_normalize_domain_and_username() {
        let mut s = state();
        s.all_users = vec![
            user("Alice", "CONTOSO.local"),
            user("  alice  ", "  contoso.local  "),
        ];

        let snap = loot_snapshot(&s);
        assert_eq!(
            snap.user_keys,
            HashSet::from([("contoso.local".to_string(), "alice".to_string())])
        );
    }

    #[test]
    fn credential_keys_normalize_identity_but_keep_the_password_verbatim() {
        let mut s = state();
        s.all_credentials = vec![credential("Alice", "CONTOSO.local", "P@ssw0rd!")];

        let snap = loot_snapshot(&s);
        assert_eq!(
            snap.cred_keys,
            HashSet::from([(
                "contoso.local".to_string(),
                "alice".to_string(),
                "P@ssw0rd!".to_string(),
            )]),
            "case-folding the password would merge distinct credentials"
        );
    }

    #[test]
    fn credentials_differing_only_by_password_stay_separate() {
        let mut s = state();
        s.all_credentials = vec![
            credential("alice", "contoso.local", "P@ssw0rd!"),
            credential("alice", "contoso.local", "p@ssw0rd!"),
        ];

        assert_eq!(loot_snapshot(&s).cred_keys.len(), 2);
    }

    #[test]
    fn hash_keys_are_fully_lowercased() {
        let mut s = state();
        s.all_hashes = vec![hash(
            "Alice",
            "CONTOSO.local",
            "NTLM",
            "AAD3B435B51404EEAAD3B435B51404EE",
        )];

        let snap = loot_snapshot(&s);
        assert_eq!(
            snap.hash_keys,
            HashSet::from([(
                "contoso.local".to_string(),
                "alice".to_string(),
                "ntlm".to_string(),
                "aad3b435b51404eeaad3b435b51404ee".to_string(),
            )])
        );
    }

    #[test]
    fn host_and_share_keys_are_kept_verbatim() {
        let mut s = state();
        s.all_hosts = vec![host("DC01.contoso.local", "192.168.58.10")];
        s.all_shares = vec![share("192.168.58.10", "SYSVOL")];

        let snap = loot_snapshot(&s);
        assert_eq!(
            snap.host_keys,
            HashSet::from([(
                "DC01.contoso.local".to_string(),
                "192.168.58.10".to_string()
            )])
        );
        assert_eq!(
            snap.share_keys,
            HashSet::from([("192.168.58.10".to_string(), "SYSVOL".to_string())])
        );
    }

    #[test]
    fn repeated_entries_collapse_to_one_key_each() {
        let mut s = state();
        s.all_hosts = vec![
            host("dc01.contoso.local", "192.168.58.10"),
            host("dc01.contoso.local", "192.168.58.10"),
        ];
        s.all_shares = vec![
            share("192.168.58.10", "SYSVOL"),
            share("192.168.58.10", "SYSVOL"),
        ];

        let snap = loot_snapshot(&s);
        assert_eq!(snap.host_keys.len(), 1);
        assert_eq!(snap.share_keys.len(), 1);
    }
}
