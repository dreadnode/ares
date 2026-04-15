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
