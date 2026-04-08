use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use chrono::Utc;
use tracing::warn;

use ares_core::models::SharedRedTeamState;
use ares_core::state::RedisStateReader;

use crate::dedup::{dedup_credentials, dedup_hashes, dedup_users, extract_weakness_title};
use crate::redis_conn::{connect_redis, resolve_operation_id};

pub(crate) async fn ops_loot(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
    json_output: bool,
    watch: u64,
    diff: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let op_id = resolve_operation_id(&mut conn, operation_id, latest).await?;

    let watch_interval = if diff && watch == 0 { 10 } else { watch };

    if watch_interval > 0 {
        loot_watch(&mut conn, &op_id, watch_interval, diff, json_output).await
    } else {
        loot_once(&mut conn, &op_id, json_output).await
    }
}

async fn loot_once(
    conn: &mut redis::aio::MultiplexedConnection,
    op_id: &str,
    json_output: bool,
) -> Result<()> {
    let reader = RedisStateReader::new(op_id.to_string());
    let state = reader
        .load_state(conn)
        .await?
        .with_context(|| format!("No state found for operation: {op_id}"))?;

    print_loot(&state, json_output);
    Ok(())
}

async fn loot_watch(
    conn: &mut redis::aio::MultiplexedConnection,
    op_id: &str,
    interval: u64,
    diff_mode: bool,
    json_output: bool,
) -> Result<()> {
    let reader = RedisStateReader::new(op_id.to_string());
    let mut prev_snapshot: Option<LootSnapshot> = None;

    loop {
        match reader.load_state(conn).await {
            Ok(Some(state)) => {
                let curr = loot_snapshot(&state);

                if diff_mode {
                    if prev_snapshot.is_none() {
                        print_loot(&state, json_output);
                    } else if let Some(prev) = &prev_snapshot {
                        print_diff(prev, &curr);
                    }
                } else {
                    let ts = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
                    if prev_snapshot.is_some() {
                        println!("\n{}", "=".repeat(60));
                    }
                    println!("[watch] Refreshing every {interval}s  |  {ts}");
                    println!("{}", "=".repeat(60));
                    print_loot(&state, json_output);
                }

                prev_snapshot = Some(curr);
            }
            Ok(None) => {
                warn!("No state found for {op_id}, retrying in {interval}s...");
            }
            Err(e) => {
                warn!("Redis fetch failed: {e}");
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
    }
}

fn print_loot(state: &SharedRedTeamState, json_output: bool) {
    if json_output {
        print_loot_json(state);
    } else {
        print_loot_human(state);
    }
}

fn print_loot_json(state: &SharedRedTeamState) {
    let unique_users = dedup_users(&state.all_users);
    let unique_creds = dedup_credentials(&state.all_credentials);
    let unique_hashes = dedup_hashes(&state.all_hashes);

    let output = serde_json::json!({
        "operation_id": state.operation_id,
        "has_domain_admin": state.has_domain_admin,
        "domain_admin_path": state.domain_admin_path,
        "has_golden_ticket": state.has_golden_ticket,
        "domains": state.all_domains,
        "hosts": state.all_hosts.iter().map(|h| serde_json::json!({
            "ip": h.ip,
            "hostname": h.hostname,
            "os": h.os,
            "is_dc": h.is_dc,
            "services": h.services,
        })).collect::<Vec<_>>(),
        "users": unique_users.iter().map(|u| serde_json::json!({
            "username": u.username,
            "domain": u.domain,
            "is_admin": u.is_admin,
            "source": u.source,
        })).collect::<Vec<_>>(),
        "credentials": unique_creds.iter().map(|c| serde_json::json!({
            "username": c.username,
            "password": c.password,
            "domain": c.domain,
            "is_admin": c.is_admin,
        })).collect::<Vec<_>>(),
        "hashes": unique_hashes.iter().map(|h| serde_json::json!({
            "username": h.username,
            "domain": h.domain,
            "hash_type": h.hash_type,
            "hash_value": h.hash_value,
            "source": h.source,
        })).collect::<Vec<_>>(),
        "shares": state.all_shares.iter().map(|s| serde_json::json!({
            "host": s.host,
            "name": s.name,
            "permissions": s.permissions,
        })).collect::<Vec<_>>(),
        "weaknesses": state.all_weaknesses,
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_default()
    );
}

fn print_loot_human(state: &SharedRedTeamState) {
    println!("Operation: {}", state.operation_id);
    if state.has_domain_admin {
        println!("*** DOMAIN ADMIN ACHIEVED ***");
        if let Some(path) = &state.domain_admin_path {
            println!("  Path: {path}");
        }
    }
    if state.has_golden_ticket {
        println!("*** GOLDEN TICKET OBTAINED ***");
    }
    println!();

    // Domains with hierarchy
    let mut domains: Vec<String> = state
        .all_domains
        .iter()
        .map(|d| d.trim().to_lowercase())
        .filter(|d| !d.is_empty())
        .collect();
    domains.sort();
    domains.dedup();

    let mut forest_roots: Vec<String> = Vec::new();
    let mut child_domains: HashMap<String, String> = HashMap::new();
    for domain in &domains {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() >= 3 {
            let parent = parts[1..].join(".");
            if domains.contains(&parent) {
                child_domains.insert(domain.clone(), parent);
            } else {
                forest_roots.push(domain.clone());
            }
        } else {
            forest_roots.push(domain.clone());
        }
    }

    println!("Domains ({}):", domains.len());
    if domains.is_empty() {
        println!("  - None");
    } else {
        let mut displayed = HashSet::new();
        for root in forest_roots.iter() {
            println!("  - {root} (forest root)");
            displayed.insert(root.clone());
            for (child, parent) in child_domains.iter() {
                if parent == root {
                    println!("    \u{2514}\u{2500} {child} (child)");
                    displayed.insert(child.clone());
                }
            }
        }
        for child in child_domains.keys() {
            if !displayed.contains(child) {
                let parent = &child_domains[child];
                println!("  - {child} (child of {parent})");
            }
        }
    }
    println!();

    // Hosts
    let dcs: Vec<_> = state.all_hosts.iter().filter(|h| h.is_dc).collect();
    println!("Hosts ({}, {} DCs):", state.all_hosts.len(), dcs.len());
    for host in &state.all_hosts {
        let mut parts = Vec::new();
        if !host.hostname.is_empty() {
            parts.push(host.hostname.as_str());
        }
        if !host.ip.is_empty() {
            parts.push(host.ip.as_str());
        }
        let mut line = if parts.is_empty() {
            "(unknown)".to_string()
        } else {
            parts.join(" / ")
        };
        if !host.os.is_empty() {
            line = format!("{line} [{}]", host.os);
        }
        if host.is_dc {
            line = format!("{line} [DC]");
        }
        println!("  - {line}");
        for svc in &host.services {
            println!("      {svc}");
        }
    }
    println!();

    // Users grouped by source
    let unique_users = dedup_users(&state.all_users);
    println!("Users ({}):", unique_users.len());
    let mut users_by_source: HashMap<String, Vec<_>> = HashMap::new();
    for user in &unique_users {
        let src = if user.source.is_empty() {
            "unknown".to_string()
        } else {
            user.source.clone()
        };
        users_by_source.entry(src).or_default().push(user);
    }
    let mut sources: Vec<String> = users_by_source.keys().cloned().collect();
    sources.sort();
    for src in &sources {
        let users = &users_by_source[src];
        println!("  [{src}] ({})", users.len());
        for user in users {
            let prefix = if user.domain.is_empty() {
                user.username.clone()
            } else {
                format!("{}\\{}", user.domain, user.username)
            };
            let suffix = if user.is_admin { " (admin)" } else { "" };
            println!("    - {prefix}{suffix}");
        }
    }
    println!();

    // Credentials
    let unique_creds = dedup_credentials(&state.all_credentials);
    println!("Credentials ({}):", unique_creds.len());
    for cred in &unique_creds {
        let prefix = if cred.domain.is_empty() {
            cred.username.clone()
        } else {
            format!("{}\\{}", cred.domain, cred.username)
        };
        let suffix = if cred.is_admin { " (admin)" } else { "" };
        println!("  - {prefix}:{}{suffix}", cred.password);
    }
    println!();

    // Hashes
    let unique_hashes = dedup_hashes(&state.all_hashes);
    println!("Hashes ({}):", unique_hashes.len());
    for h in &unique_hashes {
        let prefix = if h.domain.is_empty() {
            h.username.clone()
        } else {
            format!("{}\\{}", h.domain, h.username)
        };
        println!("  - {prefix}:{}:{}", h.hash_type, h.hash_value);
    }
    println!();

    // Shares
    println!("Shares ({}):", state.all_shares.len());
    for share in &state.all_shares {
        let line = if share.host.is_empty() {
            share.name.clone()
        } else {
            format!("{}/{}", share.host, share.name)
        };
        if share.permissions.is_empty() {
            println!("  - {line}");
        } else {
            println!("  - {line} [{}]", share.permissions);
        }
    }
    println!();

    // Weaknesses
    println!("Weaknesses ({}):", state.all_weaknesses.len());
    if state.all_weaknesses.is_empty() {
        println!("  None");
    } else {
        for (i, w) in state.all_weaknesses.iter().enumerate() {
            let title = extract_weakness_title(w);
            println!("  {}. {title}", i + 1);
        }
    }
}

// ============================================================================
// Loot snapshot and diff
// ============================================================================

#[derive(Default)]
pub(crate) struct LootSnapshot {
    pub domains: HashSet<String>,
    pub host_keys: HashSet<(String, String)>,
    pub user_keys: HashSet<(String, String)>,
    pub cred_keys: HashSet<(String, String, String)>,
    pub hash_keys: HashSet<(String, String, String, String)>,
    pub share_keys: HashSet<(String, String)>,
    pub weaknesses: HashSet<String>,
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
        weaknesses: state.all_weaknesses.iter().cloned().collect(),
    }
}

fn print_diff(prev: &LootSnapshot, curr: &LootSnapshot) {
    let new_domains: Vec<_> = curr.domains.difference(&prev.domains).collect();
    let new_hosts: Vec<_> = curr.host_keys.difference(&prev.host_keys).collect();
    let new_users: Vec<_> = curr.user_keys.difference(&prev.user_keys).collect();
    let new_creds: Vec<_> = curr.cred_keys.difference(&prev.cred_keys).collect();
    let new_hashes: Vec<_> = curr.hash_keys.difference(&prev.hash_keys).collect();
    let new_shares: Vec<_> = curr.share_keys.difference(&prev.share_keys).collect();
    let new_weaknesses: Vec<_> = curr.weaknesses.difference(&prev.weaknesses).collect();

    let total = new_domains.len()
        + new_hosts.len()
        + new_users.len()
        + new_creds.len()
        + new_hashes.len()
        + new_shares.len()
        + new_weaknesses.len();

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
    for w in &new_weaknesses {
        println!("  [weakness] {w}");
    }
}
