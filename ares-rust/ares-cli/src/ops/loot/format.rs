use std::collections::{HashMap, HashSet};

use ares_core::models::SharedRedTeamState;

use crate::dedup::{dedup_credentials, dedup_hashes, dedup_users, extract_weakness_title};

pub(crate) fn print_loot(state: &SharedRedTeamState, json_output: bool) {
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
