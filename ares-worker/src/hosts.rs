//! Background `/etc/hosts` management for AD hostname resolution.
//!
//! In Active Directory environments, Kerberos authentication requires hostname
//! resolution. Workers need to resolve DC names and other AD hosts. This module
//! periodically reads discovered hosts from Redis and appends new entries to
//! `/etc/hosts`.
//!
//! For domain controllers, the bare domain name is also added as an alias to
//! enable Kerberos realm resolution (e.g., `192.168.58.10  dc01.contoso.local dc01 contoso.local`).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use tracing::{debug, info, warn};

use ares_core::models::Host;

/// Interval between host sync cycles.
const SYNC_INTERVAL: Duration = Duration::from_secs(30);

/// Build the `/etc/hosts` entries for a list of discovered hosts.
///
/// Returns `(entries, new_written_ips)` — the formatted lines and which IPs
/// were included (for dedup tracking).
pub fn build_host_entries(hosts: &[Host], already_written: &HashSet<String>) -> Vec<String> {
    let mut entries = Vec::new();

    for host in hosts {
        if host.ip.is_empty() || host.hostname.is_empty() {
            continue;
        }
        if already_written.contains(&host.ip) {
            continue;
        }

        let hostname = host.hostname.to_lowercase();
        let parts: Vec<&str> = hostname.split('.').collect();
        let short_name = parts.first().copied().unwrap_or(&hostname);

        // Build aliases: FQDN, short name, and bare domain for DCs
        let mut aliases = vec![hostname.clone()];
        if short_name != hostname {
            aliases.push(short_name.to_string());
        }

        // For domain controllers, add bare domain for Kerberos realm resolution
        if host.is_dc && parts.len() >= 2 {
            let domain = parts[1..].join(".");
            if !domain.is_empty() {
                aliases.push(domain);
            }
        }

        entries.push(format!("{}  {}", host.ip, aliases.join(" ")));
    }

    entries
}

/// Write new host entries to `/etc/hosts`.
///
/// Appends entries in a single write to minimize race conditions.
/// Returns the set of IPs that were successfully written.
fn write_etc_hosts(entries: &[String], agent_name: &str) -> HashSet<String> {
    use std::io::Write;

    let mut written = HashSet::new();

    if entries.is_empty() {
        return written;
    }

    match std::fs::OpenOptions::new().append(true).open("/etc/hosts") {
        Ok(mut f) => {
            let mut buf = format!("\n# Ares discovered hosts ({agent_name})\n");
            for entry in entries {
                buf.push_str(entry);
                buf.push('\n');
                // Extract IP from "IP  hostname ..." format
                if let Some(ip) = entry.split_whitespace().next() {
                    written.insert(ip.to_string());
                }
            }
            if let Err(e) = f.write_all(buf.as_bytes()) {
                warn!("Cannot write to /etc/hosts: {e}");
                return HashSet::new();
            }
            info!(
                count = entries.len(),
                agent = agent_name,
                "Updated /etc/hosts"
            );
            for entry in entries {
                debug!("Added hosts entry: {entry}");
            }
        }
        Err(e) => {
            warn!("Cannot open /etc/hosts for append: {e}");
        }
    }

    written
}

/// Spawn a background task that periodically syncs hosts from Redis to `/etc/hosts`.
///
/// Requires an operation ID to know which Redis key to read from.
/// Returns the join handle.
pub fn spawn_hosts_sync(
    conn: ConnectionManager,
    operation_id: String,
    agent_name: String,
    shutdown: Arc<tokio::sync::Notify>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut conn = conn;
        let mut written_ips: HashSet<String> = HashSet::new();

        let hosts_key = format!("ares:op:{operation_id}:hosts");
        info!(key = %hosts_key, "Starting /etc/hosts sync background task");

        loop {
            tokio::select! {
                _ = tokio::time::sleep(SYNC_INTERVAL) => {}
                _ = shutdown.notified() => {
                    debug!("hosts_sync: shutdown signalled");
                    return;
                }
            }

            // Read hosts from Redis
            let hosts_json: Vec<String> = match conn.lrange(&hosts_key, 0, -1).await {
                Ok(h) => h,
                Err(e) => {
                    debug!("hosts_sync: Redis read failed: {e}");
                    continue;
                }
            };

            let hosts: Vec<Host> = hosts_json
                .iter()
                .filter_map(|json| serde_json::from_str(json).ok())
                .collect();

            let entries = build_host_entries(&hosts, &written_ips);
            if !entries.is_empty() {
                let newly_written = write_etc_hosts(&entries, &agent_name);
                written_ips.extend(newly_written);
            }
        }
    })
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_host(ip: &str, hostname: &str, is_dc: bool) -> Host {
        Host {
            ip: ip.to_string(),
            hostname: hostname.to_string(),
            os: String::new(),
            roles: Vec::new(),
            services: Vec::new(),
            is_dc,
            owned: false,
        }
    }

    #[test]
    fn test_build_host_entries_basic() {
        let hosts = vec![
            make_host("192.168.58.10", "dc01.contoso.local", true),
            make_host("192.168.58.22", "ws01.contoso.local", false),
        ];
        let entries = build_host_entries(&hosts, &HashSet::new());
        assert_eq!(entries.len(), 2);
        // DC entry should have FQDN, short name, and domain
        assert_eq!(
            entries[0],
            "192.168.58.10  dc01.contoso.local dc01 contoso.local"
        );
        // Non-DC entry should have FQDN and short name only
        assert_eq!(entries[1], "192.168.58.22  ws01.contoso.local ws01");
    }

    #[test]
    fn test_build_host_entries_dedup() {
        let hosts = vec![make_host("192.168.58.10", "dc01.contoso.local", true)];
        let mut already_written = HashSet::new();
        already_written.insert("192.168.58.10".to_string());
        let entries = build_host_entries(&hosts, &already_written);
        assert!(entries.is_empty()); // Already written
    }

    #[test]
    fn test_build_host_entries_skip_incomplete() {
        let hosts = vec![
            make_host("", "dc01.contoso.local", true),
            make_host("192.168.58.10", "", true),
        ];
        let entries = build_host_entries(&hosts, &HashSet::new());
        assert!(entries.is_empty()); // Both missing required fields
    }

    #[test]
    fn test_build_host_entries_short_hostname() {
        let hosts = vec![make_host("192.168.58.99", "fileserver", false)];
        let entries = build_host_entries(&hosts, &HashSet::new());
        assert_eq!(entries.len(), 1);
        // Short hostname without domain — no alias needed
        assert_eq!(entries[0], "192.168.58.99  fileserver");
    }

    #[test]
    fn test_build_host_entries_dc_subdomain() {
        let hosts = vec![make_host("192.168.58.15", "dc02.north.contoso.local", true)];
        let entries = build_host_entries(&hosts, &HashSet::new());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0],
            "192.168.58.15  dc02.north.contoso.local dc02 north.contoso.local"
        );
    }

    #[test]
    fn test_build_host_entries_lowercase() {
        let hosts = vec![make_host("192.168.58.10", "DC01.CONTOSO.LOCAL", true)];
        let entries = build_host_entries(&hosts, &HashSet::new());
        assert_eq!(entries.len(), 1);
        assert!(entries[0].contains("dc01.contoso.local")); // Lowercased
    }
}
