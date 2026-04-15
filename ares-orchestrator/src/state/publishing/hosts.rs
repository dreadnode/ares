//! Host and domain controller publishing methods.

use anyhow::Result;
use redis::AsyncCommands;

use ares_core::models::Host;
use ares_core::state::{self, RedisStateReader};

use crate::state::SharedState;
use crate::task_queue::TaskQueue;

use super::is_aws_hostname;

impl SharedState {
    /// Add a host to state and Redis.
    ///
    /// Merges data when a host with the same IP already exists: upgrades DC
    /// status, fills in hostname, and keeps the richer service list.
    /// AWS internal hostnames (e.g. `ip-10-1-2-150.us-west-2.compute.internal`)
    /// are stripped to allow real AD FQDNs to take precedence.
    ///
    /// When the hostname is a valid AD FQDN (e.g. `dc01.contoso.local`), the
    /// domain suffix is automatically extracted and added to `state.domains`
    /// (matches Python's `add_host()` behavior).
    pub async fn publish_host(&self, queue: &TaskQueue, host: Host) -> Result<bool> {
        // Normalize hostname: strip trailing dots and AWS internal names
        let mut host = host;
        host.hostname = host.hostname.trim_end_matches('.').to_lowercase();
        if is_aws_hostname(&host.hostname) {
            host.hostname = String::new();
        }

        // Auto-extract domain from FQDN hostname (matches Python add_host)
        // e.g. "dc02.child.contoso.local" → "child.contoso.local"
        if !host.hostname.is_empty()
            && host.hostname.contains('.')
            && !is_aws_hostname(&host.hostname)
        {
            let hostname_clean = host.hostname.trim_end_matches('.');
            let parts: Vec<&str> = hostname_clean.split('.').collect();
            if parts.len() >= 3 {
                let domain = parts[1..].join(".").to_lowercase();
                // Reject AWS/cloud domains
                if !domain.contains("compute.internal") && !domain.contains("amazonaws.com") {
                    let op_id = self.inner.read().await.operation_id.clone();
                    let mut state = self.inner.write().await;
                    if !state.domains.contains(&domain) {
                        state.domains.push(domain.clone());
                        let domain_key =
                            format!("{}:{}:{}", state::KEY_PREFIX, op_id, state::KEY_DOMAINS,);
                        let mut conn = queue.connection();
                        let _: Result<(), _> =
                            redis::AsyncCommands::sadd(&mut conn, &domain_key, &domain).await;
                        let _: Result<(), _> =
                            redis::AsyncCommands::expire(&mut conn, &domain_key, 86400i64).await;
                        tracing::info!(
                            hostname = %host.hostname,
                            domain = %domain,
                            "Auto-extracted domain from host FQDN"
                        );
                    }
                }

                // Auto-populate netbios_to_fqdn map so CLI can resolve short names.
                // e.g. "dc02.child.contoso.local" → DC02 → dc02.child.contoso.local
                let short_name = parts[0].to_uppercase();
                let fqdn = host.hostname.to_lowercase();
                let _ = self.publish_netbios(queue, &short_name, &fqdn).await;
            }
        }

        // Check for existing host with same IP or hostname and merge if the
        // new entry brings richer data (DC detection, more services, hostname).
        // Returns (needs_dc_registration, was_merged_and_changed).
        let (needs_dc_registration, merged_changed) = {
            let mut state = self.inner.write().await;
            // Look up by IP first, then fall back to hostname match
            let existing_idx = state
                .hosts
                .iter()
                .position(|h| !h.ip.is_empty() && h.ip == host.ip)
                .or_else(|| {
                    if !host.hostname.is_empty() {
                        state.hosts.iter().position(|h| {
                            !h.hostname.is_empty()
                                && h.hostname.eq_ignore_ascii_case(&host.hostname)
                        })
                    } else {
                        None
                    }
                });
            if let Some(existing) = existing_idx.map(|i| &mut state.hosts[i]) {
                // Merge IP if incoming has one and existing doesn't
                if !host.ip.is_empty() && existing.ip.is_empty() {
                    existing.ip = host.ip.clone();
                }
                let new_is_dc = host.is_dc || host.detect_dc();
                let was_dc = existing.is_dc;
                let had_hostname = !existing.hostname.is_empty();
                let mut changed = false;

                if new_is_dc && !existing.is_dc {
                    existing.is_dc = true;
                    changed = true;
                }
                // Strip AWS hostname from existing entry too
                if is_aws_hostname(&existing.hostname) {
                    existing.hostname = String::new();
                    changed = true;
                }
                if !host.hostname.is_empty() && existing.hostname.is_empty() {
                    existing.hostname = host.hostname.clone();
                    changed = true;
                }
                for svc in &host.services {
                    if !existing.services.contains(svc) {
                        existing.services.push(svc.clone());
                        changed = true;
                    }
                }
                if !host.os.is_empty() && existing.os.is_empty() {
                    existing.os = host.os.clone();
                    changed = true;
                }
                if !host.roles.is_empty() && existing.roles.is_empty() {
                    existing.roles = host.roles.clone();
                    changed = true;
                }

                if !changed {
                    return Ok(false);
                }

                // Re-register DC if it just became a DC, or if its hostname
                // was just filled in (so we can correct the domain mapping).
                let is_dc_now = existing.is_dc;
                let has_hostname_now = !existing.hostname.is_empty();
                let needs_dc =
                    (is_dc_now && !was_dc) || (is_dc_now && has_hostname_now && !had_hostname);
                (needs_dc, true)
            } else {
                // No existing host — will be added below
                (false, false)
            }
        };

        // Register netbios mapping for merged host if hostname was updated
        if merged_changed {
            let state = self.inner.read().await;
            if let Some(merged) = state.hosts.iter().find(|h| h.ip == host.ip) {
                if merged.hostname.contains('.') {
                    let parts: Vec<&str> = merged.hostname.split('.').collect();
                    if parts.len() >= 3 {
                        let short = parts[0].to_uppercase();
                        let fqdn = merged.hostname.to_lowercase();
                        drop(state);
                        let _ = self.publish_netbios(queue, &short, &fqdn).await;
                    }
                }
            }
        }

        // Persist merged host to Redis LIST (find-by-IP and LSET).
        if merged_changed {
            let state = self.inner.read().await;
            if let Some(merged) = state.hosts.iter().find(|h| h.ip == host.ip) {
                let op_id = &state.operation_id;
                let host_key = format!("{}:{}:{}", state::KEY_PREFIX, op_id, state::KEY_HOSTS,);
                let merged_json = serde_json::to_string(merged).unwrap_or_default();
                let mut conn = queue.connection();
                // Scan the Redis LIST to find the index matching this IP
                let entries: Vec<String> =
                    redis::AsyncCommands::lrange(&mut conn, &host_key, 0, -1)
                        .await
                        .unwrap_or_default();
                for (idx, entry) in entries.iter().enumerate() {
                    if let Ok(h) = serde_json::from_str::<Host>(entry) {
                        if h.ip == host.ip {
                            let _: Result<(), _> = redis::AsyncCommands::lset(
                                &mut conn,
                                &host_key,
                                idx as isize,
                                &merged_json,
                            )
                            .await;
                            break;
                        }
                    }
                }
            }
        }

        // If we merged into an existing host and it became/updated as DC, register it
        if needs_dc_registration {
            let host_snapshot = {
                let state = self.inner.read().await;
                state
                    .hosts
                    .iter()
                    .find(|h| h.ip == host.ip)
                    .cloned()
                    .unwrap()
            };
            self.register_dc(queue, &host_snapshot).await?;
            return Ok(true);
        }

        // If the host already existed (was merged), we're done
        {
            let state = self.inner.read().await;
            if state.hosts.iter().any(|h| h.ip == host.ip) {
                return Ok(true);
            }
        }

        // New host — add to Redis and state
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        reader.add_host(&mut conn, &host).await?;

        // Update DC map and domain list if this is a domain controller
        if host.is_dc || host.detect_dc() {
            self.register_dc(queue, &host).await?;
            let mut state = self.inner.write().await;
            state.hosts.push(host);
            return Ok(true);
        }

        let mut state = self.inner.write().await;
        state.hosts.push(host);
        Ok(true)
    }

    /// Register a host as a domain controller: update DC map and domain list.
    ///
    /// Domain is derived from the FQDN hostname (e.g. `dc01.contoso.local` → `contoso.local`).
    /// If the hostname is empty or not a valid AD FQDN, we fall back to the first domain
    /// already in state (from the target_domain config). This ensures DCs discovered by
    /// recon are registered even before their FQDN is known.
    pub(crate) async fn register_dc(&self, queue: &TaskQueue, host: &Host) -> Result<()> {
        // Extract domain from hostname — prefer a real FQDN
        let raw_domain = if !host.hostname.is_empty() {
            host.hostname
                .split('.')
                .skip(1)
                .collect::<Vec<_>>()
                .join(".")
        } else {
            String::new()
        };

        // If we can't derive a domain from the hostname, fall back to the
        // target domain already in state. This unblocks automation for DCs
        // discovered before their FQDN is resolved.
        let raw_domain = if raw_domain.is_empty()
            || raw_domain.contains("compute.internal")
            || raw_domain.contains("amazonaws.com")
        {
            let state = self.inner.read().await;
            if let Some(fallback) = state.domains.first().cloned() {
                tracing::info!(
                    ip = %host.ip,
                    hostname = %host.hostname,
                    fallback_domain = %fallback,
                    "DC registration: using fallback domain (no FQDN available)"
                );
                fallback
            } else {
                tracing::debug!(
                    ip = %host.ip,
                    hostname = %host.hostname,
                    "Skipping DC registration: no FQDN and no fallback domain in state"
                );
                return Ok(());
            }
        } else {
            raw_domain
        };

        let domain = raw_domain;
        let domain_lower = domain.to_lowercase();

        let mut conn = queue.connection();
        let op_id = self.inner.read().await.operation_id.clone();
        let dc_key = format!("{}:{}:{}", state::KEY_PREFIX, op_id, state::KEY_DC_MAP);

        // Remove any stale mapping that pointed this IP to a different domain
        {
            let state = self.inner.read().await;
            let stale_domains: Vec<String> = state
                .domain_controllers
                .iter()
                .filter(|(d, ip)| *ip == &host.ip && **d != domain_lower)
                .map(|(d, _)| d.clone())
                .collect();
            for stale in &stale_domains {
                tracing::info!(
                    ip = %host.ip,
                    old_domain = %stale,
                    new_domain = %domain_lower,
                    "Correcting DC domain mapping"
                );
                let _: () = conn.hdel(&dc_key, stale).await?;
            }
            // Remove stale entries from state (done below under write lock)
        }

        let _: () = conn.hset(&dc_key, &domain_lower, &host.ip).await?;

        // Add domain to state and Redis, correct stale mappings
        let mut state = self.inner.write().await;

        // Remove stale domain → IP mappings for this IP
        state
            .domain_controllers
            .retain(|d, ip| !(ip == &host.ip && *d != domain_lower));

        // Insert or update the mapping
        state
            .domain_controllers
            .insert(domain_lower.clone(), host.ip.clone());

        if !state.domains.contains(&domain_lower) {
            state.domains.push(domain_lower.clone());
            let domain_key = format!("{}:{}:{}", state::KEY_PREFIX, op_id, state::KEY_DOMAINS);
            let _: () = conn.sadd(&domain_key, &domain_lower).await?;
            let _: () = conn.expire(&domain_key, 86400).await?;
        }

        tracing::info!(
            ip = %host.ip,
            domain = %domain_lower,
            "Registered domain controller"
        );

        Ok(())
    }
}
