//! Host and domain controller publishing methods.

use anyhow::Result;
use redis::AsyncCommands;

use ares_core::models::{Host, OpStateEventPayload};
use ares_core::state::{self, RedisStateReader};

use redis::aio::ConnectionLike;

use crate::orchestrator::state::SharedState;
use crate::orchestrator::task_queue::TaskQueueCore;

use super::{emit_op_state, is_aws_hostname};

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
    pub async fn publish_host(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        host: Host,
    ) -> Result<bool> {
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
        let reader = RedisStateReader::new(operation_id.clone());
        let mut conn = queue.connection();
        reader.add_host(&mut conn, &host).await?;

        // Phase 2 dual-write: emit host.discovered for net-new hosts only.
        // Merges return earlier; HostUpdated is intentionally not yet a variant.
        emit_op_state(
            self.recorder(),
            &operation_id,
            OpStateEventPayload::HostDiscovered { host: host.clone() },
        )
        .await;

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
    pub(crate) async fn register_dc(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        host: &Host,
    ) -> Result<()> {
        // Require at least 3 dot-separated parts (e.g. dc03.contoso.local)
        // so 2-part hostnames like "HOSTNAME.local" don't yield "local" as the domain.
        let raw_domain = if !host.hostname.is_empty() {
            let parts: Vec<&str> = host.hostname.split('.').collect();
            if parts.len() >= 3 {
                parts[1..].join(".")
            } else {
                String::new()
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::state::SharedState;
    use crate::orchestrator::task_queue::TaskQueueCore;
    use ares_core::state::mock_redis::MockRedisConnection;

    fn mock_queue() -> TaskQueueCore<MockRedisConnection> {
        TaskQueueCore::from_connection(MockRedisConnection::new())
    }

    fn make_host(ip: &str, hostname: &str, is_dc: bool) -> Host {
        Host {
            ip: ip.to_string(),
            hostname: hostname.to_string(),
            os: String::new(),
            roles: vec![],
            services: vec![],
            is_dc,
            owned: false,
        }
    }

    #[tokio::test]
    async fn publish_host_adds_new_host() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let host = make_host("192.168.58.5", "srv01.contoso.local", false);
        let added = state.publish_host(&q, host).await.unwrap();
        assert!(added);

        let s = state.inner.read().await;
        assert_eq!(s.hosts.len(), 1);
        assert_eq!(s.hosts[0].ip, "192.168.58.5");
        assert_eq!(s.hosts[0].hostname, "srv01.contoso.local");
    }

    #[tokio::test]
    async fn publish_host_extracts_domain_from_fqdn() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let host = make_host("192.168.58.5", "srv01.contoso.local", false);
        state.publish_host(&q, host).await.unwrap();

        let s = state.inner.read().await;
        assert!(s.domains.contains(&"contoso.local".to_string()));
    }

    #[tokio::test]
    async fn publish_host_strips_aws_hostname() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let host = make_host(
            "192.168.58.150",
            "ip-10-1-2-150.us-west-2.compute.internal",
            false,
        );
        state.publish_host(&q, host).await.unwrap();

        let s = state.inner.read().await;
        assert_eq!(s.hosts[0].hostname, "");
    }

    #[tokio::test]
    async fn publish_host_merges_services() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let mut host1 = make_host("192.168.58.5", "srv01.contoso.local", false);
        host1.services = vec!["445/tcp".to_string()];
        state.publish_host(&q, host1).await.unwrap();

        let mut host2 = make_host("192.168.58.5", "", false);
        host2.services = vec!["445/tcp".to_string(), "139/tcp".to_string()];
        state.publish_host(&q, host2).await.unwrap();

        let s = state.inner.read().await;
        assert_eq!(s.hosts.len(), 1);
        assert!(s.hosts[0].services.contains(&"445/tcp".to_string()));
        assert!(s.hosts[0].services.contains(&"139/tcp".to_string()));
    }

    #[tokio::test]
    async fn publish_host_merges_hostname() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        // First add host without hostname
        let host1 = make_host("192.168.58.5", "", false);
        state.publish_host(&q, host1).await.unwrap();

        // Then add same IP with hostname — should merge
        let host2 = make_host("192.168.58.5", "srv01.contoso.local", false);
        state.publish_host(&q, host2).await.unwrap();

        let s = state.inner.read().await;
        assert_eq!(s.hosts.len(), 1);
        assert_eq!(s.hosts[0].hostname, "srv01.contoso.local");
    }

    #[tokio::test]
    async fn publish_host_upgrades_dc_status() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        // Add as normal host first, then add with DC status
        {
            let mut s = state.inner.write().await;
            s.domains.push("contoso.local".to_string());
        }
        let host1 = make_host("192.168.58.1", "", false);
        state.publish_host(&q, host1).await.unwrap();

        let host2 = make_host("192.168.58.1", "dc01.contoso.local", true);
        state.publish_host(&q, host2).await.unwrap();

        let s = state.inner.read().await;
        assert_eq!(s.hosts.len(), 1);
        assert!(s.hosts[0].is_dc);
        assert!(s.domain_controllers.contains_key("contoso.local"));
    }

    #[tokio::test]
    async fn publish_host_no_change_returns_false() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let host1 = make_host("192.168.58.5", "srv01.contoso.local", false);
        assert!(state.publish_host(&q, host1).await.unwrap());

        // Identical host — no new data to merge
        let host2 = make_host("192.168.58.5", "", false);
        let result = state.publish_host(&q, host2).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn publish_dc_host_registers_dc() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let host = make_host("192.168.58.1", "dc01.contoso.local", true);
        state.publish_host(&q, host).await.unwrap();

        let s = state.inner.read().await;
        assert!(s.hosts[0].is_dc);
        assert_eq!(
            s.domain_controllers.get("contoso.local"),
            Some(&"192.168.58.1".to_string())
        );
    }

    #[tokio::test]
    async fn register_dc_adds_domain() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let host = make_host("192.168.58.1", "dc01.contoso.local", true);
        state.register_dc(&q, &host).await.unwrap();

        let s = state.inner.read().await;
        assert!(s.domains.contains(&"contoso.local".to_string()));
        assert_eq!(
            s.domain_controllers.get("contoso.local"),
            Some(&"192.168.58.1".to_string())
        );
    }

    #[tokio::test]
    async fn register_dc_fallback_domain() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        // Pre-populate a domain so the fallback works
        {
            let mut s = state.inner.write().await;
            s.domains.push("contoso.local".to_string());
        }

        // Host with no FQDN — should fall back to existing domain
        let host = make_host("192.168.58.1", "", true);
        state.register_dc(&q, &host).await.unwrap();

        let s = state.inner.read().await;
        assert_eq!(
            s.domain_controllers.get("contoso.local"),
            Some(&"192.168.58.1".to_string())
        );
    }

    #[tokio::test]
    async fn register_dc_no_domain_skips() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        // No domain in state, no FQDN on host — should skip
        let host = make_host("192.168.58.1", "", true);
        state.register_dc(&q, &host).await.unwrap();

        let s = state.inner.read().await;
        assert!(s.domain_controllers.is_empty());
    }

    #[tokio::test]
    async fn register_dc_two_part_hostname_uses_fallback() {
        // Hostname with only 2 parts (e.g. "DC01.local") must NOT register
        // "local" as the domain. With a fallback domain already in state,
        // register_dc should use the fallback instead.
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();
        {
            let mut s = state.inner.write().await;
            s.domains.push("contoso.local".to_string());
        }

        let host = make_host("192.168.58.1", "DC01.local", true);
        state.register_dc(&q, &host).await.unwrap();

        let s = state.inner.read().await;
        // Must NOT have registered just "local" as a domain
        assert!(
            !s.domain_controllers.contains_key("local"),
            "two-part hostname leaked 'local' as a domain"
        );
        assert_eq!(
            s.domain_controllers.get("contoso.local"),
            Some(&"192.168.58.1".to_string()),
            "expected fallback to existing domain"
        );
    }

    #[tokio::test]
    async fn register_dc_two_part_hostname_no_fallback_skips() {
        // 2-part hostname AND no fallback domain → skip entirely instead of
        // registering a TLD as the AD domain.
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let host = make_host("192.168.58.1", "DC01.local", true);
        state.register_dc(&q, &host).await.unwrap();

        let s = state.inner.read().await;
        assert!(
            s.domain_controllers.is_empty(),
            "2-part hostname with no fallback must skip DC registration"
        );
        assert!(
            !s.domains.iter().any(|d| d == "local"),
            "2-part hostname leaked 'local' into domains"
        );
    }

    #[tokio::test]
    async fn register_dc_three_part_hostname_extracts_full_domain() {
        // Sanity check the >=3 parts branch with a deeper FQDN to make sure
        // the parts[1..].join(".") slice is right (not just the last label).
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let host = make_host("192.168.58.1", "dc.eu.contoso.local", true);
        state.register_dc(&q, &host).await.unwrap();

        let s = state.inner.read().await;
        assert_eq!(
            s.domain_controllers.get("eu.contoso.local"),
            Some(&"192.168.58.1".to_string())
        );
    }

    #[tokio::test]
    async fn publish_host_strips_trailing_dot() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let host = make_host("192.168.58.5", "srv01.contoso.local.", false);
        state.publish_host(&q, host).await.unwrap();

        let s = state.inner.read().await;
        assert_eq!(s.hosts[0].hostname, "srv01.contoso.local");
    }

    #[tokio::test]
    async fn publish_host_merges_os() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let host1 = make_host("192.168.58.5", "srv01.contoso.local", false);
        state.publish_host(&q, host1).await.unwrap();

        let mut host2 = make_host("192.168.58.5", "", false);
        host2.os = "Windows Server 2019".to_string();
        state.publish_host(&q, host2).await.unwrap();

        let s = state.inner.read().await;
        assert_eq!(s.hosts[0].os, "Windows Server 2019");
    }

    #[tokio::test]
    async fn publish_host_emits_event_for_net_new_host() {
        let recorder = std::sync::Arc::new(ares_core::op_state_log::OpStateRecorder::capturing());
        let state = SharedState::with_recorder("op-host".to_string(), recorder.clone());
        let q = mock_queue();

        let host = make_host("192.168.58.7", "ws01.contoso.local", false);
        state.publish_host(&q, host).await.unwrap();

        let evs = recorder.captured().await;
        assert!(evs.iter().any(|e| matches!(
            &e.payload,
            OpStateEventPayload::HostDiscovered { host } if host.ip == "192.168.58.7"
        )));
    }

    #[tokio::test]
    async fn publish_host_merge_does_not_emit_host_discovered() {
        // A merge into an existing host returns early before the new-host path,
        // so HostDiscovered must not fire a second time.
        let recorder = std::sync::Arc::new(ares_core::op_state_log::OpStateRecorder::capturing());
        let state = SharedState::with_recorder("op-merge".to_string(), recorder.clone());
        let q = mock_queue();

        state
            .publish_host(&q, make_host("192.168.58.8", "", false))
            .await
            .unwrap();
        let after_first = recorder.captured().await.len();

        // Second publish with richer data should merge, not emit.
        let mut host2 = make_host("192.168.58.8", "srv02.contoso.local", false);
        host2.services.push("445/tcp microsoft-ds".to_string());
        state.publish_host(&q, host2).await.unwrap();
        let after_merge = recorder.captured().await.len();

        let host_events_added = recorder
            .captured()
            .await
            .iter()
            .filter(|e| matches!(e.payload, OpStateEventPayload::HostDiscovered { .. }))
            .count();
        assert_eq!(
            host_events_added, 1,
            "merge must not re-emit HostDiscovered"
        );
        // The non-host events (e.g. netbios publish doesn't emit) shouldn't grow either.
        assert_eq!(after_first, after_merge);
    }
}
