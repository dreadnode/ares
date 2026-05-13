//! Host and domain controller publishing methods.

use anyhow::Result;
use redis::AsyncCommands;

use ares_core::models::{DomainEvidence, Host, OpStateEventPayload};
use ares_core::state::{self, RedisStateReader};

use redis::aio::ConnectionLike;

use crate::orchestrator::state::SharedState;
use crate::orchestrator::task_queue::TaskQueueCore;

use super::{emit_op_state, looks_like_real_domain, strip_netexec_artifact};

impl SharedState {
    /// Add a host to state and Redis.
    ///
    /// Merges data when a host with the same IP already exists: upgrades DC
    /// status, fills in hostname, and keeps the richer service list. Hostnames
    /// that can't be a real AD FQDN — cloud PTRs, default-OS auto-names,
    /// mDNS, bare TLDs — are cleared via `looks_like_real_domain` so a real
    /// FQDN can take precedence later.
    ///
    /// When the hostname is a valid AD FQDN (e.g. `dc01.contoso.local`), the
    /// domain suffix is automatically extracted and added to `state.domains`
    /// (matches Python's `add_host()` behavior).
    pub async fn publish_host(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        host: Host,
    ) -> Result<bool> {
        // NetExec sometimes appends "0." to domain names (e.g.
        // "dc01.contoso.local0." → "dc01.contoso.local"). Strip that, then
        // drop any multi-label hostname that fails the unified shape filter.
        let mut host = host;
        host.hostname = strip_netexec_artifact(&host.hostname).to_lowercase();
        if host.hostname.contains('.') && !looks_like_real_domain(&host.hostname) {
            host.hostname = String::new();
        }
        // Some upstream parsers (esp. Python tool output stringifying `None`)
        // emit literal placeholder strings as the hostname. These are never a
        // real machine name — clear them so the display falls back to IP-only
        // instead of `none / <ip>`.
        if matches!(
            host.hostname.as_str(),
            "none" | "null" | "unknown" | "(none)" | "(null)" | "n/a" | "-"
        ) {
            host.hostname = String::new();
        }

        // Reject malformed multi-IP `host.ip` fields. Some parsers receive a
        // target list (comma- or space-separated) as the `target` param and
        // store the whole string verbatim in `host.ip`. `dedup_hosts` then
        // rescues the malformed value into the hostname field for display,
        // producing phantom rows like `- 1.2.3.4,5.6.7.8 / (empty)`. Reject
        // anything that doesn't parse as a single IpAddr at the boundary.
        // Empty IP is allowed (hostname-only hosts are a legitimate shape).
        if !host.ip.is_empty() && host.ip.parse::<std::net::IpAddr>().is_err() {
            tracing::debug!(
                ip = %host.ip,
                "Skipping host publish: ip field is not a single valid address"
            );
            return Ok(false);
        }

        // Self-IP guard: an SMB sweep from the attacker pivot will hit its own
        // NIC and produce a "host" record for the pivot box itself. Skip it
        // silently — we don't want to count, scan, or attack ourselves. The
        // self_ips set is empty in tests (StateInner::new() default), so this
        // is a no-op outside of `orchestrator::run`, which calls
        // `initialize_self_ips()` at startup.
        if let Ok(parsed) = host.ip.parse::<std::net::IpAddr>() {
            if self.inner.read().await.self_ips.contains(&parsed) {
                tracing::debug!(
                    ip = %host.ip,
                    "Skipping host publish: IP matches orchestrator's own interface"
                );
                return Ok(false);
            }
        }

        // Auto-extract domain from FQDN hostname (matches Python add_host).
        // e.g. "dc02.child.contoso.local" → "child.contoso.local". Routed
        // through the candidate-domain pipeline: a hostname split alone is
        // weak evidence and won't reach `state.domains` unless a stronger
        // source (target config, DC self-report, probe) confirms it.
        if looks_like_real_domain(&host.hostname) {
            let hostname_clean = host.hostname.trim_end_matches('.');
            let parts: Vec<&str> = hostname_clean.split('.').collect();
            if parts.len() >= 3 {
                let domain = parts[1..].join(".").to_lowercase();
                // A DC FQDN is the DC self-reporting its own domain — strong
                // enough to bypass the candidate hold.
                let evidence = if host.is_dc || host.detect_dc() {
                    DomainEvidence::DcSelfReport
                } else {
                    DomainEvidence::HostnameInference
                };
                let _ = self
                    .publish_candidate_domain(queue, &domain, evidence, Some(host.ip.clone()))
                    .await;

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
                let had_fqdn = existing.hostname.contains('.');
                let mut changed = false;

                if new_is_dc && !existing.is_dc {
                    existing.is_dc = true;
                    changed = true;
                }
                // Drop unusable hostnames on the existing entry too so a
                // later real FQDN merge can replace them.
                if existing.hostname.contains('.') && !looks_like_real_domain(&existing.hostname) {
                    existing.hostname = String::new();
                    changed = true;
                }
                // Upgrade short name to FQDN when a better hostname arrives.
                // Without this, the short name (e.g. "dc01") sticks
                // and `register_dc` can't derive a domain from it, which
                // forces the ambiguous fallback path and mis-maps DCs.
                let upgrade_to_fqdn = host.hostname.contains('.')
                    && !existing.hostname.contains('.')
                    && host
                        .hostname
                        .to_lowercase()
                        .starts_with(&format!("{}.", existing.hostname.to_lowercase()));
                if (!host.hostname.is_empty() && existing.hostname.is_empty()) || upgrade_to_fqdn {
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
                // was upgraded to (or first set to) an FQDN — that's when we
                // can finally derive the correct domain instead of guessing.
                let is_dc_now = existing.is_dc;
                let has_fqdn_now = existing.hostname.contains('.');
                let needs_dc = (is_dc_now && !was_dc) || (is_dc_now && has_fqdn_now && !had_fqdn);
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
        // `looks_like_real_domain` enforces the unified hostname-shape rules
        // (cloud PTRs, default-OS auto-names, mDNS, bare TLDs). After it
        // passes, also require ≥3 dot-separated parts so 2-label names like
        // `DC01.local` don't yield `local` as the AD domain.
        let derived = if looks_like_real_domain(&host.hostname) {
            let parts: Vec<&str> = host.hostname.split('.').collect();
            if parts.len() >= 3 {
                parts[1..].join(".").to_lowercase()
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        // The DC's own FQDN is a self-report — strongest evidence we have
        // short of a CLDAP probe. Push it through `publish_candidate_domain`
        // so cloud / default-OS shapes are filtered consistently with other
        // discovery paths.
        let mut domain = String::new();
        if !derived.is_empty() {
            let outcome = self
                .publish_candidate_domain(
                    queue,
                    derived.clone(),
                    DomainEvidence::DcSelfReport,
                    Some(host.ip.clone()),
                )
                .await?;
            if matches!(outcome, super::DomainPublishOutcome::Promoted) {
                domain = derived;
            }
        }

        // If the FQDN was unusable (missing, rejected, or short), fall back to
        // the sole known authoritative domain. With ≥2 domains, "first" is a
        // guess that mis-maps DCs to the wrong domain — that bad mapping
        // survives later cleanup since `register_dc` only purges stale entries
        // by IP, so a subsequent correct registration with a *different* IP
        // can't dislodge the wrong (domain, ip) pair. Skip and let the next
        // FQDN-bearing discovery populate the entry.
        if domain.is_empty() {
            let state = self.inner.read().await;
            if state.domains.len() == 1 {
                let fallback = state.domains[0].clone();
                tracing::info!(
                    ip = %host.ip,
                    hostname = %host.hostname,
                    fallback_domain = %fallback,
                    "DC registration: using fallback domain (no usable FQDN)"
                );
                domain = fallback;
            } else {
                tracing::debug!(
                    ip = %host.ip,
                    hostname = %host.hostname,
                    known_domains = state.domains.len(),
                    "Skipping DC registration: no usable FQDN and ambiguous fallback domain"
                );
                return Ok(());
            }
        }

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
        }

        let _: () = conn.hset(&dc_key, &domain_lower, &host.ip).await?;

        let mut state = self.inner.write().await;
        state
            .domain_controllers
            .retain(|d, ip| !(ip == &host.ip && *d != domain_lower));
        state
            .domain_controllers
            .insert(domain_lower.clone(), host.ip.clone());

        tracing::info!(
            ip = %host.ip,
            domain = %domain_lower,
            "Registered domain controller"
        );

        Ok(())
    }

    /// Mark a host as owned (admin access confirmed).
    ///
    /// This persists the owned flag to both in-memory state and Redis so
    /// that automations like `auto_lsassy_dump` and `credential_expansion`
    /// can react to host ownership changes.
    pub async fn mark_host_owned(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        ip: &str,
    ) -> Result<()> {
        let (host_json, op_id) = {
            let mut state = self.inner.write().await;
            let host = state.hosts.iter_mut().find(|h| h.ip == ip);
            if let Some(h) = host {
                if h.owned {
                    return Ok(()); // already owned
                }
                h.owned = true;
                tracing::info!(ip = %ip, hostname = %h.hostname, "Host marked as owned");
                let json = serde_json::to_string(h).unwrap_or_default();
                (json, state.operation_id.clone())
            } else {
                // Host not yet in state — create a minimal entry so downstream
                // automations (lsassy_dump, credential_expansion) can fire.
                // This happens when secretsdump succeeds before host discovery.
                let new_host = Host {
                    ip: ip.to_string(),
                    hostname: ip.to_string(), // will be enriched by later discovery
                    os: String::new(),
                    roles: Vec::new(),
                    services: Vec::new(),
                    is_dc: state.domain_controllers.values().any(|dc| dc == ip),
                    owned: true,
                };
                tracing::info!(ip = %ip, "Host not in state — creating owned entry");
                let json = serde_json::to_string(&new_host).unwrap_or_default();
                let op_id = state.operation_id.clone();
                state.hosts.push(new_host);
                (json, op_id)
            }
        };

        // Persist to Redis
        let host_key = format!("{}:{}:{}", state::KEY_PREFIX, op_id, state::KEY_HOSTS);
        let mut conn = queue.connection();
        let entries: Vec<String> = redis::AsyncCommands::lrange(&mut conn, &host_key, 0, -1)
            .await
            .unwrap_or_default();
        let mut found = false;
        for (idx, entry) in entries.iter().enumerate() {
            if let Ok(existing) = serde_json::from_str::<Host>(entry) {
                if existing.ip == ip {
                    let _: Result<(), _> =
                        redis::AsyncCommands::lset(&mut conn, &host_key, idx as isize, &host_json)
                            .await;
                    found = true;
                    break;
                }
            }
        }
        if !found {
            // New host entry — append to Redis list
            let _: Result<(), _> =
                redis::AsyncCommands::rpush(&mut conn, &host_key, &host_json).await;
        }
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
    async fn publish_host_holds_inferred_domain_as_candidate() {
        // A non-DC host's FQDN suffix is weak evidence — the suffix should
        // land in candidate_domains, NOT state.domains, until corroborated.
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let host = make_host("192.168.58.5", "srv01.contoso.local", false);
        state.publish_host(&q, host).await.unwrap();

        let s = state.inner.read().await;
        assert!(
            !s.domains.contains(&"contoso.local".to_string()),
            "non-DC FQDN must not auto-promote into state.domains"
        );
        assert!(
            s.candidate_domains.contains_key("contoso.local"),
            "non-DC FQDN should be recorded as a candidate"
        );
    }

    #[tokio::test]
    async fn publish_host_promotes_inferred_domain_when_matches_target() {
        // If the operation's target.domain matches the inferred suffix, it's
        // corroborated and promotes immediately.
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();
        {
            let mut s = state.inner.write().await;
            s.target = Some(ares_core::models::Target {
                ip: "192.168.58.10".into(),
                hostname: String::new(),
                domain: "contoso.local".into(),
                environment: String::new(),
            });
        }
        let host = make_host("192.168.58.5", "srv01.contoso.local", false);
        state.publish_host(&q, host).await.unwrap();

        let s = state.inner.read().await;
        assert!(s.domains.contains(&"contoso.local".to_string()));
    }

    #[tokio::test]
    async fn publish_host_promotes_dc_self_report() {
        // A DC's own FQDN is a self-report — auto-promotes without corroboration.
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let host = make_host("192.168.58.1", "dc01.contoso.local", true);
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
    async fn register_dc_skips_ambiguous_fallback_with_multiple_domains() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        // Two domains in state — fallback would be a guess.
        {
            let mut s = state.inner.write().await;
            s.domains.push("contoso.local".to_string());
            s.domains.push("fabrikam.local".to_string());
        }

        // DC discovered with no FQDN — must NOT pick the first domain,
        // because that would mis-map (e.g. parent DC under child domain)
        // and the bad mapping survives later cleanup.
        let host = make_host("192.168.58.1", "", true);
        state.register_dc(&q, &host).await.unwrap();

        let s = state.inner.read().await;
        assert!(
            s.domain_controllers.is_empty(),
            "must skip registration when fallback domain is ambiguous"
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
    async fn publish_host_upgrades_short_hostname_to_fqdn_and_reregisters_dc() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        // Pre-populate two domains so the ambiguous fallback would fire
        // if FQDN derivation didn't work.
        {
            let mut s = state.inner.write().await;
            s.domains.push("contoso.local".to_string());
            s.domains.push("fabrikam.local".to_string());
        }

        // First sighting: short name only — register_dc must skip (ambiguous).
        let h1 = make_host("192.168.58.1", "dc01", true);
        state.publish_host(&q, h1).await.unwrap();
        {
            let s = state.inner.read().await;
            assert!(s.domain_controllers.is_empty());
            assert_eq!(s.hosts[0].hostname, "dc01");
        }

        // Second sighting: FQDN. Must upgrade hostname AND trigger
        // re-registration so the DC lands under the correct domain.
        let h2 = make_host("192.168.58.1", "dc01.fabrikam.local", true);
        state.publish_host(&q, h2).await.unwrap();

        let s = state.inner.read().await;
        assert_eq!(s.hosts[0].hostname, "dc01.fabrikam.local");
        assert_eq!(
            s.domain_controllers.get("fabrikam.local"),
            Some(&"192.168.58.1".to_string()),
            "DC must register under the domain derived from the upgraded FQDN"
        );
        assert!(
            !s.domain_controllers.contains_key("contoso.local"),
            "must not also register under the wrong (first) domain"
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
    async fn publish_host_rejects_default_windows_hostname_as_domain() {
        // Regression: a non-domain-joined Windows host with the default
        // `WIN-XXXX` hostname must NOT have its FQDN auto-extracted as a
        // bogus AD domain (e.g. `win-hvtt4f8yn5n.ttb0.local`).
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let host = make_host(
            "192.168.58.178",
            "win-hvtt4f8yn5n.win-hvtt4f8yn5n.ttb0.local",
            false,
        );
        state.publish_host(&q, host).await.unwrap();

        let s = state.inner.read().await;
        assert!(
            !s.domains.iter().any(|d| d.contains("win-")),
            "default Windows hostname leaked into state.domains: {:?}",
            s.domains
        );
        assert!(
            !s.candidate_domains
                .keys()
                .any(|d| d.contains("win-") || d.contains("ttb0.local")),
            "default Windows hostname leaked into candidate_domains: {:?}",
            s.candidate_domains
        );
    }

    #[tokio::test]
    async fn publish_host_rejects_desktop_oobe_hostname() {
        // Win10/11 OOBE default `DESKTOP-XXXXXXX` should be filtered too —
        // generalizes the cross-OS pre-filter beyond `WIN-` server names.
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let host = make_host("192.168.58.179", "desktop-abc1234.workgroup.local", false);
        state.publish_host(&q, host).await.unwrap();

        let s = state.inner.read().await;
        assert!(s.domains.is_empty());
        assert!(
            s.candidate_domains.is_empty(),
            "desktop-* hostname leaked: {:?}",
            s.candidate_domains
        );
    }

    #[tokio::test]
    async fn register_dc_rejects_default_windows_hostname_no_fallback() {
        // Even if a host is mis-detected as a DC, a default-Windows FQDN
        // must not be accepted as the AD domain.
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let host = make_host("192.168.58.178", "win-hvtt4f8yn5n.ttb0.local", true);
        state.register_dc(&q, &host).await.unwrap();

        let s = state.inner.read().await;
        assert!(
            s.domain_controllers.is_empty(),
            "default Windows FQDN must not register as a DC domain"
        );
        assert!(
            !s.domains.iter().any(|d| d.contains("win-")),
            "default Windows FQDN leaked into state.domains: {:?}",
            s.domains
        );
    }

    #[tokio::test]
    async fn register_dc_default_windows_hostname_falls_back_to_known_domain() {
        // If exactly one real domain is known, a DC discovered with a
        // default-Windows FQDN should fall back to the real domain.
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();
        {
            let mut s = state.inner.write().await;
            s.domains.push("contoso.local".to_string());
        }

        let host = make_host("192.168.58.1", "win-hvtt4f8yn5n.ttb0.local", true);
        state.register_dc(&q, &host).await.unwrap();

        let s = state.inner.read().await;
        assert_eq!(
            s.domain_controllers.get("contoso.local"),
            Some(&"192.168.58.1".to_string()),
            "expected fallback to the single known real domain"
        );
        assert!(!s.domain_controllers.contains_key("ttb0.local"));
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
    async fn publish_host_drops_placeholder_hostnames() {
        // Upstream Python tool output stringifies `None` into the hostname
        // field. Without clearing them the display shows e.g. `none / <ip>`.
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        for placeholder in &["none", "None", "NULL", "(none)", "n/a", "-"] {
            let host = make_host("192.168.58.50", placeholder, false);
            state.publish_host(&q, host).await.unwrap();
        }
        let s = state.inner.read().await;
        let entry = s
            .hosts
            .iter()
            .find(|h| h.ip == "192.168.58.50")
            .expect("host should be stored");
        assert_eq!(
            entry.hostname, "",
            "placeholder hostnames must be cleared, got: {:?}",
            entry.hostname
        );
    }

    #[tokio::test]
    async fn publish_host_filters_self_ip() {
        // The orchestrator's own NIC must not get counted as a discovered
        // target — that's the source of the phantom `none / <attacker-ip>`
        // host in the loot output.
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();
        {
            let mut s = state.inner.write().await;
            s.self_ips
                .insert("192.168.58.99".parse::<std::net::IpAddr>().unwrap());
        }

        let host = make_host("192.168.58.99", "", false);
        let added = state.publish_host(&q, host).await.unwrap();
        assert!(!added, "self-IP host must be silently dropped");

        let s = state.inner.read().await;
        assert!(
            s.hosts.is_empty(),
            "self-IP must never reach state.hosts, got: {:?}",
            s.hosts
        );
    }

    #[tokio::test]
    async fn publish_host_self_ip_filter_inactive_when_set_empty() {
        // StateInner::new() leaves self_ips empty so every publishing test
        // remains deterministic without mocking interface enumeration.
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let host = make_host("192.168.58.99", "srv01.contoso.local", false);
        let added = state.publish_host(&q, host).await.unwrap();
        assert!(added);
    }

    #[tokio::test]
    async fn publish_host_rejects_multi_ip_in_ip_field() {
        // Some parsers store the entire sweep target list verbatim in the
        // `ip` field (e.g. "1.2.3.4,5.6.7.8"). Without this guard,
        // `dedup_hosts` rescues the malformed string into the hostname
        // field on display, producing phantom rows with an IP-list as a
        // "hostname". Reject at the publish boundary.
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        for malformed in &[
            "192.168.58.10,192.168.58.20",
            "192.168.58.10 192.168.58.20",
            "not-an-ip",
        ] {
            let host = make_host(malformed, "", false);
            let added = state.publish_host(&q, host).await.unwrap();
            assert!(!added, "must drop malformed host.ip {:?}", malformed);
        }
        let s = state.inner.read().await;
        assert!(
            s.hosts.is_empty(),
            "no malformed entry should reach state.hosts, got: {:?}",
            s.hosts
        );
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
