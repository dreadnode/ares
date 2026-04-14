//! Publishing methods — add credentials, hashes, hosts, and vulnerabilities
//! to both in-memory state and Redis.

use anyhow::Result;
use once_cell::sync::Lazy;
use redis::AsyncCommands;
use regex::Regex;

use ares_core::models::*;
use ares_core::state::{self, RedisStateReader};

use super::{SharedState, KEY_VULN_QUEUE};
use crate::output_extraction::{is_valid_credential, strip_ansi};
use crate::task_queue::TaskQueue;

/// Regex matching `Password` (case-insensitive) followed by optional `:` and space.
static PASSWORD_PREFIX_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^password\s*:\s*").unwrap());

/// Regex matching trailing parenthetical metadata like ` (Guest)`, ` (Pwn3d!)`.
static TRAILING_PAREN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+\([^)]+\)\s*$").unwrap());

/// Sanitize and validate a credential before storage.
///
/// Mirrors Python's `add_credential()` — strips noise from password values,
/// normalizes `user@domain@domain` usernames, resolves NetBIOS domains to FQDN,
/// and rejects invalid entries. Returns `None` if the credential should be dropped.
fn sanitize_credential(
    mut cred: Credential,
    netbios_to_fqdn: &std::collections::HashMap<String, String>,
) -> Option<Credential> {
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
    // e.g. "samwell.tarly@north.sevenkingdoms.local@essos.local"
    //   → username="samwell.tarly", domain="north.sevenkingdoms.local"
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

    // Resolve NetBIOS domain to FQDN (e.g. "NORTH" → "north.sevenkingdoms.local")
    if !cred.domain.is_empty() && !cred.domain.contains('.') {
        let domain_upper = cred.domain.to_uppercase();
        if let Some(fqdn) = netbios_to_fqdn.get(&domain_upper) {
            // netbios_to_fqdn maps SHORTNAME → host.domain.local
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

    // Validate after sanitization
    if !is_valid_credential(&cred.username, &cred.password) {
        return None;
    }

    Some(cred)
}

/// Check if a hostname is an AWS internal PTR name.
fn is_aws_hostname(hostname: &str) -> bool {
    let lower = hostname.to_lowercase();
    lower.starts_with("ip-") && lower.contains("compute.internal")
}

impl SharedState {
    /// Add a credential to state and Redis (with dedup).
    ///
    /// Sanitizes the credential before storage (strips "Password:" prefix, trailing
    /// metadata, normalizes domains, rejects noise). When the credential's domain is
    /// a valid FQDN (contains a dot), it is automatically added to `state.domains`
    /// (matches Python's `add_credential()` behavior).
    pub async fn publish_credential(&self, queue: &TaskQueue, cred: Credential) -> Result<bool> {
        // Sanitize and validate before storage
        let netbios_map = {
            let state = self.inner.read().await;
            state.netbios_to_fqdn.clone()
        };
        let cred = match sanitize_credential(cred, &netbios_map) {
            Some(c) => c,
            None => return Ok(false),
        };

        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id.clone());
        let mut conn = queue.connection();
        let added = reader.add_credential(&mut conn, &cred).await?;
        if added {
            // Auto-extract domain from credential (matches Python add_credential)
            let cred_domain = cred.domain.to_lowercase();
            if cred_domain.contains('.') {
                let mut state = self.inner.write().await;
                if !state.domains.contains(&cred_domain) {
                    state.domains.push(cred_domain.clone());
                    let domain_key = format!(
                        "{}:{}:{}",
                        state::KEY_PREFIX,
                        operation_id,
                        state::KEY_DOMAINS,
                    );
                    let _: Result<(), _> =
                        redis::AsyncCommands::sadd(&mut conn, &domain_key, &cred_domain).await;
                    let _: Result<(), _> =
                        redis::AsyncCommands::expire(&mut conn, &domain_key, 86400i64).await;
                    tracing::info!(
                        domain = %cred_domain,
                        username = %cred.username,
                        "Auto-extracted domain from credential"
                    );
                }
                state.credentials.push(cred);
            } else {
                let mut state = self.inner.write().await;
                state.credentials.push(cred);
            }
        }
        Ok(added)
    }

    /// Add a hash to state and Redis (with dedup).
    ///
    /// When a `krbtgt` NTLM hash is stored, `has_domain_admin` is automatically
    /// set — mirroring Python's `add_hash()` behaviour so that `auto_golden_ticket`
    /// triggers without requiring the LLM to emit a structured JSON payload.
    pub async fn publish_hash(&self, queue: &TaskQueue, hash: Hash) -> Result<bool> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        let added = reader.add_hash(&mut conn, &hash).await?;
        if added {
            let is_krbtgt = hash.username.to_lowercase() == "krbtgt"
                && hash.hash_type.to_lowercase().contains("ntlm");
            let hash_domain = hash.domain.clone();
            let mut state = self.inner.write().await;
            state.hashes.push(hash);

            // Track per-domain domination when krbtgt NTLM hash arrives
            if is_krbtgt {
                let krbtgt_domain = if hash_domain.is_empty() {
                    state.domains.first().cloned().unwrap_or_default()
                } else {
                    hash_domain.to_lowercase()
                };
                if !krbtgt_domain.is_empty() {
                    state.dominated_domains.insert(krbtgt_domain.clone());
                    tracing::info!(domain = %krbtgt_domain, "Domain dominated (krbtgt hash obtained)");
                }

                // Auto-set domain admin when first krbtgt NTLM hash arrives (matches Python)
                if !state.has_domain_admin {
                    drop(state);
                    let path = Some("secretsdump → krbtgt NTLM hash".to_string());
                    if let Err(e) = self.set_domain_admin(queue, path).await {
                        tracing::warn!(err = %e, "Failed to auto-set domain admin from krbtgt hash");
                    } else {
                        tracing::info!(
                            "🎯 Domain Admin auto-set from krbtgt NTLM hash in publish_hash"
                        );
                    }
                }
            }
        }
        Ok(added)
    }

    /// Update a hash's `cracked_password` field in memory and Redis.
    ///
    /// Finds the first hash matching the given username and domain (case-insensitive)
    /// that has no cracked password yet, sets it, and persists the change to the Redis
    /// HASH by scanning fields and updating the matching entry.
    pub async fn update_hash_cracked_password(
        &self,
        queue: &TaskQueue,
        username: &str,
        domain: &str,
        password: &str,
    ) -> Result<bool> {
        // Update in-memory state and capture the updated hash for Redis persist
        let (op_id, hash_type) = {
            let mut state = self.inner.write().await;
            let idx = state.hashes.iter().position(|h| {
                h.username.eq_ignore_ascii_case(username)
                    && h.domain.eq_ignore_ascii_case(domain)
                    && h.cracked_password.is_none()
            });
            match idx {
                Some(i) => {
                    state.hashes[i].cracked_password = Some(password.to_string());
                    let ht = state.hashes[i].hash_type.clone();
                    (state.operation_id.clone(), ht)
                }
                None => return Ok(false),
            }
        };

        // Persist to Redis HASH: scan fields, find the matching entry, update it
        let hash_key = format!("{}:{}:{}", state::KEY_PREFIX, op_id, state::KEY_HASHES,);
        let mut conn = queue.connection();
        let entries: std::collections::HashMap<String, String> =
            redis::AsyncCommands::hgetall(&mut conn, &hash_key)
                .await
                .unwrap_or_default();
        for (field, value) in &entries {
            if let Ok(mut h) = serde_json::from_str::<Hash>(value) {
                if h.username.eq_ignore_ascii_case(username)
                    && h.domain.eq_ignore_ascii_case(domain)
                    && h.cracked_password.is_none()
                {
                    h.cracked_password = Some(password.to_string());
                    let updated_json = serde_json::to_string(&h).unwrap_or_default();
                    let _: Result<(), _> =
                        redis::AsyncCommands::hset(&mut conn, &hash_key, field, &updated_json)
                            .await;
                    break;
                }
            }
        }

        tracing::info!(
            username = %username,
            domain = %domain,
            hash_type = %hash_type,
            "Hash cracked_password updated in state and Redis"
        );

        Ok(true)
    }

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
        // e.g. "winterfell.north.sevenkingdoms.local" → "north.sevenkingdoms.local"
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
                // e.g. "winterfell.north.sevenkingdoms.local" → WINTERFELL → winterfell.north.sevenkingdoms.local
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
    async fn register_dc(&self, queue: &TaskQueue, host: &Host) -> Result<()> {
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

    /// Add a user to state and Redis (with dedup).
    pub async fn publish_user(&self, queue: &TaskQueue, user: User) -> Result<bool> {
        // Check for duplicate in memory
        {
            let state = self.inner.read().await;
            let dedup = format!(
                "{}@{}",
                user.username.to_lowercase(),
                user.domain.to_lowercase()
            );
            if state.users.iter().any(|u| {
                format!("{}@{}", u.username.to_lowercase(), u.domain.to_lowercase()) == dedup
            }) {
                return Ok(false);
            }
        }

        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        let added = reader.add_user(&mut conn, &user).await?;
        if added {
            let mut state = self.inner.write().await;
            state.users.push(user);
        }
        Ok(added)
    }

    /// Add a vulnerability to state and Redis.
    pub async fn publish_vulnerability(
        &self,
        queue: &TaskQueue,
        vuln: VulnerabilityInfo,
    ) -> Result<bool> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id.clone());
        let mut conn = queue.connection();
        let added = reader.add_vulnerability(&mut conn, &vuln).await?;
        if added {
            // Also add to vuln queue ZSET for exploitation workflow
            let vuln_queue_key =
                format!("{}:{}:{}", state::KEY_PREFIX, operation_id, KEY_VULN_QUEUE);
            let vuln_json = serde_json::to_string(&vuln).unwrap_or_default();
            let score = vuln.priority as f64;
            let _: () = conn
                .zadd(&vuln_queue_key, &vuln_json, score)
                .await
                .unwrap_or(());
            let _: () = conn.expire(&vuln_queue_key, 86400).await.unwrap_or(());

            let mut state = self.inner.write().await;
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }
        Ok(added)
    }

    /// Add a share to state and Redis (with dedup).
    pub async fn publish_share(&self, queue: &TaskQueue, share: Share) -> Result<bool> {
        // Check for duplicate in memory
        {
            let state = self.inner.read().await;
            if state.shares.iter().any(|s| {
                s.host.to_lowercase() == share.host.to_lowercase()
                    && s.name.to_lowercase() == share.name.to_lowercase()
            }) {
                return Ok(false);
            }
        }

        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        let added = reader.add_share(&mut conn, &share).await?;
        if added {
            let mut state = self.inner.write().await;
            state.shares.push(share);
        }
        Ok(added)
    }

    /// Persist a timeline event to Redis and add MITRE techniques.
    pub async fn persist_timeline_event(
        &self,
        queue: &TaskQueue,
        event: &serde_json::Value,
        mitre_techniques: &[String],
    ) -> Result<()> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();

        reader.add_timeline_event(&mut conn, event).await?;

        for technique in mitre_techniques {
            let _ = reader.add_technique(&mut conn, technique).await;
        }

        Ok(())
    }

    /// Add a MITRE ATT&CK technique to Redis SET.
    pub async fn add_technique(&self, queue: &TaskQueue, technique_id: &str) -> Result<bool> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        let added = reader.add_technique(&mut conn, technique_id).await?;
        Ok(added)
    }

    /// Record a pending task in memory and persist to Redis HASH.
    ///
    /// Key: `ares:op:{id}:pending_tasks` — matches Python's state_backend.
    pub async fn track_pending_task(
        &self,
        queue: &TaskQueue,
        task: ares_core::models::TaskInfo,
    ) -> Result<()> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let task_id = task.task_id.clone();
        let json = serde_json::to_string(&task).unwrap_or_default();

        // Persist to Redis
        let key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_PENDING_TASKS,
        );
        let mut conn = queue.connection();
        let _: Result<(), _> = redis::AsyncCommands::hset(&mut conn, &key, &task_id, &json).await;
        let _: Result<(), _> = redis::AsyncCommands::expire(&mut conn, &key, 86400i64).await;

        // Update in-memory state
        let mut state = self.inner.write().await;
        state.pending_tasks.insert(task_id, task);
        Ok(())
    }

    /// Move a task from pending to completed, persisting both changes to Redis.
    ///
    /// Keys: `ares:op:{id}:pending_tasks`, `ares:op:{id}:completed_tasks`
    pub async fn complete_task(
        &self,
        queue: &TaskQueue,
        task_id: &str,
        result: ares_core::models::TaskResult,
    ) -> Result<()> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let result_json = serde_json::to_string(&result).unwrap_or_default();

        let pending_key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_PENDING_TASKS,
        );
        let completed_key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_COMPLETED_TASKS,
        );

        let mut conn = queue.connection();
        // Remove from pending, add to completed
        let _: Result<(), _> = redis::AsyncCommands::hdel(&mut conn, &pending_key, task_id).await;
        let _: Result<(), _> =
            redis::AsyncCommands::hset(&mut conn, &completed_key, task_id, &result_json).await;
        let _: Result<(), _> =
            redis::AsyncCommands::expire(&mut conn, &completed_key, 86400i64).await;

        // Update in-memory state
        let mut state = self.inner.write().await;
        state.pending_tasks.remove(task_id);
        state.completed_tasks.insert(task_id.to_string(), result);
        Ok(())
    }

    /// Persist a NetBIOS to FQDN mapping to Redis HASH.
    ///
    /// Key: `ares:op:{id}:netbios_map` — matches Python's `HSET` on netbios_map.
    pub async fn publish_netbios(
        &self,
        queue: &TaskQueue,
        netbios: &str,
        fqdn: &str,
    ) -> Result<()> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_NETBIOS_MAP,
        );
        let mut conn = queue.connection();
        let _: () = redis::AsyncCommands::hset(&mut conn, &key, netbios, fqdn).await?;
        let _: () = redis::AsyncCommands::expire(&mut conn, &key, 86400i64).await?;

        let mut state = self.inner.write().await;
        state
            .netbios_to_fqdn
            .insert(netbios.to_string(), fqdn.to_string());
        Ok(())
    }

    /// Add a trust relationship to state and Redis.
    pub async fn publish_trust_info(
        &self,
        queue: &TaskQueue,
        trust: ares_core::models::TrustInfo,
    ) -> Result<bool> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        let added = reader.add_trusted_domain(&mut conn, &trust).await?;
        if added {
            let domain_key = trust.domain.to_lowercase();
            let mut state = self.inner.write().await;
            state.trusted_domains.insert(domain_key, trust);
        }
        Ok(added)
    }

    /// Set has_golden_ticket flag and persist to Redis.
    pub async fn set_golden_ticket(&self, queue: &TaskQueue, domain: &str) -> Result<()> {
        {
            let state = self.inner.read().await;
            if state.has_golden_ticket {
                return Ok(());
            }
        }
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        reader
            .set_meta_field(
                &mut conn,
                "has_golden_ticket",
                &serde_json::Value::Bool(true),
            )
            .await?;

        let mut state = self.inner.write().await;
        state.has_golden_ticket = true;
        tracing::info!(domain = %domain, "🏆 Golden ticket flag set");
        Ok(())
    }

    /// Set has_domain_admin flag and persist to Redis.
    pub async fn set_domain_admin(&self, queue: &TaskQueue, path: Option<String>) -> Result<()> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        reader
            .set_meta_field(
                &mut conn,
                "has_domain_admin",
                &serde_json::Value::Bool(true),
            )
            .await?;
        if let Some(ref p) = path {
            reader
                .set_meta_field(
                    &mut conn,
                    "domain_admin_path",
                    &serde_json::Value::String(p.clone()),
                )
                .await?;
        }

        let mut state = self.inner.write().await;
        state.has_domain_admin = true;
        state.domain_admin_path = path;
        Ok(())
    }
}
