//! StateInner — the actual mutable state backing SharedState.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use chrono::{DateTime, Utc};

use ares_core::models::*;

use super::ALL_DEDUP_SETS;

/// Lockout quarantine duration: 5 minutes matches S4U cooldown and typical
/// AD lockout observation windows. Longer values block the critical path.
const QUARANTINE_DURATION_SECS: i64 = 300;

const CAPTURE_IN_FLIGHT_TTL_SECS: i64 = 180;

#[derive(Debug)]
pub struct StateInner {
    pub operation_id: String,
    pub target: Option<Target>,
    pub target_ips: Vec<String>,

    // Collections (append-mostly)
    pub credentials: Vec<Credential>,
    pub hashes: Vec<Hash>,
    pub hosts: Vec<Host>,
    pub users: Vec<User>,
    pub shares: Vec<Share>,
    pub domains: Vec<String>,
    /// Domains discovered with evidence weaker than authoritative (typically
    /// inferred from a host FQDN). Held here until the probe confirms or a
    /// stronger source promotes them. Keyed by lowercase FQDN.
    pub candidate_domains: HashMap<String, CandidateDomain>,

    // Vulnerability tracking
    pub discovered_vulnerabilities: HashMap<String, VulnerabilityInfo>,
    pub exploited_vulnerabilities: HashSet<String>,

    // Per-vuln consecutive exploit-failure counts. Drives `is_exploit_abandoned`
    // — once a vuln crosses MAX_EXPLOIT_FAILURES, the exploitation workflow
    // skips it permanently for this op. Prevents 2-hour LLM stuck-loops on
    // exploits whose preconditions (creds, reachable target, working tool)
    // can never be satisfied. Operation-scoped, in-memory only.
    pub exploit_failure_counts: HashMap<String, u32>,

    // Maps
    pub domain_controllers: HashMap<String, String>,
    pub netbios_to_fqdn: HashMap<String, String>,
    pub domain_sids: HashMap<String, String>,
    /// RID-500 account name per domain (may differ from "Administrator" if renamed).
    pub admin_names: HashMap<String, String>,

    // Trust relationships (domain FQDN → trust metadata)
    pub trusted_domains: HashMap<String, TrustInfo>,

    // Per-domain DA tracking: domains where krbtgt NTLM has been obtained
    pub dominated_domains: HashSet<String>,

    // Per-domain timestamp set when an automation dispatches a credential-
    // capture primitive (secretsdump/DCSync). Read by destructive ACL gates
    // to defer ForceChangePassword while DCSync is still in flight. TTL'd —
    // no explicit clear hook; once the dump succeeds the domain enters
    // `dominated_domains`, and the TTL is the safety valve for silent fails.
    pub credential_capture_in_flight: HashMap<String, DateTime<Utc>>,

    // Flags
    pub has_domain_admin: bool,
    pub has_golden_ticket: bool,
    pub domain_admin_path: Option<String>,

    // Dedup sets (persisted to Redis)
    pub dedup: HashMap<String, HashSet<String>>,

    // MSSQL enum tracking (persisted to Redis SET)
    pub mssql_enum_dispatched: HashSet<String>,

    // ACL chain data (from BloodHound, stored in Redis LIST)
    pub acl_chains: Vec<serde_json::Value>,

    // ACL step dedup (tracks which chain steps have been dispatched)
    pub dispatched_acl_steps: HashSet<String>,

    // Pending/completed tasks (in-memory only)
    pub pending_tasks: HashMap<String, TaskInfo>,
    pub completed_tasks: HashMap<String, ares_core::models::TaskResult>,

    // Principal lockout quarantine: `user@domain` → expiry time.
    // Populated by two write paths that converge on the same semantics:
    //   - auth attempts that returned STATUS_ACCOUNT_LOCKED_OUT or
    //     KDC_ERR_CLIENT_REVOKED for a known cleartext credential
    //   - enumeration paths (username_as_password, password_spray) that
    //     observed the principal locked even though we don't hold a
    //     cleartext for them
    // Both cases carry the same operational meaning at every read site —
    // "don't authenticate as this principal right now" — so they share one
    // map. Used by the LLM snapshot filter, automation paths that consume
    // credential/hash lists, and the spray-injection path that builds
    // excluded_users.
    pub quarantined_principals: HashMap<String, DateTime<Utc>>,

    // Per-trust counter: how many times the cross-forest forge dispatch
    // has been deferred waiting for the AES256 trust key to upsert.
    // secretsdump runs twice (NTLM-only first, then AES-equipped) and
    // Win2016+ targets reject RC4-only inter-realm tickets. Bound this
    // so we don't defer indefinitely if AES never arrives.
    pub forge_aes_defers: HashMap<String, u32>,

    // Per-(linked_server vuln) failed-attempt counter for
    // `auto_mssql_link_pivot`. Bounded retries before we mark the
    // pivot dedup'd — keeps a flaky link from looping forever while
    // still tolerating transient auth races.
    pub mssql_link_pivot_attempts: HashMap<String, u32>,

    // Per-hash crack attempt counter, keyed by `crack_dedup_key`. Lets a
    // failed crack (wrong wordlist, password not in list, hashcat transient)
    // be retried up to `MAX_CRACK_ATTEMPTS` before the dispatcher marks
    // `DEDUP_CRACK_REQUESTS` and gives up permanently. The previous behavior
    // wrote dedup on dispatch success, so a single hashcat exit ≠ 0 left
    // the hash stuck uncracked forever. Restart resilience: the counter is
    // in-memory only; dedup (the cap marker) is persisted to Redis, so
    // post-restart capped hashes stay capped while uncapped ones get a
    // fresh budget (acceptable mild leak).
    pub crack_attempts: HashMap<String, u32>,

    // Forged inter-realm Kerberos tickets (source→target forest, cached path)
    pub kerberos_tickets: Vec<ares_core::models::KerberosTicket>,

    // Completion flag (set externally to signal operation should wrap up)
    pub completed: bool,

    /// Timestamp when all forests were first detected as dominated.
    /// Used by the completion monitor to enforce a post-exploitation grace period.
    pub all_forests_dominated_at: Option<tokio::time::Instant>,

    /// IPv4 addresses bound to the orchestrator's own network interfaces.
    /// Populated once at orchestrator startup via `SharedState::initialize_self_ips`
    /// from `local_ip_address::list_afinet_netifas`. `publish_host` skips any
    /// host whose IP is in this set so the attacker pivot box doesn't get
    /// counted as a discovered target when an SMB sweep hits its own NIC.
    /// Empty by default — tests using `StateInner::new` get deterministic
    /// no-op filtering without needing to mock interface enumeration.
    pub self_ips: HashSet<IpAddr>,
}

impl StateInner {
    pub(crate) fn new(operation_id: String) -> Self {
        let mut dedup = HashMap::new();
        for name in ALL_DEDUP_SETS {
            dedup.insert(name.to_string(), HashSet::new());
        }

        Self {
            operation_id,
            target: None,
            target_ips: Vec::new(),
            credentials: Vec::new(),
            hashes: Vec::new(),
            hosts: Vec::new(),
            users: Vec::new(),
            shares: Vec::new(),
            domains: Vec::new(),
            candidate_domains: HashMap::new(),
            discovered_vulnerabilities: HashMap::new(),
            exploited_vulnerabilities: HashSet::new(),
            exploit_failure_counts: HashMap::new(),
            domain_controllers: HashMap::new(),
            netbios_to_fqdn: HashMap::new(),
            domain_sids: HashMap::new(),
            admin_names: HashMap::new(),
            trusted_domains: HashMap::new(),
            dominated_domains: HashSet::new(),
            credential_capture_in_flight: HashMap::new(),
            has_domain_admin: false,
            has_golden_ticket: false,
            domain_admin_path: None,
            dedup,
            mssql_enum_dispatched: HashSet::new(),
            acl_chains: Vec::new(),
            dispatched_acl_steps: HashSet::new(),
            pending_tasks: HashMap::new(),
            completed_tasks: HashMap::new(),
            quarantined_principals: HashMap::new(),
            forge_aes_defers: HashMap::new(),
            mssql_link_pivot_attempts: HashMap::new(),
            crack_attempts: HashMap::new(),
            kerberos_tickets: Vec::new(),
            completed: false,
            all_forests_dominated_at: None,
            self_ips: HashSet::new(),
        }
    }

    /// Check if a username is the delegating account for a constrained
    /// delegation or RBCD vulnerability.  These accounts must be reserved
    /// for S4U exploitation — spraying or secretsdump with their creds
    /// causes lockout before S4U can use them.
    pub fn is_delegation_account(&self, username: &str) -> bool {
        let u = username.to_lowercase();
        self.discovered_vulnerabilities.values().any(|vuln| {
            let vtype = vuln.vuln_type.to_lowercase();
            if vtype != "constrained_delegation" && vtype != "rbcd" {
                return false;
            }
            vuln.details
                .get("account_name")
                .or_else(|| vuln.details.get("AccountName"))
                .and_then(|v| v.as_str())
                .map(|a| a.to_lowercase() == u)
                .unwrap_or(false)
        })
    }

    /// Check if a principal (`user@domain`) is quarantined due to lockout —
    /// either a known cleartext that returned STATUS_ACCOUNT_LOCKED_OUT /
    /// KDC_ERR_CLIENT_REVOKED, or a principal observed locked during
    /// enumeration (`username_as_password`, `password_spray`). Expired
    /// quarantines are ignored (lazy cleanup).
    pub fn is_principal_quarantined(&self, username: &str, domain: &str) -> bool {
        let key = format!("{}@{}", username.to_lowercase(), domain.to_lowercase());
        self.quarantined_principals
            .get(&key)
            .map(|expiry| Utc::now() < *expiry)
            .unwrap_or(false)
    }

    /// Quarantine a principal for `QUARANTINE_DURATION_SECS` after a lockout
    /// signal. See [`is_principal_quarantined`] for which signals feed in.
    pub fn quarantine_principal(&mut self, username: &str, domain: &str) {
        let key = format!("{}@{}", username.to_lowercase(), domain.to_lowercase());
        let expiry = Utc::now() + chrono::Duration::seconds(QUARANTINE_DURATION_SECS);
        self.quarantined_principals.insert(key, expiry);
    }

    pub fn mark_credential_capture_in_flight(&mut self, domain: &str) {
        if domain.is_empty() {
            return;
        }
        self.credential_capture_in_flight
            .insert(domain.to_lowercase(), Utc::now());
    }

    pub fn credential_capture_in_flight_for(&self, domain: &str) -> bool {
        let d = domain.to_lowercase();
        let Some(ts) = self.credential_capture_in_flight.get(&d) else {
            return false;
        };
        Utc::now().signed_duration_since(*ts).num_seconds() < CAPTURE_IN_FLIGHT_TTL_SECS
    }

    /// Return a deduplicated list of currently-quarantined usernames in
    /// `domain` (case-insensitive). Used to populate `excluded_users` on
    /// outbound spray dispatches so the worker can drop them before auth.
    pub fn quarantined_principals_in_domain(&self, domain: &str) -> Vec<String> {
        let domain_l = domain.to_lowercase();
        let now = Utc::now();
        let mut out: Vec<String> = self
            .quarantined_principals
            .iter()
            .filter(|(_, expiry)| now < **expiry)
            .filter_map(|(key, _)| {
                let (user, dom) = key.split_once('@')?;
                if dom == domain_l {
                    Some(user.to_string())
                } else {
                    None
                }
            })
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Resolve the DC IP for a domain.
    ///
    /// Checks `domain_controllers` first, then falls back to scanning the hosts
    /// list for a DC whose FQDN suffix matches the domain. This is more robust
    /// than relying solely on `domain_controllers`, which can have stale or
    /// missing entries due to startup seed timing issues in multi-domain
    /// environments.
    pub fn resolve_dc_ip(&self, domain: &str) -> Option<String> {
        let domain_lower = domain.to_lowercase();
        // Tier 1: explicit DC map (case-insensitive)
        if let Some(ip) = self.domain_controllers.get(&domain_lower).or_else(|| {
            self.domain_controllers
                .iter()
                .find(|(k, _)| k.to_lowercase() == domain_lower)
                .map(|(_, v)| v)
        }) {
            return Some(ip.clone());
        }
        // Tier 2: scan hosts for a DC matching this domain by FQDN suffix
        for host in &self.hosts {
            if !(host.is_dc || host.detect_dc()) {
                continue;
            }
            if host.hostname.is_empty() {
                continue;
            }
            let parts: Vec<&str> = host.hostname.split('.').collect();
            if parts.len() >= 3 {
                let host_domain = parts[1..].join(".").to_lowercase();
                if host_domain == domain_lower {
                    return Some(host.ip.clone());
                }
            }
        }
        None
    }

    /// Return all unique domains that have a resolvable DC.
    ///
    /// Merges domains from `domain_controllers`, `domains`, and `trusted_domains`
    /// then filters to those where `resolve_dc_ip()` succeeds. Returns
    /// `(domain, dc_ip)` pairs.
    pub fn all_domains_with_dcs(&self) -> Vec<(String, String)> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();

        // Gather all known domain names (lowercased for dedup)
        let mut all_domains: Vec<String> = Vec::new();
        for d in self.domain_controllers.keys() {
            all_domains.push(d.to_lowercase());
        }
        for d in &self.domains {
            all_domains.push(d.to_lowercase());
        }
        for d in self.trusted_domains.keys() {
            all_domains.push(d.to_lowercase());
        }

        for domain in all_domains {
            if seen.contains(&domain) {
                continue;
            }
            seen.insert(domain.clone());
            if let Some(ip) = self.resolve_dc_ip(&domain) {
                result.push((domain, ip));
            }
        }

        result
    }

    /// Find a cleartext credential from a trusted domain that can authenticate
    /// to `target_domain` via AD trust (child→parent or cross-forest).
    ///
    /// Used as a fallback when no same-domain cleartext credential exists.
    /// Child-domain creds authenticate to parent DCs via the parent-child trust;
    /// cross-forest creds authenticate via bidirectional forest trusts.
    pub fn find_trust_credential(
        &self,
        target_domain: &str,
    ) -> Option<ares_core::models::Credential> {
        let target = target_domain.to_lowercase();

        // Priority 1: child-domain cred → parent-domain (most reliable)
        if let Some(c) = self.credentials.iter().find(|c| {
            !c.password.is_empty()
                && !self.is_principal_quarantined(&c.username, &c.domain)
                && c.domain.to_lowercase().ends_with(&format!(".{target}"))
        }) {
            return Some(c.clone());
        }

        // Priority 2: cross-forest trusted domain cred (bidirectional trust)
        // Check if any credential's domain has a trust with the target domain.
        // Also falls back to discovered-domain heuristic: if both domains have
        // known DCs in the same operation, they are likely in a trust relationship.
        // LDAP bind will simply fail if there is no actual trust.
        for cred in &self.credentials {
            if cred.password.is_empty()
                || self.is_principal_quarantined(&cred.username, &cred.domain)
            {
                continue;
            }
            let cred_dom = cred.domain.to_lowercase();
            if cred_dom == target {
                continue; // same domain, not a trust fallback
            }
            let cred_forest = self.forest_root_of(&cred_dom);
            let target_forest = self.forest_root_of(&target);
            if cred_forest != target_forest {
                // Explicit trust relationship known
                if self.trusted_domains.contains_key(&target_forest)
                    || self.trusted_domains.contains_key(&cred_forest)
                {
                    return Some(cred.clone());
                }
                // Heuristic: both forests have DCs in this engagement — likely
                // trust-related. LDAP bind will fail harmlessly if not.
                let target_has_dc = self.domain_controllers.keys().any(|d| {
                    let d = d.to_lowercase();
                    d == target_forest || self.forest_root_of(&d) == target_forest
                });
                let cred_has_dc = self.domain_controllers.keys().any(|d| {
                    let d = d.to_lowercase();
                    d == cred_forest || self.forest_root_of(&d) == cred_forest
                });
                if target_has_dc && cred_has_dc {
                    return Some(cred.clone());
                }
            }
        }

        None
    }

    /// Find a credential for the SOURCE user (the principal performing the
    /// action), regardless of which TARGET domain the action is aimed at.
    ///
    /// Cross-forest ACL/MSSQL/ADCS exploitation has the source user living in
    /// their own domain (e.g. `testuser@contoso.local`) while a vuln's
    /// `domain` field points at the target (e.g. `fabrikam.local`).
    /// Same-domain matching against the target therefore drops legitimate
    /// cross-forest work.
    ///
    /// Selection priority:
    ///   1. Cred whose domain matches the explicit `@domain` suffix of
    ///      `source_user`, if present.
    ///   2. Cred whose domain == `target_domain` (same-domain case).
    ///   3. Cred from a domain in a trust relationship with `target_domain`
    ///      (forest sibling, child↔parent, or trusted_domains entry).
    ///   4. Any non-empty, non-quarantined cred with matching username.
    pub fn find_source_credential(
        &self,
        source_user: &str,
        target_domain: &str,
    ) -> Option<ares_core::models::Credential> {
        let (name, explicit_dom) = parse_principal(source_user);
        let name_l = name.to_lowercase();
        let target_l = target_domain.to_lowercase();
        let target_forest = self.forest_root_of(&target_l);

        let usable = |c: &ares_core::models::Credential| -> bool {
            !c.password.is_empty()
                && !self.is_principal_quarantined(&c.username, &c.domain)
                && c.username.to_lowercase() == name_l
        };

        if let Some(ref d) = explicit_dom {
            if let Some(c) = self
                .credentials
                .iter()
                .find(|c| usable(c) && c.domain.to_lowercase() == *d)
            {
                return Some(c.clone());
            }
        }

        if let Some(c) = self
            .credentials
            .iter()
            .find(|c| usable(c) && c.domain.to_lowercase() == target_l)
        {
            return Some(c.clone());
        }

        if let Some(c) = self.credentials.iter().find(|c| {
            if !usable(c) {
                return false;
            }
            let dom = c.domain.to_lowercase();
            if dom == target_l {
                return false;
            }
            let cred_forest = self.forest_root_of(&dom);
            cred_forest == target_forest
                || self.trusted_domains.contains_key(&target_forest)
                || self.trusted_domains.contains_key(&cred_forest)
        }) {
            return Some(c.clone());
        }

        self.credentials.iter().find(|c| usable(c)).cloned()
    }

    /// NTLM-hash variant of [`find_source_credential`] with the same priority
    /// order. Restricts to NTLM hashes (the only type usable for PTH).
    pub fn find_source_hash(
        &self,
        source_user: &str,
        target_domain: &str,
    ) -> Option<ares_core::models::Hash> {
        let (name, explicit_dom) = parse_principal(source_user);
        let name_l = name.to_lowercase();
        let target_l = target_domain.to_lowercase();
        let target_forest = self.forest_root_of(&target_l);

        let usable = |h: &ares_core::models::Hash| -> bool {
            !h.hash_value.is_empty()
                && h.hash_type.eq_ignore_ascii_case("NTLM")
                && !self.is_principal_quarantined(&h.username, &h.domain)
                && h.username.to_lowercase() == name_l
        };

        if let Some(ref d) = explicit_dom {
            if let Some(h) = self
                .hashes
                .iter()
                .find(|h| usable(h) && h.domain.to_lowercase() == *d)
            {
                return Some(h.clone());
            }
        }

        if let Some(h) = self
            .hashes
            .iter()
            .find(|h| usable(h) && h.domain.to_lowercase() == target_l)
        {
            return Some(h.clone());
        }

        if let Some(h) = self.hashes.iter().find(|h| {
            if !usable(h) {
                return false;
            }
            let dom = h.domain.to_lowercase();
            if dom == target_l {
                return false;
            }
            let cred_forest = self.forest_root_of(&dom);
            cred_forest == target_forest
                || self.trusted_domains.contains_key(&target_forest)
                || self.trusted_domains.contains_key(&cred_forest)
        }) {
            return Some(h.clone());
        }

        self.hashes.iter().find(|h| usable(h)).cloned()
    }

    /// Get the forest root for a domain.
    /// If the domain is a child (e.g. `child.contoso.local`), the forest
    /// root is the parent (e.g. `contoso.local`). Otherwise returns self.
    pub fn forest_root_of(&self, domain: &str) -> String {
        let d = domain.to_lowercase();
        // Check if this domain is a child of any known domain
        for known in self.domains.iter() {
            let k = known.to_lowercase();
            if d != k && d.ends_with(&format!(".{k}")) {
                return k;
            }
        }
        for known in self.domain_controllers.keys() {
            let k = known.to_lowercase();
            if d != k && d.ends_with(&format!(".{k}")) {
                return k;
            }
        }
        d
    }

    /// Check if a dedup key exists in the named set.
    pub fn is_processed(&self, set_name: &str, key: &str) -> bool {
        self.dedup
            .get(set_name)
            .map(|s| s.contains(key))
            .unwrap_or(false)
    }

    /// Check if any key in the named dedup set starts with `prefix`.
    pub fn has_processed_prefix(&self, set_name: &str, prefix: &str) -> bool {
        self.dedup
            .get(set_name)
            .map(|s| s.iter().any(|k| k.starts_with(prefix)))
            .unwrap_or(false)
    }

    /// Mark a key as processed in the named set.
    pub fn mark_processed(&mut self, set_name: &str, key: String) {
        self.dedup
            .entry(set_name.to_string())
            .or_default()
            .insert(key);
    }

    /// Remove a key from the named dedup set so it can be retried.
    pub fn unmark_processed(&mut self, set_name: &str, key: &str) {
        if let Some(s) = self.dedup.get_mut(set_name) {
            s.remove(key);
        }
    }

    /// Remove every key in `set_name` that starts with `prefix`. Returns the
    /// removed keys so the caller can also drop them from the persisted store.
    /// Used by trust automation to wake cross-forest fallback automations
    /// (FSP/ACL/group enum) for a target domain when their dedup format is
    /// `{kind}:{domain}[:tail]` — clearing all entries for a target without
    /// knowing the full key.
    pub fn unmark_processed_by_prefix(&mut self, set_name: &str, prefix: &str) -> Vec<String> {
        let Some(s) = self.dedup.get_mut(set_name) else {
            return Vec::new();
        };
        let to_remove: Vec<String> = s
            .iter()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect();
        for k in &to_remove {
            s.remove(k);
        }
        to_remove
    }

    /// Check if all discovered forests have been dominated (krbtgt obtained).
    ///
    /// Returns `true` when `compute_undominated_forests()` returns an empty list,
    /// meaning every forest root (initial target, trusted domains, and DCs) has
    /// a corresponding entry in `dominated_domains`.
    ///
    /// Automations should check `has_domain_admin && all_forests_dominated()`
    /// before going idle — DA in one forest doesn't mean we're done if cross-forest
    /// targets remain.
    pub fn all_forests_dominated(&self) -> bool {
        crate::orchestrator::completion::compute_undominated_forests(
            self.target.as_ref().map(|t| t.domain.as_str()),
            self.domains.first().map(|d| d.as_str()),
            &self.trusted_domains,
            &self.dominated_domains,
            &self.domain_controllers,
        )
        .is_empty()
    }
}

/// Parse a principal string of form `name` or `name@domain.fqdn`.
/// Returns `(name, Some(domain_lower))` for the @-form, `(name, None)` for bare names.
fn parse_principal(s: &str) -> (&str, Option<String>) {
    if let Some((name, dom)) = s.split_once('@') {
        (name, Some(dom.to_lowercase()))
    } else {
        (s, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::state::*;

    #[test]
    fn state_inner_new_initializes_all_dedup_sets() {
        let state = StateInner::new("op-test".into());
        assert_eq!(state.operation_id, "op-test");
        assert!(!state.has_domain_admin);
        assert!(!state.has_golden_ticket);
        assert!(!state.completed);

        // All 19 dedup sets should be initialized
        for name in ALL_DEDUP_SETS {
            assert!(state.dedup.contains_key(*name), "Missing dedup set: {name}");
            assert!(state.dedup[*name].is_empty());
        }
        assert_eq!(state.dedup.len(), ALL_DEDUP_SETS.len());
    }

    #[test]
    fn is_processed_returns_false_for_unknown_set() {
        let state = StateInner::new("op-1".into());
        assert!(!state.is_processed("nonexistent_set", "key1"));
    }

    #[test]
    fn mark_processed_and_is_processed() {
        let mut state = StateInner::new("op-1".into());
        assert!(!state.is_processed(DEDUP_CRACK_REQUESTS, "hash1"));

        state.mark_processed(DEDUP_CRACK_REQUESTS, "hash1".into());
        assert!(state.is_processed(DEDUP_CRACK_REQUESTS, "hash1"));
        assert!(!state.is_processed(DEDUP_CRACK_REQUESTS, "hash2"));
    }

    #[test]
    fn mark_processed_creates_new_set_if_needed() {
        let mut state = StateInner::new("op-1".into());
        state.mark_processed("custom_set", "key1".into());
        assert!(state.is_processed("custom_set", "key1"));
    }

    #[test]
    fn mark_processed_idempotent() {
        let mut state = StateInner::new("op-1".into());
        state.mark_processed(DEDUP_SECRETSDUMP, "192.168.58.10".into());
        state.mark_processed(DEDUP_SECRETSDUMP, "192.168.58.10".into());
        assert_eq!(state.dedup[DEDUP_SECRETSDUMP].len(), 1);
    }

    #[test]
    fn unmark_processed_by_prefix_removes_matching() {
        let mut state = StateInner::new("op-1".into());
        state.mark_processed(DEDUP_SECRETSDUMP, "xforest:fabrikam.local:dc01".into());
        state.mark_processed(DEDUP_SECRETSDUMP, "xforest:fabrikam.local:dc02".into());
        state.mark_processed(DEDUP_SECRETSDUMP, "xforest:contoso.local:dc01".into());
        state.mark_processed(DEDUP_SECRETSDUMP, "unrelated:key".into());
        let removed =
            state.unmark_processed_by_prefix(DEDUP_SECRETSDUMP, "xforest:fabrikam.local:");
        assert_eq!(removed.len(), 2);
        assert!(removed
            .iter()
            .all(|k| k.starts_with("xforest:fabrikam.local:")));
        assert_eq!(state.dedup[DEDUP_SECRETSDUMP].len(), 2);
    }

    #[test]
    fn unmark_processed_by_prefix_unknown_set_returns_empty() {
        let mut state = StateInner::new("op-1".into());
        let removed = state.unmark_processed_by_prefix("does_not_exist", "x:");
        assert!(removed.is_empty());
    }

    #[test]
    fn credential_capture_in_flight_initially_empty() {
        let state = StateInner::new("op-1".into());
        assert!(!state.credential_capture_in_flight_for("contoso.local"));
    }

    #[test]
    fn credential_capture_in_flight_after_mark() {
        let mut state = StateInner::new("op-1".into());
        state.mark_credential_capture_in_flight("Contoso.Local");
        // Stored lowercased; lookup is case-insensitive.
        assert!(state.credential_capture_in_flight_for("contoso.local"));
        assert!(state.credential_capture_in_flight_for("CONTOSO.LOCAL"));
        // Unrelated domain stays clear.
        assert!(!state.credential_capture_in_flight_for("fabrikam.local"));
    }

    #[test]
    fn credential_capture_in_flight_expires_after_ttl() {
        let mut state = StateInner::new("op-1".into());
        // Backdate the marker past the TTL by writing directly.
        state.credential_capture_in_flight.insert(
            "contoso.local".to_string(),
            Utc::now() - chrono::Duration::seconds(CAPTURE_IN_FLIGHT_TTL_SECS + 1),
        );
        assert!(!state.credential_capture_in_flight_for("contoso.local"));
    }

    #[test]
    fn credential_capture_in_flight_empty_domain_noop() {
        let mut state = StateInner::new("op-1".into());
        state.mark_credential_capture_in_flight("");
        assert!(state.credential_capture_in_flight.is_empty());
    }

    #[test]
    fn dedup_sets_are_independent() {
        let mut state = StateInner::new("op-1".into());
        state.mark_processed(DEDUP_CRACK_REQUESTS, "hash1".into());
        state.mark_processed(DEDUP_SECRETSDUMP, "192.168.58.10".into());

        assert!(state.is_processed(DEDUP_CRACK_REQUESTS, "hash1"));
        assert!(!state.is_processed(DEDUP_CRACK_REQUESTS, "192.168.58.10"));
        assert!(state.is_processed(DEDUP_SECRETSDUMP, "192.168.58.10"));
        assert!(!state.is_processed(DEDUP_SECRETSDUMP, "hash1"));
    }

    #[test]
    fn exploited_vulnerabilities_tracking() {
        let mut state = StateInner::new("op-1".into());
        assert!(state.exploited_vulnerabilities.is_empty());

        state
            .exploited_vulnerabilities
            .insert("vuln-001".to_string());
        assert!(state.exploited_vulnerabilities.contains("vuln-001"));
        assert!(!state.exploited_vulnerabilities.contains("vuln-002"));
    }

    #[test]
    fn mssql_enum_dispatched_tracking() {
        let mut state = StateInner::new("op-1".into());
        assert!(!state.mssql_enum_dispatched.contains("192.168.58.20"));

        state
            .mssql_enum_dispatched
            .insert("192.168.58.20".to_string());
        assert!(state.mssql_enum_dispatched.contains("192.168.58.20"));
    }

    #[test]
    fn domain_controller_map() {
        let mut state = StateInner::new("op-1".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.20".into());

        assert_eq!(
            state.domain_controllers.get("contoso.local"),
            Some(&"192.168.58.10".to_string())
        );
        assert_eq!(
            state.domain_controllers.get("fabrikam.local"),
            Some(&"192.168.58.20".to_string())
        );
        assert_eq!(state.domain_controllers.get("unknown.local"), None);
    }

    #[test]
    fn all_known_dedup_set_constants() {
        // Verify constants are accessible and match expected names
        let expected = vec![
            DEDUP_CRACK_REQUESTS,
            DEDUP_SECRETSDUMP,
            DEDUP_DELEGATION_CREDS,
            DEDUP_ADCS_SERVERS,
            DEDUP_BLOODHOUND_DOMAINS,
            DEDUP_SPIDERED_SHARES,
            DEDUP_EXPANSION_CREDS,
            DEDUP_ASREP_DOMAINS,
            DEDUP_USERNAME_SPRAY,
            DEDUP_PASSWORD_SPRAY,
            DEDUP_ESC8_SERVERS,
            DEDUP_COERCED_DCS,
            DEDUP_WRITABLE_SHARES,
            DEDUP_HASH_LATERAL,
            DEDUP_SCANNED_TARGETS,
            DEDUP_ACL_STEPS,
            DEDUP_TRUST_FOLLOW,
            DEDUP_S4U_EXPLOITS,
            DEDUP_GMSA_ACCOUNTS,
            DEDUP_LOW_HANGING,
            DEDUP_CRED_SECRETSDUMP,
            DEDUP_SHARE_ENUM,
            DEDUP_ADCS_EXPLOIT,
            DEDUP_GPO_ABUSE,
            DEDUP_LAPS,
            DEDUP_NTLM_RELAY,
            DEDUP_NOPAC,
            DEDUP_ZEROLOGON,
            DEDUP_PRINTNIGHTMARE,
            DEDUP_MSSQL_COERCION,
            DEDUP_PASSWORD_POLICY,
            DEDUP_GPP_SYSVOL,
            DEDUP_NTLMV1_DOWNGRADE,
            DEDUP_LDAP_SIGNING,
            DEDUP_WEBDAV_DETECTION,
            DEDUP_SPOOLER_CHECK,
            DEDUP_MACHINE_ACCOUNT_QUOTA,
            DEDUP_DFS_COERCION,
            DEDUP_PETITPOTAM_UNAUTH,
            DEDUP_WINRM_LATERAL,
            DEDUP_GROUP_ENUMERATION,
            DEDUP_LOCALUSER_SPRAY,
            DEDUP_KRBRELAYUP,
            DEDUP_SEARCHCONNECTOR,
            DEDUP_LSASSY_DUMP,
            DEDUP_RDP_LATERAL,
            DEDUP_FOREIGN_GROUP_ENUM,
            DEDUP_CERTIPY_AUTH,
            DEDUP_SID_ENUMERATION,
            DEDUP_DNS_ENUM,
            DEDUP_DOMAIN_USER_ENUM,
            DEDUP_PTH_SPRAY,
            DEDUP_CERTIFRIED,
            DEDUP_DACL_ABUSE,
            DEDUP_SMBCLIENT_ENUM,
            DEDUP_ACL_DISCOVERY,
            DEDUP_CROSS_FOREST_ENUM,
            DEDUP_CROSS_REALM_LATERAL,
            DEDUP_GOLDEN_CERT,
            DEDUP_MSSQL_RETRY,
            DEDUP_MSSQL_LINK_PIVOT,
            DEDUP_MSSQL_IMPERSONATION,
            DEDUP_ASSIST_ABANDONED,
            DEDUP_SID_HISTORY,
        ];
        assert_eq!(expected.len(), ALL_DEDUP_SETS.len());
        for name in expected {
            assert!(
                ALL_DEDUP_SETS.contains(&name),
                "Missing from ALL_DEDUP_SETS: {name}"
            );
        }
    }

    #[test]
    fn checks_delegation_account() {
        let mut state = StateInner::new("op-1".into());
        assert!(!state.is_delegation_account("john.smith"));

        // Add a constrained delegation vuln for john.smith
        let mut details = std::collections::HashMap::new();
        details.insert("account_name".to_string(), serde_json::json!("john.smith"));
        state.discovered_vulnerabilities.insert(
            "constrained_delegation_john.smith".into(),
            ares_core::models::VulnerabilityInfo {
                vuln_id: "constrained_delegation_john.smith".into(),
                vuln_type: "constrained_delegation".into(),
                target: "".into(),
                discovered_by: "".into(),
                discovered_at: chrono::Utc::now(),
                details,
                recommended_agent: "".into(),
                priority: 8,
            },
        );

        assert!(state.is_delegation_account("john.smith"));
        assert!(state.is_delegation_account("John.Smith")); // case insensitive
        assert!(!state.is_delegation_account("sam.wilson"));
    }

    #[test]
    fn credential_quarantine() {
        let mut state = StateInner::new("op-1".into());

        // Not quarantined initially
        assert!(!state.is_principal_quarantined("jdoe", "child.contoso.local"));

        // Quarantine a credential
        state.quarantine_principal("jdoe", "child.contoso.local");
        assert!(state.is_principal_quarantined("jdoe", "child.contoso.local"));
        assert!(state.is_principal_quarantined("JDOE", "CHILD.CONTOSO.LOCAL")); // case insensitive

        // Different credential not affected
        assert!(!state.is_principal_quarantined("john.smith", "child.contoso.local"));
    }

    #[test]
    fn all_forests_dominated_no_forests() {
        let state = StateInner::new("op-1".into());
        // No domains, no DCs, no trusts → vacuously true
        assert!(state.all_forests_dominated());
    }

    #[test]
    fn all_forests_dominated_single_forest() {
        let mut state = StateInner::new("op-1".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // Not dominated yet
        assert!(!state.all_forests_dominated());

        // Dominate it
        state.dominated_domains.insert("contoso.local".into());
        assert!(state.all_forests_dominated());
    }

    #[test]
    fn all_forests_dominated_multi_forest() {
        let mut state = StateInner::new("op-1".into());
        state
            .domain_controllers
            .insert("child.contoso.local".into(), "192.168.58.11".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.23".into());

        // Dominate only the contoso forest
        state.dominated_domains.insert("child.contoso.local".into());
        state.dominated_domains.insert("contoso.local".into());

        // fabrikam.local is still undominated
        assert!(!state.all_forests_dominated());

        // Dominate fabrikam too
        state.dominated_domains.insert("fabrikam.local".into());
        assert!(state.all_forests_dominated());
    }

    #[test]
    fn user_quarantine_basic() {
        let mut state = StateInner::new("op-1".into());
        assert!(!state.is_principal_quarantined("testuser1", "contoso.local"));

        state.quarantine_principal("testuser1", "contoso.local");
        assert!(state.is_principal_quarantined("testuser1", "contoso.local"));
        assert!(state.is_principal_quarantined("TESTUSER1", "CONTOSO.LOCAL")); // case insensitive

        // Different user not affected
        assert!(!state.is_principal_quarantined("testuser2", "contoso.local"));
        // Same user, different domain not affected
        assert!(!state.is_principal_quarantined("testuser1", "fabrikam.local"));
    }

    #[test]
    fn quarantined_principals_in_domain_filters() {
        let mut state = StateInner::new("op-1".into());
        state.quarantine_principal("testuser1", "contoso.local");
        state.quarantine_principal("testuser2", "contoso.local");
        state.quarantine_principal("testuser3", "fabrikam.local");

        let mut contoso = state.quarantined_principals_in_domain("contoso.local");
        contoso.sort();
        assert_eq!(
            contoso,
            vec!["testuser1".to_string(), "testuser2".to_string()]
        );

        let fabrikam = state.quarantined_principals_in_domain("fabrikam.local");
        assert_eq!(fabrikam, vec!["testuser3".to_string()]);

        let unknown = state.quarantined_principals_in_domain("unknown.local");
        assert!(unknown.is_empty());
    }

    #[test]
    fn quarantined_principals_in_domain_skips_expired() {
        let mut state = StateInner::new("op-1".into());
        state.quarantined_principals.insert(
            "expired@contoso.local".into(),
            Utc::now() - chrono::Duration::seconds(1),
        );
        state.quarantine_principal("fresh", "contoso.local");

        let users = state.quarantined_principals_in_domain("contoso.local");
        assert_eq!(users, vec!["fresh".to_string()]);
    }

    #[test]
    fn credential_quarantine_expired() {
        let mut state = StateInner::new("op-1".into());

        // Insert with an already-expired time
        let key = "jdoe@child.contoso.local".to_string();
        state
            .quarantined_principals
            .insert(key, Utc::now() - chrono::Duration::seconds(1));

        // Should not be quarantined (expired)
        assert!(!state.is_principal_quarantined("jdoe", "child.contoso.local"));
    }
}
