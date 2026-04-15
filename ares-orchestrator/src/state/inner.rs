//! StateInner — the actual mutable state backing SharedState.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};

use ares_core::models::*;

use super::ALL_DEDUP_SETS;

/// Lockout quarantine duration: 5 minutes matches S4U cooldown and typical
/// AD lockout observation windows. Longer values block the critical path.
const QUARANTINE_DURATION_SECS: i64 = 300;

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

    // Vulnerability tracking
    pub discovered_vulnerabilities: HashMap<String, VulnerabilityInfo>,
    pub exploited_vulnerabilities: HashSet<String>,

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

    // Credential lockout quarantine: `user@domain` → expiry time.
    // Credentials that triggered STATUS_ACCOUNT_LOCKED_OUT or
    // KDC_ERR_CLIENT_REVOKED are quarantined to avoid burning auth budget.
    pub quarantined_credentials: HashMap<String, DateTime<Utc>>,

    // Completion flag (set externally to signal operation should wrap up)
    pub completed: bool,
}

impl StateInner {
    pub(super) fn new(operation_id: String) -> Self {
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
            discovered_vulnerabilities: HashMap::new(),
            exploited_vulnerabilities: HashSet::new(),
            domain_controllers: HashMap::new(),
            netbios_to_fqdn: HashMap::new(),
            domain_sids: HashMap::new(),
            admin_names: HashMap::new(),
            trusted_domains: HashMap::new(),
            dominated_domains: HashSet::new(),
            has_domain_admin: false,
            has_golden_ticket: false,
            domain_admin_path: None,
            dedup,
            mssql_enum_dispatched: HashSet::new(),
            acl_chains: Vec::new(),
            dispatched_acl_steps: HashSet::new(),
            pending_tasks: HashMap::new(),
            completed_tasks: HashMap::new(),
            quarantined_credentials: HashMap::new(),
            completed: false,
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

    /// Check if a credential is quarantined due to lockout.
    /// Expired quarantines are ignored (lazy cleanup).
    pub fn is_credential_quarantined(&self, username: &str, domain: &str) -> bool {
        let key = format!("{}@{}", username.to_lowercase(), domain.to_lowercase());
        self.quarantined_credentials
            .get(&key)
            .map(|expiry| Utc::now() < *expiry)
            .unwrap_or(false)
    }

    /// Quarantine a credential for `QUARANTINE_DURATION_SECS` after lockout.
    pub fn quarantine_credential(&mut self, username: &str, domain: &str) {
        let key = format!("{}@{}", username.to_lowercase(), domain.to_lowercase());
        let expiry = Utc::now() + chrono::Duration::seconds(QUARANTINE_DURATION_SECS);
        self.quarantined_credentials.insert(key, expiry);
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::*;

    #[test]
    fn test_state_inner_new_initializes_all_dedup_sets() {
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
    fn test_is_processed_returns_false_for_unknown_set() {
        let state = StateInner::new("op-1".into());
        assert!(!state.is_processed("nonexistent_set", "key1"));
    }

    #[test]
    fn test_mark_processed_and_is_processed() {
        let mut state = StateInner::new("op-1".into());
        assert!(!state.is_processed(DEDUP_CRACK_REQUESTS, "hash1"));

        state.mark_processed(DEDUP_CRACK_REQUESTS, "hash1".into());
        assert!(state.is_processed(DEDUP_CRACK_REQUESTS, "hash1"));
        assert!(!state.is_processed(DEDUP_CRACK_REQUESTS, "hash2"));
    }

    #[test]
    fn test_mark_processed_creates_new_set_if_needed() {
        let mut state = StateInner::new("op-1".into());
        state.mark_processed("custom_set", "key1".into());
        assert!(state.is_processed("custom_set", "key1"));
    }

    #[test]
    fn test_mark_processed_idempotent() {
        let mut state = StateInner::new("op-1".into());
        state.mark_processed(DEDUP_SECRETSDUMP, "192.168.58.10".into());
        state.mark_processed(DEDUP_SECRETSDUMP, "192.168.58.10".into());
        assert_eq!(state.dedup[DEDUP_SECRETSDUMP].len(), 1);
    }

    #[test]
    fn test_dedup_sets_are_independent() {
        let mut state = StateInner::new("op-1".into());
        state.mark_processed(DEDUP_CRACK_REQUESTS, "hash1".into());
        state.mark_processed(DEDUP_SECRETSDUMP, "192.168.58.10".into());

        assert!(state.is_processed(DEDUP_CRACK_REQUESTS, "hash1"));
        assert!(!state.is_processed(DEDUP_CRACK_REQUESTS, "192.168.58.10"));
        assert!(state.is_processed(DEDUP_SECRETSDUMP, "192.168.58.10"));
        assert!(!state.is_processed(DEDUP_SECRETSDUMP, "hash1"));
    }

    #[test]
    fn test_exploited_vulnerabilities_tracking() {
        let mut state = StateInner::new("op-1".into());
        assert!(state.exploited_vulnerabilities.is_empty());

        state
            .exploited_vulnerabilities
            .insert("vuln-001".to_string());
        assert!(state.exploited_vulnerabilities.contains("vuln-001"));
        assert!(!state.exploited_vulnerabilities.contains("vuln-002"));
    }

    #[test]
    fn test_mssql_enum_dispatched_tracking() {
        let mut state = StateInner::new("op-1".into());
        assert!(!state.mssql_enum_dispatched.contains("192.168.58.20"));

        state
            .mssql_enum_dispatched
            .insert("192.168.58.20".to_string());
        assert!(state.mssql_enum_dispatched.contains("192.168.58.20"));
    }

    #[test]
    fn test_domain_controller_map() {
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
    fn test_all_known_dedup_set_constants() {
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
    fn test_is_delegation_account() {
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
    fn test_credential_quarantine() {
        let mut state = StateInner::new("op-1".into());

        // Not quarantined initially
        assert!(!state.is_credential_quarantined("jdoe", "child.contoso.local"));

        // Quarantine a credential
        state.quarantine_credential("jdoe", "child.contoso.local");
        assert!(state.is_credential_quarantined("jdoe", "child.contoso.local"));
        assert!(state.is_credential_quarantined("JDOE", "CHILD.CONTOSO.LOCAL")); // case insensitive

        // Different credential not affected
        assert!(!state.is_credential_quarantined("john.smith", "child.contoso.local"));
    }

    #[test]
    fn test_credential_quarantine_expired() {
        let mut state = StateInner::new("op-1".into());

        // Insert with an already-expired time
        let key = "jdoe@child.contoso.local".to_string();
        state
            .quarantined_credentials
            .insert(key, Utc::now() - chrono::Duration::seconds(1));

        // Should not be quarantined (expired)
        assert!(!state.is_credential_quarantined("jdoe", "child.contoso.local"));
    }
}
