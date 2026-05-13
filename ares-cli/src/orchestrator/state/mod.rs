//! In-memory shared state synced with Redis.
//!
//! `SharedState` wraps the operation state in `Arc<RwLock<...>>` so that all
//! background automation tasks can read state concurrently, and writes
//! (credential publishing, result processing) are serialized.
//!
//! State is loaded from Redis at startup and updated incrementally as results
//! arrive. Dedup sets are persisted to Redis so they survive orchestrator restarts.

mod dedup;
pub mod domain_probe;
mod inner;
mod persistence;
mod publishing;
pub(crate) mod replay;
mod shared;

// Re-export everything that was publicly visible from the old single file.
pub use dedup::MAX_EXPLOIT_FAILURES;
pub use inner::StateInner;
pub use shared::SharedState;

pub const DEDUP_CRACK_REQUESTS: &str = "crack_requests";
pub const DEDUP_SECRETSDUMP: &str = "secretsdump";
pub const DEDUP_DELEGATION_CREDS: &str = "delegation_creds";
pub const DEDUP_ADCS_SERVERS: &str = "adcs_servers";
pub const DEDUP_BLOODHOUND_DOMAINS: &str = "bloodhound_domains";
pub const DEDUP_SPIDERED_SHARES: &str = "spidered_shares";
pub const DEDUP_EXPANSION_CREDS: &str = "expansion_creds";
pub const DEDUP_ASREP_DOMAINS: &str = "asrep_domains";
pub const DEDUP_USERNAME_SPRAY: &str = "username_spray";
pub const DEDUP_PASSWORD_SPRAY: &str = "password_spray";
pub const DEDUP_ESC8_SERVERS: &str = "esc8_servers";
pub const DEDUP_COERCED_DCS: &str = "coerced_dcs";
pub const DEDUP_WRITABLE_SHARES: &str = "writable_shares";
pub const DEDUP_HASH_LATERAL: &str = "hash_lateral";
pub const DEDUP_SCANNED_TARGETS: &str = "scanned_targets";
pub const DEDUP_ACL_STEPS: &str = "acl_steps";
pub const DEDUP_TRUST_FOLLOW: &str = "trust_follow";
pub const DEDUP_S4U_EXPLOITS: &str = "s4u_exploits";
pub const DEDUP_GMSA_ACCOUNTS: &str = "gmsa_accounts";
pub const DEDUP_LOW_HANGING: &str = "low_hanging";
pub const DEDUP_CRED_SECRETSDUMP: &str = "cred_secretsdump";
pub const DEDUP_SHARE_ENUM: &str = "share_enum";
pub const DEDUP_ADCS_EXPLOIT: &str = "adcs_exploit";
pub const DEDUP_GPO_ABUSE: &str = "gpo_abuse";
pub const DEDUP_LAPS: &str = "laps_extract";
pub const DEDUP_NTLM_RELAY: &str = "ntlm_relay";
pub const DEDUP_NOPAC: &str = "nopac";
pub const DEDUP_ZEROLOGON: &str = "zerologon";
pub const DEDUP_PRINTNIGHTMARE: &str = "printnightmare";
pub const DEDUP_MSSQL_COERCION: &str = "mssql_coercion";
pub const DEDUP_PASSWORD_POLICY: &str = "password_policy";
pub const DEDUP_GPP_SYSVOL: &str = "gpp_sysvol";
pub const DEDUP_NTLMV1_DOWNGRADE: &str = "ntlmv1_downgrade";
pub const DEDUP_LDAP_SIGNING: &str = "ldap_signing";
pub const DEDUP_WEBDAV_DETECTION: &str = "webdav_detection";
pub const DEDUP_SPOOLER_CHECK: &str = "spooler_check";
pub const DEDUP_MACHINE_ACCOUNT_QUOTA: &str = "machine_account_quota";
pub const DEDUP_DFS_COERCION: &str = "dfs_coercion";
pub const DEDUP_PETITPOTAM_UNAUTH: &str = "petitpotam_unauth";
pub const DEDUP_WINRM_LATERAL: &str = "winrm_lateral";
pub const DEDUP_GROUP_ENUMERATION: &str = "group_enumeration";
pub const DEDUP_LOCALUSER_SPRAY: &str = "localuser_spray";
pub const DEDUP_KRBRELAYUP: &str = "krbrelayup";
pub const DEDUP_SEARCHCONNECTOR: &str = "searchconnector";
pub const DEDUP_LSASSY_DUMP: &str = "lsassy_dump";
pub const DEDUP_RDP_LATERAL: &str = "rdp_lateral";
pub const DEDUP_FOREIGN_GROUP_ENUM: &str = "foreign_group_enum";
pub const DEDUP_CERTIPY_AUTH: &str = "certipy_auth";
pub const DEDUP_SID_ENUMERATION: &str = "sid_enumeration";
pub const DEDUP_DNS_ENUM: &str = "dns_enum";
pub const DEDUP_DOMAIN_USER_ENUM: &str = "domain_user_enum";
pub const DEDUP_PTH_SPRAY: &str = "pth_spray";
pub const DEDUP_CERTIFRIED: &str = "certifried";
pub const DEDUP_DACL_ABUSE: &str = "dacl_abuse";
pub const DEDUP_SMBCLIENT_ENUM: &str = "smbclient_enum";
pub const DEDUP_ACL_DISCOVERY: &str = "acl_discovery";
pub const DEDUP_CROSS_FOREST_ENUM: &str = "cross_forest_enum";
pub const DEDUP_CROSS_REALM_LATERAL: &str = "cross_realm_lateral";
pub const DEDUP_GOLDEN_CERT: &str = "golden_cert";
/// Per-(vuln_id, credential) dedup for re-dispatching MSSQL exploits when
/// a new cred for the vuln's domain becomes available after the initial
/// LLM attempt failed (e.g. cred-timing race in cross-forest pivots).
pub const DEDUP_MSSQL_RETRY: &str = "mssql_retry";

/// Dedup for `auto_mssql_link_pivot` — a deterministic per-linked-server
/// probe that fires `mssql_exec_linked` directly via the tool dispatcher.
/// The companion automation deduplicates only after either a confirmed
/// remote SELECT or attempt-cap exhaustion, so a one-shot transient auth
/// failure does not permanently bury the cross-forest hop primitive.
pub const DEDUP_MSSQL_LINK_PIVOT: &str = "mssql_link_pivot";

/// Dedup for `auto_mssql_impersonation` — fires `mssql_impersonate` directly
/// when an `mssql_impersonation` vuln has been confirmed AND a credential
/// for the named impersonable account is in state. Key is per-(vuln_id,
/// account); a transient auth race that fails the probe clears the dedup
/// so the next tick re-attempts up to MAX_IMPERSONATION_ATTEMPTS.
pub const DEDUP_MSSQL_IMPERSONATION: &str = "mssql_impersonation_auto";

/// Task patterns that ended with `RequestAssistance` are recorded here and
/// refused on re-dispatch. Each entry is a canonical key of
/// `(task_type, target_ip, username, domain)` — enough to identify a
/// repeating doomed dispatch without false-positiving unrelated work
/// against the same target. Caps token burn from automations that keep
/// firing the same impossible task (e.g. missing tool primitive, no auth
/// resolvable for the principal, wrong-realm pairing).
pub const DEDUP_ASSIST_ABANDONED: &str = "assist_abandoned";

/// Dedup for `auto_sid_history_enum` — one LDAP `(sIDHistory=*)` probe per
/// (domain, DC) pair. The probe is a read-only LDAP query and the result
/// immediately marks `sid_history_<user>` exploited, so re-firing is wasteful.
pub const DEDUP_SID_HISTORY: &str = "sid_history_enum";

/// Vuln queue ZSET key suffix.
pub const KEY_VULN_QUEUE: &str = "vuln_queue";

/// Discovery list key prefix (NOT under ares:op:).
pub const DISCOVERY_KEY_PREFIX: &str = "ares:discoveries";

const ALL_DEDUP_SETS: &[&str] = &[
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
    DEDUP_SHARE_ENUM,
    DEDUP_GMSA_ACCOUNTS,
    DEDUP_LOW_HANGING,
    DEDUP_CRED_SECRETSDUMP,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_dedup_sets_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for name in ALL_DEDUP_SETS {
            assert!(seen.insert(*name), "Duplicate dedup set name: {name}");
        }
    }

    #[test]
    fn new_dedup_constants_in_all_dedup_sets() {
        let new_constants = [
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
        ];
        for c in &new_constants {
            assert!(
                ALL_DEDUP_SETS.contains(c),
                "Dedup constant '{c}' missing from ALL_DEDUP_SETS"
            );
        }
    }

    #[test]
    fn dedup_set_count() {
        // Ensure we know how many dedup sets exist (catches accidental omissions)
        assert!(
            ALL_DEDUP_SETS.len() >= 45,
            "Expected at least 45 dedup sets, got {}",
            ALL_DEDUP_SETS.len()
        );
    }
}
