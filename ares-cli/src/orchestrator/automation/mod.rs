//! Background automation tasks.
//!
//! Each `auto_*` function is a long-running tokio task that periodically checks
//! the shared state and dispatches new tasks when conditions are met. All follow
//! the same pattern:
//!
//!   1. Sleep for an interval (configurable)
//!   2. Take a read lock, collect new work items
//!   3. Release lock, submit tasks via the dispatcher
//!   4. Mark items as processed (write lock + Redis persist)
//!
//! This mirrors the Python `_orchestrator.py` background tasks but eliminates
//! all threading hacks since tokio tasks are truly concurrent.

mod acl;
mod acl_discovery;
mod adcs;
mod adcs_exploitation;
mod bloodhound;
mod certifried;
mod certipy_auth;
mod coercion;
mod crack;
mod credential_access;
mod credential_expansion;
mod credential_reuse;
mod cross_forest_enum;
mod dacl_abuse;
mod delegation;
mod dfs_coercion;
mod dns_enum;
mod domain_user_enum;
mod foreign_group_enum;
mod gmsa;
mod golden_cert;
mod golden_ticket;
mod gpo;
mod gpp_sysvol;
mod group_enumeration;
mod krbrelayup;
mod laps;
mod ldap_signing;
mod localuser_spray;
mod lsassy_dump;
mod machine_account_quota;
mod mssql;
mod mssql_coercion;
mod mssql_exploitation;
mod mssql_link_pivot;
mod nopac;
mod ntlm_relay;
mod ntlmv1_downgrade;
mod password_policy;
mod petitpotam_unauth;
mod print_nightmare;
mod pth_spray;
mod rbcd;
mod rdp_lateral;
mod refresh;
mod s4u;
mod searchconnector_coercion;
mod secretsdump;
mod shadow_credentials;
mod share_coercion;
mod share_enum;
mod shares;
mod sid_enumeration;
mod sid_history_enum;
mod smb_signing;
mod smbclient_enum;
mod spooler_check;
mod stall_detection;
mod trust;
mod unconstrained;
mod webdav_detection;
mod winrm_lateral;
mod zerologon;

// Re-export all public task functions at the same paths they had before the split.
pub use acl::auto_acl_chain_follow;
pub use acl_discovery::auto_acl_discovery;
pub use adcs::auto_adcs_enumeration;
pub use adcs_exploitation::auto_adcs_exploitation;
pub(crate) use adcs_exploitation::EXPLOITABLE_ESC_TYPES;
pub use bloodhound::auto_bloodhound;
pub use certifried::auto_certifried;
pub use certipy_auth::auto_certipy_auth;
pub use coercion::auto_coercion;
pub use crack::auto_crack_dispatch;
pub use credential_access::auto_credential_access;
pub use credential_expansion::auto_credential_expansion;
pub use credential_reuse::auto_credential_reuse;
pub use cross_forest_enum::auto_cross_forest_enum;
pub use dacl_abuse::auto_dacl_abuse;
pub use delegation::auto_delegation_enumeration;
pub use dfs_coercion::auto_dfs_coercion;
pub use dns_enum::auto_dns_enum;
pub use domain_user_enum::auto_domain_user_enum;
pub use foreign_group_enum::auto_foreign_group_enum;
pub use gmsa::auto_gmsa_extraction;
pub use golden_cert::auto_golden_cert;
pub use golden_ticket::auto_golden_ticket;
pub use gpo::auto_gpo_abuse;
pub use gpp_sysvol::auto_gpp_sysvol;
pub use group_enumeration::auto_group_enumeration;
pub use krbrelayup::auto_krbrelayup;
pub use laps::auto_laps_extraction;
pub use ldap_signing::auto_ldap_signing;
pub use localuser_spray::auto_localuser_spray;
pub use lsassy_dump::auto_lsassy_dump;
pub use machine_account_quota::auto_machine_account_quota;
pub use mssql::auto_mssql_detection;
pub use mssql_coercion::auto_mssql_coercion;
pub use mssql_exploitation::auto_mssql_exploitation;
pub use mssql_exploitation::auto_mssql_impersonation;
pub use mssql_link_pivot::auto_mssql_link_pivot;
pub use nopac::auto_nopac;
pub use ntlm_relay::auto_ntlm_relay;
pub use ntlmv1_downgrade::auto_ntlmv1_downgrade;
pub use password_policy::auto_password_policy;
pub use petitpotam_unauth::auto_petitpotam_unauth;
pub use print_nightmare::auto_print_nightmare;
pub use pth_spray::auto_pth_spray;
pub use rbcd::auto_rbcd_exploitation;
pub use rdp_lateral::auto_rdp_lateral;
pub use refresh::state_refresh;
pub use s4u::auto_s4u_exploitation;
pub use searchconnector_coercion::auto_searchconnector_coercion;
pub use secretsdump::auto_local_admin_secretsdump;
pub use shadow_credentials::auto_shadow_credentials;
pub use share_coercion::auto_share_coercion;
pub use share_enum::auto_share_enumeration;
pub use shares::auto_share_spider;
pub use sid_enumeration::auto_sid_enumeration;
pub use sid_history_enum::auto_sid_history_enum;
pub use smb_signing::auto_smb_signing_detection;
pub use smbclient_enum::auto_smbclient_enum;
pub use spooler_check::auto_spooler_check;
pub use stall_detection::auto_stall_detection;
pub use trust::auto_trust_follow;
pub use unconstrained::auto_unconstrained_exploitation;
pub use webdav_detection::auto_webdav_detection;
pub use winrm_lateral::auto_winrm_lateral;
pub use zerologon::auto_zerologon;

pub(crate) fn crack_dedup_key(hash: &ares_core::models::Hash) -> String {
    let prefix = &hash.hash_value[..32.min(hash.hash_value.len())];
    format!(
        "{}:{}:{}",
        hash.domain.to_lowercase(),
        hash.username.to_lowercase(),
        prefix
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::Hash;

    fn make_hash(username: &str, domain: &str, hash_value: &str) -> Hash {
        Hash {
            id: "h1".into(),
            username: username.into(),
            hash_type: "NTLM".into(),
            hash_value: hash_value.into(),
            domain: domain.into(),
            source: "test".into(),
            cracked_password: None,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        }
    }

    #[test]
    fn dedup_key_basic() {
        let h = make_hash("Admin", "CONTOSO.LOCAL", "aad3b435b51404eeaad3b435b51404ee");
        let key = crack_dedup_key(&h);
        assert_eq!(key, "contoso.local:admin:aad3b435b51404eeaad3b435b51404ee");
    }

    #[test]
    fn dedup_key_short_hash() {
        let h = make_hash("user", "domain.com", "abc123");
        let key = crack_dedup_key(&h);
        assert_eq!(key, "domain.com:user:abc123");
    }

    #[test]
    fn dedup_key_long_hash_truncated() {
        let long_hash = "a".repeat(64);
        let h = make_hash("svc", "contoso.local", &long_hash);
        let key = crack_dedup_key(&h);
        assert!(key.ends_with(&"a".repeat(32)));
        assert!(!key.ends_with(&"a".repeat(33)));
    }

    #[test]
    fn dedup_key_case_insensitive() {
        let h1 = make_hash("Admin", "CONTOSO.LOCAL", "abc");
        let h2 = make_hash("admin", "contoso.local", "abc");
        assert_eq!(crack_dedup_key(&h1), crack_dedup_key(&h2));
    }
}
