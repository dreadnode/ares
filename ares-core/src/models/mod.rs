//! Data models for the Ares red team orchestration system.

#[cfg(feature = "blue")]
mod blue;
mod core;
mod op_state_event;
mod operation;
mod task;
mod util;

#[cfg(feature = "blue")]
pub use blue::{
    BlueTaskInfo, Evidence, InvestigationStage, PyramidLevel, SharedBlueTeamState, TimelineEvent,
    TriageDecision, TriageRecord,
};
pub use core::{
    is_always_disabled_account, CandidateDomain, Credential, DomainEvidence, Hash, Host,
    KerberosTicket, Share, Target, TrustInfo, User,
};
pub use op_state_event::{OpStateEvent, OpStateEventPayload};
pub use operation::{AttackChainStep, OperationMeta, SharedRedTeamState};
pub use task::{
    AgentInfo, AgentRole, TaskInfo, TaskResult, TaskStatus, TaskStatusRecord, VulnerabilityInfo,
};
// util functions are pub(crate) and imported directly by sibling modules via super::util::

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn credential_roundtrip() {
        // Match the exact compact JSON format used by the state backend.
        let json = r#"{"id":"abc","username":"testuser","password":"P@ssw0rd!","domain":"contoso.local","source":"manual-inject","parent_id":null,"attack_step":0}"#; // pragma: allowlist secret
        let cred: Credential = serde_json::from_str(json).unwrap();
        assert_eq!(cred.username, "testuser");
        assert_eq!(cred.domain, "contoso.local");
        assert_eq!(cred.password, "P@ssw0rd!");
        assert_eq!(cred.attack_step, 0);
        assert!(cred.parent_id.is_none());
    }

    #[test]
    fn hash_roundtrip() {
        let json = r#"{"id":"def","username":"krbtgt","hash_type":"NTLM","hash_value":"aad3b435b51404ee","domain":"contoso.local","source":"secretsdump","cracked_password":null,"discovered_at":"2025-01-28T12:00:00Z","parent_id":null,"attack_step":0}"#; // pragma: allowlist secret
        let h: Hash = serde_json::from_str(json).unwrap();
        assert_eq!(h.username, "krbtgt");
        assert_eq!(h.hash_type, "NTLM");
        assert_eq!(h.domain, "contoso.local");
    }

    #[test]
    fn host_roundtrip() {
        let json = r#"{"ip":"192.168.58.10","hostname":"dc01.contoso.local","os":"Windows Server 2019","roles":["Domain Controller"],"services":["88/tcp kerberos","389/tcp ldap"],"is_dc":true}"#;
        let host: Host = serde_json::from_str(json).unwrap();
        assert_eq!(host.ip, "192.168.58.10");
        assert!(host.is_dc);
        assert!(host.detect_dc());
    }

    #[test]
    fn user_roundtrip() {
        let json = r#"{"username":"testuser","domain":"contoso.local","source":"netexec_smb"}"#;
        let user: User = serde_json::from_str(json).unwrap();
        assert_eq!(user.username, "testuser");
        assert_eq!(user.domain, "contoso.local");
    }

    #[test]
    fn share_roundtrip() {
        let json = r#"{"host":"192.168.58.10","name":"SYSVOL","permissions":"READ","comment":""}"#;
        let share: Share = serde_json::from_str(json).unwrap();
        assert_eq!(share.name, "SYSVOL");
    }

    #[test]
    fn vulnerability_roundtrip() {
        let json = r#"{"vuln_id":"esc1_192.168.58.10_svc","vuln_type":"ADCS_ESC1","target":"192.168.58.10","discovered_by":"recon","discovered_at":"2025-01-28T12:00:00Z","details":{"target_ip":"192.168.58.10"},"recommended_agent":"privesc","priority":1}"#;
        let vuln: VulnerabilityInfo = serde_json::from_str(json).unwrap();
        assert_eq!(vuln.vuln_type, "ADCS_ESC1");
        assert_eq!(vuln.priority, 1);
    }

    #[test]
    fn operation_meta_from_hash() {
        let mut data = HashMap::new();
        data.insert("has_domain_admin".to_string(), "True".to_string());
        data.insert("has_golden_ticket".to_string(), "false".to_string());
        data.insert(
            "started_at".to_string(),
            "2025-01-28T12:00:00+00:00".to_string(),
        );
        data.insert(
            "target_ips".to_string(),
            "192.168.58.10,192.168.58.20".to_string(),
        );

        let meta = OperationMeta::from_redis_hash(&data);
        assert!(meta.has_domain_admin);
        assert!(!meta.has_golden_ticket);
        assert!(meta.started_at.is_some());
        assert_eq!(meta.target_ips.len(), 2);
    }

    #[test]
    fn operation_meta_json_encoded() {
        // Meta values are stored via json.dumps()-style encoding: booleans become
        // "true"/"false", strings become "\"value\"", arrays become "[\"a\",\"b\"]".
        let mut data = HashMap::new();
        data.insert("has_domain_admin".to_string(), "true".to_string());
        data.insert("has_golden_ticket".to_string(), "false".to_string());
        data.insert(
            "started_at".to_string(),
            "\"2025-01-28T12:00:00+00:00\"".to_string(),
        );
        data.insert(
            "target_ips".to_string(),
            r#"["192.168.58.10","192.168.58.20"]"#.to_string(),
        );
        data.insert("target_domain".to_string(), "\"contoso.local\"".to_string());
        data.insert("target_ip".to_string(), "\"192.168.58.10\"".to_string());
        data.insert(
            "domain_admin_path".to_string(),
            "\"secretsdump -> golden ticket\"".to_string(),
        );

        let meta = OperationMeta::from_redis_hash(&data);
        assert!(meta.has_domain_admin);
        assert!(!meta.has_golden_ticket);
        assert!(meta.started_at.is_some());
        assert_eq!(meta.target_ips.len(), 2);
        assert_eq!(meta.target_ips[0], "192.168.58.10");
        assert_eq!(meta.target_ips[1], "192.168.58.20");
        assert_eq!(meta.target_domain.as_deref(), Some("contoso.local"));
        assert_eq!(meta.target_ip.as_deref(), Some("192.168.58.10"));
        assert_eq!(
            meta.domain_admin_path.as_deref(),
            Some("secretsdump -> golden ticket")
        );
    }

    #[test]
    fn meta_null_and_empty() {
        let mut data = HashMap::new();
        data.insert("target_domain".to_string(), "null".to_string());
        data.insert("target_ip".to_string(), "\"\"".to_string());
        data.insert("domain_admin_path".to_string(), "".to_string());

        let meta = OperationMeta::from_redis_hash(&data);
        assert!(meta.target_domain.is_none());
        assert!(meta.target_ip.is_none());
        assert!(meta.domain_admin_path.is_none());
    }

    #[test]
    fn task_status_display() {
        assert_eq!(TaskStatus::InProgress.to_string(), "in_progress");
        assert_eq!(TaskStatus::Pending.to_string(), "pending");
    }

    #[test]
    fn is_always_disabled_account_canonical() {
        assert!(is_always_disabled_account("Guest"));
        assert!(is_always_disabled_account("guest"));
        assert!(is_always_disabled_account("GUEST"));
        assert!(is_always_disabled_account("krbtgt"));
        assert!(is_always_disabled_account("DefaultAccount"));
        assert!(is_always_disabled_account("WDAGUtilityAccount"));
    }

    #[test]
    fn is_always_disabled_account_excludes_real_users() {
        assert!(!is_always_disabled_account("Administrator"));
        assert!(!is_always_disabled_account("svc_sql"));
        assert!(!is_always_disabled_account("jdoe"));
        assert!(!is_always_disabled_account(""));
    }
}
