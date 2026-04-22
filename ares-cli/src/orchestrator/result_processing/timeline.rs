//! Timeline event helpers.

use std::sync::Arc;

use crate::orchestrator::dispatcher::Dispatcher;

/// Classify MITRE techniques for a credential discovery event.
pub(crate) fn credential_techniques(source: &str, is_admin: bool) -> Vec<String> {
    let mut techniques = vec![if is_admin {
        "T1078".to_string()
    } else {
        "T1552".to_string()
    }];
    let source_lower = source.to_lowercase();
    if source_lower.contains("kerberoast") {
        techniques.push("T1558.003".to_string());
    }
    if source_lower.contains("asrep") || source_lower.contains("as-rep") {
        techniques.push("T1558.004".to_string());
    }
    if source_lower.contains("cracked") {
        techniques.push("T1110".to_string());
    }
    techniques
}

/// Classify MITRE techniques for a hash discovery event.
pub(crate) fn hash_techniques(hash_value: &str, hash_type: &str, source: &str) -> Vec<String> {
    let mut techniques: Vec<String> = vec!["T1003".to_string()];
    let hash_value_lower = hash_value.to_lowercase();
    let hash_type_lower = hash_type.to_lowercase();
    let source_lower = source.to_lowercase();
    if hash_value_lower.contains("$krb5tgs$")
        || matches!(
            hash_type_lower.as_str(),
            "kerberoast" | "krb5tgs" | "tgs-rep" | "tgs"
        )
        || source_lower.contains("kerberoast")
    {
        techniques.push("T1558.003".to_string());
    }
    if hash_value_lower.contains("$krb5asrep$")
        || matches!(hash_type_lower.as_str(), "asrep" | "as-rep" | "krb5asrep")
        || source_lower.contains("asrep")
        || source_lower.contains("as-rep")
    {
        techniques.push("T1558.004".to_string());
    }
    if hash_type_lower == "ntlm"
        && (source_lower.contains("secretsdump") || source_lower.contains("dcsync"))
    {
        techniques.push("T1003.006".to_string());
    }
    techniques
}

/// Check if a hash is for a critical account (krbtgt or administrator).
pub(crate) fn is_critical_hash(username: &str) -> bool {
    matches!(username.to_lowercase().as_str(), "krbtgt" | "administrator")
}

pub(crate) async fn create_credential_timeline_event(
    dispatcher: &Arc<Dispatcher>,
    source: &str,
    username: &str,
    domain: &str,
    is_admin: bool,
) {
    let techniques = credential_techniques(source, is_admin);
    let event_id = format!(
        "evt-cred-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let event = serde_json::json!({
        "id": event_id,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "source": source,
        "description": format!("Credential discovered: {domain}\\{username} via {source}"),
        "mitre_techniques": techniques,
    });
    let _ = dispatcher
        .state
        .persist_timeline_event(&dispatcher.queue, &event, &techniques)
        .await;
}

pub(crate) async fn create_hash_timeline_event(
    dispatcher: &Arc<Dispatcher>,
    username: &str,
    domain: &str,
    hash_type: &str,
    hash_value: &str,
    source: &str,
) {
    let techniques = hash_techniques(hash_value, hash_type, source);
    let description = if is_critical_hash(username) {
        format!("CRITICAL: Hash discovered: {domain}\\{username} ({hash_type})")
    } else {
        format!("Hash discovered: {domain}\\{username} ({hash_type})")
    };
    let event_id = format!(
        "evt-hash-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let event = serde_json::json!({
        "id": event_id,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "source": source,
        "description": description,
        "mitre_techniques": techniques,
    });
    let _ = dispatcher
        .state
        .persist_timeline_event(&dispatcher.queue, &event, &techniques)
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- credential_techniques ---

    #[test]
    fn credential_techniques_admin() {
        let t = credential_techniques("nxc-smb", true);
        assert!(t.contains(&"T1078".to_string()));
        assert!(!t.contains(&"T1552".to_string()));
    }

    #[test]
    fn credential_techniques_non_admin() {
        let t = credential_techniques("nxc-smb", false);
        assert!(t.contains(&"T1552".to_string()));
        assert!(!t.contains(&"T1078".to_string()));
    }

    #[test]
    fn credential_techniques_kerberoast_source() {
        let t = credential_techniques("kerberoast", false);
        assert!(t.contains(&"T1558.003".to_string()));
    }

    #[test]
    fn credential_techniques_asrep_source() {
        let t = credential_techniques("asrep", false);
        assert!(t.contains(&"T1558.004".to_string()));
    }

    #[test]
    fn credential_techniques_as_rep_hyphenated() {
        let t = credential_techniques("as-rep", false);
        assert!(t.contains(&"T1558.004".to_string()));
    }

    #[test]
    fn credential_techniques_cracked_source() {
        let t = credential_techniques("cracked", true);
        assert!(t.contains(&"T1110".to_string()));
    }

    #[test]
    fn credential_techniques_no_special_source() {
        let t = credential_techniques("manual", false);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0], "T1552");
    }

    #[test]
    fn credential_techniques_case_insensitive() {
        let t = credential_techniques("KERBEROAST", false);
        assert!(t.contains(&"T1558.003".to_string()));
    }

    // --- hash_techniques ---

    #[test]
    fn hash_techniques_base() {
        let t = hash_techniques("aabbccdd", "ntlm", "manual");
        assert!(t.contains(&"T1003".to_string()));
    }

    #[test]
    fn hash_techniques_krb5tgs_in_value() {
        let t = hash_techniques("$krb5tgs$23$*user", "unknown", "tool");
        assert!(t.contains(&"T1558.003".to_string()));
    }

    #[test]
    fn hash_techniques_kerberoast_type() {
        let t = hash_techniques("somehash", "kerberoast", "tool");
        assert!(t.contains(&"T1558.003".to_string()));
    }

    #[test]
    fn hash_techniques_tgs_rep_type() {
        let t = hash_techniques("somehash", "tgs-rep", "tool");
        assert!(t.contains(&"T1558.003".to_string()));
    }

    #[test]
    fn hash_techniques_kerberoast_source() {
        let t = hash_techniques("somehash", "unknown", "kerberoast");
        assert!(t.contains(&"T1558.003".to_string()));
    }

    #[test]
    fn hash_techniques_krb5asrep_in_value() {
        let t = hash_techniques("$krb5asrep$23$user", "unknown", "tool");
        assert!(t.contains(&"T1558.004".to_string()));
    }

    #[test]
    fn hash_techniques_asrep_type() {
        let t = hash_techniques("somehash", "asrep", "tool");
        assert!(t.contains(&"T1558.004".to_string()));
    }

    #[test]
    fn hash_techniques_asrep_source() {
        let t = hash_techniques("somehash", "unknown", "as-rep");
        assert!(t.contains(&"T1558.004".to_string()));
    }

    #[test]
    fn hash_techniques_ntlm_secretsdump() {
        let t = hash_techniques("aabbccdd", "ntlm", "secretsdump");
        assert!(t.contains(&"T1003.006".to_string()));
    }

    #[test]
    fn hash_techniques_ntlm_dcsync() {
        let t = hash_techniques("aabbccdd", "ntlm", "dcsync");
        assert!(t.contains(&"T1003.006".to_string()));
    }

    #[test]
    fn hash_techniques_ntlm_no_secretsdump() {
        let t = hash_techniques("aabbccdd", "ntlm", "manual");
        assert!(!t.contains(&"T1003.006".to_string()));
    }

    // --- is_critical_hash ---

    #[test]
    fn critical_hash_krbtgt() {
        assert!(is_critical_hash("krbtgt"));
    }

    #[test]
    fn critical_hash_administrator() {
        assert!(is_critical_hash("Administrator"));
    }

    #[test]
    fn critical_hash_regular_user() {
        assert!(!is_critical_hash("jsmith"));
    }
}
