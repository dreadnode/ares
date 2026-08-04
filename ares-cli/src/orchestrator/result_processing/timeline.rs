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

pub(crate) async fn publish_credential_credited(
    dispatcher: &Arc<Dispatcher>,
    cred: ares_core::models::Credential,
) -> anyhow::Result<bool> {
    let source = cred.source.clone();
    let username = cred.username.clone();
    let domain = cred.domain.clone();
    let is_admin = cred.is_admin;
    let published = dispatcher
        .state
        .publish_credential(&dispatcher.queue, cred)
        .await?;
    if published {
        create_credential_timeline_event(dispatcher, &source, &username, &domain, is_admin).await;
    }
    Ok(published)
}

async fn create_credential_timeline_event(
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

/// Emit a timeline event when a credential is upgraded to admin (Pwn3d! detected).
/// Description for the admin-upgrade timeline event, naming the host the grant
/// was proven on.
///
/// `Credential::is_admin` is a single global bool, so the host that produced the
/// `Pwn3d!` was extracted and then dropped by the same function that found it —
/// ares discovered all three of the lab's local-admin grants and recorded none
/// of their scope. The timeline event is the one consumer that reaches a report,
/// so the host goes here.
///
/// The `Admin access confirmed: ` prefix is load-bearing: the corpus
/// reproduction greps in `GAPS.md` key off it, as do 32 historical events.
/// Extend it, never reword it.
pub(crate) fn admin_upgrade_description(
    username: &str,
    domain: &str,
    pwned_host: Option<&str>,
) -> String {
    match pwned_host {
        Some(host) => format!("Admin access confirmed: {domain}\\{username} on {host} (Pwn3d!)"),
        None => format!("Admin access confirmed: {domain}\\{username} (Pwn3d!)"),
    }
}

pub(crate) async fn create_admin_upgrade_timeline_event(
    dispatcher: &Arc<Dispatcher>,
    username: &str,
    domain: &str,
    pwned_host: Option<&str>,
) {
    let techniques = vec!["T1078".to_string()]; // Valid Accounts
    let event_id = format!(
        "evt-admin-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let description = admin_upgrade_description(username, domain, pwned_host);
    let mut event = serde_json::json!({
        "id": event_id,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "source": "admin_upgrade",
        "description": description,
        "mitre_techniques": techniques,
    });
    if let Some(host) = pwned_host {
        event["target_ip"] = serde_json::json!(host);
    }
    let _ = dispatcher
        .state
        .persist_timeline_event(&dispatcher.queue, &event, &techniques)
        .await;
}

/// Emit a timeline event when a vulnerability is exploited.
pub(crate) async fn create_exploitation_timeline_event(
    dispatcher: &Arc<Dispatcher>,
    vuln_id: &str,
    task_id: &str,
) {
    let techniques = exploitation_techniques(vuln_id);
    let event_id = format!(
        "evt-exploit-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let event = serde_json::json!({
        "id": event_id,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "source": "exploitation",
        "outcome": "succeeded",
        "description": format!("Vulnerability exploited: {vuln_id} (task {task_id})"),
        "mitre_techniques": techniques,
    });
    let _ = dispatcher
        .state
        .persist_timeline_event(&dispatcher.queue, &event, &techniques)
        .await;
}

/// Emit a timeline event for lateral movement via S4U/delegation.
pub(crate) async fn create_lateral_movement_timeline_event(
    dispatcher: &Arc<Dispatcher>,
    target: &str,
    _ticket_path: &str,
) {
    let techniques = vec![
        "T1550.003".to_string(), // Use Alternate Authentication Material: Pass the Ticket
        "T1021".to_string(),     // Remote Services
    ];
    let event_id = format!(
        "evt-lateral-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let event = serde_json::json!({
        "id": event_id,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "source": "s4u_lateral_movement",
        "description": format!("Lateral movement via S4U delegation to {target}"),
        "mitre_techniques": techniques,
    });
    let _ = dispatcher
        .state
        .persist_timeline_event(&dispatcher.queue, &event, &techniques)
        .await;
}

/// Emit a timeline event when Domain Admin is achieved.
pub(crate) async fn create_domain_admin_timeline_event(
    dispatcher: &Arc<Dispatcher>,
    domain: &str,
    path: Option<&str>,
) {
    let techniques = vec![
        "T1003.006".to_string(), // OS Credential Dumping: DCSync
        "T1078.002".to_string(), // Valid Accounts: Domain Accounts
    ];
    let event_id = format!("evt-da-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let description = match path {
        Some(p) => format!("CRITICAL: Domain Admin achieved for {domain} via {p}"),
        None => format!("CRITICAL: Domain Admin achieved for {domain}"),
    };
    let event = serde_json::json!({
        "id": event_id,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "source": "domain_admin",
        "description": description,
        "mitre_techniques": techniques,
    });
    let _ = dispatcher
        .state
        .persist_timeline_event(&dispatcher.queue, &event, &techniques)
        .await;
}

/// Map vulnerability IDs to MITRE ATT&CK technique IDs.
pub(super) fn exploitation_techniques(vuln_id: &str) -> Vec<String> {
    let vuln_lower = vuln_id.to_lowercase();
    let mut techniques: Vec<String> = Vec::new();
    if vuln_lower.contains("unconstrained_delegation") {
        techniques.push("T1558".to_string());
    } else if vuln_lower.contains("constrained_delegation") {
        techniques.push("T1558.003".to_string());
    }
    if vuln_lower.contains("mssql") {
        techniques.push("T1134".to_string());
    }
    if is_adcs_vuln(&vuln_lower) {
        techniques.push("T1649".to_string());
    }
    if vuln_lower.contains("rbcd") {
        techniques.push("T1134.001".to_string());
    }
    if vuln_lower.contains("smb_signing") {
        techniques.push("T1557.001".to_string());
    }
    if vuln_lower.starts_with("acl_") || vuln_lower.contains("_acl_") {
        techniques.push("T1098".to_string());
    }
    if vuln_lower.contains("winrm") {
        techniques.push("T1021.006".to_string());
    }
    if vuln_lower.contains("child_to_parent")
        || vuln_lower.contains("forest_trust")
        || vuln_lower.contains("sid_history")
    {
        techniques.push("T1134.005".to_string());
    }
    if vuln_lower.contains("golden_ticket") {
        techniques.push("T1558.001".to_string());
    }
    if vuln_lower.contains("dc_secretsdump") {
        techniques.push("T1003.006".to_string());
    }
    if vuln_lower.contains("ntlm_relay") {
        techniques.push("T1557.001".to_string());
    }
    if vuln_lower.contains("nopac") {
        techniques.push("T1210".to_string());
    }
    techniques
}

fn is_adcs_vuln(vuln_lower: &str) -> bool {
    if vuln_lower.contains("adcs")
        || vuln_lower.contains("certificate")
        || vuln_lower.contains("certipy")
    {
        return true;
    }
    vuln_lower
        .split("esc")
        .skip(1)
        .any(|rest| rest.chars().next().is_some_and(|c| c.is_ascii_digit()))
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

    // --- exploitation_techniques ---

    #[test]
    fn exploitation_techniques_base() {
        let t = exploitation_techniques("some_vuln");
        assert!(
            t.is_empty(),
            "an unclassified vuln must claim no technique at all: {t:?}"
        );
    }

    #[test]
    fn exploitation_techniques_constrained_delegation() {
        let t = exploitation_techniques("constrained_delegation_dc01");
        assert!(t.contains(&"T1558.003".to_string()));
    }

    #[test]
    fn exploitation_techniques_mssql() {
        let t = exploitation_techniques("mssql_impersonation_sql01");
        assert!(t.contains(&"T1134".to_string()));
        assert!(
            !t.contains(&"T1505".to_string()),
            "T1505 is persistence via a malicious stored procedure, which ares never installs"
        );
    }

    #[test]
    fn exploitation_techniques_esc1() {
        let t = exploitation_techniques("esc1_template");
        assert!(t.contains(&"T1649".to_string()));
    }

    #[test]
    fn exploitation_techniques_esc4() {
        let t = exploitation_techniques("esc4_template");
        assert!(t.contains(&"T1649".to_string()));
    }

    #[test]
    fn exploitation_techniques_rbcd() {
        let t = exploitation_techniques("rbcd_dc01");
        assert!(t.contains(&"T1134.001".to_string()));
    }

    #[test]
    fn acl_edge_abuse_is_account_manipulation_not_the_fallback() {
        for vuln in [
            "acl_genericall_alice_dc01",
            "acl_genericwrite_alice_domain admins",
            "acl_writeproperty_alice_bob",
            "acl_addmember_alice_ca01",
            "acl_forcechangepassword_alice_bob",
        ] {
            let t = exploitation_techniques(vuln);
            assert!(
                t.contains(&"T1098".to_string()),
                "{vuln} must map to T1098, which blue's delegation-abuse rule emits"
            );
            assert!(
                !t.contains(&"T1210".to_string()),
                "{vuln} must not land in the unclassified bucket: {t:?}"
            );
        }
    }

    #[test]
    fn every_esc_number_is_adcs_not_the_fallback() {
        for vuln in [
            "adcs_esc9__esc9",
            "esc3_template",
            "esc13_template",
            "esc16_template",
            "certificate_obtained_dc01",
        ] {
            let t = exploitation_techniques(vuln);
            assert!(
                t.contains(&"T1649".to_string()),
                "{vuln} must map to T1649: {t:?}"
            );
            assert!(!t.contains(&"T1210".to_string()), "{vuln} -> {t:?}");
        }
    }

    #[test]
    fn escalate_is_not_mistaken_for_an_esc_template() {
        let t = exploitation_techniques("escalate_local_admin");
        assert!(
            !t.contains(&"T1649".to_string()),
            "the esc<N> probe must require a digit, not match the word 'escalate': {t:?}"
        );
    }

    #[test]
    fn winrm_access_is_remote_management_not_the_fallback() {
        let t = exploitation_techniques("winrm_access_192.168.58.10");
        assert!(t.contains(&"T1021.006".to_string()), "{t:?}");
        assert!(!t.contains(&"T1210".to_string()), "{t:?}");
    }

    #[test]
    fn nopac_keeps_t1210_so_the_id_still_means_exploitation() {
        let t = exploitation_techniques("nopac_dc01");
        assert!(
            t.contains(&"T1210".to_string()),
            "NoPac is genuine remote-service exploitation, so T1210 here is a real \
             claim rather than the unclassified fallback: {t:?}"
        );
    }

    #[test]
    fn cross_domain_trust_abuse_is_sid_history() {
        for vuln in ["child_to_parent_contoso_fabrikam", "forest_trust_contoso"] {
            let t = exploitation_techniques(vuln);
            assert!(t.contains(&"T1134.005".to_string()), "{vuln} -> {t:?}");
            assert!(!t.contains(&"T1210".to_string()), "{vuln} -> {t:?}");
        }
    }

    #[test]
    fn exploitation_techniques_smb_signing() {
        let t = exploitation_techniques("smb_signing_disabled_192.168.58.10");
        assert!(t.contains(&"T1557.001".to_string()));
    }

    #[test]
    fn exploitation_techniques_unconstrained() {
        let t = exploitation_techniques("unconstrained_delegation_ws01");
        assert!(t.contains(&"T1558".to_string()));
        assert!(
            !t.contains(&"T1558.003".to_string()),
            "unconstrained delegation is not S4U/kerberoasting"
        );
    }

    #[test]
    fn every_emitted_technique_is_coverable_by_the_blue_catalog() {
        // A red technique with no exact or parent/child match in the detection
        // catalog can never be credited, so it lands in the report as "missed"
        // however well blue actually detected the activity. Retiring the blanket
        // T1210 first left mssql on T1505, which nothing covered; mapping it to
        // T1134 puts it back under detect_mssql_impersonation.
        let blue: Vec<&str> = ares_core::detection::detection_config()
            .templates
            .values()
            .map(|t| t.mitre_id.as_str())
            .collect();

        for vuln in [
            "unconstrained_delegation_ws01",
            "constrained_delegation_dc01",
            "mssql_impersonation_sql01",
            "esc1_template",
            "esc4_template",
            "esc8_ca01",
            "rbcd_dc01",
            "smb_signing_disabled_192.168.58.10",
            "acl_genericall_alice_dc01",
            "acl_forcechangepassword_alice_bob",
            "adcs_esc9__esc9",
            "certificate_obtained_dc01",
            "winrm_access_192.168.58.10",
            "nopac_dc01",
            "child_to_parent_contoso_fabrikam",
            "forest_trust_contoso",
            "sid_history_contoso",
            "golden_ticket_contoso",
            "dc_secretsdump_dc01",
            "ntlm_relay_192.168.58.10",
            "some_unmapped_vuln",
        ] {
            for red in exploitation_techniques(vuln) {
                assert!(
                    blue.iter().any(|b| {
                        ares_core::correlation::redblue::RedBlueCorrelator::techniques_match(
                            Some(&red),
                            Some(b),
                        )
                    }),
                    "{vuln} emits {red}, which no detection template can cover"
                );
            }
        }
    }

    #[test]
    fn exploitation_techniques_specific_vuln_omits_t1210() {
        for vuln in [
            "esc1_template",
            "esc8_ca01",
            "constrained_delegation_dc01",
            "unconstrained_delegation_ws01",
            "rbcd_dc01",
            "mssql_impersonation_sql01",
            "smb_signing_disabled_192.168.58.10",
        ] {
            let t = exploitation_techniques(vuln);
            assert!(
                !t.contains(&"T1210".to_string()),
                "{vuln} is not exploitation of a remote service"
            );
        }
    }

    #[test]
    fn families_blue_actually_detects_keep_a_technique_after_the_fallback_dies() {
        for (vuln, want) in [
            ("golden_ticket_contoso", "T1558.001"),
            ("dc_secretsdump_dc01", "T1003.006"),
            ("ntlm_relay_192.168.58.10", "T1557.001"),
            ("sid_history_contoso", "T1134.005"),
        ] {
            let t = exploitation_techniques(vuln);
            assert!(
                t.contains(&want.to_string()),
                "{vuln} rode the T1210 fallback; blue has an exact rule for it, so dropping \
                 the fallback must not leave it silent: want {want}, got {t:?}"
            );
        }
    }

    #[test]
    fn unrecognized_vuln_claims_no_technique_instead_of_t1210() {
        for vuln in ["zerologon_dc01", "printnightmare_web01", "some_vuln"] {
            let t = exploitation_techniques(vuln);
            assert!(
                t.is_empty(),
                "{vuln} is unclassified, and emitting T1210 for it lets any blue rule \
                 carrying T1210 claim coverage red never earned: {t:?}"
            );
        }
    }

    #[test]
    fn mssql_linked_server_rule_matches_mssql_and_not_nopac() {
        let (_, entry) = ares_core::detection::find_template("detect_mssql_linked_server")
            .expect("detect_mssql_linked_server must exist");
        let matches = |red: &str| {
            ares_core::correlation::redblue::RedBlueCorrelator::techniques_match(
                Some(red),
                Some(&entry.mitre_id),
            )
        };

        for red in exploitation_techniques("mssql_linked_server_sql01") {
            assert!(
                matches(&red),
                "a blue MSSQL rule that no MSSQL vuln can match is coverage red never gets \
                 credited for: red={red} blue={}",
                entry.mitre_id
            );
        }

        for red in exploitation_techniques("nopac_dc01") {
            assert!(
                !matches(&red),
                "an MSSQL linked-server alert must not credit NoPac coverage: red={red} \
                 blue={}",
                entry.mitre_id
            );
        }
    }
}
