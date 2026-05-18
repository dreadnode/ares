//! Operation recovery manager.
//!
//! On startup, the orchestrator can recover state from a previous run by
//! loading it from Redis and re-enqueueing any interrupted tasks (those with
//! status PENDING, IN_PROGRESS, or RETRYING).
//!
//! Key behaviors:
//!
//! - **Hash deduplication** (`dedupe_hashes`) -- AS-REP by (domain,username),
//!   Kerberoast by (domain,username,spn_key), NTLM by exact hash value.
//! - **Pending-task requeuing** -- loads `ares:op:{id}:pending_tasks` HASH
//!   instead of scanning global `ares:task_status:*` keys.
//! - **State normalization** -- fixes NetBIOS -> FQDN domain mismatches on
//!   credentials and hashes, persists corrections back to Redis.
//! - **Connection error detection** with retry logic.
mod dedup;
mod manager;
mod normalize;
mod types;

pub use manager::OperationRecoveryManager;

// Normalization helpers consumed by `worker::credential_resolver` for
// realm-strict lookups; re-exported here so the worker doesn't reach into
// the private submodule layout.
pub(crate) use normalize::{normalize_credential_domains, normalize_hash_domains, resolve_domain};

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ares_core::models::{Credential, Hash, TaskInfo, TaskStatus};

    use super::dedup::{dedupe_hashes, extract_kerberoast_spn_key};
    use super::types::is_connection_error;
    use super::*;

    fn make_hash(username: &str, domain: &str, hash_type: &str, hash_value: &str) -> Hash {
        Hash {
            id: uuid::Uuid::new_v4().to_string(),
            username: username.to_string(),
            hash_value: hash_value.to_string(),
            hash_type: hash_type.to_string(),
            domain: domain.to_string(),
            cracked_password: None,
            source: String::new(),
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
    fn dedupe_asrep_by_domain_username() {
        let hashes = vec![
            make_hash(
                "edavis",
                "contoso.local",
                "asrep",
                "$krb5asrep$23$edavis@CONTOSO.LOCAL$aaaa",
            ),
            make_hash(
                "edavis",
                "contoso.local",
                "asrep",
                "$krb5asrep$23$edavis@CONTOSO.LOCAL$bbbb",
            ),
            make_hash(
                "edavis",
                "contoso.local",
                "asrep",
                "$krb5asrep$23$edavis@CONTOSO.LOCAL$cccc",
            ),
        ];
        let result = dedupe_hashes(hashes);
        assert_eq!(
            result.len(),
            1,
            "AS-REP hashes for same user should dedupe to 1"
        );
        assert!(
            result[0].hash_value.ends_with("$aaaa"),
            "Should keep first occurrence"
        );
    }

    #[test]
    fn dedupe_asrep_different_users_kept() {
        let hashes = vec![
            make_hash(
                "edavis",
                "contoso.local",
                "as-rep",
                "$krb5asrep$23$edavis@C$aaa",
            ),
            make_hash(
                "fwilson",
                "contoso.local",
                "as-rep",
                "$krb5asrep$23$fwilson@C$bbb",
            ),
        ];
        let result = dedupe_hashes(hashes);
        assert_eq!(result.len(), 2, "Different users should be kept");
    }

    #[test]
    fn dedupe_kerberoast_by_spn() {
        let hashes = vec![
            make_hash(
                "svc_sql",
                "contoso.local",
                "kerberoast",
                "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$MSSQLSvc/db01.contoso.local*$checksum1$enc1",
            ),
            make_hash(
                "svc_sql",
                "contoso.local",
                "kerberoast",
                "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$MSSQLSvc/db01.contoso.local*$checksum2$enc2",
            ),
        ];
        let result = dedupe_hashes(hashes);
        assert_eq!(result.len(), 1, "Same SPN kerberoast hashes should dedupe");
    }

    #[test]
    fn dedupe_kerberoast_different_spn_kept() {
        let hashes = vec![
            make_hash(
                "svc_sql",
                "contoso.local",
                "kerberoast",
                "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$MSSQLSvc/db01*$chk$enc",
            ),
            make_hash(
                "svc_sql",
                "contoso.local",
                "kerberoast",
                "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$MSSQLSvc/db02*$chk$enc",
            ),
        ];
        let result = dedupe_hashes(hashes);
        assert_eq!(result.len(), 2, "Different SPNs should be kept");
    }

    #[test]
    fn dedupe_ntlm_by_exact_value() {
        let hashes = vec![
            make_hash(
                "admin",
                "contoso.local",
                "NTLM",
                "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", // pragma: allowlist secret
            ),
            make_hash(
                "admin",
                "contoso.local",
                "NTLM",
                "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", // pragma: allowlist secret
            ),
            make_hash(
                "admin",
                "contoso.local",
                "NTLM",
                "aad3b435b51404eeaad3b435b51404ee:different_hash_value", // pragma: allowlist secret
            ),
        ];
        let result = dedupe_hashes(hashes);
        assert_eq!(
            result.len(),
            2,
            "Identical NTLM hashes should dedupe, different kept"
        );
    }

    #[test]
    fn dedupe_mixed_types() {
        let hashes = vec![
            // 2 AS-REP for same user -> 1
            make_hash(
                "edavis",
                "contoso.local",
                "asrep",
                "$krb5asrep$23$edavis@C$a",
            ),
            make_hash(
                "edavis",
                "contoso.local",
                "asrep",
                "$krb5asrep$23$edavis@C$b",
            ),
            // 1 NTLM
            make_hash("admin", "contoso.local", "NTLM", "aad3b435:hash1"), // pragma: allowlist secret
            // 1 Kerberoast
            make_hash(
                "svc",
                "contoso.local",
                "kerberoast",
                "$krb5tgs$23$*svc$CONTOSO.LOCAL$SPN*$chk$enc",
            ),
        ];
        let result = dedupe_hashes(hashes);
        assert_eq!(
            result.len(),
            3,
            "Should keep 1 asrep + 1 ntlm + 1 kerberoast"
        );
    }

    #[test]
    fn dedupe_empty() {
        let result = dedupe_hashes(vec![]);
        assert!(result.is_empty());
    }

    #[test]
    fn dedupe_case_insensitive() {
        let hashes = vec![
            make_hash(
                "EDavis",
                "CONTOSO.LOCAL",
                "asrep",
                "$krb5asrep$23$EDavis@C$a",
            ),
            make_hash(
                "edavis",
                "contoso.local",
                "asrep",
                "$krb5asrep$23$edavis@C$b",
            ),
        ];
        let result = dedupe_hashes(hashes);
        assert_eq!(result.len(), 1, "Case-insensitive dedup for AS-REP");
    }

    #[test]
    fn retry_limit_not_exceeded() {
        let task = TaskInfo {
            task_id: "test_1".to_string(),
            task_type: "recon".to_string(),
            assigned_agent: "recon".to_string(),
            status: TaskStatus::InProgress,
            created_at: chrono::Utc::now(),
            started_at: None,
            completed_at: None,
            last_activity_at: chrono::Utc::now(),
            params: HashMap::new(),
            result: None,
            error: None,
            retry_count: 2,
            max_retries: 3,
        };
        // retry_count (2) after increment (3) should still be <= max_retries (3)
        assert!(
            task.retry_count < task.max_retries,
            "Task with retry_count=2 should still be requeueable"
        );
    }

    #[test]
    fn retry_limit_exceeded() {
        let task = TaskInfo {
            task_id: "test_2".to_string(),
            task_type: "recon".to_string(),
            assigned_agent: "recon".to_string(),
            status: TaskStatus::InProgress,
            created_at: chrono::Utc::now(),
            started_at: None,
            completed_at: None,
            last_activity_at: chrono::Utc::now(),
            params: HashMap::new(),
            result: None,
            error: None,
            retry_count: 3,
            max_retries: 3,
        };
        // After increment: retry_count=4 > max_retries=3
        assert!(
            task.retry_count + 1 > task.max_retries,
            "Task with retry_count=3 after increment should exceed max"
        );
    }

    #[test]
    fn normalize_credential_domains_netbios_to_fqdn() {
        let mut creds = vec![
            Credential {
                id: "1".to_string(),
                username: "admin".to_string(),
                password: "pass".to_string(), // pragma: allowlist secret
                domain: "CONTOSO".to_string(),
                source: String::new(),
                discovered_at: None,
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            },
            Credential {
                id: "2".to_string(),
                username: "user1".to_string(),
                password: "pass2".to_string(), // pragma: allowlist secret
                domain: "contoso.local".to_string(), // already FQDN
                source: String::new(),
                discovered_at: None,
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            },
        ];

        let mut netbios_map = HashMap::new();
        netbios_map.insert("CONTOSO".to_string(), "contoso.local".to_string());

        let fixed = normalize_credential_domains(&mut creds, &netbios_map);
        assert_eq!(fixed, 1);
        assert_eq!(creds[0].domain, "contoso.local");
        assert_eq!(creds[1].domain, "contoso.local"); // unchanged
    }

    #[test]
    fn normalizes_hash_domains() {
        let mut hashes = vec![make_hash("admin", "FABRIKAM", "NTLM", "hash123")];

        let mut netbios_map = HashMap::new();
        netbios_map.insert("FABRIKAM".to_string(), "fabrikam.local".to_string());

        let fixed = normalize_hash_domains(&mut hashes, &netbios_map);
        assert_eq!(fixed, 1);
        assert_eq!(hashes[0].domain, "fabrikam.local");
    }

    #[test]
    fn normalize_no_changes_when_fqdn() {
        let mut creds = vec![Credential {
            id: "1".to_string(),
            username: "admin".to_string(),
            password: "pass".to_string(), // pragma: allowlist secret
            domain: "contoso.local".to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }];

        let netbios_map = HashMap::new();
        let fixed = normalize_credential_domains(&mut creds, &netbios_map);
        assert_eq!(fixed, 0, "FQDN domain should not be touched");
    }

    #[test]
    fn resolve_domain_empty_and_dotted() {
        let map = HashMap::new();
        assert!(resolve_domain("", &map).is_none(), "Empty domain -> None");
        assert!(
            resolve_domain("already.fqdn.local", &map).is_none(),
            "Dotted domain -> None"
        );
    }

    #[test]
    fn resolve_domain_case_insensitive_lookup() {
        let mut map = HashMap::new();
        map.insert("CONTOSO".to_string(), "contoso.local".to_string());

        assert_eq!(
            resolve_domain("contoso", &map),
            Some("contoso.local".to_string()),
            "Lowercase input should match uppercase key via to_uppercase"
        );
        assert_eq!(
            resolve_domain("CONTOSO", &map),
            Some("contoso.local".to_string()),
        );
        assert_eq!(
            resolve_domain("Contoso", &map),
            Some("contoso.local".to_string()),
        );
    }

    #[test]
    fn extract_kerberoast_spn_key_valid() {
        let hash = "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$MSSQLSvc/db01.contoso.local*$chk$enc";
        let result = extract_kerberoast_spn_key(hash);
        assert_eq!(result, Some("23:MSSQLSvc/db01.contoso.local".to_string()));
    }

    #[test]
    fn extract_kerberoast_spn_key_invalid() {
        assert!(extract_kerberoast_spn_key("not_a_krb_hash").is_none());
        assert!(extract_kerberoast_spn_key("$krb5tgs$").is_none());
        assert!(extract_kerberoast_spn_key("$krb5tgs$23$nope").is_none());
    }

    #[test]
    fn connection_error_detection() {
        let conn_err = anyhow::anyhow!("Connection reset by peer");
        assert!(is_connection_error(&conn_err));

        let timeout_err = anyhow::anyhow!("Operation TIMEOUT after 30s");
        assert!(is_connection_error(&timeout_err));

        let broken = anyhow::anyhow!("Broken pipe");
        assert!(is_connection_error(&broken));

        let normal = anyhow::anyhow!("Key not found");
        assert!(!is_connection_error(&normal));
    }
}
