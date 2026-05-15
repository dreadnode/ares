use super::*;
use serde_json::json;

use ares_llm::provider::ToolCall;
use ares_llm::CallbackResult;

use crate::orchestrator::state::SharedState;

/// Helper to create a credential without Default.
fn make_cred(
    username: &str,
    password: &str,
    domain: &str,
    is_admin: bool,
) -> ares_core::models::Credential {
    ares_core::models::Credential {
        id: uuid::Uuid::new_v4().to_string(),
        username: username.into(),
        password: password.into(),
        domain: domain.into(),
        source: String::new(),
        discovered_at: None,
        is_admin,
        parent_id: None,
        attack_step: 0,
    }
}

/// Helper to create a hash without Default.
fn make_hash(
    username: &str,
    domain: &str,
    hash_type: &str,
    hash_value: &str,
    aes_key: Option<&str>,
) -> ares_core::models::Hash {
    ares_core::models::Hash {
        id: uuid::Uuid::new_v4().to_string(),
        username: username.into(),
        hash_value: hash_value.into(),
        hash_type: hash_type.into(),
        domain: domain.into(),
        cracked_password: None,
        source: String::new(),
        discovered_at: None,
        parent_id: None,
        attack_step: 0,
        aes_key: aes_key.map(|s| s.to_string()),
        is_previous: false,
        source_host: None,
        is_trust_key: false,
        trust_pair_label: None,
    }
}

fn make_handler() -> OrchestratorCallbackHandler {
    OrchestratorCallbackHandler::new_for_test(SharedState::new("test-op".to_string()))
}

#[tokio::test]
async fn credential_summary_empty() {
    let handler = make_handler();
    let call = ToolCall {
        id: "c1".into(),
        name: "get_credential_summary".into(),
        arguments: json!({}),
    };
    let result = handler.handle_callback(&call).await.unwrap().unwrap();
    match result {
        CallbackResult::Continue(msg) => {
            let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
            assert_eq!(parsed["total_credentials"], 0);
        }
        other => panic!("Expected Continue, got: {:?}", other),
    }
}

#[tokio::test]
async fn credential_summary_with_data() {
    let handler = make_handler();
    {
        let mut s = handler.state.write().await;
        s.credentials
            .push(make_cred("admin", "pass", "contoso.local", true));
        s.credentials
            .push(make_cred("user1", "pass1", "contoso.local", false));
    }

    let call = ToolCall {
        id: "c2".into(),
        name: "get_credential_summary".into(),
        arguments: json!({}),
    };
    let result = handler.handle_callback(&call).await.unwrap().unwrap();
    match result {
        CallbackResult::Continue(msg) => {
            let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
            assert_eq!(parsed["total_credentials"], 2);
        }
        other => panic!("Expected Continue, got: {:?}", other),
    }
}

#[tokio::test]
async fn hash_summary_empty() {
    let handler = make_handler();
    let call = ToolCall {
        id: "c3".into(),
        name: "get_hash_summary".into(),
        arguments: json!({}),
    };
    let result = handler.handle_callback(&call).await.unwrap().unwrap();
    match result {
        CallbackResult::Continue(msg) => {
            let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
            assert_eq!(parsed["total_hashes"], 0);
        }
        other => panic!("Expected Continue, got: {:?}", other),
    }
}

#[tokio::test]
async fn hash_value_lookup() {
    let handler = make_handler();
    {
        let mut s = handler.state.write().await;
        s.hashes.push(make_hash(
            "krbtgt",
            "contoso.local",
            "NTLM",
            "aad3b435b51404ee:313b6f423a71d74c",
            Some("f8b6c5e4d3a2b109"),
        ));
    }

    let call = ToolCall {
        id: "c4".into(),
        name: "get_hash_value".into(),
        arguments: json!({"username": "krbtgt", "domain": "contoso.local"}),
    };
    let result = handler.handle_callback(&call).await.unwrap().unwrap();
    match result {
        CallbackResult::Continue(msg) => {
            assert!(msg.contains("313b6f423a71d74c"));
            assert!(msg.contains("f8b6c5e4d3a2b109"));
        }
        other => panic!("Expected Continue, got: {:?}", other),
    }
}

#[tokio::test]
async fn hash_value_not_found() {
    let handler = make_handler();
    let call = ToolCall {
        id: "c5".into(),
        name: "get_hash_value".into(),
        arguments: json!({"username": "nobody", "domain": "contoso.local"}),
    };
    let result = handler.handle_callback(&call).await.unwrap().unwrap();
    match result {
        CallbackResult::Continue(msg) => assert!(msg.contains("No hashes found")),
        other => panic!("Expected Continue, got: {:?}", other),
    }
}

#[tokio::test]
async fn pending_tasks_empty() {
    let handler = make_handler();
    let call = ToolCall {
        id: "c6".into(),
        name: "get_pending_tasks".into(),
        arguments: json!({}),
    };
    let result = handler.handle_callback(&call).await.unwrap().unwrap();
    match result {
        CallbackResult::Continue(msg) => {
            let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
            assert_eq!(parsed["total"], 0);
        }
        other => panic!("Expected Continue, got: {:?}", other),
    }
}

#[tokio::test]
async fn unknown_tool_returns_none() {
    let handler = make_handler();
    let call = ToolCall {
        id: "c7".into(),
        name: "nmap_scan".into(),
        arguments: json!({}),
    };
    assert!(handler.handle_callback(&call).await.is_none());
}

#[tokio::test]
async fn dispatch_without_dispatcher() {
    let handler = make_handler();
    let call = ToolCall {
        id: "c8".into(),
        name: "dispatch_recon".into(),
        arguments: json!({"target_ip": "192.168.58.10"}),
    };
    let result = handler.handle_callback(&call).await.unwrap();
    assert!(result.is_err()); // No dispatcher configured
}

#[tokio::test]
async fn operation_summary() {
    let handler = make_handler();
    {
        let mut s = handler.state.write().await;
        s.credentials
            .push(make_cred("admin", "pass", "contoso.local", true));
        s.hashes.push(make_hash(
            "krbtgt",
            "contoso.local",
            "NTLM",
            "aad3b435:313b6f42",
            None,
        ));
        s.has_domain_admin = true;
    }

    let call = ToolCall {
        id: "c10".into(),
        name: "get_operation_summary".into(),
        arguments: json!({}),
    };
    let result = handler.handle_callback(&call).await.unwrap().unwrap();
    match result {
        CallbackResult::Continue(msg) => {
            let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
            assert_eq!(parsed["credentials"]["total"], 1);
            assert_eq!(parsed["credentials"]["admin"], 1);
            assert_eq!(parsed["hashes"]["total"], 1);
            assert_eq!(parsed["has_domain_admin"], true);
        }
        other => panic!("Expected Continue, got: {:?}", other),
    }
}

#[tokio::test]
async fn dispatch_crack_without_dispatcher() {
    let handler = make_handler();
    let call = ToolCall {
        id: "c11".into(),
        name: "dispatch_crack".into(),
        arguments: json!({"hash_value": "aad3b435:beef", "hash_type": "ntlm"}),
    };
    let result = handler.handle_callback(&call).await.unwrap();
    assert!(result.is_err()); // No dispatcher configured
}

#[tokio::test]
async fn all_credentials_pagination() {
    let handler = make_handler();
    {
        let mut s = handler.state.write().await;
        for i in 0..10 {
            s.credentials.push(make_cred(
                &format!("user{i}"),
                "pass",
                "contoso.local",
                false,
            ));
        }
    }

    let call = ToolCall {
        id: "c9".into(),
        name: "get_all_credentials".into(),
        arguments: json!({"limit": 3, "offset": 2}),
    };
    let result = handler.handle_callback(&call).await.unwrap().unwrap();
    match result {
        CallbackResult::Continue(msg) => {
            let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
            assert_eq!(parsed["total"], 10);
            assert_eq!(parsed["credentials"].as_array().unwrap().len(), 3);
            assert_eq!(parsed["offset"], 2);
        }
        other => panic!("Expected Continue, got: {:?}", other),
    }
}

#[tokio::test]
async fn full_summary_with_populated_state() {
    let handler = make_handler();
    {
        let mut s = handler.state.write().await;
        s.credentials
            .push(make_cred("admin", "P@ss1", "contoso.local", true));
        s.credentials
            .push(make_cred("user1", "pass1", "contoso.local", false));
        s.credentials
            .push(make_cred("svc_sql", "SqlP@ss", "fabrikam.local", false));
        s.hashes.push(make_hash(
            "krbtgt",
            "contoso.local",
            "NTLM",
            "aad3b:beef",
            None,
        ));
        let mut h = make_hash("admin", "contoso.local", "NTLM", "aad3b:dead", None);
        h.cracked_password = Some("cracked123".into());
        s.hashes.push(h);
        s.has_domain_admin = true;
        s.domains.push("contoso.local".into());
        s.discovered_vulnerabilities.insert(
            "vuln-1".into(),
            ares_core::models::VulnerabilityInfo {
                vuln_id: "vuln-1".into(),
                vuln_type: "constrained_delegation".into(),
                target: "192.168.58.30".into(),
                discovered_by: "test".into(),
                discovered_at: chrono::Utc::now(),
                details: {
                    let mut m = std::collections::HashMap::new();
                    m.insert("account".into(), json!("svc_sql"));
                    m
                },
                recommended_agent: String::new(),
                priority: 5,
            },
        );
    }

    let call = ToolCall {
        id: "int-1".into(),
        name: "get_operation_summary".into(),
        arguments: json!({}),
    };
    let result = handler.handle_callback(&call).await.unwrap().unwrap();
    match result {
        CallbackResult::Continue(msg) => {
            let p: serde_json::Value = serde_json::from_str(&msg).unwrap();
            assert_eq!(p["credentials"]["total"], 3);
            assert_eq!(p["credentials"]["admin"], 1);
            assert_eq!(p["hashes"]["total"], 2);
            assert_eq!(p["hashes"]["cracked"], 1);
            assert_eq!(p["has_domain_admin"], true);
            assert_eq!(p["discovered_vulnerabilities"], 1);
        }
        other => panic!("Expected Continue, got: {:?}", other),
    }
}

#[tokio::test]
async fn credential_summary_multi_domain() {
    let handler = make_handler();
    {
        let mut s = handler.state.write().await;
        s.credentials
            .push(make_cred("admin", "p1", "contoso.local", true));
        s.credentials
            .push(make_cred("user1", "p2", "contoso.local", false));
        s.credentials
            .push(make_cred("admin2", "p3", "fabrikam.local", true));
    }

    let call = ToolCall {
        id: "int-2".into(),
        name: "get_credential_summary".into(),
        arguments: json!({}),
    };
    let result = handler.handle_callback(&call).await.unwrap().unwrap();
    match result {
        CallbackResult::Continue(msg) => {
            let p: serde_json::Value = serde_json::from_str(&msg).unwrap();
            assert_eq!(p["total_credentials"], 3);
            let domains = p["by_domain"].as_array().unwrap();
            assert_eq!(domains.len(), 2);
        }
        other => panic!("Expected Continue, got: {:?}", other),
    }
}

#[tokio::test]
async fn hash_value_case_insensitive_lookup() {
    let handler = make_handler();
    {
        let mut s = handler.state.write().await;
        s.hashes.push(make_hash(
            "Administrator",
            "CONTOSO.LOCAL",
            "NTLM",
            "beef:dead",
            None,
        ));
    }

    let call = ToolCall {
        id: "int-3".into(),
        name: "get_hash_value".into(),
        arguments: json!({"username": "administrator", "domain": "contoso.local"}),
    };
    let result = handler.handle_callback(&call).await.unwrap().unwrap();
    match result {
        CallbackResult::Continue(msg) => assert!(msg.contains("beef:dead")),
        other => panic!("Expected Continue, got: {:?}", other),
    }
}

#[tokio::test]
async fn hash_value_filter_by_type() {
    let handler = make_handler();
    {
        let mut s = handler.state.write().await;
        s.hashes.push(make_hash(
            "admin",
            "contoso.local",
            "NTLM",
            "ntlm_hash",
            None,
        ));
        s.hashes.push(make_hash(
            "admin",
            "contoso.local",
            "aes256",
            "aes_hash",
            None,
        ));
    }

    let call = ToolCall {
        id: "int-4".into(),
        name: "get_hash_value".into(),
        arguments: json!({"username": "admin", "domain": "contoso.local", "hash_type": "aes256"}),
    };
    let result = handler.handle_callback(&call).await.unwrap().unwrap();
    match result {
        CallbackResult::Continue(msg) => {
            assert!(msg.contains("aes_hash"));
            assert!(!msg.contains("ntlm_hash"));
        }
        other => panic!("Expected Continue, got: {:?}", other),
    }
}

#[tokio::test]
async fn all_dispatch_tools_fail_without_dispatcher() {
    let handler = make_handler();
    let dispatch_tools = [
        ("dispatch_recon", json!({"target_ip": "192.168.58.10"})),
        (
            "dispatch_credential_access",
            json!({"technique": "secretsdump", "target_ip": "x", "domain": "x", "username": "x", "password": "x"}),
        ),
        (
            "dispatch_lateral_movement",
            json!({"target_ip": "x", "technique": "psexec", "username": "x", "password": "x", "domain": "x"}),
        ),
        ("dispatch_privesc_exploit", json!({"vuln_id": "v-1"})),
        (
            "dispatch_coercion",
            json!({"target_ip": "x", "listener_ip": "x"}),
        ),
        (
            "dispatch_crack",
            json!({"hash_value": "aad3b:beef", "hash_type": "ntlm"}),
        ),
    ];

    for (tool, args) in &dispatch_tools {
        let call = ToolCall {
            id: format!("disp-{tool}"),
            name: tool.to_string(),
            arguments: args.clone(),
        };
        let result = handler.handle_callback(&call).await;
        assert!(result.is_some(), "Should recognize: {tool}");
        assert!(
            result.unwrap().is_err(),
            "Should error without dispatcher: {tool}"
        );
    }
}

#[tokio::test]
async fn all_callback_tools_recognized() {
    let handler = make_handler();
    let tools = [
        "get_credential_summary",
        "get_hash_summary",
        "get_all_credentials",
        "get_all_hashes",
        "get_hash_value",
        "get_pending_tasks",
        "get_operation_summary",
        "dispatch_recon",
        "dispatch_credential_access",
        "dispatch_lateral_movement",
        "dispatch_privesc_exploit",
        "dispatch_coercion",
        "dispatch_crack",
    ];

    for tool in &tools {
        let call = ToolCall {
            id: format!("route-{tool}"),
            name: tool.to_string(),
            arguments: json!({"username": "x", "domain": "x", "target_ip": "x",
                            "technique": "x", "password": "x", "hash_value": "x",
                            "hash_type": "x", "vuln_id": "x", "listener_ip": "x"}),
        };
        assert!(
            handler.handle_callback(&call).await.is_some(),
            "Handler should recognize: {tool}"
        );
    }

    // Unknown tool returns None
    let call = ToolCall {
        id: "route-unknown".into(),
        name: "nmap_scan".into(),
        arguments: json!({}),
    };
    assert!(handler.handle_callback(&call).await.is_none());
}

#[tokio::test]
async fn all_hashes_pagination_large() {
    let handler = make_handler();
    {
        let mut s = handler.state.write().await;
        for i in 0..50 {
            s.hashes.push(make_hash(
                &format!("user{i}"),
                "contoso.local",
                "NTLM",
                &format!("hash_{i}"),
                None,
            ));
        }
    }

    let call = ToolCall {
        id: "int-pg".into(),
        name: "get_all_hashes".into(),
        arguments: json!({"limit": 10, "offset": 40}),
    };
    let result = handler.handle_callback(&call).await.unwrap().unwrap();
    match result {
        CallbackResult::Continue(msg) => {
            let p: serde_json::Value = serde_json::from_str(&msg).unwrap();
            assert_eq!(p["total"], 50);
            assert_eq!(p["hashes"].as_array().unwrap().len(), 10);
        }
        other => panic!("Expected Continue, got: {:?}", other),
    }
}

#[tokio::test]
async fn record_credential_disabled() {
    let handler = make_handler();
    let call = ToolCall {
        id: "dis-1".into(),
        name: "record_credential".into(),
        arguments: json!({"username": "admin", "password": "pass", "domain": "contoso.local"}),
    };
    let result = handler.handle_callback(&call).await.unwrap().unwrap();
    match result {
        CallbackResult::Continue(msg) => {
            assert!(msg.contains("disabled"));
            assert!(msg.contains("automatically extracted"));
        }
        other => panic!("Expected Continue, got: {:?}", other),
    }
}

#[tokio::test]
async fn record_timeline_event_disabled() {
    let handler = make_handler();
    let call = ToolCall {
        id: "dis-2".into(),
        name: "record_timeline_event".into(),
        arguments: json!({"event": "some event"}),
    };
    let result = handler.handle_callback(&call).await.unwrap().unwrap();
    match result {
        CallbackResult::Continue(msg) => {
            assert!(msg.contains("disabled"));
            assert!(msg.contains("automatically generated"));
        }
        other => panic!("Expected Continue, got: {:?}", other),
    }
}

#[tokio::test]
async fn report_cracked_credential_falls_through_to_builtin_handler() {
    let handler = make_handler();
    let call = ToolCall {
        id: "rej-1".into(),
        name: "report_cracked_credential".into(),
        arguments: json!({
            "username": "alice",
            "domain": "contoso.local",
            "password": "secret123",
        }),
    };
    assert!(handler.handle_callback(&call).await.is_none());
}

#[tokio::test]
async fn list_credentials_delegates_to_get_all() {
    let handler = make_handler();
    {
        let mut s = handler.state.write().await;
        s.credentials
            .push(make_cred("admin", "pass", "contoso.local", true));
        s.credentials
            .push(make_cred("user1", "pass1", "fabrikam.local", false));
    }

    let call = ToolCall {
        id: "lc-1".into(),
        name: "list_credentials".into(),
        arguments: json!({}),
    };
    let result = handler.handle_callback(&call).await.unwrap().unwrap();
    match result {
        CallbackResult::Continue(msg) => {
            let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
            assert_eq!(parsed["total"], 2);
            assert!(parsed["credentials"].as_array().is_some());
        }
        other => panic!("Expected Continue, got: {:?}", other),
    }
}

#[tokio::test]
async fn dispatch_coercion_without_dispatcher() {
    let handler = make_handler();
    let call = ToolCall {
        id: "co-1".into(),
        name: "dispatch_coercion".into(),
        arguments: json!({"target_ip": "192.168.58.10", "listener_ip": "192.168.58.100"}),
    };
    let result = handler.handle_callback(&call).await.unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn dispatch_exploit_without_dispatcher() {
    let handler = make_handler();
    let call = ToolCall {
        id: "ex-1".into(),
        name: "dispatch_privesc_exploit".into(),
        arguments: json!({"vuln_id": "vuln-999", "priority": 3}),
    };
    let result = handler.handle_callback(&call).await.unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn get_agent_status_without_task_queue() {
    let handler = make_handler();
    let call = ToolCall {
        id: "as-1".into(),
        name: "get_agent_status".into(),
        arguments: json!({}),
    };
    let result = handler.handle_callback(&call).await.unwrap();
    // new_for_test has no task_queue, so this should error
    assert!(result.is_err());
}

#[tokio::test]
async fn hash_summary_with_mixed_types() {
    let handler = make_handler();
    {
        let mut s = handler.state.write().await;
        s.hashes.push(make_hash(
            "admin",
            "contoso.local",
            "NTLM",
            "ntlm_hash",
            None,
        ));
        s.hashes.push(make_hash(
            "admin",
            "contoso.local",
            "aes256",
            "aes_hash",
            Some("aes_key_val"),
        ));
        let mut cracked = make_hash("user1", "contoso.local", "NTLM", "cracked_hash", None);
        cracked.cracked_password = Some("password123".to_string());
        s.hashes.push(cracked);
    }

    let call = ToolCall {
        id: "hs-1".into(),
        name: "get_hash_summary".into(),
        arguments: json!({}),
    };
    let result = handler.handle_callback(&call).await.unwrap().unwrap();
    match result {
        CallbackResult::Continue(msg) => {
            let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
            assert_eq!(parsed["total_hashes"], 3);
            let by_type = parsed["by_type"].as_array().unwrap();
            assert_eq!(by_type.len(), 2); // NTLM and aes256
        }
        other => panic!("Expected Continue, got: {:?}", other),
    }
}

#[tokio::test]
async fn all_credentials_zero_offset_default_limit() {
    let handler = make_handler();
    {
        let mut s = handler.state.write().await;
        for i in 0..5 {
            s.credentials.push(make_cred(
                &format!("user{i}"),
                "pass",
                "contoso.local",
                false,
            ));
        }
    }

    // No limit/offset in args => defaults (limit=30, offset=0)
    let call = ToolCall {
        id: "ac-def".into(),
        name: "get_all_credentials".into(),
        arguments: json!({}),
    };
    let result = handler.handle_callback(&call).await.unwrap().unwrap();
    match result {
        CallbackResult::Continue(msg) => {
            let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
            assert_eq!(parsed["total"], 5);
            assert_eq!(parsed["offset"], 0);
            assert_eq!(parsed["limit"], 30);
            assert_eq!(parsed["credentials"].as_array().unwrap().len(), 5);
        }
        other => panic!("Expected Continue, got: {:?}", other),
    }
}

#[tokio::test]
async fn all_hashes_default_params() {
    let handler = make_handler();
    {
        let mut s = handler.state.write().await;
        s.hashes.push(make_hash(
            "admin",
            "contoso.local",
            "NTLM",
            "hash_val",
            Some("aes_key"),
        ));
    }

    let call = ToolCall {
        id: "ah-def".into(),
        name: "get_all_hashes".into(),
        arguments: json!({}),
    };
    let result = handler.handle_callback(&call).await.unwrap().unwrap();
    match result {
        CallbackResult::Continue(msg) => {
            let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
            assert_eq!(parsed["total"], 1);
            let h = &parsed["hashes"].as_array().unwrap()[0];
            assert_eq!(h["username"], "admin");
            assert_eq!(h["has_aes_key"], true);
        }
        other => panic!("Expected Continue, got: {:?}", other),
    }
}

#[tokio::test]
async fn operation_summary_empty_state() {
    let handler = make_handler();
    let call = ToolCall {
        id: "os-empty".into(),
        name: "get_operation_summary".into(),
        arguments: json!({}),
    };
    let result = handler.handle_callback(&call).await.unwrap().unwrap();
    match result {
        CallbackResult::Continue(msg) => {
            let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
            assert_eq!(parsed["credentials"]["total"], 0);
            assert_eq!(parsed["hashes"]["total"], 0);
            assert_eq!(parsed["has_domain_admin"], false);
            assert_eq!(parsed["hosts"], 0);
            assert_eq!(parsed["discovered_vulnerabilities"], 0);
        }
        other => panic!("Expected Continue, got: {:?}", other),
    }
}

#[tokio::test]
async fn hash_value_empty_domain_filter() {
    let handler = make_handler();
    {
        let mut s = handler.state.write().await;
        s.hashes
            .push(make_hash("admin", "contoso.local", "NTLM", "hash_a", None));
        s.hashes
            .push(make_hash("admin", "fabrikam.local", "NTLM", "hash_b", None));
    }

    // Empty domain should match all domains for that user
    let call = ToolCall {
        id: "hv-nodom".into(),
        name: "get_hash_value".into(),
        arguments: json!({"username": "admin", "domain": ""}),
    };
    let result = handler.handle_callback(&call).await.unwrap().unwrap();
    match result {
        CallbackResult::Continue(msg) => {
            let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
            let arr = parsed.as_array().unwrap();
            assert_eq!(arr.len(), 2);
        }
        other => panic!("Expected Continue, got: {:?}", other),
    }
}
