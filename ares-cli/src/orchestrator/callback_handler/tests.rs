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
        name: "list_credentials".into(),
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
        name: "list_credentials".into(),
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
async fn orchestrator_tools_are_trapped_but_never_executed() {
    let handler = make_handler();
    let retired = [
        "dispatch_recon",
        "dispatch_credential_access",
        "dispatch_lateral_movement",
        "dispatch_privesc_exploit",
        "dispatch_coercion",
        "dispatch_crack",
        "complete_operation",
        "get_credential_summary",
        "get_hash_summary",
        "get_all_hashes",
        "get_hash_value",
        "get_pending_tasks",
        "get_agent_status",
    ];

    for tool in &retired {
        assert!(
            ares_llm::tool_registry::is_callback_tool(tool),
            "{tool} must stay trapped in-process so it is never sent to a worker"
        );
        let call = ToolCall {
            id: format!("retired-{tool}"),
            name: tool.to_string(),
            arguments: json!({"username": "alice", "domain": "contoso.local", "target_ip": "192.168.58.10"}),
        };
        assert!(
            handler.handle_callback(&call).await.is_none(),
            "{tool} must not be routed to a live handler"
        );
    }
}

#[tokio::test]
async fn universal_reporting_tools_still_route() {
    let handler = make_handler();
    for tool in &["list_credentials", "get_operation_summary"] {
        let call = ToolCall {
            id: format!("live-{tool}"),
            name: tool.to_string(),
            arguments: json!({}),
        };
        assert!(
            handler.handle_callback(&call).await.is_some(),
            "{tool} is offered to every role and must still be handled"
        );
    }
}
