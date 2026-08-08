use super::dispatch::is_cross_realm;
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
    assert!(handler
        .handle_callback(&call, "orchestrator")
        .await
        .is_none());
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
    let result = handler
        .handle_callback(&call, "orchestrator")
        .await
        .unwrap()
        .unwrap();
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
    let result = handler
        .handle_callback(&call, "orchestrator")
        .await
        .unwrap()
        .unwrap();
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
    let result = handler
        .handle_callback(&call, "orchestrator")
        .await
        .unwrap()
        .unwrap();
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
    let result = handler
        .handle_callback(&call, "orchestrator")
        .await
        .unwrap()
        .unwrap();
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
    let result = handler
        .handle_callback(&call, "orchestrator")
        .await
        .unwrap()
        .unwrap();
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
    assert!(handler
        .handle_callback(&call, "orchestrator")
        .await
        .is_none());
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
    let result = handler
        .handle_callback(&call, "orchestrator")
        .await
        .unwrap()
        .unwrap();
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
    let result = handler
        .handle_callback(&call, "orchestrator")
        .await
        .unwrap()
        .unwrap();
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
    let result = handler
        .handle_callback(&call, "orchestrator")
        .await
        .unwrap()
        .unwrap();
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
async fn orchestrator_tools_never_reach_a_worker_queue() {
    for tool in [
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
        "get_pending_tasks",
        "get_agent_status",
    ] {
        assert!(
            ares_llm::tool_registry::is_callback_tool(tool),
            "{tool} must route in-process so it is never sent to a worker"
        );
    }
}

#[tokio::test]
async fn get_hash_value_stays_retired() {
    let handler = make_handler();
    assert!(ares_llm::tool_registry::is_callback_tool("get_hash_value"));
    let call = ToolCall {
        id: "retired-get_hash_value".into(),
        name: "get_hash_value".into(),
        arguments: json!({"username": "alice", "domain": "contoso.local"}),
    };
    assert!(handler
        .handle_callback(&call, "orchestrator")
        .await
        .is_none());
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
            handler
                .handle_callback(&call, "orchestrator")
                .await
                .is_some(),
            "{tool} is offered to every role and must still be handled"
        );
    }
}

#[tokio::test]
async fn worker_role_cannot_dispatch_work() {
    let handler = make_handler();
    for tool in [
        "dispatch_recon",
        "dispatch_credential_access",
        "dispatch_lateral_movement",
        "dispatch_privesc_exploit",
        "dispatch_coercion",
        "dispatch_crack",
    ] {
        let call = ToolCall {
            id: "w-1".into(),
            name: tool.into(),
            arguments: json!({"target_ip": "192.168.58.10", "domain": "contoso.local"}),
        };
        let result = handler
            .handle_callback(&call, "recon")
            .await
            .unwrap_or_else(|| panic!("{tool} must be intercepted, not passed through"))
            .unwrap();
        match result {
            CallbackResult::Continue(msg) => {
                assert!(
                    msg.contains("not the orchestrator"),
                    "{tool} must be refused for a worker, got: {msg}"
                );
            }
            other => panic!("{tool} must return Continue, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn worker_role_cannot_end_the_operation() {
    let handler = make_handler();
    let call = ToolCall {
        id: "w-2".into(),
        name: "complete_operation".into(),
        arguments: json!({"summary": "all done"}),
    };
    let result = handler
        .handle_callback(&call, "privesc")
        .await
        .unwrap()
        .unwrap();
    match result {
        CallbackResult::Continue(msg) => assert!(msg.contains("not the orchestrator")),
        other => panic!("Expected Continue, got {other:?}"),
    }
    assert!(
        !handler.state.read().await.completed,
        "a worker must not be able to set the completion flag"
    );
}

#[tokio::test]
async fn orchestrator_completing_sets_the_state_flag() {
    let handler = make_handler();
    assert!(!handler.state.read().await.completed);

    let call = ToolCall {
        id: "o-1".into(),
        name: "complete_operation".into(),
        arguments: json!({"summary": "krbtgt extracted in every forest"}),
    };
    let result = handler
        .handle_callback(&call, "orchestrator")
        .await
        .unwrap()
        .unwrap();
    match result {
        CallbackResult::Continue(msg) => assert!(msg.contains("marked complete")),
        other => panic!("Expected Continue, got {other:?}"),
    }
    assert!(handler.state.read().await.completed);
}

#[tokio::test]
async fn worker_role_may_still_query_state() {
    let handler = make_handler();
    let call = ToolCall {
        id: "w-3".into(),
        name: "get_operation_summary".into(),
        arguments: json!({}),
    };
    let result = handler
        .handle_callback(&call, "lateral")
        .await
        .unwrap()
        .unwrap();
    match result {
        CallbackResult::Continue(msg) => assert!(msg.contains("operation_id")),
        other => panic!("Expected Continue, got {other:?}"),
    }
}

#[tokio::test]
async fn dispatch_crack_refuses_ntlm_of_an_already_dominated_domain() {
    let handler = make_handler();
    {
        let mut s = handler.state.write().await;
        s.dominated_domains.insert("contoso.local".to_string());
        s.hashes.push(make_hash(
            "bob",
            "contoso.local",
            "NTLM",
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            None,
        ));
    }
    let call = ToolCall {
        id: "c-1".into(),
        name: "dispatch_crack".into(),
        arguments: json!({"username": "bob", "domain": "contoso.local"}),
    };
    match handler.dispatch_crack(&call).await.unwrap() {
        CallbackResult::Continue(msg) => {
            assert!(msg.starts_with("Refused:"), "expected refusal, got {msg}");
            assert!(msg.contains("pass-the-hash"), "{msg}");
        }
        other => panic!("Expected Continue, got {other:?}"),
    }
}

#[tokio::test]
async fn dispatch_crack_still_accepts_a_roastable_in_a_dominated_domain() {
    let handler = make_handler();
    {
        let mut s = handler.state.write().await;
        s.dominated_domains.insert("contoso.local".to_string());
        s.hashes.push(make_hash(
            "alice",
            "contoso.local",
            "asrep",
            "$krb5asrep$23$alice@CONTOSO.LOCAL:abc$def",
            None,
        ));
    }
    let call = ToolCall {
        id: "c-2".into(),
        name: "dispatch_crack".into(),
        arguments: json!({"username": "alice", "domain": "contoso.local"}),
    };
    let err = handler.dispatch_crack(&call).await.unwrap_err();
    assert!(
        err.to_string().contains("Dispatcher not configured"),
        "roastable must reach dispatch, got {err}"
    );
}

fn make_host(ip: &str, hostname: &str) -> ares_core::models::Host {
    ares_core::models::Host {
        ip: ip.into(),
        hostname: hostname.into(),
        os: String::new(),
        roles: vec![],
        services: vec![],
        is_dc: true,
        owned: false,
    }
}

async fn handler_with_host(ip: &str, hostname: &str) -> OrchestratorCallbackHandler {
    let handler = make_handler();
    {
        let mut s = handler.state.write().await;
        s.hosts.push(make_host(ip, hostname));
        s.credentials
            .push(make_cred("alice", "P@ssw0rd!", "contoso.local", true));
    }
    handler
}

fn cred_access_call(target_ip: &str, domain: &str) -> ToolCall {
    ToolCall {
        id: "ca-1".into(),
        name: "dispatch_credential_access".into(),
        arguments: json!({
            "technique": "secretsdump",
            "target_ip": target_ip,
            "domain": domain,
            "username": "alice",
        }),
    }
}

#[test]
fn is_cross_realm_allows_same_and_parent_child_pairs() {
    assert!(!is_cross_realm("contoso.local", "contoso.local"));
    assert!(!is_cross_realm("CONTOSO.LOCAL", "contoso.local"));
    assert!(!is_cross_realm("contoso.local", "child.contoso.local"));
    assert!(!is_cross_realm("child.contoso.local", "contoso.local"));
    assert!(!is_cross_realm("", "contoso.local"));
    assert!(is_cross_realm("contoso.local", "fabrikam.local"));
}

#[tokio::test]
async fn dispatch_credential_access_rejects_cross_forest_target() {
    let handler = handler_with_host("192.168.58.5", "dc01.fabrikam.local").await;
    let call = cred_access_call("192.168.58.5", "contoso.local");

    let result = handler.dispatch_credential_access(&call).await.unwrap();
    let CallbackResult::Continue(msg) = result else {
        panic!("expected a Continue rejection");
    };
    assert!(
        msg.contains("REJECTED") && msg.contains("fabrikam.local"),
        "cross-forest dump must be refused with the target realm named, got: {msg}"
    );
}

#[tokio::test]
async fn dispatch_credential_access_allows_child_realm_target() {
    let handler = handler_with_host("192.168.58.6", "dc02.child.contoso.local").await;
    let call = cred_access_call("192.168.58.6", "contoso.local");

    let err = handler.dispatch_credential_access(&call).await.unwrap_err();
    assert!(
        err.to_string().contains("Dispatcher not configured"),
        "parent credential against a child DC must reach dispatch, got {err}"
    );
}

#[tokio::test]
async fn dispatch_credential_access_allows_target_with_unknown_realm() {
    let handler = handler_with_host("192.168.58.7", "dc03.contoso.local").await;
    let call = cred_access_call("192.168.58.99", "contoso.local");

    let err = handler.dispatch_credential_access(&call).await.unwrap_err();
    assert!(
        err.to_string().contains("Dispatcher not configured"),
        "an unmapped target must not be guessed as cross-realm, got {err}"
    );
}

#[tokio::test]
async fn dispatch_lateral_still_rejects_cross_forest_target() {
    let handler = handler_with_host("192.168.58.5", "dc01.fabrikam.local").await;
    let call = ToolCall {
        id: "lat-1".into(),
        name: "dispatch_lateral_movement".into(),
        arguments: json!({
            "technique": "psexec",
            "target_ip": "192.168.58.5",
            "domain": "contoso.local",
            "username": "alice",
        }),
    };

    let result = handler.dispatch_lateral(&call).await.unwrap();
    let CallbackResult::Continue(msg) = result else {
        panic!("expected a Continue rejection");
    };
    assert!(msg.contains("REJECTED"), "got: {msg}");
}

fn make_vuln(vuln_id: &str, vuln_type: &str) -> ares_core::models::VulnerabilityInfo {
    ares_core::models::VulnerabilityInfo {
        vuln_id: vuln_id.into(),
        vuln_type: vuln_type.into(),
        target: "192.168.58.220".into(),
        discovered_by: "test".into(),
        discovered_at: chrono::Utc::now(),
        details: {
            let mut m = std::collections::HashMap::new();
            m.insert("domain".into(), json!("contoso.local"));
            m.insert("ca_name".into(), json!("CONTOSO-CA"));
            m
        },
        recommended_agent: String::new(),
        priority: 1,
    }
}

fn exploit_call(vuln_id: &str) -> ToolCall {
    ToolCall {
        id: "exp-1".into(),
        name: "dispatch_exploit".into(),
        arguments: json!({ "vuln_id": vuln_id }),
    }
}

#[tokio::test]
async fn dispatch_exploit_refuses_a_vuln_abandoned_at_max_failures() {
    let state = SharedState::new("test-op".to_string());
    {
        let mut s = state.write().await;
        s.discovered_vulnerabilities.insert(
            "adcs_esc1_dead".into(),
            make_vuln("adcs_esc1_dead", "adcs_esc1"),
        );
    }
    for _ in 0..crate::orchestrator::state::MAX_EXPLOIT_FAILURES {
        state.record_exploit_failure("adcs_esc1_dead").await;
    }

    let handler = OrchestratorCallbackHandler::new_for_test(state);
    let result = handler
        .dispatch_exploit(&exploit_call("adcs_esc1_dead"))
        .await
        .unwrap();

    let CallbackResult::Continue(msg) = result else {
        panic!("expected a Continue refusal");
    };
    assert!(msg.contains("Refused"), "got: {msg}");
    assert!(msg.contains("adcs_esc1_dead"), "got: {msg}");
}

#[tokio::test]
async fn dispatch_exploit_refuses_forest_pivot_vulns_owned_by_trust_automation() {
    for vuln_type in ["forest_trust_escalation", "child_to_parent"] {
        let vuln_id = format!("{vuln_type}_contoso.local_fabrikam.local");
        let state = SharedState::new("test-op".to_string());
        {
            let mut s = state.write().await;
            s.discovered_vulnerabilities
                .insert(vuln_id.clone(), make_vuln(&vuln_id, vuln_type));
        }

        let handler = OrchestratorCallbackHandler::new_for_test(state);
        let result = handler.dispatch_exploit(&exploit_call(&vuln_id)).await;

        let Ok(CallbackResult::Continue(msg)) = result else {
            panic!("{vuln_type} must be refused before the dispatcher lookup");
        };
        assert!(msg.contains("Refused"), "got: {msg}");
        assert!(msg.contains(&vuln_id), "got: {msg}");
        assert!(
            msg.contains("TARGET realm"),
            "the refusal must redirect the planner at the real blocker, got: {msg}"
        );
    }
}

#[tokio::test]
async fn dispatch_exploit_still_allows_acl_vulns_the_llm_path_can_land() {
    let state = SharedState::new("test-op".to_string());
    {
        let mut s = state.write().await;
        s.discovered_vulnerabilities.insert(
            "acl_genericall_alice_bob".into(),
            make_vuln("acl_genericall_alice_bob", "genericall"),
        );
    }

    let handler = OrchestratorCallbackHandler::new_for_test(state);
    let err = handler
        .dispatch_exploit(&exploit_call("acl_genericall_alice_bob"))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("Dispatcher not configured"),
        "an ACL vuln must still reach dispatch, got {err}"
    );
}

#[tokio::test]
async fn dispatch_exploit_still_dispatches_below_the_failure_cap() {
    let state = SharedState::new("test-op".to_string());
    {
        let mut s = state.write().await;
        s.discovered_vulnerabilities.insert(
            "adcs_esc1_live".into(),
            make_vuln("adcs_esc1_live", "adcs_esc1"),
        );
    }
    for _ in 0..(crate::orchestrator::state::MAX_EXPLOIT_FAILURES - 1) {
        state.record_exploit_failure("adcs_esc1_live").await;
    }

    let handler = OrchestratorCallbackHandler::new_for_test(state);
    // Below the cap the guard must fall through to the dispatcher, which this
    // test handler does not have — proving the vuln was not refused.
    let err = handler
        .dispatch_exploit(&exploit_call("adcs_esc1_live"))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("Dispatcher not configured"),
        "a vuln below the cap must reach dispatch, got {err}"
    );
}
