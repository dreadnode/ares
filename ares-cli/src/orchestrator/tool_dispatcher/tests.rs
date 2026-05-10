use super::*;
use crate::orchestrator::task_queue::TaskQueueCore;
use ares_core::state::mock_redis::MockRedisConnection;
use redis::AsyncCommands;

#[test]
fn tool_exec_request_serialization() {
    let req = ToolExecRequest {
        call_id: "nmap_scan_abc123".into(),
        task_id: "recon_def456".into(),
        tool_name: "nmap_scan".into(),
        arguments: serde_json::json!({"target": "192.168.58.0/24"}),
        traceparent: None,
        operation_id: Some("op-20260415-120000".into()),
    };

    let json = serde_json::to_string(&req).unwrap();
    let parsed: ToolExecRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.call_id, "nmap_scan_abc123");
    assert_eq!(parsed.tool_name, "nmap_scan");
}

#[test]
fn tool_exec_response_deserialization() {
    let json = r#"{"call_id":"nmap_scan_abc","output":"Found 5 hosts","error":null}"#;
    let resp: ToolExecResponse = serde_json::from_str(json).unwrap();
    assert_eq!(resp.output, "Found 5 hosts");
    assert!(resp.error.is_none());
}

#[test]
fn tool_exec_response_with_error() {
    let json = r#"{"call_id":"x","output":"","error":"Connection refused"}"#;
    let resp: ToolExecResponse = serde_json::from_str(json).unwrap();
    assert_eq!(resp.error.as_deref(), Some("Connection refused"));
}

#[test]
fn cross_role_routing_netexec_tools() {
    // Netexec tools called from credential_access should route to recon
    assert_eq!(
        resolve_queue_role("credential_access", "password_spray"),
        "recon"
    );
    assert_eq!(
        resolve_queue_role("credential_access", "username_as_password"),
        "recon"
    );
    assert_eq!(
        resolve_queue_role("credential_access", "ldap_search_descriptions"),
        "recon"
    );
    assert_eq!(
        resolve_queue_role("credential_access", "gpp_password_finder"),
        "recon"
    );
    assert_eq!(
        resolve_queue_role("credential_access", "sysvol_script_search"),
        "recon"
    );
    assert_eq!(
        resolve_queue_role("credential_access", "laps_dump"),
        "recon"
    );
    assert_eq!(
        resolve_queue_role("credential_access", "smbclient_spider"),
        "recon"
    );
    assert_eq!(
        resolve_queue_role("credential_access", "password_policy"),
        "recon"
    );
}

#[test]
fn cross_role_routing_native_tools_stay() {
    // Tools native to credential_access should stay on credential_access
    assert_eq!(
        resolve_queue_role("credential_access", "secretsdump"),
        "credential_access"
    );
    assert_eq!(
        resolve_queue_role("credential_access", "kerberoast"),
        "credential_access"
    );
    assert_eq!(
        resolve_queue_role("credential_access", "lsassy"),
        "credential_access"
    );
}

#[test]
fn cross_role_routing_recon_stays_recon() {
    // When recon itself calls these tools, they stay on recon
    assert_eq!(resolve_queue_role("recon", "password_spray"), "recon");
    assert_eq!(resolve_queue_role("recon", "nmap_scan"), "recon");
    assert_eq!(
        resolve_queue_role("recon", "ldap_search_descriptions"),
        "recon"
    );
}

#[test]
fn extract_credential_key_returns_none_for_non_auth_tool() {
    let call = ares_llm::ToolCall {
        id: "1".into(),
        name: "nmap_scan".into(),
        arguments: serde_json::json!({"target": "192.168.58.0/24"}),
    };
    assert!(extract_credential_key(&call).is_none());
}

#[test]
fn extract_credential_key_returns_none_when_username_missing() {
    let call = ares_llm::ToolCall {
        id: "1".into(),
        name: "secretsdump".into(),
        arguments: serde_json::json!({"target": "192.168.58.10"}),
    };
    assert!(extract_credential_key(&call).is_none());
}

#[test]
fn extract_credential_key_lowercases_username_and_domain() {
    let call = ares_llm::ToolCall {
        id: "1".into(),
        name: "password_spray".into(),
        arguments: serde_json::json!({
            "username": "Administrator",
            "domain": "CONTOSO.LOCAL",
            "passwords": ["P@ss"]
        }),
    };
    let key = extract_credential_key(&call).expect("key extracted");
    assert_eq!(key, "administrator@contoso.local");
}

#[test]
fn extract_credential_key_uses_unknown_when_domain_missing() {
    let call = ares_llm::ToolCall {
        id: "1".into(),
        name: "secretsdump".into(),
        arguments: serde_json::json!({"username": "admin", "target": "192.168.58.10"}),
    };
    let key = extract_credential_key(&call).expect("key extracted");
    assert_eq!(key, "admin@unknown");
}

#[test]
fn extract_credential_key_uses_unknown_when_domain_empty() {
    let call = ares_llm::ToolCall {
        id: "1".into(),
        name: "kerberoast".into(),
        arguments: serde_json::json!({"username": "user1", "domain": ""}),
    };
    let key = extract_credential_key(&call).expect("key extracted");
    assert_eq!(key, "user1@unknown");
}

#[test]
fn extract_credential_key_recognizes_lateral_tools() {
    for tool in ["smbexec", "psexec", "wmiexec", "dcomexec", "atexec"] {
        let call = ares_llm::ToolCall {
            id: "1".into(),
            name: tool.into(),
            arguments: serde_json::json!({"username": "u", "domain": "d", "target": "x"}),
        };
        assert_eq!(
            extract_credential_key(&call).as_deref(),
            Some("u@d"),
            "tool {tool} should be auth-bearing"
        );
    }
}

#[test]
fn extract_credential_key_recognizes_netexec_tools() {
    for tool in [
        "ldap_search_descriptions",
        "username_as_password",
        "gpp_password_finder",
        "sysvol_script_search",
        "password_policy",
        "laps_dump",
        "smbclient_spider",
        "check_credman_entries",
        "check_autologon_registry",
        "domain_admin_checker",
        "gmsa_dump_passwords",
    ] {
        let call = ares_llm::ToolCall {
            id: "1".into(),
            name: tool.into(),
            arguments: serde_json::json!({"username": "u", "domain": "d"}),
        };
        assert_eq!(
            extract_credential_key(&call).as_deref(),
            Some("u@d"),
            "tool {tool} should be auth-bearing"
        );
    }
}

#[test]
fn extract_credential_key_recognizes_impacket_tools() {
    for tool in [
        "secretsdump",
        "secretsdump_kerberos",
        "kerberoast",
        "asrep_roast",
        "lsassy",
        "ntds_dit_extract",
    ] {
        let call = ares_llm::ToolCall {
            id: "1".into(),
            name: tool.into(),
            arguments: serde_json::json!({"username": "u", "domain": "d"}),
        };
        assert_eq!(
            extract_credential_key(&call).as_deref(),
            Some("u@d"),
            "tool {tool} should be auth-bearing"
        );
    }
}

#[test]
fn cross_role_routing_lateral_movement_stays() {
    // Lateral tools should stay on the calling role
    assert_eq!(resolve_queue_role("lateral", "smbexec"), "lateral");
    assert_eq!(resolve_queue_role("lateral", "psexec"), "lateral");
    assert_eq!(resolve_queue_role("lateral", "wmiexec"), "lateral");
}

#[test]
fn cross_role_routing_native_recon_tools() {
    // Pure recon tools (not in RECON_ROUTED_TOOLS) stay on whatever role calls them.
    assert_eq!(resolve_queue_role("custom", "nmap_scan"), "custom");
    assert_eq!(resolve_queue_role("custom", "secretsdump"), "custom");
}

#[test]
fn tool_exec_request_omits_traceparent_when_none() {
    let req = ToolExecRequest {
        call_id: "c".into(),
        task_id: "t".into(),
        tool_name: "nmap_scan".into(),
        arguments: serde_json::json!({}),
        traceparent: None,
        operation_id: None,
    };
    let json = serde_json::to_string(&req).unwrap();
    assert!(!json.contains("traceparent"));
    assert!(!json.contains("operation_id"));
}

#[test]
fn tool_exec_request_includes_traceparent_when_some() {
    let req = ToolExecRequest {
        call_id: "c".into(),
        task_id: "t".into(),
        tool_name: "nmap_scan".into(),
        arguments: serde_json::json!({}),
        traceparent: Some("00-trace-span-01".into()),
        operation_id: Some("op-123".into()),
    };
    let json = serde_json::to_string(&req).unwrap();
    assert!(json.contains("traceparent"));
    assert!(json.contains("00-trace-span-01"));
    assert!(json.contains("op-123"));
}

#[test]
fn tool_exec_response_with_discoveries_field() {
    let json = r#"{
        "call_id":"c",
        "output":"out",
        "error":null,
        "discoveries":{"hosts":[{"ip":"192.168.58.10"}]}
    }"#;
    let resp: ToolExecResponse = serde_json::from_str(json).unwrap();
    assert!(resp.discoveries.is_some());
    let disc = resp.discoveries.unwrap();
    assert_eq!(disc["hosts"][0]["ip"], "192.168.58.10");
}

#[test]
fn tool_exec_response_default_discoveries_none() {
    // discoveries field is optional with #[serde(default)]
    let json = r#"{"call_id":"c","output":"out","error":null}"#;
    let resp: ToolExecResponse = serde_json::from_str(json).unwrap();
    assert!(resp.discoveries.is_none());
}

#[tokio::test]
async fn auth_throttle_allows_under_limit() {
    let throttle = AuthThrottle::new(3, std::time::Duration::from_secs(60));
    let start = std::time::Instant::now();
    throttle.acquire("admin@contoso").await;
    throttle.acquire("admin@contoso").await;
    throttle.acquire("admin@contoso").await;
    // All three within window — should not have slept
    assert!(start.elapsed() < std::time::Duration::from_millis(500));
}

#[tokio::test]
async fn auth_throttle_separate_credentials_dont_interfere() {
    let throttle = AuthThrottle::new(2, std::time::Duration::from_secs(60));
    let start = std::time::Instant::now();
    throttle.acquire("user1@d").await;
    throttle.acquire("user1@d").await;
    // user1 is at limit, but user2 should be free
    throttle.acquire("user2@d").await;
    throttle.acquire("user2@d").await;
    assert!(start.elapsed() < std::time::Duration::from_millis(500));
}

#[tokio::test]
async fn auth_throttle_window_pruning_allows_more_after_expiry() {
    // 2 attempts in a 100ms window
    let throttle = AuthThrottle::new(2, std::time::Duration::from_millis(100));
    throttle.acquire("u@d").await;
    throttle.acquire("u@d").await;
    // Sleep past the window
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let start = std::time::Instant::now();
    // Old attempts pruned — this should not block
    throttle.acquire("u@d").await;
    assert!(start.elapsed() < std::time::Duration::from_millis(50));
}

fn mock_queue() -> TaskQueueCore<MockRedisConnection> {
    TaskQueueCore::from_connection(MockRedisConnection::new())
}

#[tokio::test]
async fn push_realtime_discoveries_pushes_hosts() {
    let q = mock_queue();
    let discoveries = serde_json::json!({
        "hosts": [
            {"ip": "192.168.58.10", "hostname": "dc01"},
            {"ip": "192.168.58.11", "hostname": "ws01"}
        ]
    });
    let args = serde_json::json!({});

    push_realtime_discoveries(&q, "op-1", &discoveries, "nmap_scan", &args).await;

    let mut conn = q.connection();
    let key = format!("{DISCOVERY_KEY_PREFIX}:op-1");
    let entries: Vec<String> = conn.lrange(&key, 0, -1).await.unwrap();
    assert_eq!(entries.len(), 2);
    let parsed0: serde_json::Value = serde_json::from_str(&entries[0]).unwrap();
    assert_eq!(parsed0["type"], "host");
    assert_eq!(parsed0["source_tool"], "nmap_scan");
    assert!(parsed0["data"]["ip"].is_string());
}

#[tokio::test]
async fn push_realtime_discoveries_pushes_credentials_with_input_context() {
    let q = mock_queue();
    let discoveries = serde_json::json!({
        "credentials": [
            {"username": "svc_admin", "password": "P@ss"}
        ]
    });
    let args = serde_json::json!({
        "username": "Administrator",
        "domain": "contoso.local"
    });

    push_realtime_discoveries(&q, "op-2", &discoveries, "secretsdump", &args).await;

    let mut conn = q.connection();
    let key = format!("{DISCOVERY_KEY_PREFIX}:op-2");
    let entries: Vec<String> = conn.lrange(&key, 0, -1).await.unwrap();
    assert_eq!(entries.len(), 1);
    let parsed: serde_json::Value = serde_json::from_str(&entries[0]).unwrap();
    assert_eq!(parsed["type"], "credential");
    assert_eq!(parsed["input_username"], "Administrator");
    assert_eq!(parsed["input_domain"], "contoso.local");
}

#[tokio::test]
async fn push_realtime_discoveries_handles_multiple_types() {
    let q = mock_queue();
    let discoveries = serde_json::json!({
        "hosts": [{"ip": "192.168.58.10"}],
        "credentials": [{"username": "u"}],
        "hashes": [{"hash": "aad3..."}],
        "vulnerabilities": [{"id": "CVE-1"}],
        "shares": [{"name": "C$"}],
        "discovered_users": [{"username": "u2"}],
        "trusted_domains": [{"name": "child.contoso"}]
    });
    let args = serde_json::json!({});

    push_realtime_discoveries(&q, "op-3", &discoveries, "tool", &args).await;

    let mut conn = q.connection();
    let key = format!("{DISCOVERY_KEY_PREFIX}:op-3");
    let entries: Vec<String> = conn.lrange(&key, 0, -1).await.unwrap();
    assert_eq!(entries.len(), 7);
    let types: Vec<String> = entries
        .iter()
        .map(|e| {
            serde_json::from_str::<serde_json::Value>(e).unwrap()["type"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    for expected in [
        "host",
        "credential",
        "hash",
        "vulnerability",
        "share",
        "user",
        "trust",
    ] {
        assert!(
            types.contains(&expected.to_string()),
            "missing type: {expected}"
        );
    }
}

#[tokio::test]
async fn push_realtime_discoveries_skips_non_array_fields() {
    let q = mock_queue();
    // hosts is a string instead of an array — should be skipped
    let discoveries = serde_json::json!({
        "hosts": "not-an-array",
        "credentials": [{"username": "u"}]
    });
    let args = serde_json::json!({});

    push_realtime_discoveries(&q, "op-4", &discoveries, "tool", &args).await;

    let mut conn = q.connection();
    let key = format!("{DISCOVERY_KEY_PREFIX}:op-4");
    let entries: Vec<String> = conn.lrange(&key, 0, -1).await.unwrap();
    assert_eq!(entries.len(), 1);
    let parsed: serde_json::Value = serde_json::from_str(&entries[0]).unwrap();
    assert_eq!(parsed["type"], "credential");
}

#[tokio::test]
async fn push_realtime_discoveries_no_input_context_when_args_lack_username() {
    let q = mock_queue();
    let discoveries = serde_json::json!({
        "hosts": [{"ip": "192.168.58.10"}]
    });
    let args = serde_json::json!({"target": "192.168.58.0/24"});

    push_realtime_discoveries(&q, "op-5", &discoveries, "nmap_scan", &args).await;

    let mut conn = q.connection();
    let key = format!("{DISCOVERY_KEY_PREFIX}:op-5");
    let entries: Vec<String> = conn.lrange(&key, 0, -1).await.unwrap();
    assert_eq!(entries.len(), 1);
    let parsed: serde_json::Value = serde_json::from_str(&entries[0]).unwrap();
    assert!(parsed.get("input_username").is_none());
    assert!(parsed.get("input_domain").is_none());
}

#[tokio::test]
async fn push_realtime_discoveries_uses_user_alias_when_username_missing() {
    let q = mock_queue();
    let discoveries = serde_json::json!({
        "hosts": [{"ip": "192.168.58.10"}]
    });
    // Some tools call it "user" instead of "username"
    let args = serde_json::json!({"user": "fallback_user", "domain": "d"});

    push_realtime_discoveries(&q, "op-6", &discoveries, "tool", &args).await;

    let mut conn = q.connection();
    let key = format!("{DISCOVERY_KEY_PREFIX}:op-6");
    let entries: Vec<String> = conn.lrange(&key, 0, -1).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&entries[0]).unwrap();
    assert_eq!(parsed["input_username"], "fallback_user");
    assert_eq!(parsed["input_domain"], "d");
}

#[tokio::test]
async fn push_realtime_discoveries_no_op_when_no_known_keys() {
    let q = mock_queue();
    let discoveries = serde_json::json!({
        "unknown_field": [{"x": 1}]
    });
    let args = serde_json::json!({});

    push_realtime_discoveries(&q, "op-7", &discoveries, "tool", &args).await;

    let mut conn = q.connection();
    let key = format!("{DISCOVERY_KEY_PREFIX}:op-7");
    let exists: bool = conn.exists(&key).await.unwrap();
    assert!(!exists, "should not have created discovery list");
}

#[test]
fn dispatch_error_result_includes_tool_name_and_underlying_error() {
    use redis_dispatcher::dispatch_error_result;
    let r = dispatch_error_result("nmap_scan", "no responders available");
    assert_eq!(r.output, "");
    assert!(r.discoveries.is_none());
    let err = r.error.as_deref().unwrap();
    assert!(err.contains("nmap_scan"), "missing tool name in {err}");
    assert!(err.contains("dispatch error"));
    assert!(err.contains("no responders available"));
}

#[test]
fn dispatch_error_result_handles_anyhow_errors() {
    use redis_dispatcher::dispatch_error_result;
    let upstream = anyhow::anyhow!("upstream broken pipe");
    let r = dispatch_error_result("certipy", upstream);
    assert!(r.error.unwrap().contains("upstream broken pipe"));
}

#[test]
fn dispatch_timeout_result_renders_seconds() {
    use redis_dispatcher::dispatch_timeout_result;
    let r = dispatch_timeout_result("hashcat", std::time::Duration::from_secs(1500));
    assert_eq!(r.output, "");
    assert!(r.discoveries.is_none());
    let err = r.error.as_deref().unwrap();
    assert!(err.contains("hashcat"));
    assert!(err.contains("1500s"));
    assert!(err.contains("timed out"));
}

#[test]
fn dispatch_timeout_result_zero_seconds_still_well_formed() {
    use redis_dispatcher::dispatch_timeout_result;
    let r = dispatch_timeout_result("nmap", std::time::Duration::from_secs(0));
    assert!(r.error.unwrap().contains("0s"));
}

#[test]
fn default_tool_timeout_is_25_minutes() {
    // 1500s = 25min — must exceed worst-case hashcat queue + run time.
    assert_eq!(DEFAULT_TOOL_TIMEOUT_SECS, 25 * 60);
}

#[test]
fn dispatch_error_and_timeout_results_share_shape() {
    // Both helpers must produce the same shape so the agent loop can treat
    // them uniformly: empty output, no discoveries, non-empty error.
    use redis_dispatcher::{dispatch_error_result, dispatch_timeout_result};
    let e = dispatch_error_result("t", "oops");
    let t = dispatch_timeout_result("t", std::time::Duration::from_secs(60));
    assert_eq!(e.output, t.output);
    assert!(e.discoveries.is_none() && t.discoveries.is_none());
    assert!(e.error.is_some() && t.error.is_some());
}

#[test]
fn build_call_id_includes_tool_name_prefix() {
    use redis_dispatcher::build_call_id;
    let id = build_call_id("nmap_scan");
    assert!(id.starts_with("nmap_scan_"), "got {id}");
    // simple uuid is 32 hex chars after the prefix + underscore
    let suffix = id.strip_prefix("nmap_scan_").unwrap();
    assert_eq!(suffix.len(), 32);
    assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn build_call_id_is_unique_per_invocation() {
    use redis_dispatcher::build_call_id;
    let a = build_call_id("hashcat");
    let b = build_call_id("hashcat");
    assert_ne!(a, b);
}

#[test]
fn build_tool_exec_request_carries_all_inputs() {
    use redis_dispatcher::build_tool_exec_request;
    let req = build_tool_exec_request(
        "nmap_scan_abc".into(),
        "task-1",
        "nmap_scan",
        serde_json::json!({"target": "192.168.58.10"}),
        Some("00-trace-span-01".into()),
        Some("op-2026".into()),
    );
    assert_eq!(req.call_id, "nmap_scan_abc");
    assert_eq!(req.task_id, "task-1");
    assert_eq!(req.tool_name, "nmap_scan");
    assert_eq!(req.arguments["target"], "192.168.58.10");
    assert_eq!(req.traceparent.as_deref(), Some("00-trace-span-01"));
    assert_eq!(req.operation_id.as_deref(), Some("op-2026"));
}

#[test]
fn build_tool_exec_request_with_no_traceparent_or_operation() {
    use redis_dispatcher::build_tool_exec_request;
    let req = build_tool_exec_request("c".into(), "t", "whoami", serde_json::json!({}), None, None);
    assert!(req.traceparent.is_none());
    assert!(req.operation_id.is_none());
    let json = serde_json::to_string(&req).unwrap();
    // Optional fields skip when None
    assert!(!json.contains("traceparent"));
    assert!(!json.contains("operation_id"));
}

#[test]
fn tool_exec_result_from_response_passes_through_all_fields() {
    use redis_dispatcher::tool_exec_result_from_response;
    let resp = ToolExecResponse {
        call_id: "c".into(),
        output: "out".into(),
        error: None,
        discoveries: Some(serde_json::json!({"hosts": [{"ip": "192.168.58.10"}]})),
    };
    let r = tool_exec_result_from_response(resp);
    assert_eq!(r.output, "out");
    assert!(r.error.is_none());
    assert_eq!(r.discoveries.unwrap()["hosts"][0]["ip"], "192.168.58.10");
}

#[test]
fn tool_exec_result_from_response_preserves_error_string() {
    use redis_dispatcher::tool_exec_result_from_response;
    let resp = ToolExecResponse {
        call_id: "c".into(),
        output: String::new(),
        error: Some("connection refused".into()),
        discoveries: None,
    };
    let r = tool_exec_result_from_response(resp);
    assert_eq!(r.error.as_deref(), Some("connection refused"));
    assert!(r.discoveries.is_none());
}
