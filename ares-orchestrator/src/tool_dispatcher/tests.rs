use super::*;

#[test]
fn test_tool_exec_request_serialization() {
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
fn test_tool_exec_response_deserialization() {
    let json = r#"{"call_id":"nmap_scan_abc","output":"Found 5 hosts","error":null}"#;
    let resp: ToolExecResponse = serde_json::from_str(json).unwrap();
    assert_eq!(resp.output, "Found 5 hosts");
    assert!(resp.error.is_none());
}

#[test]
fn test_tool_exec_response_with_error() {
    let json = r#"{"call_id":"x","output":"","error":"Connection refused"}"#;
    let resp: ToolExecResponse = serde_json::from_str(json).unwrap();
    assert_eq!(resp.error.as_deref(), Some("Connection refused"));
}

#[test]
fn test_cross_role_routing_netexec_tools() {
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
fn test_cross_role_routing_native_tools_stay() {
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
fn test_cross_role_routing_recon_stays_recon() {
    // When recon itself calls these tools, they stay on recon
    assert_eq!(resolve_queue_role("recon", "password_spray"), "recon");
    assert_eq!(resolve_queue_role("recon", "nmap_scan"), "recon");
    assert_eq!(
        resolve_queue_role("recon", "ldap_search_descriptions"),
        "recon"
    );
}
