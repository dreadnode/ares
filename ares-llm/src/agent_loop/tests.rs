use super::callbacks::handle_builtin_callback;
use super::config::{AgentLoopConfig, ContextConfig, RetryConfig};
use super::context::{estimate_tokens, trim_conversation, truncate_tool_output};
use super::retry::simple_hash;
use super::types::CallbackResult;
use crate::provider::{ChatMessage, LlmError, Role, ToolCall};

#[test]
fn test_handle_task_complete_callback() {
    let call = ToolCall {
        id: "call_1".into(),
        name: "task_complete".into(),
        arguments: serde_json::json!({
            "task_id": "task-001",
            "result": "Found 5 hosts"
        }),
    };
    let result = handle_builtin_callback(&call).unwrap();
    match result {
        CallbackResult::TaskComplete { task_id, result } => {
            assert_eq!(task_id, "task-001");
            assert_eq!(result, "Found 5 hosts");
        }
        _ => panic!("Expected TaskComplete"),
    }
}

#[test]
fn test_handle_request_assistance_callback() {
    let call = ToolCall {
        id: "call_2".into(),
        name: "request_assistance".into(),
        arguments: serde_json::json!({
            "issue": "Cannot reach target",
            "context": "Tried 3 times"
        }),
    };
    let result = handle_builtin_callback(&call).unwrap();
    match result {
        CallbackResult::RequestAssistance { issue, context } => {
            assert_eq!(issue, "Cannot reach target");
            assert_eq!(context, "Tried 3 times");
        }
        _ => panic!("Expected RequestAssistance"),
    }
}

#[test]
fn test_handle_report_finding_callback() {
    let call = ToolCall {
        id: "call_3".into(),
        name: "report_finding".into(),
        arguments: serde_json::json!({
            "finding_type": "smb_signing_disabled",
            "description": "SMB signing not required on 192.168.58.20"
        }),
    };
    let result = handle_builtin_callback(&call).unwrap();
    match result {
        CallbackResult::Continue(msg) => {
            assert!(msg.contains("smb_signing_disabled"));
        }
        _ => panic!("Expected Continue"),
    }
}

#[test]
fn test_unknown_callback() {
    let call = ToolCall {
        id: "call_x".into(),
        name: "unknown_callback".into(),
        arguments: serde_json::json!({}),
    };
    assert!(handle_builtin_callback(&call).is_err());
}

#[test]
fn test_agent_loop_config_defaults() {
    let config = AgentLoopConfig::default();
    assert_eq!(config.max_steps, 75);
    assert_eq!(config.max_tokens, 4096);
    assert_eq!(config.retry.max_retries, 5);
    assert_eq!(config.retry.base_delay_ms, 1_000);
    assert_eq!(config.retry.max_delay_ms, 60_000);
}

#[test]
fn test_retry_config_defaults() {
    let config = RetryConfig::default();
    assert_eq!(config.max_retries, 5);
    assert_eq!(config.base_delay_ms, 1_000);
    assert_eq!(config.max_delay_ms, 60_000);
}

#[test]
fn test_llm_error_retryable() {
    assert!(LlmError::RateLimited {
        retry_after_ms: Some(1000)
    }
    .is_retryable());
    assert!(LlmError::Network("timeout".into()).is_retryable());
    assert!(LlmError::ApiError {
        status: 500,
        message: "internal error".into()
    }
    .is_retryable());
    assert!(LlmError::ApiError {
        status: 502,
        message: "bad gateway".into()
    }
    .is_retryable());
    assert!(!LlmError::AuthError("bad key".into()).is_retryable());
    assert!(!LlmError::ContextTooLong("too big".into()).is_retryable());
    assert!(!LlmError::ApiError {
        status: 400,
        message: "bad request".into()
    }
    .is_retryable());
}

#[test]
fn test_llm_error_retry_after() {
    assert_eq!(
        LlmError::RateLimited {
            retry_after_ms: Some(5000)
        }
        .retry_after_ms(),
        Some(5000)
    );
    assert_eq!(
        LlmError::RateLimited {
            retry_after_ms: None
        }
        .retry_after_ms(),
        None
    );
    assert_eq!(LlmError::Network("err".into()).retry_after_ms(), None);
}

#[test]
fn test_simple_hash_deterministic() {
    let h1 = simple_hash(0, "task-001");
    let h2 = simple_hash(0, "task-001");
    assert_eq!(h1, h2);

    let h3 = simple_hash(1, "task-001");
    assert_ne!(h1, h3);

    let h4 = simple_hash(0, "task-002");
    assert_ne!(h1, h4);
}

// Context management tests

#[test]
fn test_estimate_tokens() {
    assert_eq!(estimate_tokens(""), 0); // (0 + 3) / 4 = 0
    assert_eq!(estimate_tokens("hello"), 2); // (5 + 3) / 4 = 2
    assert_eq!(estimate_tokens(&"a".repeat(400)), 100); // (400 + 3) / 4 = 100
}

#[test]
fn test_truncate_tool_output_short() {
    let output = "short output";
    assert_eq!(truncate_tool_output(output, 100), output);
}

#[test]
fn test_truncate_tool_output_no_limit() {
    let output = "a".repeat(100_000);
    assert_eq!(truncate_tool_output(&output, 0), output);
}

#[test]
fn test_truncate_tool_output_long() {
    let output = "a".repeat(50_000);
    let truncated = truncate_tool_output(&output, 1000);
    assert!(truncated.len() < 1200); // Slightly over due to notice
    assert!(truncated.contains("truncated"));
    assert!(truncated.starts_with("aaa")); // Head preserved
    assert!(truncated.ends_with("aaa")); // Tail preserved
}

#[test]
fn test_context_config_defaults() {
    let config = ContextConfig::default();
    assert_eq!(config.max_context_tokens, 180_000);
    assert_eq!(config.max_tool_output_chars, 30_000);
    assert_eq!(config.min_recent_messages, 10);
}

#[test]
fn test_trim_conversation_under_limit() {
    let mut messages = vec![
        ChatMessage::text(Role::User, "task prompt"),
        ChatMessage::text(Role::Assistant, "I'll scan."),
        ChatMessage::tool_result("call_1", "scan result"),
    ];
    let config = ContextConfig {
        max_context_tokens: 1_000_000,
        max_tool_output_chars: 0,
        min_recent_messages: 10,
    };
    let original_len = messages.len();
    trim_conversation(&mut messages, "system", &[], &config);
    assert_eq!(messages.len(), original_len); // No change
}

#[test]
fn test_trim_conversation_disabled() {
    let mut messages = vec![ChatMessage::text(
        Role::User,
        "a".repeat(1_000_000).as_str(),
    )];
    let config = ContextConfig {
        max_context_tokens: 0, // Disabled
        max_tool_output_chars: 0,
        min_recent_messages: 10,
    };
    trim_conversation(&mut messages, "system", &[], &config);
    assert_eq!(messages.len(), 1);
}

#[test]
fn test_trim_conversation_drops_middle() {
    // Create a conversation that exceeds the limit
    let mut messages = Vec::new();
    messages.push(ChatMessage::text(Role::User, "task prompt"));
    for i in 0..20 {
        messages.push(ChatMessage::text(
            Role::Assistant,
            format!("Step {i}: {}", "x".repeat(500)),
        ));
        messages.push(ChatMessage::tool_result(
            format!("call_{i}"),
            "y".repeat(500),
        ));
    }
    // 1 + 40 = 41 messages

    let config = ContextConfig {
        max_context_tokens: 100, // Very low limit to force trimming
        max_tool_output_chars: 0,
        min_recent_messages: 4,
    };

    trim_conversation(&mut messages, "system", &[], &config);

    // Should have: first message + summary + last 4 messages = 6
    assert_eq!(messages.len(), 6);
    // First message preserved
    assert_eq!(messages[0].text_content().unwrap(), "task prompt");
    // Summary marker inserted
    assert!(messages[1]
        .text_content()
        .unwrap()
        .contains("Context trimmed"));
}
