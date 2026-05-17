//! End-to-end smoke test for the Ares LLM agent loop.
//!
//! Exercises the full pipeline without any external services:
//!   1. Prompt generation (task prompt + system prompt via Tera templates)
//!   2. Tool registry (role-specific tool definitions)
//!   3. Agent loop with a mock LLM provider that returns `task_complete`
//!
//! Run:  cargo run --example smoke_test

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::Result;
use serde_json::json;

use ares_llm::prompt::generate_task_prompt;
use ares_llm::prompt::templates::{render_agent_instructions, OperationContext, TEMPLATE_RECON};
use ares_llm::tool_registry::{tools_for_role, AgentRole};
use ares_llm::{
    run_agent_loop, AgentLoopConfig, CallbackHandler, LlmError, LlmProvider, LlmRequest,
    LlmResponse, LoopEndReason, RunAgentLoopParams, StopReason, TokenUsage, ToolCall,
    ToolDefinition, ToolDispatcher, ToolExecResult,
};

struct MockProvider {
    step: AtomicU32,
}

impl MockProvider {
    fn new() -> Self {
        Self {
            step: AtomicU32::new(0),
        }
    }
}

#[async_trait::async_trait]
impl LlmProvider for MockProvider {
    async fn chat(&self, _request: &LlmRequest) -> Result<LlmResponse, LlmError> {
        let step = self.step.fetch_add(1, Ordering::SeqCst);
        match step {
            0 => Ok(LlmResponse {
                content: "I'll start with a port scan on the target.".into(),
                tool_calls: vec![ToolCall {
                    id: "tc_1".into(),
                    name: "nmap_scan".into(),
                    arguments: json!({
                        "target": "192.168.58.10",
                        "scan_type": "default"
                    }),
                }],
                stop_reason: StopReason::ToolUse,
                usage: TokenUsage {
                    input_tokens: 500,
                    output_tokens: 80,
                    ..Default::default()
                },
            }),
            _ => Ok(LlmResponse {
                content: "Scan complete. Found SMB, LDAP, and Kerberos services.".into(),
                tool_calls: vec![ToolCall {
                    id: "tc_2".into(),
                    name: "task_complete".into(),
                    arguments: json!({
                        "task_id": "t-smoke-1",
                        "result": "Port scan complete: 445/tcp (SMB), 389/tcp (LDAP), 88/tcp (Kerberos)"
                    }),
                }],
                stop_reason: StopReason::ToolUse,
                usage: TokenUsage {
                    input_tokens: 1200,
                    output_tokens: 120,
                    ..Default::default()
                },
            }),
        }
    }

    fn name(&self) -> &str {
        "mock"
    }
}

struct MockDispatcher;

#[async_trait::async_trait]
impl ToolDispatcher for MockDispatcher {
    async fn dispatch_tool(
        &self,
        _role: &str,
        _task_id: &str,
        call: &ToolCall,
    ) -> Result<ToolExecResult> {
        match call.name.as_str() {
            "nmap_scan" => Ok(ToolExecResult {
                output: concat!(
                    "PORT    STATE SERVICE\n",
                    "88/tcp  open  kerberos-sec\n",
                    "135/tcp open  msrpc\n",
                    "389/tcp open  ldap\n",
                    "445/tcp open  microsoft-ds\n",
                    "3268/tcp open globalcatLDAP\n",
                )
                .into(),
                error: None,
                discoveries: Some(json!({
                    "hosts": [{
                        "ip": "192.168.58.10",
                        "hostname": "dc01.contoso.local",
                        "open_ports": [88, 135, 389, 445, 3268]
                    }]
                })),
            }),
            other => Ok(ToolExecResult {
                output: format!("Mock output for {other}"),
                error: None,
                discoveries: None,
            }),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Ares LLM Smoke Test ===\n");

    // ── 1. System prompt via Tera template ──
    let capabilities = vec![
        "nmap_scan".to_string(),
        "enumerate_users".to_string(),
        "run_bloodhound".to_string(),
    ];
    let system_prompt = render_agent_instructions(
        TEMPLATE_RECON,
        &capabilities,
        false,
        &[],
        OperationContext {
            target_domain: "contoso.local",
            target_dc_ip: "192.168.58.10",
            target_dc_fqdn: "dc01.contoso.local",
            listener_ip: "192.168.58.50",
        },
    )?;
    assert!(!system_prompt.is_empty());
    println!(
        "[OK] System prompt rendered ({} chars)",
        system_prompt.len()
    );

    // ── 2. Task prompt from payload ──
    let payload = json!({
        "target": "192.168.58.10",
        "scan_type": "default",
        "domain": "contoso.local"
    });
    let task_prompt = generate_task_prompt("recon", "t-smoke-1", &payload, None)
        .expect("recon prompt should be recognized");
    assert!(!task_prompt.is_empty());
    println!("[OK] Task prompt generated ({} chars)", task_prompt.len());

    // ── 3. Tool registry ──
    let tools: Vec<ToolDefinition> = tools_for_role(AgentRole::Recon);
    assert!(!tools.is_empty());
    println!("[OK] Tool registry: {} tools for recon role", tools.len());

    // ── 4. Agent loop (mock provider + mock dispatcher) ──
    let provider = MockProvider::new();
    let dispatcher: Arc<dyn ToolDispatcher> = Arc::new(MockDispatcher);
    let config = AgentLoopConfig {
        model: "mock".into(),
        max_steps: 10,
        ..AgentLoopConfig::default()
    };

    let callbacks: Option<Arc<dyn CallbackHandler>> = None;
    let outcome = run_agent_loop(RunAgentLoopParams {
        provider: &provider,
        dispatcher,
        config: &config,
        system_prompt: &system_prompt,
        task_prompt: &task_prompt,
        role: "recon",
        task_id: "t-smoke-1",
        tools: &tools,
        callback_handler: callbacks,
        hostname_map: None,
    })
    .await;

    println!("\n--- Agent Loop Outcome ---");
    println!("  Reason: {:?}", outcome.reason);
    println!("  Steps: {}", outcome.steps);
    println!("  Tool calls: {}", outcome.tool_calls_dispatched);
    println!(
        "  Tokens: {} in / {} out",
        outcome.total_usage.input_tokens, outcome.total_usage.output_tokens
    );
    println!("  Discoveries: {} batch(es)", outcome.discoveries.len());

    let LoopEndReason::TaskComplete { task_id, result } = &outcome.reason else {
        panic!("expected TaskComplete, got: {:?}", outcome.reason);
    };
    assert_eq!(task_id, "t-smoke-1");
    assert!(result.contains("Port scan complete"));
    println!("\n[OK] Agent loop completed task '{task_id}'");

    assert_eq!(outcome.steps, 2);
    assert_eq!(outcome.tool_calls_dispatched, 1); // nmap_scan only; task_complete is callback
    assert!(!outcome.discoveries.is_empty());
    println!("[OK] Assertions passed (2 steps, 1 dispatched tool, discoveries present)");

    println!("\n=== All smoke tests passed ===");
    Ok(())
}
