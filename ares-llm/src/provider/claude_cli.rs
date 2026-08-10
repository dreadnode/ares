//! Claude Code CLI provider — uses the local `claude -p` binary so calls draw
//! from the operator's signed-in Claude Code subscription instead of an
//! Anthropic API key.
//!
//! Each `chat()` spawns `claude -p --input-format stream-json --output-format
//! stream-json --verbose`, writes a single user frame to stdin, and parses the
//! final `result` event from stdout. The CLI's own tools are disabled
//! (`--disallowed-tools '*'`); Ares' tool definitions are rendered into the
//! prompt as XML and tool_use blocks are extracted from the response text.
//! This is degraded vs. native function calling but keeps the existing
//! [`crate::agent_loop`] flow working unchanged.
//!
//! Set `ARES_CLAUDE_CLI_BIN` to override the binary path (default: `claude`).
//! `ANTHROPIC_API_KEY` is stripped from the child env so the CLI falls back to
//! its OAuth subscription credentials.

use std::process::Stdio;

use regex::Regex;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{debug, warn};

use super::{
    ChatMessage, ContentPart, LlmError, LlmProvider, LlmRequest, LlmResponse, Role, StopReason,
    TokenUsage, ToolCall, ToolDefinition,
};

const BINARY_ENV: &str = "ARES_CLAUDE_CLI_BIN";
const DEFAULT_BINARY: &str = "claude";
/// Cap on stdout we'll buffer per turn. Mirrors OpenClaw's per-turn guard.
const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

pub struct ClaudeCliProvider {
    binary: String,
}

impl Default for ClaudeCliProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ClaudeCliProvider {
    pub fn new() -> Self {
        let binary = std::env::var(BINARY_ENV).unwrap_or_else(|_| DEFAULT_BINARY.to_string());
        Self { binary }
    }

    pub fn with_binary(binary: impl Into<String>) -> Self {
        Self {
            binary: binary.into(),
        }
    }
}

#[async_trait::async_trait]
impl LlmProvider for ClaudeCliProvider {
    async fn chat(&self, request: &LlmRequest) -> Result<LlmResponse, LlmError> {
        let prompt = build_prompt(request);
        let frame = serde_json::json!({
            "type": "user",
            "message": {
                "role": "user",
                "content": [{ "type": "text", "text": prompt }],
            },
        });
        let frame_line = format!("{}\n", serde_json::to_string(&frame).unwrap());

        debug!(
            model = %request.model,
            msg_count = request.messages.len(),
            tool_count = request.tools.len(),
            prompt_bytes = prompt.len(),
            "claude-cli request"
        );

        let mut cmd = Command::new(&self.binary);
        cmd.arg("-p")
            .arg("--input-format")
            .arg("stream-json")
            .arg("--output-format")
            .arg("stream-json")
            .arg("--verbose")
            .arg("--disallowed-tools")
            .arg("*")
            .arg("--model")
            .arg(&request.model)
            .env_remove("ANTHROPIC_API_KEY")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd.spawn().map_err(|e| {
            LlmError::Other(anyhow::anyhow!(
                "failed to spawn `{}`: {e} (set {BINARY_ENV} to override path)",
                self.binary,
            ))
        })?;

        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| LlmError::Other(anyhow::anyhow!("claude-cli: stdin missing")))?;
            stdin
                .write_all(frame_line.as_bytes())
                .await
                .map_err(|e| LlmError::Network(format!("claude-cli stdin write: {e}")))?;
            stdin
                .shutdown()
                .await
                .map_err(|e| LlmError::Network(format!("claude-cli stdin close: {e}")))?;
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| LlmError::Network(format!("claude-cli wait: {e}")))?;

        if output.stdout.len() > MAX_OUTPUT_BYTES {
            return Err(LlmError::Other(anyhow::anyhow!(
                "claude-cli stdout exceeded {} bytes",
                MAX_OUTPUT_BYTES
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !output.status.success() && find_result_line(&stdout).is_none() {
            return Err(classify_exit(output.status.code(), &stderr));
        }

        parse_response(&stdout, &stderr)
    }

    fn name(&self) -> &str {
        "claude-cli"
    }
}

fn classify_exit(code: Option<i32>, stderr: &str) -> LlmError {
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("not logged in") || lower.contains("unauthor") || lower.contains("login") {
        return LlmError::AuthError(format!("claude-cli not logged in: {stderr}"));
    }
    LlmError::ApiError {
        status: code.and_then(|c| u16::try_from(c).ok()).unwrap_or(500),
        message: format!("claude-cli exited (code {code:?}): {stderr}"),
    }
}

fn find_result_line(stdout: &str) -> Option<&str> {
    stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .rev()
        .find(|l| l.contains(r#""type":"result""#))
}

#[derive(Deserialize)]
struct ResultEvent {
    #[serde(default)]
    is_error: bool,
    #[serde(default)]
    result: String,
    #[serde(default)]
    stop_reason: Option<String>,
    #[serde(default)]
    subtype: Option<String>,
    #[serde(default)]
    usage: Option<ResultUsage>,
}

#[derive(Deserialize, Default)]
struct ResultUsage {
    #[serde(default)]
    input_tokens: u32,
    #[serde(default)]
    output_tokens: u32,
    #[serde(default)]
    cache_creation_input_tokens: u32,
    #[serde(default)]
    cache_read_input_tokens: u32,
}

fn parse_response(stdout: &str, stderr: &str) -> Result<LlmResponse, LlmError> {
    let line = find_result_line(stdout).ok_or_else(|| {
        LlmError::Other(anyhow::anyhow!(
            "claude-cli: no `result` event in stdout (stderr: {})",
            truncate(stderr, 512)
        ))
    })?;

    let event: ResultEvent = serde_json::from_str(line).map_err(|e| {
        LlmError::Other(anyhow::anyhow!(
            "claude-cli: failed to parse `result` event: {e}; line={}",
            truncate(line, 512)
        ))
    })?;

    if event.is_error {
        let subtype = event.subtype.as_deref().unwrap_or("unknown");
        // Surface rate-limit / overage signals through the typed error so the
        // retry policy in `agent_loop::retry` can back off correctly.
        if subtype.contains("rate") || subtype.contains("overage") {
            return Err(LlmError::RateLimited {
                retry_after_ms: None,
            });
        }
        return Err(LlmError::ApiError {
            status: 500,
            message: format!("claude-cli result error ({subtype}): {}", event.result),
        });
    }

    let (clean_text, tool_calls) = extract_tool_calls(&event.result);

    let stop_reason = if !tool_calls.is_empty() {
        StopReason::ToolUse
    } else {
        match event.stop_reason.as_deref() {
            Some("end_turn") | None => StopReason::EndTurn,
            Some("tool_use") => StopReason::ToolUse,
            Some("max_tokens") => StopReason::MaxTokens,
            Some(other) => StopReason::Other(other.to_string()),
        }
    };

    let usage = event.usage.unwrap_or_default();
    let usage = TokenUsage {
        input_tokens: usage.input_tokens,
        output_tokens: usage.output_tokens,
        cache_creation_input_tokens: usage.cache_creation_input_tokens,
        cache_read_input_tokens: usage.cache_read_input_tokens,
    };

    debug!(
        input_tokens = usage.input_tokens,
        output_tokens = usage.output_tokens,
        cache_read = usage.cache_read_input_tokens,
        tool_calls = tool_calls.len(),
        stop = ?stop_reason,
        "claude-cli response"
    );

    Ok(LlmResponse {
        content: clean_text,
        tool_calls,
        stop_reason,
        usage,
    })
}

/// Build the single prompt string sent to `claude -p`. The CLI sees one user
/// turn that bundles the system prompt, an XML tool spec, and the full prior
/// conversation rendered as labeled sections — there is no native message
/// history channel in non-interactive mode without `--resume`, and this
/// provider is intentionally stateless per call.
fn build_prompt(req: &LlmRequest) -> String {
    let mut s = String::with_capacity(512);

    if let Some(sys) = req.system.as_deref() {
        if !sys.is_empty() {
            s.push_str(sys);
            s.push_str("\n\n");
        }
    }

    if !req.tools.is_empty() {
        render_tool_spec(&mut s, &req.tools);
    }

    let body: Vec<&ChatMessage> = req
        .messages
        .iter()
        .filter(|m| m.role != Role::System)
        .collect();
    if !body.is_empty() {
        s.push_str("# Conversation so far\n\n");
        for m in body {
            render_message(&mut s, m);
        }
        s.push_str("# Your turn\n");
        s.push_str(
            "Respond to the latest USER message above. If you need a tool, emit one or more \
             `<tool_call>` blocks exactly as specified and stop — do not narrate after them.\n",
        );
    }

    s
}

fn render_tool_spec(buf: &mut String, tools: &[ToolDefinition]) {
    buf.push_str("# Tool-call protocol\n\n");
    buf.push_str(
        "You have no built-in tools. To invoke a tool, emit a `<tool_call>` block with this exact \
         shape on its own line, then stop generating:\n\n",
    );
    buf.push_str(
        "    <tool_call name=\"TOOL_NAME\" id=\"call_<unique>\">{\"arg\":\"value\"}</tool_call>\n\n",
    );
    buf.push_str(
        "Emit one block per tool call (multiple blocks allowed in a single reply). The body \
         between the tags MUST be a single JSON object matching the tool's input schema. The \
         runtime will execute each call and feed results back as `<tool_result id=\"...\">...\
         </tool_result>` sections in the next turn.\n\n",
    );
    buf.push_str("## Available tools\n\n");
    for t in tools {
        buf.push_str("### ");
        buf.push_str(&t.name);
        buf.push_str("\n\n");
        if !t.description.is_empty() {
            buf.push_str(&t.description);
            buf.push_str("\n\n");
        }
        buf.push_str("Input schema:\n```json\n");
        let schema =
            serde_json::to_string_pretty(&t.input_schema).unwrap_or_else(|_| "{}".to_string());
        buf.push_str(&schema);
        buf.push_str("\n```\n\n");
    }
}

fn render_message(buf: &mut String, m: &ChatMessage) {
    let label = match m.role {
        Role::User => "USER",
        Role::Assistant => "ASSISTANT",
        Role::Tool => "TOOL",
        Role::System => return,
    };
    buf.push_str("## ");
    buf.push_str(label);
    buf.push('\n');

    if let Some(text) = m.content.as_deref() {
        if !text.is_empty() {
            buf.push_str(text);
            buf.push('\n');
        }
    }

    if let Some(parts) = m.parts.as_deref() {
        for part in parts {
            match part {
                ContentPart::Text { text } => {
                    if !text.is_empty() {
                        buf.push_str(text);
                        buf.push('\n');
                    }
                }
                ContentPart::ToolUse { id, name, input } => {
                    let args = serde_json::to_string(input).unwrap_or_else(|_| "{}".to_string());
                    buf.push_str(&format!(
                        "<tool_call name=\"{}\" id=\"{}\">{}</tool_call>\n",
                        xml_escape_attr(name),
                        xml_escape_attr(id),
                        args,
                    ));
                }
                ContentPart::ToolResult {
                    tool_use_id,
                    content,
                } => {
                    buf.push_str(&format!(
                        "<tool_result id=\"{}\">\n{}\n</tool_result>\n",
                        xml_escape_attr(tool_use_id),
                        content,
                    ));
                }
            }
        }
    }
    buf.push('\n');
}

fn xml_escape_attr(s: &str) -> String {
    s.replace('&', "&amp;").replace('"', "&quot;")
}

/// Extract `<tool_call name="..." id="...">{json}</tool_call>` blocks from the
/// model's response text. Returns the text with those blocks stripped plus the
/// parsed [`ToolCall`]s. Malformed JSON arguments fall through as
/// [`serde_json::Value::Null`] rather than dropping the call — the agent loop
/// will surface a tool error and the model can self-correct.
fn extract_tool_calls(text: &str) -> (String, Vec<ToolCall>) {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r#"(?s)<tool_call\s+name\s*=\s*"([^"]+)"\s+id\s*=\s*"([^"]+)"\s*>(.*?)</tool_call>"#,
        )
        .expect("tool_call regex compiles")
    });

    let mut tool_calls = Vec::new();
    let stripped = re.replace_all(text, |caps: &regex::Captures<'_>| {
        let name = caps[1].to_string();
        let id = caps[2].to_string();
        let body = caps[3].trim();
        let arguments: serde_json::Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(e) => {
                warn!(name = %name, error = %e, body = %truncate(body, 256),
                    "claude-cli: tool_call body is not valid JSON; passing Null");
                serde_json::Value::Null
            }
        };
        tool_calls.push(ToolCall {
            id,
            name,
            arguments,
        });
        String::new()
    });

    (stripped.trim().to_string(), tool_calls)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut out = s[..max].to_string();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{ChatMessage, LlmRequest, Role, ToolDefinition};

    fn schema_obj() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": { "target": { "type": "string" } },
            "required": ["target"],
        })
    }

    #[test]
    fn prompt_includes_system_tools_and_history() {
        let mut req = LlmRequest::new("haiku");
        req.system = Some("you are a recon agent.".to_string());
        req.tools.push(ToolDefinition {
            name: "nmap_scan".into(),
            description: "Run nmap.".into(),
            input_schema: schema_obj(),
        });
        req.messages
            .push(ChatMessage::text(Role::User, "scan 192.168.58.10"));
        req.messages.push(ChatMessage::assistant_tool_use(
            Some("Scanning.".into()),
            vec![ToolCall {
                id: "call_1".into(),
                name: "nmap_scan".into(),
                arguments: serde_json::json!({"target": "192.168.58.10"}),
            }],
        ));
        req.messages
            .push(ChatMessage::tool_result("call_1", "1 host up"));

        let prompt = build_prompt(&req);
        assert!(prompt.starts_with("you are a recon agent."));
        assert!(prompt.contains("# Tool-call protocol"));
        assert!(prompt.contains("### nmap_scan"));
        assert!(prompt.contains("\"target\""));
        assert!(prompt.contains("## USER\nscan 192.168.58.10"));
        assert!(prompt.contains("<tool_call name=\"nmap_scan\" id=\"call_1\">"));
        assert!(prompt.contains("<tool_result id=\"call_1\">"));
        assert!(prompt.contains("# Your turn"));
    }

    #[test]
    fn prompt_without_tools_omits_protocol_section() {
        let mut req = LlmRequest::new("sonnet");
        req.system = Some("hi".into());
        req.messages
            .push(ChatMessage::text(Role::User, "what's up?"));
        let p = build_prompt(&req);
        assert!(!p.contains("# Tool-call protocol"));
        assert!(p.contains("## USER"));
    }

    #[test]
    fn extract_single_tool_call_strips_block_and_parses_args() {
        let text = "I'll scan.\n\
            <tool_call name=\"nmap_scan\" id=\"call_1\">{\"target\":\"192.168.58.10\"}</tool_call>\n";
        let (clean, calls) = extract_tool_calls(text);
        assert_eq!(clean, "I'll scan.");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "nmap_scan");
        assert_eq!(calls[0].id, "call_1");
        assert_eq!(calls[0].arguments["target"], "192.168.58.10");
    }

    #[test]
    fn extract_multiple_tool_calls() {
        let text = "doing two things\n\
            <tool_call name=\"a\" id=\"c1\">{\"x\":1}</tool_call>\n\
            <tool_call name=\"b\" id=\"c2\">{\"y\":2}</tool_call>";
        let (_, calls) = extract_tool_calls(text);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].name, "a");
        assert_eq!(calls[1].id, "c2");
    }

    #[test]
    fn extract_tool_call_with_malformed_json_yields_null_args() {
        let text = "<tool_call name=\"a\" id=\"c1\">{not json}</tool_call>";
        let (_, calls) = extract_tool_calls(text);
        assert_eq!(calls.len(), 1);
        assert!(calls[0].arguments.is_null());
    }

    #[test]
    fn extract_no_tool_calls_returns_text_unchanged() {
        let text = "Just a plain answer.";
        let (clean, calls) = extract_tool_calls(text);
        assert_eq!(clean, "Just a plain answer.");
        assert!(calls.is_empty());
    }

    #[test]
    fn parse_response_success() {
        let stdout = "\
{\"type\":\"system\",\"subtype\":\"init\"}
{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"result\":\"ok\",\"stop_reason\":\"end_turn\",\"usage\":{\"input_tokens\":10,\"output_tokens\":3,\"cache_read_input_tokens\":42,\"cache_creation_input_tokens\":7}}
";
        let resp = parse_response(stdout, "").expect("parse ok");
        assert_eq!(resp.content, "ok");
        assert_eq!(resp.stop_reason, StopReason::EndTurn);
        assert_eq!(resp.usage.input_tokens, 10);
        assert_eq!(resp.usage.output_tokens, 3);
        assert_eq!(resp.usage.cache_read_input_tokens, 42);
        assert_eq!(resp.usage.cache_creation_input_tokens, 7);
        assert!(resp.tool_calls.is_empty());
    }

    #[test]
    fn parse_response_extracts_tool_call_and_sets_stop_reason() {
        let stdout = "\
{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"result\":\"<tool_call name=\\\"nmap_scan\\\" id=\\\"c1\\\">{\\\"target\\\":\\\"x\\\"}</tool_call>\",\"stop_reason\":\"end_turn\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}
";
        let resp = parse_response(stdout, "").expect("parse ok");
        assert_eq!(resp.stop_reason, StopReason::ToolUse);
        assert_eq!(resp.tool_calls.len(), 1);
        assert_eq!(resp.tool_calls[0].name, "nmap_scan");
    }

    #[test]
    fn parse_response_is_error_becomes_api_error() {
        let stdout = "\
{\"type\":\"result\",\"subtype\":\"error_during_execution\",\"is_error\":true,\"result\":\"boom\",\"stop_reason\":\"error\"}
";
        let err = parse_response(stdout, "").unwrap_err();
        assert!(matches!(err, LlmError::ApiError { .. }));
    }

    #[test]
    fn parse_response_rate_limit_subtype_becomes_rate_limited() {
        let stdout = "\
{\"type\":\"result\",\"subtype\":\"rate_limited\",\"is_error\":true,\"result\":\"5h limit hit\"}
";
        let err = parse_response(stdout, "").unwrap_err();
        assert!(matches!(err, LlmError::RateLimited { .. }));
    }

    #[test]
    fn parse_response_missing_result_event_errors() {
        let stdout = "{\"type\":\"system\",\"subtype\":\"init\"}\n";
        let err = parse_response(stdout, "stderr blob").unwrap_err();
        assert!(matches!(err, LlmError::Other(_)));
    }

    #[test]
    fn find_result_line_picks_last_result() {
        let s = "\
{\"type\":\"system\"}
{\"type\":\"result\",\"subtype\":\"success\",\"result\":\"first\"}
{\"type\":\"result\",\"subtype\":\"success\",\"result\":\"second\"}
";
        let line = find_result_line(s).unwrap();
        assert!(line.contains("second"));
    }

    #[test]
    fn classify_exit_detects_login_failure() {
        let err = classify_exit(Some(1), "You are not logged in. Run claude login.");
        assert!(matches!(err, LlmError::AuthError(_)));
    }

    #[test]
    fn xml_escape_attr_quotes_and_amps() {
        assert_eq!(xml_escape_attr(r#"a"b&c"#), "a&quot;b&amp;c");
    }

    #[test]
    fn truncate_short_and_long() {
        assert_eq!(truncate("hi", 10), "hi");
        let long: String = "x".repeat(20);
        let t = truncate(&long, 5);
        assert!(t.starts_with("xxxxx"));
        assert!(t.ends_with('…'));
    }

    #[test]
    fn provider_name_is_claude_cli() {
        let p = ClaudeCliProvider::with_binary("claude");
        assert_eq!(p.name(), "claude-cli");
    }
}
