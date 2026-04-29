//! Anthropic Messages API provider.
//!
//! Implements the `LlmProvider` trait for the Anthropic Messages API.
//! See: <https://docs.anthropic.com/en/api/messages>

use serde::{Deserialize, Serialize};
use tracing::debug;

use super::{
    ChatMessage, ContentPart, LlmError, LlmProvider, LlmRequest, LlmResponse, Role, StopReason,
    TokenUsage, ToolCall,
};

const API_URL: &str = "https://api.anthropic.com/v1/messages";
const API_VERSION: &str = "2023-06-01";

pub struct AnthropicProvider {
    api_key: String,
    client: reqwest::Client,
}

impl AnthropicProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(300))
                .connect_timeout(std::time::Duration::from_secs(15))
                .build()
                .expect("failed to build reqwest client"),
        }
    }
}

#[derive(Serialize)]
struct ApiRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<ApiMessage>,
    /// `system` is sent as an array of typed blocks when caching is enabled
    /// (so we can attach `cache_control` to the trailing block) and as a
    /// plain string otherwise. We always emit blocks for consistency — the
    /// API accepts both forms but blocks are required for cache breakpoints.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    system: Vec<ApiSystemBlock>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<ApiTool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
}

#[derive(Serialize)]
struct ApiMessage {
    role: String,
    content: ApiContent,
}

#[derive(Serialize)]
#[serde(untagged)]
enum ApiContent {
    Text(String),
    Parts(Vec<ApiContentBlock>),
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum ApiContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    #[serde(rename = "tool_result")]
    ToolResult {
        tool_use_id: String,
        content: String,
    },
}

#[derive(Serialize)]
struct ApiSystemBlock {
    #[serde(rename = "type")]
    block_type: &'static str,
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_control: Option<ApiCacheControl>,
}

#[derive(Serialize)]
struct ApiTool {
    name: String,
    description: String,
    input_schema: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_control: Option<ApiCacheControl>,
}

#[derive(Serialize, Clone, Copy)]
struct ApiCacheControl {
    #[serde(rename = "type")]
    cc_type: &'static str,
}

impl ApiCacheControl {
    const fn ephemeral() -> Self {
        Self {
            cc_type: "ephemeral",
        }
    }
}

#[derive(Deserialize)]
struct ApiResponse {
    content: Vec<ApiResponseBlock>,
    stop_reason: Option<String>,
    usage: Option<ApiUsage>,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum ApiResponseBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
}

#[derive(Deserialize)]
struct ApiUsage {
    input_tokens: u32,
    output_tokens: u32,
    #[serde(default)]
    cache_creation_input_tokens: u32,
    #[serde(default)]
    cache_read_input_tokens: u32,
}

#[derive(Deserialize)]
struct ApiError {
    error: ApiErrorDetail,
}

#[derive(Deserialize)]
struct ApiErrorDetail {
    #[serde(rename = "type")]
    error_type: String,
    message: String,
}

fn convert_message(msg: &ChatMessage) -> ApiMessage {
    let role = match msg.role {
        Role::User | Role::Tool => "user",
        Role::Assistant => "assistant",
        Role::System => "user", // system messages go in the system field, not here
    };

    let content = if let Some(ref parts) = msg.parts {
        let blocks: Vec<ApiContentBlock> = parts
            .iter()
            .map(|p| match p {
                ContentPart::Text { text } => ApiContentBlock::Text { text: text.clone() },
                ContentPart::ToolResult {
                    tool_use_id,
                    content,
                } => ApiContentBlock::ToolResult {
                    tool_use_id: tool_use_id.clone(),
                    content: content.clone(),
                },
                ContentPart::ToolUse { id, name, input } => ApiContentBlock::ToolUse {
                    id: id.clone(),
                    name: name.clone(),
                    input: input.clone(),
                },
            })
            .collect();
        ApiContent::Parts(blocks)
    } else {
        ApiContent::Text(msg.content.clone().unwrap_or_default())
    };

    ApiMessage {
        role: role.to_string(),
        content,
    }
}

/// Build the system blocks for the request, attaching a single ephemeral
/// cache breakpoint to the final block when caching is enabled. The system
/// prompt is the longest stable prefix in our agent loops, so this is the
/// highest-leverage cache hit.
fn build_system_blocks(system: Option<&str>, cache: bool) -> Vec<ApiSystemBlock> {
    let Some(text) = system else {
        return Vec::new();
    };
    if text.is_empty() {
        return Vec::new();
    }
    vec![ApiSystemBlock {
        block_type: "text",
        text: text.to_string(),
        cache_control: cache.then(ApiCacheControl::ephemeral),
    }]
}

/// Convert tool definitions, attaching a cache breakpoint to the *last*
/// tool when caching is enabled. A breakpoint at the tail of the tools
/// array caches the entire stable prefix (system + tools); subsequent
/// requests with the same definitions read from cache.
fn convert_tools(tools: &[super::ToolDefinition], cache: bool) -> Vec<ApiTool> {
    let last_idx = tools.len().checked_sub(1);
    tools
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let cc = if cache && Some(i) == last_idx {
                Some(ApiCacheControl::ephemeral())
            } else {
                None
            };
            ApiTool {
                name: t.name.clone(),
                description: t.description.clone(),
                input_schema: t.input_schema.clone(),
                cache_control: cc,
            }
        })
        .collect()
}

fn parse_stop_reason(reason: Option<&str>) -> StopReason {
    match reason {
        Some("end_turn") => StopReason::EndTurn,
        Some("tool_use") => StopReason::ToolUse,
        Some("max_tokens") => StopReason::MaxTokens,
        Some(other) => StopReason::Other(other.to_string()),
        None => StopReason::EndTurn,
    }
}

#[async_trait::async_trait]
impl LlmProvider for AnthropicProvider {
    async fn chat(&self, request: &LlmRequest) -> Result<LlmResponse, LlmError> {
        let messages: Vec<ApiMessage> = request
            .messages
            .iter()
            .filter(|m| m.role != Role::System)
            .map(convert_message)
            .collect();

        let api_request = ApiRequest {
            model: request.model.clone(),
            max_tokens: request.max_tokens,
            messages,
            system: build_system_blocks(request.system.as_deref(), request.enable_prompt_cache),
            tools: convert_tools(&request.tools, request.enable_prompt_cache),
            temperature: request.temperature,
        };

        debug!(
            model = %request.model,
            msg_count = request.messages.len(),
            tool_count = request.tools.len(),
            cache = request.enable_prompt_cache,
            "Anthropic API request"
        );

        let response = self
            .client
            .post(API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", API_VERSION)
            .header("content-type", "application/json")
            .json(&api_request)
            .send()
            .await
            .map_err(|e| LlmError::Network(e.to_string()))?;

        let status = response.status();
        let retry_after_ms = parse_retry_after(response.headers());
        let body = response
            .text()
            .await
            .map_err(|e| LlmError::Network(e.to_string()))?;

        if !status.is_success() {
            let message = if let Ok(err) = serde_json::from_str::<ApiError>(&body) {
                let msg = format!("{} — {}", err.error.error_type, err.error.message);
                // Classify by error type
                if err.error.error_type == "request_too_large" {
                    return Err(LlmError::ContextTooLong(msg));
                }
                msg
            } else {
                body
            };

            return Err(match status.as_u16() {
                429 => LlmError::RateLimited { retry_after_ms },
                401 => LlmError::AuthError(message),
                _ => LlmError::ApiError {
                    status: status.as_u16(),
                    message,
                },
            });
        }

        let api_response: ApiResponse = serde_json::from_str(&body).map_err(|e| {
            LlmError::Other(anyhow::anyhow!("Failed to parse Anthropic response: {e}"))
        })?;

        // Extract text and tool calls from response blocks
        let mut text_parts = Vec::new();
        let mut tool_calls = Vec::new();

        for block in &api_response.content {
            match block {
                ApiResponseBlock::Text { text } => {
                    text_parts.push(text.clone());
                }
                ApiResponseBlock::ToolUse { id, name, input } => {
                    tool_calls.push(ToolCall {
                        id: id.clone(),
                        name: name.clone(),
                        arguments: input.clone(),
                    });
                }
            }
        }

        let usage = api_response
            .usage
            .map_or_else(TokenUsage::default, |u| TokenUsage {
                input_tokens: u.input_tokens,
                output_tokens: u.output_tokens,
                cache_creation_input_tokens: u.cache_creation_input_tokens,
                cache_read_input_tokens: u.cache_read_input_tokens,
            });

        let stop_reason = parse_stop_reason(api_response.stop_reason.as_deref());

        debug!(
            input_tokens = usage.input_tokens,
            output_tokens = usage.output_tokens,
            cache_creation = usage.cache_creation_input_tokens,
            cache_read = usage.cache_read_input_tokens,
            tool_calls = tool_calls.len(),
            stop = ?stop_reason,
            "Anthropic API response"
        );

        Ok(LlmResponse {
            content: text_parts.join(""),
            tool_calls,
            stop_reason,
            usage,
        })
    }

    fn name(&self) -> &str {
        "anthropic"
    }
}

/// Parse the `retry-after` header value to milliseconds.
fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<f64>().ok())
        .map(|secs| (secs * 1000.0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_simple_message() {
        let msg = ChatMessage::text(Role::User, "hello");
        let api_msg = convert_message(&msg);
        assert_eq!(api_msg.role, "user");
        match api_msg.content {
            ApiContent::Text(t) => assert_eq!(t, "hello"),
            _ => panic!("Expected text content"),
        }
    }

    #[test]
    fn convert_tool_result_message() {
        let msg = ChatMessage::tool_result("call_1", "scan complete");
        let api_msg = convert_message(&msg);
        assert_eq!(api_msg.role, "user");
        match api_msg.content {
            ApiContent::Parts(parts) => {
                assert_eq!(parts.len(), 1);
            }
            _ => panic!("Expected parts content"),
        }
    }

    #[test]
    fn parse_stop_reasons() {
        assert_eq!(parse_stop_reason(Some("end_turn")), StopReason::EndTurn);
        assert_eq!(parse_stop_reason(Some("tool_use")), StopReason::ToolUse);
        assert_eq!(parse_stop_reason(Some("max_tokens")), StopReason::MaxTokens);
        assert_eq!(
            parse_stop_reason(Some("foo")),
            StopReason::Other("foo".to_string())
        );
        assert_eq!(parse_stop_reason(None), StopReason::EndTurn);
    }

    #[test]
    fn converts_tools_no_cache() {
        let tools = vec![super::super::ToolDefinition {
            name: "nmap_scan".into(),
            description: "Run nmap".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"]
            }),
        }];
        let api_tools = convert_tools(&tools, false);
        assert_eq!(api_tools.len(), 1);
        assert_eq!(api_tools[0].name, "nmap_scan");
        // No cache_control when caching disabled.
        let json = serde_json::to_value(&api_tools[0]).unwrap();
        assert!(json.get("cache_control").is_none());
    }

    #[test]
    fn converts_tools_cache_breakpoint_on_last() {
        let tools = vec![
            super::super::ToolDefinition {
                name: "tool_a".into(),
                description: "first".into(),
                input_schema: serde_json::json!({}),
            },
            super::super::ToolDefinition {
                name: "tool_b".into(),
                description: "second".into(),
                input_schema: serde_json::json!({}),
            },
        ];
        let api_tools = convert_tools(&tools, true);
        let first = serde_json::to_value(&api_tools[0]).unwrap();
        let last = serde_json::to_value(&api_tools[1]).unwrap();
        assert!(first.get("cache_control").is_none());
        assert_eq!(last["cache_control"]["type"], "ephemeral");
    }

    #[test]
    fn build_system_blocks_with_cache() {
        let blocks = build_system_blocks(Some("you are a recon agent"), true);
        assert_eq!(blocks.len(), 1);
        let json = serde_json::to_value(&blocks[0]).unwrap();
        assert_eq!(json["type"], "text");
        assert_eq!(json["cache_control"]["type"], "ephemeral");
    }

    #[test]
    fn build_system_blocks_without_cache() {
        let blocks = build_system_blocks(Some("hello"), false);
        let json = serde_json::to_value(&blocks[0]).unwrap();
        assert!(json.get("cache_control").is_none());
    }

    #[test]
    fn build_system_blocks_empty() {
        assert!(build_system_blocks(None, true).is_empty());
        assert!(build_system_blocks(Some(""), true).is_empty());
    }

    #[test]
    fn deserialize_response() {
        let json = r#"{
            "content": [
                {"type": "text", "text": "I'll scan the network."},
                {"type": "tool_use", "id": "call_1", "name": "nmap_scan", "input": {"target": "192.168.58.0/24"}}
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 100, "output_tokens": 50}
        }"#;
        let resp: ApiResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.content.len(), 2);
        assert_eq!(resp.stop_reason.as_deref(), Some("tool_use"));
    }

    #[test]
    fn serialize_api_request_with_cache() {
        let req = ApiRequest {
            model: "claude-sonnet-4-20250514".to_string(),
            max_tokens: 4096,
            messages: vec![ApiMessage {
                role: "user".to_string(),
                content: ApiContent::Text("hello".to_string()),
            }],
            system: build_system_blocks(Some("You are a recon agent."), true),
            tools: vec![],
            temperature: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["model"], "claude-sonnet-4-20250514");
        assert!(json["system"].is_array());
        assert_eq!(json["system"][0]["text"], "You are a recon agent.");
        assert_eq!(json["system"][0]["cache_control"]["type"], "ephemeral");
        assert!(json.get("tools").is_none());
    }

    #[test]
    fn serialize_api_request_no_cache_no_breakpoints() {
        let req = ApiRequest {
            model: "claude-sonnet-4-20250514".to_string(),
            max_tokens: 4096,
            messages: vec![],
            system: build_system_blocks(Some("hi"), false),
            tools: vec![],
            temperature: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(json["system"][0].get("cache_control").is_none());
    }
}
