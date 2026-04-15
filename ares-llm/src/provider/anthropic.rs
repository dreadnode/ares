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

// ---------------------------------------------------------------------------
// Anthropic API types (request)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ApiRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<ApiMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
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
struct ApiTool {
    name: String,
    description: String,
    input_schema: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Anthropic API types (response)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

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

fn convert_tools(tools: &[super::ToolDefinition]) -> Vec<ApiTool> {
    tools
        .iter()
        .map(|t| ApiTool {
            name: t.name.clone(),
            description: t.description.clone(),
            input_schema: t.input_schema.clone(),
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

// ---------------------------------------------------------------------------
// LlmProvider implementation
// ---------------------------------------------------------------------------

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
            system: request.system.clone(),
            tools: convert_tools(&request.tools),
            temperature: request.temperature,
        };

        debug!(
            model = %request.model,
            msg_count = request.messages.len(),
            tool_count = request.tools.len(),
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_simple_message() {
        let msg = ChatMessage::text(Role::User, "hello");
        let api_msg = convert_message(&msg);
        assert_eq!(api_msg.role, "user");
        match api_msg.content {
            ApiContent::Text(t) => assert_eq!(t, "hello"),
            _ => panic!("Expected text content"),
        }
    }

    #[test]
    fn test_convert_tool_result_message() {
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
    fn test_parse_stop_reasons() {
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
    fn test_convert_tools() {
        let tools = vec![super::super::ToolDefinition {
            name: "nmap_scan".into(),
            description: "Run nmap".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": ["target"]
            }),
        }];
        let api_tools = convert_tools(&tools);
        assert_eq!(api_tools.len(), 1);
        assert_eq!(api_tools[0].name, "nmap_scan");
    }

    #[test]
    fn test_deserialize_response() {
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
    fn test_serialize_api_request() {
        let req = ApiRequest {
            model: "claude-sonnet-4-20250514".to_string(),
            max_tokens: 4096,
            messages: vec![ApiMessage {
                role: "user".to_string(),
                content: ApiContent::Text("hello".to_string()),
            }],
            system: Some("You are a recon agent.".to_string()),
            tools: vec![],
            temperature: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["model"], "claude-sonnet-4-20250514");
        assert_eq!(json["system"], "You are a recon agent.");
        assert!(json.get("tools").is_none()); // empty vec skipped
    }
}
