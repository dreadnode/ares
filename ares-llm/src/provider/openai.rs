//! OpenAI Chat Completions API provider.
//!
//! Implements the `LlmProvider` trait for the OpenAI Chat Completions API.
//! See: <https://platform.openai.com/docs/api-reference/chat>

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use super::{
    ChatMessage, ContentPart, LlmError, LlmProvider, LlmRequest, LlmResponse, Role, StopReason,
    TokenUsage, ToolCall,
};

const DEFAULT_API_URL: &str = "https://api.openai.com/v1/chat/completions";

const DEFAULT_REASONING_HEADROOM_TOKENS: u32 = 25_000;

pub struct OpenAiProvider {
    api_key: String,
    base_url: String,
    client: reqwest::Client,
}

impl OpenAiProvider {
    pub fn new(api_key: String, base_url: Option<String>) -> Self {
        Self {
            api_key,
            base_url: base_url.unwrap_or_else(|| DEFAULT_API_URL.to_string()),
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
    messages: Vec<ApiMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_completion_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<ApiTool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    /// OpenAI's seed parameter for best-effort deterministic sampling.
    /// See <https://platform.openai.com/docs/api-reference/chat/create#chat-create-seed>.
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<u64>,
    /// Reasoning effort, sent only to reasoning models — a non-reasoning model
    /// rejects the parameter outright.
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning_effort: Option<String>,
}

#[derive(Serialize)]
struct ApiMessage {
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<ApiContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<ApiToolCall>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum ApiContent {
    Text(String),
}

#[derive(Serialize)]
struct ApiToolCall {
    id: String,
    #[serde(rename = "type")]
    call_type: String,
    function: ApiFunction,
}

#[derive(Serialize)]
struct ApiFunction {
    name: String,
    arguments: String,
}

#[derive(Serialize)]
struct ApiTool {
    #[serde(rename = "type")]
    tool_type: String,
    function: ApiToolFunction,
}

#[derive(Serialize)]
struct ApiToolFunction {
    name: String,
    description: String,
    parameters: serde_json::Value,
}

#[derive(Deserialize)]
struct ApiResponse {
    choices: Vec<ApiChoice>,
    usage: Option<ApiUsage>,
}

#[derive(Deserialize)]
struct ApiChoice {
    message: ApiResponseMessage,
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct ApiResponseMessage {
    content: Option<String>,
    tool_calls: Option<Vec<ApiResponseToolCall>>,
}

#[derive(Deserialize)]
struct ApiResponseToolCall {
    id: String,
    function: ApiResponseFunction,
}

#[derive(Deserialize)]
struct ApiResponseFunction {
    name: String,
    arguments: String,
}

#[derive(Deserialize)]
struct ApiUsage {
    prompt_tokens: u32,
    completion_tokens: u32,
    #[serde(default)]
    prompt_tokens_details: Option<PromptTokensDetails>,
    #[serde(default)]
    completion_tokens_details: Option<CompletionTokensDetails>,
}

#[derive(Deserialize, Default)]
struct PromptTokensDetails {
    #[serde(default)]
    cached_tokens: u32,
}

#[derive(Deserialize, Default)]
struct CompletionTokensDetails {
    #[serde(default)]
    reasoning_tokens: u32,
}

#[derive(Deserialize)]
struct ApiErrorResponse {
    error: ApiErrorDetail,
}

#[derive(Deserialize)]
struct ApiErrorDetail {
    message: String,
    #[serde(rename = "type")]
    error_type: Option<String>,
}

fn convert_message(msg: &ChatMessage) -> ApiMessage {
    let role = match msg.role {
        Role::System => "system",
        Role::User => "user",
        Role::Assistant => "assistant",
        Role::Tool => "tool",
    };

    if msg.role == Role::Tool || msg.role == Role::User {
        if let Some(ref parts) = msg.parts {
            for part in parts {
                if let ContentPart::ToolResult {
                    tool_use_id,
                    content,
                } = part
                {
                    return ApiMessage {
                        role: "tool".to_string(),
                        content: Some(ApiContent::Text(content.clone())),
                        tool_calls: None,
                        tool_call_id: Some(tool_use_id.clone()),
                    };
                }
            }
        }
    }

    if msg.role == Role::Assistant {
        if let Some(ref parts) = msg.parts {
            let mut text_parts = Vec::new();
            let mut tool_calls = Vec::new();

            for part in parts {
                match part {
                    ContentPart::Text { text } => text_parts.push(text.clone()),
                    ContentPart::ToolUse { id, name, input } => {
                        tool_calls.push(ApiToolCall {
                            id: id.clone(),
                            call_type: "function".to_string(),
                            function: ApiFunction {
                                name: name.clone(),
                                arguments: serde_json::to_string(input).unwrap_or_default(),
                            },
                        });
                    }
                    _ => {}
                }
            }

            let content = if text_parts.is_empty() {
                None
            } else {
                Some(ApiContent::Text(text_parts.join("")))
            };

            let tool_calls = if tool_calls.is_empty() {
                None
            } else {
                Some(tool_calls)
            };

            return ApiMessage {
                role: role.to_string(),
                content,
                tool_calls,
                tool_call_id: None,
            };
        }
    }

    ApiMessage {
        role: role.to_string(),
        content: Some(ApiContent::Text(msg.content.clone().unwrap_or_default())),
        tool_calls: None,
        tool_call_id: None,
    }
}

fn convert_tools(tools: &[super::ToolDefinition]) -> Vec<ApiTool> {
    tools
        .iter()
        .map(|t| ApiTool {
            tool_type: "function".to_string(),
            function: ApiToolFunction {
                name: t.name.clone(),
                description: t.description.clone(),
                parameters: t.input_schema.clone(),
            },
        })
        .collect()
}

fn parse_stop_reason(reason: Option<&str>) -> StopReason {
    match reason {
        Some("stop") => StopReason::EndTurn,
        Some("tool_calls") => StopReason::ToolUse,
        Some("length") => StopReason::MaxTokens,
        Some(other) => StopReason::Other(other.to_string()),
        None => StopReason::EndTurn,
    }
}

fn uses_max_completion_tokens(model: &str) -> bool {
    let model = model.strip_prefix("openai/").unwrap_or(model);
    model.starts_with("gpt-5")
}

/// Only the reasoning models accept `reasoning_effort`; sending it to a
/// non-reasoning model is a 400 on every call the role makes.
fn supports_reasoning_effort(model: &str) -> bool {
    let model = model.strip_prefix("openai/").unwrap_or(model);
    model.starts_with("gpt-5")
}

fn reasoning_headroom_tokens() -> u32 {
    std::env::var("ARES_OPENAI_REASONING_HEADROOM_TOKENS")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(DEFAULT_REASONING_HEADROOM_TOKENS)
}

fn completion_token_budget(max_tokens: u32, headroom: u32) -> u32 {
    max_tokens.saturating_add(headroom)
}

#[async_trait::async_trait]
impl LlmProvider for OpenAiProvider {
    async fn chat(&self, request: &LlmRequest) -> Result<LlmResponse, LlmError> {
        let mut messages: Vec<ApiMessage> = Vec::new();

        // System message goes as first message for OpenAI
        if let Some(ref system) = request.system {
            messages.push(ApiMessage {
                role: "system".to_string(),
                content: Some(ApiContent::Text(system.clone())),
                tool_calls: None,
                tool_call_id: None,
            });
        }

        for msg in &request.messages {
            if msg.role == Role::System {
                continue; // Already handled above
            }
            messages.push(convert_message(msg));
        }

        let use_max_completion_tokens = uses_max_completion_tokens(&request.model);
        let completion_budget =
            completion_token_budget(request.max_tokens, reasoning_headroom_tokens());
        let api_request = ApiRequest {
            model: request.model.clone(),
            messages,
            max_tokens: (!use_max_completion_tokens).then_some(request.max_tokens),
            max_completion_tokens: use_max_completion_tokens.then_some(completion_budget),
            tools: convert_tools(&request.tools),
            temperature: request.temperature,
            seed: request.seed,
            reasoning_effort: supports_reasoning_effort(&request.model)
                .then(|| request.reasoning_effort.clone())
                .flatten(),
        };

        info!(
            model = %request.model,
            msg_count = request.messages.len(),
            tool_count = request.tools.len(),
            max_completion_tokens = ?api_request.max_completion_tokens,
            "OpenAI API request"
        );

        let response = self
            .client
            .post(&self.base_url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&api_request)
            .send()
            .await
            .map_err(|e| LlmError::Network(e.to_string()))?;

        let status = response.status();
        let retry_after_ms = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<f64>().ok())
            .map(|secs| (secs * 1000.0) as u64);
        let body = response
            .text()
            .await
            .map_err(|e| LlmError::Network(e.to_string()))?;

        if !status.is_success() {
            let message = if let Ok(err) = serde_json::from_str::<ApiErrorResponse>(&body) {
                // Check for context length exceeded
                if let Some(ref code) = err.error.error_type {
                    if (code == "context_length_exceeded" || code == "invalid_request_error")
                        && (err.error.message.contains("context length")
                            || err.error.message.contains("maximum context"))
                    {
                        return Err(LlmError::ContextTooLong(err.error.message));
                    }
                }
                err.error.message
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
            LlmError::Other(anyhow::anyhow!("Failed to parse OpenAI response: {e}"))
        })?;

        let choice = api_response
            .choices
            .first()
            .ok_or_else(|| LlmError::Other(anyhow::anyhow!("No choices in OpenAI response")))?;

        let content = choice.message.content.clone().unwrap_or_default();

        let tool_calls: Vec<ToolCall> = choice
            .message
            .tool_calls
            .as_ref()
            .map(|calls| {
                calls
                    .iter()
                    .map(|tc| {
                        let args: serde_json::Value = serde_json::from_str(&tc.function.arguments)
                            .unwrap_or_else(|e| {
                                warn!(
                                    tool = %tc.function.name,
                                    err = %e,
                                    arg_len = tc.function.arguments.len(),
                                    "OpenAI tool call arguments failed to parse"
                                );
                                serde_json::Value::default()
                            });
                        ToolCall {
                            id: tc.id.clone(),
                            name: tc.function.name.clone(),
                            arguments: args,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let reasoning_tokens = api_response
            .usage
            .as_ref()
            .and_then(|u| u.completion_tokens_details.as_ref())
            .map(|d| d.reasoning_tokens)
            .unwrap_or(0);

        let usage = api_response.usage.map_or_else(TokenUsage::default, |u| {
            let cached = u
                .prompt_tokens_details
                .as_ref()
                .map(|d| d.cached_tokens)
                .unwrap_or(0);
            // OpenAI reports prompt_tokens as the full input count and
            // cached_tokens as the cached portion of that count. Subtract
            // so downstream cost math bills cached input at the cached
            // rate and the remainder at the full input rate.
            let uncached_input = u.prompt_tokens.saturating_sub(cached);
            TokenUsage {
                input_tokens: uncached_input,
                output_tokens: u.completion_tokens,
                cache_read_input_tokens: cached,
                ..Default::default()
            }
        });

        let stop_reason = parse_stop_reason(choice.finish_reason.as_deref());

        info!(
            input_tokens = usage.input_tokens,
            cache_read_input_tokens = usage.cache_read_input_tokens,
            output_tokens = usage.output_tokens,
            reasoning_tokens = reasoning_tokens,
            tool_calls = tool_calls.len(),
            stop = ?stop_reason,
            "OpenAI API response"
        );

        if stop_reason == StopReason::MaxTokens {
            warn!(
                model = %request.model,
                max_completion_tokens = ?api_request.max_completion_tokens,
                output_tokens = usage.output_tokens,
                reasoning_tokens = reasoning_tokens,
                content_len = content.len(),
                tool_calls = tool_calls.len(),
                "OpenAI truncated completion at the token ceiling"
            );
        }

        Ok(LlmResponse {
            content,
            tool_calls,
            stop_reason,
            usage,
        })
    }

    fn name(&self) -> &str {
        "openai"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasoning_effort_only_goes_to_reasoning_models() {
        assert!(supports_reasoning_effort("gpt-5"));
        assert!(supports_reasoning_effort("gpt-5.2"));
        assert!(supports_reasoning_effort("openai/gpt-5-mini"));
        assert!(
            !supports_reasoning_effort("gpt-4o"),
            "a non-reasoning model rejects reasoning_effort outright, so it must never be sent"
        );
    }

    #[test]
    fn reasoning_effort_is_omitted_from_the_wire_when_unset() {
        let request = ApiRequest {
            model: "gpt-5".into(),
            messages: Vec::new(),
            max_tokens: None,
            max_completion_tokens: Some(4096),
            tools: Vec::new(),
            temperature: None,
            seed: None,
            reasoning_effort: None,
        };
        let body = serde_json::to_string(&request).unwrap();
        assert!(
            !body.contains("reasoning_effort"),
            "an unset effort must leave the provider default in place, not serialize null"
        );
    }

    #[test]
    fn convert_user_message() {
        let msg = ChatMessage::text(Role::User, "scan the network");
        let api_msg = convert_message(&msg);
        assert_eq!(api_msg.role, "user");
        assert!(api_msg.tool_calls.is_none());
    }

    #[test]
    fn convert_tool_result() {
        let msg = ChatMessage::tool_result("call_1", "scan done");
        let api_msg = convert_message(&msg);
        assert_eq!(api_msg.role, "tool");
        assert_eq!(api_msg.tool_call_id, Some("call_1".to_string()));
    }

    #[test]
    fn parse_openai_stop_reasons() {
        assert_eq!(parse_stop_reason(Some("stop")), StopReason::EndTurn);
        assert_eq!(parse_stop_reason(Some("tool_calls")), StopReason::ToolUse);
        assert_eq!(parse_stop_reason(Some("length")), StopReason::MaxTokens);
    }

    #[test]
    fn deserialize_openai_response() {
        let json = r#"{
            "choices": [{
                "message": {
                    "content": "I will scan the network.",
                    "tool_calls": [{
                        "id": "call_abc",
                        "type": "function",
                        "function": {
                            "name": "nmap_scan",
                            "arguments": "{\"target\":\"192.168.58.0/24\"}"
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50}
        }"#;
        let resp: ApiResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.choices.len(), 1);
        assert_eq!(
            resp.choices[0].message.tool_calls.as_ref().unwrap().len(),
            1
        );
    }

    #[test]
    fn convert_openai_tools() {
        let tools = vec![super::super::ToolDefinition {
            name: "nmap_scan".into(),
            description: "Run nmap".into(),
            input_schema: serde_json::json!({"type": "object"}),
        }];
        let api_tools = convert_tools(&tools);
        assert_eq!(api_tools[0].tool_type, "function");
        assert_eq!(api_tools[0].function.name, "nmap_scan");
    }

    #[test]
    fn parse_usage_with_cached_tokens() {
        let json = r#"{
            "prompt_tokens": 1000,
            "completion_tokens": 50,
            "prompt_tokens_details": {"cached_tokens": 768}
        }"#;
        let usage: ApiUsage = serde_json::from_str(json).unwrap();
        assert_eq!(usage.prompt_tokens, 1000);
        assert_eq!(
            usage.prompt_tokens_details.as_ref().unwrap().cached_tokens,
            768
        );
    }

    #[test]
    fn parse_usage_without_cached_tokens() {
        let json = r#"{"prompt_tokens": 100, "completion_tokens": 50}"#;
        let usage: ApiUsage = serde_json::from_str(json).unwrap();
        assert!(usage.prompt_tokens_details.is_none());
    }

    #[test]
    fn gpt5_uses_max_completion_tokens() {
        assert!(uses_max_completion_tokens("gpt-5.2"));
        assert!(uses_max_completion_tokens("openai/gpt-5.2"));
        assert!(!uses_max_completion_tokens("gpt-4o-mini"));
    }

    #[test]
    fn completion_budget_adds_reasoning_headroom() {
        assert_eq!(
            completion_token_budget(4096, DEFAULT_REASONING_HEADROOM_TOKENS),
            4096 + DEFAULT_REASONING_HEADROOM_TOKENS
        );
        assert_eq!(completion_token_budget(4096, 0), 4096);
    }

    #[test]
    fn completion_budget_saturates_instead_of_overflowing() {
        assert_eq!(completion_token_budget(u32::MAX, 25_000), u32::MAX);
    }

    #[test]
    fn parse_usage_with_reasoning_tokens() {
        let json = r#"{
            "prompt_tokens": 12000,
            "completion_tokens": 4096,
            "completion_tokens_details": {"reasoning_tokens": 4096}
        }"#;
        let usage: ApiUsage = serde_json::from_str(json).unwrap();
        assert_eq!(
            usage
                .completion_tokens_details
                .as_ref()
                .unwrap()
                .reasoning_tokens,
            4096
        );
    }

    #[test]
    fn parse_usage_without_reasoning_tokens() {
        let json = r#"{"prompt_tokens": 100, "completion_tokens": 50}"#;
        let usage: ApiUsage = serde_json::from_str(json).unwrap();
        assert!(usage.completion_tokens_details.is_none());
    }

    #[test]
    fn truncated_reasoning_response_deserializes_as_max_tokens() {
        let json = r#"{
            "choices": [{
                "message": {"content": null, "tool_calls": null},
                "finish_reason": "length"
            }],
            "usage": {
                "prompt_tokens": 18000,
                "completion_tokens": 4096,
                "completion_tokens_details": {"reasoning_tokens": 4096}
            }
        }"#;
        let resp: ApiResponse = serde_json::from_str(json).unwrap();
        let choice = &resp.choices[0];
        assert_eq!(
            parse_stop_reason(choice.finish_reason.as_deref()),
            StopReason::MaxTokens
        );
        assert!(choice.message.content.is_none());
        assert!(choice.message.tool_calls.is_none());
    }
}
