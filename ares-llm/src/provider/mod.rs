//! Model-agnostic LLM provider trait and shared types.
//!
//! Providers implement `LlmProvider` to support different LLM backends
//! (Anthropic, OpenAI, Ollama) through a unified interface.

pub mod anthropic;
pub mod ollama;
pub mod openai;

use serde::{Deserialize, Serialize};

/// Message role in a conversation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

/// A single part of message content (text or tool result).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ContentPart {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_result")]
    ToolResult {
        tool_use_id: String,
        content: String,
    },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
}

/// A chat message in the conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: Role,
    /// Simple text content (mutually exclusive with `parts`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// Multi-part content (tool results, mixed text+tool_use).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parts: Option<Vec<ContentPart>>,
}

impl ChatMessage {
    /// Create a simple text message.
    pub fn text(role: Role, content: impl Into<String>) -> Self {
        Self {
            role,
            content: Some(content.into()),
            parts: None,
        }
    }

    /// Create a tool result message.
    pub fn tool_result(tool_use_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: Role::User,
            content: None,
            parts: Some(vec![ContentPart::ToolResult {
                tool_use_id: tool_use_id.into(),
                content: content.into(),
            }]),
        }
    }

    /// Create an assistant message with tool use calls.
    pub fn assistant_tool_use(text: Option<String>, tool_calls: Vec<ToolCall>) -> Self {
        let mut parts = Vec::new();
        if let Some(t) = text {
            if !t.is_empty() {
                parts.push(ContentPart::Text { text: t });
            }
        }
        for tc in tool_calls {
            parts.push(ContentPart::ToolUse {
                id: tc.id,
                name: tc.name,
                input: tc.arguments,
            });
        }
        Self {
            role: Role::Assistant,
            content: None,
            parts: Some(parts),
        }
    }

    /// Get text content (from either simple or parts form).
    pub fn text_content(&self) -> Option<&str> {
        if let Some(ref c) = self.content {
            return Some(c);
        }
        if let Some(ref parts) = self.parts {
            for part in parts {
                if let ContentPart::Text { text } = part {
                    return Some(text);
                }
            }
        }
        None
    }
}

/// Tool definition for LLM tool_use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    /// JSON Schema for the tool's input parameters.
    pub input_schema: serde_json::Value,
}

/// A tool call from the LLM response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

/// Why the LLM stopped generating.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StopReason {
    /// Normal end of turn.
    EndTurn,
    /// Model wants to use a tool.
    ToolUse,
    /// Hit max tokens limit.
    MaxTokens,
    /// Other/unknown stop reason.
    Other(String),
}

/// Token usage from the LLM response.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    /// Cache-related tokens (provider-specific).
    #[serde(default)]
    pub cache_creation_input_tokens: u32,
    #[serde(default)]
    pub cache_read_input_tokens: u32,
}

/// Typed error for LLM provider calls, enabling retry classification.
#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    /// Rate limited by the provider — retryable with backoff.
    #[error("rate limited (retry after {retry_after_ms:?}ms)")]
    RateLimited { retry_after_ms: Option<u64> },

    /// Authentication failure — not retryable.
    #[error("authentication failed: {0}")]
    AuthError(String),

    /// Request too large for context window — not retryable as-is.
    #[error("context too long: {0}")]
    ContextTooLong(String),

    /// Network/connection error — retryable.
    #[error("network error: {0}")]
    Network(String),

    /// API returned a non-success status — may or may not be retryable.
    #[error("API error ({status}): {message}")]
    ApiError { status: u16, message: String },

    /// Catch-all for other errors.
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

impl LlmError {
    /// Whether this error is worth retrying with backoff.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            LlmError::RateLimited { .. }
                | LlmError::Network(_)
                | LlmError::ApiError {
                    status: 500..=599,
                    ..
                }
        )
    }

    /// Suggested wait time before retrying, if available.
    pub fn retry_after_ms(&self) -> Option<u64> {
        match self {
            LlmError::RateLimited { retry_after_ms } => *retry_after_ms,
            _ => None,
        }
    }
}

/// A request to the LLM provider.
#[derive(Debug, Clone)]
pub struct LlmRequest {
    pub model: String,
    pub system: Option<String>,
    pub messages: Vec<ChatMessage>,
    pub tools: Vec<ToolDefinition>,
    pub max_tokens: u32,
    pub temperature: Option<f32>,
}

impl LlmRequest {
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            system: None,
            messages: Vec::new(),
            tools: Vec::new(),
            max_tokens: 4096,
            temperature: None,
        }
    }
}

/// A response from the LLM provider.
#[derive(Debug, Clone)]
pub struct LlmResponse {
    /// Text content from the response (may be empty if only tool calls).
    pub content: String,
    /// Tool calls requested by the model.
    pub tool_calls: Vec<ToolCall>,
    /// Why the model stopped.
    pub stop_reason: StopReason,
    /// Token usage.
    pub usage: TokenUsage,
}

// ---------------------------------------------------------------------------
// Provider trait
// ---------------------------------------------------------------------------

/// Model-agnostic LLM provider.
#[async_trait::async_trait]
pub trait LlmProvider: Send + Sync {
    /// Send a chat request and get a response.
    async fn chat(&self, request: &LlmRequest) -> Result<LlmResponse, LlmError>;

    /// Provider name (e.g. "anthropic", "openai", "ollama").
    fn name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Parse a model string like "anthropic/claude-sonnet-4-20250514" and create
/// the appropriate provider + extracted model name.
///
/// Supported prefixes:
/// - `anthropic/` → AnthropicProvider (reads `ANTHROPIC_API_KEY`)
/// - `openai/` → OpenAiProvider (reads `OPENAI_API_KEY`)
/// - `ollama/` → OllamaProvider (reads `OLLAMA_BASE_URL`, default `http://localhost:11434`)
///
/// If no prefix, defaults to Anthropic.
pub fn create_provider(model: &str) -> anyhow::Result<(Box<dyn LlmProvider>, String)> {
    if let Some(model_name) = model.strip_prefix("anthropic/") {
        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .map_err(|_| anyhow::anyhow!("ANTHROPIC_API_KEY not set"))?;
        let provider = anthropic::AnthropicProvider::new(api_key);
        Ok((Box::new(provider), model_name.to_string()))
    } else if let Some(model_name) = model.strip_prefix("openai/") {
        let api_key = std::env::var("OPENAI_API_KEY")
            .map_err(|_| anyhow::anyhow!("OPENAI_API_KEY not set"))?;
        let provider = openai::OpenAiProvider::new(api_key, None);
        Ok((Box::new(provider), model_name.to_string()))
    } else if let Some(model_name) = model.strip_prefix("ollama/") {
        let base_url = std::env::var("OLLAMA_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:11434".to_string());
        let provider = ollama::OllamaProvider::new(base_url);
        Ok((Box::new(provider), model_name.to_string()))
    } else if model.starts_with("gpt-")
        || model.starts_with("o1")
        || model.starts_with("o3")
        || model.starts_with("o4")
    {
        // Auto-detect OpenAI models without explicit prefix
        let api_key = std::env::var("OPENAI_API_KEY")
            .map_err(|_| anyhow::anyhow!("OPENAI_API_KEY not set for model '{model}'"))?;
        let provider = openai::OpenAiProvider::new(api_key, None);
        Ok((Box::new(provider), model.to_string()))
    } else {
        // Default to Anthropic if no prefix
        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .map_err(|_| anyhow::anyhow!("ANTHROPIC_API_KEY not set for model '{model}'"))?;
        let provider = anthropic::AnthropicProvider::new(api_key);
        Ok((Box::new(provider), model.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chat_message_text() {
        let msg = ChatMessage::text(Role::User, "hello");
        assert_eq!(msg.text_content(), Some("hello"));
    }

    #[test]
    fn test_chat_message_tool_result() {
        let msg = ChatMessage::tool_result("call_1", "output");
        assert_eq!(msg.role, Role::User);
        assert!(msg.parts.is_some());
    }

    #[test]
    fn test_chat_message_assistant_tool_use() {
        let calls = vec![ToolCall {
            id: "call_1".into(),
            name: "nmap_scan".into(),
            arguments: serde_json::json!({"target": "192.168.58.0/24"}),
        }];
        let msg = ChatMessage::assistant_tool_use(Some("Let me scan".into()), calls);
        assert_eq!(msg.role, Role::Assistant);
        let parts = msg.parts.unwrap();
        assert_eq!(parts.len(), 2); // text + tool_use
    }

    #[test]
    fn test_llm_request_builder() {
        let req = LlmRequest::new("claude-sonnet-4-20250514");
        assert_eq!(req.model, "claude-sonnet-4-20250514");
        assert_eq!(req.max_tokens, 4096);
        assert!(req.tools.is_empty());
    }

    #[test]
    fn test_stop_reason_equality() {
        assert_eq!(StopReason::EndTurn, StopReason::EndTurn);
        assert_eq!(StopReason::ToolUse, StopReason::ToolUse);
        assert_ne!(StopReason::EndTurn, StopReason::ToolUse);
    }

    #[test]
    fn test_tool_definition_serialize() {
        let tool = ToolDefinition {
            name: "nmap_scan".into(),
            description: "Run an nmap scan".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string"}
                },
                "required": ["target"]
            }),
        };
        let json = serde_json::to_value(&tool).unwrap();
        assert_eq!(json["name"], "nmap_scan");
    }
}
