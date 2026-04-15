/// Configuration for an agent loop execution.
#[derive(Debug, Clone)]
pub struct AgentLoopConfig {
    /// LLM model identifier (e.g. "claude-sonnet-4-20250514").
    pub model: String,
    /// Maximum number of LLM steps before forcefully ending.
    pub max_steps: u32,
    /// Maximum tokens per LLM response.
    pub max_tokens: u32,
    /// Optional temperature override.
    pub temperature: Option<f32>,
    /// Retry configuration for transient LLM errors (rate limits, network).
    pub retry: RetryConfig,
    /// Context window management configuration.
    pub context: ContextConfig,
    /// Maximum times a single tool can be called within one agent loop before
    /// it is removed from the tool definitions to force the LLM to try
    /// a different approach. Blue investigations need higher limits since
    /// detection queries are the primary tool.
    pub max_tool_calls_per_name: u32,
}

impl Default for AgentLoopConfig {
    fn default() -> Self {
        Self {
            model: "claude-sonnet-4-20250514".to_string(),
            max_steps: 75,
            max_tokens: 4096,
            temperature: None,
            retry: RetryConfig::default(),
            context: ContextConfig::default(),
            max_tool_calls_per_name: 10,
        }
    }
}

/// Context window management to prevent unbounded message growth.
#[derive(Debug, Clone)]
pub struct ContextConfig {
    /// Maximum context budget in estimated tokens (0 = no limit).
    /// When the conversation exceeds this, older messages in the middle are dropped.
    pub max_context_tokens: u32,
    /// Maximum chars for a single tool result before truncation.
    /// Large tool outputs (nmap scans, secretsdump) are truncated to this limit.
    pub max_tool_output_chars: usize,
    /// Minimum number of recent messages to always keep (never truncated).
    pub min_recent_messages: usize,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            max_context_tokens: 180_000,   // Conservative for 200k models
            max_tool_output_chars: 30_000, // ~7,500 tokens per tool output
            min_recent_messages: 10,
        }
    }
}

/// Retry configuration for LLM calls with exponential backoff + jitter.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retries for retryable errors.
    pub max_retries: u32,
    /// Base delay in milliseconds (doubles each retry).
    pub base_delay_ms: u64,
    /// Maximum delay cap in milliseconds.
    pub max_delay_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            base_delay_ms: 1_000,
            max_delay_ms: 60_000,
        }
    }
}
