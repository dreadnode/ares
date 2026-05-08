use std::path::PathBuf;

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
    /// Token budget circuit breaker; when exceeded the loop ends with
    /// `LoopEndReason::BudgetExceeded` rather than calling the LLM again.
    pub budget: BudgetConfig,
    /// Append-only session log configuration.
    pub session_log: SessionLogConfig,
    /// Maximum times a single tool can be called within one agent loop before
    /// it is removed from the tool definitions to force the LLM to try
    /// a different approach. Blue investigations need higher limits since
    /// detection queries are the primary tool.
    pub max_tool_calls_per_name: u32,
    /// Whether to attach Anthropic prompt-cache breakpoints to the stable
    /// prefix (system + tool definitions). No-op for non-Anthropic providers.
    pub enable_prompt_cache: bool,
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
            budget: BudgetConfig::default(),
            session_log: SessionLogConfig::default(),
            max_tool_calls_per_name: 10,
            enable_prompt_cache: true,
        }
    }
}

impl AgentLoopConfig {
    /// Build an `AgentLoopConfig` with the given model + temperature, layered
    /// over env-var overrides for the remaining fields.
    ///
    /// Env vars (all optional, fall back to default values):
    /// - `ARES_AGENT_MAX_STEPS`
    /// - `ARES_AGENT_MAX_TOKENS`
    /// - `ARES_AGENT_MAX_TOOL_CALLS_PER_NAME`
    /// - `ARES_AGENT_ENABLE_PROMPT_CACHE` (`true`/`false`/`1`/`0`)
    /// - everything from `ContextConfig::from_env`, `BudgetConfig::from_env`,
    ///   `SessionLogConfig::from_env`
    pub fn from_env(model: String, temperature: Option<f32>) -> Self {
        let defaults = Self::default();
        Self {
            model,
            temperature,
            max_steps: parse_env_u32("ARES_AGENT_MAX_STEPS", defaults.max_steps),
            max_tokens: parse_env_u32("ARES_AGENT_MAX_TOKENS", defaults.max_tokens),
            max_tool_calls_per_name: parse_env_u32(
                "ARES_AGENT_MAX_TOOL_CALLS_PER_NAME",
                defaults.max_tool_calls_per_name,
            ),
            enable_prompt_cache: parse_env_bool(
                "ARES_AGENT_ENABLE_PROMPT_CACHE",
                defaults.enable_prompt_cache,
            ),
            retry: defaults.retry,
            context: ContextConfig::from_env(),
            budget: BudgetConfig::from_env(),
            session_log: SessionLogConfig::from_env(),
        }
    }
}

/// Context window management to prevent unbounded message growth.
#[derive(Debug, Clone)]
pub struct ContextConfig {
    /// Maximum context budget in estimated tokens (0 = no limit).
    /// When the conversation exceeds this hard ceiling, older messages in the
    /// middle are dropped regardless of cadence (defensive cliff).
    pub max_context_tokens: u32,
    /// Compact when `estimated_tokens / max_context_tokens` reaches this ratio
    /// (e.g. 0.6 → compact at 60% utilization). Set to 1.0 to keep the old
    /// reactive-at-the-wall behavior. Ignored when `max_context_tokens == 0`.
    pub compaction_threshold_ratio: f32,
    /// Only check the threshold every N agent loop iterations (1 = every step).
    /// The hard ceiling is always checked. Higher values reduce overhead at
    /// the cost of slightly later compaction.
    pub compaction_check_every: u32,
    /// Maximum chars for a single tool result before truncation.
    /// Large tool outputs (nmap scans, secretsdump) are truncated to this limit.
    pub max_tool_output_chars: usize,
    /// Minimum number of recent messages to always keep (never truncated).
    pub min_recent_messages: usize,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            max_context_tokens: 180_000,     // Conservative for 200k models
            compaction_threshold_ratio: 0.6, // Compact proactively at 60%
            compaction_check_every: 5,
            max_tool_output_chars: 30_000, // ~7,500 tokens per tool output
            min_recent_messages: 10,
        }
    }
}

impl ContextConfig {
    pub fn from_env() -> Self {
        let defaults = Self::default();
        Self {
            max_context_tokens: parse_env_u32(
                "ARES_CONTEXT_MAX_TOKENS",
                defaults.max_context_tokens,
            ),
            compaction_threshold_ratio: parse_env_f32(
                "ARES_CONTEXT_COMPACTION_THRESHOLD",
                defaults.compaction_threshold_ratio,
            )
            .clamp(0.1, 1.0),
            compaction_check_every: parse_env_u32(
                "ARES_CONTEXT_COMPACTION_CHECK_EVERY",
                defaults.compaction_check_every,
            )
            .max(1),
            max_tool_output_chars: parse_env_usize(
                "ARES_CONTEXT_MAX_TOOL_OUTPUT_CHARS",
                defaults.max_tool_output_chars,
            ),
            min_recent_messages: parse_env_usize(
                "ARES_CONTEXT_MIN_RECENT_MESSAGES",
                defaults.min_recent_messages,
            ),
        }
    }

    /// Token threshold at which proactive compaction fires. Returns 0 when
    /// either the ceiling is disabled or the ratio is at the wall (1.0).
    pub fn compaction_trigger_tokens(&self) -> u32 {
        if self.max_context_tokens == 0 {
            return 0;
        }
        let scaled =
            (self.max_context_tokens as f32 * self.compaction_threshold_ratio).round() as u32;
        scaled.min(self.max_context_tokens)
    }
}

/// Per-loop token budget enforcement (circuit breaker).
///
/// Budgets cap the *cumulative* input + output tokens a single agent loop
/// invocation may consume. A zero value disables that specific check, so
/// the default-constructed config is fully disabled and operators opt in
/// via env vars.
#[derive(Debug, Clone, Default)]
pub struct BudgetConfig {
    /// Maximum cumulative input tokens (0 = no limit).
    pub max_input_tokens: u32,
    /// Maximum cumulative output tokens (0 = no limit).
    pub max_output_tokens: u32,
    /// Maximum cumulative input + output tokens (0 = no limit).
    pub max_total_tokens: u32,
}

impl BudgetConfig {
    pub fn from_env() -> Self {
        Self {
            max_input_tokens: parse_env_u32("ARES_BUDGET_MAX_INPUT_TOKENS", 0),
            max_output_tokens: parse_env_u32("ARES_BUDGET_MAX_OUTPUT_TOKENS", 0),
            max_total_tokens: parse_env_u32("ARES_BUDGET_MAX_TOTAL_TOKENS", 0),
        }
    }

    /// Returns the first budget violation (if any) given the cumulative usage so far.
    pub fn check(&self, input: u32, output: u32) -> Option<String> {
        if self.max_input_tokens > 0 && input >= self.max_input_tokens {
            return Some(format!(
                "input token budget exhausted ({input} >= {})",
                self.max_input_tokens
            ));
        }
        if self.max_output_tokens > 0 && output >= self.max_output_tokens {
            return Some(format!(
                "output token budget exhausted ({output} >= {})",
                self.max_output_tokens
            ));
        }
        let total = input.saturating_add(output);
        if self.max_total_tokens > 0 && total >= self.max_total_tokens {
            return Some(format!(
                "total token budget exhausted ({total} >= {})",
                self.max_total_tokens
            ));
        }
        None
    }
}

/// Append-only JSONL session log configuration.
///
/// When enabled, every conversation event (user prompt, assistant turn,
/// tool result, terminal outcome) is appended as a JSON line under
/// `dir/{op_id}/{task_id}.jsonl`. The log is the primary source of truth
/// for crash recovery / `--resume` and post-hoc debugging.
#[derive(Debug, Clone, Default)]
pub struct SessionLogConfig {
    /// Root directory for session logs. `None` disables logging.
    pub dir: Option<PathBuf>,
}

impl SessionLogConfig {
    /// Construct from env vars:
    /// - `ARES_SESSION_LOG_DIR` (explicit path; takes precedence)
    /// - `ARES_SESSION_LOG_ENABLED=0` opts out (default is enabled)
    ///
    /// When enabled with no explicit dir, defaults to `~/.ares/sessions`.
    pub fn from_env() -> Self {
        if let Ok(dir) = std::env::var("ARES_SESSION_LOG_DIR") {
            if !dir.trim().is_empty() {
                return Self {
                    dir: Some(PathBuf::from(dir)),
                };
            }
        }
        if parse_env_bool("ARES_SESSION_LOG_ENABLED", true) {
            if let Some(home) = std::env::var_os("HOME") {
                let mut p = PathBuf::from(home);
                p.push(".ares");
                p.push("sessions");
                return Self { dir: Some(p) };
            }
        }
        Self { dir: None }
    }

    /// Default session-log root used when `ARES_SESSION_LOG_DIR` is unset.
    /// Mirrors the path resolution in `from_env` so external callers (e.g.
    /// the `ares ops sessions` CLI) can find logs without re-implementing
    /// the lookup. Returns `None` when `HOME` is unset.
    pub fn default_root() -> Option<PathBuf> {
        if let Ok(dir) = std::env::var("ARES_SESSION_LOG_DIR") {
            if !dir.trim().is_empty() {
                return Some(PathBuf::from(dir));
            }
        }
        let home = std::env::var_os("HOME")?;
        let mut p = PathBuf::from(home);
        p.push(".ares");
        p.push("sessions");
        Some(p)
    }

    pub fn enabled(&self) -> bool {
        self.dir.is_some()
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

fn parse_env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(default)
}

fn parse_env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

fn parse_env_f32(key: &str, default: f32) -> f32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<f32>().ok())
        .unwrap_or(default)
}

fn parse_env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" | "" => false,
            _ => default,
        },
        Err(_) => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes tests that mutate ARES_SESSION_LOG_* / HOME to keep
    /// `cargo test`'s parallel scheduler from observing partial states.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn agent_loop_config_defaults() {
        let cfg = AgentLoopConfig::default();
        assert_eq!(cfg.model, "claude-sonnet-4-20250514");
        assert_eq!(cfg.max_steps, 75);
        assert_eq!(cfg.max_tokens, 4096);
        assert!(cfg.temperature.is_none());
        assert_eq!(cfg.max_tool_calls_per_name, 10);
        assert!(cfg.enable_prompt_cache);
    }

    #[test]
    fn context_config_defaults() {
        let cfg = ContextConfig::default();
        assert_eq!(cfg.max_context_tokens, 180_000);
        assert_eq!(cfg.max_tool_output_chars, 30_000);
        assert_eq!(cfg.min_recent_messages, 10);
        assert!((cfg.compaction_threshold_ratio - 0.6).abs() < 1e-6);
        assert_eq!(cfg.compaction_check_every, 5);
    }

    #[test]
    fn retry_config_defaults() {
        let cfg = RetryConfig::default();
        assert_eq!(cfg.max_retries, 5);
        assert_eq!(cfg.base_delay_ms, 1_000);
        assert_eq!(cfg.max_delay_ms, 60_000);
    }

    #[test]
    fn budget_config_disabled_by_default() {
        let cfg = BudgetConfig::default();
        assert_eq!(cfg.max_input_tokens, 0);
        assert_eq!(cfg.max_output_tokens, 0);
        assert_eq!(cfg.max_total_tokens, 0);
        assert!(cfg.check(u32::MAX, u32::MAX).is_none());
    }

    #[test]
    fn budget_config_check_input() {
        let cfg = BudgetConfig {
            max_input_tokens: 1000,
            ..Default::default()
        };
        assert!(cfg.check(999, 0).is_none());
        let v = cfg.check(1000, 0).expect("should trip");
        assert!(v.contains("input"));
    }

    #[test]
    fn budget_config_check_output() {
        let cfg = BudgetConfig {
            max_output_tokens: 500,
            ..Default::default()
        };
        assert!(cfg.check(0, 499).is_none());
        let v = cfg.check(0, 500).expect("should trip");
        assert!(v.contains("output"));
    }

    #[test]
    fn budget_config_check_total() {
        let cfg = BudgetConfig {
            max_total_tokens: 100,
            ..Default::default()
        };
        assert!(cfg.check(40, 50).is_none());
        let v = cfg.check(60, 40).expect("should trip");
        assert!(v.contains("total"));
    }

    #[test]
    fn compaction_trigger_tokens_at_60pct() {
        let cfg = ContextConfig {
            max_context_tokens: 100_000,
            compaction_threshold_ratio: 0.6,
            ..ContextConfig::default()
        };
        assert_eq!(cfg.compaction_trigger_tokens(), 60_000);
    }

    #[test]
    fn compaction_trigger_tokens_disabled() {
        let cfg = ContextConfig {
            max_context_tokens: 0,
            ..ContextConfig::default()
        };
        assert_eq!(cfg.compaction_trigger_tokens(), 0);
    }

    #[test]
    fn session_log_disabled_by_default() {
        let cfg = SessionLogConfig::default();
        assert!(!cfg.enabled());
    }

    #[test]
    fn parse_env_u32_uses_default_when_unset() {
        std::env::remove_var("ARES_TEST_PARSE_U32_UNSET");
        assert_eq!(parse_env_u32("ARES_TEST_PARSE_U32_UNSET", 42), 42);
    }

    #[test]
    fn parse_env_u32_parses_and_falls_back() {
        std::env::set_var("ARES_TEST_PARSE_U32_VALID", "  123 ");
        assert_eq!(parse_env_u32("ARES_TEST_PARSE_U32_VALID", 0), 123);
        std::env::remove_var("ARES_TEST_PARSE_U32_VALID");

        std::env::set_var("ARES_TEST_PARSE_U32_BAD", "not-a-number");
        assert_eq!(parse_env_u32("ARES_TEST_PARSE_U32_BAD", 7), 7);
        std::env::remove_var("ARES_TEST_PARSE_U32_BAD");
    }

    #[test]
    fn parse_env_usize_parses_and_falls_back() {
        std::env::set_var("ARES_TEST_PARSE_USIZE_VALID", "999");
        assert_eq!(parse_env_usize("ARES_TEST_PARSE_USIZE_VALID", 0), 999);
        std::env::remove_var("ARES_TEST_PARSE_USIZE_VALID");

        std::env::set_var("ARES_TEST_PARSE_USIZE_BAD", "xx");
        assert_eq!(parse_env_usize("ARES_TEST_PARSE_USIZE_BAD", 5), 5);
        std::env::remove_var("ARES_TEST_PARSE_USIZE_BAD");
    }

    #[test]
    fn parse_env_f32_parses_and_falls_back() {
        std::env::set_var("ARES_TEST_PARSE_F32_VALID", "0.75");
        let v = parse_env_f32("ARES_TEST_PARSE_F32_VALID", 1.0);
        assert!((v - 0.75).abs() < 1e-6);
        std::env::remove_var("ARES_TEST_PARSE_F32_VALID");

        std::env::set_var("ARES_TEST_PARSE_F32_BAD", "abc");
        let v = parse_env_f32("ARES_TEST_PARSE_F32_BAD", 0.5);
        assert!((v - 0.5).abs() < 1e-6);
        std::env::remove_var("ARES_TEST_PARSE_F32_BAD");
    }

    #[test]
    fn parse_env_bool_recognizes_truthy_falsy() {
        for v in &["1", "true", "yes", "on", "TRUE", "Yes"] {
            std::env::set_var("ARES_TEST_PARSE_BOOL", v);
            assert!(parse_env_bool("ARES_TEST_PARSE_BOOL", false), "case {v}");
        }
        for v in &["0", "false", "no", "off", ""] {
            std::env::set_var("ARES_TEST_PARSE_BOOL", v);
            assert!(!parse_env_bool("ARES_TEST_PARSE_BOOL", true), "case {v:?}");
        }
        std::env::set_var("ARES_TEST_PARSE_BOOL", "junk");
        assert!(parse_env_bool("ARES_TEST_PARSE_BOOL", true));
        assert!(!parse_env_bool("ARES_TEST_PARSE_BOOL", false));
        std::env::remove_var("ARES_TEST_PARSE_BOOL");

        std::env::remove_var("ARES_TEST_PARSE_BOOL_UNSET");
        assert!(parse_env_bool("ARES_TEST_PARSE_BOOL_UNSET", true));
    }

    #[test]
    fn budget_config_from_env_reads_all_keys() {
        std::env::set_var("ARES_BUDGET_MAX_INPUT_TOKENS", "11");
        std::env::set_var("ARES_BUDGET_MAX_OUTPUT_TOKENS", "22");
        std::env::set_var("ARES_BUDGET_MAX_TOTAL_TOKENS", "33");
        let cfg = BudgetConfig::from_env();
        assert_eq!(cfg.max_input_tokens, 11);
        assert_eq!(cfg.max_output_tokens, 22);
        assert_eq!(cfg.max_total_tokens, 33);
        std::env::remove_var("ARES_BUDGET_MAX_INPUT_TOKENS");
        std::env::remove_var("ARES_BUDGET_MAX_OUTPUT_TOKENS");
        std::env::remove_var("ARES_BUDGET_MAX_TOTAL_TOKENS");
    }

    #[test]
    fn context_config_from_env_clamps_threshold() {
        std::env::set_var("ARES_CONTEXT_MAX_TOKENS", "12345");
        std::env::set_var("ARES_CONTEXT_COMPACTION_THRESHOLD", "5.0"); // clamp to 1.0
        std::env::set_var("ARES_CONTEXT_COMPACTION_CHECK_EVERY", "0"); // bumped to 1
        std::env::set_var("ARES_CONTEXT_MAX_TOOL_OUTPUT_CHARS", "9999");
        std::env::set_var("ARES_CONTEXT_MIN_RECENT_MESSAGES", "8");
        let cfg = ContextConfig::from_env();
        assert_eq!(cfg.max_context_tokens, 12345);
        assert!((cfg.compaction_threshold_ratio - 1.0).abs() < 1e-6);
        assert_eq!(cfg.compaction_check_every, 1);
        assert_eq!(cfg.max_tool_output_chars, 9999);
        assert_eq!(cfg.min_recent_messages, 8);
        std::env::remove_var("ARES_CONTEXT_MAX_TOKENS");
        std::env::remove_var("ARES_CONTEXT_COMPACTION_THRESHOLD");
        std::env::remove_var("ARES_CONTEXT_COMPACTION_CHECK_EVERY");
        std::env::remove_var("ARES_CONTEXT_MAX_TOOL_OUTPUT_CHARS");
        std::env::remove_var("ARES_CONTEXT_MIN_RECENT_MESSAGES");
    }

    // Consolidated to avoid cross-test races on the shared ARES_SESSION_LOG_*
    // environment variables — running each behavior in its own #[test] would
    // let `cargo test`'s parallel scheduler observe one test's mutations
    // mid-flight in another.
    #[test]
    fn session_log_config_from_env_behaviors() {
        let _guard = ENV_LOCK.lock().unwrap();
        let saved_home = std::env::var_os("HOME");

        // 1. Explicit ARES_SESSION_LOG_DIR wins regardless of ENABLED.
        std::env::set_var("ARES_SESSION_LOG_DIR", "/tmp/ares-test-sessions");
        std::env::remove_var("ARES_SESSION_LOG_ENABLED");
        let cfg = SessionLogConfig::from_env();
        assert!(cfg.enabled());
        assert_eq!(
            cfg.dir.as_deref(),
            Some(std::path::Path::new("/tmp/ares-test-sessions"))
        );

        // 2. Explicit opt-out (ENABLED=0) with whitespace dir → disabled.
        std::env::set_var("ARES_SESSION_LOG_ENABLED", "0");
        std::env::set_var("ARES_SESSION_LOG_DIR", "   ");
        let cfg = SessionLogConfig::from_env();
        assert!(!cfg.enabled());

        // 3. Default-on: no env vars set, HOME → `~/.ares/sessions`.
        std::env::remove_var("ARES_SESSION_LOG_ENABLED");
        std::env::remove_var("ARES_SESSION_LOG_DIR");
        std::env::set_var("HOME", "/tmp/ares-test-home");
        let cfg = SessionLogConfig::from_env();
        assert!(cfg.enabled(), "session log should default to on");
        assert_eq!(
            cfg.dir.as_deref(),
            Some(std::path::Path::new("/tmp/ares-test-home/.ares/sessions"))
        );

        // 4. default_root mirrors from_env's path resolution.
        assert_eq!(
            SessionLogConfig::default_root().as_deref(),
            Some(std::path::Path::new("/tmp/ares-test-home/.ares/sessions"))
        );

        match saved_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn agent_loop_config_from_env_layers_overrides() {
        std::env::set_var("ARES_AGENT_MAX_STEPS", "13");
        std::env::set_var("ARES_AGENT_MAX_TOKENS", "8192");
        std::env::set_var("ARES_AGENT_MAX_TOOL_CALLS_PER_NAME", "3");
        std::env::set_var("ARES_AGENT_ENABLE_PROMPT_CACHE", "false");
        let cfg = AgentLoopConfig::from_env("test-model".into(), Some(0.25));
        assert_eq!(cfg.model, "test-model");
        assert_eq!(cfg.temperature, Some(0.25));
        assert_eq!(cfg.max_steps, 13);
        assert_eq!(cfg.max_tokens, 8192);
        assert_eq!(cfg.max_tool_calls_per_name, 3);
        assert!(!cfg.enable_prompt_cache);
        std::env::remove_var("ARES_AGENT_MAX_STEPS");
        std::env::remove_var("ARES_AGENT_MAX_TOKENS");
        std::env::remove_var("ARES_AGENT_MAX_TOOL_CALLS_PER_NAME");
        std::env::remove_var("ARES_AGENT_ENABLE_PROMPT_CACHE");
    }
}
