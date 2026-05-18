use tracing::{debug, info};

use crate::provider::{ChatMessage, ContentPart, Role};

use super::config::ContextConfig;

/// Estimate token count for a string using the chars/4 heuristic.
/// This approximation works well for English text and code with
/// Anthropic and OpenAI tokenizers.
pub(super) fn estimate_tokens(text: &str) -> u32 {
    // chars/4 is a widely-used approximation; slightly conservative.
    // Clamp to u32::MAX before casting to avoid silent truncation on
    // strings larger than ~4 GiB (possible in theory for tool outputs).
    let len = text.len().min(u32::MAX as usize) as u32;
    len.div_ceil(4)
}

/// Estimate total tokens for a message.
pub(super) fn estimate_message_tokens(msg: &ChatMessage) -> u32 {
    let mut tokens = 4u32; // Role overhead
    if let Some(ref content) = msg.content {
        tokens += estimate_tokens(content);
    }
    if let Some(ref parts) = msg.parts {
        for part in parts {
            tokens += match part {
                ContentPart::Text { text } => estimate_tokens(text),
                ContentPart::ToolResult { content, .. } => estimate_tokens(content) + 10,
                ContentPart::ToolUse { input, .. } => estimate_tokens(&input.to_string()) + 10,
            };
        }
    }
    tokens
}

/// Estimate total tokens for the full context (system + messages + tools).
pub(super) fn estimate_context_tokens(
    system: &str,
    messages: &[ChatMessage],
    tools: &[crate::ToolDefinition],
) -> u32 {
    let mut total = estimate_tokens(system);
    for msg in messages {
        total += estimate_message_tokens(msg);
    }
    // Tool definitions contribute to context (~50 tokens per tool avg)
    total = total.saturating_add(tools.len().min(u32::MAX as usize) as u32 * 50);
    total
}

/// Truncate a tool output string to fit within the character limit.
/// Keeps the beginning and end, inserting a truncation notice in the middle.
/// Uses char indices (not byte offsets) to avoid slicing mid-UTF-8.
pub(super) fn truncate_tool_output(output: &str, max_chars: usize) -> String {
    let char_count = output.chars().count();
    if char_count <= max_chars || max_chars == 0 {
        return output.to_string();
    }

    let keep = max_chars.saturating_sub(80); // Reserve space for notice
    let head_chars = keep * 2 / 3;
    let tail_chars = keep - head_chars;

    // Find byte offset of the head_chars-th character
    let head_byte = output
        .char_indices()
        .nth(head_chars)
        .map(|(i, _)| i)
        .unwrap_or(output.len());
    // Find byte offset of the (char_count - tail_chars)-th character
    let tail_byte = output
        .char_indices()
        .nth(char_count.saturating_sub(tail_chars))
        .map(|(i, _)| i)
        .unwrap_or(output.len());

    let head_str = &output[..head_byte];
    let tail_str = &output[tail_byte..];
    let omitted = char_count - head_chars - tail_chars;
    format!(
        "{head_str}\n\n[... {omitted} characters truncated — showing first {head_chars} and last {tail_chars} chars ...]\n\n{tail_str}"
    )
}

/// Why `maybe_compact` decided to (or not to) trim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CompactionDecision {
    /// Nothing to do; under the proactive threshold (or disabled).
    Skipped,
    /// Compacted because the proactive threshold (e.g. 60%) was crossed.
    Proactive,
    /// Compacted because the hard ceiling was hit; this is the last-resort path.
    Reactive,
}

/// Decide whether to compact and, if so, perform the trim.
///
/// Strategy:
/// 1. Cheap path: if `step % compaction_check_every != 0` AND we are below
///    the hard ceiling, skip token estimation entirely.
/// 2. Otherwise estimate the context. If we cross the proactive threshold
///    (e.g. 60% utilization) we compact early — better than waiting until
///    the wall and risking a truncated tool-call/result pair.
/// 3. The hard ceiling check still runs every step regardless of cadence;
///    a runaway tool output should never escape the trim.
pub(super) fn maybe_compact(
    messages: &mut Vec<ChatMessage>,
    system: &str,
    tools: &[crate::ToolDefinition],
    config: &ContextConfig,
    step: u32,
) -> CompactionDecision {
    if config.max_context_tokens == 0 {
        return CompactionDecision::Skipped;
    }

    let trigger = config.compaction_trigger_tokens();
    let on_cadence = step.is_multiple_of(config.compaction_check_every);

    // Cheap fast path: skip estimation entirely when neither the cadence
    // tick nor the wall would do anything.
    if !on_cadence && messages.len() < config.min_recent_messages * 4 {
        return CompactionDecision::Skipped;
    }

    let total = estimate_context_tokens(system, messages, tools);
    let over_ceiling = total > config.max_context_tokens;
    let over_threshold = trigger > 0 && total >= trigger;

    if !(over_ceiling || (on_cadence && over_threshold)) {
        return CompactionDecision::Skipped;
    }

    let decision = if over_ceiling {
        CompactionDecision::Reactive
    } else {
        CompactionDecision::Proactive
    };

    if compact_messages(messages, total, system, tools, config, decision).is_some() {
        decision
    } else {
        CompactionDecision::Skipped
    }
}

/// Trim the conversation. Test-only wrapper around `maybe_compact` that
/// forces the cadence tick (by passing `step = compaction_check_every`).
#[cfg(test)]
pub(super) fn trim_conversation(
    messages: &mut Vec<ChatMessage>,
    system: &str,
    tools: &[crate::ToolDefinition],
    config: &ContextConfig,
) {
    // step=cadence ensures the cadence branch fires; the threshold logic
    // inside still gates on `total > max_context_tokens`-style conditions
    // when the threshold is at the wall (1.0).
    let _ = maybe_compact(
        messages,
        system,
        tools,
        config,
        config.compaction_check_every,
    );
}

/// Perform the actual compaction. Returns `Some(())` when a trim happened.
///
/// Tool-call groups (an assistant message with tool_calls followed by its
/// tool-result messages) are treated as atomic units — we never split them,
/// since OpenAI rejects orphaned tool_call_ids with a 400 "invalid JSON" error.
fn compact_messages(
    messages: &mut Vec<ChatMessage>,
    total_before: u32,
    system: &str,
    tools: &[crate::ToolDefinition],
    config: &ContextConfig,
    decision: CompactionDecision,
) -> Option<()> {
    let min_keep = config.min_recent_messages;
    if messages.len() <= min_keep + 1 {
        return None;
    }

    // Keep first message + last min_keep messages, drop the middle
    let mut drop_end = messages.len().saturating_sub(min_keep);
    if drop_end <= 1 {
        return None;
    }

    // Adjust drop_end so we don't sever tool-call / tool-result pairs.
    // If the first kept message (at drop_end) is a tool-result, walk backward
    // to include the preceding assistant tool-call message in the kept set.
    while drop_end > 1 && is_tool_result(&messages[drop_end]) {
        drop_end -= 1;
    }

    if drop_end <= 1 {
        return None;
    }

    // If the last dropped message (at drop_end - 1) is an assistant message
    // with tool_calls, we must also drop the subsequent tool-result messages,
    // so advance drop_end past them.
    if has_tool_calls(&messages[drop_end - 1]) {
        while drop_end < messages.len() && is_tool_result(&messages[drop_end]) {
            drop_end += 1;
        }
    }

    if drop_end <= 1 || drop_end >= messages.len() {
        return None;
    }

    // Score the about-to-be-dropped slice and surface a short semantic recap
    // alongside the count, so the LLM still has a pointer to what it just
    // worked on. This is the lightweight "semantic scoring" version: we
    // pick the highest-signal text fragments rather than a separate
    // summarization LLM call.
    let recap = semantic_recap(&messages[1..drop_end]);
    let dropped = drop_end - 1;
    let kind = match decision {
        CompactionDecision::Proactive => "proactive",
        CompactionDecision::Reactive => "reactive",
        CompactionDecision::Skipped => "skipped",
    };
    let summary = if recap.is_empty() {
        format!(
            "[Context compacted ({kind}): {dropped} earlier messages removed to stay within token \
             budget. The conversation continues from the most recent exchanges.]"
        )
    } else {
        format!(
            "[Context compacted ({kind}): {dropped} earlier messages removed to stay within token \
             budget. Salient highlights:\n{recap}\nThe conversation continues from the most recent \
             exchanges.]"
        )
    };

    messages.splice(
        1..drop_end,
        std::iter::once(ChatMessage::text(Role::User, &summary)),
    );

    let total_after = estimate_context_tokens(system, messages, tools);
    let log_msg = "Compacted conversation context";
    match decision {
        CompactionDecision::Proactive => {
            info!(
                kind = "proactive",
                dropped = dropped,
                remaining = messages.len(),
                tokens_before = total_before,
                tokens_after = total_after,
                log_msg
            );
        }
        CompactionDecision::Reactive | CompactionDecision::Skipped => {
            debug!(
                kind = kind,
                dropped = dropped,
                remaining = messages.len(),
                tokens_before = total_before,
                tokens_after = total_after,
                log_msg
            );
        }
    }

    Some(())
}

/// Pick a few high-signal lines from a slice of messages. Heuristic: prefer
/// the first line of any tool-result (often the most informative summary
/// line of a scan/dump) and the first sentence of any assistant text. Cap
/// the recap to avoid re-introducing context bloat.
fn semantic_recap(slice: &[ChatMessage]) -> String {
    const MAX_LINES: usize = 6;
    const MAX_LINE_CHARS: usize = 160;
    let mut out: Vec<String> = Vec::with_capacity(MAX_LINES);

    for msg in slice {
        if out.len() >= MAX_LINES {
            break;
        }
        if let Some(parts) = &msg.parts {
            for part in parts {
                if out.len() >= MAX_LINES {
                    break;
                }
                match part {
                    ContentPart::ToolResult { content, .. } => {
                        if let Some(line) = first_signal_line(content) {
                            out.push(format!("- tool: {}", clip(&line, MAX_LINE_CHARS)));
                        }
                    }
                    ContentPart::Text { text } => {
                        if let Some(line) = first_signal_line(text) {
                            out.push(format!("- llm: {}", clip(&line, MAX_LINE_CHARS)));
                        }
                    }
                    ContentPart::ToolUse { name, .. } => {
                        out.push(format!("- call: {name}"));
                    }
                }
            }
        } else if let Some(content) = &msg.content {
            if let Some(line) = first_signal_line(content) {
                let role = match msg.role {
                    Role::User => "user",
                    Role::Assistant => "llm",
                    _ => "msg",
                };
                out.push(format!("- {role}: {}", clip(&line, MAX_LINE_CHARS)));
            }
        }
    }

    out.join("\n")
}

fn first_signal_line(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("```"))
        .map(|s| s.to_string())
}

fn clip(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let cut = s
        .char_indices()
        .nth(max_chars)
        .map(|(i, _)| i)
        .unwrap_or(s.len());
    format!("{}…", &s[..cut])
}

/// Check if a message is a tool result (role=Tool or User with ToolResult parts).
pub(super) fn is_tool_result(msg: &ChatMessage) -> bool {
    if msg.role == Role::Tool {
        return true;
    }
    if let Some(ref parts) = msg.parts {
        return parts
            .iter()
            .any(|p| matches!(p, ContentPart::ToolResult { .. }));
    }
    false
}

/// Check if a message is an assistant message with tool_use calls.
pub(super) fn has_tool_calls(msg: &ChatMessage) -> bool {
    if msg.role != Role::Assistant {
        return false;
    }
    if let Some(ref parts) = msg.parts {
        return parts
            .iter()
            .any(|p| matches!(p, ContentPart::ToolUse { .. }));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_tokens_empty() {
        assert_eq!(estimate_tokens(""), 0);
    }

    #[test]
    fn estimate_tokens_short_string() {
        // 12 bytes -> ceil(12/4) = 3
        assert_eq!(estimate_tokens("hello world!"), 3);
    }

    #[test]
    fn estimate_tokens_exact_multiple() {
        // 8 bytes -> 8/4 = 2
        assert_eq!(estimate_tokens("abcdefgh"), 2);
    }

    #[test]
    fn estimate_tokens_rounds_up() {
        // 5 bytes -> ceil(5/4) = 2
        assert_eq!(estimate_tokens("abcde"), 2);
    }

    #[test]
    fn estimate_message_tokens_text_content() {
        let msg = ChatMessage::text(Role::User, "hello");
        // 4 (overhead) + ceil(5/4) = 4 + 2 = 6
        assert_eq!(estimate_message_tokens(&msg), 6);
    }

    #[test]
    fn estimate_message_tokens_no_content() {
        let msg = ChatMessage {
            role: Role::Assistant,
            content: None,
            parts: None,
        };
        assert_eq!(estimate_message_tokens(&msg), 4);
    }

    #[test]
    fn truncate_tool_output_short_unchanged() {
        let output = "short output";
        let result = truncate_tool_output(output, 100);
        assert_eq!(result, output);
    }

    #[test]
    fn truncate_tool_output_zero_max_unchanged() {
        let output = "any output";
        let result = truncate_tool_output(output, 0);
        assert_eq!(result, output);
    }

    #[test]
    fn truncate_tool_output_long_truncated() {
        let output = "a".repeat(1000);
        let result = truncate_tool_output(&output, 200);
        assert!(result.len() < 1000);
        assert!(result.contains("truncated"));
    }

    #[test]
    fn truncate_tool_output_preserves_head_and_tail() {
        let head = "HEAD".repeat(50);
        let middle = "M".repeat(600);
        let tail = "TAIL".repeat(50);
        let output = format!("{head}{middle}{tail}");
        let result = truncate_tool_output(&output, 300);
        assert!(result.starts_with("HEAD"));
        assert!(result.ends_with("TAIL"));
    }

    #[test]
    fn is_tool_result_tool_role() {
        let msg = ChatMessage {
            role: Role::Tool,
            content: Some("result".to_string()),
            parts: None,
        };
        assert!(is_tool_result(&msg));
    }

    #[test]
    fn is_tool_result_user_no_parts() {
        let msg = ChatMessage::text(Role::User, "hello");
        assert!(!is_tool_result(&msg));
    }

    #[test]
    fn is_tool_result_user_with_tool_result_part() {
        let msg = ChatMessage {
            role: Role::User,
            content: None,
            parts: Some(vec![ContentPart::ToolResult {
                tool_use_id: "id1".to_string(),
                content: "output".to_string(),
            }]),
        };
        assert!(is_tool_result(&msg));
    }

    #[test]
    fn has_tool_calls_assistant_with_tool_use() {
        let msg = ChatMessage {
            role: Role::Assistant,
            content: None,
            parts: Some(vec![ContentPart::ToolUse {
                id: "id1".to_string(),
                name: "tool".to_string(),
                input: serde_json::json!({}),
            }]),
        };
        assert!(has_tool_calls(&msg));
    }

    #[test]
    fn has_tool_calls_user_role_false() {
        let msg = ChatMessage {
            role: Role::User,
            content: None,
            parts: Some(vec![ContentPart::ToolUse {
                id: "id1".to_string(),
                name: "tool".to_string(),
                input: serde_json::json!({}),
            }]),
        };
        assert!(!has_tool_calls(&msg));
    }

    #[test]
    fn has_tool_calls_assistant_no_parts() {
        let msg = ChatMessage::text(Role::Assistant, "hello");
        assert!(!has_tool_calls(&msg));
    }

    #[test]
    fn trim_conversation_no_limit() {
        let config = ContextConfig {
            max_context_tokens: 0,
            compaction_threshold_ratio: 0.6,
            compaction_check_every: 1,
            max_tool_output_chars: 30_000,
            min_recent_messages: 10,
        };
        let mut msgs = vec![
            ChatMessage::text(Role::User, "first"),
            ChatMessage::text(Role::Assistant, "second"),
        ];
        trim_conversation(&mut msgs, "system", &[], &config);
        assert_eq!(msgs.len(), 2);
    }

    #[test]
    fn trim_conversation_under_budget_unchanged() {
        let config = ContextConfig {
            max_context_tokens: 100_000,
            compaction_threshold_ratio: 0.6,
            compaction_check_every: 1,
            max_tool_output_chars: 30_000,
            min_recent_messages: 2,
        };
        let mut msgs = vec![
            ChatMessage::text(Role::User, "first"),
            ChatMessage::text(Role::Assistant, "second"),
        ];
        trim_conversation(&mut msgs, "sys", &[], &config);
        assert_eq!(msgs.len(), 2);
    }

    #[test]
    fn maybe_compact_proactive_at_60_percent() {
        let config = ContextConfig {
            max_context_tokens: 1000,
            compaction_threshold_ratio: 0.6,
            compaction_check_every: 1,
            max_tool_output_chars: 0,
            min_recent_messages: 2,
        };
        let mut messages: Vec<ChatMessage> = Vec::new();
        messages.push(ChatMessage::text(Role::User, "task prompt"));
        // Each message ~ 250 chars -> ~ 62 tokens. Add enough to cross 600 tokens.
        for i in 0..15 {
            messages.push(ChatMessage::text(
                Role::Assistant,
                format!("step {i} {}", "x".repeat(240)),
            ));
        }
        let decision = maybe_compact(&mut messages, "sys", &[], &config, 1);
        assert_eq!(decision, CompactionDecision::Proactive);
        assert!(messages.len() < 16);
        assert!(messages[1]
            .text_content()
            .unwrap()
            .contains("Context compacted"));
    }

    #[test]
    fn maybe_compact_reactive_when_over_ceiling() {
        let config = ContextConfig {
            max_context_tokens: 200,
            compaction_threshold_ratio: 1.0, // disable proactive
            compaction_check_every: 100,     // off-cadence
            max_tool_output_chars: 0,
            min_recent_messages: 2,
        };
        let mut messages: Vec<ChatMessage> = Vec::new();
        messages.push(ChatMessage::text(Role::User, "task"));
        for i in 0..10 {
            messages.push(ChatMessage::text(
                Role::Assistant,
                format!("step {i} {}", "x".repeat(200)),
            ));
        }
        // Off-cadence step=1, but the hard ceiling must still trip.
        let decision = maybe_compact(&mut messages, "sys", &[], &config, 1);
        assert_eq!(decision, CompactionDecision::Reactive);
    }

    #[test]
    fn maybe_compact_skips_when_under_threshold() {
        let config = ContextConfig {
            max_context_tokens: 1_000_000,
            compaction_threshold_ratio: 0.6,
            compaction_check_every: 1,
            max_tool_output_chars: 0,
            min_recent_messages: 4,
        };
        let mut messages = vec![
            ChatMessage::text(Role::User, "first"),
            ChatMessage::text(Role::Assistant, "second"),
        ];
        let decision = maybe_compact(&mut messages, "sys", &[], &config, 1);
        assert_eq!(decision, CompactionDecision::Skipped);
        assert_eq!(messages.len(), 2);
    }

    #[test]
    fn semantic_recap_picks_first_signal_lines() {
        let messages = vec![
            ChatMessage::text(Role::Assistant, "I'll start by scanning.\nDetails follow."),
            ChatMessage::tool_result("c1", "Host 192.168.58.10 is up.\n22/tcp open ssh"),
        ];
        let recap = semantic_recap(&messages);
        assert!(recap.contains("scanning"));
        assert!(recap.contains("192.168.58.10"));
    }
}
