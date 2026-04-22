use tracing::debug;

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

/// Trim the conversation to fit within the token budget.
///
/// Strategy: keep the first message (task prompt) and the last N messages
/// (most recent context). Drop messages in the middle, replacing them with
/// a summary marker.
///
/// Tool-call groups (an assistant message with tool_calls followed by its
/// tool-result messages) are treated as atomic units — we never split them,
/// since OpenAI rejects orphaned tool_call_ids with a 400 "invalid JSON" error.
pub(super) fn trim_conversation(
    messages: &mut Vec<ChatMessage>,
    system: &str,
    tools: &[crate::ToolDefinition],
    config: &ContextConfig,
) {
    if config.max_context_tokens == 0 {
        return;
    }

    let total = estimate_context_tokens(system, messages, tools);
    if total <= config.max_context_tokens {
        return;
    }

    let min_keep = config.min_recent_messages;
    if messages.len() <= min_keep + 1 {
        // Not enough messages to trim
        return;
    }

    // Keep first message + last min_keep messages, drop the middle
    let mut drop_end = messages.len().saturating_sub(min_keep);
    if drop_end <= 1 {
        return;
    }

    // Adjust drop_end so we don't sever tool-call / tool-result pairs.
    // If the first kept message (at drop_end) is a tool-result, walk backward
    // to include the preceding assistant tool-call message in the kept set.
    while drop_end > 1 && is_tool_result(&messages[drop_end]) {
        drop_end -= 1;
    }

    // If after adjustment there's nothing left to drop, bail out.
    if drop_end <= 1 {
        return;
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
        return;
    }

    let dropped = drop_end - 1;
    let summary = format!(
        "[Context trimmed: {dropped} earlier messages removed to stay within token budget. \
         The conversation continues from the most recent exchanges.]"
    );

    // Replace middle section with summary
    messages.splice(
        1..drop_end,
        std::iter::once(ChatMessage::text(Role::User, &summary)),
    );

    debug!(
        dropped = dropped,
        remaining = messages.len(),
        estimated_tokens = estimate_context_tokens(system, messages, tools),
        "Trimmed conversation context"
    );
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
}
