use std::time::Instant;

use tracing::{field::Empty, info_span, warn, Instrument};

use crate::provider::{LlmError, LlmProvider, LlmRequest, LlmResponse};

use super::config::RetryConfig;

/// Call the LLM with retry on transient errors (rate limits, network failures).
///
/// Uses exponential backoff with jitter. Respects `Retry-After` headers from
/// rate-limited responses. Non-retryable errors (auth, context too long) fail
/// immediately.
pub(super) async fn call_with_retry(
    provider: &dyn LlmProvider,
    request: &LlmRequest,
    config: &RetryConfig,
    task_id: &str,
) -> Result<LlmResponse, LlmError> {
    let mut last_err: Option<LlmError> = None;

    for attempt in 0..=config.max_retries {
        // One span per attempt: durations and token counts have to be on the
        // attempt that produced them, otherwise rate-limit retries inflate
        // the wall-clock attributed to the successful call.
        let span = info_span!(
            "llm.call",
            "llm.model" = %request.model,
            "llm.attempt" = attempt,
            "llm.input_tokens" = Empty,
            "llm.output_tokens" = Empty,
            "llm.cache_read_tokens" = Empty,
            "llm.cache_creation_tokens" = Empty,
            "llm.tool_count" = request.tools.len(),
            "llm.message_count" = request.messages.len(),
            "llm.duration_ms" = Empty,
            "llm.stop_reason" = Empty,
            "llm.error" = Empty,
            "task.id" = task_id,
        );
        let start = Instant::now();
        let result = provider.chat(request).instrument(span.clone()).await;
        let duration_ms = start.elapsed().as_millis() as u64;
        span.record("llm.duration_ms", duration_ms);
        match &result {
            Ok(response) => {
                span.record("llm.input_tokens", response.usage.input_tokens);
                span.record("llm.output_tokens", response.usage.output_tokens);
                span.record(
                    "llm.cache_read_tokens",
                    response.usage.cache_read_input_tokens,
                );
                span.record(
                    "llm.cache_creation_tokens",
                    response.usage.cache_creation_input_tokens,
                );
                span.record(
                    "llm.stop_reason",
                    format!("{:?}", response.stop_reason).as_str(),
                );
            }
            Err(e) => {
                span.record("llm.error", format!("{e}").as_str());
            }
        }

        match result {
            Ok(response) => return Ok(response),
            Err(e) => {
                if !e.is_retryable() || attempt == config.max_retries {
                    return Err(e);
                }

                // Calculate delay: use Retry-After if available, otherwise exponential backoff
                let backoff_ms = config.base_delay_ms.saturating_mul(1u64 << attempt.min(10));
                let delay_ms = e
                    .retry_after_ms()
                    .unwrap_or(backoff_ms)
                    .min(config.max_delay_ms);

                // Add jitter: ±25% of the delay
                let jitter = delay_ms / 4;
                let jittered = if jitter > 0 {
                    let offset =
                        (simple_hash(attempt, task_id) % (jitter * 2)) as i64 - jitter as i64;
                    (delay_ms as i64 + offset).max(100) as u64
                } else {
                    delay_ms
                };

                warn!(
                    err = %e,
                    attempt = attempt + 1,
                    max_retries = config.max_retries,
                    delay_ms = jittered,
                    task_id = task_id,
                    "LLM call failed, retrying"
                );

                tokio::time::sleep(tokio::time::Duration::from_millis(jittered)).await;
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| LlmError::Other(anyhow::anyhow!("retry exhausted"))))
}

/// Simple deterministic hash for jitter (avoids rand dependency).
pub(super) fn simple_hash(attempt: u32, task_id: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in task_id.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h ^= attempt as u64;
    h = h.wrapping_mul(0x100000001b3);
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_hash_deterministic() {
        let h1 = simple_hash(0, "task-123");
        let h2 = simple_hash(0, "task-123");
        assert_eq!(h1, h2);
    }

    #[test]
    fn simple_hash_different_attempts() {
        let h0 = simple_hash(0, "task-abc");
        let h1 = simple_hash(1, "task-abc");
        assert_ne!(h0, h1);
    }

    #[test]
    fn simple_hash_different_task_ids() {
        let ha = simple_hash(0, "task-a");
        let hb = simple_hash(0, "task-b");
        assert_ne!(ha, hb);
    }

    #[test]
    fn simple_hash_empty_task_id() {
        // Should not panic
        let h = simple_hash(0, "");
        assert_ne!(h, 0);
    }

    #[test]
    fn simple_hash_large_attempt() {
        // Should not panic or overflow
        let h = simple_hash(u32::MAX, "task-xyz");
        assert_ne!(h, 0);
    }
}
