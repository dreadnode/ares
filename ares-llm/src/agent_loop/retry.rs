use tracing::warn;

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
        match provider.chat(request).await {
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
