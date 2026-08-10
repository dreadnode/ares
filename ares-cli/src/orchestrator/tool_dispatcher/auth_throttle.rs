//! Per-credential auth throttle to prevent AD account lockout.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tracing::debug;

/// Per-credential auth attempt tracker.
///
/// Tracks timestamps of auth-bearing tool dispatches keyed by `user@domain`.
/// Before dispatching, callers must call `acquire()` which sleeps if the
/// credential has been used too many times within the observation window.
///
/// Configured by the orchestrator; see `ARES_AUTH_THROTTLE_MAX_ATTEMPTS` and
/// `ARES_AUTH_THROTTLE_WINDOW_SECS`.
///
/// This throttle only covers tools that name a single authenticating
/// principal, because [`super::extract_credential_key`] keys on the
/// `username` argument. `password_spray` has no `username` — it takes a
/// `users_file` — so it is **not** throttled here despite appearing in
/// `AUTH_BEARING_TOOLS`. Spray lockout is bounded at the tool instead, by
/// the per-account password cap in `ares_tools::credential_access`.
#[derive(Clone)]
pub struct AuthThrottle {
    pub(super) inner: Arc<Mutex<AuthThrottleInner>>,
}

pub(super) struct AuthThrottleInner {
    /// `credential_key` → Vec of timestamps
    pub(super) attempts: std::collections::HashMap<String, Vec<Instant>>,
    /// Max auth attempts per credential within the observation window.
    pub(super) max_attempts: usize,
    /// Observation window for rate limiting.
    pub(super) window: Duration,
}

impl AuthThrottle {
    pub fn new(max_attempts: usize, window: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(AuthThrottleInner {
                attempts: std::collections::HashMap::new(),
                max_attempts,
                window,
            })),
        }
    }

    /// Acquire permission to dispatch an auth-bearing tool call.
    /// Sleeps if the credential has hit the rate limit within the window.
    pub async fn acquire(&self, credential_key: &str) {
        loop {
            let sleep_dur = {
                let mut inner = self.inner.lock().await;
                let now = Instant::now();
                let max_attempts = inner.max_attempts;
                let window = inner.window;

                let timestamps = inner
                    .attempts
                    .entry(credential_key.to_string())
                    .or_default();

                timestamps.retain(|t| now.duration_since(*t) < window);

                if timestamps.len() < max_attempts {
                    // Under the limit — record this attempt and proceed
                    timestamps.push(now);
                    return;
                }

                // Over the limit — calculate how long to wait until the oldest
                // attempt falls outside the window
                let oldest = timestamps[0];
                let elapsed = now.duration_since(oldest);
                if elapsed >= window {
                    // Edge case: already expired, prune and retry
                    timestamps.remove(0);
                    timestamps.push(now);
                    return;
                }

                window - elapsed + Duration::from_millis(100)
            };

            debug!(
                credential = credential_key,
                wait_secs = sleep_dur.as_secs_f32(),
                "Auth throttle: delaying tool dispatch to avoid account lockout"
            );
            tokio::time::sleep(sleep_dur).await;
        }
    }
}
