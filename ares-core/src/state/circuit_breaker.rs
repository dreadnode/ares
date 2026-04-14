//! Circuit breaker pattern for Redis operation resilience.
//!
//! Provides a simple circuit breaker that tracks failures and temporarily
//! stops sending requests to a failing backend, giving it time to recover.
//!
//! # States
//!
//! - **Closed**: Normal operation. Failures are counted; when the threshold
//!   is reached the circuit opens.
//! - **Open**: All calls are rejected immediately. After `recovery_timeout`
//!   elapses, the circuit transitions to half-open.
//! - **HalfOpen**: A single probe call is allowed through. Success closes
//!   the circuit; failure re-opens it.

use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tracing::{debug, warn};

/// Internal state machine for the circuit breaker.
#[derive(Debug, Clone)]
pub enum CircuitState {
    /// Normal operation, counting consecutive failures.
    Closed { failure_count: u32 },
    /// Circuit is open, rejecting all calls until recovery timeout.
    Open { opened_at: Instant },
    /// Testing whether the backend has recovered.
    HalfOpen,
}

/// Errors produced by the circuit breaker.
#[derive(Debug)]
pub enum CircuitBreakerError {
    /// The circuit is open and rejecting calls.
    Open {
        /// Time remaining before the circuit will transition to half-open.
        remaining: Duration,
    },
    /// An inner operation failed (wraps the stringified error).
    Inner(String),
}

impl fmt::Display for CircuitBreakerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open { remaining } => {
                write!(
                    f,
                    "circuit breaker is open, retry after {:.1}s",
                    remaining.as_secs_f64()
                )
            }
            Self::Inner(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for CircuitBreakerError {}

/// A thread-safe circuit breaker for wrapping fallible operations.
///
/// # Example
///
/// ```rust
/// use ares_core::state::CircuitBreaker;
/// use std::time::Duration;
///
/// let cb = CircuitBreaker::new(3, Duration::from_secs(10));
///
/// // Wrap an async operation:
/// // let result = cb.execute(|| async { do_redis_call().await }).await;
/// ```
#[derive(Clone)]
pub struct CircuitBreaker {
    failure_threshold: u32,
    recovery_timeout: Duration,
    state: Arc<Mutex<CircuitState>>,
}

impl fmt::Debug for CircuitBreaker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().unwrap();
        f.debug_struct("CircuitBreaker")
            .field("failure_threshold", &self.failure_threshold)
            .field("recovery_timeout", &self.recovery_timeout)
            .field("state", &*state)
            .finish()
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(5, Duration::from_secs(30))
    }
}

impl CircuitBreaker {
    /// Create a new circuit breaker.
    ///
    /// - `failure_threshold`: number of consecutive failures before the circuit opens.
    /// - `recovery_timeout`: how long the circuit stays open before allowing a probe.
    pub fn new(failure_threshold: u32, recovery_timeout: Duration) -> Self {
        Self {
            failure_threshold,
            recovery_timeout,
            state: Arc::new(Mutex::new(CircuitState::Closed { failure_count: 0 })),
        }
    }

    /// Check whether a call should proceed.
    ///
    /// Returns `Ok(())` if the circuit is closed or half-open (probe allowed).
    /// Returns `Err(CircuitBreakerError::Open { remaining })` if the circuit
    /// is open and the recovery timeout has not yet elapsed.
    ///
    /// When the recovery timeout has elapsed, this method transitions the
    /// circuit from Open to HalfOpen and returns `Ok(())`.
    pub fn check(&self) -> Result<(), CircuitBreakerError> {
        let mut state = self.state.lock().unwrap();
        match *state {
            CircuitState::Closed { .. } => Ok(()),
            CircuitState::HalfOpen => Ok(()),
            CircuitState::Open { opened_at } => {
                let elapsed = opened_at.elapsed();
                if elapsed >= self.recovery_timeout {
                    debug!("circuit breaker transitioning to half-open");
                    *state = CircuitState::HalfOpen;
                    Ok(())
                } else {
                    Err(CircuitBreakerError::Open {
                        remaining: self.recovery_timeout - elapsed,
                    })
                }
            }
        }
    }

    /// Record a successful operation. Resets the failure count and closes
    /// the circuit if it was half-open.
    pub fn record_success(&self) {
        let mut state = self.state.lock().unwrap();
        match *state {
            CircuitState::HalfOpen => {
                debug!("circuit breaker closing after successful probe");
                *state = CircuitState::Closed { failure_count: 0 };
            }
            CircuitState::Closed { .. } => {
                *state = CircuitState::Closed { failure_count: 0 };
            }
            CircuitState::Open { .. } => {
                // Shouldn't normally happen, but reset anyway.
                *state = CircuitState::Closed { failure_count: 0 };
            }
        }
    }

    /// Record a failed operation. Increments the failure count and opens
    /// the circuit when the threshold is reached. If the circuit was
    /// half-open, it re-opens immediately.
    pub fn record_failure(&self) {
        let mut state = self.state.lock().unwrap();
        match *state {
            CircuitState::Closed { failure_count } => {
                let new_count = failure_count + 1;
                if new_count >= self.failure_threshold {
                    warn!(
                        threshold = self.failure_threshold,
                        "circuit breaker opening after {new_count} consecutive failures"
                    );
                    *state = CircuitState::Open {
                        opened_at: Instant::now(),
                    };
                } else {
                    *state = CircuitState::Closed {
                        failure_count: new_count,
                    };
                }
            }
            CircuitState::HalfOpen => {
                warn!("circuit breaker re-opening after failed probe");
                *state = CircuitState::Open {
                    opened_at: Instant::now(),
                };
            }
            CircuitState::Open { .. } => {
                // Already open; nothing to do.
            }
        }
    }

    /// Execute an async closure with circuit breaker protection.
    ///
    /// 1. Checks whether the circuit allows a call.
    /// 2. Runs the closure.
    /// 3. Records success or failure based on the result.
    /// 4. Returns the result or a `CircuitBreakerError`.
    pub async fn execute<F, Fut, T, E>(&self, f: F) -> Result<T, CircuitBreakerError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: fmt::Display,
    {
        self.check()?;

        match f().await {
            Ok(value) => {
                self.record_success();
                Ok(value)
            }
            Err(e) => {
                self.record_failure();
                Err(CircuitBreakerError::Inner(e.to_string()))
            }
        }
    }

    /// Return a snapshot of the current circuit state (mainly for testing/debugging).
    pub fn current_state(&self) -> CircuitState {
        self.state.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cb(threshold: u32, timeout: Duration) -> CircuitBreaker {
        CircuitBreaker::new(threshold, timeout)
    }

    #[test]
    fn stays_closed_on_success() {
        let cb = make_cb(3, Duration::from_secs(30));

        // Successive successes should keep the circuit closed.
        for _ in 0..10 {
            assert!(cb.check().is_ok());
            cb.record_success();
        }

        match cb.current_state() {
            CircuitState::Closed { failure_count } => assert_eq!(failure_count, 0),
            other => panic!("expected Closed, got {other:?}"),
        }
    }

    #[test]
    fn opens_after_threshold_failures() {
        let cb = make_cb(3, Duration::from_secs(30));

        // Two failures: still closed.
        cb.record_failure();
        cb.record_failure();
        assert!(cb.check().is_ok());

        // Third failure: should open.
        cb.record_failure();
        let err = cb.check().unwrap_err();
        assert!(matches!(err, CircuitBreakerError::Open { .. }));
    }

    #[test]
    fn success_resets_failure_count() {
        let cb = make_cb(3, Duration::from_secs(30));

        cb.record_failure();
        cb.record_failure();
        // One more would open it, but a success resets.
        cb.record_success();
        cb.record_failure();
        cb.record_failure();
        // Still closed because count was reset.
        assert!(cb.check().is_ok());
    }

    #[test]
    fn transitions_to_half_open_after_timeout() {
        let cb = make_cb(2, Duration::from_millis(10));

        cb.record_failure();
        cb.record_failure();
        // Circuit should be open now.
        assert!(cb.check().is_err());

        // Wait for the recovery timeout to elapse.
        std::thread::sleep(Duration::from_millis(15));

        // Should transition to half-open and allow the call.
        assert!(cb.check().is_ok());
        match cb.current_state() {
            CircuitState::HalfOpen => {}
            other => panic!("expected HalfOpen, got {other:?}"),
        }
    }

    #[test]
    fn successful_half_open_closes_circuit() {
        let cb = make_cb(2, Duration::from_millis(10));

        // Open the circuit.
        cb.record_failure();
        cb.record_failure();

        // Wait for timeout.
        std::thread::sleep(Duration::from_millis(15));
        assert!(cb.check().is_ok()); // transitions to half-open

        // Successful probe should close it.
        cb.record_success();
        match cb.current_state() {
            CircuitState::Closed { failure_count } => assert_eq!(failure_count, 0),
            other => panic!("expected Closed, got {other:?}"),
        }
    }

    #[test]
    fn failed_half_open_reopens_circuit() {
        let cb = make_cb(2, Duration::from_millis(10));

        // Open the circuit.
        cb.record_failure();
        cb.record_failure();

        // Wait for timeout.
        std::thread::sleep(Duration::from_millis(15));
        assert!(cb.check().is_ok()); // transitions to half-open

        // Failed probe should re-open.
        cb.record_failure();
        let err = cb.check().unwrap_err();
        assert!(matches!(err, CircuitBreakerError::Open { .. }));
    }

    #[tokio::test]
    async fn execute_records_success() {
        let cb = make_cb(3, Duration::from_secs(30));

        let result = cb.execute(|| async { Ok::<_, std::io::Error>(42) }).await;
        assert_eq!(result.unwrap(), 42);
        match cb.current_state() {
            CircuitState::Closed { failure_count } => assert_eq!(failure_count, 0),
            other => panic!("expected Closed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_records_failure() {
        let cb = make_cb(3, Duration::from_secs(30));

        for _ in 0..3 {
            let result = cb
                .execute(|| async { Err::<(), _>(std::io::Error::other("boom")) })
                .await;
            assert!(result.is_err());
        }

        // Circuit should be open now; execute should fail immediately.
        let result = cb.execute(|| async { Ok::<_, std::io::Error>(99) }).await;
        assert!(matches!(
            result.unwrap_err(),
            CircuitBreakerError::Open { .. }
        ));
    }

    #[test]
    fn default_has_sensible_values() {
        let cb = CircuitBreaker::default();
        assert_eq!(cb.failure_threshold, 5);
        assert_eq!(cb.recovery_timeout, Duration::from_secs(30));
        match cb.current_state() {
            CircuitState::Closed { failure_count } => assert_eq!(failure_count, 0),
            other => panic!("expected Closed, got {other:?}"),
        }
    }

    #[test]
    fn display_errors() {
        let open_err = CircuitBreakerError::Open {
            remaining: Duration::from_secs(10),
        };
        assert!(open_err.to_string().contains("10.0s"));

        let inner_err = CircuitBreakerError::Inner("connection refused".to_string());
        assert_eq!(inner_err.to_string(), "connection refused");
    }
}
