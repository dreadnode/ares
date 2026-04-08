//! PyO3 bridge for calling Python agent steps from Rust.
//!
//! The key principle: Rust owns the event loop and all Redis IO. Python is
//! only called for the LLM agent step (prompt in, action out). The GIL is
//! acquired only for the duration of the Python call and released for all
//! other work.
//!
//! When the `python` feature is disabled (the default), a mock implementation
//! is provided that returns a static response. This allows `cargo test` to
//! run without a Python interpreter.

use anyhow::Result;
use tracing::{debug, info};

// ---------------------------------------------------------------------------
// Feature-gated implementations
// ---------------------------------------------------------------------------

/// Trait abstracting the Python agent interface.
pub trait AgentBridge: Send + Sync {
    /// Call a Python agent step with the given prompt.
    ///
    /// The returned string is the agent's response (tool calls, reasoning,
    /// or a final answer).
    fn call_agent_step(&self, agent_role: &str, prompt: &str) -> Result<String>;

    /// Initialize the Python interpreter and import required modules.
    fn initialize(&self) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Real PyO3 bridge (compiled only with `python` feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "python")]
pub mod real {
    use super::*;
    use pyo3::prelude::*;
    use pyo3::types::PyDict;
    use std::sync::Once;

    static INIT: Once = Once::new();

    /// Bridge that calls into the real Python `ares.agents` module via PyO3.
    pub struct PyAgentBridge;

    impl PyAgentBridge {
        pub fn new() -> Self {
            Self
        }
    }

    impl AgentBridge for PyAgentBridge {
        fn initialize(&self) -> Result<()> {
            INIT.call_once(|| {
                pyo3::prepare_freethreaded_python();
                info!("Python interpreter initialized");
            });

            // Verify we can import the agent module
            Python::with_gil(|py| {
                py.import("ares.agents")
                    .map_err(|e| anyhow::anyhow!("Failed to import ares.agents: {}", e))?;
                info!("ares.agents module imported successfully");
                Ok(())
            })
        }

        fn call_agent_step(&self, agent_role: &str, prompt: &str) -> Result<String> {
            debug!(
                role = agent_role,
                prompt_len = prompt.len(),
                "Calling Python agent step"
            );

            // Acquire the GIL only for the Python call.
            // All Redis IO happens outside this block.
            Python::with_gil(|py| {
                let agents_mod = py
                    .import("ares.agents")
                    .map_err(|e| anyhow::anyhow!("Failed to import ares.agents: {e}"))?;

                let kwargs = PyDict::new(py);
                kwargs
                    .set_item("role", agent_role)
                    .map_err(|e| anyhow::anyhow!("Failed to set kwargs: {e}"))?;
                kwargs
                    .set_item("prompt", prompt)
                    .map_err(|e| anyhow::anyhow!("Failed to set kwargs: {e}"))?;

                let result = agents_mod
                    .call_method("run_step", (), Some(&kwargs))
                    .map_err(|e| anyhow::anyhow!("Python agent step raised an exception: {e}"))?;

                let response: String = result
                    .extract()
                    .map_err(|e| anyhow::anyhow!("Agent step did not return a string: {e}"))?;

                debug!(
                    role = agent_role,
                    response_len = response.len(),
                    "Python agent step completed"
                );
                Ok(response)
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Mock bridge (default, no Python dependency)
// ---------------------------------------------------------------------------

pub mod mock {
    use super::*;

    /// Mock bridge for testing without a Python interpreter.
    pub struct MockAgentBridge;

    impl MockAgentBridge {
        pub fn new() -> Self {
            Self
        }
    }

    impl AgentBridge for MockAgentBridge {
        fn initialize(&self) -> Result<()> {
            info!("Mock Python bridge initialized (no real Python)");
            Ok(())
        }

        fn call_agent_step(&self, agent_role: &str, prompt: &str) -> Result<String> {
            debug!(
                role = agent_role,
                prompt_len = prompt.len(),
                "Mock agent step called"
            );
            Ok(format!(
                "{{\"action\": \"noop\", \"reason\": \"mock bridge for role {agent_role}\"}}"
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Create the appropriate bridge based on compiled features.
pub fn create_bridge() -> Box<dyn AgentBridge> {
    #[cfg(feature = "python")]
    {
        Box::new(real::PyAgentBridge::new())
    }
    #[cfg(not(feature = "python"))]
    {
        Box::new(mock::MockAgentBridge::new())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Mock bridge tests (run without Python, default test suite) ────────

    #[test]
    fn test_create_bridge_succeeds() {
        // Should succeed without Python — returns the mock bridge.
        let bridge = create_bridge();
        // Just verify we got something back (type-erased Box<dyn AgentBridge>).
        assert!(bridge.initialize().is_ok());
    }

    #[test]
    fn test_mock_bridge_initialize() {
        let bridge = mock::MockAgentBridge::new();
        let result = bridge.initialize();
        assert!(result.is_ok());
    }

    #[test]
    fn test_mock_bridge_call_agent_step_returns_noop() {
        let bridge = mock::MockAgentBridge::new();
        let result = bridge.call_agent_step("recon", "test prompt");
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(
            output.contains("noop"),
            "Mock bridge should return a noop action, got: {output}"
        );
    }

    #[test]
    fn test_mock_bridge_includes_role_in_response() {
        let bridge = mock::MockAgentBridge::new();
        let output = bridge.call_agent_step("privesc", "escalate").unwrap();
        assert!(
            output.contains("privesc"),
            "Mock response should include the agent role, got: {output}"
        );
    }

    #[test]
    fn test_mock_bridge_returns_valid_json() {
        let bridge = mock::MockAgentBridge::new();
        let output = bridge.call_agent_step("recon", "scan 10.0.0.1").unwrap();
        let parsed: serde_json::Result<serde_json::Value> = serde_json::from_str(&output);
        assert!(
            parsed.is_ok(),
            "Mock bridge should return valid JSON, got: {output}"
        );
    }

    #[test]
    fn test_mock_bridge_different_roles() {
        let bridge = mock::MockAgentBridge::new();
        for role in &["recon", "privesc", "credential_access", "lateral_movement"] {
            let output = bridge.call_agent_step(role, "test").unwrap();
            assert!(
                output.contains(role),
                "Response for role '{role}' should include role name, got: {output}"
            );
        }
    }

    #[test]
    fn test_mock_bridge_handles_empty_prompt() {
        let bridge = mock::MockAgentBridge::new();
        let result = bridge.call_agent_step("recon", "");
        assert!(result.is_ok(), "Mock bridge should handle empty prompts");
    }

    #[test]
    fn test_mock_bridge_handles_large_prompt() {
        let bridge = mock::MockAgentBridge::new();
        let large_prompt = "x".repeat(100_000);
        let result = bridge.call_agent_step("recon", &large_prompt);
        assert!(result.is_ok(), "Mock bridge should handle large prompts");
    }

    // ── Trait object tests ───────────────────────────────────────────────

    #[test]
    fn test_bridge_trait_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<mock::MockAgentBridge>();
        // Also verify the trait object is Send + Sync (required for Arc sharing).
        fn assert_boxed_send_sync<T: Send + Sync + ?Sized>() {}
        assert_boxed_send_sync::<dyn AgentBridge>();
    }

    #[test]
    fn test_bridge_usable_through_trait_object() {
        // Verify the bridge works when used via Box<dyn AgentBridge>,
        // which is how main.rs uses it.
        let bridge: Box<dyn AgentBridge> = create_bridge();
        bridge.initialize().unwrap();
        let result = bridge.call_agent_step("recon", "test").unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_bridge_usable_through_arc() {
        // The orchestrator may share the bridge across tasks via Arc.
        let bridge: std::sync::Arc<dyn AgentBridge> = std::sync::Arc::from(create_bridge());
        let result = bridge.call_agent_step("recon", "test").unwrap();
        assert!(!result.is_empty());
    }

    // ── Feature-gated Python integration tests ───────────────────────────

    #[cfg(feature = "python")]
    mod python_integration {
        use super::super::*;

        #[test]
        #[ignore] // requires Python environment with ares package installed
        fn test_python_bridge_initializes() {
            let bridge = real::PyAgentBridge::new();
            let result = bridge.initialize();
            assert!(
                result.is_ok(),
                "Python bridge should initialize: {:?}",
                result.err()
            );
        }

        #[test]
        #[ignore] // requires Python environment with ares package installed
        fn test_python_bridge_agent_step() {
            let bridge = real::PyAgentBridge::new();
            bridge.initialize().expect("Failed to initialize bridge");
            let result = bridge.call_agent_step("recon", "Enumerate targets");
            assert!(
                result.is_ok(),
                "Python agent step should succeed: {:?}",
                result.err()
            );
            let output = result.unwrap();
            assert!(
                !output.is_empty(),
                "Agent step should return non-empty output"
            );
        }

        #[test]
        #[ignore] // requires Python environment with ares package installed
        fn test_python_bridge_multiple_calls() {
            // Verify the bridge can handle multiple sequential calls
            // (GIL acquisition/release cycle works correctly).
            let bridge = real::PyAgentBridge::new();
            bridge.initialize().expect("Failed to initialize bridge");
            for i in 0..3 {
                let result = bridge.call_agent_step("recon", &format!("Step {i}"));
                assert!(
                    result.is_ok(),
                    "Call {i} should succeed: {:?}",
                    result.err()
                );
            }
        }

        #[test]
        #[ignore] // requires Python environment with ares package installed
        fn test_gil_not_held_during_struct_creation() {
            // Creating multiple bridge instances from different threads should not
            // deadlock — struct creation must not hold the GIL.
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    std::thread::spawn(|| {
                        let _bridge = real::PyAgentBridge::new();
                    })
                })
                .collect();
            for h in handles {
                h.join()
                    .expect("Thread should not panic during bridge creation");
            }
        }
    }
}
