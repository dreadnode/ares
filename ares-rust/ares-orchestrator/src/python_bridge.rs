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
                    .context("Failed to import ares.agents")?;

                let kwargs = PyDict::new(py);
                kwargs.set_item("role", agent_role)?;
                kwargs.set_item("prompt", prompt)?;

                let result = agents_mod
                    .call_method("run_step", (), Some(&kwargs))
                    .context("Python agent step raised an exception")?;

                let response: String = result
                    .extract()
                    .context("Agent step did not return a string")?;

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
