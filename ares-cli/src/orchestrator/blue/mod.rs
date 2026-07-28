//! Blue team investigation orchestrator.
//!
//! Consumes investigation requests from `ares:blue:investigations`,
//! dispatches tasks to specialized agents (triage, threat_hunter,
//! lateral_analyst, escalation_triage) via the blue task queue,
//! and processes results.
//!
//! Parallels the red team orchestrator but drives SOC investigation
//! workflows instead of attack chains.

pub mod auto_submit;
mod callbacks;
pub mod chaining;
mod investigation;
pub(crate) mod runner;
mod simulated_response;
mod sub_agent;
mod sweep;

pub use auto_submit::spawn_blue_auto_submit;
pub use runner::spawn_blue_orchestrator;
