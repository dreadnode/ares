//! Blue team investigation orchestrator.
//!
//! Consumes investigation requests from `ares:blue:investigations`,
//! dispatches tasks to specialized agents (triage, threat_hunter,
//! lateral_analyst, escalation_triage) via the blue task queue,
//! and processes results.
//!
//! Parallels the red team orchestrator but drives SOC investigation
//! workflows instead of attack chains.

mod callbacks;
pub mod chaining;
mod investigation;
mod runner;
mod sub_agent;

pub use runner::spawn_blue_orchestrator;
