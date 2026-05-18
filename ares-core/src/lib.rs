//! Core library for the Ares red team orchestration system.
//!
//! This crate provides the data models and Redis state backend used by the
//! `ares` binary to interact with the Ares orchestrator system.
//!
//! # Modules
//!
//! - [`models`] — Data model structs.
//! - [`state`] — Redis state backend with key patterns and read/write operations.

pub mod config;
#[cfg(feature = "blue")]
pub mod correlation;
#[cfg(feature = "blue")]
pub mod detection;
#[cfg(feature = "blue")]
pub mod eval;
pub mod models;
pub mod nats;
pub mod op_state_log;
pub mod parsing;
pub mod persistent_store;
pub mod reports;
pub mod state;
#[cfg(feature = "telemetry")]
pub mod telemetry;
pub mod token_usage;
