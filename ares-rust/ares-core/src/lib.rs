//! Core library for the Ares red team orchestration system.
//!
//! This crate provides the data models and Redis state backend used by the
//! `ares-cli` binary to interact with the Ares orchestrator system.
//!
//! # Modules
//!
//! - [`models`] — Data model structs matching the Python models exactly.
//! - [`state`] — Redis state backend with key patterns and read/write operations.

pub mod config;
pub mod models;
pub mod parsing;
pub mod state;
pub mod token_usage;

#[cfg(feature = "python")]
mod python;
