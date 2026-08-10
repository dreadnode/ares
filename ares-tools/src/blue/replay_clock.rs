//! Re-export of the shared replay clock (see [`ares_core::replay_clock`]).
//!
//! The implementation lives in `ares-core` so `ares-tools` and `ares-llm` share
//! a single clock source rather than each re-implementing the env parse. Kept as
//! a module here so existing `crate::blue::replay_clock::*` /
//! `super::replay_clock::*` call sites in the blue tools resolve unchanged.
pub use ares_core::replay_clock::*;
