//! Lateral movement analysis for investigation scope expansion.
//!
//! Provides:
//! 1. Graph representation of host-to-host connections
//! 2. Detection of lateral movement patterns
//! 3. Pivot suggestions for investigation scope expansion
//! 4. Attack path reconstruction

mod analyzer;
mod graph;
mod patterns;

pub use analyzer::{looks_like_hostname, LateralMovementAnalyzer};
pub use graph::{mitre_for_connection, HostConnection, LateralGraph};
pub use patterns::{LateralPatterns, HOSTNAME_RE, IP_RE};

#[cfg(test)]
mod tests;
