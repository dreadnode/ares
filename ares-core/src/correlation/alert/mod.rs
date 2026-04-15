//! Alert correlation engine for grouping related alerts.
//!
//! Provides:
//! 1. Alert clustering based on shared characteristics (hosts, users, IPs, techniques)
//! 2. Similarity scoring between alerts
//! 3. Correlation context for investigations

mod cluster;
mod correlator;

pub use cluster::AlertCluster;
pub use correlator::AlertCorrelator;

#[cfg(test)]
mod tests;
