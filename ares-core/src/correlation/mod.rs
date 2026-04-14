//! Correlation and analysis engines for red-blue team assessment.
//!
//! # Modules
//!
//! - [`alert`] — Alert clustering and correlation for grouping related alerts.
//! - [`lateral`] — Lateral movement graph analysis and pivot suggestions.
//! - [`redblue`] — Red-blue correlation engine for detection coverage analysis.

pub mod alert;
pub mod lateral;
pub mod redblue;
