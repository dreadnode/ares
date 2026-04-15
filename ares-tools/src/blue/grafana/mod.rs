//! Grafana alerting and dashboard query tools.
//!
//! HTTP-based queries against Grafana's REST API for alerts, annotations,
//! and dashboard data.

pub mod annotate;
pub mod query;
pub mod rules;

use anyhow::{Context, Result};

use crate::ToolOutput;

pub(super) fn grafana_url() -> String {
    std::env::var("GRAFANA_URL").unwrap_or_else(|_| "http://localhost:3000".to_string())
}

pub(super) fn grafana_api_key() -> Option<String> {
    std::env::var("GRAFANA_SERVICE_ACCOUNT_TOKEN").ok()
}

pub(super) fn make_output(body: &str) -> ToolOutput {
    ToolOutput {
        stdout: body.to_string(),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    }
}

pub(super) fn make_error(msg: &str) -> ToolOutput {
    ToolOutput {
        stdout: String::new(),
        stderr: msg.to_string(),
        exit_code: Some(1),
        success: false,
    }
}

/// Build a reqwest client with optional Bearer token authentication.
pub(super) fn build_client() -> Result<reqwest::Client> {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(key) = grafana_api_key() {
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {key}"))
                .context("invalid API key characters")?,
        );
    }
    reqwest::Client::builder()
        .default_headers(headers)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("Failed to build HTTP client")
}

// Re-export all public functions so callers use grafana::get_alerts() etc.
pub use annotate::{create_annotation, post_investigation_completed, post_investigation_started};
pub use query::{get_alerts, get_annotations, get_dashboard, search_dashboards};
pub use rules::{create_detection_rule, get_alert_history, get_alerts_in_time_range};
