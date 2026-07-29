//! Detection query execution — calls Loki and aggregates results.

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_i64, optional_str, required_str};
use crate::ToolOutput;

use super::super::loki;
use super::config::detection_config;
use super::templates::build_detection_template;
use super::{build_event_filter, build_selector, WIN_SECURITY};

/// Run a pre-built detection query template.
pub async fn run_detection_query(args: &Value) -> Result<ToolOutput> {
    let query_name = required_str(args, "query_name")?;
    let target_host = optional_str(args, "target_host");
    // Clamp to max 2h — larger windows timeout through Grafana proxy (~90s per query)
    let hours_back = optional_i64(args, "hours_back").unwrap_or(1).min(2);

    let Some(tmpl) = build_detection_template(query_name, target_host) else {
        return Ok(ToolOutput {
            stdout: String::new(),
            stderr: format!(
                "Unknown detection template: '{query_name}'. Use list_detection_templates to see available templates."
            ),
            exit_code: Some(1),
            success: false,
        });
    };

    let now = chrono::Utc::now();
    let start = now - chrono::Duration::hours(hours_back);

    // Running a catalog template is catalog work whoever dispatched it, so the
    // results carry the same provenance the deterministic sweep writes. Without
    // this, an analyst re-running a template has its hits counted as
    // independent analyst evidence in the report's provenance split.
    let query_args = serde_json::json!({
        "logql": tmpl.logql,
        "start_time": start.to_rfc3339(),
        "end_time": now.to_rfc3339(),
        "limit": 100,
        "evidence_source": format!(
            "{}:{query_name}",
            super::super::evidence_validator::CATALOG_QUERY_SOURCE_PREFIX
        ),
    });

    let mut result = loki::query_logs(&query_args).await?;
    result.stdout = format!("{}\n{}", tmpl.format_header(), result.stdout);
    Ok(result)
}

/// What a detection template matched, with the event times preserved.
#[derive(Debug, Clone, Default)]
pub struct DetectionEvents {
    pub event_count: usize,
    /// Earliest matched event — the anchor for "did this detection follow the
    /// attacker action it is credited to?".
    pub first_event_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_event_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Hosts the matched events came from, from the stream labels.
    pub hosts: Vec<String>,
}

fn scan_start(
    now: chrono::DateTime<chrono::Utc>,
    hours_back: i64,
    not_before: Option<chrono::DateTime<chrono::Utc>>,
) -> chrono::DateTime<chrono::Utc> {
    let lookback = now - chrono::Duration::hours(hours_back.min(2));
    match not_before {
        Some(nb) if nb > lookback => nb,
        _ => lookback,
    }
}

/// Run a detection template and return its matches with event timestamps.
///
/// [`run_detection_query`] answers the same question as formatted text, which
/// forces callers to scrape a count back out of prose and leaves them with no
/// event times at all. Correlating a detection against attacker activity needs
/// both, so this returns the aggregate directly.
///
/// An unknown template is an error rather than an empty result — silently
/// scoring a typo'd template as "no matches" would understate coverage.
///
/// `not_before` clamps the scan to an operation's attack window. It can only
/// narrow the `hours_back` window, never widen it. Without it a detection whose
/// events straddle the window start reports a `first_event_at` from before the
/// operation began, and that timestamp is what lands in the investigation
/// timeline — dating this operation's detections to activity that predates it.
pub async fn run_detection_query_events(
    query_name: &str,
    target_host: Option<&str>,
    hours_back: i64,
    not_before: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<DetectionEvents> {
    let Some(tmpl) = build_detection_template(query_name, target_host) else {
        anyhow::bail!("Unknown detection template: '{query_name}'");
    };

    let now = chrono::Utc::now();
    let start = scan_start(now, hours_back, not_before);

    let entries = loki::query_log_entries(
        &tmpl.logql,
        &start.to_rfc3339(),
        &now.to_rfc3339(),
        DETECTION_ENTRY_LIMIT,
    )
    .await?;

    if !entries.is_empty() {
        let joined = entries
            .iter()
            .map(|e| e.line.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        super::super::evidence_validator::store_query_result_from(
            &joined,
            &format!(
                "{}:{query_name}",
                super::super::evidence_validator::CATALOG_QUERY_SOURCE_PREFIX
            ),
        );
    }

    let mut hosts: Vec<String> = entries
        .iter()
        .filter_map(|e| {
            HOST_LABEL_KEYS
                .iter()
                .find_map(|k| e.labels.get(*k))
                .cloned()
        })
        .collect();
    hosts.sort();
    hosts.dedup();

    Ok(DetectionEvents {
        event_count: entries.len(),
        first_event_at: entries.first().map(|e| e.timestamp),
        last_event_at: entries.last().map(|e| e.timestamp),
        hosts,
    })
}

/// Stream labels that carry the originating host, most specific first.
const HOST_LABEL_KEYS: &[&str] = &["hostname", "host", "computer", "instance", "agent_hostname"];

/// Line cap for a structured detection query. Matches the formatted path's
/// limit so the two cannot disagree about whether a template fired.
const DETECTION_ENTRY_LIMIT: i64 = 100;

/// Run multiple detection queries in parallel.
pub async fn run_parallel_detections(args: &Value) -> Result<ToolOutput> {
    let query_names = args
        .get("query_names")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let target_host = optional_str(args, "target_host");
    let hours_back = optional_i64(args, "hours_back").unwrap_or(1).min(2);
    let max_concurrent = optional_i64(args, "max_concurrent").unwrap_or(5) as usize;

    let mut output_parts = Vec::new();

    // Process in batches
    for batch in query_names.chunks(max_concurrent) {
        let mut handles = Vec::new();
        for name in batch {
            let name = name.clone();
            let host = target_host.map(|s| s.to_string());
            handles.push(tokio::spawn(async move {
                let query_args = serde_json::json!({
                    "query_name": name,
                    "target_host": host,
                    "hours_back": hours_back,
                });
                let result = run_detection_query(&query_args).await;
                (name, result)
            }));
        }

        for handle in handles {
            match handle.await {
                Ok((name, Ok(output))) => {
                    if output.success {
                        output_parts.push(output.stdout);
                    } else {
                        output_parts.push(format!("### {name}\nError: {}", output.stderr));
                    }
                }
                Ok((name, Err(e))) => {
                    output_parts.push(format!("### {name}\nError: {e}"));
                }
                Err(e) => {
                    output_parts.push(format!("### Query failed\nError: {e}"));
                }
            }
        }
    }

    Ok(ToolOutput {
        stdout: format!(
            "Parallel detections completed: {}/{} queries\n\n---\n\n{}",
            output_parts.len(),
            query_names.len(),
            output_parts.join("\n\n---\n\n")
        ),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    })
}

/// Get all activity for a specific host.
pub async fn get_host_activity(args: &Value) -> Result<ToolOutput> {
    let hostname = required_str(args, "hostname")?;
    let hours_back = optional_i64(args, "hours_back").unwrap_or(1).min(2);
    let attack_patterns_only = args
        .get("attack_patterns_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let sel = build_selector(WIN_SECURITY, Some(hostname));

    let config = detection_config();
    let scope = if attack_patterns_only {
        "host_attack_patterns"
    } else {
        "host_all_security"
    };
    let scope_ids = &config.activity_scopes[scope];
    let id_refs: Vec<&str> = scope_ids.iter().map(|s| s.as_str()).collect();
    let event_filter = build_event_filter(&id_refs);
    let logql = format!("{sel}{event_filter}");

    let now = chrono::Utc::now();
    let start = now - chrono::Duration::hours(hours_back);

    let query_args = serde_json::json!({
        "logql": logql,
        "start_time": start.to_rfc3339(),
        "end_time": now.to_rfc3339(),
        "limit": 200,
    });

    let mut result = loki::query_logs(&query_args).await?;
    result.stdout = format!(
        "## Host Activity: {hostname}\n**Query:** `{logql}`\n**Attack patterns only:** {attack_patterns_only}\n\n{}",
        result.stdout
    );
    Ok(result)
}

/// Get all activity for a specific user.
pub async fn get_user_activity(args: &Value) -> Result<ToolOutput> {
    let username = required_str(args, "username")?;
    let hours_back = optional_i64(args, "hours_back").unwrap_or(1).min(2);

    let sel = build_selector(WIN_SECURITY, None);
    let config = detection_config();
    let scope_ids = &config.activity_scopes["user_activity"];
    let id_refs: Vec<&str> = scope_ids.iter().map(|s| s.as_str()).collect();
    let event_filter = build_event_filter(&id_refs);
    // Escape regex metacharacters in the username so that special characters
    // (e.g. `.`, `+`, `(`) do not corrupt the LogQL regex or match unintended lines.
    let escaped_username = regex::escape(username);
    let logql = format!(r#"{sel}{event_filter} |~ "(?i){escaped_username}""#);

    let now = chrono::Utc::now();
    let start = now - chrono::Duration::hours(hours_back);

    let query_args = serde_json::json!({
        "logql": logql,
        "start_time": start.to_rfc3339(),
        "end_time": now.to_rfc3339(),
        "limit": 200,
    });

    let mut result = loki::query_logs(&query_args).await?;
    result.stdout = format!(
        "## User Activity: {username}\n**Query:** `{logql}`\n\n{}",
        result.stdout
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::scan_start;

    fn t(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn attack_window_start_narrows_the_scan() {
        let now = t("2026-07-28T01:52:00+00:00");
        assert_eq!(
            scan_start(now, 2, Some(t("2026-07-28T01:37:51+00:00"))),
            t("2026-07-28T01:37:51+00:00")
        );
    }

    #[test]
    fn attack_window_start_never_widens_the_scan() {
        // A window opening before the lookback must not pull in more history:
        // the runner's 2h clamp exists because wider Loki queries time out.
        let now = t("2026-07-28T01:52:00+00:00");
        assert_eq!(
            scan_start(now, 2, Some(t("2026-07-01T00:00:00+00:00"))),
            t("2026-07-27T23:52:00+00:00")
        );
    }

    #[test]
    fn without_a_window_the_lookback_is_unchanged() {
        let now = t("2026-07-28T01:52:00+00:00");
        assert_eq!(scan_start(now, 2, None), t("2026-07-27T23:52:00+00:00"));
    }

    #[test]
    fn hours_back_stays_clamped_to_two() {
        let now = t("2026-07-28T01:52:00+00:00");
        assert_eq!(scan_start(now, 24, None), t("2026-07-27T23:52:00+00:00"));
    }
}
