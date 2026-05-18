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

    let query_args = serde_json::json!({
        "logql": tmpl.logql,
        "start_time": start.to_rfc3339(),
        "end_time": now.to_rfc3339(),
        "limit": 100,
    });

    let mut result = loki::query_logs(&query_args).await?;
    result.stdout = format!("{}\n{}", tmpl.format_header(), result.stdout);
    Ok(result)
}

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
