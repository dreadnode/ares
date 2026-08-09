//! Alert rule management: create detection rules and query alert history.

use anyhow::{Context, Result};
use serde_json::Value;

use crate::args::{optional_i64, optional_str, required_str};
use crate::ToolOutput;

use super::{build_client, grafana_url, make_error, make_output};

use ares_core::detection::rule_creation_enabled;

const RULE_FOLDER_UID: &str = "ares-security";
const RULE_GROUP: &str = "ares-detections";

/// Parse a Grafana evaluation interval ("30s", "5m", "1h") into seconds.
///
/// Grafana requires group intervals to be a positive multiple of the base
/// interval (10s by default); anything else is rejected rather than coerced.
fn parse_duration_seconds(raw: &str) -> Option<i64> {
    let trimmed = raw.trim();
    let (digits, multiplier) = if let Some(d) = trimmed.strip_suffix('s') {
        (d, 1)
    } else if let Some(d) = trimmed.strip_suffix('m') {
        (d, 60)
    } else if let Some(d) = trimmed.strip_suffix('h') {
        (d, 3600)
    } else {
        (trimmed, 1)
    };
    let seconds = digits.trim().parse::<i64>().ok()?.checked_mul(multiplier)?;
    (seconds >= 0).then_some(seconds)
}

fn parse_interval_seconds(raw: &str) -> Option<i64> {
    let seconds = parse_duration_seconds(raw)?;
    (seconds >= 10 && seconds % 10 == 0).then_some(seconds)
}

/// Render a second count back into Grafana/LogQL duration notation.
fn format_interval(seconds: i64) -> String {
    if seconds % 3600 == 0 {
        format!("{}h", seconds / 3600)
    } else if seconds % 60 == 0 {
        format!("{}m", seconds / 60)
    } else {
        format!("{seconds}s")
    }
}

/// Build the provisioning payload for a detection rule.
///
/// The lookback window is pinned to `pending_period + interval` so consecutive
/// evaluations tile the timeline with no blind gap, and a match stays inside
/// the window long enough for the pending period to elapse. A shorter lookback
/// drops the match before `for` is satisfied and the rule can never fire.
fn build_rule_body(
    title: &str,
    logql_query: &str,
    description: &str,
    mitre_technique: &str,
    severity: &str,
    pending_period: &str,
    interval_seconds: i64,
) -> Value {
    let lookback_seconds =
        interval_seconds.saturating_add(parse_duration_seconds(pending_period).unwrap_or(0));
    let window = format_interval(lookback_seconds);
    let wrapped_query = format!("count_over_time({logql_query} [{window}]) > 0");
    let mut labels = serde_json::json!({
        "severity": severity,
        "source": "ares",
    });
    if !mitre_technique.is_empty() {
        labels["mitre_technique"] = serde_json::json!(mitre_technique);
    }

    serde_json::json!({
        "folderUID": RULE_FOLDER_UID,
        "ruleGroup": RULE_GROUP,
        "title": title,
        "condition": "C",
        "noDataState": "OK",
        "execErrState": "OK",
        "for": pending_period,
        "annotations": {
            "summary": description,
            "description": format!("Auto-created by ARES. LogQL: {logql_query}"),
        },
        "labels": labels,
        "data": [
            {
                "refId": "A",
                "relativeTimeRange": { "from": lookback_seconds, "to": 0 },
                "datasourceUid": "loki",
                "model": {
                    "expr": wrapped_query,
                    "refId": "A",
                },
            },
            {
                "refId": "C",
                "relativeTimeRange": { "from": 0, "to": 0 },
                "datasourceUid": "__expr__",
                "model": {
                    "type": "threshold",
                    "refId": "C",
                    "expression": "A",
                    "conditions": [{
                        "evaluator": { "type": "gt", "params": [0.0] },
                    }],
                },
            },
        ],
    })
}

/// Set the evaluation cadence on the rule group and read back what Grafana kept.
///
/// `POST /api/v1/provisioning/alert-rules` discards any per-rule
/// `intervalSeconds` — Grafana overwrites it with the group's interval (or the
/// 60s default for a group it has just created). Cadence therefore has to be
/// written to the group, and the returned value is what actually applies.
async fn sync_group_interval(
    client: &reqwest::Client,
    interval_seconds: i64,
) -> Result<i64, String> {
    let url = format!(
        "{}/api/v1/provisioning/folder/{RULE_FOLDER_UID}/rule-groups/{RULE_GROUP}",
        grafana_url()
    );

    let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("GET rule group returned {status}: {body}"));
    }
    let mut group: Value =
        serde_json::from_str(&body).map_err(|e| format!("unparsable rule group: {e}"))?;
    group["interval"] = serde_json::json!(interval_seconds);

    let put = client
        .put(&url)
        .json(&group)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let put_status = put.status();
    let put_body = put.text().await.unwrap_or_default();
    if !put_status.is_success() {
        return Err(format!("PUT rule group returned {put_status}: {put_body}"));
    }

    let confirm = client.get(&url).send().await.map_err(|e| e.to_string())?;
    let confirm_body = confirm.text().await.unwrap_or_default();
    serde_json::from_str::<Value>(&confirm_body)
        .ok()
        .and_then(|g| g.get("interval").and_then(Value::as_i64))
        .ok_or_else(|| "rule group reported no interval after update".to_string())
}

/// Create a detection alert rule in Grafana.
///
/// Gated behind `ARES_BLUE_ALLOW_RULE_CREATION`; returns a tool error without
/// contacting Grafana when unset.
///
/// Parameters:
/// - `title` (required): Rule name
/// - `logql_query` (required): LogQL query for detection
/// - `description` (optional)
/// - `mitre_technique` (optional): Associated MITRE technique
/// - `severity` (optional): "critical", "high", "medium", "low" (default: "medium")
/// - `evaluation_interval` (optional): e.g. "5m" (default: "5m"). Grafana keeps
///   cadence per group, so this resets the shared `ares-detections` group and
///   changes every rule already in it.
/// - `pending_period` (optional): e.g. "0s" (default: "0s")
pub async fn create_detection_rule(args: &Value) -> Result<ToolOutput> {
    let title = required_str(args, "title")?;
    let logql_query = required_str(args, "logql_query")?;

    if !rule_creation_enabled() {
        tracing::info!(
            rule_title = title,
            "Detection rule creation blocked — ARES_BLUE_ALLOW_RULE_CREATION is not set"
        );
        return Ok(make_error(
            "Detection rule creation is disabled. Report the proposed rule \
             (title, LogQL, MITRE technique) in your findings so an operator \
             can review and deploy it.",
        ));
    }
    let description = optional_str(args, "description").unwrap_or("");
    let mitre_technique = optional_str(args, "mitre_technique").unwrap_or("");
    let severity = optional_str(args, "severity").unwrap_or("medium");
    let eval_interval = optional_str(args, "evaluation_interval").unwrap_or("5m");
    let pending_period = optional_str(args, "pending_period").unwrap_or("0s");

    let Some(interval_seconds) = parse_interval_seconds(eval_interval) else {
        return Ok(make_error(&format!(
            "Invalid evaluation_interval '{eval_interval}'. Use a duration that is a \
             multiple of 10s, e.g. \"30s\", \"1m\", \"5m\", \"1h\"."
        )));
    };

    // Validate: reject overly broad selectors
    let broad_selectors = [
        r#"{job=~".+"}"#,
        r#"{job!=""}"#,
        r#"{__name__=~".+"}"#,
        r#"{job=~".*"}"#,
    ];
    for broad in &broad_selectors {
        if logql_query.contains(broad) {
            return Ok(make_error(&format!(
                "Query too broad — contains '{broad}'. Use a specific log selector."
            )));
        }
    }

    let client = build_client()?;

    // Ensure the ares-security folder exists
    let folder_url = format!("{}/api/folders/{RULE_FOLDER_UID}", grafana_url());
    let folder_resp = client.get(&folder_url).send().await;
    if let Ok(resp) = folder_resp {
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            let create_body = serde_json::json!({
                "uid": RULE_FOLDER_UID,
                "title": "ARES Security Detections"
            });
            let _ = client
                .post(format!("{}/api/folders", grafana_url()))
                .json(&create_body)
                .send()
                .await;
        }
    }

    let rule_body = build_rule_body(
        title,
        logql_query,
        description,
        mitre_technique,
        severity,
        pending_period,
        interval_seconds,
    );

    let url = format!("{}/api/v1/provisioning/alert-rules", grafana_url());
    let resp = client
        .post(&url)
        .json(&rule_body)
        .send()
        .await
        .context("Failed to create Grafana alert rule")?;

    let status = resp.status();
    let resp_body = resp.text().await.unwrap_or_default();

    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Ok(make_error(&format!(
            "Grafana authentication failed ({status}): {resp_body}"
        )));
    }

    if !status.is_success() {
        return Ok(make_error(&format!(
            "Failed to create detection rule ({status}): {resp_body}"
        )));
    }

    let created = format!(
        "[+] Detection rule created: {title} (severity={severity}, folder={RULE_FOLDER_UID}, group={RULE_GROUP})"
    );
    let requested = format_interval(interval_seconds);

    Ok(match sync_group_interval(&client, interval_seconds).await {
        Ok(confirmed) if confirmed == interval_seconds => {
            make_output(&format!("{created}\n[+] Group evaluates every {requested}"))
        }
        Ok(confirmed) => make_output(&format!(
            "{created}\n[!] Requested interval {requested} was not applied — group \
             {RULE_GROUP} still evaluates every {}",
            format_interval(confirmed)
        )),
        Err(e) => make_output(&format!(
            "{created}\n[!] Evaluation interval unverified — could not set group \
             {RULE_GROUP} to {requested}: {e}"
        )),
    })
}

/// Get alert rule definitions from Grafana's provisioning API.
///
/// The provisioning endpoint returns rule definitions, which carry no time
/// dimension, so this executor takes no arguments.
pub async fn get_alert_history(_args: &Value) -> Result<ToolOutput> {
    let client = build_client()?;

    let url = format!("{}/api/v1/provisioning/alert-rules", grafana_url());
    let resp = client.get(&url).send().await;

    let resp = match resp {
        Ok(r) => r,
        Err(e) => return Ok(make_error(&format!("Failed to query Grafana: {e}"))),
    };

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Ok(make_error(&format!(
            "Grafana authentication failed ({status}): {body}"
        )));
    }

    if !status.is_success() {
        return Ok(make_error(&format!("Grafana returned {status}: {body}")));
    }

    if let Ok(rules) = serde_json::from_str::<Vec<Value>>(&body) {
        let mut parts = Vec::new();
        parts.push(format!("Alert rules ({} total):\n", rules.len()));
        for rule in &rules {
            let title = rule
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("unnamed");
            let uid = rule.get("uid").and_then(|v| v.as_str()).unwrap_or("-");
            let folder = rule
                .get("folderUID")
                .and_then(|v| v.as_str())
                .unwrap_or("-");
            let interval = rule
                .get("intervalSeconds")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            parts.push(format!(
                "  - {title} (uid={uid}, folder={folder}, interval={interval}s)"
            ));
        }
        Ok(make_output(&parts.join("\n")))
    } else {
        Ok(make_output(&body))
    }
}

/// Get alerts that fired within a specific time range.
///
/// Queries Grafana's annotations API for alert annotations within the given
/// time window (with configurable buffer), then transforms annotations into
/// a normalized alert format.
pub async fn get_alerts_in_time_range(args: &Value) -> Result<ToolOutput> {
    let from_time = required_str(args, "from_time")?;
    let to_time = required_str(args, "to_time")?;
    let buffer_minutes = optional_i64(args, "buffer_minutes").unwrap_or(30);

    // Parse timestamps
    let from_dt = chrono::DateTime::parse_from_rfc3339(from_time)
        .or_else(|_| chrono::DateTime::parse_from_str(from_time, "%Y-%m-%dT%H:%M:%S%.fZ"))
        .unwrap_or_else(|_| crate::blue::replay_clock::replay_now().into());
    let to_dt = chrono::DateTime::parse_from_rfc3339(to_time)
        .or_else(|_| chrono::DateTime::parse_from_str(to_time, "%Y-%m-%dT%H:%M:%S%.fZ"))
        .unwrap_or_else(|_| crate::blue::replay_clock::replay_now().into());

    // Apply buffer
    let from_buffered = from_dt - chrono::Duration::minutes(buffer_minutes);
    let to_buffered = to_dt + chrono::Duration::minutes(buffer_minutes);

    let from_ms = from_buffered.timestamp_millis();
    let to_ms = to_buffered.timestamp_millis();

    let client = build_client()?;
    let url = format!("{}/api/annotations", grafana_url());

    let mut query = vec![
        ("from", from_ms.to_string()),
        ("to", to_ms.to_string()),
        ("limit", "5000".to_string()),
    ];
    // Live: alert-rule annotations are type=alert. Replay: seeded firings are
    // plain org annotations (type=annotation), so don't filter by type — the
    // loop tag-matches `ares-replay-firing` instead.
    if !crate::blue::replay_clock::is_replay() {
        query.push(("type", "alert".to_string()));
    }
    let resp = client
        .get(&url)
        .query(&query)
        .send()
        .await
        .context("Failed to query Grafana annotations")?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    if !status.is_success() {
        return Ok(make_error(&format!("Grafana returned {status}: {body}")));
    }

    let annotations: Vec<Value> = serde_json::from_str(&body).unwrap_or_default();

    // Transform annotations to alert format with dedup
    let mut seen_fingerprints = std::collections::HashSet::new();
    let mut alerts = Vec::new();

    // In replay, seeded firings are plain annotations (POST /api/annotations
    // can't set alertId), so alertId is 0 — don't skip them then.
    let replay = crate::blue::replay_clock::is_replay();

    for ann in &annotations {
        let alert_id = ann.get("alertId").and_then(|v| v.as_i64()).unwrap_or(0);
        if replay {
            // Only seeded firings (tagged at seed time) — not other annotations
            // such as investigation-lifecycle markers.
            let is_firing = ann
                .get("tags")
                .and_then(|v| v.as_array())
                .map(|tags| {
                    tags.iter()
                        .any(|t| t.as_str() == Some("ares-replay-firing"))
                })
                .unwrap_or(false);
            if !is_firing {
                continue;
            }
        } else if alert_id == 0 {
            continue; // skip non-alert annotations (live only)
        }
        let panel_id = ann.get("panelId").and_then(|v| v.as_i64()).unwrap_or(0);
        // alertId=0 seeded firings would all collapse to "ann-0-0"; key the dedup
        // on the annotation's own id in that case.
        let fingerprint = if alert_id != 0 {
            format!("ann-{alert_id}-{panel_id}")
        } else {
            let ann_id = ann.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
            format!("ann-id-{ann_id}")
        };

        if !seen_fingerprints.insert(fingerprint.clone()) {
            continue; // deduplicate
        }

        // Extract labels. Seeded replay firings carry their original labels in
        // `data`; live alert annotations encode them in tags.
        let mut labels = serde_json::Map::new();
        if replay {
            if let Some(dl) = ann.pointer("/data/labels").and_then(|v| v.as_object()) {
                labels = dl.clone();
            }
            if !labels.contains_key("alertname") {
                if let Some(t) = ann.get("text").and_then(|v| v.as_str()) {
                    labels.insert("alertname".to_string(), Value::String(t.to_string()));
                }
            }
        } else {
            if let Some(tags) = ann.get("tags").and_then(|v| v.as_array()) {
                for tag in tags {
                    if let Some(s) = tag.as_str() {
                        if let Some((k, v)) = s.split_once(':').or_else(|| s.split_once('=')) {
                            labels.insert(k.to_string(), Value::String(v.to_string()));
                        } else {
                            labels.insert("alertname".to_string(), Value::String(s.to_string()));
                        }
                    }
                }
            }
            if !labels.contains_key("alertname") {
                if let Some(name) = ann.get("alertName").and_then(|v| v.as_str()) {
                    labels.insert("alertname".to_string(), Value::String(name.to_string()));
                }
            }
        }

        let text = ann
            .get("text")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let time_ms = ann.get("time").and_then(|v| v.as_i64()).unwrap_or(0);
        let time_end_ms = ann.get("timeEnd").and_then(|v| v.as_i64());

        let starts_at = chrono::DateTime::from_timestamp_millis(time_ms)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();
        let ends_at = time_end_ms
            .and_then(chrono::DateTime::from_timestamp_millis)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();
        let state = if time_end_ms.is_some() {
            "resolved"
        } else {
            "firing"
        };

        alerts.push(serde_json::json!({
            "fingerprint": fingerprint,
            "labels": labels,
            "annotations": { "summary": text, "description": text },
            "startsAt": starts_at,
            "endsAt": ends_at,
            "status": { "state": state },
        }));
    }

    if alerts.is_empty() {
        return Ok(make_output("No alerts found in the specified time range."));
    }

    let output = serde_json::to_string_pretty(&alerts).unwrap_or_default();
    Ok(make_output(&format!(
        "Found {} alerts in time range:\n\n{}",
        alerts.len(),
        output
    )))
}

#[cfg(test)]
mod rule_gate_tests {
    use super::*;
    use ares_core::detection::RULE_CREATION_ENV;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvGuard {
        prior: Option<String>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn acquire() -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            Self {
                prior: std::env::var(RULE_CREATION_ENV).ok(),
                _lock: lock,
            }
        }

        fn set(&self, value: &str) {
            std::env::set_var(RULE_CREATION_ENV, value);
        }

        fn unset(&self) {
            std::env::remove_var(RULE_CREATION_ENV);
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prior {
                Some(v) => std::env::set_var(RULE_CREATION_ENV, v),
                None => std::env::remove_var(RULE_CREATION_ENV),
            }
        }
    }

    #[test]
    fn rule_creation_defaults_off_and_respects_opt_in() {
        let env = EnvGuard::acquire();

        env.unset();
        assert!(!rule_creation_enabled());

        for enabled in ["1", "true", "YES", " on "] {
            env.set(enabled);
            assert!(rule_creation_enabled(), "expected {enabled:?} to enable");
        }

        for disabled in ["0", "false", "", "maybe"] {
            env.set(disabled);
            assert!(!rule_creation_enabled(), "expected {disabled:?} to disable");
        }
    }

    #[test]
    fn create_detection_rule_refuses_when_gate_is_unset() {
        let env = EnvGuard::acquire();
        env.unset();

        let args = serde_json::json!({
            "title": "Detect DCSync",
            "logql_query": r#"{job="windows"} |= "4662""#,
        });
        let out = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build runtime")
            .block_on(create_detection_rule(&args))
            .expect("tool call");

        assert!(!out.success);
        assert!(out.stderr.contains("disabled"));
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn create_detection_rule_rejects_unparsable_interval() {
        let env = EnvGuard::acquire();
        env.set("1");

        let args = serde_json::json!({
            "title": "Detect DCSync",
            "logql_query": r#"{job="windows"} |= "4662""#,
            "evaluation_interval": "5 minutes",
        });
        let out = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build runtime")
            .block_on(create_detection_rule(&args))
            .expect("tool call");

        assert!(!out.success);
        assert!(out.stderr.contains("Invalid evaluation_interval"));
    }
}

#[cfg(test)]
mod rule_body_tests {
    use super::*;

    #[test]
    fn parse_interval_seconds_accepts_grafana_durations() {
        assert_eq!(parse_interval_seconds("30s"), Some(30));
        assert_eq!(parse_interval_seconds("1m"), Some(60));
        assert_eq!(parse_interval_seconds(" 5m "), Some(300));
        assert_eq!(parse_interval_seconds("1h"), Some(3600));
        assert_eq!(parse_interval_seconds("600"), Some(600));
    }

    #[test]
    fn parse_interval_seconds_rejects_rather_than_coercing() {
        for bad in ["5 minutes", "", "0m", "-5m", "7s", "abc", "5d"] {
            assert_eq!(
                parse_interval_seconds(bad),
                None,
                "expected {bad:?} rejected"
            );
        }
    }

    #[test]
    fn format_interval_round_trips() {
        for raw in ["30s", "1m", "5m", "15m", "1h"] {
            let seconds = parse_interval_seconds(raw).expect("parses");
            assert_eq!(format_interval(seconds), raw);
        }
    }

    fn body(interval_seconds: i64) -> Value {
        build_rule_body(
            "Detect DCSync",
            r#"{job="windows"} |= "4662""#,
            "",
            "T1003.006",
            "high",
            "0s",
            interval_seconds,
        )
    }

    #[test]
    fn rule_body_omits_per_rule_interval() {
        assert!(
            body(300).get("intervalSeconds").is_none(),
            "provisioning API overwrites per-rule intervalSeconds from the group; \
             sending it invites a false confirmation"
        );
    }

    #[test]
    fn lookback_window_tiles_the_evaluation_interval() {
        for raw in ["1m", "5m", "15m"] {
            let seconds = parse_interval_seconds(raw).expect("parses");
            let rule = body(seconds);
            let query = rule.pointer("/data/0/model/expr").and_then(Value::as_str);
            assert_eq!(
                query,
                Some(
                    format!(r#"count_over_time({{job="windows"}} |= "4662" [{raw}]) > 0"#).as_str()
                )
            );
            assert_eq!(
                rule.pointer("/data/0/relativeTimeRange/from")
                    .and_then(Value::as_i64),
                Some(seconds)
            );
        }
    }

    #[test]
    fn lookback_covers_pending_period_plus_interval() {
        let rule = build_rule_body(
            "Detect DCSync",
            r#"{job="windows"} |= "4662""#,
            "",
            "T1003.006",
            "high",
            "30s",
            300,
        );
        assert_eq!(
            rule.pointer("/data/0/relativeTimeRange/from")
                .and_then(Value::as_i64),
            Some(330)
        );
        assert_eq!(
            rule.pointer("/data/0/model/expr").and_then(Value::as_str),
            Some(r#"count_over_time({job="windows"} |= "4662" [330s]) > 0"#)
        );
    }
}
