//! Investigation state mutation tools for blue team LLM agents.
//!
//! These tools run in-process (not dispatched to workers) and write
//! directly to Redis, following the same key patterns as the Python
//! `BlueStateBackend` and the Rust `BlueStateWriter`.

use anyhow::{Context, Result};
use redis::AsyncCommands;
use serde_json::Value;
use uuid::Uuid;

use crate::args::{optional_str, required_str};
use crate::ToolOutput;

use super::validation;

// ---------------------------------------------------------------------------
// Redis key constants (mirrored from ares-core/src/state/keys.rs to avoid
// adding ares-core as a dependency of ares-tools)
// ---------------------------------------------------------------------------

const BLUE_KEY_PREFIX: &str = "ares:blue:inv";
const BLUE_KEY_EVIDENCE: &str = "evidence";
const BLUE_KEY_TIMELINE: &str = "timeline";
const BLUE_KEY_TECHNIQUES: &str = "techniques";
const BLUE_KEY_TECHNIQUE_NAMES: &str = "technique_names";
const BLUE_KEY_LATERAL: &str = "lateral";
const BLUE_KEY_HOSTS: &str = "hosts";
const BLUE_KEY_USERS: &str = "users";
const BLUE_KEY_META: &str = "meta";

const TTL_SECS: i64 = 86400;

fn blue_key(investigation_id: &str, suffix: &str) -> String {
    format!("{BLUE_KEY_PREFIX}:{investigation_id}:{suffix}")
}

// ---------------------------------------------------------------------------
// Redis connection helper
// ---------------------------------------------------------------------------

async fn get_redis_connection() -> Result<redis::aio::MultiplexedConnection> {
    let url = std::env::var("ARES_REDIS_URL")
        .or_else(|_| std::env::var("REDIS_URL"))
        .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

    let client = redis::Client::open(url.as_str()).context("failed to create Redis client")?;
    let conn = client
        .get_multiplexed_tokio_connection()
        .await
        .context("failed to connect to Redis")?;
    Ok(conn)
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

fn make_output(body: &str) -> ToolOutput {
    ToolOutput {
        stdout: body.to_string(),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    }
}

fn make_error(msg: &str) -> ToolOutput {
    ToolOutput {
        stdout: String::new(),
        stderr: msg.to_string(),
        exit_code: Some(1),
        success: false,
    }
}

// ---------------------------------------------------------------------------
// 1. add_evidence
// ---------------------------------------------------------------------------

/// Add evidence to investigation state.
///
/// Required: `investigation_id`, `evidence_type`, `value`, `source`
/// Optional: `confidence` (f64), `pyramid_level` (string), `timestamp`
///
/// Uses HSETNX for O(1) deduplication, matching BlueStateWriter.
pub async fn add_evidence(args: &Value) -> Result<ToolOutput> {
    let investigation_id = required_str(args, "investigation_id")?;
    let evidence_type = required_str(args, "evidence_type")?;
    let value = required_str(args, "value")?;
    let source = required_str(args, "source")?;

    // ── Validate evidence before writing ─────────────────────────────
    let vr = validation::validate_evidence(evidence_type, value, source);
    if !vr.valid {
        return Ok(make_error(&format!(
            "Evidence validation failed: {}",
            vr.warnings.join("; "),
        )));
    }

    let confidence = args
        .get("confidence")
        .and_then(Value::as_f64)
        .unwrap_or(0.5);

    // Auto-assign pyramid level from evidence type when caller omits it
    let pyramid_level = optional_str(args, "pyramid_level")
        .unwrap_or_else(|| validation::assign_pyramid_level(&vr.normalized_type));

    let timestamp = optional_str(args, "timestamp")
        .map(|s| s.to_string())
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

    let pyramid_level_int = match pyramid_level {
        "hash_values" => 1,
        "ip_addresses" => 2,
        "domain_names" => 3,
        "network_host_artifacts" => 4,
        "tools" => 5,
        "ttps" => 6,
        _ => pyramid_level.parse::<i32>().unwrap_or(2),
    };

    let evidence_id = Uuid::new_v4().to_string();

    let evidence = serde_json::json!({
        "id": evidence_id,
        "type": vr.normalized_type,
        "value": value,
        "source": source,
        "timestamp": timestamp,
        "pyramid_level": pyramid_level_int,
        "confidence": confidence,
        "mitre_techniques": [],
        "metadata": {},
        "validated": true,
    });

    // Dedup key matches BlueStateWriter: type:value_lower:source
    let dedup_key = format!("{}:{}:{}", vr.normalized_type, value.to_lowercase(), source,);

    let mut conn = match get_redis_connection().await {
        Ok(c) => c,
        Err(e) => return Ok(make_error(&format!("Redis connection failed: {e}"))),
    };

    let key = blue_key(investigation_id, BLUE_KEY_EVIDENCE);
    let data = serde_json::to_string(&evidence).unwrap_or_default();

    let added: bool = conn
        .hset_nx(&key, &dedup_key, &data)
        .await
        .context("HSETNX failed")?;

    if added {
        let _: () = conn.expire(&key, TTL_SECS).await?;
    }

    // Build output, including any warnings
    let warning_str = if vr.warnings.is_empty() {
        String::new()
    } else {
        format!(" [warnings: {}]", vr.warnings.join("; "))
    };

    if added {
        Ok(make_output(&format!(
            "[+] Evidence added: {evidence_type}={value} (id={evidence_id}, confidence={confidence:.1}, pyramid={pyramid_level}){warning_str}"
        )))
    } else {
        Ok(make_output(&format!(
            "[*] Duplicate evidence (already recorded): {evidence_type}={value}{warning_str}"
        )))
    }
}

// ---------------------------------------------------------------------------
// 2. record_timeline_event
// ---------------------------------------------------------------------------

/// Record a timeline event for the investigation.
///
/// Required: `investigation_id`, `description`, `timestamp`
/// Optional: `mitre_techniques` (array), `confidence`, `source`, `evidence_ids` (array)
pub async fn record_timeline_event(args: &Value) -> Result<ToolOutput> {
    let investigation_id = required_str(args, "investigation_id")?;
    let description = required_str(args, "description")?;
    let timestamp = required_str(args, "timestamp")?;

    let confidence = args
        .get("confidence")
        .and_then(Value::as_f64)
        .unwrap_or(0.5);
    let source = optional_str(args, "source").unwrap_or("agent");

    let mitre_techniques: Vec<String> = args
        .get("mitre_techniques")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();

    let evidence_ids: Vec<String> = args
        .get("evidence_ids")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();

    let event_id = Uuid::new_v4().to_string();

    let event = serde_json::json!({
        "id": event_id,
        "timestamp": timestamp,
        "description": description,
        "evidence_ids": evidence_ids,
        "mitre_techniques": mitre_techniques,
        "confidence": confidence,
        "source": source,
    });

    let mut conn = match get_redis_connection().await {
        Ok(c) => c,
        Err(e) => return Ok(make_error(&format!("Redis connection failed: {e}"))),
    };

    let key = blue_key(investigation_id, BLUE_KEY_TIMELINE);
    let data = serde_json::to_string(&event).unwrap_or_default();

    let _: () = conn.rpush(&key, &data).await.context("RPUSH failed")?;
    let _: () = conn.expire(&key, TTL_SECS).await?;

    let technique_str = if mitre_techniques.is_empty() {
        String::new()
    } else {
        format!(" [{}]", mitre_techniques.join(", "))
    };

    Ok(make_output(&format!(
        "[+] Timeline event recorded at {timestamp}: {description}{technique_str} (id={event_id})"
    )))
}

// ---------------------------------------------------------------------------
// 3. add_technique
// ---------------------------------------------------------------------------

/// Record a MITRE ATT&CK technique observed during investigation.
///
/// Required: `investigation_id`, `technique_id`
/// Optional: `technique_name`
pub async fn add_technique(args: &Value) -> Result<ToolOutput> {
    let investigation_id = required_str(args, "investigation_id")?;
    let technique_id = required_str(args, "technique_id")?;
    let technique_name = optional_str(args, "technique_name");

    let mut conn = match get_redis_connection().await {
        Ok(c) => c,
        Err(e) => return Ok(make_error(&format!("Redis connection failed: {e}"))),
    };

    // Add technique ID to the SET
    let tech_key = blue_key(investigation_id, BLUE_KEY_TECHNIQUES);
    let added: i64 = conn
        .sadd(&tech_key, technique_id)
        .await
        .context("SADD failed")?;
    let _: () = conn.expire(&tech_key, TTL_SECS).await?;

    // If a name was provided, store the name mapping
    if let Some(name) = technique_name {
        let names_key = blue_key(investigation_id, BLUE_KEY_TECHNIQUE_NAMES);
        let _: () = conn.hset(&names_key, technique_id, name).await?;
        let _: () = conn.expire(&names_key, TTL_SECS).await?;
    }

    if added > 0 {
        let display_name = technique_name
            .map(|n| format!("{technique_id} ({n})"))
            .unwrap_or_else(|| technique_id.to_string());
        Ok(make_output(&format!(
            "[+] MITRE technique recorded: {display_name}"
        )))
    } else {
        Ok(make_output(&format!(
            "[*] Technique already recorded: {technique_id}"
        )))
    }
}

// ---------------------------------------------------------------------------
// 4. add_lateral_connection
// ---------------------------------------------------------------------------

/// Record a lateral movement connection between hosts.
///
/// Required: `investigation_id`, `source_host`, `destination_host`
/// Optional: `method`, `timestamp`, `user`
pub async fn add_lateral_connection(args: &Value) -> Result<ToolOutput> {
    let investigation_id = required_str(args, "investigation_id")?;
    let source_host = required_str(args, "source_host")?;
    let destination_host = required_str(args, "destination_host")?;

    let method = optional_str(args, "method").unwrap_or("unknown");
    let timestamp = optional_str(args, "timestamp")
        .map(|s| s.to_string())
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    let user = optional_str(args, "user");

    let mut connection = serde_json::json!({
        "source_host": source_host,
        "destination_host": destination_host,
        "method": method,
        "timestamp": timestamp,
    });

    if let Some(u) = user {
        connection["user"] = serde_json::Value::String(u.to_string());
    }

    let mut conn = match get_redis_connection().await {
        Ok(c) => c,
        Err(e) => return Ok(make_error(&format!("Redis connection failed: {e}"))),
    };

    // Append to lateral LIST
    let lateral_key = blue_key(investigation_id, BLUE_KEY_LATERAL);
    let data = serde_json::to_string(&connection).unwrap_or_default();
    let _: () = conn
        .rpush(&lateral_key, &data)
        .await
        .context("RPUSH failed")?;
    let _: () = conn.expire(&lateral_key, TTL_SECS).await?;

    // Also track both hosts in the hosts SET
    let hosts_key = blue_key(investigation_id, BLUE_KEY_HOSTS);
    let _: () = conn.sadd(&hosts_key, source_host.to_lowercase()).await?;
    let _: () = conn
        .sadd(&hosts_key, destination_host.to_lowercase())
        .await?;
    let _: () = conn.expire(&hosts_key, TTL_SECS).await?;

    // Track user if provided
    if let Some(u) = user {
        let users_key = blue_key(investigation_id, BLUE_KEY_USERS);
        let _: () = conn.sadd(&users_key, u.to_lowercase()).await?;
        let _: () = conn.expire(&users_key, TTL_SECS).await?;
    }

    let user_str = user.map(|u| format!(" (user={u})")).unwrap_or_default();

    Ok(make_output(&format!(
        "[+] Lateral connection recorded: {source_host} -> {destination_host} via {method}{user_str}"
    )))
}

// ---------------------------------------------------------------------------
// 5. get_investigation_summary
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 5. transition_stage
// ---------------------------------------------------------------------------

/// Transition investigation to a new stage.
///
/// Required: `investigation_id`, `new_stage`
pub async fn transition_stage(args: &Value) -> Result<ToolOutput> {
    let investigation_id = required_str(args, "investigation_id")?;
    let new_stage = required_str(args, "new_stage")?;

    let valid_stages = ["triage", "causation", "lateral", "synthesis"];
    if !valid_stages.contains(&new_stage) {
        return Ok(make_error(&format!(
            "Invalid stage '{new_stage}'. Must be one of: {}",
            valid_stages.join(", ")
        )));
    }

    let mut conn = match get_redis_connection().await {
        Ok(c) => c,
        Err(e) => return Ok(make_error(&format!("Redis connection failed: {e}"))),
    };

    let meta_key = blue_key(investigation_id, BLUE_KEY_META);
    let stage_json = serde_json::to_string(&new_stage).unwrap_or_default();
    let _: () = conn
        .hset(&meta_key, "stage", &stage_json)
        .await
        .context("HSET stage failed")?;
    let _: () = conn.expire(&meta_key, TTL_SECS).await?;

    Ok(make_output(&format!(
        "[+] Investigation stage transitioned to: {new_stage}"
    )))
}

// ---------------------------------------------------------------------------
// 6. track_host_investigation
// ---------------------------------------------------------------------------

/// Mark a host as investigated and track it in the investigation state.
///
/// Required: `investigation_id`, `hostname`
pub async fn track_host_investigation(args: &Value) -> Result<ToolOutput> {
    let investigation_id = required_str(args, "investigation_id")?;
    let hostname = required_str(args, "hostname")?;

    let mut conn = match get_redis_connection().await {
        Ok(c) => c,
        Err(e) => return Ok(make_error(&format!("Redis connection failed: {e}"))),
    };

    let hosts_key = blue_key(investigation_id, BLUE_KEY_HOSTS);
    let added: i64 = conn
        .sadd(&hosts_key, hostname.to_lowercase())
        .await
        .context("SADD hosts failed")?;
    let _: () = conn.expire(&hosts_key, TTL_SECS).await?;

    if added > 0 {
        Ok(make_output(&format!(
            "[+] Host tracked for investigation: {hostname}"
        )))
    } else {
        Ok(make_output(&format!(
            "[*] Host already tracked: {hostname}"
        )))
    }
}

// ---------------------------------------------------------------------------
// 7. track_user_investigation
// ---------------------------------------------------------------------------

/// Mark a user as investigated and track them in the investigation state.
///
/// Required: `investigation_id`, `username`
pub async fn track_user_investigation(args: &Value) -> Result<ToolOutput> {
    let investigation_id = required_str(args, "investigation_id")?;
    let username = required_str(args, "username")?;

    let mut conn = match get_redis_connection().await {
        Ok(c) => c,
        Err(e) => return Ok(make_error(&format!("Redis connection failed: {e}"))),
    };

    let users_key = blue_key(investigation_id, BLUE_KEY_USERS);
    let added: i64 = conn
        .sadd(&users_key, username.to_lowercase())
        .await
        .context("SADD users failed")?;
    let _: () = conn.expire(&users_key, TTL_SECS).await?;

    if added > 0 {
        Ok(make_output(&format!(
            "[+] User tracked for investigation: {username}"
        )))
    } else {
        Ok(make_output(&format!(
            "[*] User already tracked: {username}"
        )))
    }
}

// ---------------------------------------------------------------------------
// 8. list_evidence
// ---------------------------------------------------------------------------

/// List all evidence items grouped by Pyramid of Pain level.
///
/// Required: `investigation_id`
/// Optional: `pyramid_level` (filter to a specific level)
pub async fn list_evidence(args: &Value) -> Result<ToolOutput> {
    let investigation_id = required_str(args, "investigation_id")?;
    let filter_level = args.get("pyramid_level").and_then(|v| v.as_i64());

    let mut conn = match get_redis_connection().await {
        Ok(c) => c,
        Err(e) => return Ok(make_error(&format!("Redis connection failed: {e}"))),
    };

    let evidence_key = blue_key(investigation_id, BLUE_KEY_EVIDENCE);
    let all_evidence: std::collections::HashMap<String, String> =
        conn.hgetall(&evidence_key).await.unwrap_or_default();

    if all_evidence.is_empty() {
        return Ok(make_output("No evidence recorded yet."));
    }

    // Parse and group by pyramid level
    let level_names = [
        (1, "Hash Values"),
        (2, "IP Addresses"),
        (3, "Domain Names"),
        (4, "Network/Host Artifacts"),
        (5, "Tools"),
        (6, "TTPs"),
    ];

    let mut grouped: std::collections::BTreeMap<i32, Vec<serde_json::Value>> =
        std::collections::BTreeMap::new();

    for json_str in all_evidence.values() {
        if let Ok(ev) = serde_json::from_str::<serde_json::Value>(json_str) {
            let level = ev
                .get("pyramid_level")
                .and_then(|l| l.as_i64())
                .unwrap_or(2) as i32;
            if filter_level.is_none() || filter_level == Some(level as i64) {
                grouped.entry(level).or_default().push(ev);
            }
        }
    }

    if grouped.is_empty() {
        return Ok(make_output(&format!(
            "No evidence at pyramid level {}.",
            filter_level.unwrap_or(0)
        )));
    }

    let mut lines = vec![format!(
        "=== Evidence ({} items) ===",
        grouped.values().map(|v| v.len()).sum::<usize>()
    )];

    for (level, items) in &grouped {
        let level_name = level_names
            .iter()
            .find(|(l, _)| l == level)
            .map(|(_, n)| *n)
            .unwrap_or("Unknown");
        lines.push(format!(
            "\n--- Level {level}: {level_name} ({} items) ---",
            items.len()
        ));
        for ev in items {
            let ev_type = ev.get("type").and_then(|t| t.as_str()).unwrap_or("?");
            let value = ev.get("value").and_then(|v| v.as_str()).unwrap_or("?");
            let source = ev.get("source").and_then(|s| s.as_str()).unwrap_or("?");
            let confidence = ev.get("confidence").and_then(|c| c.as_f64()).unwrap_or(0.0);
            lines.push(format!(
                "  [{ev_type}] {value} (source={source}, confidence={confidence:.1})"
            ));
        }
    }

    Ok(make_output(&lines.join("\n")))
}

// ---------------------------------------------------------------------------
// 9. get_investigation_context (for escalation triage)
// ---------------------------------------------------------------------------

/// Get full investigation context for escalation triage evaluation.
///
/// Returns a comprehensive view of the investigation state including evidence,
/// timeline, techniques with implied capabilities, and triage history.
///
/// Required: `investigation_id`
pub async fn get_investigation_context(args: &Value) -> Result<ToolOutput> {
    let investigation_id = required_str(args, "investigation_id")?;

    let mut conn = match get_redis_connection().await {
        Ok(c) => c,
        Err(e) => return Ok(make_error(&format!("Redis connection failed: {e}"))),
    };

    // Check existence
    let meta_key = blue_key(investigation_id, BLUE_KEY_META);
    let exists: bool = conn.exists(&meta_key).await?;
    if !exists {
        return Ok(make_output(&format!(
            "No investigation found with id: {investigation_id}"
        )));
    }

    // Read all state
    let meta: std::collections::HashMap<String, String> = conn.hgetall(&meta_key).await?;
    let stage = meta
        .get("stage")
        .and_then(|s| serde_json::from_str::<String>(s).ok())
        .unwrap_or_else(|| "unknown".to_string());
    let escalated = meta
        .get("escalated")
        .and_then(|s| serde_json::from_str::<bool>(s).ok())
        .unwrap_or(false);

    // Evidence
    let evidence_key = blue_key(investigation_id, BLUE_KEY_EVIDENCE);
    let evidence: std::collections::HashMap<String, String> =
        conn.hgetall(&evidence_key).await.unwrap_or_default();

    // Timeline
    let timeline_key = blue_key(investigation_id, BLUE_KEY_TIMELINE);
    let timeline: Vec<String> = conn.lrange(&timeline_key, 0, -1).await.unwrap_or_default();

    // Techniques
    let techniques_key = blue_key(investigation_id, BLUE_KEY_TECHNIQUES);
    let techniques: std::collections::HashSet<String> =
        conn.smembers(&techniques_key).await.unwrap_or_default();
    let names_key = blue_key(investigation_id, BLUE_KEY_TECHNIQUE_NAMES);
    let technique_names: std::collections::HashMap<String, String> =
        conn.hgetall(&names_key).await.unwrap_or_default();

    // Hosts & Users
    let hosts_key = blue_key(investigation_id, BLUE_KEY_HOSTS);
    let hosts: std::collections::HashSet<String> =
        conn.smembers(&hosts_key).await.unwrap_or_default();
    let users_key = blue_key(investigation_id, BLUE_KEY_USERS);
    let users: std::collections::HashSet<String> =
        conn.smembers(&users_key).await.unwrap_or_default();

    // Lateral
    let lateral_key = blue_key(investigation_id, BLUE_KEY_LATERAL);
    let lateral: Vec<String> = conn.lrange(&lateral_key, 0, -1).await.unwrap_or_default();

    // Build comprehensive context
    let mut parts = Vec::new();
    parts.push(format!("=== Investigation Context: {investigation_id} ==="));
    parts.push(format!("Stage: {stage}"));
    parts.push(format!("Escalated: {escalated}"));

    // Evidence summary
    parts.push(format!("\n--- Evidence ({} items) ---", evidence.len()));
    let mut high_confidence = Vec::new();
    for json_str in evidence.values() {
        if let Ok(ev) = serde_json::from_str::<serde_json::Value>(json_str) {
            let ev_type = ev.get("type").and_then(|t| t.as_str()).unwrap_or("?");
            let value = ev.get("value").and_then(|v| v.as_str()).unwrap_or("?");
            let confidence = ev.get("confidence").and_then(|c| c.as_f64()).unwrap_or(0.0);
            let level = ev
                .get("pyramid_level")
                .and_then(|l| l.as_i64())
                .unwrap_or(0);
            parts.push(format!(
                "  [{ev_type}] {value} (confidence={confidence:.1}, pyramid={level})"
            ));
            if confidence >= 0.7 {
                high_confidence.push(format!("{ev_type}: {value}"));
            }
        }
    }
    if !high_confidence.is_empty() {
        parts.push(format!(
            "\nHigh-confidence evidence: {}",
            high_confidence.join(", ")
        ));
    }

    // Techniques with implied capabilities
    if !techniques.is_empty() {
        parts.push(format!("\n--- Techniques ({}) ---", techniques.len()));
        let mut sorted: Vec<&String> = techniques.iter().collect();
        sorted.sort();
        for tech in sorted {
            let name = technique_names
                .get(tech.as_str())
                .map(|n| n.as_str())
                .unwrap_or("");
            let implied = infer_capability(tech);
            let mut line = if name.is_empty() {
                format!("  {tech}")
            } else {
                format!("  {tech} ({name})")
            };
            if !implied.is_empty() {
                line.push_str(&format!(" -> implies: {implied}"));
            }
            parts.push(line);
        }
    }

    // Timeline (last 10 events)
    if !timeline.is_empty() {
        parts.push(format!(
            "\n--- Timeline ({} events, last 10) ---",
            timeline.len()
        ));
        for entry in timeline.iter().rev().take(10) {
            if let Ok(ev) = serde_json::from_str::<serde_json::Value>(entry) {
                let ts = ev.get("timestamp").and_then(|t| t.as_str()).unwrap_or("?");
                let desc = ev
                    .get("description")
                    .and_then(|d| d.as_str())
                    .unwrap_or("?");
                parts.push(format!("  [{ts}] {desc}"));
            }
        }
    }

    // Hosts, Users, Lateral
    if !hosts.is_empty() {
        let mut h: Vec<&String> = hosts.iter().collect();
        h.sort();
        parts.push(format!(
            "\nHosts investigated: {}",
            h.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }
    if !users.is_empty() {
        let mut u: Vec<&String> = users.iter().collect();
        u.sort();
        parts.push(format!(
            "Users investigated: {}",
            u.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }
    if !lateral.is_empty() {
        parts.push(format!("\n--- Lateral Connections ({}) ---", lateral.len()));
        for conn_str in &lateral {
            if let Ok(conn_val) = serde_json::from_str::<serde_json::Value>(conn_str) {
                let src = conn_val
                    .get("source_host")
                    .and_then(|s| s.as_str())
                    .unwrap_or("?");
                let dst = conn_val
                    .get("destination_host")
                    .and_then(|d| d.as_str())
                    .unwrap_or("?");
                let method = conn_val
                    .get("method")
                    .and_then(|m| m.as_str())
                    .unwrap_or("?");
                parts.push(format!("  {src} -> {dst} via {method}"));
            }
        }
    }

    Ok(make_output(&parts.join("\n")))
}

/// Infer implied capabilities from a MITRE technique ID.
fn infer_capability(technique_id: &str) -> &'static str {
    match technique_id {
        "T1003.006" => "can perform DCSync (domain replication), likely has domain admin",
        "T1558.001" => "can forge golden tickets (full domain compromise)",
        "T1558.003" => "can crack service account passwords offline",
        "T1558.004" => "can crack accounts without pre-auth offline",
        "T1550.002" => "can move laterally with stolen NTLM hashes",
        "T1021.002" => "can access remote admin shares (likely has admin creds)",
        "T1649" => "can forge authentication certificates (ADCS compromise)",
        _ => "",
    }
}

// ---------------------------------------------------------------------------
// 10. get_investigation_summary
// ---------------------------------------------------------------------------

pub async fn get_investigation_summary(args: &Value) -> Result<ToolOutput> {
    let investigation_id = required_str(args, "investigation_id")?;

    let mut conn = match get_redis_connection().await {
        Ok(c) => c,
        Err(e) => return Ok(make_error(&format!("Redis connection failed: {e}"))),
    };

    // Check if investigation exists
    let meta_key = blue_key(investigation_id, BLUE_KEY_META);
    let exists: bool = conn.exists(&meta_key).await?;
    if !exists {
        return Ok(make_output(&format!(
            "No investigation found with id: {investigation_id}"
        )));
    }

    // Read meta
    let meta: std::collections::HashMap<String, String> = conn.hgetall(&meta_key).await?;
    let stage = meta
        .get("stage")
        .and_then(|s| serde_json::from_str::<String>(s).ok())
        .unwrap_or_else(|| "unknown".to_string());

    // Evidence count
    let evidence_key = blue_key(investigation_id, BLUE_KEY_EVIDENCE);
    let evidence_count: usize = conn.hlen(&evidence_key).await.unwrap_or(0);

    // Timeline count
    let timeline_key = blue_key(investigation_id, BLUE_KEY_TIMELINE);
    let timeline_count: usize = conn.llen(&timeline_key).await.unwrap_or(0);

    // Techniques
    let techniques_key = blue_key(investigation_id, BLUE_KEY_TECHNIQUES);
    let techniques: std::collections::HashSet<String> =
        conn.smembers(&techniques_key).await.unwrap_or_default();

    // Technique names
    let names_key = blue_key(investigation_id, BLUE_KEY_TECHNIQUE_NAMES);
    let technique_names: std::collections::HashMap<String, String> =
        conn.hgetall(&names_key).await.unwrap_or_default();

    // Hosts
    let hosts_key = blue_key(investigation_id, BLUE_KEY_HOSTS);
    let hosts: std::collections::HashSet<String> =
        conn.smembers(&hosts_key).await.unwrap_or_default();

    // Users
    let users_key = blue_key(investigation_id, BLUE_KEY_USERS);
    let users: std::collections::HashSet<String> =
        conn.smembers(&users_key).await.unwrap_or_default();

    // Lateral connections count
    let lateral_key = blue_key(investigation_id, BLUE_KEY_LATERAL);
    let lateral_count: usize = conn.llen(&lateral_key).await.unwrap_or(0);

    // Format output
    let mut parts = Vec::new();
    parts.push(format!("=== Investigation Summary: {investigation_id} ==="));
    parts.push(format!("Stage: {stage}"));
    parts.push(format!("Evidence items: {evidence_count}"));
    parts.push(format!("Timeline events: {timeline_count}"));
    parts.push(format!("Lateral connections: {lateral_count}"));

    if !techniques.is_empty() {
        let mut tech_lines: Vec<String> = techniques
            .iter()
            .map(|t| {
                if let Some(name) = technique_names.get(t.as_str()) {
                    format!("  - {t} ({name})")
                } else {
                    format!("  - {t}")
                }
            })
            .collect();
        tech_lines.sort();
        parts.push(format!(
            "MITRE techniques ({}):\n{}",
            techniques.len(),
            tech_lines.join("\n")
        ));
    } else {
        parts.push("MITRE techniques: none".to_string());
    }

    if !hosts.is_empty() {
        let mut host_list: Vec<&String> = hosts.iter().collect();
        host_list.sort();
        parts.push(format!(
            "Hosts ({}): {}",
            hosts.len(),
            host_list
                .iter()
                .map(|h| h.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    if !users.is_empty() {
        let mut user_list: Vec<&String> = users.iter().collect();
        user_list.sort();
        parts.push(format!(
            "Users ({}): {}",
            users.len(),
            user_list
                .iter()
                .map(|u| u.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    Ok(make_output(&parts.join("\n")))
}
