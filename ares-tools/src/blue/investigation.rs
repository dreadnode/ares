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

/// Add one or more evidence items to the investigation using a Redis pipeline.
///
/// Required: `investigation_id`, `items` (array of evidence objects)
/// Each item requires: `evidence_type`, `value`, `source`
/// Each item optionally: `confidence`, `pyramid_level`, `timestamp`
///
/// Uses HSETNX for O(1) deduplication, matching BlueStateWriter.
pub async fn add_evidence(args: &Value) -> Result<ToolOutput> {
    let investigation_id = required_str(args, "investigation_id")?;
    let items = args
        .get("items")
        .and_then(|v| v.as_array())
        .context("items must be an array")?;

    if items.is_empty() {
        return Ok(make_output("[*] No items provided"));
    }

    // Cap at 50 items per call to bound output size
    let items: Vec<&Value> = items.iter().take(50).collect();

    let mut conn = match get_redis_connection().await {
        Ok(c) => c,
        Err(e) => return Ok(make_error(&format!("Redis connection failed: {e}"))),
    };

    let key = blue_key(investigation_id, BLUE_KEY_EVIDENCE);
    let now = chrono::Utc::now().to_rfc3339();

    // Prepare all items: validate, build JSON, compute dedup keys
    struct PreparedItem {
        dedup_key: String,
        data: String,
        label: String,
        evidence_id: String,
        confidence: f64,
        pyramid_level: String,
    }

    let mut prepared = Vec::with_capacity(items.len());
    let mut validation_errors = Vec::new();

    for (i, item) in items.iter().enumerate() {
        let evidence_type = match item.get("evidence_type").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                validation_errors.push(format!("item[{i}]: missing evidence_type"));
                continue;
            }
        };
        let value = match item.get("value").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                validation_errors.push(format!("item[{i}]: missing value"));
                continue;
            }
        };
        let source = match item.get("source").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                validation_errors.push(format!("item[{i}]: missing source"));
                continue;
            }
        };

        let vr = validation::validate_evidence(evidence_type, value, source);
        if !vr.valid {
            validation_errors.push(format!(
                "item[{i}] {evidence_type}={value}: {}",
                vr.warnings.join("; ")
            ));
            continue;
        }

        let (query_validated, _) = super::evidence_validator::validate_evidence_value(value);
        let raw_confidence = item
            .get("confidence")
            .and_then(Value::as_f64)
            .unwrap_or(0.5);
        let confidence =
            super::evidence_validator::adjust_confidence(raw_confidence, query_validated);

        let pyramid_level = item
            .get("pyramid_level")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| validation::assign_pyramid_level(&vr.normalized_type));

        let timestamp = item
            .get("timestamp")
            .and_then(|v| v.as_str())
            .unwrap_or(&now);

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

        let dedup_key = format!("{}:{}:{}", vr.normalized_type, value.to_lowercase(), source);
        let data = serde_json::to_string(&evidence).unwrap_or_default();

        prepared.push(PreparedItem {
            dedup_key,
            data,
            label: format!("{evidence_type}={value}"),
            evidence_id,
            confidence,
            pyramid_level: pyramid_level.to_string(),
        });
    }

    if prepared.is_empty() {
        let err_summary = validation_errors.join("\n");
        return Ok(make_error(&format!(
            "All items failed validation:\n{err_summary}"
        )));
    }

    // Execute all HSETNX in a single Redis pipeline round-trip
    let mut pipe = redis::pipe();
    for item in &prepared {
        pipe.cmd("HSETNX")
            .arg(&key)
            .arg(&item.dedup_key)
            .arg(&item.data);
    }

    let results: Vec<bool> = pipe
        .query_async(&mut conn)
        .await
        .context("Redis pipeline failed")?;

    // Set TTL once if any items were added
    if results.iter().any(|&added| added) {
        let _: () = conn.expire(&key, TTL_SECS).await?;
    }

    // Build output summary
    let mut added_count = 0;
    let mut dup_count = 0;
    let mut output_lines = Vec::new();

    for (item, &added) in prepared.iter().zip(results.iter()) {
        if added {
            added_count += 1;
            output_lines.push(format!(
                "[+] {} (id={}, confidence={:.1}, pyramid={})",
                item.label, item.evidence_id, item.confidence, item.pyramid_level
            ));
        } else {
            dup_count += 1;
        }
    }

    if dup_count > 0 {
        output_lines.push(format!("[*] {dup_count} duplicate(s) skipped"));
    }
    if !validation_errors.is_empty() {
        output_lines.push(format!(
            "[!] {} item(s) failed validation",
            validation_errors.len()
        ));
    }

    let summary = format!(
        "Evidence recorded: {added_count} added, {dup_count} duplicates, {} invalid",
        validation_errors.len()
    );
    output_lines.insert(0, summary);

    Ok(make_output(&output_lines.join("\n")))
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

    let suggested_queries = format!(
        "\n\nSuggested queries for {hostname}:\n\
         - Authentication: {{job=\"windows\"}} |~ \"(?i){hostname}\" |~ \"4624|4625|4648\"\n\
         - Process creation: {{job=\"windows\"}} |~ \"(?i){hostname}\" |~ \"4688|1\"\n\
         - Lateral movement: {{job=\"windows\"}} |~ \"(?i){hostname}\" |~ \"5140|5145|4624\"\n\
         - Service installation: {{job=\"windows\"}} |~ \"(?i){hostname}\" |~ \"7045|4697\"\n\
         - Scheduled tasks: {{job=\"windows\"}} |~ \"(?i){hostname}\" |~ \"4698|4702\"\n\
         - All activity: {{job=\"windows\"}} |~ \"(?i){hostname}\""
    );

    if added > 0 {
        Ok(make_output(&format!(
            "[+] Host tracked for investigation: {hostname}{suggested_queries}"
        )))
    } else {
        Ok(make_output(&format!(
            "[*] Host already tracked: {hostname}{suggested_queries}"
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

    let suggested_queries = format!(
        "\n\nSuggested queries for {username}:\n\
         - Logon events: {{job=\"windows\"}} |~ \"(?i){username}\" |~ \"4624|4625|4648\"\n\
         - Kerberos: {{job=\"windows\"}} |~ \"(?i){username}\" |~ \"4768|4769|4771\"\n\
         - Privilege use: {{job=\"windows\"}} |~ \"(?i){username}\" |~ \"4672|4673\"\n\
         - Object access: {{job=\"windows\"}} |~ \"(?i){username}\" |~ \"4662|4663\"\n\
         - Account changes: {{job=\"windows\"}} |~ \"(?i){username}\" |~ \"4720|4722|4738\"\n\
         - All activity: {{job=\"windows\"}} |~ \"(?i){username}\""
    );

    if added > 0 {
        Ok(make_output(&format!(
            "[+] User tracked for investigation: {username}{suggested_queries}"
        )))
    } else {
        Ok(make_output(&format!(
            "[*] User already tracked: {username}{suggested_queries}"
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

// ---------------------------------------------------------------------------
// 11. get_suggested_evidence
// ---------------------------------------------------------------------------

/// Get auto-extracted IOCs from recent query results as evidence suggestions.
pub fn get_suggested_evidence(_args: &Value) -> Result<ToolOutput> {
    let iocs = super::evidence_validator::get_suggested_iocs();
    if iocs.is_empty() {
        return Ok(make_output(
            "No IOCs extracted from recent queries. Run more Loki/Prometheus queries first.",
        ));
    }

    let mut lines = vec![format!(
        "Suggested evidence from recent queries ({} IOCs):",
        iocs.len()
    )];
    for ioc in &iocs {
        lines.push(format!(
            "  [{}] {} (from {})",
            ioc.ioc_type, ioc.value, ioc.source_query_id
        ));
    }
    lines.push(String::new());
    lines.push(
        "Use add_evidence to record relevant items. Evidence validated against query results \
         gets higher confidence scores."
            .to_string(),
    );

    Ok(make_output(&lines.join("\n")))
}

// ---------------------------------------------------------------------------
// 12. analyze_lateral_movement
// ---------------------------------------------------------------------------

/// Analyze lateral movement graph from investigation state.
///
/// Required: `investigation_id`
/// Optional: `focus_host`
pub async fn analyze_lateral_movement(args: &Value) -> Result<ToolOutput> {
    let investigation_id = required_str(args, "investigation_id")?;
    let focus_host = optional_str(args, "focus_host");

    let mut conn = match get_redis_connection().await {
        Ok(c) => c,
        Err(e) => return Ok(make_error(&format!("Redis connection failed: {e}"))),
    };

    let lateral_key = blue_key(investigation_id, BLUE_KEY_LATERAL);
    let lateral: Vec<String> = conn.lrange(&lateral_key, 0, -1).await.unwrap_or_default();

    if lateral.is_empty() {
        return Ok(make_output(
            "No lateral connections recorded yet. Use add_lateral_connection to record connections.",
        ));
    }

    let hosts_key = blue_key(investigation_id, BLUE_KEY_HOSTS);
    let investigated_hosts: std::collections::HashSet<String> =
        conn.smembers(&hosts_key).await.unwrap_or_default();

    struct LateralConn {
        source: String,
        destination: String,
        method: String,
        user: Option<String>,
    }

    let mut connections = Vec::new();
    let mut all_hosts = std::collections::HashSet::new();

    for conn_str in &lateral {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(conn_str) {
            let src = v
                .get("source_host")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_lowercase();
            let dst = v
                .get("destination_host")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_lowercase();
            let method = v
                .get("method")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown")
                .to_string();
            let user = v.get("user").and_then(|u| u.as_str()).map(String::from);
            all_hosts.insert(src.clone());
            all_hosts.insert(dst.clone());
            connections.push(LateralConn {
                source: src,
                destination: dst,
                method,
                user,
            });
        }
    }

    let mut parts = Vec::new();
    parts.push(format!(
        "=== Lateral Movement Analysis ({} connections) ===",
        connections.len()
    ));

    // Graph summary
    let mut connection_types: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::new();
    let mut unique_users = std::collections::HashSet::new();
    for c in &connections {
        *connection_types.entry(&c.method).or_insert(0) += 1;
        if let Some(u) = &c.user {
            unique_users.insert(u.as_str());
        }
    }

    let pending: Vec<&String> = all_hosts
        .iter()
        .filter(|h| !investigated_hosts.contains(h.as_str()))
        .collect();

    parts.push(format!("Hosts in graph: {}", all_hosts.len()));
    parts.push(format!("Hosts investigated: {}", investigated_hosts.len()));
    parts.push(format!("Hosts pending: {}", pending.len()));
    parts.push(format!(
        "Connection types: {}",
        connection_types
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    if !unique_users.is_empty() {
        let mut users: Vec<&&str> = unique_users.iter().collect();
        users.sort();
        parts.push(format!(
            "Users involved: {}",
            users.iter().map(|u| **u).collect::<Vec<_>>().join(", ")
        ));
    }

    // Attack path (DFS from entry points)
    let destinations: std::collections::HashSet<&str> =
        connections.iter().map(|c| c.destination.as_str()).collect();
    let entry_points: Vec<&str> = connections
        .iter()
        .map(|c| c.source.as_str())
        .filter(|s| !destinations.contains(s))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    if !entry_points.is_empty() {
        let mut path = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut stack: Vec<&str> = entry_points;
        while let Some(host) = stack.pop() {
            if visited.contains(host) {
                continue;
            }
            visited.insert(host);
            path.push(host.to_string());
            for c in &connections {
                if c.source == host && !visited.contains(c.destination.as_str()) {
                    stack.push(&c.destination);
                }
            }
        }
        parts.push(format!("\nAttack path: {}", path.join(" -> ")));
    }

    // Pivot suggestions
    if !pending.is_empty() {
        parts.push(format!(
            "\n--- Pivot Suggestions ({} pending hosts) ---",
            pending.len()
        ));
        for host in pending.iter().take(5) {
            let incoming: Vec<&LateralConn> = connections
                .iter()
                .filter(|c| c.destination == **host)
                .collect();
            let methods: Vec<&str> = incoming.iter().map(|c| c.method.as_str()).collect();
            let sources: Vec<&str> = incoming.iter().map(|c| c.source.as_str()).collect();
            parts.push(format!(
                "  {host} (discovered from: {}, via: {})",
                sources.join(", "),
                methods.join(", ")
            ));
            parts.push(format!(
                "    Suggested: {{job=\"windows\"}} |~ \"(?i){host}\""
            ));
        }
    }

    // Focus host details
    if let Some(focus) = focus_host {
        let focus_lower = focus.to_lowercase();
        let host_conns: Vec<&LateralConn> = connections
            .iter()
            .filter(|c| c.source == focus_lower || c.destination == focus_lower)
            .collect();
        if !host_conns.is_empty() {
            parts.push(format!(
                "\n--- Connections for {focus} ({} total) ---",
                host_conns.len()
            ));
            for c in &host_conns {
                let user_str = c
                    .user
                    .as_deref()
                    .map(|u| format!(" (user={u})"))
                    .unwrap_or_default();
                parts.push(format!(
                    "  {} -> {} via {}{user_str}",
                    c.source, c.destination, c.method
                ));
            }
        }
    }

    Ok(make_output(&parts.join("\n")))
}

// ---------------------------------------------------------------------------
// 13. get_correlated_alerts
// ---------------------------------------------------------------------------

/// Get alert correlation context from investigation metadata.
///
/// Required: `investigation_id`
pub async fn get_correlated_alerts(args: &Value) -> Result<ToolOutput> {
    let investigation_id = required_str(args, "investigation_id")?;

    let mut conn = match get_redis_connection().await {
        Ok(c) => c,
        Err(e) => return Ok(make_error(&format!("Redis connection failed: {e}"))),
    };

    let meta_key = blue_key(investigation_id, BLUE_KEY_META);
    let meta: std::collections::HashMap<String, String> = conn.hgetall(&meta_key).await?;

    if let Some(ctx_json) = meta.get("correlation_context") {
        if let Ok(ctx) = serde_json::from_str::<serde_json::Value>(ctx_json) {
            let related_count = ctx
                .get("related_alerts")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .or_else(|| {
                    ctx.get("related_alert_count")
                        .and_then(|v| v.as_u64())
                        .map(|n| n as usize)
                })
                .unwrap_or(0);
            let common_hosts = ctx
                .get("common_hosts")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let common_users = ctx
                .get("common_users")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let techniques = ctx
                .get("techniques_in_cluster")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();

            let mut parts = vec!["=== Alert Correlation Context ===".to_string()];
            parts.push(format!("Related alerts: {related_count}"));
            if !common_hosts.is_empty() {
                parts.push(format!("Common hosts: {common_hosts}"));
            }
            if !common_users.is_empty() {
                parts.push(format!("Common users: {common_users}"));
            }
            if !techniques.is_empty() {
                parts.push(format!("Techniques in cluster: {techniques}"));
            }
            return Ok(make_output(&parts.join("\n")));
        }
    }

    // Fallback: return current investigation scope
    let hosts: std::collections::HashSet<String> = conn
        .smembers(blue_key(investigation_id, BLUE_KEY_HOSTS))
        .await
        .unwrap_or_default();
    let users: std::collections::HashSet<String> = conn
        .smembers(blue_key(investigation_id, BLUE_KEY_USERS))
        .await
        .unwrap_or_default();
    let techniques: std::collections::HashSet<String> = conn
        .smembers(blue_key(investigation_id, BLUE_KEY_TECHNIQUES))
        .await
        .unwrap_or_default();

    let mut parts =
        vec!["No correlation context available (this may be the first alert).".to_string()];
    if !hosts.is_empty() {
        let mut h: Vec<&String> = hosts.iter().collect();
        h.sort();
        parts.push(format!(
            "Queried hosts: {}",
            h.iter()
                .take(5)
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !users.is_empty() {
        let mut u: Vec<&String> = users.iter().collect();
        u.sort();
        parts.push(format!(
            "Queried users: {}",
            u.iter()
                .take(5)
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !techniques.is_empty() {
        let mut t: Vec<&String> = techniques.iter().collect();
        t.sort();
        parts.push(format!(
            "Identified techniques: {}",
            t.iter()
                .take(10)
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    Ok(make_output(&parts.join("\n")))
}

// ---------------------------------------------------------------------------
// 14. get_queued_queries
// ---------------------------------------------------------------------------

/// Get auto-queued pivot and chain queries from the investigation.
///
/// Required: `investigation_id`
pub async fn get_queued_queries(args: &Value) -> Result<ToolOutput> {
    let investigation_id = required_str(args, "investigation_id")?;

    let mut conn = match get_redis_connection().await {
        Ok(c) => c,
        Err(e) => return Ok(make_error(&format!("Redis connection failed: {e}"))),
    };

    let pivot_key = format!("{BLUE_KEY_PREFIX}:{investigation_id}:pivot_queue");
    let chain_key = format!("{BLUE_KEY_PREFIX}:{investigation_id}:chain_queue");
    let query_types_key = format!("{BLUE_KEY_PREFIX}:{investigation_id}:query_types");

    let pivots: Vec<String> = conn.lrange(&pivot_key, 0, -1).await.unwrap_or_default();
    let chains: Vec<String> = conn.lrange(&chain_key, 0, -1).await.unwrap_or_default();
    let executed: std::collections::HashSet<String> =
        conn.smembers(&query_types_key).await.unwrap_or_default();
    let total = pivots.len() + chains.len();

    let mut parts = vec![format!("=== Queued Queries ({total} total) ===")];

    if !pivots.is_empty() {
        parts.push(format!("\nPivot queries ({}):", pivots.len()));
        for (i, p) in pivots.iter().take(5).enumerate() {
            parts.push(format!("  {}. {p}", i + 1));
        }
        if pivots.len() > 5 {
            parts.push(format!("  ... and {} more", pivots.len() - 5));
        }
    }
    if !chains.is_empty() {
        parts.push(format!("\nChain queries ({}):", chains.len()));
        for (i, c) in chains.iter().take(5).enumerate() {
            parts.push(format!("  {}. {c}", i + 1));
        }
        if chains.len() > 5 {
            parts.push(format!("  ... and {} more", chains.len() - 5));
        }
    }
    if !executed.is_empty() {
        let mut exec_list: Vec<&String> = executed.iter().collect();
        exec_list.sort();
        parts.push(format!(
            "\nAlready executed ({}):\n  {}",
            executed.len(),
            exec_list
                .iter()
                .take(10)
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    if total > 0 {
        parts.push(format!(
            "\nRecommendation: Execute these {total} queued queries to expand investigation scope."
        ));
    } else {
        parts.push(
            "\nNo auto-queued queries. Run detection queries to trigger evidence chaining."
                .to_string(),
        );
    }

    Ok(make_output(&parts.join("\n")))
}

// ---------------------------------------------------------------------------
// 15. get_formatted_summary (rate-limited progress view)
// ---------------------------------------------------------------------------

/// Get a formatted investigation summary with progress indicators.
/// Rate-limited to 30 seconds to prevent polling loops.
///
/// Required: `investigation_id`
pub async fn get_formatted_summary(args: &Value) -> Result<ToolOutput> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    static LAST_CHECK: AtomicU64 = AtomicU64::new(0);
    static CACHE: std::sync::OnceLock<Mutex<(String, String)>> = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new((String::new(), String::new())));

    let investigation_id = required_str(args, "investigation_id")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let last = LAST_CHECK.load(Ordering::Relaxed);

    if now - last < 30 {
        let cached = cache.lock().unwrap();
        if cached.0 == investigation_id && !cached.1.is_empty() {
            return Ok(make_output(&format!(
                "[Cached - take action before checking again]\n\n{}",
                cached.1
            )));
        }
    }

    let mut conn = match get_redis_connection().await {
        Ok(c) => c,
        Err(e) => return Ok(make_error(&format!("Redis connection failed: {e}"))),
    };

    let meta_key = blue_key(investigation_id, BLUE_KEY_META);
    let meta: std::collections::HashMap<String, String> =
        conn.hgetall(&meta_key).await.unwrap_or_default();
    let stage = meta
        .get("stage")
        .and_then(|s| serde_json::from_str::<String>(s).ok())
        .unwrap_or_else(|| "unknown".to_string());

    let evidence_key = blue_key(investigation_id, BLUE_KEY_EVIDENCE);
    let evidence_count: usize = conn.hlen(&evidence_key).await.unwrap_or(0);
    let timeline_count: usize = conn
        .llen(blue_key(investigation_id, BLUE_KEY_TIMELINE))
        .await
        .unwrap_or(0);
    let technique_count: usize = conn
        .scard(blue_key(investigation_id, BLUE_KEY_TECHNIQUES))
        .await
        .unwrap_or(0);
    let lateral_count: usize = conn
        .llen(blue_key(investigation_id, BLUE_KEY_LATERAL))
        .await
        .unwrap_or(0);

    // Compute pyramid stats from evidence
    let all_evidence: std::collections::HashMap<String, String> =
        conn.hgetall(&evidence_key).await.unwrap_or_default();
    let mut highest_pyramid = 0i32;
    let (mut ttp_count, mut tool_count) = (0usize, 0usize);
    for json_str in all_evidence.values() {
        if let Ok(ev) = serde_json::from_str::<serde_json::Value>(json_str) {
            let level = ev
                .get("pyramid_level")
                .and_then(|l| l.as_i64())
                .unwrap_or(0) as i32;
            if level > highest_pyramid {
                highest_pyramid = level;
            }
            if level == 6 {
                ttp_count += 1;
            }
            if level == 5 {
                tool_count += 1;
            }
        }
    }

    let pyramid_label = match highest_pyramid {
        6 => "6/6 (TTPs)",
        5 => "5/6 (Tools)",
        4 => "4/6 (Network/Host Artifacts)",
        3 => "3/6 (Domain Names)",
        2 => "2/6 (IP Addresses)",
        1 => "1/6 (Hash Values)",
        _ => "0/6 (None)",
    };

    let mut lines = Vec::new();
    lines.push("INVESTIGATION SUMMARY".to_string());
    lines.push("========================================".to_string());
    lines.push(format!("Investigation: {investigation_id}"));
    lines.push(format!("Stage: {}", stage.to_uppercase()));
    lines.push(String::new());
    lines.push("Discovery Metrics:".to_string());
    lines.push(format!("  Evidence collected: {evidence_count}"));
    lines.push(format!("  Timeline events: {timeline_count}"));
    lines.push(format!("  Techniques identified: {technique_count}"));
    lines.push(format!("  Lateral connections: {lateral_count}"));
    lines.push(String::new());
    lines.push("Pyramid Progress:".to_string());
    lines.push(format!("  Highest level reached: {pyramid_label}"));
    lines.push(format!("  TTPs identified: {ttp_count}"));
    lines.push(String::new());
    lines.push("Milestones:".to_string());
    if ttp_count > 0 {
        lines.push(format!("  [x] TTP LEVEL REACHED ({ttp_count} TTPs)"));
    } else {
        lines.push("  [ ] TTP level: not yet reached".to_string());
    }
    if tool_count > 0 {
        lines.push(format!("  [x] TOOL IDENTIFICATION COMPLETE ({tool_count})"));
    } else {
        lines.push("  [ ] Tool identification: pending".to_string());
    }
    if technique_count >= 3 {
        lines.push("  [x] COMPREHENSIVE TECHNIQUE COVERAGE".to_string());
    } else {
        lines.push(format!(
            "  [ ] Technique coverage: {technique_count}/3 minimum"
        ));
    }

    let output = lines.join("\n");

    LAST_CHECK.store(now, Ordering::Relaxed);
    {
        let mut cached = cache.lock().unwrap();
        cached.0 = investigation_id.to_string();
        cached.1 = output.clone();
    }

    Ok(make_output(&output))
}

// ---------------------------------------------------------------------------
// Queue pop tools (pivot & chain queues)
// ---------------------------------------------------------------------------

const BLUE_KEY_PIVOT_QUEUE: &str = "pivot_queue";
const BLUE_KEY_CHAIN_QUEUE: &str = "chain_queue";

/// Pop all queued pivot and chain queries, deduped and ready for execution.
pub async fn pop_all_queued(args: &Value) -> Result<ToolOutput> {
    let investigation_id = required_str(args, "investigation_id")?;
    let mut conn = get_redis_connection().await?;

    let pivot_key = blue_key(investigation_id, BLUE_KEY_PIVOT_QUEUE);
    let chain_key = blue_key(investigation_id, BLUE_KEY_CHAIN_QUEUE);

    let pivots: Vec<String> = redis::cmd("LRANGE")
        .arg(&pivot_key)
        .arg(0i64)
        .arg(-1i64)
        .query_async(&mut conn)
        .await
        .unwrap_or_default();

    let chains: Vec<String> = redis::cmd("LRANGE")
        .arg(&chain_key)
        .arg(0i64)
        .arg(-1i64)
        .query_async(&mut conn)
        .await
        .unwrap_or_default();

    // Delete the queues after reading
    if !pivots.is_empty() {
        let _: () = conn.del(&pivot_key).await.unwrap_or_default();
    }
    if !chains.is_empty() {
        let _: () = conn.del(&chain_key).await.unwrap_or_default();
    }

    // Dedup across both queues
    let mut seen = std::collections::HashSet::new();
    let mut all_queries = Vec::new();

    for q in pivots.iter() {
        if seen.insert(q.clone()) {
            all_queries.push(format!("[pivot] {q}"));
        }
    }
    for q in chains.iter() {
        if seen.insert(q.clone()) {
            all_queries.push(format!("[chain] {q}"));
        }
    }

    if all_queries.is_empty() {
        return Ok(make_output("No queued queries."));
    }

    Ok(make_output(&format!(
        "Popped {} queries ({} pivot, {} chain):\n\n{}",
        all_queries.len(),
        pivots.len(),
        chains.len(),
        all_queries.join("\n")
    )))
}
