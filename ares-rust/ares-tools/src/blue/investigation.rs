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

/// Read investigation state and return a formatted summary.
///
/// Required: `investigation_id`
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
