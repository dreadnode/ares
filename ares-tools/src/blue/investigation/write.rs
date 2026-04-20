//! Write/mutation investigation tools (tools 1-7).

use anyhow::{Context, Result};
use redis::AsyncCommands;
use serde_json::Value;
use uuid::Uuid;

use crate::args::{optional_str, required_str};
use crate::ToolOutput;

use super::super::{evidence_validator, validation};
use super::{
    blue_key, get_redis_connection, make_error, make_output, BLUE_KEY_EVIDENCE, BLUE_KEY_HOSTS,
    BLUE_KEY_LATERAL, BLUE_KEY_META, BLUE_KEY_TECHNIQUES, BLUE_KEY_TECHNIQUE_NAMES,
    BLUE_KEY_TIMELINE, BLUE_KEY_USERS, TTL_SECS,
};

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

    // Validate evidence against recent query results and adjust confidence
    let (query_validated, _source_query_id) = evidence_validator::validate_evidence_value(value);
    let raw_confidence = args
        .get("confidence")
        .and_then(Value::as_f64)
        .unwrap_or(0.5);
    let confidence = evidence_validator::adjust_confidence(raw_confidence, query_validated);

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

    let evidence_id = Uuid::new_v4().to_string();

    let evidence = serde_json::json!({
        "id": evidence_id,
        "type": vr.normalized_type,
        "value": value,
        "source": source,
        "timestamp": timestamp,
        "pyramid_level": pyramid_level_int,
        "confidence": confidence,
        "mitre_techniques": mitre_techniques,
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
// 1b. add_evidence_batch
// ---------------------------------------------------------------------------

/// Add multiple evidence items in a single call using a Redis pipeline.
///
/// Required: `investigation_id`, `items` (array of evidence objects)
/// Each item requires: `evidence_type`, `value`, `source`
/// Each item optionally: `confidence`, `pyramid_level`, `timestamp`
pub async fn add_evidence_batch(args: &Value) -> Result<ToolOutput> {
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

        let (query_validated, _) = evidence_validator::validate_evidence_value(value);
        let raw_confidence = item
            .get("confidence")
            .and_then(Value::as_f64)
            .unwrap_or(0.5);
        let confidence = evidence_validator::adjust_confidence(raw_confidence, query_validated);

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

        let mitre_techniques: Vec<String> = item
            .get("mitre_techniques")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        let evidence_id = Uuid::new_v4().to_string();

        let evidence = serde_json::json!({
            "id": evidence_id,
            "type": vr.normalized_type,
            "value": value,
            "source": source,
            "timestamp": timestamp,
            "pyramid_level": pyramid_level_int,
            "confidence": confidence,
            "mitre_techniques": mitre_techniques,
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
        "Batch complete: {added_count} added, {dup_count} duplicates, {} invalid",
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

    let dep_label = std::env::var("ARES_DEPLOYMENT")
        .map(|d| format!(r#", deployment="{d}""#))
        .unwrap_or_default();

    let suggested_queries = format!(
        "\n\nSuggested queries for {hostname}:\n\
         - Authentication: {{job=\"windows-security\"{dep_label}, computer=~\"{hostname}\"}} |~ \"4624|4625|4648\"\n\
         - Process creation: {{job=\"windows-security\"{dep_label}, computer=~\"{hostname}\"}} |~ \"4688|1\"\n\
         - Lateral movement: {{job=\"windows-security\"{dep_label}, computer=~\"{hostname}\"}} |~ \"5140|5145|4624\"\n\
         - Service installation: {{job=\"windows-system\"{dep_label}, computer=~\"{hostname}\"}} |~ \"7045|4697\"\n\
         - Scheduled tasks: {{job=\"windows-security\"{dep_label}, computer=~\"{hostname}\"}} |~ \"4698|4702\"\n\
         - All activity: {{job=\"windows-security\"{dep_label}, computer=~\"{hostname}\"}}"
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

    let dep_label = std::env::var("ARES_DEPLOYMENT")
        .map(|d| format!(r#", deployment="{d}""#))
        .unwrap_or_default();

    let suggested_queries = format!(
        "\n\nSuggested queries for {username}:\n\
         - Logon events: {{job=\"windows-security\"{dep_label}}} |~ \"(?i){username}\" |~ \"4624|4625|4648\"\n\
         - Kerberos: {{job=\"windows-security\"{dep_label}}} |~ \"(?i){username}\" |~ \"4768|4769|4771\"\n\
         - Privilege use: {{job=\"windows-security\"{dep_label}}} |~ \"(?i){username}\" |~ \"4672|4673\"\n\
         - Object access: {{job=\"windows-security\"{dep_label}}} |~ \"(?i){username}\" |~ \"4662|4663\"\n\
         - Account changes: {{job=\"windows-security\"{dep_label}}} |~ \"(?i){username}\" |~ \"4720|4722|4738\"\n\
         - All activity: {{job=\"windows-security\"{dep_label}}} |~ \"(?i){username}\""
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
