//! Read/query investigation tools (tools 8-10).

use anyhow::Result;
use redis::AsyncCommands;
use serde_json::Value;

use crate::args::required_str;
use crate::ToolOutput;

use super::{
    blue_key, get_redis_connection, make_error, make_output, BLUE_KEY_EVIDENCE, BLUE_KEY_HOSTS,
    BLUE_KEY_LATERAL, BLUE_KEY_META, BLUE_KEY_TECHNIQUES, BLUE_KEY_TECHNIQUE_NAMES,
    BLUE_KEY_TIMELINE, BLUE_KEY_USERS,
};

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
