//! Analysis and queue tools (tools 11-16).

use anyhow::Result;
use redis::AsyncCommands;
use serde_json::Value;

use crate::args::{optional_str, required_str};
use crate::ToolOutput;

use super::super::evidence_validator;
use super::{
    blue_key, get_redis_connection, make_error, make_output, BLUE_KEY_EVIDENCE, BLUE_KEY_HOSTS,
    BLUE_KEY_LATERAL, BLUE_KEY_META, BLUE_KEY_PREFIX, BLUE_KEY_TECHNIQUES, BLUE_KEY_TIMELINE,
    BLUE_KEY_USERS,
};

// ---------------------------------------------------------------------------
// 11. get_suggested_evidence
// ---------------------------------------------------------------------------

/// Get auto-extracted IOCs from recent query results as evidence suggestions.
pub fn get_suggested_evidence(_args: &Value) -> Result<ToolOutput> {
    let iocs = evidence_validator::get_suggested_iocs();
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
