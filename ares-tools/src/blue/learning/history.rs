//! Investigation history tools — backed by the persistence store.

use anyhow::Result;
use serde_json::Value;

use crate::args::required_str;
use crate::ToolOutput;

/// Find similar past investigations for learning and guidance.
///
/// Parameters:
/// - `alert_name` (optional)
/// - `technique_id` (optional)
/// - `severity` (optional)
/// - `limit` (optional, default: 5)
pub fn find_similar_investigations(args: &Value) -> Result<ToolOutput> {
    let alert_name = args.get("alert_name").and_then(Value::as_str);
    let technique_id = args.get("technique_id").and_then(Value::as_str);
    let severity = args.get("severity").and_then(Value::as_str);
    let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(5) as usize;

    if alert_name.is_none() && technique_id.is_none() && severity.is_none() {
        return Ok(ToolOutput {
            stdout: String::new(),
            stderr: "At least one of alert_name, technique_id, or severity is required".into(),
            exit_code: Some(1),
            success: false,
        });
    }

    let store = crate::blue::persistence::get_investigation_store();
    let similar = store.find_similar_investigations(
        alert_name,
        None, // fingerprint not available in tool context
        technique_id,
        severity,
        limit,
    );

    if similar.is_empty() {
        return Ok(ToolOutput {
            stdout: "No similar past investigations found.".into(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        });
    }

    let mut lines = vec![format!(
        "Found {} similar investigation(s):\n",
        similar.len()
    )];

    let completed_count = similar
        .iter()
        .filter(|s| s.investigation.status == "completed")
        .count();
    let tp_count = similar
        .iter()
        .filter(|s| s.investigation.is_true_positive == Some(true))
        .count();
    let fp_count = similar
        .iter()
        .filter(|s| s.investigation.is_true_positive == Some(false))
        .count();

    lines.push(format!(
        "Summary: {completed_count} completed, {tp_count} true positive(s), {fp_count} false positive(s)\n"
    ));

    for (i, sim) in similar.iter().enumerate() {
        let inv = &sim.investigation;
        let tp_label = match inv.is_true_positive {
            Some(true) => " [TRUE POSITIVE]",
            Some(false) => " [FALSE POSITIVE]",
            None => "",
        };

        lines.push(format!(
            "{}. {} (similarity: {:.0}%, matched: {}){tp_label}",
            i + 1,
            inv.alert_name,
            sim.similarity_score * 100.0,
            sim.matching_factors.join(", "),
        ));
        lines.push(format!(
            "   Status: {}, Evidence: {}, Techniques: {}, Duration: {:.0}s",
            inv.status,
            inv.evidence_count,
            inv.techniques_identified.len(),
            inv.duration_seconds,
        ));
        if !inv.effective_queries.is_empty() {
            lines.push(format!(
                "   Effective queries: {}",
                inv.effective_queries.join(", ")
            ));
        }
    }

    // Generate guidance from best completed investigation
    if let Some(best) = similar
        .iter()
        .find(|s| {
            s.investigation.status == "completed" && s.investigation.is_true_positive == Some(true)
        })
        .or_else(|| {
            similar
                .iter()
                .find(|s| s.investigation.status == "completed")
        })
    {
        lines.push(String::new());
        lines.push("**Guidance from best match**:".to_string());
        if !best.investigation.techniques_identified.is_empty() {
            lines.push(format!(
                "- Previously identified techniques: {}",
                best.investigation.techniques_identified.join(", ")
            ));
        }
        if !best.investigation.effective_queries.is_empty() {
            lines.push(format!(
                "- Recommended queries: {}",
                best.investigation.effective_queries.join(", ")
            ));
        }
        lines.push(format!(
            "- Previous query success rate: {:.0}%",
            best.investigation.query_success_rate * 100.0
        ));
    }

    Ok(ToolOutput {
        stdout: lines.join("\n"),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    })
}

/// Get effective queries that have historically produced evidence.
///
/// Parameters:
/// - `alert_name` (optional): Filter by alert type
/// - `limit` (optional, default: 10)
pub fn get_effective_queries(args: &Value) -> Result<ToolOutput> {
    let alert_name = args.get("alert_name").and_then(Value::as_str);
    let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(10) as usize;

    let store = crate::blue::persistence::get_investigation_store();
    let queries = store.get_effective_queries(alert_name, 0.2, limit);

    if queries.is_empty() {
        return Ok(ToolOutput {
            stdout: "No effective queries found yet. Query effectiveness is tracked as investigations are completed.".into(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        });
    }

    let mut lines = vec![format!(
        "Top {} effective queries (min 3 executions, 20%+ evidence rate):\n",
        queries.len()
    )];

    for (i, q) in queries.iter().enumerate() {
        lines.push(format!(
            "{}. {} — success: {:.0}%, evidence: {:.0}% ({} executions)",
            i + 1,
            q.query_pattern,
            q.success_rate() * 100.0,
            q.evidence_rate() * 100.0,
            q.total_executions,
        ));
    }

    Ok(ToolOutput {
        stdout: lines.join("\n"),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    })
}

/// Check if an alert matches known false positive patterns.
///
/// Parameters:
/// - `alert_name` (required)
/// - `alert_fingerprint` (optional)
pub fn check_false_positive_pattern(args: &Value) -> Result<ToolOutput> {
    let alert_name = required_str(args, "alert_name")?;
    let alert_fingerprint = args.get("alert_fingerprint").and_then(Value::as_str);

    let store = crate::blue::persistence::get_investigation_store();

    // Find similar investigations to compute FP rate
    let similar =
        store.find_similar_investigations(Some(alert_name), alert_fingerprint, None, None, 20);

    if similar.is_empty() {
        return Ok(ToolOutput {
            stdout: format!(
                "No historical data for alert '{alert_name}'. Cannot assess false positive likelihood."
            ),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        });
    }

    let labeled = similar
        .iter()
        .filter(|s| s.investigation.is_true_positive.is_some())
        .count();
    let fp_count = similar
        .iter()
        .filter(|s| s.investigation.is_true_positive == Some(false))
        .count();

    let fp_rate = if labeled > 0 {
        fp_count as f64 / labeled as f64
    } else {
        0.0
    };

    // Check known FP patterns
    let fp_patterns = store.get_false_positive_patterns(2);
    let matching_pattern = fp_patterns
        .iter()
        .find(|p| p.alert_name.to_lowercase() == alert_name.to_lowercase());

    let confidence = if fp_rate > 0.8 {
        "HIGH"
    } else if fp_rate > 0.5 {
        "MEDIUM"
    } else {
        "LOW"
    };

    let mut lines = Vec::new();
    lines.push(format!("False positive assessment for '{alert_name}':"));
    lines.push(format!(
        "  Historical FP rate: {:.0}% ({fp_count}/{labeled} labeled investigations)",
        fp_rate * 100.0
    ));
    lines.push(format!("  Confidence: {confidence}"));
    lines.push(format!("  Total similar investigations: {}", similar.len()));

    if let Some(pattern) = matching_pattern {
        lines.push(format!(
            "  Known FP pattern: {} occurrences, {:.0}% FP rate",
            pattern.occurrences,
            pattern.fp_rate * 100.0
        ));
    }

    if fp_rate > 0.5 {
        lines.push(String::new());
        lines.push(
            "  Recommendation: This alert has a high false positive rate. \
             Consider tuning the detection rule or adding exclusions."
                .to_string(),
        );
    }

    Ok(ToolOutput {
        stdout: lines.join("\n"),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    })
}

/// Get aggregate investigation statistics.
pub fn get_investigation_statistics(_args: &Value) -> Result<ToolOutput> {
    let store = crate::blue::persistence::get_investigation_store();
    let stats = store.get_statistics();

    if stats.total_investigations == 0 {
        return Ok(ToolOutput {
            stdout: "No investigations recorded yet.".into(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        });
    }

    let fp_rate = if stats.labeled > 0 {
        stats.false_positives as f64 / stats.labeled as f64
    } else {
        0.0
    };

    let lines = [
        "=== Investigation Statistics ===".to_string(),
        format!("Total investigations: {}", stats.total_investigations),
        format!(
            "  Completed: {}, Escalated: {}, Failed: {}",
            stats.completed, stats.escalated, stats.failed
        ),
        format!(
            "  True positives: {}, False positives: {} ({} labeled, {:.0}% FP rate)",
            stats.true_positives,
            stats.false_positives,
            stats.labeled,
            fp_rate * 100.0
        ),
        format!(
            "  Avg duration: {:.0}s, Avg evidence: {:.1} items",
            stats.avg_duration_seconds, stats.avg_evidence_count
        ),
    ];

    Ok(ToolOutput {
        stdout: lines.join("\n"),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    })
}
