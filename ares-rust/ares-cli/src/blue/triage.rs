use std::collections::HashMap;

use anyhow::Result;
use redis::AsyncCommands;

use crate::redis_conn::connect_redis;

use super::resolve_investigation_id;

pub(crate) async fn blue_triage_status(
    redis_url: Option<String>,
    investigation_id: Option<String>,
    latest: bool,
    json_output: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let inv_id = resolve_investigation_id(&mut conn, investigation_id, latest).await?;

    // Read triage decision
    let decision_key = format!("ares:blue:inv:{inv_id}:triage:decision");
    let decision_raw: Option<String> = conn.get(&decision_key).await?;

    // Read triage records (audit trail)
    let records_key = format!("ares:blue:inv:{inv_id}:triage:records");
    let records_raw: Vec<String> = conn.lrange(&records_key, 0, -1).await?;
    let mut records: Vec<serde_json::Value> = Vec::new();
    for r in &records_raw {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(r) {
            records.push(v);
        }
    }

    // Read investigation status
    let status_key = format!("ares:blue:inv:{inv_id}:status");
    let status_raw: Option<String> = conn.get(&status_key).await?;
    let status = status_raw
        .as_ref()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        .and_then(|v| v.get("status").and_then(|s| s.as_str()).map(String::from))
        .unwrap_or_else(|| "unknown".to_string());

    // Read meta for escalation info
    let meta_key = format!("ares:blue:inv:{inv_id}:meta");
    let meta_data: HashMap<String, String> = conn.hgetall(&meta_key).await?;
    let escalated = meta_data
        .get("escalated")
        .and_then(|v| serde_json::from_str::<bool>(v).ok())
        .unwrap_or(false);
    let escalation_reason = meta_data.get("escalation_reason").and_then(|v| {
        serde_json::from_str::<serde_json::Value>(v)
            .ok()
            .and_then(|val| val.as_str().map(String::from))
            .or_else(|| Some(v.clone()))
    });

    if json_output {
        let decision_val = decision_raw
            .as_ref()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
        let output = serde_json::json!({
            "investigation_id": inv_id,
            "status": status,
            "escalated": escalated,
            "escalation_reason": escalation_reason,
            "triage_decision": decision_val,
            "triage_records": records,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
        return Ok(());
    }

    println!("Investigation: {inv_id}");
    println!("Status: {status}");
    println!("Escalated: {escalated}");
    if let Some(reason) = &escalation_reason {
        println!("Escalation reason: {reason}");
    }
    println!("{}", "-".repeat(60));

    if decision_raw.is_none() && records.is_empty() {
        println!("No triage data found (investigation may not have been escalated)");
        return Ok(());
    }

    println!("\nTriage Decision:");
    if let Some(ref decision_str) = decision_raw {
        if let Ok(decision) = serde_json::from_str::<serde_json::Value>(decision_str) {
            let dec_val = decision
                .get("decision")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            println!("  Decision: {}", dec_val.to_uppercase());
            let confidence = decision
                .get("confidence")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            println!("  Confidence: {confidence:.2}");
            if let Some(routed_to) = decision.get("routed_to").and_then(|v| v.as_str()) {
                if !routed_to.is_empty() {
                    println!("  Routed to: {routed_to}");
                }
            }
            if let Some(focus_areas) = decision.get("focus_areas").and_then(|v| v.as_array()) {
                let areas: Vec<&str> = focus_areas.iter().filter_map(|v| v.as_str()).collect();
                if !areas.is_empty() {
                    println!("  Focus areas: {}", areas.join(", "));
                }
            }
            if let Some(cycle) = decision
                .get("reinvestigation_cycle")
                .and_then(|v| v.as_i64())
            {
                if cycle > 0 {
                    println!("  Reinvestigation cycle: {cycle}/2");
                }
            }
            let reasoning = decision
                .get("reasoning")
                .and_then(|v| v.as_str())
                .unwrap_or("None provided");
            println!("\n  Reasoning: {reasoning}");
        }
    } else {
        println!("  Decision: PENDING");
    }

    if !records.is_empty() {
        println!("\n{}", "-".repeat(60));
        println!("Triage Audit Trail:");
        for (i, record) in records.iter().enumerate() {
            let created_at = record
                .get("created_at")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            println!("\n  [{}] {created_at}", i + 1);
            let dec = record
                .get("decision")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            println!("      Decision: {}", dec.to_uppercase());
            let conf = record
                .get("confidence")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            println!("      Confidence: {conf:.2}");
            let reasoning = record
                .get("reasoning")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if reasoning.len() > 100 {
                let mut end = 100;
                while !reasoning.is_char_boundary(end) {
                    end -= 1;
                }
                println!("      Reasoning: {}...", &reasoning[..end]);
            } else {
                println!("      Reasoning: {reasoning}");
            }
        }
    }

    Ok(())
}
