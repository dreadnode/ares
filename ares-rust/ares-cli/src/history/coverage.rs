use std::collections::{HashMap, HashSet};

use anyhow::Result;
use chrono::Utc;

use super::connect_postgres;
use super::types::MitreCoverageRow;

pub(crate) async fn history_mitre_coverage(
    since_days: Option<i64>,
    json_output: bool,
) -> Result<()> {
    let pool = connect_postgres().await?;

    let since = since_days.map(|days| Utc::now() - chrono::Duration::days(days));

    // Query timeline events joined with operations to get MITRE techniques
    let rows: Vec<MitreCoverageRow> = if let Some(ref since_ts) = since {
        sqlx::query_as::<_, MitreCoverageRow>(
            "SELECT te.mitre_techniques, o.operation_id \
             FROM timeline_events te \
             JOIN operations o ON te.operation_id = o.id \
             WHERE te.mitre_techniques IS NOT NULL \
               AND array_length(te.mitre_techniques, 1) > 0 \
               AND o.started_at >= $1",
        )
        .bind(since_ts)
        .fetch_all(&pool)
        .await?
    } else {
        sqlx::query_as::<_, MitreCoverageRow>(
            "SELECT te.mitre_techniques, o.operation_id \
             FROM timeline_events te \
             JOIN operations o ON te.operation_id = o.id \
             WHERE te.mitre_techniques IS NOT NULL \
               AND array_length(te.mitre_techniques, 1) > 0",
        )
        .fetch_all(&pool)
        .await?
    };

    // Aggregate: technique_id -> set of operation_ids
    let mut coverage: HashMap<String, HashSet<String>> = HashMap::new();
    for row in &rows {
        for technique in &row.mitre_techniques {
            coverage
                .entry(technique.clone())
                .or_default()
                .insert(row.operation_id.clone());
        }
    }

    // Sort by occurrence count descending
    let mut sorted: Vec<(String, Vec<String>)> = coverage
        .into_iter()
        .map(|(t, ops)| {
            let mut ops_vec: Vec<String> = ops.into_iter().collect();
            ops_vec.sort();
            (t, ops_vec)
        })
        .collect();
    sorted.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));

    if json_output {
        let data: Vec<serde_json::Value> = sorted
            .iter()
            .map(|(technique, ops)| {
                serde_json::json!({
                    "technique_id": technique,
                    "occurrence_count": ops.len(),
                    "operations": ops,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    } else {
        if sorted.is_empty() {
            println!("No MITRE techniques found");
            return Ok(());
        }

        println!("\n{:<18} {:<8} OPERATIONS", "TECHNIQUE", "COUNT");
        println!("{}", "-".repeat(80));
        for (technique, ops) in &sorted {
            let ops_display = if ops.len() <= 3 {
                ops.join(", ")
            } else {
                let shown: Vec<&str> = ops.iter().take(3).map(|s| s.as_str()).collect();
                format!("{} (+{} more)", shown.join(", "), ops.len() - 3)
            };
            println!("{:<18} {:<8} {}", technique, ops.len(), ops_display);
        }
        println!("\nTotal: {} techniques", sorted.len());
    }

    Ok(())
}
