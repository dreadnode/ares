use anyhow::Result;
use chrono::Utc;

use super::connect_postgres;
use super::types::OperationRow;
use crate::util::compute_duration_str;

pub(crate) async fn history_list(
    domain: Option<String>,
    has_da: Option<bool>,
    since_days: Option<i64>,
    limit: i64,
    json_output: bool,
) -> Result<()> {
    let pool = connect_postgres().await?;

    let since = since_days.map(|days| Utc::now() - chrono::Duration::days(days));

    // Build dynamic query
    let mut query = String::from(
        "SELECT operation_id, target_domain, target_ip::text, started_at, completed_at, \
         has_domain_admin, has_golden_ticket, \
         COALESCE(credential_count, 0) as credential_count, \
         COALESCE(hash_count, 0) as hash_count, \
         COALESCE(host_count, 0) as host_count, \
         COALESCE(vulnerability_count, 0) as vulnerability_count \
         FROM operations WHERE 1=1",
    );
    let mut bind_idx = 0u32;
    let mut conditions: Vec<String> = Vec::new();

    if domain.is_some() {
        bind_idx += 1;
        conditions.push(format!(" AND target_domain ILIKE ${bind_idx}"));
    }
    if has_da.is_some() {
        bind_idx += 1;
        conditions.push(format!(" AND has_domain_admin = ${bind_idx}"));
    }
    if since.is_some() {
        bind_idx += 1;
        conditions.push(format!(" AND started_at >= ${bind_idx}"));
    }

    for c in &conditions {
        query.push_str(c);
    }
    bind_idx += 1;
    query.push_str(&format!(" ORDER BY started_at DESC LIMIT ${bind_idx}"));

    let mut q = sqlx::query_as::<_, OperationRow>(&query);

    if let Some(ref d) = domain {
        q = q.bind(format!("%{d}%"));
    }
    if let Some(da) = has_da {
        q = q.bind(da);
    }
    if let Some(ref s) = since {
        q = q.bind(s);
    }
    q = q.bind(limit);

    let rows: Vec<OperationRow> = q.fetch_all(&pool).await?;

    if json_output {
        let data: Vec<serde_json::Value> = rows
            .iter()
            .map(|op| {
                let duration = compute_duration_str(op.started_at, op.completed_at);
                serde_json::json!({
                    "operation_id": op.operation_id,
                    "target_domain": op.target_domain,
                    "target_ip": op.target_ip,
                    "started_at": op.started_at.to_rfc3339(),
                    "completed_at": op.completed_at.map(|t| t.to_rfc3339()),
                    "has_domain_admin": op.has_domain_admin,
                    "has_golden_ticket": op.has_golden_ticket,
                    "duration": duration,
                    "credentials": op.credential_count,
                    "hashes": op.hash_count,
                    "hosts": op.host_count,
                    "vulnerabilities": op.vulnerability_count,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    } else {
        if rows.is_empty() {
            println!("No operations found");
            return Ok(());
        }

        println!(
            "\n{:<30} {:<25} {:<4} {:<6} {:<7} {:<12}",
            "OPERATION ID", "DOMAIN", "DA", "CREDS", "HASHES", "DURATION"
        );
        println!("{}", "-".repeat(95));
        for op in &rows {
            let da_mark = if op.has_domain_admin { "Y" } else { "N" };
            let domain_display = op
                .target_domain
                .as_deref()
                .unwrap_or("")
                .chars()
                .take(24)
                .collect::<String>();
            let duration = compute_duration_str(op.started_at, op.completed_at);
            println!(
                "{:<30} {:<25} {:<4} {:<6} {:<7} {:<12}",
                op.operation_id,
                domain_display,
                da_mark,
                op.credential_count,
                op.hash_count,
                duration
            );
        }
        println!("\nTotal: {} operations", rows.len());
    }

    Ok(())
}
