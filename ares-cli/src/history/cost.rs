use anyhow::Result;
use chrono::Utc;

use super::connect_postgres;
use super::types::CostRow;

pub(crate) async fn history_cost(
    domain: Option<String>,
    since_days: Option<i64>,
    limit: i64,
    json_output: bool,
) -> Result<()> {
    let pool = connect_postgres().await?;
    let since = since_days.map(|days| Utc::now() - chrono::Duration::days(days));

    let mut query = String::from(
        "SELECT operation_id, target_domain, started_at, \
         total_input_tokens, total_output_tokens, total_cost, model_usage \
         FROM operations WHERE total_input_tokens IS NOT NULL",
    );
    let mut bind_idx = 0u32;
    let mut conditions: Vec<String> = Vec::new();

    if domain.is_some() {
        bind_idx += 1;
        conditions.push(format!(" AND target_domain ILIKE ${bind_idx}"));
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

    let mut q = sqlx::query_as::<_, CostRow>(sqlx::AssertSqlSafe(query.as_str()));

    if let Some(ref d) = domain {
        q = q.bind(format!("%{d}%"));
    }
    if let Some(ref s) = since {
        q = q.bind(s);
    }
    q = q.bind(limit);

    let rows: Vec<CostRow> = q.fetch_all(&pool).await?;

    if json_output {
        let data: Vec<serde_json::Value> = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "operation_id": r.operation_id,
                    "target_domain": r.target_domain,
                    "started_at": r.started_at.to_rfc3339(),
                    "input_tokens": r.total_input_tokens,
                    "output_tokens": r.total_output_tokens,
                    "total_tokens": r.total_input_tokens.unwrap_or(0) + r.total_output_tokens.unwrap_or(0),
                    "cost": r.total_cost,
                    "model_usage": r.model_usage,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    } else {
        if rows.is_empty() {
            println!("No operations with token usage data found");
            return Ok(());
        }

        println!(
            "\n{:<30} {:<20} {:>12} {:>12} {:>10}",
            "OPERATION ID", "DOMAIN", "IN TOKENS", "OUT TOKENS", "COST"
        );
        println!("{}", "-".repeat(90));

        let mut grand_total_in: i64 = 0;
        let mut grand_total_out: i64 = 0;
        let mut grand_total_cost: f64 = 0.0;

        for r in &rows {
            let in_tok = r.total_input_tokens.unwrap_or(0);
            let out_tok = r.total_output_tokens.unwrap_or(0);
            let cost = r.total_cost.unwrap_or(0.0);
            grand_total_in += in_tok;
            grand_total_out += out_tok;
            grand_total_cost += cost;

            let domain_display = r
                .target_domain
                .as_deref()
                .unwrap_or("")
                .chars()
                .take(19)
                .collect::<String>();
            let cost_str = if cost > 0.0 {
                format!("${cost:.4}")
            } else {
                "-".to_string()
            };

            println!(
                "{:<30} {:<20} {:>12} {:>12} {:>10}",
                r.operation_id, domain_display, in_tok, out_tok, cost_str
            );
        }

        println!("{}", "-".repeat(90));
        let grand_cost_str = if grand_total_cost > 0.0 {
            format!("${grand_total_cost:.4}")
        } else {
            "-".to_string()
        };
        println!(
            "{:<30} {:<20} {:>12} {:>12} {:>10}",
            format!("TOTAL ({} ops)", rows.len()),
            "",
            grand_total_in,
            grand_total_out,
            grand_cost_str
        );
    }

    Ok(())
}
