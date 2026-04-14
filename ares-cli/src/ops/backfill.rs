use std::collections::HashSet;

use anyhow::{Context, Result};
use tracing::info;

use ares_core::state::{self, RedisStateReader};

use crate::redis_conn::{connect_redis, resolve_operation_id};

pub(crate) async fn ops_backfill_domains(
    redis_url: Option<String>,
    operation_id: String,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let reader = RedisStateReader::new(operation_id.clone());

    let state = reader
        .load_state(&mut conn)
        .await?
        .with_context(|| format!("No state found for operation: {operation_id}"))?;

    let mut inferred_domains = HashSet::new();

    // Extract domains from target
    if let Some(target) = &state.target {
        let d = target.domain.trim().to_lowercase();
        if !d.is_empty() {
            inferred_domains.insert(d);
        }
    }

    // Extract from credentials
    for cred in &state.all_credentials {
        let d = cred.domain.trim().to_lowercase();
        if !d.is_empty() {
            inferred_domains.insert(d);
        }
    }

    // Extract from users
    for user in &state.all_users {
        let d = user.domain.trim().to_lowercase();
        if !d.is_empty() {
            inferred_domains.insert(d);
        }
    }

    // Extract from hashes
    for h in &state.all_hashes {
        let d = h.domain.trim().to_lowercase();
        if !d.is_empty() {
            inferred_domains.insert(d);
        }
    }

    // Extract from hostnames
    for host in &state.all_hosts {
        if host.hostname.contains('.') {
            let parts: Vec<&str> = host.hostname.split('.').collect();
            if parts.len() > 1 {
                let domain = parts[1..].join(".");
                inferred_domains.insert(domain.to_lowercase());
            }
        }
    }

    let existing: HashSet<String> = state
        .all_domains
        .iter()
        .map(|d| d.trim().to_lowercase())
        .collect();

    let mut added = Vec::new();
    for domain in &inferred_domains {
        if !existing.contains(domain) {
            let was_new = reader.add_domain(&mut conn, domain).await?;
            if was_new {
                added.push(domain.clone());
            }
        }
    }

    if added.is_empty() {
        println!("Backfilled domains (0): None");
    } else {
        let n = state::publish_state_update(&mut conn, &operation_id)
            .await
            .unwrap_or(0);
        println!(
            "Backfilled domains ({}): {} ({n} subscribers notified)",
            added.len(),
            added.join(", ")
        );
    }

    Ok(())
}

pub(crate) async fn ops_offload_cost(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let op_id = resolve_operation_id(&mut conn, operation_id, latest).await?;

    // Read token usage from Redis
    let usage = ares_core::token_usage::get_token_usage(&mut conn, &op_id)
        .await?
        .with_context(|| format!("No token usage data in Redis for operation: {op_id}"))?;

    if usage.input_tokens == 0 && usage.output_tokens == 0 {
        println!("No token usage to offload for operation {op_id}");
        return Ok(());
    }

    // Calculate cost
    let (total_cost, breakdown, _unpriced) = ares_core::token_usage::estimate_usage_cost(&usage);

    // Build per-model JSONB payload
    let model_usage_json: serde_json::Value = if !usage.models.is_empty() {
        let mut models = serde_json::Map::new();
        for (model_name, model_usage) in &usage.models {
            let cost_for_model = breakdown
                .iter()
                .find(|b| &b.model == model_name)
                .map(|b| b.cost)
                .unwrap_or(0.0);
            models.insert(
                model_name.clone(),
                serde_json::json!({
                    "input_tokens": model_usage.input_tokens,
                    "output_tokens": model_usage.output_tokens,
                    "cost": cost_for_model,
                }),
            );
        }
        serde_json::Value::Object(models)
    } else {
        serde_json::Value::Null
    };

    // Write to PostgreSQL
    let pool = crate::history::connect_postgres().await?;

    let rows_affected = sqlx::query(
        "UPDATE operations SET \
         total_input_tokens = $1, \
         total_output_tokens = $2, \
         total_cost = $3, \
         model_usage = $4 \
         WHERE operation_id = $5",
    )
    .bind(usage.input_tokens as i64)
    .bind(usage.output_tokens as i64)
    .bind(total_cost)
    .bind(&model_usage_json)
    .bind(&op_id)
    .execute(&pool)
    .await?
    .rows_affected();

    if rows_affected == 0 {
        println!(
            "Warning: Operation {op_id} not found in PostgreSQL. \
             Run 'ares-cli ops offload' to persist the operation first."
        );
        return Ok(());
    }

    let total_tokens = usage.input_tokens + usage.output_tokens;
    let cost_str = total_cost
        .map(|c| format!("${c:.4}"))
        .unwrap_or_else(|| "unavailable".to_string());
    info!(
        "Offloaded token usage for {op_id}: {total_tokens} tokens ({} in, {} out), cost: {cost_str}",
        usage.input_tokens, usage.output_tokens
    );
    println!(
        "Offloaded token usage for {op_id}: {total_tokens} tokens ({} in, {} out), cost: {cost_str}",
        usage.input_tokens, usage.output_tokens
    );

    Ok(())
}
