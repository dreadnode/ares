use anyhow::{Context, Result};
use tracing::info;

use ares_core::state;

pub(crate) async fn connect_redis(
    redis_url: Option<String>,
) -> Result<redis::aio::MultiplexedConnection> {
    let url = redis_url.unwrap_or_else(|| {
        std::env::var("ARES_REDIS_URL")
            .or_else(|_| std::env::var("REDIS_URL"))
            .unwrap_or_else(|_| "redis://localhost:6379".to_string())
    });
    let client = redis::Client::open(url.as_str())
        .with_context(|| format!("Failed to create Redis client from URL: {url}"))?;
    let config = redis::AsyncConnectionConfig::new()
        .set_response_timeout(Some(std::time::Duration::from_secs(30)));
    let conn = client
        .get_multiplexed_async_connection_with_config(&config)
        .await
        .context("Failed to connect to Redis")?;
    Ok(conn)
}

pub(crate) async fn resolve_operation_id(
    conn: &mut redis::aio::MultiplexedConnection,
    operation_id: Option<String>,
    latest: bool,
) -> Result<String> {
    if let Some(id) = operation_id {
        return Ok(id);
    }
    if latest {
        let id = state::resolve_latest_operation(conn)
            .await?
            .context("No operations found")?;
        info!("Using latest operation: {id}");
        return Ok(id);
    }
    anyhow::bail!("Either operation_id or --latest is required")
}
