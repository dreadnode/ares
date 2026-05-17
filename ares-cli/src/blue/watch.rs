use anyhow::Result;
use tracing::{error, info};

/// Continuously poll and submit blue investigations from the latest red team operation.
pub(crate) async fn blue_watch(
    redis_url: Option<String>,
    poll_interval: u64,
    model: Option<String>,
    max_steps: u32,
    grafana_url: Option<String>,
    grafana_api_key: Option<String>,
) -> Result<()> {
    println!("Blue team watch mode — polling every {poll_interval}s");
    println!("Press Ctrl+C to stop\n");

    loop {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S");
        println!("[{now}] Submitting blue investigation from latest operation...");

        match super::submit::blue_from_operation(super::submit::BlueFromOperationParams {
            redis_url: redis_url.clone(),
            operation_id: None,
            latest: true,
            model: model.clone(),
            max_steps,
            grafana_url: grafana_url.clone(),
            grafana_api_key: grafana_api_key.clone(),
        })
        .await
        {
            Ok(()) => info!("Investigation submitted successfully"),
            Err(e) => {
                error!("Investigation failed: {e:#}");
            }
        }

        println!("[{now}] Sleeping {poll_interval}s...\n");
        tokio::time::sleep(std::time::Duration::from_secs(poll_interval)).await;
    }
}
