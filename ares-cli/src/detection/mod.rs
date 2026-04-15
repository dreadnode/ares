pub(crate) mod markdown;
pub(crate) mod playbook;
pub(crate) mod queries;
pub(crate) mod techniques;
pub(crate) mod types;

use anyhow::{Context, Result};

use ares_core::state::RedisStateReader;

use crate::redis_conn::{connect_redis, resolve_operation_id};

pub(crate) async fn ops_export_detection(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
    output_dir: String,
    json_output: bool,
    markdown_output: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let op_id = resolve_operation_id(&mut conn, operation_id, latest).await?;

    let reader = RedisStateReader::new(op_id.clone());

    let state = reader
        .load_state(&mut conn)
        .await?
        .with_context(|| format!("No state found for operation: {op_id}"))?;

    let techniques = reader.get_techniques(&mut conn).await.unwrap_or_default();

    let detection_playbook = playbook::generate_detection_playbook(&state, &techniques);

    if json_output {
        let json = serde_json::to_string_pretty(&detection_playbook)?;
        println!("{json}");
    } else {
        let dir = format!("{output_dir}/{op_id}");
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create output directory: {dir}"))?;

        // Save JSON
        let json_path = format!("{dir}/detection_playbook.json");
        let json = serde_json::to_string_pretty(&detection_playbook)?;
        std::fs::write(&json_path, &json)
            .with_context(|| format!("Failed to write JSON playbook to {json_path}"))?;
        println!("Detection playbook (JSON) saved to {json_path}");

        // Save Markdown
        if markdown_output {
            let md_path = format!("{dir}/detection_playbook.md");
            let md = markdown::generate_detection_markdown(&detection_playbook);
            std::fs::write(&md_path, &md)
                .with_context(|| format!("Failed to write markdown playbook to {md_path}"))?;
            println!("Detection playbook (Markdown) saved to {md_path}");
        }

        // Console summary
        println!();
        println!("Detection Playbook Summary");
        println!("  Operation:    {}", detection_playbook.operation_id);
        println!(
            "  Techniques:   {}",
            detection_playbook.summary.techniques_used.len()
        );
        println!(
            "  Credentials:  {}",
            detection_playbook.summary.total_credentials
        );
        println!("  Hosts:        {}", detection_playbook.summary.total_hosts);
        println!(
            "  Domain Admin: {}",
            if detection_playbook.summary.achieved_domain_admin {
                "YES"
            } else {
                "No"
            }
        );
        println!(
            "  Priority Queries: {}",
            detection_playbook.priority_queries.len()
        );
        println!(
            "  Detection Targets: {}",
            detection_playbook.detection_targets.len()
        );
        println!();

        // Show top 5 priority queries
        if !detection_playbook.priority_queries.is_empty() {
            println!("Top Priority Queries:");
            for (i, q) in detection_playbook
                .priority_queries
                .iter()
                .take(5)
                .enumerate()
            {
                println!(
                    "  {}. [{}] {}: {}",
                    i + 1,
                    q.priority.to_uppercase(),
                    q.technique_id,
                    q.description
                );
            }
        }
    }

    Ok(())
}
