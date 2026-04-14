use anyhow::Result;

use super::connect_postgres;
use super::types::OperationDetailRow;

pub(crate) async fn history_get(operation_id: String, json_output: bool) -> Result<()> {
    let pool = connect_postgres().await?;

    let row = sqlx::query_as::<_, OperationDetailRow>(
        "SELECT operation_id, target_domain, target_ip::text, environment, \
         started_at, completed_at, has_domain_admin, has_golden_ticket, domain_admin_path, \
         COALESCE(credential_count, 0) as credential_count, \
         COALESCE(hash_count, 0) as hash_count, \
         COALESCE(host_count, 0) as host_count, \
         COALESCE(vulnerability_count, 0) as vulnerability_count \
         FROM operations WHERE operation_id = $1",
    )
    .bind(&operation_id)
    .fetch_optional(&pool)
    .await?;

    let Some(op) = row else {
        println!("Operation not found: {operation_id}");
        return Ok(());
    };

    if json_output {
        let data = serde_json::json!({
            "operation_id": op.operation_id,
            "target_domain": op.target_domain,
            "target_ip": op.target_ip,
            "environment": op.environment,
            "started_at": op.started_at.to_rfc3339(),
            "completed_at": op.completed_at.map(|t| t.to_rfc3339()),
            "has_domain_admin": op.has_domain_admin,
            "has_golden_ticket": op.has_golden_ticket,
            "domain_admin_path": op.domain_admin_path,
            "credential_count": op.credential_count,
            "hash_count": op.hash_count,
            "host_count": op.host_count,
            "vulnerability_count": op.vulnerability_count,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    } else {
        println!("\nOperation: {}", op.operation_id);
        println!("{}", "=".repeat(60));
        println!(
            "Target Domain:  {}",
            op.target_domain.as_deref().unwrap_or("N/A")
        );
        println!(
            "Target IP:      {}",
            op.target_ip.as_deref().unwrap_or("N/A")
        );
        println!(
            "Environment:    {}",
            op.environment.as_deref().unwrap_or("N/A")
        );
        println!("Started:        {}", op.started_at);
        println!(
            "Completed:      {}",
            op.completed_at
                .map(|t| t.to_string())
                .unwrap_or_else(|| "Running".to_string())
        );
        println!(
            "Domain Admin:   {}",
            if op.has_domain_admin { "Yes" } else { "No" }
        );
        println!(
            "Golden Ticket:  {}",
            if op.has_golden_ticket { "Yes" } else { "No" }
        );
        if let Some(path) = &op.domain_admin_path {
            println!("DA Path:        {path}");
        }
        println!();
        println!("Credentials:    {}", op.credential_count);
        println!("Hashes:         {}", op.hash_count);
        println!("Hosts:          {}", op.host_count);
        println!("Vulnerabilities: {}", op.vulnerability_count);
    }

    Ok(())
}
