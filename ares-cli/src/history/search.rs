use anyhow::Result;

use super::connect_postgres;
use super::types::{CredentialSearchRow, HashSearchRow};
use crate::util::truncate_str;

pub(crate) async fn history_search_creds(
    domain: Option<String>,
    username: Option<String>,
    admin: bool,
    limit: i64,
    json_output: bool,
) -> Result<()> {
    let pool = connect_postgres().await?;

    let mut query = String::from(
        "SELECT c.username, c.domain, c.is_admin, c.source, \
         o.operation_id \
         FROM credentials c JOIN operations o ON c.operation_id = o.id \
         WHERE 1=1",
    );
    let mut bind_idx = 0u32;
    let mut conditions: Vec<String> = Vec::new();

    if domain.is_some() {
        bind_idx += 1;
        conditions.push(format!(" AND LOWER(c.domain) = LOWER(${bind_idx})"));
    }
    if username.is_some() {
        bind_idx += 1;
        conditions.push(format!(" AND c.username ILIKE ${bind_idx}"));
    }
    if admin {
        conditions.push(" AND c.is_admin = true".to_string());
    }

    for c in &conditions {
        query.push_str(c);
    }
    bind_idx += 1;
    query.push_str(&format!(" ORDER BY c.created_at DESC LIMIT ${bind_idx}"));

    let mut q = sqlx::query_as::<_, CredentialSearchRow>(sqlx::AssertSqlSafe(query.as_str()));

    if let Some(ref d) = domain {
        q = q.bind(d);
    }
    if let Some(ref u) = username {
        q = q.bind(format!("%{u}%"));
    }
    q = q.bind(limit);

    let rows: Vec<CredentialSearchRow> = q.fetch_all(&pool).await?;

    if json_output {
        let data: Vec<serde_json::Value> = rows
            .iter()
            .map(|c| {
                serde_json::json!({
                    "username": c.username,
                    "domain": c.domain,
                    "is_admin": c.is_admin,
                    "source": c.source,
                    "operation_id": c.operation_id,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    } else {
        if rows.is_empty() {
            println!("No credentials found");
            return Ok(());
        }

        println!(
            "\n{:<25} {:<25} {:<6} {:<25}",
            "USERNAME", "DOMAIN", "ADMIN", "OPERATION"
        );
        println!("{}", "-".repeat(85));
        for c in &rows {
            let admin_mark = if c.is_admin { "Y" } else { "N" };
            let domain_display = c.domain.as_deref().unwrap_or("");
            println!(
                "{:<25} {:<25} {:<6} {:<25}",
                truncate_str(&c.username, 24),
                truncate_str(domain_display, 24),
                admin_mark,
                truncate_str(&c.operation_id, 24)
            );
        }
        println!("\nTotal: {} credentials", rows.len());
    }

    Ok(())
}

pub(crate) async fn history_search_hashes(
    domain: Option<String>,
    username: Option<String>,
    hash_type: Option<String>,
    cracked: bool,
    limit: i64,
    json_output: bool,
) -> Result<()> {
    let pool = connect_postgres().await?;

    let mut query = String::from(
        "SELECT h.username, h.domain, h.hash_type, \
         (h.cracked_password_hash IS NOT NULL) as is_cracked, \
         h.source, o.operation_id \
         FROM hashes h JOIN operations o ON h.operation_id = o.id \
         WHERE 1=1",
    );
    let mut bind_idx = 0u32;
    let mut conditions: Vec<String> = Vec::new();

    if domain.is_some() {
        bind_idx += 1;
        conditions.push(format!(" AND LOWER(h.domain) = LOWER(${bind_idx})"));
    }
    if username.is_some() {
        bind_idx += 1;
        conditions.push(format!(" AND h.username ILIKE ${bind_idx}"));
    }
    if hash_type.is_some() {
        bind_idx += 1;
        conditions.push(format!(" AND LOWER(h.hash_type) = LOWER(${bind_idx})"));
    }
    if cracked {
        conditions.push(" AND h.cracked_password_hash IS NOT NULL".to_string());
    }

    for c in &conditions {
        query.push_str(c);
    }
    bind_idx += 1;
    query.push_str(&format!(" ORDER BY h.created_at DESC LIMIT ${bind_idx}"));

    let mut q = sqlx::query_as::<_, HashSearchRow>(sqlx::AssertSqlSafe(query.as_str()));

    if let Some(ref d) = domain {
        q = q.bind(d);
    }
    if let Some(ref u) = username {
        q = q.bind(format!("%{u}%"));
    }
    if let Some(ref ht) = hash_type {
        q = q.bind(ht);
    }
    q = q.bind(limit);

    let rows: Vec<HashSearchRow> = q.fetch_all(&pool).await?;

    if json_output {
        let data: Vec<serde_json::Value> = rows
            .iter()
            .map(|h| {
                serde_json::json!({
                    "username": h.username,
                    "domain": h.domain,
                    "hash_type": h.hash_type,
                    "is_cracked": h.is_cracked,
                    "source": h.source,
                    "operation_id": h.operation_id,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    } else {
        if rows.is_empty() {
            println!("No hashes found");
            return Ok(());
        }

        println!(
            "\n{:<25} {:<20} {:<12} {:<8} {:<20}",
            "USERNAME", "DOMAIN", "TYPE", "CRACKED", "OPERATION"
        );
        println!("{}", "-".repeat(90));
        for h in &rows {
            let cracked_mark = if h.is_cracked.unwrap_or(false) {
                "Y"
            } else {
                "N"
            };
            let domain_display = h.domain.as_deref().unwrap_or("");
            let hash_type_display = h.hash_type.as_deref().unwrap_or("");
            println!(
                "{:<25} {:<20} {:<12} {:<8} {:<20}",
                truncate_str(&h.username, 24),
                truncate_str(domain_display, 19),
                truncate_str(hash_type_display, 11),
                cracked_mark,
                truncate_str(&h.operation_id, 19)
            );
        }
        println!("\nTotal: {} hashes", rows.len());
    }

    Ok(())
}
