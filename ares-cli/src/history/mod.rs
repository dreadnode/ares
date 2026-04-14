mod cost;
mod coverage;
mod get;
mod list;
mod search;
pub(crate) mod types;

use anyhow::{Context, Result};

use crate::cli::HistoryCommands;

pub(crate) async fn run_history(cmd: HistoryCommands) -> Result<()> {
    match cmd {
        HistoryCommands::List {
            domain,
            has_da,
            since_days,
            limit,
            json,
        } => list::history_list(domain, has_da, since_days, limit, json).await,
        HistoryCommands::Get { operation_id, json } => get::history_get(operation_id, json).await,
        HistoryCommands::SearchCreds {
            domain,
            username,
            admin,
            limit,
            json,
        } => search::history_search_creds(domain, username, admin, limit, json).await,
        HistoryCommands::SearchHashes {
            domain,
            username,
            hash_type,
            cracked,
            limit,
            json,
        } => search::history_search_hashes(domain, username, hash_type, cracked, limit, json).await,
        HistoryCommands::MitreCoverage {
            since_days,
            json: json_output,
        } => coverage::history_mitre_coverage(since_days, json_output).await,
        HistoryCommands::Cost {
            domain,
            since_days,
            limit,
            json,
        } => cost::history_cost(domain, since_days, limit, json).await,
    }
}

fn get_database_url() -> Result<String> {
    std::env::var("ARES_DATABASE_URL")
        .context("Persistent store not enabled. Set ARES_DATABASE_URL environment variable.")
}

pub(crate) async fn connect_postgres() -> Result<sqlx::PgPool> {
    let url = get_database_url()?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .context("Failed to connect to Postgres")?;
    Ok(pool)
}
