//! Ares CLI — unified command-line interface for the Ares red team orchestration system.
//!
//! Replaces the Python CLI scripts (cli_ops.py, cli_blue_ops.py, cli_history.py)
//! with a single native binary. Pure Redis/Postgres client, no Python interop.

mod blue;
mod cli;
mod config;
mod dedup;
mod detection;
mod history;
mod ops;
mod redis_conn;
mod util;

use std::process;

use anyhow::Result;
use clap::Parser;
use tracing::error;

use cli::{Cli, Commands};

#[tokio::main]
async fn main() {
    // Initialize telemetry (console + OTLP when endpoint is configured)
    let _telemetry = ares_core::telemetry::init_telemetry(
        ares_core::telemetry::TelemetryConfig::new("ares-cli")
            .with_default_filter("warn,ares_cli=info"),
    );

    let cli = Cli::parse();

    if let Err(e) = run(cli).await {
        error!("{e:#}");
        process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Ops(cmd) => ops::run_ops(cmd, cli.redis_url).await,
        Commands::Blue(cmd) => blue::run_blue(cmd, cli.redis_url).await,
        Commands::History(cmd) => history::run_history(cmd).await,
        Commands::Config(cmd) => config::run_config(cmd),
    }
}
