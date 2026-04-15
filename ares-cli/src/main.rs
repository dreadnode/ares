//! Ares CLI — unified command-line interface for the Ares red team orchestration system.
//!
//! Replaces the Python CLI scripts (cli_ops.py, cli_blue_ops.py, cli_history.py)
//! with a single native binary. Pure Redis/Postgres client, no Python interop.

#[cfg(feature = "blue")]
mod blue;
mod cli;
mod config;
mod dedup;
mod detection;
mod history;
mod ops;
mod redis_conn;
mod secrets;
mod util;

mod transport;

use std::process;

use anyhow::Result;
use clap::Parser;
use tracing::{error, info};

use cli::{Cli, Commands};

#[tokio::main]
async fn main() {
    // If --k8s or --ec2 is present, re-exec via kubectl/SSM and exit.
    if let Some(code) = transport::maybe_exec_k8s() {
        process::exit(code);
    }
    if let Some(code) = transport::maybe_exec_ec2() {
        process::exit(code);
    }

    // ── Load secrets BEFORE clap parses ──
    // This ensures clap's `env = "..."` attributes and `collect_env_vars()`
    // see values from .env files or 1Password.
    let (env_file, secrets_from) = secrets::prescan_secrets_args();

    if let Some(ref path) = env_file {
        // Explicit --env-file: fail hard if it doesn't work
        match secrets::load_env_file(path) {
            Ok(n) => eprintln!("Loaded {n} variable(s) from {path}"),
            Err(e) => {
                eprintln!("Error: {e:#}");
                process::exit(1);
            }
        }
    } else if secrets_from.is_none() {
        // No explicit flag: silently try .env from cwd (standard convention)
        secrets::try_load_default_env();
    }

    // ── Initialize telemetry before using tracing macros ──
    // This must happen before any tracing calls below.
    let _telemetry = ares_core::telemetry::init_telemetry(
        ares_core::telemetry::TelemetryConfig::new("ares-cli")
            .with_default_filter("warn,ares_cli=info"),
    );

    if let Some(ref source) = secrets_from {
        match source.as_str() {
            "1password" | "1pass" | "op" => match secrets::load_1password_secrets() {
                Ok(n) => info!("Loaded {n} secret(s) from 1Password"),
                Err(e) => {
                    error!("Error loading 1Password secrets: {e:#}");
                    process::exit(1);
                }
            },
            other => {
                error!("Unknown secrets source: {other} (supported: 1password)");
                process::exit(1);
            }
        }
    }

    // ── Normal CLI parsing (env vars are now populated) ──
    let cli = Cli::parse();

    if let Err(e) = run(cli).await {
        error!("{e:#}");
        process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Ops(cmd) => ops::run_ops(cmd, cli.redis_url).await,
        #[cfg(feature = "blue")]
        Commands::Blue(cmd) => blue::run_blue(cmd, cli.redis_url).await,
        Commands::History(cmd) => history::run_history(cmd).await,
        Commands::Config(cmd) => config::run_config(cmd),
    }
}
