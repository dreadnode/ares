//! Ares — unified binary for the Ares red team orchestration system.
//!
//! Consolidates CLI, orchestrator, and worker into a single binary with
//! subcommands: `ares ops`, `ares orchestrator`, `ares worker`, etc.

#[cfg(feature = "blue")]
mod blue;
mod cli;
mod config;
mod dedup;
mod detection;
mod history;
mod ops;
mod orchestrator;
mod redis_conn;
mod secrets;
mod util;
mod worker;

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
    // Skip for orchestrator/worker subcommands — they init their own telemetry
    // with the correct service name.
    let is_service_subcommand = std::env::args()
        .nth(1)
        .is_some_and(|a| a == "orchestrator" || a == "worker");
    let _telemetry = if !is_service_subcommand {
        Some(ares_core::telemetry::init_telemetry(
            ares_core::telemetry::TelemetryConfig::new("ares-cli")
                .with_default_filter("warn,ares_cli=info"),
        ))
    } else {
        None
    };

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
    let mut cli = Cli::parse();

    // Fall back to REDIS_URL if ARES_REDIS_URL wasn't set (K8s pods expose REDIS_URL)
    if cli.redis_url.is_none() {
        cli.redis_url = std::env::var("REDIS_URL").ok();
    }

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
        Commands::Orchestrator => orchestrator::run().await,
        Commands::Worker { .. } => worker::run().await,
    }
}
