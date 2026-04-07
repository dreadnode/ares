//! Ares CLI — unified command-line interface for the Ares red team orchestration system.
//!
//! Replaces the Python CLI scripts (cli_ops.py, cli_blue_ops.py, cli_history.py)
//! with a single native binary. Pure Redis/Postgres client, no Python interop.

use std::collections::{HashMap, HashSet};
use std::process;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use redis::AsyncCommands;
use tracing::{error, info, warn};

use ares_core::config::AresConfig;
use ares_core::models::*;
use ares_core::state::{self, RedisStateReader};

// ============================================================================
// CLI Structure
// ============================================================================

#[derive(Parser)]
#[command(
    name = "ares-cli",
    about = "Ares red team orchestration CLI",
    version,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Redis URL (default: from ARES_REDIS_URL or redis://localhost:6379)
    #[arg(long, global = true, env = "ARES_REDIS_URL")]
    redis_url: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Red team operations
    #[command(subcommand)]
    Ops(OpsCommands),

    /// Blue team investigations
    #[command(subcommand)]
    Blue(BlueCommands),

    /// Historical operation queries (requires Postgres)
    #[command(subcommand)]
    History(HistoryCommands),

    /// Configuration management (single source of truth)
    #[command(subcommand)]
    Config(ConfigCommands),
}

// ============================================================================
// Red Team Operations (ops)
// ============================================================================

#[derive(Subcommand)]
enum OpsCommands {
    /// List all operations
    List {
        /// Only print the latest operation ID (prefer running)
        #[arg(long)]
        latest: bool,
    },

    /// Get the status of an operation
    Status {
        /// Operation ID
        operation_id: Option<String>,
        /// Use the latest operation (prefer running)
        #[arg(long)]
        latest: bool,
    },

    /// Show runtime for an operation
    Runtime {
        /// Operation ID
        operation_id: Option<String>,
        /// Use the latest operation (prefer running)
        #[arg(long)]
        latest: bool,
    },

    /// Dump loot (users, credentials, hosts, hashes) from operation state
    Loot {
        /// Operation ID
        operation_id: Option<String>,
        /// Use the latest operation (prefer running)
        #[arg(long)]
        latest: bool,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Watch mode: refresh every N seconds (0=off)
        #[arg(long, default_value = "0")]
        watch: u64,
        /// Diff mode: only print new items each refresh (implies --watch)
        #[arg(long)]
        diff: bool,
    },

    /// List tasks for an operation
    Tasks {
        /// Operation ID
        operation_id: Option<String>,
        /// Use the latest operation
        #[arg(long)]
        latest: bool,
        /// Filter by status (running/completed/failed/pending/all)
        #[arg(long, default_value = "running")]
        status: String,
        /// Filter by role
        #[arg(long)]
        role: Option<String>,
    },

    /// List operations and queue state from Redis
    Queue,

    /// Generate a report for an operation
    Report {
        /// Operation ID
        operation_id: Option<String>,
        /// Use the latest operation
        #[arg(long)]
        latest: bool,
        /// Regenerate report from state (ignore cached)
        #[arg(long)]
        regenerate: bool,
        /// Output directory for report
        #[arg(long, default_value = "./reports")]
        output_dir: String,
    },

    /// Inject a credential into an operation's shared state
    InjectCredential {
        /// Operation ID
        operation_id: String,
        /// Username to inject
        username: String,
        /// Password for the credential
        password: String,
        /// Domain for the credential
        #[arg(long, default_value = "")]
        domain: String,
        /// Source of the credential
        #[arg(long, default_value = "manual-inject")]
        source: String,
        /// Mark credential as admin
        #[arg(long)]
        is_admin: bool,
    },

    /// Inject a vulnerability into an operation's shared state
    InjectVulnerability {
        /// Operation ID
        operation_id: String,
        /// Vulnerability type (e.g., constrained_delegation, esc1, esc4)
        vuln_type: String,
        /// Target IP address
        target_ip: String,
        /// Target hostname
        #[arg(long, default_value = "")]
        target_hostname: String,
        /// Target SPN for delegation attacks
        #[arg(long, default_value = "")]
        target_spn: String,
        /// Account name (for delegation)
        #[arg(long, default_value = "")]
        account_name: String,
        /// Domain
        #[arg(long, default_value = "")]
        domain: String,
        /// Additional details (JSON string)
        #[arg(long, default_value = "{}")]
        details: String,
    },

    /// Inject a host into an operation's shared state
    InjectHost {
        /// Operation ID
        operation_id: String,
        /// IP address
        ip: String,
        /// Hostname
        hostname: String,
    },

    /// Inject a hash into an operation's shared state
    InjectHash {
        /// Operation ID
        operation_id: String,
        /// Username (account the hash belongs to)
        username: String,
        /// Hash value (e.g., NTLM hash)
        hash_value: String,
        /// Domain
        #[arg(long, default_value = "")]
        domain: String,
        /// Hash type (NTLM, AS-REP, Kerberoast, etc.)
        #[arg(long, default_value = "NTLM")]
        hash_type: String,
        /// Source of the hash
        #[arg(long, default_value = "manual-inject")]
        source: String,
        /// AES256 key for golden tickets (Windows 2016+ rejects RC4)
        #[arg(long)]
        aes_key: Option<String>,
    },

    /// Inject a domain SID into an operation's shared state
    InjectDomainSid {
        /// Operation ID
        operation_id: String,
        /// Domain FQDN (e.g., contoso.local)
        domain: String,
        /// Domain SID (e.g., S-1-5-21-...)
        sid: String,
    },

    /// Delete an operation and all its associated data
    Delete {
        /// Operation ID
        operation_id: String,
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },

    /// Backfill domain list from discovered data
    BackfillDomains {
        /// Operation ID
        operation_id: String,
    },

    /// Clean up old operation checkpoints
    Cleanup {
        /// Max age in hours
        #[arg(long, default_value = "24")]
        max_age_hours: u64,
    },

    /// Persist token usage from Redis to PostgreSQL for an operation
    OffloadCost {
        /// Operation ID
        operation_id: Option<String>,
        /// Use the latest operation
        #[arg(long)]
        latest: bool,
    },
}

// ============================================================================
// Blue Team Investigations (blue)
// ============================================================================

#[derive(Subcommand)]
enum BlueCommands {
    /// List all investigations
    List {
        /// Only print the latest investigation ID
        #[arg(long)]
        latest: bool,
    },

    /// Get the status of an investigation
    Status {
        /// Investigation ID
        investigation_id: Option<String>,
        /// Use the latest investigation
        #[arg(long)]
        latest: bool,
    },

    /// Show evidence collected during an investigation
    Evidence {
        /// Investigation ID
        investigation_id: Option<String>,
        /// Use the latest investigation
        #[arg(long)]
        latest: bool,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show MITRE ATT&CK techniques identified during an investigation
    Techniques {
        /// Investigation ID
        investigation_id: Option<String>,
        /// Use the latest investigation
        #[arg(long)]
        latest: bool,
    },

    /// Show runtime information for an investigation
    Runtime {
        /// Investigation ID
        investigation_id: Option<String>,
        /// Use the latest investigation
        #[arg(long)]
        latest: bool,
    },

    /// Show triage decision and audit trail for an investigation
    TriageStatus {
        /// Investigation ID
        investigation_id: Option<String>,
        /// Use the latest investigation
        #[arg(long)]
        latest: bool,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show aggregate status of all investigations from a red team operation
    OperationStatus {
        /// Red team operation ID
        operation_id: Option<String>,
        /// Use the latest red team operation
        #[arg(long)]
        latest: bool,
        /// Watch mode: refresh every N seconds (0=off)
        #[arg(long, default_value = "0")]
        watch: u64,
    },

    /// Delete an investigation
    Delete {
        /// Investigation ID
        investigation_id: String,
        /// Skip confirmation
        #[arg(long)]
        force: bool,
    },

    /// Delete an operation and all its investigations
    DeleteOperation {
        /// Operation ID
        operation_id: String,
        /// Skip confirmation
        #[arg(long)]
        force: bool,
    },

    /// Clean up old investigations
    Cleanup {
        /// Max age in hours
        #[arg(long, default_value = "24")]
        max_age_hours: u64,
        /// Delete ALL investigations (ignores max-age-hours)
        #[arg(long)]
        all: bool,
        /// Show what would be deleted
        #[arg(long)]
        dry_run: bool,
        /// Skip confirmation for --all
        #[arg(long)]
        force: bool,
    },
}

// ============================================================================
// History Commands (history)
// ============================================================================

#[derive(Subcommand)]
enum HistoryCommands {
    /// List historical operations (requires Postgres)
    List {
        /// Filter by target domain
        #[arg(long)]
        domain: Option<String>,
        /// Filter by domain admin achieved
        #[arg(long)]
        has_da: Option<bool>,
        /// Operations from last N days
        #[arg(long)]
        since_days: Option<i64>,
        /// Maximum results
        #[arg(long, default_value = "50")]
        limit: i64,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Get detailed information about a specific operation
    Get {
        /// Operation ID
        operation_id: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Search credentials across all historical operations
    SearchCreds {
        /// Filter by domain
        #[arg(long)]
        domain: Option<String>,
        /// Filter by username (partial)
        #[arg(long)]
        username: Option<String>,
        /// Only admin accounts
        #[arg(long)]
        admin: bool,
        /// Maximum results
        #[arg(long, default_value = "50")]
        limit: i64,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Search hashes across all historical operations
    SearchHashes {
        /// Filter by domain
        #[arg(long)]
        domain: Option<String>,
        /// Filter by username
        #[arg(long)]
        username: Option<String>,
        /// Filter by type (ntlm, asrep, kerberoast)
        #[arg(long)]
        hash_type: Option<String>,
        /// Only cracked hashes
        #[arg(long)]
        cracked: bool,
        /// Maximum results
        #[arg(long, default_value = "50")]
        limit: i64,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show MITRE ATT&CK technique coverage across operations
    MitreCoverage {
        /// Operations from last N days
        #[arg(long)]
        since_days: Option<i64>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show token usage and cost across historical operations
    Cost {
        /// Filter by target domain
        #[arg(long)]
        domain: Option<String>,
        /// Operations from last N days
        #[arg(long)]
        since_days: Option<i64>,
        /// Maximum results
        #[arg(long, default_value = "50")]
        limit: i64,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

// ============================================================================
// Config Commands (config)
// ============================================================================

#[derive(Subcommand)]
enum ConfigCommands {
    /// Pretty-print the resolved configuration
    Show {
        /// Only show model assignments per role
        #[arg(long)]
        models: bool,

        /// Path to config file (overrides ARES_CONFIG and defaults)
        #[arg(long, env = "ARES_CONFIG")]
        config: Option<String>,
    },

    /// Validate the configuration file
    Validate {
        /// Path to config file (overrides ARES_CONFIG and defaults)
        #[arg(long, env = "ARES_CONFIG")]
        config: Option<String>,
    },

    /// Set the model for one or all agent roles (edits the YAML in-place)
    SetModel {
        /// Agent role (e.g. orchestrator, recon). Omit when using --all.
        role: Option<String>,

        /// Model identifier (e.g. gpt-5.2, gpt-4.1)
        model: String,

        /// Set all roles to the given model
        #[arg(long)]
        all: bool,

        /// Path to config file (overrides ARES_CONFIG and defaults)
        #[arg(long, env = "ARES_CONFIG")]
        config: Option<String>,
    },
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,ares_cli=info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    if let Err(e) = run(cli).await {
        error!("{e:#}");
        process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Ops(cmd) => run_ops(cmd, cli.redis_url).await,
        Commands::Blue(cmd) => run_blue(cmd, cli.redis_url).await,
        Commands::History(cmd) => run_history(cmd).await,
        Commands::Config(cmd) => run_config(cmd),
    }
}

// ============================================================================
// Redis Connection
// ============================================================================

async fn connect_redis(redis_url: Option<String>) -> Result<redis::aio::MultiplexedConnection> {
    let url = redis_url.unwrap_or_else(|| {
        std::env::var("ARES_REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string())
    });
    let client = redis::Client::open(url.as_str())
        .with_context(|| format!("Failed to create Redis client from URL: {url}"))?;
    let conn = client
        .get_multiplexed_async_connection()
        .await
        .context("Failed to connect to Redis")?;
    Ok(conn)
}

// ============================================================================
// Ops Command Handlers
// ============================================================================

async fn run_ops(cmd: OpsCommands, redis_url: Option<String>) -> Result<()> {
    match cmd {
        OpsCommands::List { latest } => ops_list(redis_url, latest).await,
        OpsCommands::Status {
            operation_id,
            latest,
        } => ops_status(redis_url, operation_id, latest).await,
        OpsCommands::Runtime {
            operation_id,
            latest,
        } => ops_runtime(redis_url, operation_id, latest).await,
        OpsCommands::Loot {
            operation_id,
            latest,
            json,
            watch,
            diff,
        } => ops_loot(redis_url, operation_id, latest, json, watch, diff).await,
        OpsCommands::Tasks {
            operation_id,
            latest,
            status,
            role,
        } => ops_tasks(redis_url, operation_id, latest, status, role).await,
        OpsCommands::Queue => ops_queue(redis_url).await,
        OpsCommands::InjectCredential {
            operation_id,
            username,
            password,
            domain,
            source,
            is_admin,
        } => {
            ops_inject_credential(
                redis_url,
                operation_id,
                username,
                password,
                domain,
                source,
                is_admin,
            )
            .await
        }
        OpsCommands::InjectVulnerability {
            operation_id,
            vuln_type,
            target_ip,
            target_hostname,
            target_spn,
            account_name,
            domain,
            details,
        } => {
            ops_inject_vulnerability(
                redis_url,
                operation_id,
                vuln_type,
                target_ip,
                target_hostname,
                target_spn,
                account_name,
                domain,
                details,
            )
            .await
        }
        OpsCommands::InjectHost {
            operation_id,
            ip,
            hostname,
        } => ops_inject_host(redis_url, operation_id, ip, hostname).await,
        OpsCommands::Delete {
            operation_id,
            force,
        } => ops_delete(redis_url, operation_id, force).await,
        OpsCommands::InjectHash {
            operation_id,
            username,
            hash_value,
            domain,
            hash_type,
            source,
            aes_key,
        } => {
            ops_inject_hash(
                redis_url,
                operation_id,
                username,
                hash_value,
                domain,
                hash_type,
                source,
                aes_key,
            )
            .await
        }
        OpsCommands::InjectDomainSid {
            operation_id,
            domain,
            sid,
        } => ops_inject_domain_sid(redis_url, operation_id, domain, sid).await,
        OpsCommands::BackfillDomains { operation_id } => {
            ops_backfill_domains(redis_url, operation_id).await
        }
        OpsCommands::OffloadCost {
            operation_id,
            latest,
        } => ops_offload_cost(redis_url, operation_id, latest).await,
        OpsCommands::Report {
            operation_id,
            latest,
            regenerate,
            output_dir,
        } => ops_report(redis_url, operation_id, latest, regenerate, output_dir).await,
        OpsCommands::Cleanup { max_age_hours } => ops_cleanup(redis_url, max_age_hours).await,
    }
}

// ============================================================================
// Resolve operation ID
// ============================================================================

async fn resolve_operation_id(
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

// ============================================================================
// ops list
// ============================================================================

async fn ops_list(redis_url: Option<String>, latest: bool) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;

    if latest {
        let op_id = state::resolve_latest_operation(&mut conn)
            .await?
            .context("No operations found")?;
        println!("{op_id}");
        return Ok(());
    }

    let running_ops = state::list_running_operations(&mut conn).await?;
    let op_ids = state::list_operation_ids(&mut conn).await?;

    if op_ids.is_empty() {
        println!("No operations found");
        return Ok(());
    }

    // Collect metadata for each operation
    #[allow(clippy::type_complexity)]
    let mut ops: Vec<(Option<DateTime<Utc>>, String, bool, Option<DateTime<Utc>>)> = Vec::new();
    for op_id in &op_ids {
        let reader = RedisStateReader::new(op_id.clone());
        let meta = reader.get_meta(&mut conn).await?;
        let is_running = running_ops.contains(op_id);
        ops.push((meta.started_at, op_id.clone(), is_running, meta.started_at));
    }

    // Sort by started_at descending
    ops.sort_by(|a, b| b.0.cmp(&a.0));

    println!("Multi-Agent Operations:");
    println!("{}", "=".repeat(70));

    let now = Utc::now();
    for (checkpoint_time, op_id, is_running, started_at) in &ops {
        let status = if *is_running { " [running]" } else { "" };
        let mut runtime_str = String::new();
        if let Some(started) = started_at {
            let end_time = if *is_running {
                now
            } else {
                checkpoint_time.unwrap_or(now)
            };
            let runtime_seconds = (end_time - started).num_seconds().max(0) as u64;
            runtime_str = format!(" runtime: {}", format_duration(runtime_seconds));
        }
        let time_str = checkpoint_time
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| "unknown".to_string());
        println!("  {op_id}: checkpoint at {time_str}{status}{runtime_str}");
    }

    Ok(())
}

// ============================================================================
// ops status
// ============================================================================

async fn ops_status(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let op_id = resolve_operation_id(&mut conn, operation_id, latest).await?;

    let reader = RedisStateReader::new(op_id.clone());
    if !reader.exists(&mut conn).await? {
        println!("Operation {op_id} not found");
        return Ok(());
    }

    let meta = reader.get_meta(&mut conn).await?;
    let is_running = reader.is_running(&mut conn).await?;

    let status = if meta.completed_at.is_some() {
        "completed"
    } else if is_running {
        "running"
    } else {
        "stopped"
    };

    println!("Operation: {op_id}");
    println!("Status: {status}");
    if let Some(started) = meta.started_at {
        println!("Started: {}", started.to_rfc3339());
    }
    if meta.has_domain_admin {
        println!("*** DOMAIN ADMIN ACHIEVED ***");
    }
    if meta.has_golden_ticket {
        println!("*** GOLDEN TICKET OBTAINED ***");
    }

    Ok(())
}

// ============================================================================
// ops runtime
// ============================================================================

async fn ops_runtime(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let op_id = resolve_operation_id(&mut conn, operation_id, latest).await?;

    let reader = RedisStateReader::new(op_id.clone());
    let state = reader
        .load_state(&mut conn)
        .await?
        .with_context(|| format!("No state found for operation: {op_id}"))?;

    let is_running = reader.is_running(&mut conn).await?;
    let now = Utc::now();

    let (runtime_seconds, status) = if let Some(completed) = state.completed_at {
        (
            (completed - state.started_at).num_seconds().max(0) as u64,
            "completed",
        )
    } else if is_running {
        (
            (now - state.started_at).num_seconds().max(0) as u64,
            "running",
        )
    } else {
        (
            (now - state.started_at).num_seconds().max(0) as u64,
            "stopped",
        )
    };

    println!("Operation: {op_id}");
    println!("Status:    {status}");
    println!("Started:   {}", state.started_at.to_rfc3339());
    println!("Runtime:   {}", format_duration(runtime_seconds));
    println!();

    let creds = state.all_credentials.len();
    let hashes = state.all_hashes.len();
    let hosts = state.all_hosts.len();
    let vulns = state.discovered_vulnerabilities.len();
    let exploited = state.exploited_vulnerabilities.len();

    println!("Credentials: {creds}  Hashes: {hashes}  Hosts: {hosts}");
    println!("Vulns: {vulns} discovered, {exploited} exploited");

    if state.has_domain_admin {
        println!("\n*** DOMAIN ADMIN ACHIEVED ***");
    }
    if state.has_golden_ticket {
        println!("*** GOLDEN TICKET OBTAINED ***");
    }

    // Token usage & estimated cost (from Redis counters set by workers)
    match ares_core::token_usage::get_token_usage(&mut conn, &op_id).await {
        Ok(Some(usage)) if usage.input_tokens > 0 || usage.output_tokens > 0 => {
            let in_tok = usage.input_tokens;
            let out_tok = usage.output_tokens;
            let total_tok = in_tok + out_tok;

            println!("\nTokens: {total_tok} (in: {in_tok}  out: {out_tok})");

            if !usage.models.is_empty() {
                let mut model_names: Vec<_> = usage.models.keys().collect();
                model_names.sort();
                let label = if model_names.len() > 1 {
                    "Models"
                } else {
                    "Model"
                };
                println!(
                    "{label}:  {}",
                    model_names
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );

                let (total_cost, breakdown, unpriced) =
                    ares_core::token_usage::estimate_usage_cost(&usage);

                if let Some(cost) = total_cost {
                    let suffix = if breakdown.len() > 1 {
                        " (blended)"
                    } else {
                        ""
                    };
                    println!("Cost:   ${cost:.4}{suffix}");
                } else if !usage.model.is_empty() {
                    println!("Cost:   unavailable");
                }

                // Per-model breakdown for multi-model operations
                if breakdown.len() > 1 {
                    for item in &breakdown {
                        println!(
                            "  - {}: {} tokens (${:.4})",
                            item.model, item.total_tokens, item.cost
                        );
                    }
                }

                if !unpriced.is_empty() {
                    println!("Unpriced models: {}", unpriced.join(", "));
                }
            }
        }
        _ => {}
    }

    Ok(())
}

// ============================================================================
// ops loot
// ============================================================================

async fn ops_loot(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
    json_output: bool,
    watch: u64,
    diff: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let op_id = resolve_operation_id(&mut conn, operation_id, latest).await?;

    let watch_interval = if diff && watch == 0 { 10 } else { watch };

    if watch_interval > 0 {
        loot_watch(&mut conn, &op_id, watch_interval, diff, json_output).await
    } else {
        loot_once(&mut conn, &op_id, json_output).await
    }
}

async fn loot_once(
    conn: &mut redis::aio::MultiplexedConnection,
    op_id: &str,
    json_output: bool,
) -> Result<()> {
    let reader = RedisStateReader::new(op_id.to_string());
    let state = reader
        .load_state(conn)
        .await?
        .with_context(|| format!("No state found for operation: {op_id}"))?;

    print_loot(&state, json_output);
    Ok(())
}

async fn loot_watch(
    conn: &mut redis::aio::MultiplexedConnection,
    op_id: &str,
    interval: u64,
    diff_mode: bool,
    json_output: bool,
) -> Result<()> {
    let reader = RedisStateReader::new(op_id.to_string());
    let mut prev_snapshot: Option<LootSnapshot> = None;

    loop {
        match reader.load_state(conn).await {
            Ok(Some(state)) => {
                let curr = loot_snapshot(&state);

                if diff_mode {
                    if prev_snapshot.is_none() {
                        print_loot(&state, json_output);
                    } else if let Some(prev) = &prev_snapshot {
                        print_diff(prev, &curr, &state);
                    }
                } else {
                    let ts = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
                    if prev_snapshot.is_some() {
                        println!("\n{}", "=".repeat(60));
                    }
                    println!("[watch] Refreshing every {interval}s  |  {ts}");
                    println!("{}", "=".repeat(60));
                    print_loot(&state, json_output);
                }

                prev_snapshot = Some(curr);
            }
            Ok(None) => {
                warn!("No state found for {op_id}, retrying in {interval}s...");
            }
            Err(e) => {
                warn!("Redis fetch failed: {e}");
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
    }
}

fn print_loot(state: &SharedRedTeamState, json_output: bool) {
    if json_output {
        print_loot_json(state);
    } else {
        print_loot_human(state);
    }
}

fn print_loot_json(state: &SharedRedTeamState) {
    let unique_users = dedup_users(&state.all_users);
    let unique_creds = dedup_credentials(&state.all_credentials);
    let unique_hashes = dedup_hashes(&state.all_hashes);

    let output = serde_json::json!({
        "operation_id": state.operation_id,
        "has_domain_admin": state.has_domain_admin,
        "domain_admin_path": state.domain_admin_path,
        "has_golden_ticket": state.has_golden_ticket,
        "domains": state.all_domains,
        "hosts": state.all_hosts.iter().map(|h| serde_json::json!({
            "ip": h.ip,
            "hostname": h.hostname,
            "os": h.os,
            "is_dc": h.is_dc,
            "services": h.services,
        })).collect::<Vec<_>>(),
        "users": unique_users.iter().map(|u| serde_json::json!({
            "username": u.username,
            "domain": u.domain,
            "is_admin": u.is_admin,
            "source": u.source,
        })).collect::<Vec<_>>(),
        "credentials": unique_creds.iter().map(|c| serde_json::json!({
            "username": c.username,
            "password": c.password,
            "domain": c.domain,
            "is_admin": c.is_admin,
        })).collect::<Vec<_>>(),
        "hashes": unique_hashes.iter().map(|h| serde_json::json!({
            "username": h.username,
            "domain": h.domain,
            "hash_type": h.hash_type,
            "hash_value": h.hash_value,
            "source": h.source,
        })).collect::<Vec<_>>(),
        "shares": state.all_shares.iter().map(|s| serde_json::json!({
            "host": s.host,
            "name": s.name,
            "permissions": s.permissions,
        })).collect::<Vec<_>>(),
        "weaknesses": state.all_weaknesses,
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_default()
    );
}

fn print_loot_human(state: &SharedRedTeamState) {
    println!("Operation: {}", state.operation_id);
    if state.has_domain_admin {
        println!("*** DOMAIN ADMIN ACHIEVED ***");
        if let Some(path) = &state.domain_admin_path {
            println!("  Path: {path}");
        }
    }
    if state.has_golden_ticket {
        println!("*** GOLDEN TICKET OBTAINED ***");
    }
    println!();

    // Domains with hierarchy
    let mut domains: Vec<String> = state
        .all_domains
        .iter()
        .map(|d| d.trim().to_lowercase())
        .filter(|d| !d.is_empty())
        .collect();
    domains.sort();
    domains.dedup();

    let mut forest_roots: Vec<String> = Vec::new();
    let mut child_domains: HashMap<String, String> = HashMap::new();
    for domain in &domains {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() >= 3 {
            let parent = parts[1..].join(".");
            if domains.contains(&parent) {
                child_domains.insert(domain.clone(), parent);
            } else {
                forest_roots.push(domain.clone());
            }
        } else {
            forest_roots.push(domain.clone());
        }
    }

    println!("Domains ({}):", domains.len());
    if domains.is_empty() {
        println!("  - None");
    } else {
        let mut displayed = std::collections::HashSet::new();
        for root in forest_roots.iter() {
            println!("  - {root} (forest root)");
            displayed.insert(root.clone());
            for (child, parent) in child_domains.iter() {
                if parent == root {
                    println!("    \u{2514}\u{2500} {child} (child)");
                    displayed.insert(child.clone());
                }
            }
        }
        for child in child_domains.keys() {
            if !displayed.contains(child) {
                let parent = &child_domains[child];
                println!("  - {child} (child of {parent})");
            }
        }
    }
    println!();

    // Hosts
    let dcs: Vec<&Host> = state.all_hosts.iter().filter(|h| h.is_dc).collect();
    println!("Hosts ({}, {} DCs):", state.all_hosts.len(), dcs.len());
    for host in &state.all_hosts {
        let mut parts = Vec::new();
        if !host.hostname.is_empty() {
            parts.push(host.hostname.as_str());
        }
        if !host.ip.is_empty() {
            parts.push(host.ip.as_str());
        }
        let mut line = if parts.is_empty() {
            "(unknown)".to_string()
        } else {
            parts.join(" / ")
        };
        if !host.os.is_empty() {
            line = format!("{line} [{}]", host.os);
        }
        if host.is_dc {
            line = format!("{line} [DC]");
        }
        println!("  - {line}");
        for svc in &host.services {
            println!("      {svc}");
        }
    }
    println!();

    // Users grouped by source
    let unique_users = dedup_users(&state.all_users);
    println!("Users ({}):", unique_users.len());
    let mut users_by_source: HashMap<String, Vec<&User>> = HashMap::new();
    for user in &unique_users {
        let src = if user.source.is_empty() {
            "unknown".to_string()
        } else {
            user.source.clone()
        };
        users_by_source.entry(src).or_default().push(user);
    }
    let mut sources: Vec<String> = users_by_source.keys().cloned().collect();
    sources.sort();
    for src in &sources {
        let users = &users_by_source[src];
        println!("  [{src}] ({})", users.len());
        for user in users {
            let prefix = if user.domain.is_empty() {
                user.username.clone()
            } else {
                format!("{}\\{}", user.domain, user.username)
            };
            let suffix = if user.is_admin { " (admin)" } else { "" };
            println!("    - {prefix}{suffix}");
        }
    }
    println!();

    // Credentials
    let unique_creds = dedup_credentials(&state.all_credentials);
    println!("Credentials ({}):", unique_creds.len());
    for cred in &unique_creds {
        let prefix = if cred.domain.is_empty() {
            cred.username.clone()
        } else {
            format!("{}\\{}", cred.domain, cred.username)
        };
        let suffix = if cred.is_admin { " (admin)" } else { "" };
        println!("  - {prefix}:{}{suffix}", cred.password);
    }
    println!();

    // Hashes
    let unique_hashes = dedup_hashes(&state.all_hashes);
    println!("Hashes ({}):", unique_hashes.len());
    for h in &unique_hashes {
        let prefix = if h.domain.is_empty() {
            h.username.clone()
        } else {
            format!("{}\\{}", h.domain, h.username)
        };
        println!("  - {prefix}:{}:{}", h.hash_type, h.hash_value);
    }
    println!();

    // Shares
    println!("Shares ({}):", state.all_shares.len());
    for share in &state.all_shares {
        let line = if share.host.is_empty() {
            share.name.clone()
        } else {
            format!("{}/{}", share.host, share.name)
        };
        if share.permissions.is_empty() {
            println!("  - {line}");
        } else {
            println!("  - {line} [{}]", share.permissions);
        }
    }
    println!();

    // Weaknesses
    println!("Weaknesses ({}):", state.all_weaknesses.len());
    if state.all_weaknesses.is_empty() {
        println!("  None");
    } else {
        for (i, w) in state.all_weaknesses.iter().enumerate() {
            let title = extract_weakness_title(w);
            println!("  {}. {title}", i + 1);
        }
    }
}

fn extract_weakness_title(block: &str) -> &str {
    for line in block.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("### ") {
            return rest.trim();
        }
        if trimmed.starts_with("**") && trimmed.ends_with("**") && !trimmed.contains(":**") {
            let inner = trimmed.trim_matches('*').trim();
            if !inner.is_empty() {
                return inner;
            }
        }
    }
    let first = block.lines().next().unwrap_or("Untitled Weakness");
    if first.len() > 60 {
        &first[..60]
    } else {
        first
    }
}

// ============================================================================
// Deduplication (matches Python logic)
// ============================================================================

fn dedup_users(users: &[User]) -> Vec<User> {
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    for u in users {
        let key = (
            u.domain.trim().to_lowercase(),
            u.username.trim().to_lowercase(),
        );
        if seen.insert(key) {
            result.push(u.clone());
        }
    }
    result
}

fn dedup_credentials(creds: &[Credential]) -> Vec<Credential> {
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    for c in creds {
        let key = (
            c.domain.trim().to_lowercase(),
            c.username.trim().to_lowercase(),
            c.password.clone(),
        );
        if seen.insert(key) {
            result.push(c.clone());
        }
    }
    result
}

fn dedup_hashes(hashes: &[Hash]) -> Vec<Hash> {
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    for h in hashes {
        let key = (
            h.domain.trim().to_lowercase(),
            h.username.trim().to_lowercase(),
            h.hash_type.trim().to_lowercase(),
            h.hash_value.trim().to_lowercase(),
        );
        if seen.insert(key) {
            result.push(h.clone());
        }
    }
    result
}

// ============================================================================
// Loot snapshot and diff (matches Python _loot_snapshot / _print_diff)
// ============================================================================

#[derive(Default)]
struct LootSnapshot {
    domains: std::collections::HashSet<String>,
    host_keys: std::collections::HashSet<(String, String)>,
    user_keys: std::collections::HashSet<(String, String)>,
    cred_keys: std::collections::HashSet<(String, String, String)>,
    hash_keys: std::collections::HashSet<(String, String, String, String)>,
    share_keys: std::collections::HashSet<(String, String)>,
    weaknesses: std::collections::HashSet<String>,
}

fn loot_snapshot(state: &SharedRedTeamState) -> LootSnapshot {
    LootSnapshot {
        domains: state
            .all_domains
            .iter()
            .map(|d| d.trim().to_lowercase())
            .filter(|d| !d.is_empty())
            .collect(),
        host_keys: state
            .all_hosts
            .iter()
            .map(|h| (h.hostname.clone(), h.ip.clone()))
            .collect(),
        user_keys: state
            .all_users
            .iter()
            .map(|u| {
                (
                    u.domain.trim().to_lowercase(),
                    u.username.trim().to_lowercase(),
                )
            })
            .collect(),
        cred_keys: state
            .all_credentials
            .iter()
            .map(|c| {
                (
                    c.domain.trim().to_lowercase(),
                    c.username.trim().to_lowercase(),
                    c.password.clone(),
                )
            })
            .collect(),
        hash_keys: state
            .all_hashes
            .iter()
            .map(|h| {
                (
                    h.domain.trim().to_lowercase(),
                    h.username.trim().to_lowercase(),
                    h.hash_type.trim().to_lowercase(),
                    h.hash_value.trim().to_lowercase(),
                )
            })
            .collect(),
        share_keys: state
            .all_shares
            .iter()
            .map(|s| (s.host.clone(), s.name.clone()))
            .collect(),
        weaknesses: state.all_weaknesses.iter().cloned().collect(),
    }
}

fn print_diff(prev: &LootSnapshot, curr: &LootSnapshot, _state: &SharedRedTeamState) {
    let new_domains: Vec<_> = curr.domains.difference(&prev.domains).collect();
    let new_hosts: Vec<_> = curr.host_keys.difference(&prev.host_keys).collect();
    let new_users: Vec<_> = curr.user_keys.difference(&prev.user_keys).collect();
    let new_creds: Vec<_> = curr.cred_keys.difference(&prev.cred_keys).collect();
    let new_hashes: Vec<_> = curr.hash_keys.difference(&prev.hash_keys).collect();
    let new_shares: Vec<_> = curr.share_keys.difference(&prev.share_keys).collect();
    let new_weaknesses: Vec<_> = curr.weaknesses.difference(&prev.weaknesses).collect();

    let total = new_domains.len()
        + new_hosts.len()
        + new_users.len()
        + new_creds.len()
        + new_hashes.len()
        + new_shares.len()
        + new_weaknesses.len();

    if total == 0 {
        return;
    }

    let ts = Utc::now().format("%H:%M:%S");
    println!("\n--- New loot at {ts} ({total} items) ---");

    for d in &new_domains {
        println!("  [domain] {d}");
    }
    for (hostname, ip) in &new_hosts {
        let parts: Vec<&str> = [hostname.as_str(), ip.as_str()]
            .iter()
            .copied()
            .filter(|s| !s.is_empty())
            .collect();
        println!("  [host] {}", parts.join(" / "));
    }
    for (domain, username) in &new_users {
        let prefix = if domain.is_empty() {
            username.clone()
        } else {
            format!("{domain}\\{username}")
        };
        println!("  [user] {prefix}");
    }
    for (domain, username, password) in &new_creds {
        let prefix = if domain.is_empty() {
            username.clone()
        } else {
            format!("{domain}\\{username}")
        };
        println!("  [cred] {prefix}:{password}");
    }
    for (domain, username, hash_type, hash_value) in &new_hashes {
        let prefix = if domain.is_empty() {
            username.clone()
        } else {
            format!("{domain}\\{username}")
        };
        println!("  [hash] {prefix}:{hash_type}:{hash_value}");
    }
    for (host, name) in &new_shares {
        println!("  [share] {host}/{name}");
    }
    for w in &new_weaknesses {
        println!("  [weakness] {w}");
    }
}

// ============================================================================
// ops tasks
// ============================================================================

async fn ops_tasks(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
    task_status: String,
    role: Option<String>,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let op_id = resolve_operation_id(&mut conn, operation_id, latest).await?;

    let task_keys: Vec<String> = redis::cmd("KEYS")
        .arg("ares:task_status:*")
        .query_async(&mut conn)
        .await?;

    let mut found_tasks: Vec<(String, TaskStatusRecord)> = Vec::new();

    for key in &task_keys {
        let raw: Option<String> = conn.get(key).await?;
        let Some(json_str) = raw else { continue };

        let data: TaskStatusRecord = match serde_json::from_str(&json_str) {
            Ok(d) => d,
            Err(_) => continue,
        };

        if data.operation_id != op_id {
            continue;
        }
        if let Some(ref role_filter) = role {
            if data.role.as_deref() != Some(role_filter.as_str()) {
                continue;
            }
        }
        if task_status != "all" && data.status != task_status {
            continue;
        }

        found_tasks.push((key.clone(), data));
    }

    if found_tasks.is_empty() {
        println!("No {task_status} tasks found for operation {op_id}");
        return Ok(());
    }

    found_tasks.sort_by(|a, b| {
        let a_time =
            a.1.started_at
                .as_deref()
                .or(a.1.ended_at.as_deref())
                .unwrap_or("");
        let b_time =
            b.1.started_at
                .as_deref()
                .or(b.1.ended_at.as_deref())
                .unwrap_or("");
        a_time.cmp(b_time)
    });

    for (key, data) in &found_tasks {
        println!("{key}");
        let display = serde_json::json!({
            "status": data.status,
            "started_at": data.started_at,
            "ended_at": data.ended_at,
            "pod": data.pod_name,
            "role": data.role,
            "task_type": data.task_type,
            "error": data.error,
            "payload": data.payload,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&display).unwrap_or_default()
        );
    }

    Ok(())
}

// ============================================================================
// ops queue
// ============================================================================

async fn ops_queue(redis_url: Option<String>) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let running_ops = state::list_running_operations(&mut conn).await?;
    let op_ids = state::list_operation_ids(&mut conn).await?;

    if op_ids.is_empty() {
        println!("No operations found");
        return Ok(());
    }

    println!("Multi-Agent Operations (Redis)");
    println!("{}", "=".repeat(70));

    for op_id in &op_ids {
        let reader = RedisStateReader::new(op_id.clone());
        let meta = reader.get_meta(&mut conn).await?;
        let is_running = running_ops.contains(op_id);
        let vulns = reader.get_vulnerabilities(&mut conn).await?;
        let exploited = reader.get_exploited_vulnerabilities(&mut conn).await?;

        let status = if is_running { "running" } else { "idle" };
        let checkpoint = meta
            .started_at
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| "unknown".to_string());

        let da = if meta.has_domain_admin { "yes" } else { "no" };
        let gt = if meta.has_golden_ticket { "yes" } else { "no" };

        println!("  {op_id} [{status}] checkpoint: {checkpoint}");
        println!(
            "    domain_admin: {da}  golden_ticket: {gt}  vulns: {}  exploited: {}",
            vulns.len(),
            exploited.len()
        );
    }

    Ok(())
}

// ============================================================================
// ops inject-credential
// ============================================================================

async fn ops_inject_credential(
    redis_url: Option<String>,
    operation_id: String,
    username: String,
    password: String,
    domain: String,
    source: String,
    is_admin: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let reader = RedisStateReader::new(operation_id.clone());

    if !reader.exists(&mut conn).await? {
        anyhow::bail!("No state found for operation: {operation_id}");
    }

    let cred = Credential {
        id: uuid::Uuid::new_v4().to_string(),
        username: username.clone(),
        password: password.clone(),
        domain: domain.clone(),
        source,
        discovered_at: Some(Utc::now()),
        is_admin,
        parent_id: None,
        attack_step: 0,
    };

    let added = reader.add_credential(&mut conn, &cred).await?;

    if added {
        let n = state::publish_state_update(&mut conn, &operation_id)
            .await
            .unwrap_or(0);
        info!(
            "Injected credential: {}\\{}:{} ({n} subscribers notified)",
            domain, username, password
        );
    } else {
        info!("Credential already exists: {}\\{}", domain, username);
    }

    Ok(())
}

// ============================================================================
// ops inject-vulnerability
// ============================================================================

#[allow(clippy::too_many_arguments)]
async fn ops_inject_vulnerability(
    redis_url: Option<String>,
    operation_id: String,
    vuln_type: String,
    target_ip: String,
    target_hostname: String,
    target_spn: String,
    account_name: String,
    domain: String,
    details_json: String,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let reader = RedisStateReader::new(operation_id.clone());

    if !reader.exists(&mut conn).await? {
        anyhow::bail!("No state found for operation: {operation_id}");
    }

    let extra_details: HashMap<String, serde_json::Value> =
        serde_json::from_str(&details_json).unwrap_or_default();

    let mut vuln_details = HashMap::new();
    vuln_details.insert(
        "target_ip".to_string(),
        serde_json::Value::String(target_ip.clone()),
    );
    vuln_details.insert(
        "target_hostname".to_string(),
        serde_json::Value::String(target_hostname),
    );
    vuln_details.insert("domain".to_string(), serde_json::Value::String(domain));
    if !target_spn.is_empty() {
        vuln_details.insert(
            "target_spn".to_string(),
            serde_json::Value::String(target_spn),
        );
    }
    if !account_name.is_empty() {
        vuln_details.insert(
            "account_name".to_string(),
            serde_json::Value::String(account_name.clone()),
        );
    }
    vuln_details.extend(extra_details);

    let vuln_id = format!(
        "{}_{}_{}",
        vuln_type,
        target_ip,
        if account_name.is_empty() {
            "manual"
        } else {
            &account_name
        }
    );

    let vuln = VulnerabilityInfo {
        vuln_id,
        vuln_type: vuln_type.clone(),
        target: target_ip.clone(),
        discovered_by: "manual-inject".to_string(),
        discovered_at: Utc::now(),
        details: vuln_details,
        recommended_agent: String::new(),
        priority: 99, // Default priority; config lookup would go here
    };

    let added = reader.add_vulnerability(&mut conn, &vuln).await?;
    if added {
        let n = state::publish_state_update(&mut conn, &operation_id)
            .await
            .unwrap_or(0);
        info!(
            "Injected vulnerability: {vuln_type} on {target_ip} (priority={}, {n} subscribers notified)",
            vuln.priority
        );
    } else {
        info!("Vulnerability already exists");
    }

    Ok(())
}

// ============================================================================
// ops inject-host
// ============================================================================

async fn ops_inject_host(
    redis_url: Option<String>,
    operation_id: String,
    ip: String,
    hostname: String,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let reader = RedisStateReader::new(operation_id.clone());

    if !reader.exists(&mut conn).await? {
        anyhow::bail!("No state found for operation: {operation_id}");
    }

    let mut host = Host {
        ip: ip.clone(),
        hostname: hostname.clone(),
        os: String::new(),
        roles: Vec::new(),
        services: Vec::new(),
        is_dc: false,
        owned: false,
    };
    host.is_dc = host.detect_dc();

    reader.add_host(&mut conn, &host).await?;
    info!("Injected host: {hostname} / {ip}");

    // Also add the domain if hostname has a domain part
    if hostname.contains('.') {
        let parts: Vec<&str> = hostname.split('.').collect();
        if parts.len() > 1 {
            let domain = parts[1..].join(".");
            let added = reader.add_domain(&mut conn, &domain).await?;
            if added {
                info!("Added domain from hostname: {domain}");
            }
        }
    }

    let n = state::publish_state_update(&mut conn, &operation_id)
        .await
        .unwrap_or(0);
    info!("{n} subscribers notified of host_added");

    Ok(())
}

// ============================================================================
// ops inject-hash
// ============================================================================

#[allow(clippy::too_many_arguments)]
async fn ops_inject_hash(
    redis_url: Option<String>,
    operation_id: String,
    username: String,
    hash_value: String,
    domain: String,
    hash_type: String,
    source: String,
    aes_key: Option<String>,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let reader = RedisStateReader::new(operation_id.clone());

    if !reader.exists(&mut conn).await? {
        anyhow::bail!("No state found for operation: {operation_id}");
    }

    let hash = Hash {
        id: uuid::Uuid::new_v4().to_string(),
        username: username.clone(),
        hash_value: hash_value.clone(),
        hash_type: hash_type.clone(),
        domain: domain.clone(),
        cracked_password: None,
        source,
        discovered_at: Some(Utc::now()),
        parent_id: None,
        attack_step: 0,
        aes_key,
    };

    let added = reader.add_hash(&mut conn, &hash).await?;

    if added {
        // If username is krbtgt or Administrator, set has_domain_admin=True
        let username_lower = username.trim().to_lowercase();
        if username_lower == "krbtgt" || username_lower == "administrator" {
            reader
                .set_meta_field(
                    &mut conn,
                    "has_domain_admin",
                    &serde_json::Value::Bool(true),
                )
                .await?;
            info!("Set has_domain_admin=true (injected {username_lower} hash)");
        }

        let n = state::publish_state_update(&mut conn, &operation_id)
            .await
            .unwrap_or(0);
        info!(
            "Injected hash: {}\\{}:{} ({n} subscribers notified)",
            domain, username, hash_type
        );
    } else {
        info!("Hash already exists: {}\\{}", domain, username);
    }

    Ok(())
}

// ============================================================================
// ops inject-domain-sid
// ============================================================================

async fn ops_inject_domain_sid(
    redis_url: Option<String>,
    operation_id: String,
    domain: String,
    sid: String,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let reader = RedisStateReader::new(operation_id.clone());

    if !reader.exists(&mut conn).await? {
        anyhow::bail!("No state found for operation: {operation_id}");
    }

    reader.set_domain_sid(&mut conn, &domain, &sid).await?;

    let n = state::publish_state_update(&mut conn, &operation_id)
        .await
        .unwrap_or(0);
    info!("Injected domain SID: {domain} = {sid} ({n} subscribers notified)");

    Ok(())
}

// ============================================================================
// ops delete
// ============================================================================

async fn ops_delete(redis_url: Option<String>, operation_id: String, force: bool) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;

    let meta_key = state::build_key(&operation_id, state::KEY_META);
    let exists: bool = conn.exists(&meta_key).await?;

    if !exists {
        warn!("Operation {operation_id} not found");
        return Ok(());
    }

    if !force {
        eprint!("Delete operation {operation_id}? [y/N]: ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim().to_lowercase() != "y" {
            println!("Cancelled");
            return Ok(());
        }
    }

    let deleted = state::delete_operation(&mut conn, &operation_id).await?;
    info!("Deleted operation {operation_id} ({deleted} keys removed)");

    Ok(())
}

// ============================================================================
// ops report
// ============================================================================

async fn ops_report(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
    regenerate: bool,
    output_dir: String,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let op_id = resolve_operation_id(&mut conn, operation_id, latest).await?;

    let reader = RedisStateReader::new(op_id.clone());

    // Check for cached report first (unless regenerating)
    if !regenerate {
        if let Ok(Some(cached)) = reader.get_report(&mut conn).await {
            let report_path = save_report(&output_dir, &op_id, &cached)?;
            println!("Report saved to {report_path} (cached)");
            return Ok(());
        }
    }

    // Generate report from state
    let state = reader
        .load_state(&mut conn)
        .await?
        .with_context(|| format!("No state found for operation: {op_id}"))?;

    let timeline = reader.get_timeline(&mut conn).await.unwrap_or_default();
    let techniques = reader.get_techniques(&mut conn).await.unwrap_or_default();
    let is_running = reader.is_running(&mut conn).await.unwrap_or(false);

    let report = generate_report(&state, &timeline, &techniques, is_running);
    let report_path = save_report(&output_dir, &op_id, &report)?;
    println!("Report saved to {report_path}");

    Ok(())
}

fn generate_report(
    state: &SharedRedTeamState,
    timeline: &[serde_json::Value],
    techniques: &[String],
    is_running: bool,
) -> String {
    let unique_creds = dedup_credentials(&state.all_credentials);
    let unique_hashes = dedup_hashes(&state.all_hashes);
    let now = Utc::now();

    let (runtime_seconds, status) = if let Some(completed) = state.completed_at {
        (
            (completed - state.started_at).num_seconds().max(0) as u64,
            "Completed",
        )
    } else if is_running {
        (
            (now - state.started_at).num_seconds().max(0) as u64,
            "Running",
        )
    } else {
        (
            (now - state.started_at).num_seconds().max(0) as u64,
            "Stopped",
        )
    };

    let target_display = state
        .target
        .as_ref()
        .map(|t| {
            if !t.domain.is_empty() {
                format!("{} ({})", t.ip, t.domain)
            } else {
                t.ip.clone()
            }
        })
        .unwrap_or_else(|| {
            if state.target_ips.is_empty() {
                "Unknown".to_string()
            } else {
                state.target_ips.join(", ")
            }
        });

    let dc_count = state
        .all_hosts
        .iter()
        .filter(|h| h.is_dc || h.detect_dc())
        .count();

    let mut report = String::with_capacity(8192);

    // Header
    report.push_str("# Red Team Operation Report\n\n");
    report.push_str(&format!("**Operation ID**: {}\n\n", state.operation_id));
    report.push_str(&format!("**Target**: {target_display}\n\n"));
    report.push_str(&format!(
        "**Started**: {}\n\n",
        state.started_at.to_rfc3339()
    ));
    report.push_str(&format!(
        "**Completed**: {}\n\n",
        state
            .completed_at
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| status.to_string())
    ));
    report.push_str(&format!(
        "**Duration**: {}\n\n",
        format_duration(runtime_seconds)
    ));
    report.push_str("---\n\n");

    // Executive Summary
    report.push_str("## Executive Summary\n\n");
    if state.has_domain_admin {
        report.push_str("### DOMAIN ADMIN ACHIEVED\n\n");
        report.push_str(&format!(
            "**Attack Path**: {}\n\n",
            state
                .domain_admin_path
                .as_deref()
                .unwrap_or("Path not recorded")
        ));
    } else {
        report.push_str("Domain Admin access was **not achieved** during this operation.\n\n");
    }
    if state.has_golden_ticket {
        report.push_str("### GOLDEN TICKET GENERATED\n\n");
        report.push_str("Persistent domain access has been established via Golden Ticket.\n\n");
    }
    report.push_str("---\n\n");

    // Success Metrics
    report.push_str("## Success Metrics\n\n");
    report.push_str("| Metric | Value |\n|--------|-------|\n");
    report.push_str(&format!(
        "| Domain Admin Access | {} |\n",
        if state.has_domain_admin {
            "ACHIEVED"
        } else {
            "Not Achieved"
        }
    ));
    report.push_str(&format!(
        "| Golden Ticket | {} |\n",
        if state.has_golden_ticket {
            "GENERATED"
        } else {
            "Not Generated"
        }
    ));
    report.push_str(&format!(
        "| Domains Discovered | {} |\n",
        state.all_domains.len()
    ));
    report.push_str(&format!(
        "| Hosts Discovered | {} ({} DCs) |\n",
        state.all_hosts.len(),
        dc_count
    ));
    report.push_str(&format!(
        "| Users Discovered | {} |\n",
        state.all_users.len()
    ));
    report.push_str(&format!(
        "| Credentials Obtained | {} |\n",
        unique_creds.len()
    ));
    report.push_str(&format!(
        "| NTLM Hashes Captured | {} |\n",
        unique_hashes.len()
    ));
    report.push_str(&format!(
        "| Vulnerabilities Found | {} |\n",
        state.discovered_vulnerabilities.len()
    ));
    report.push_str(&format!(
        "| Vulnerabilities Exploited | {} |\n",
        state.exploited_vulnerabilities.len()
    ));
    report.push_str(&format!(
        "| Network Shares | {} |\n",
        state.all_shares.len()
    ));
    report.push_str("\n---\n\n");

    // Domains
    report.push_str("## Domains\n\n");
    if state.all_domains.is_empty() {
        report.push_str("No domains discovered.\n\n");
    } else {
        let mut domains: Vec<_> = state.all_domains.iter().map(|d| d.to_lowercase()).collect();
        domains.sort();
        domains.dedup();
        for d in &domains {
            report.push_str(&format!("- {d}\n"));
        }
        report.push('\n');
    }
    report.push_str("---\n\n");

    // Discovered Hosts
    report.push_str("## Discovered Hosts\n\n");
    if state.all_hosts.is_empty() {
        report.push_str("No hosts discovered.\n\n");
    } else {
        for host in &state.all_hosts {
            let label = if !host.hostname.is_empty() {
                &host.hostname
            } else {
                &host.ip
            };
            let dc_tag = if host.is_dc || host.detect_dc() {
                " [DOMAIN CONTROLLER]"
            } else {
                ""
            };
            report.push_str(&format!("### {label}{dc_tag}\n\n"));
            report.push_str(&format!("- **IP**: {}\n", host.ip));
            report.push_str(&format!(
                "- **OS**: {}\n",
                if host.os.is_empty() {
                    "Unknown"
                } else {
                    &host.os
                }
            ));
            if !host.services.is_empty() {
                report.push_str("- **Services**:\n");
                for svc in &host.services {
                    report.push_str(&format!("  - {svc}\n"));
                }
            }
            report.push('\n');
        }
    }
    report.push_str("---\n\n");

    // Network Shares
    report.push_str("## Network Shares\n\n");
    if state.all_shares.is_empty() {
        report.push_str("No network shares discovered.\n\n");
    } else {
        report.push_str("| Share | Host | Permissions |\n|-------|------|-------------|\n");
        for share in &state.all_shares {
            report.push_str(&format!(
                "| {} | {} | {} |\n",
                share.name,
                share.host,
                if share.permissions.is_empty() {
                    "-"
                } else {
                    &share.permissions
                }
            ));
        }
        report.push('\n');
    }
    report.push_str("---\n\n");

    // Credentials & Hashes
    report.push_str("## Credentials & Hashes\n\n");
    report.push_str(&format!(
        "### Plaintext Credentials ({})\n\n",
        unique_creds.len()
    ));
    if unique_creds.is_empty() {
        report.push_str("No plaintext credentials captured.\n\n");
    } else {
        report.push_str("| Domain | Username | Password | Source | Admin |\n|--------|----------|----------|--------|-------|\n");
        for cred in &unique_creds {
            report.push_str(&format!(
                "| {} | {} | `{}` | {} | {} |\n",
                cred.domain,
                cred.username,
                cred.password,
                cred.source,
                if cred.is_admin { "Yes" } else { "No" }
            ));
        }
        report.push('\n');
    }

    report.push_str(&format!("### NTLM Hashes ({})\n\n", unique_hashes.len()));
    if unique_hashes.is_empty() {
        report.push_str("No NTLM hashes captured.\n\n");
    } else {
        for hash in &unique_hashes {
            report.push_str(&format!(
                "- `{}\\{}:{}:{}`",
                hash.domain, hash.username, hash.hash_type, hash.hash_value
            ));
            if !hash.source.is_empty() {
                report.push_str(&format!(" ({})", hash.source));
            }
            report.push('\n');
        }
        report.push('\n');
    }
    report.push_str("---\n\n");

    // Timeline
    report.push_str("## Attack Path & Timeline\n\n");
    if let Some(path) = &state.domain_admin_path {
        report.push_str("### Path to Domain Admin\n\n");
        report.push_str(path);
        report.push_str("\n\n");
    }
    report.push_str("### Key Events\n\n");
    if timeline.is_empty() {
        report.push_str("No timeline events recorded.\n\n");
    } else {
        report.push_str("| Time (UTC) | Event | MITRE |\n|------------|-------|-------|\n");
        for event in timeline {
            let ts = event
                .get("timestamp")
                .and_then(|v| v.as_str())
                .unwrap_or("-");
            let desc = event
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("-");
            let mitre = event
                .get("mitre_techniques")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_else(|| "-".to_string());
            report.push_str(&format!("| {ts} | {desc} | {mitre} |\n"));
        }
        report.push('\n');
    }
    report.push_str("---\n\n");

    // Vulnerabilities
    report.push_str("## Vulnerabilities & Weaknesses\n\n");
    report.push_str("### Discovered Vulnerabilities\n\n");
    if state.discovered_vulnerabilities.is_empty() {
        report.push_str("No specific vulnerabilities discovered.\n\n");
    } else {
        for (vuln_id, vuln) in &state.discovered_vulnerabilities {
            let exploited = state.exploited_vulnerabilities.contains(vuln_id);
            report.push_str(&format!("#### {} on {}\n\n", vuln.vuln_type, vuln.target));
            report.push_str(&format!("- **Priority**: {}\n", vuln.priority));
            report.push_str(&format!(
                "- **Status**: {}\n",
                if exploited {
                    "EXPLOITED"
                } else {
                    "Not Exploited"
                }
            ));
            if !vuln.details.is_empty() {
                report.push_str(&format!("- **Details**: {:?}\n", vuln.details));
            }
            report.push('\n');
        }
    }

    report.push_str("### Security Weaknesses\n\n");
    if state.all_weaknesses.is_empty() {
        report.push_str("No significant weaknesses recorded.\n\n");
    } else {
        for w in &state.all_weaknesses {
            report.push_str(&format!("- {w}\n"));
        }
        report.push('\n');
    }
    report.push_str("---\n\n");

    // MITRE ATT&CK
    report.push_str("## MITRE ATT&CK Mapping\n\n");
    if techniques.is_empty() {
        report.push_str("No MITRE techniques mapped.\n\n");
    } else {
        let mut sorted_techniques = techniques.to_vec();
        sorted_techniques.sort();
        for t in &sorted_techniques {
            report.push_str(&format!("- {t}\n"));
        }
        report.push('\n');
    }
    report.push_str("---\n\n");

    // Recommendations
    report.push_str("## Recommendations\n\n");
    report.push_str("### Immediate Actions\n\n");
    report.push_str("1. **Reset all compromised credentials** - All passwords listed above should be changed immediately\n");
    report.push_str("2. **Revoke any generated tickets** - If golden ticket was created, full krbtgt password reset required (twice)\n");
    report.push_str(
        "3. **Investigate lateral movement** - Review access logs on all compromised hosts\n",
    );
    report.push_str("4. **Patch identified vulnerabilities** - Address all discovered vulnerabilities by priority\n\n");
    report.push_str("### Long-term Improvements\n\n");
    report.push_str("1. Implement credential tiering and reduce credential exposure\n");
    report.push_str(
        "2. Enable and monitor for Kerberos anomalies (unconstrained delegation, S4U abuse)\n",
    );
    report.push_str("3. Segment network to limit lateral movement paths\n");
    report.push_str("4. Deploy endpoint detection for common attack tools (Impacket, Mimikatz)\n");
    report.push_str("5. Regular vulnerability assessments for ADCS, MSSQL, and delegation misconfigurations\n\n");
    report.push_str("---\n\n");
    report.push_str(&format!(
        "*Report generated by Ares Red Team Agent*\n*{}*\n",
        now.to_rfc3339()
    ));

    report
}

fn save_report(output_dir: &str, op_id: &str, report: &str) -> Result<String> {
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create report directory: {output_dir}"))?;
    let path = format!("{output_dir}/{op_id}_report.md");
    std::fs::write(&path, report).with_context(|| format!("Failed to write report to {path}"))?;
    Ok(path)
}

// ============================================================================
// ops cleanup
// ============================================================================

async fn ops_cleanup(redis_url: Option<String>, max_age_hours: u64) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let cutoff = Utc::now() - chrono::Duration::hours(max_age_hours as i64);

    let all_op_ids = state::list_operation_ids(&mut conn).await?;
    let running_ops = state::list_running_operations(&mut conn).await?;

    let mut cleaned = 0u32;
    for op_id in &all_op_ids {
        // Never clean up running operations
        if running_ops.contains(op_id) {
            continue;
        }

        // Parse timestamp from operation ID format: op-YYYYMMDD-HHMMSS
        let op_time = parse_operation_timestamp(op_id);
        match op_time {
            Some(ts) if ts < cutoff => {
                let deleted = state::delete_operation(&mut conn, op_id).await?;
                info!("Cleaned up {op_id} ({deleted} keys)");
                cleaned += 1;
            }
            Some(_) => {} // Not old enough
            None => {
                warn!("Could not parse timestamp from operation ID: {op_id}, skipping");
            }
        }
    }

    if cleaned == 0 {
        println!("No operations older than {max_age_hours}h to clean up");
    } else {
        println!("Cleaned up {cleaned} operation(s)");
    }

    Ok(())
}

/// Parse a UTC timestamp from an operation ID with format `op-YYYYMMDD-HHMMSS`.
fn parse_operation_timestamp(op_id: &str) -> Option<DateTime<Utc>> {
    // Expected format: op-YYYYMMDD-HHMMSS (e.g., op-20250128-123456)
    if !op_id.starts_with("op-") || op_id.len() < 18 {
        return None;
    }
    let date_part = &op_id[3..11]; // YYYYMMDD
    let time_part = &op_id[12..18]; // HHMMSS
    let datetime_str = format!(
        "{}-{}-{}T{}:{}:{}Z",
        &date_part[..4],
        &date_part[4..6],
        &date_part[6..8],
        &time_part[..2],
        &time_part[2..4],
        &time_part[4..6],
    );
    datetime_str.parse::<DateTime<Utc>>().ok()
}

// ============================================================================
// ops backfill-domains
// ============================================================================

async fn ops_backfill_domains(redis_url: Option<String>, operation_id: String) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let reader = RedisStateReader::new(operation_id.clone());

    let state = reader
        .load_state(&mut conn)
        .await?
        .with_context(|| format!("No state found for operation: {operation_id}"))?;

    let mut inferred_domains = std::collections::HashSet::new();

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

    let existing: std::collections::HashSet<String> = state
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

// ============================================================================
// Blue Team Commands
// ============================================================================

async fn run_blue(cmd: BlueCommands, redis_url: Option<String>) -> Result<()> {
    match cmd {
        BlueCommands::List { latest } => blue_list(redis_url, latest).await,
        BlueCommands::Status {
            investigation_id,
            latest,
        } => blue_status(redis_url, investigation_id, latest).await,
        BlueCommands::Evidence {
            investigation_id,
            latest,
            json,
        } => blue_evidence(redis_url, investigation_id, latest, json).await,
        BlueCommands::Techniques {
            investigation_id,
            latest,
        } => blue_techniques(redis_url, investigation_id, latest).await,
        BlueCommands::Runtime {
            investigation_id,
            latest,
        } => blue_runtime(redis_url, investigation_id, latest).await,
        BlueCommands::TriageStatus {
            investigation_id,
            latest,
            json,
        } => blue_triage_status(redis_url, investigation_id, latest, json).await,
        BlueCommands::OperationStatus {
            operation_id,
            latest,
            watch,
        } => blue_operation_status(redis_url, operation_id, latest, watch).await,
        BlueCommands::Delete {
            investigation_id,
            force,
        } => blue_delete(redis_url, investigation_id, force).await,
        BlueCommands::DeleteOperation {
            operation_id,
            force,
        } => blue_delete_operation(redis_url, operation_id, force).await,
        BlueCommands::Cleanup {
            max_age_hours,
            all,
            dry_run,
            force,
        } => blue_cleanup(redis_url, max_age_hours, all, dry_run, force).await,
    }
}

async fn blue_list(redis_url: Option<String>, latest: bool) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;

    let status_keys: Vec<String> = redis::cmd("KEYS")
        .arg("ares:blue:inv:*:status")
        .query_async(&mut conn)
        .await?;

    let mut investigations: Vec<(String, String, String)> = Vec::new();

    for key in &status_keys {
        let parts: Vec<&str> = key.split(':').collect();
        if parts.len() < 4 {
            continue;
        }
        let inv_id = parts[3].to_string();

        let raw: Option<String> = conn.get(key).await?;
        if let Some(json_str) = raw {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&json_str) {
                let status = data
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let started = data
                    .get("started_at")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                investigations.push((inv_id, status, started));
            }
        }
    }

    investigations.sort_by(|a, b| b.2.cmp(&a.2));

    if latest {
        // Prefer running
        if let Some(running) = investigations.iter().find(|(_, s, _)| s == "running") {
            println!("{}", running.0);
        } else if let Some(first) = investigations.first() {
            println!("{}", first.0);
        }
        return Ok(());
    }

    if investigations.is_empty() {
        println!("No investigations found");
        return Ok(());
    }

    println!(
        "{:<25} {:<12} {:<25}",
        "Investigation ID", "Status", "Started"
    );
    println!("{}", "-".repeat(65));
    for (id, status, started) in &investigations {
        let started_display = if started.len() > 25 {
            &started[..25]
        } else {
            started
        };
        println!("{id:<25} {status:<12} {started_display:<25}");
    }

    Ok(())
}

async fn blue_status(
    redis_url: Option<String>,
    investigation_id: Option<String>,
    latest: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;

    let inv_id = if latest {
        // Resolve latest
        let status_keys: Vec<String> = redis::cmd("KEYS")
            .arg("ares:blue:inv:*:status")
            .query_async(&mut conn)
            .await?;

        let mut candidates: Vec<(String, String)> = Vec::new();
        for key in &status_keys {
            let parts: Vec<&str> = key.split(':').collect();
            if parts.len() < 4 {
                continue;
            }
            let id = parts[3].to_string();
            let raw: Option<String> = conn.get(key).await?;
            let started = raw
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                .and_then(|v| {
                    v.get("started_at")
                        .and_then(|s| s.as_str().map(String::from))
                })
                .unwrap_or_default();
            candidates.push((id, started));
        }
        candidates.sort_by(|a, b| b.1.cmp(&a.1));
        candidates
            .first()
            .map(|(id, _)| id.clone())
            .context("No investigations found")?
    } else {
        investigation_id.context("Either investigation_id or --latest is required")?
    };

    let status_key = format!("ares:blue:inv:{inv_id}:status");
    let raw: Option<String> = conn.get(&status_key).await?;

    match raw {
        Some(json_str) => {
            let data: serde_json::Value = serde_json::from_str(&json_str)?;
            println!("Investigation: {inv_id}");
            println!(
                "Status: {}",
                data.get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
            );
            if let Some(started) = data.get("started_at").and_then(|v| v.as_str()) {
                println!("Started: {started}");
            }
            if let Some(completed) = data.get("completed_at").and_then(|v| v.as_str()) {
                println!("Completed: {completed}");
            }
            if let Some(error) = data.get("error").and_then(|v| v.as_str()) {
                println!("Error: {error}");
            }
        }
        None => println!("Investigation not found: {inv_id}"),
    }

    Ok(())
}

async fn blue_delete(
    redis_url: Option<String>,
    investigation_id: String,
    force: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;

    if !force {
        eprint!("Delete investigation {investigation_id} and all data? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim().to_lowercase() != "y" {
            println!("Aborted");
            return Ok(());
        }
    }

    let pattern = format!("ares:blue:inv:{investigation_id}:*");
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(&pattern)
        .query_async(&mut conn)
        .await?;

    let mut deleted = 0usize;
    for key in &keys {
        let count: usize = conn.del(key).await?;
        deleted += count;
    }

    let removed: i64 = conn
        .srem("ares:blue:active_investigations", &investigation_id)
        .await?;
    deleted += removed as usize;

    if deleted == 0 {
        println!("No data found for investigation: {investigation_id}");
    } else {
        println!("Deleted {deleted} keys for investigation: {investigation_id}");
    }

    Ok(())
}

async fn blue_delete_operation(
    redis_url: Option<String>,
    operation_id: String,
    force: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;

    let op_inv_key = format!("ares:blue:op:{operation_id}:investigations");
    let inv_ids: HashSet<String> = conn.smembers(&op_inv_key).await?;

    if inv_ids.is_empty() {
        println!("No investigations found for operation: {operation_id}");
        return Ok(());
    }

    println!("Operation: {operation_id}");
    println!("Investigations to delete: {}", inv_ids.len());
    for inv_id in &inv_ids {
        println!("  - {inv_id}");
    }

    if !force {
        eprint!(
            "\nDelete operation {operation_id} and {} investigation(s)? [y/N] ",
            inv_ids.len()
        );
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim().to_lowercase() != "y" {
            println!("Aborted");
            return Ok(());
        }
    }

    let mut total_deleted = 0usize;
    for inv_id in &inv_ids {
        let pattern = format!("ares:blue:inv:{inv_id}:*");
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(&pattern)
            .query_async(&mut conn)
            .await?;
        for key in &keys {
            let count: usize = conn.del(key).await?;
            total_deleted += count;
        }
    }

    if !inv_ids.is_empty() {
        let inv_list: Vec<&String> = inv_ids.iter().collect();
        let removed: i64 = conn
            .srem("ares:blue:active_investigations", inv_list.as_slice())
            .await?;
        total_deleted += removed as usize;
    }

    let _: usize = conn.del(&op_inv_key).await?;
    total_deleted += 1;

    println!("\nDeleted {total_deleted} keys");
    println!(
        "Operation {operation_id} and {} investigation(s) deleted",
        inv_ids.len()
    );

    Ok(())
}

// ============================================================================
// Resolve latest investigation ID (prefer running)
// ============================================================================

async fn resolve_latest_investigation(
    conn: &mut redis::aio::MultiplexedConnection,
) -> Result<Option<String>> {
    let status_keys: Vec<String> = redis::cmd("KEYS")
        .arg("ares:blue:inv:*:status")
        .query_async(conn)
        .await?;

    let mut candidates: Vec<(String, String, String)> = Vec::new(); // (id, status, started_at)

    for key in &status_keys {
        let parts: Vec<&str> = key.split(':').collect();
        if parts.len() < 4 {
            continue;
        }
        let inv_id = parts[3].to_string();

        let raw: Option<String> = conn.get(key).await?;
        if let Some(json_str) = raw {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&json_str) {
                let status = data
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let started = data
                    .get("started_at")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                candidates.push((inv_id, status, started));
            }
        }
    }

    if candidates.is_empty() {
        return Ok(None);
    }

    // Sort by started_at descending
    candidates.sort_by(|a, b| b.2.cmp(&a.2));

    // Prefer running investigations
    if let Some(running) = candidates.iter().find(|(_, s, _)| s == "running") {
        return Ok(Some(running.0.clone()));
    }

    Ok(candidates.first().map(|(id, _, _)| id.clone()))
}

async fn resolve_investigation_id(
    conn: &mut redis::aio::MultiplexedConnection,
    investigation_id: Option<String>,
    latest: bool,
) -> Result<String> {
    if let Some(id) = investigation_id {
        return Ok(id);
    }
    if latest {
        let id = resolve_latest_investigation(conn)
            .await?
            .context("No investigations found")?;
        info!("Using latest investigation: {id}");
        return Ok(id);
    }
    anyhow::bail!("Either investigation_id or --latest is required")
}

// ============================================================================
// blue evidence
// ============================================================================

async fn blue_evidence(
    redis_url: Option<String>,
    investigation_id: Option<String>,
    latest: bool,
    json_output: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let inv_id = resolve_investigation_id(&mut conn, investigation_id, latest).await?;

    let evidence_key = format!("ares:blue:inv:{inv_id}:evidence");
    let evidence_data: HashMap<String, String> = conn.hgetall(&evidence_key).await?;

    if evidence_data.is_empty() {
        println!("No evidence found for investigation: {inv_id}");
        return Ok(());
    }

    let mut evidence_items: Vec<serde_json::Value> = Vec::new();
    for value in evidence_data.values() {
        if let Ok(item) = serde_json::from_str::<serde_json::Value>(value) {
            evidence_items.push(item);
        }
    }

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&evidence_items).unwrap_or_default()
        );
        return Ok(());
    }

    println!("Evidence for investigation: {inv_id}");
    println!("Total items: {}", evidence_items.len());
    println!("{}", "-".repeat(60));

    // Group by type
    let mut by_type: HashMap<String, Vec<&serde_json::Value>> = HashMap::new();
    for item in &evidence_items {
        let ev_type = item
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        by_type.entry(ev_type).or_default().push(item);
    }

    let mut types: Vec<String> = by_type.keys().cloned().collect();
    types.sort();

    for ev_type in &types {
        let items = &by_type[ev_type];
        println!("\n{} ({} items):", ev_type.to_uppercase(), items.len());
        for item in items.iter().take(10) {
            let value = item
                .get("value")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let display = if value.is_object() || value.is_array() {
                serde_json::to_string(&value).unwrap_or_default()
            } else {
                value
                    .as_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| value.to_string())
            };
            if display.len() > 80 {
                println!("  - {}...", &display[..80]);
            } else {
                println!("  - {display}");
            }
        }
        if items.len() > 10 {
            println!("  ... and {} more", items.len() - 10);
        }
    }

    Ok(())
}

// ============================================================================
// blue techniques
// ============================================================================

async fn blue_techniques(
    redis_url: Option<String>,
    investigation_id: Option<String>,
    latest: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let inv_id = resolve_investigation_id(&mut conn, investigation_id, latest).await?;

    let techniques_key = format!("ares:blue:inv:{inv_id}:techniques");
    let techniques: HashSet<String> = conn.smembers(&techniques_key).await?;

    let names_key = format!("ares:blue:inv:{inv_id}:technique_names");
    let names: HashMap<String, String> = conn.hgetall(&names_key).await?;

    if techniques.is_empty() {
        println!("No techniques identified for investigation: {inv_id}");
        return Ok(());
    }

    println!("MITRE ATT&CK Techniques for investigation: {inv_id}");
    println!("{}", "-".repeat(60));

    let mut sorted_techniques: Vec<String> = techniques.into_iter().collect();
    sorted_techniques.sort();

    for tech_id in &sorted_techniques {
        if let Some(name) = names.get(tech_id) {
            if !name.is_empty() {
                println!("  {tech_id}: {name}");
            } else {
                println!("  {tech_id}");
            }
        } else {
            println!("  {tech_id}");
        }
    }

    Ok(())
}

// ============================================================================
// blue runtime
// ============================================================================

async fn blue_runtime(
    redis_url: Option<String>,
    investigation_id: Option<String>,
    latest: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let inv_id = resolve_investigation_id(&mut conn, investigation_id, latest).await?;

    let status_key = format!("ares:blue:inv:{inv_id}:status");
    let raw: Option<String> = conn.get(&status_key).await?;

    match raw {
        Some(json_str) => {
            let data: serde_json::Value = serde_json::from_str(&json_str)?;
            let status = data
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            println!("Investigation: {inv_id}");
            println!("Status: {status}");

            let started_at = data.get("started_at").and_then(|v| v.as_str());
            let completed_at = data
                .get("completed_at")
                .and_then(|v| v.as_str())
                .or_else(|| data.get("failed_at").and_then(|v| v.as_str()));

            if let Some(started_str) = started_at {
                if let Ok(start_dt) = parse_datetime(started_str) {
                    println!("Started: {}", start_dt.to_rfc3339());

                    let elapsed = if let Some(end_str) = completed_at {
                        parse_datetime(end_str)
                            .ok()
                            .map(|end_dt| (end_dt - start_dt).num_seconds().max(0) as u64)
                    } else if status == "running" {
                        Some((Utc::now() - start_dt).num_seconds().max(0) as u64)
                    } else {
                        None
                    };

                    if let Some(secs) = elapsed {
                        if secs > 0 {
                            println!("Duration: {}", format_duration(secs));
                        }
                    }
                }
            }

            if let Some(completed) = completed_at {
                println!("Completed: {completed}");
            }
        }
        None => {
            println!("Investigation not found: {inv_id}");
        }
    }

    Ok(())
}

// ============================================================================
// blue triage-status
// ============================================================================

async fn blue_triage_status(
    redis_url: Option<String>,
    investigation_id: Option<String>,
    latest: bool,
    json_output: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;
    let inv_id = resolve_investigation_id(&mut conn, investigation_id, latest).await?;

    // Read triage decision
    let decision_key = format!("ares:blue:inv:{inv_id}:triage:decision");
    let decision_raw: Option<String> = conn.get(&decision_key).await?;

    // Read triage records (audit trail)
    let records_key = format!("ares:blue:inv:{inv_id}:triage:records");
    let records_raw: Vec<String> = conn.lrange(&records_key, 0, -1).await?;
    let mut records: Vec<serde_json::Value> = Vec::new();
    for r in &records_raw {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(r) {
            records.push(v);
        }
    }

    // Read investigation status
    let status_key = format!("ares:blue:inv:{inv_id}:status");
    let status_raw: Option<String> = conn.get(&status_key).await?;
    let status = status_raw
        .as_ref()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        .and_then(|v| v.get("status").and_then(|s| s.as_str()).map(String::from))
        .unwrap_or_else(|| "unknown".to_string());

    // Read meta for escalation info
    let meta_key = format!("ares:blue:inv:{inv_id}:meta");
    let meta_data: HashMap<String, String> = conn.hgetall(&meta_key).await?;
    let escalated = meta_data
        .get("escalated")
        .and_then(|v| serde_json::from_str::<bool>(v).ok())
        .unwrap_or(false);
    let escalation_reason = meta_data.get("escalation_reason").and_then(|v| {
        serde_json::from_str::<serde_json::Value>(v)
            .ok()
            .and_then(|val| val.as_str().map(String::from))
            .or_else(|| Some(v.clone()))
    });

    if json_output {
        let decision_val = decision_raw
            .as_ref()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
        let output = serde_json::json!({
            "investigation_id": inv_id,
            "status": status,
            "escalated": escalated,
            "escalation_reason": escalation_reason,
            "triage_decision": decision_val,
            "triage_records": records,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
        return Ok(());
    }

    println!("Investigation: {inv_id}");
    println!("Status: {status}");
    println!("Escalated: {escalated}");
    if let Some(reason) = &escalation_reason {
        println!("Escalation reason: {reason}");
    }
    println!("{}", "-".repeat(60));

    if decision_raw.is_none() && records.is_empty() {
        println!("No triage data found (investigation may not have been escalated)");
        return Ok(());
    }

    println!("\nTriage Decision:");
    if let Some(ref decision_str) = decision_raw {
        if let Ok(decision) = serde_json::from_str::<serde_json::Value>(decision_str) {
            let dec_val = decision
                .get("decision")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            println!("  Decision: {}", dec_val.to_uppercase());
            let confidence = decision
                .get("confidence")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            println!("  Confidence: {confidence:.2}");
            if let Some(routed_to) = decision.get("routed_to").and_then(|v| v.as_str()) {
                if !routed_to.is_empty() {
                    println!("  Routed to: {routed_to}");
                }
            }
            if let Some(focus_areas) = decision.get("focus_areas").and_then(|v| v.as_array()) {
                let areas: Vec<&str> = focus_areas.iter().filter_map(|v| v.as_str()).collect();
                if !areas.is_empty() {
                    println!("  Focus areas: {}", areas.join(", "));
                }
            }
            if let Some(cycle) = decision
                .get("reinvestigation_cycle")
                .and_then(|v| v.as_i64())
            {
                if cycle > 0 {
                    println!("  Reinvestigation cycle: {cycle}/2");
                }
            }
            let reasoning = decision
                .get("reasoning")
                .and_then(|v| v.as_str())
                .unwrap_or("None provided");
            println!("\n  Reasoning: {reasoning}");
        }
    } else {
        println!("  Decision: PENDING");
    }

    if !records.is_empty() {
        println!("\n{}", "-".repeat(60));
        println!("Triage Audit Trail:");
        for (i, record) in records.iter().enumerate() {
            let created_at = record
                .get("created_at")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            println!("\n  [{}] {created_at}", i + 1);
            let dec = record
                .get("decision")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            println!("      Decision: {}", dec.to_uppercase());
            let conf = record
                .get("confidence")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            println!("      Confidence: {conf:.2}");
            let reasoning = record
                .get("reasoning")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if reasoning.len() > 100 {
                println!("      Reasoning: {}...", &reasoning[..100]);
            } else {
                println!("      Reasoning: {reasoning}");
            }
        }
    }

    Ok(())
}

// ============================================================================
// blue operation-status
// ============================================================================

async fn blue_operation_status(
    redis_url: Option<String>,
    operation_id: Option<String>,
    latest: bool,
    watch: u64,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;

    let op_id = if latest {
        // Resolve latest red team operation
        state::resolve_latest_operation(&mut conn)
            .await?
            .context("No red team operations found")?
    } else {
        operation_id.context("Either operation_id or --latest is required")?
    };

    if watch > 0 {
        loop {
            // Clear screen
            print!("\x1B[2J\x1B[H");
            let all_done = blue_operation_status_once(&mut conn, &op_id).await?;
            if all_done {
                println!("\nAll investigations complete.");
                break;
            }
            println!("\nRefreshing in {watch}s... (Ctrl+C to stop)");
            tokio::time::sleep(tokio::time::Duration::from_secs(watch)).await;
        }
    } else {
        blue_operation_status_once(&mut conn, &op_id).await?;
    }

    Ok(())
}

/// Show status for all investigations in an operation. Returns true if all done.
async fn blue_operation_status_once(
    conn: &mut redis::aio::MultiplexedConnection,
    operation_id: &str,
) -> Result<bool> {
    let op_inv_key = format!("ares:blue:op:{operation_id}:investigations");
    let inv_ids: HashSet<String> = conn.smembers(&op_inv_key).await?;

    if inv_ids.is_empty() {
        println!("No investigations found for operation: {operation_id}");
        return Ok(true);
    }

    let mut status_counts: HashMap<String, Vec<serde_json::Value>> = HashMap::new();
    let mut triage_counts: HashMap<String, i64> = HashMap::new();
    let mut earliest_start: Option<DateTime<Utc>> = None;
    let mut latest_end: Option<DateTime<Utc>> = None;

    let mut sorted_ids: Vec<String> = inv_ids.iter().cloned().collect();
    sorted_ids.sort();

    for inv_id in &sorted_ids {
        let status_key = format!("ares:blue:inv:{inv_id}:status");
        let status_json: Option<String> = conn.get(&status_key).await?;

        if let Some(json_str) = status_json {
            if let Ok(mut data) = serde_json::from_str::<serde_json::Value>(&json_str) {
                data.as_object_mut().map(|obj| {
                    obj.insert(
                        "investigation_id".to_string(),
                        serde_json::Value::String(inv_id.clone()),
                    )
                });

                let inv_status = data
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();

                // Track timestamps
                if let Some(started) = data.get("started_at").and_then(|v| v.as_str()) {
                    if let Ok(dt) = parse_datetime(started) {
                        if earliest_start.is_none() || dt < earliest_start.unwrap() {
                            earliest_start = Some(dt);
                        }
                    }
                }

                let completed_at = data
                    .get("completed_at")
                    .and_then(|v| v.as_str())
                    .or_else(|| data.get("failed_at").and_then(|v| v.as_str()));
                if let Some(end_str) = completed_at {
                    if let Ok(dt) = parse_datetime(end_str) {
                        if latest_end.is_none() || dt > latest_end.unwrap() {
                            latest_end = Some(dt);
                        }
                    }
                }

                // Check triage for escalated/routed/completed
                if matches!(inv_status.as_str(), "escalated" | "routed" | "completed") {
                    let triage_key = format!("ares:blue:inv:{inv_id}:triage:decision");
                    let triage_data: Option<String> = conn.get(&triage_key).await?;
                    if let Some(triage_str) = triage_data {
                        if let Ok(triage) = serde_json::from_str::<serde_json::Value>(&triage_str) {
                            let decision = triage
                                .get("decision")
                                .and_then(|v| v.as_str())
                                .unwrap_or("pending")
                                .to_string();
                            *triage_counts.entry(decision).or_insert(0) += 1;
                        }
                    }
                }

                status_counts.entry(inv_status).or_default().push(data);
            }
        } else {
            status_counts
                .entry("submitted".to_string())
                .or_default()
                .push(serde_json::json!({"investigation_id": inv_id}));
        }
    }

    // Calculate duration
    let now = Utc::now();
    let elapsed = if let Some(start) = earliest_start {
        let has_running =
            status_counts.contains_key("running") || status_counts.contains_key("submitted");
        if has_running {
            (now - start).num_seconds().max(0) as u64
        } else if let Some(end) = latest_end {
            (end - start).num_seconds().max(0) as u64
        } else {
            0
        }
    } else {
        0
    };

    let total = sorted_ids.len();
    let running = status_counts.get("running").map_or(0, |v| v.len());
    let completed = status_counts.get("completed").map_or(0, |v| v.len());
    let escalated = status_counts.get("escalated").map_or(0, |v| v.len());
    let routed = status_counts.get("routed").map_or(0, |v| v.len());
    let failed = status_counts.get("failed").map_or(0, |v| v.len());
    let submitted = status_counts.get("submitted").map_or(0, |v| v.len());

    println!("Operation: {operation_id}");
    println!("Total investigations: {total}");
    println!("  Running:   {running}");
    println!("  Completed: {completed}");
    println!("  Escalated: {escalated}");
    println!("  Routed:    {routed}");
    println!("  Failed:    {failed}");
    println!("  Submitted: {submitted}");
    println!("Duration: {}", format_duration(elapsed));

    let total_triaged: i64 = triage_counts.values().sum();
    if total_triaged > 0 {
        println!("\nTriage breakdown:");
        println!(
            "  Confirmed:     {}",
            triage_counts.get("confirmed").unwrap_or(&0)
        );
        println!(
            "  Downgraded:    {}",
            triage_counts.get("downgraded").unwrap_or(&0)
        );
        println!(
            "  Routed:        {}",
            triage_counts.get("routed").unwrap_or(&0)
        );
        println!(
            "  Reinvestigate: {}",
            triage_counts.get("reinvestigate").unwrap_or(&0)
        );
        println!(
            "  Pending:       {}",
            triage_counts.get("pending").unwrap_or(&0)
        );
    }

    if let Some(start) = earliest_start {
        println!("\nStarted: {}", start.to_rfc3339());
    }
    let has_active = running > 0 || submitted > 0;
    if let Some(end) = latest_end {
        if !has_active {
            println!("Completed: {}", end.to_rfc3339());
        }
    }

    if let Some(running_invs) = status_counts.get("running") {
        println!("\nRunning investigations:");
        for inv in running_invs {
            let inv_id = inv
                .get("investigation_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let started = inv.get("started_at").and_then(|v| v.as_str()).unwrap_or("");
            let started_display = if started.len() > 19 {
                &started[..19]
            } else {
                started
            };
            println!("  {inv_id} (started: {started_display})");
        }
    }

    if let Some(failed_invs) = status_counts.get("failed") {
        println!("\nFailed investigations:");
        for inv in failed_invs {
            let inv_id = inv
                .get("investigation_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let error = inv.get("error").and_then(|v| v.as_str()).unwrap_or("");
            let error_display = if error.len() > 60 {
                &error[..60]
            } else {
                error
            };
            println!("  {inv_id}: {error_display}");
        }
    }

    Ok(!has_active)
}

// ============================================================================
// blue cleanup (full implementation)
// ============================================================================

async fn blue_cleanup(
    redis_url: Option<String>,
    max_age_hours: u64,
    all: bool,
    dry_run: bool,
    force: bool,
) -> Result<()> {
    let mut conn = connect_redis(redis_url).await?;

    if all {
        let inv_keys: Vec<String> = redis::cmd("KEYS")
            .arg("ares:blue:inv:*")
            .query_async(&mut conn)
            .await?;
        let op_keys: Vec<String> = redis::cmd("KEYS")
            .arg("ares:blue:op:*")
            .query_async(&mut conn)
            .await?;
        let active_exists: bool = conn.exists("ares:blue:active_investigations").await?;
        let queue_len: i64 = conn.llen("ares:blue:investigations").await?;

        println!("Found {} investigation keys", inv_keys.len());
        println!("Found {} operation tracking keys", op_keys.len());
        println!("Queue length: {queue_len}");

        if dry_run {
            println!("(dry run - no changes made)");
            return Ok(());
        }

        if !force {
            eprint!("Delete ALL blue team investigations? [y/N] ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if input.trim().to_lowercase() != "y" {
                println!("Aborted");
                return Ok(());
            }
        }

        let mut deleted = 0usize;
        for key in &inv_keys {
            let count: usize = conn.del(key).await?;
            deleted += count;
        }
        for key in &op_keys {
            let count: usize = conn.del(key).await?;
            deleted += count;
        }
        if active_exists {
            let count: usize = conn.del("ares:blue:active_investigations").await?;
            deleted += count;
        }
        if queue_len > 0 {
            let _: usize = conn.del("ares:blue:investigations").await?;
            deleted += 1;
        }

        println!("Deleted {deleted} keys");
        println!("All blue team investigations cleared");
        return Ok(());
    }

    // Selective cleanup: only completed/failed older than max_age_hours
    let cutoff = Utc::now().timestamp() - (max_age_hours as i64 * 3600);

    let status_keys: Vec<String> = redis::cmd("KEYS")
        .arg("ares:blue:inv:*:status")
        .query_async(&mut conn)
        .await?;

    let mut to_delete: Vec<String> = Vec::new();

    for key in &status_keys {
        let parts: Vec<&str> = key.split(':').collect();
        if parts.len() < 4 {
            continue;
        }
        let inv_id = parts[3].to_string();

        let raw: Option<String> = conn.get(key).await?;
        let Some(json_str) = raw else { continue };

        let data: serde_json::Value = match serde_json::from_str(&json_str) {
            Ok(d) => d,
            Err(_) => continue,
        };

        let status = data.get("status").and_then(|v| v.as_str()).unwrap_or("");

        if status != "completed" && status != "failed" {
            continue;
        }

        let completed_str = data
            .get("completed_at")
            .and_then(|v| v.as_str())
            .or_else(|| data.get("failed_at").and_then(|v| v.as_str()));

        if let Some(ts_str) = completed_str {
            if let Ok(dt) = parse_datetime(ts_str) {
                if dt.timestamp() < cutoff {
                    to_delete.push(inv_id);
                }
            }
        }
    }

    if to_delete.is_empty() {
        println!("No investigations older than {max_age_hours} hours to clean up");
        return Ok(());
    }

    println!("Found {} investigation(s) to clean up:", to_delete.len());
    for inv_id in &to_delete {
        println!("  - {inv_id}");
    }

    if dry_run {
        println!("(dry run - no changes made)");
        return Ok(());
    }

    let mut total_deleted = 0usize;
    for inv_id in &to_delete {
        let pattern = format!("ares:blue:inv:{inv_id}:*");
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(&pattern)
            .query_async(&mut conn)
            .await?;
        for key in &keys {
            let count: usize = conn.del(key).await?;
            total_deleted += count;
        }
    }

    if !to_delete.is_empty() {
        let inv_refs: Vec<&str> = to_delete.iter().map(|s| s.as_str()).collect();
        let removed: i64 = conn
            .srem("ares:blue:active_investigations", inv_refs.as_slice())
            .await?;
        total_deleted += removed as usize;
    }

    println!(
        "Deleted {total_deleted} keys from {} investigation(s)",
        to_delete.len()
    );

    Ok(())
}

// ============================================================================
// History Commands (Postgres via sqlx)
// ============================================================================

async fn run_history(cmd: HistoryCommands) -> Result<()> {
    match cmd {
        HistoryCommands::List {
            domain,
            has_da,
            since_days,
            limit,
            json,
        } => history_list(domain, has_da, since_days, limit, json).await,
        HistoryCommands::Get { operation_id, json } => history_get(operation_id, json).await,
        HistoryCommands::SearchCreds {
            domain,
            username,
            admin,
            limit,
            json,
        } => history_search_creds(domain, username, admin, limit, json).await,
        HistoryCommands::SearchHashes {
            domain,
            username,
            hash_type,
            cracked,
            limit,
            json,
        } => history_search_hashes(domain, username, hash_type, cracked, limit, json).await,
        HistoryCommands::MitreCoverage {
            since_days,
            json: json_output,
        } => history_mitre_coverage(since_days, json_output).await,
        HistoryCommands::Cost {
            domain,
            since_days,
            limit,
            json,
        } => history_cost(domain, since_days, limit, json).await,
    }
}

fn get_database_url() -> Result<String> {
    std::env::var("ARES_DATABASE_URL")
        .context("Persistent store not enabled. Set ARES_DATABASE_URL environment variable.")
}

async fn connect_postgres() -> Result<sqlx::PgPool> {
    let url = get_database_url()?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .context("Failed to connect to Postgres")?;
    Ok(pool)
}

// ============================================================================
// history list
// ============================================================================

async fn history_list(
    domain: Option<String>,
    has_da: Option<bool>,
    since_days: Option<i64>,
    limit: i64,
    json_output: bool,
) -> Result<()> {
    let pool = connect_postgres().await?;

    let since = since_days.map(|days| Utc::now() - chrono::Duration::days(days));

    // Build dynamic query
    let mut query = String::from(
        "SELECT operation_id, target_domain, target_ip::text, started_at, completed_at, \
         has_domain_admin, has_golden_ticket, \
         COALESCE(credential_count, 0) as credential_count, \
         COALESCE(hash_count, 0) as hash_count, \
         COALESCE(host_count, 0) as host_count, \
         COALESCE(vulnerability_count, 0) as vulnerability_count \
         FROM operations WHERE 1=1",
    );
    let mut bind_idx = 0u32;
    let mut conditions: Vec<String> = Vec::new();

    if domain.is_some() {
        bind_idx += 1;
        conditions.push(format!(" AND target_domain ILIKE ${bind_idx}"));
    }
    if has_da.is_some() {
        bind_idx += 1;
        conditions.push(format!(" AND has_domain_admin = ${bind_idx}"));
    }
    if since.is_some() {
        bind_idx += 1;
        conditions.push(format!(" AND started_at >= ${bind_idx}"));
    }

    for c in &conditions {
        query.push_str(c);
    }
    bind_idx += 1;
    query.push_str(&format!(" ORDER BY started_at DESC LIMIT ${bind_idx}"));

    let mut q = sqlx::query_as::<_, OperationRow>(&query);

    if let Some(ref d) = domain {
        q = q.bind(format!("%{d}%"));
    }
    if let Some(da) = has_da {
        q = q.bind(da);
    }
    if let Some(ref s) = since {
        q = q.bind(s);
    }
    q = q.bind(limit);

    let rows: Vec<OperationRow> = q.fetch_all(&pool).await?;

    if json_output {
        let data: Vec<serde_json::Value> = rows
            .iter()
            .map(|op| {
                let duration = compute_duration_str(op.started_at, op.completed_at);
                serde_json::json!({
                    "operation_id": op.operation_id,
                    "target_domain": op.target_domain,
                    "target_ip": op.target_ip,
                    "started_at": op.started_at.to_rfc3339(),
                    "completed_at": op.completed_at.map(|t| t.to_rfc3339()),
                    "has_domain_admin": op.has_domain_admin,
                    "has_golden_ticket": op.has_golden_ticket,
                    "duration": duration,
                    "credentials": op.credential_count,
                    "hashes": op.hash_count,
                    "hosts": op.host_count,
                    "vulnerabilities": op.vulnerability_count,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    } else {
        if rows.is_empty() {
            println!("No operations found");
            return Ok(());
        }

        println!(
            "\n{:<30} {:<25} {:<4} {:<6} {:<7} {:<12}",
            "OPERATION ID", "DOMAIN", "DA", "CREDS", "HASHES", "DURATION"
        );
        println!("{}", "-".repeat(95));
        for op in &rows {
            let da_mark = if op.has_domain_admin { "Y" } else { "N" };
            let domain_display = op
                .target_domain
                .as_deref()
                .unwrap_or("")
                .chars()
                .take(24)
                .collect::<String>();
            let duration = compute_duration_str(op.started_at, op.completed_at);
            println!(
                "{:<30} {:<25} {:<4} {:<6} {:<7} {:<12}",
                op.operation_id,
                domain_display,
                da_mark,
                op.credential_count,
                op.hash_count,
                duration
            );
        }
        println!("\nTotal: {} operations", rows.len());
    }

    Ok(())
}

// ============================================================================
// history get
// ============================================================================

async fn history_get(operation_id: String, json_output: bool) -> Result<()> {
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

// ============================================================================
// history search-creds
// ============================================================================

async fn history_search_creds(
    domain: Option<String>,
    username: Option<String>,
    admin: bool,
    limit: i64,
    json_output: bool,
) -> Result<()> {
    let pool = connect_postgres().await?;

    let mut query = String::from(
        "SELECT c.username, c.domain, c.is_admin, c.source, c.attack_step, \
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

    let mut q = sqlx::query_as::<_, CredentialSearchRow>(&query);

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

// ============================================================================
// history search-hashes
// ============================================================================

async fn history_search_hashes(
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

    let mut q = sqlx::query_as::<_, HashSearchRow>(&query);

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

// ============================================================================
// Utility Functions
// ============================================================================

fn format_duration(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    if hours > 0 {
        format!("{hours}h {minutes}m {secs}s")
    } else if minutes > 0 {
        format!("{minutes}m {secs}s")
    } else {
        format!("{secs}s")
    }
}

fn parse_datetime(s: &str) -> Result<DateTime<Utc>> {
    let fixed = s.replace('Z', "+00:00");
    DateTime::parse_from_rfc3339(&fixed)
        .or_else(|_| DateTime::parse_from_rfc3339(s))
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f")
                .map(|ndt| ndt.and_utc())
        })
        .map_err(|e| anyhow::anyhow!("Failed to parse datetime '{s}': {e}"))
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    } else {
        s.to_string()
    }
}

fn compute_duration_str(started_at: DateTime<Utc>, completed_at: Option<DateTime<Utc>>) -> String {
    let seconds = if let Some(completed) = completed_at {
        (completed - started_at).num_seconds().max(0) as u64
    } else {
        (Utc::now() - started_at).num_seconds().max(0) as u64
    };

    if completed_at.is_none() {
        format!("{} (running)", format_duration(seconds))
    } else {
        format_duration(seconds)
    }
}

// ============================================================================
// Sqlx row types for history queries
// ============================================================================

#[derive(sqlx::FromRow)]
struct OperationRow {
    operation_id: String,
    target_domain: Option<String>,
    target_ip: Option<String>,
    started_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    has_domain_admin: bool,
    has_golden_ticket: bool,
    credential_count: i32,
    hash_count: i32,
    host_count: i32,
    vulnerability_count: i32,
}

#[derive(sqlx::FromRow)]
struct OperationDetailRow {
    operation_id: String,
    target_domain: Option<String>,
    target_ip: Option<String>,
    environment: Option<String>,
    started_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    has_domain_admin: bool,
    has_golden_ticket: bool,
    domain_admin_path: Option<String>,
    credential_count: i32,
    hash_count: i32,
    host_count: i32,
    vulnerability_count: i32,
}

#[derive(sqlx::FromRow)]
struct CredentialSearchRow {
    username: String,
    domain: Option<String>,
    is_admin: bool,
    source: Option<String>,
    #[allow(dead_code)]
    attack_step: Option<i32>,
    operation_id: String,
}

#[derive(sqlx::FromRow)]
struct HashSearchRow {
    username: String,
    domain: Option<String>,
    hash_type: Option<String>,
    is_cracked: Option<bool>,
    #[allow(dead_code)]
    source: Option<String>,
    operation_id: String,
}

#[derive(sqlx::FromRow)]
struct CostRow {
    operation_id: String,
    target_domain: Option<String>,
    started_at: DateTime<Utc>,
    total_input_tokens: Option<i64>,
    total_output_tokens: Option<i64>,
    total_cost: Option<f64>,
    model_usage: Option<serde_json::Value>,
}

// ============================================================================
// history mitre-coverage
// ============================================================================

async fn history_mitre_coverage(since_days: Option<i64>, json_output: bool) -> Result<()> {
    let pool = connect_postgres().await?;

    let since = since_days.map(|days| Utc::now() - chrono::Duration::days(days));

    // Query timeline events joined with operations to get MITRE techniques
    let rows: Vec<MitreCoverageRow> = if let Some(ref since_ts) = since {
        sqlx::query_as::<_, MitreCoverageRow>(
            "SELECT te.mitre_techniques, o.operation_id \
             FROM timeline_events te \
             JOIN operations o ON te.operation_id = o.id \
             WHERE te.mitre_techniques IS NOT NULL \
               AND array_length(te.mitre_techniques, 1) > 0 \
               AND o.started_at >= $1",
        )
        .bind(since_ts)
        .fetch_all(&pool)
        .await?
    } else {
        sqlx::query_as::<_, MitreCoverageRow>(
            "SELECT te.mitre_techniques, o.operation_id \
             FROM timeline_events te \
             JOIN operations o ON te.operation_id = o.id \
             WHERE te.mitre_techniques IS NOT NULL \
               AND array_length(te.mitre_techniques, 1) > 0",
        )
        .fetch_all(&pool)
        .await?
    };

    // Aggregate: technique_id -> set of operation_ids
    let mut coverage: HashMap<String, HashSet<String>> = HashMap::new();
    for row in &rows {
        for technique in &row.mitre_techniques {
            coverage
                .entry(technique.clone())
                .or_default()
                .insert(row.operation_id.clone());
        }
    }

    // Sort by occurrence count descending
    let mut sorted: Vec<(String, Vec<String>)> = coverage
        .into_iter()
        .map(|(t, ops)| {
            let mut ops_vec: Vec<String> = ops.into_iter().collect();
            ops_vec.sort();
            (t, ops_vec)
        })
        .collect();
    sorted.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));

    if json_output {
        let data: Vec<serde_json::Value> = sorted
            .iter()
            .map(|(technique, ops)| {
                serde_json::json!({
                    "technique_id": technique,
                    "occurrence_count": ops.len(),
                    "operations": ops,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    } else {
        if sorted.is_empty() {
            println!("No MITRE techniques found");
            return Ok(());
        }

        println!("\n{:<18} {:<8} OPERATIONS", "TECHNIQUE", "COUNT");
        println!("{}", "-".repeat(80));
        for (technique, ops) in &sorted {
            let ops_display = if ops.len() <= 3 {
                ops.join(", ")
            } else {
                let shown: Vec<&str> = ops.iter().take(3).map(|s| s.as_str()).collect();
                format!("{} (+{} more)", shown.join(", "), ops.len() - 3)
            };
            println!("{:<18} {:<8} {}", technique, ops.len(), ops_display);
        }
        println!("\nTotal: {} techniques", sorted.len());
    }

    Ok(())
}

#[derive(sqlx::FromRow)]
struct MitreCoverageRow {
    mitre_techniques: Vec<String>,
    operation_id: String,
}

// ============================================================================
// history cost
// ============================================================================

async fn history_cost(
    domain: Option<String>,
    since_days: Option<i64>,
    limit: i64,
    json_output: bool,
) -> Result<()> {
    let pool = connect_postgres().await?;
    let since = since_days.map(|days| Utc::now() - chrono::Duration::days(days));

    let mut query = String::from(
        "SELECT operation_id, target_domain, started_at, \
         total_input_tokens, total_output_tokens, total_cost, model_usage \
         FROM operations WHERE total_input_tokens IS NOT NULL",
    );
    let mut bind_idx = 0u32;
    let mut conditions: Vec<String> = Vec::new();

    if domain.is_some() {
        bind_idx += 1;
        conditions.push(format!(" AND target_domain ILIKE ${bind_idx}"));
    }
    if since.is_some() {
        bind_idx += 1;
        conditions.push(format!(" AND started_at >= ${bind_idx}"));
    }

    for c in &conditions {
        query.push_str(c);
    }
    bind_idx += 1;
    query.push_str(&format!(" ORDER BY started_at DESC LIMIT ${bind_idx}"));

    let mut q = sqlx::query_as::<_, CostRow>(&query);

    if let Some(ref d) = domain {
        q = q.bind(format!("%{d}%"));
    }
    if let Some(ref s) = since {
        q = q.bind(s);
    }
    q = q.bind(limit);

    let rows: Vec<CostRow> = q.fetch_all(&pool).await?;

    if json_output {
        let data: Vec<serde_json::Value> = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "operation_id": r.operation_id,
                    "target_domain": r.target_domain,
                    "started_at": r.started_at.to_rfc3339(),
                    "input_tokens": r.total_input_tokens,
                    "output_tokens": r.total_output_tokens,
                    "total_tokens": r.total_input_tokens.unwrap_or(0) + r.total_output_tokens.unwrap_or(0),
                    "cost": r.total_cost,
                    "model_usage": r.model_usage,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    } else {
        if rows.is_empty() {
            println!("No operations with token usage data found");
            return Ok(());
        }

        println!(
            "\n{:<30} {:<20} {:>12} {:>12} {:>10}",
            "OPERATION ID", "DOMAIN", "IN TOKENS", "OUT TOKENS", "COST"
        );
        println!("{}", "-".repeat(90));

        let mut grand_total_in: i64 = 0;
        let mut grand_total_out: i64 = 0;
        let mut grand_total_cost: f64 = 0.0;

        for r in &rows {
            let in_tok = r.total_input_tokens.unwrap_or(0);
            let out_tok = r.total_output_tokens.unwrap_or(0);
            let cost = r.total_cost.unwrap_or(0.0);
            grand_total_in += in_tok;
            grand_total_out += out_tok;
            grand_total_cost += cost;

            let domain_display = r
                .target_domain
                .as_deref()
                .unwrap_or("")
                .chars()
                .take(19)
                .collect::<String>();
            let cost_str = if cost > 0.0 {
                format!("${cost:.4}")
            } else {
                "-".to_string()
            };

            println!(
                "{:<30} {:<20} {:>12} {:>12} {:>10}",
                r.operation_id, domain_display, in_tok, out_tok, cost_str
            );
        }

        println!("{}", "-".repeat(90));
        let grand_cost_str = if grand_total_cost > 0.0 {
            format!("${grand_total_cost:.4}")
        } else {
            "-".to_string()
        };
        println!(
            "{:<30} {:<20} {:>12} {:>12} {:>10}",
            format!("TOTAL ({} ops)", rows.len()),
            "",
            grand_total_in,
            grand_total_out,
            grand_cost_str
        );
    }

    Ok(())
}

// ============================================================================
// ops offload-cost
// ============================================================================

async fn ops_offload_cost(
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
    let pool = connect_postgres().await?;

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
    println!(
        "Offloaded token usage for {op_id}: {total_tokens} tokens ({} in, {} out), cost: {cost_str}",
        usage.input_tokens, usage.output_tokens
    );

    Ok(())
}

// ============================================================================
// Config Command Handlers
// ============================================================================

fn resolve_config_path(explicit: Option<String>) -> Result<std::path::PathBuf> {
    if let Some(p) = explicit {
        let path = std::path::PathBuf::from(&p);
        if path.exists() {
            return Ok(path);
        }
        anyhow::bail!("Config file not found: {p}");
    }
    AresConfig::resolve_path()
}

fn run_config(cmd: ConfigCommands) -> Result<()> {
    match cmd {
        ConfigCommands::Show { models, config } => config_show(config, models),
        ConfigCommands::Validate { config } => config_validate(config),
        ConfigCommands::SetModel {
            role,
            model,
            all,
            config,
        } => config_set_model(config, role, model, all),
    }
}

fn config_show(config_path: Option<String>, models_only: bool) -> Result<()> {
    let path = resolve_config_path(config_path)?;
    let cfg = AresConfig::load(&path)?;

    if models_only {
        println!("Model assignments (from {}):", path.display());
        println!();
        let mut roles: Vec<_> = cfg.agents.iter().collect();
        roles.sort_by_key(|(k, _)| (*k).clone());
        let max_len = roles.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
        for (role, agent) in &roles {
            println!("  {:<width$}  {}", role, agent.model, width = max_len);
        }
        println!();
        return Ok(());
    }

    println!("# Resolved config: {}\n", path.display());

    // Operation
    println!("operation:");
    println!("  name: {}", cfg.operation.name);
    println!("  namespace: {}", cfg.operation.namespace);
    println!(
        "  checkpoint_interval: {}s",
        cfg.operation.checkpoint_interval
    );
    println!(
        "  max_concurrent_tasks: {}",
        cfg.operation.max_concurrent_tasks
    );
    println!(
        "  task_dispatch_delay: {}s",
        cfg.operation.task_dispatch_delay
    );
    println!(
        "  rate_limit_backoff: {}s",
        cfg.operation.rate_limit_backoff
    );
    println!(
        "  rate_limit_threshold: {}",
        cfg.operation.rate_limit_threshold
    );
    println!(
        "  stop_on_domain_admin: {}",
        cfg.operation.stop_on_domain_admin
    );
    println!(
        "  stop_on_golden_ticket: {}",
        cfg.operation.stop_on_golden_ticket
    );

    // Agents
    println!("\nagents:");
    let mut roles: Vec<_> = cfg.agents.iter().collect();
    roles.sort_by_key(|(k, _)| (*k).clone());
    for (role, agent) in &roles {
        println!("  {}:", role);
        println!("    model: {}", agent.model);
        println!("    max_steps: {}", agent.max_steps);
        if !agent.pod_selector.is_empty() {
            println!("    pod_selector: {}", agent.pod_selector);
        }
        if !agent.capabilities.is_empty() {
            println!("    capabilities: {} tools", agent.capabilities.len());
        }
        if !agent.tools.is_empty() {
            println!("    tools: {} dispatch actions", agent.tools.len());
        }
    }

    // Timeouts
    println!("\ntimeouts:");
    println!("  agent_heartbeat: {}s", cfg.timeouts.agent_heartbeat);
    println!("  task_timeout: {}s", cfg.timeouts.task_timeout);
    println!(
        "  operation_timeout: {}s ({}h)",
        cfg.timeouts.operation_timeout,
        cfg.timeouts.operation_timeout / 3600
    );
    println!("  lateral_movement: {}s", cfg.timeouts.lateral_movement);
    println!("  hash_cracking: {}s", cfg.timeouts.hash_cracking);
    println!("  exploitation: {}s", cfg.timeouts.exploitation);

    // Recovery
    println!("\nrecovery:");
    println!("  enabled: {}", cfg.recovery.enabled);
    println!("  max_retries: {}", cfg.recovery.max_retries);
    println!("  retry_delay: {}s", cfg.recovery.retry_delay);

    // Vulnerability priorities
    println!("\nvulnerability_priorities:");
    let mut vulns: Vec<_> = cfg.vulnerability_priorities.iter().collect();
    vulns.sort_by_key(|(_, v)| **v);
    for (vuln, priority) in &vulns {
        println!("  {}: {}", vuln, priority);
    }

    // Context management
    println!("\ncontext_management:");
    println!(
        "  max_context_tokens: {}",
        cfg.context_management.max_context_tokens
    );
    println!(
        "  min_messages_to_keep: {}",
        cfg.context_management.min_messages_to_keep
    );
    println!(
        "  max_output_chars: {}",
        cfg.context_management.max_output_chars
    );

    // Grafana
    if let Some(ref g) = cfg.grafana {
        println!("\ngrafana:");
        println!("  enabled: {}", g.enabled);
        println!("  dashboard_uid: {}", g.dashboard_uid);
    }

    Ok(())
}

fn config_validate(config_path: Option<String>) -> Result<()> {
    let path = resolve_config_path(config_path)?;
    let cfg = AresConfig::load(&path)?;

    let mut warnings = Vec::new();

    // Check all agents have models
    for (role, agent) in &cfg.agents {
        if agent.model.is_empty() {
            warnings.push(format!("Agent '{}' has no model set", role));
        }
    }

    // Check expected roles exist
    let expected_roles = [
        "orchestrator",
        "recon",
        "credential_access",
        "cracker",
        "acl",
        "privesc",
        "lateral",
        "coercion",
    ];
    for role in &expected_roles {
        if !cfg.agents.contains_key(*role) {
            warnings.push(format!("Expected agent role '{}' not found", role));
        }
    }

    // Check timeouts are reasonable
    if cfg.timeouts.operation_timeout < cfg.timeouts.task_timeout {
        warnings.push("operation_timeout is less than task_timeout".to_string());
    }

    if warnings.is_empty() {
        println!(
            "Config OK: {} ({}  agent roles)",
            path.display(),
            cfg.agents.len()
        );
    } else {
        println!("Config: {} ({} warnings)\n", path.display(), warnings.len());
        for w in &warnings {
            println!("  WARNING: {}", w);
        }
    }

    Ok(())
}

fn config_set_model(
    config_path: Option<String>,
    role: Option<String>,
    model: String,
    all: bool,
) -> Result<()> {
    let path = resolve_config_path(config_path)?;

    // Read the raw YAML to do text-level replacement (preserves comments and formatting).
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    // Also parse to validate and get the agent list
    let cfg = AresConfig::load(&path)?;

    if all {
        // Replace model for all agents
        let mut new_contents = contents.clone();
        for (role_name, agent) in &cfg.agents {
            new_contents = replace_model_in_yaml(&new_contents, role_name, &agent.model, &model);
        }
        std::fs::write(&path, &new_contents)
            .with_context(|| format!("Failed to write {}", path.display()))?;

        println!("Set all {} roles to model '{}'", cfg.agents.len(), model);
        return Ok(());
    }

    let role = role.context("Role argument is required when --all is not set")?;

    if !cfg.agents.contains_key(&role) {
        let available: Vec<_> = cfg.agent_roles();
        anyhow::bail!(
            "Unknown role '{}'. Available roles: {}",
            role,
            available.join(", ")
        );
    }

    let old_model = cfg.agents[&role].model.as_str();
    let new_contents = replace_model_in_yaml(&contents, &role, old_model, &model);
    std::fs::write(&path, &new_contents)
        .with_context(|| format!("Failed to write {}", path.display()))?;

    println!("{}: {} -> {}", role, old_model, model);
    Ok(())
}

/// Replace the model value for a specific role in the YAML text.
///
/// This does a targeted text replacement to preserve comments and formatting.
/// It finds the role's section under `agents:` and replaces its `model:` line.
fn replace_model_in_yaml(yaml: &str, role: &str, _old_model: &str, new_model: &str) -> String {
    // Strategy: find `  {role}:\n` then the next `    model: "{old}"` line
    let role_header = format!("  {}:", role);
    let mut result = String::with_capacity(yaml.len());
    let lines = yaml.lines().peekable();
    let mut in_target_role = false;
    let mut replaced = false;

    for line in lines {
        if line.starts_with(&role_header)
            && (line.len() == role_header.len()
                || line[role_header.len()..].starts_with(' ')
                || line[role_header.len()..].starts_with('\n'))
        {
            in_target_role = true;
            result.push_str(line);
            result.push('\n');
            continue;
        }

        if in_target_role && !replaced {
            let trimmed = line.trim();
            if trimmed.starts_with("model:") {
                // Replace the model value, preserving indentation
                let indent = &line[..line.len() - line.trim_start().len()];
                let new_line = format!("{}model: \"{}\"", indent, new_model);
                result.push_str(&new_line);
                result.push('\n');
                replaced = true;
                in_target_role = false;
                continue;
            }
        }

        // If we hit a new role (non-indented or less-indented), we left the target
        if in_target_role && !line.starts_with("    ") && !line.is_empty() && !line.starts_with('#')
        {
            in_target_role = false;
        }

        result.push_str(line);
        result.push('\n');
    }

    // Remove trailing extra newline if original didn't have one
    if !yaml.ends_with('\n') && result.ends_with('\n') {
        result.pop();
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_operation_timestamp_valid() {
        let ts = parse_operation_timestamp("op-20250128-123456").unwrap();
        assert_eq!(
            ts.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2025-01-28 12:34:56"
        );
    }

    #[test]
    fn test_parse_operation_timestamp_invalid() {
        assert!(parse_operation_timestamp("not-an-op-id").is_none());
        assert!(parse_operation_timestamp("op-bad").is_none());
        assert!(parse_operation_timestamp("").is_none());
    }

    #[test]
    fn test_parse_operation_timestamp_with_suffix() {
        // Some IDs may have extra suffix after the timestamp
        let ts = parse_operation_timestamp("op-20260407-091000-abc123").unwrap();
        assert_eq!(
            ts.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2026-04-07 09:10:00"
        );
    }
}
