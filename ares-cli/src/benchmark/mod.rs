//! Benchmark replay system for deterministic blue team evaluation.
//!
//! Subcommands:
//! - `capture`: snapshot a completed operation's Loki state + red team data
//! - `load`: import a snapshot into a target Loki instance
//! - `run`: run a blue investigation against an already-provisioned replay
//!   stack (provisioning + teardown live in `.taskfiles/benchmark/`)
//! - `list`: list available snapshots from the benchmark S3 bucket

mod capture;
pub(crate) mod manifest;
mod replay;
pub(crate) mod snapshot_s3;
mod tempo_push;
pub(crate) mod versions;

use anyhow::Result;

use crate::cli::BenchmarkCommands;

pub(crate) async fn run_benchmark(cmd: BenchmarkCommands, redis_url: Option<String>) -> Result<()> {
    match cmd {
        BenchmarkCommands::Capture {
            operation_id,
            latest,
            output_dir,
            pre_window_hours,
            post_window_minutes,
            no_upload,
            attacker_ips,
            no_wait_for_flush,
            flush_timeout_mins,
        } => {
            capture::run_capture(
                redis_url,
                operation_id,
                latest,
                &output_dir,
                pre_window_hours,
                post_window_minutes,
                no_upload,
                attacker_ips,
                !no_wait_for_flush,
                flush_timeout_mins,
            )
            .await
        }
        BenchmarkCommands::Load {
            snapshot_dir,
            loki_url,
            loki_token,
        } => replay::run_load(&snapshot_dir, &loki_url, loki_token.as_deref()).await,
        BenchmarkCommands::Run {
            snapshot,
            snapshot_dir,
            replay_mode,
            trigger_mode,
            output_dir,
            model,
            max_steps,
            quiet_period,
            clock,
            stack_ip,
            seed,
            temperature,
            replicates,
        } => {
            replay::run_replay(replay::ReplayParams {
                redis_url,
                snapshot,
                snapshot_dir,
                replay_mode,
                trigger_mode,
                output_dir,
                model,
                max_steps,
                quiet_period,
                clock_mode: clock,
                stack_ip,
                seed,
                temperature,
                replicates,
            })
            .await
        }
        BenchmarkCommands::List => run_list(),
    }
}

/// List available benchmark snapshots from S3.
fn run_list() -> Result<()> {
    let config = snapshot_s3::SnapshotConfig::from_env()?;
    let snapshots =
        snapshot_s3::list_snapshots(&config.aws_profile, &config.aws_region, &config.s3_bucket)?;

    if snapshots.is_empty() {
        println!("No snapshots found in s3://{}/snapshots/", config.s3_bucket);
        return Ok(());
    }

    println!(
        "{:<25} {:<20} {:<12} {:<6} {:<5} {:<6}",
        "SNAPSHOT", "TARGET", "DATE", "TECHS", "DA", "CREDS"
    );
    println!("{}", "-".repeat(78));

    for (op_id, m) in &snapshots {
        let date = m.captured_at.format("%Y-%m-%d").to_string();
        let da = if m.has_domain_admin { "yes" } else { "no" };
        println!(
            "{:<25} {:<20} {:<12} {:<6} {:<5} {:<6}",
            op_id,
            truncate(&m.target_domain, 18),
            date,
            m.techniques.len(),
            da,
            m.credential_count,
        );
    }

    println!("\n{} snapshot(s) available", snapshots.len());
    Ok(())
}

/// Truncate a string with ellipsis if longer than max.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}
