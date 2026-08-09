//! Benchmark replay: provision EC2 Loki, run blue team investigations, score.
//!
//! - `load`: import a snapshot's JSONL streams into a target Loki instance
//! - `run`: full pipeline (EC2 Loki → investigate → score → teardown)

use std::fs;
#[allow(unused_imports)]
use std::io::BufReader;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::Utc;
use redis::AsyncCommands;
use tracing::{info, warn};

use ares_core::eval::gap_analysis::analyze_detection_gaps;
use ares_core::eval::ground_truth::{create_ground_truth_from_red_state, EvaluationGroundTruth};
use ares_core::eval::scorers::{self, InvestigationSnapshot};
use ares_core::eval::workflow::load_red_state_from_file;
use ares_core::nats::NatsBroker;
use ares_core::state::blue_task_queue::BlueTaskQueue;
use ares_core::state::BlueStateReader;
use ares_tools::blue::loki_bulk::{self, BulkLokiConfig};

use crate::ops::submit::{collect_env_vars, resolve_model, BLUE_ENV_VAR_NAMES};
use crate::redis_conn::connect_redis;

use super::manifest::{BenchmarkResult, FiredAlert, SnapshotManifest};
use super::snapshot_s3::SnapshotConfig;

/// Parameters for the `benchmark run` command.
pub(crate) struct ReplayParams {
    pub redis_url: Option<String>,
    pub snapshot: String,
    pub snapshot_dir: Option<String>,
    pub replay_mode: String,
    pub trigger_mode: String,
    pub output_dir: String,
    pub model: Option<String>,
    pub max_steps: u32,
    pub quiet_period: Option<f64>,
    /// Timeline clock advance mode: "step" (default) or "wallclock".
    pub clock_mode: String,
    /// Private IP of an already-provisioned replay stack. The stack is stood
    /// up by `task benchmark:replay:provision`; `benchmark run` only runs the
    /// investigation against it.
    pub stack_ip: String,
    /// Optional LLM sampling seed (OpenAI-only; other providers log-and-continue).
    pub seed: Option<u64>,
    /// Optional LLM sampling temperature override (0.0 = greedy).
    pub temperature: Option<f32>,
    /// Replicate count. K > 1 reruns the same investigation K times against the
    /// same stack and reports mean/stddev/min/max so a tuning loop can
    /// distinguish real deltas from LLM sampling noise.
    pub replicates: u32,
}

/// Import a snapshot's Loki data into a target Loki instance.
///
/// For `s3-chunks` snapshots, copies the chunk/index data into Loki's
/// filesystem storage directory. For legacy `api-export` snapshots,
/// pushes JSONL streams via the Loki push API.
pub(crate) async fn run_load(
    snapshot_dir: &str,
    loki_url: &str,
    loki_token: Option<&str>,
) -> Result<()> {
    let manifest = load_manifest(snapshot_dir)?;

    if manifest.loki_source == "s3-chunks" {
        println!("Snapshot uses S3-chunks Loki data.");
        println!("  Chunks:  {}", manifest.loki_chunks);
        println!("  Index:   {}", manifest.loki_index_files);
        println!();
        println!("To use this data, configure Loki with filesystem storage");
        println!("pointing at: {}/loki/", snapshot_dir);
        println!("  chunks: {}/loki/fake/", snapshot_dir);
        println!("  index:  {}/loki/index/", snapshot_dir);
        return Ok(());
    }

    // Legacy api-export path (JSONL import via push API)
    let config = BulkLokiConfig {
        base_url: loki_url.trim_end_matches('/').to_string(),
        auth_token: loki_token.map(String::from),
    };

    let import_start = std::time::Instant::now();
    let total = import_all_streams(snapshot_dir, &manifest, &config).await?;
    let duration = import_start.elapsed();

    println!("Import complete");
    println!("  Entries:  {total}");
    println!("  Duration: {:.1}s", duration.as_secs_f64());

    Ok(())
}

/// Run a blue investigation against an already-provisioned replay stack.
///
/// The stack is stood up by `task benchmark:replay:provision` (or the caller
/// running the equivalent AWS-CLI commands) and its private IP is passed as
/// `--stack-ip`. This function submits the investigation to NATS, polls
/// Redis for completion, and computes the score — no provisioning, no
/// teardown.
///
/// Replay modes:
/// - `static`: all data pre-loaded, agent knows full attack window (operation trigger)
/// - `timeline`: quiet period before first alert, alert-replay trigger (no end window),
///   simulating an unfolding attack
pub(crate) async fn run_replay(p: ReplayParams) -> Result<()> {
    let session_started_at = Utc::now();
    let session_stem = format!("inv-{}", session_started_at.format("%Y%m%d-%H%M%S"));
    let is_timeline = p.replay_mode == "timeline";
    let replicates = p.replicates.max(1);

    if !matches!(p.replay_mode.as_str(), "static" | "timeline") {
        bail!(
            "unknown replay-mode: {} (expected: static, timeline)",
            p.replay_mode
        );
    }

    apply_sampling_env(p.seed, p.temperature, p.model.as_deref());

    // Point the blue agent's observability surface at the caller-supplied
    // stack and pull LLM keys from Secrets Manager if they're missing (e.g.
    // when `benchmark run` runs on an EC2 box that doesn't have `op`).
    // SAFETY: single-threaded — tokio hasn't spawned anything yet.
    let loki_url = format!("http://{}:3100", p.stack_ip);
    let grafana_url = format!("http://{}:3000", p.stack_ip);
    let prometheus_url = format!("http://{}:9090", p.stack_ip);
    let tempo_url = format!("http://{}:3200", p.stack_ip);
    // Capture the blue investigation transcript (every LLM message + tool call)
    // the same way red ops are — into the analytical DB's session-log root so the
    // ingester picks it up. Tag it team=blue and file it under the *replayed*
    // op_id (ARES_SESSION_OP_ID overrides the log path without triggering
    // red-state correlation). The blue agents' task_id is the run_id, so repeated
    // runs land in distinct files — /var/log/ares/session/<op_id>/<run_id>.jsonl —
    // joinable to red on op_id and separable per-run by task_id/run_id.
    let session_dir = std::env::var("ARES_SESSION_LOG_DIR")
        .unwrap_or_else(|_| "/var/log/ares/session".to_string());
    let _ = std::fs::create_dir_all(&session_dir);
    unsafe {
        std::env::set_var("LOKI_URL", &loki_url);
        std::env::set_var("GRAFANA_URL", &grafana_url);
        std::env::set_var("PROMETHEUS_URL", &prometheus_url);
        std::env::set_var("TEMPO_URL", &tempo_url);
        std::env::set_var("ARES_SESSION_LOG_DIR", &session_dir);
        std::env::set_var("ARES_SESSION_TEAM", "blue");
        // ARES_SESSION_OP_ID (= the replayed op) is set in run_replay_inner where
        // the manifest is in scope, before the blue config is built.
    }
    info!(
        "blue investigation transcripts → {session_dir}/<op>/{session_stem}[-r*].jsonl (team=blue → SQL)"
    );
    ensure_llm_secrets();

    let snapshot_config = SnapshotConfig::from_env();
    let (snapshot_path, _is_temp) =
        resolve_snapshot(&p.snapshot, p.snapshot_dir.as_deref(), &snapshot_config)?;

    let manifest = load_manifest(snapshot_path.to_str().unwrap())?;

    info!(
        "benchmark run {session_stem} [mode={}, trigger={}, replicates={}] for operation {} against stack {}",
        p.replay_mode,
        if is_timeline {
            "alert-replay"
        } else {
            &p.trigger_mode
        },
        replicates,
        manifest.operation_id,
        p.stack_ip,
    );

    // Push captured Tempo traces into the ephemeral stack so the demo
    // dashboard's attack-graph panel renders on this replay. Best-effort:
    // a snapshot captured before D1 landed carries no bundle and this is
    // an Ok(0) no-op; a live-Tempo failure is logged but does not abort
    // the investigation.
    if manifest.tempo_traces_captured > 0 {
        let otlp_url = super::tempo_push::otlp_url_for_stack(&p.stack_ip);
        match super::tempo_push::push_traces_bundle(&snapshot_path, &otlp_url, None).await {
            Ok(n) => info!(
                pushed = n,
                expected = manifest.tempo_traces_captured,
                url = %otlp_url,
                "pushed captured Tempo traces to replay stack"
            ),
            Err(e) => {
                tracing::warn!(err = %e, "Tempo trace push failed — attack-graph panel will be empty")
            }
        }
    }

    run_replay_inner(
        &p,
        &manifest,
        &loki_url,
        &snapshot_path,
        &session_stem,
        is_timeline,
        session_started_at,
        replicates,
    )
    .await
}

/// Apply the `--seed` / `--temperature` knobs by setting the env vars the
/// agent loop reads at request-build time (`ARES_LLM_SEED`, `ARES_LLM_TEMPERATURE`).
///
/// When `--seed` is set without `--temperature`, temperature is forced to
/// `0.0` because seeded sampling only meaningfully constrains variance at
/// low temperature. Explicit `--temperature` always wins.
///
/// Providers that don't honour `seed` (Anthropic, Ollama today) log a
/// warning and continue — the request-level field is silently dropped.
///
/// SAFETY: called from `run_replay` before any worker tasks are spawned;
/// no other thread can be reading these env vars concurrently.
fn apply_sampling_env(seed: Option<u64>, temperature: Option<f32>, model: Option<&str>) {
    if seed.is_none() && temperature.is_none() {
        return;
    }
    if let Some(t) = temperature {
        unsafe { std::env::set_var("ARES_LLM_TEMPERATURE", format!("{t}")) };
        info!("blue sampling: ARES_LLM_TEMPERATURE={t}");
    } else if seed.is_some() {
        unsafe { std::env::set_var("ARES_LLM_TEMPERATURE", "0") };
        info!("blue sampling: ARES_LLM_TEMPERATURE=0 (implied by --seed)");
    }
    if let Some(s) = seed {
        unsafe { std::env::set_var("ARES_LLM_SEED", s.to_string()) };
        info!("blue sampling: ARES_LLM_SEED={s}");
        if !provider_supports_seed(model) {
            warn!(
                "provider derived from model={:?} does not support LLM seed; \
                 request-level seed will be dropped and outputs will still vary \
                 across replicates",
                model.unwrap_or("<default>"),
            );
        }
    }
}

/// Return true when the resolved model routes to a provider that honours
/// `LlmRequest.seed`. Today that's OpenAI only. Unknown / unset models
/// (falling back to the config-YAML default) are treated as supporting seed
/// — the default blue model is OpenAI, and being wrong here just means an
/// occasional false-negative warning.
fn provider_supports_seed(model: Option<&str>) -> bool {
    let Some(m) = model else { return true };
    if m.starts_with("openai/") {
        return true;
    }
    // Bare model names without a provider prefix follow ares_llm::create_provider's
    // resolution rules; we can't tell without invoking it. Warn only for the
    // prefixes we know skip seed (anthropic, claude-cli, ollama).
    !(m.starts_with("anthropic/") || m.starts_with("claude-cli/") || m.starts_with("ollama/"))
}

/// Ensure LLM API keys are in the environment. Delegates to the shared
/// Secrets Manager loader in `secrets.rs` for the "re-exec'd onto an EC2 box"
/// case, where `op` is unavailable but instance credentials are — no-op when
/// the keys are already set. Region resolution favors `BENCHMARK_AWS_REGION`
/// so the fetch lands in the same account as the replay stack.
fn ensure_llm_secrets() {
    if std::env::var("OPENAI_API_KEY").is_ok() && std::env::var("ANTHROPIC_API_KEY").is_ok() {
        return;
    }
    let secret_id = std::env::var("ARES_SECRETS_ID").ok();
    let region = std::env::var("BENCHMARK_AWS_REGION").ok();
    match crate::secrets::load_secrets_manager_secrets(secret_id.as_deref(), region.as_deref()) {
        Ok(n) if n > 0 => info!("LLM keys loaded from Secrets Manager ({n})"),
        Ok(_) => {}
        Err(e) => eprintln!("WARNING: could not fetch LLM keys from Secrets Manager: {e:#}; the investigation may fail to start"),
    }
}

/// Inner replay logic, separated so teardown always runs.
#[allow(clippy::too_many_arguments)]
async fn run_replay_inner(
    p: &ReplayParams,
    manifest: &SnapshotManifest,
    loki_url: &str,
    snapshot_path: &Path,
    session_stem: &str,
    is_timeline: bool,
    session_started_at: chrono::DateTime<Utc>,
    replicates: u32,
) -> Result<()> {
    // SAFETY: this is the documented mechanism for pointing the blue agent
    // at a specific Loki. The env var is read by loki_config() in loki.rs.
    unsafe {
        std::env::set_var("LOKI_URL", loki_url);
    }

    let quiet_period_secs = if is_timeline {
        let secs = p
            .quiet_period
            .unwrap_or_else(|| rand::random_range(60.0..=300.0));
        if secs > 0.0 {
            info!("timeline mode: quiet period {secs:.0}s before first alert");
            tokio::time::sleep(std::time::Duration::from_secs_f64(secs)).await;
        }
        Some(secs)
    } else {
        None
    };

    // Timeline mode always uses alert-replay (no attack_window_end).
    let snapshot_dir_str = snapshot_path.to_str().unwrap();
    let effective_trigger_mode = if is_timeline {
        "alert-replay"
    } else {
        &p.trigger_mode
    };

    let alert_json = match effective_trigger_mode {
        "alert-replay" => build_alert_replay_trigger(snapshot_dir_str, manifest)?,
        "operation" => build_operation_trigger(snapshot_dir_str, manifest)?,
        other => bail!("unknown trigger-mode: {other} (expected: alert-replay, operation)"),
    };

    info!("trigger built (mode={effective_trigger_mode})");

    // Anchor the replay clock at the trigger time so the blue agent's
    // "recent"/relative-window queries and the initial-alert prompt land on the
    // captured attack instead of wall-clock now (read via ARES_REPLAY_CLOCK_START
    // by ares-tools::blue::replay_clock and the prompt builder).
    // SAFETY: single-threaded replay setup, before the investigation runs.
    if let Some(anchor) = alert_json
        .get("startsAt")
        .and_then(|v| v.as_str())
        .or_else(|| {
            alert_json
                .pointer("/operation_context/attack_window_start")
                .and_then(|v| v.as_str())
        })
    {
        unsafe {
            std::env::set_var("ARES_REPLAY_CLOCK_START", anchor);
        }
    }

    // Configure the replay clock so the world unfolds correctly: `static` holds
    // the whole concluded attack (frozen at attack end, everything visible);
    // timeline advances (step-based by default) and the query tools clamp
    // visibility to the clock. Set before collect_env_vars so these propagate to
    // the in-process blue consumer.
    unsafe {
        std::env::set_var("ARES_REPLAY_CLOCK_END", manifest.completed_at.to_rfc3339());
        std::env::set_var("ARES_REPLAY_MAX_STEPS", p.max_steps.to_string());
        std::env::set_var(
            "ARES_REPLAY_CLOCK_MODE",
            if is_timeline {
                p.clock_mode.as_str()
            } else {
                "static"
            },
        );
        // File the blue transcript under the replayed op (team=blue) so it joins
        // to red on op_id in the analytical DB. Overrides the SessionLog op_id
        // without touching investigation.operation_id (avoids red-state leak).
        std::env::set_var("ARES_SESSION_OP_ID", &manifest.operation_id);
    }

    let effective_model = resolve_model(&p.model);
    let mut env_vars = collect_env_vars(BLUE_ENV_VAR_NAMES);
    env_vars.insert("LOKI_URL".to_string(), loki_url.to_string());

    let nats = NatsBroker::connect_from_env()
        .await
        .context("connect to NATS for investigation submission")?;
    nats.ensure_streams().await?;

    // Spawn an ephemeral in-process blue consumer ONCE for the entire session —
    // even when K > 1, all replicates share the same consumer since NATS
    // multiplexes their investigation-submissions across a single subscriber.
    // It dies with the process and uses the isolated ARES_BLUE_TASKS stream,
    // so it never interferes with a red fleet.
    let redis_url_str = p.redis_url.clone().unwrap_or_else(|| {
        std::env::var("ARES_REDIS_URL")
            .or_else(|_| std::env::var("REDIS_URL"))
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string())
    });
    let nats_url_str = NatsBroker::url_from_env();
    let consumer_model = effective_model
        .clone()
        .or_else(|| std::env::var("ARES_BLUE_LLM_MODEL").ok())
        .or_else(|| std::env::var("ARES_LLM_MODEL").ok())
        .unwrap_or_else(|| "openai/gpt-5.2".to_string());
    let (blue_handle, blue_shutdown) = crate::orchestrator::spawn_inprocess_blue_consumer(
        &consumer_model,
        &redis_url_str,
        &nats_url_str,
    )
    .await
    .context("spawn in-process blue consumer")?;

    fs::create_dir_all(&p.output_dir)
        .with_context(|| format!("create output dir: {}", p.output_dir))?;

    let ctx = ReplicateContext {
        p,
        manifest,
        snapshot_path,
        effective_trigger_mode,
        effective_model: effective_model.as_deref(),
        alert_json: &alert_json,
        env_vars: &env_vars,
        nats: &nats,
        session_started_at,
        quiet_period_secs,
    };

    let mut replicate_scores: Vec<f64> = Vec::with_capacity(replicates as usize);
    let mut replicate_summaries: Vec<ReplicateSummary> = Vec::with_capacity(replicates as usize);
    let run_result: Result<()> = async {
        for i in 0..replicates {
            let run_id = if replicates == 1 {
                session_stem.to_string()
            } else {
                format!("{session_stem}-r{i}")
            };
            info!("replicate {}/{} → run_id={run_id}", i + 1, replicates);
            let outcome = run_single_replicate(&ctx, &run_id).await?;
            replicate_scores.push(outcome.overall_score);
            replicate_summaries.push(ReplicateSummary {
                run_id: run_id.clone(),
                overall_score: outcome.overall_score,
                technique_coverage: outcome.technique_coverage,
                ioc_detection_rate: outcome.ioc_detection_rate,
                grade: outcome.grade,
                passed: outcome.passed,
                investigation_duration_secs: outcome.investigation_duration_secs,
                result_path: outcome.result_path,
            });
        }
        Ok(())
    }
    .await;

    // Always tear down the in-process blue consumer — bail path or clean finish.
    let _ = blue_shutdown.send(true);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(30), blue_handle).await;

    run_result?;

    // Guard: `operation` trigger hands the agent the ground-truth techniques and
    // IOCs it is graded on (see build_operation_trigger). It's an oracle/debug
    // mode, never a valid score — flag it loudly so nobody reports it.
    if effective_trigger_mode == "operation" {
        eprintln!(
            "\n⚠️  trigger-mode=operation hands the agent the ground-truth techniques and \
             IOCs it is graded on — this score is CONTAMINATED and must NOT be used for \
             comparison. Use the default (alert-replay) for real scoring.\n"
        );
    }

    if replicates > 1 {
        write_and_print_replicate_summary(
            &p.output_dir,
            session_stem,
            &manifest.operation_id,
            &effective_model,
            session_started_at,
            &replicate_summaries,
            &replicate_scores,
        )?;
    }

    Ok(())
}

/// Immutable state shared across every replicate in one `benchmark run`.
struct ReplicateContext<'a> {
    p: &'a ReplayParams,
    manifest: &'a SnapshotManifest,
    snapshot_path: &'a Path,
    effective_trigger_mode: &'a str,
    effective_model: Option<&'a str>,
    alert_json: &'a serde_json::Value,
    env_vars: &'a std::collections::HashMap<String, String>,
    nats: &'a NatsBroker,
    session_started_at: chrono::DateTime<Utc>,
    quiet_period_secs: Option<f64>,
}

/// Summary of one replicate used to build the K-replicate aggregate report.
struct ReplicateOutcome {
    overall_score: f64,
    technique_coverage: f64,
    ioc_detection_rate: f64,
    grade: String,
    passed: bool,
    investigation_duration_secs: f64,
    result_path: PathBuf,
}

/// Per-replicate line written into the aggregate summary JSON.
#[derive(serde::Serialize)]
struct ReplicateSummary {
    run_id: String,
    overall_score: f64,
    technique_coverage: f64,
    ioc_detection_rate: f64,
    grade: String,
    passed: bool,
    investigation_duration_secs: f64,
    result_path: PathBuf,
}

/// Submit one investigation, poll for completion, score it, write the
/// per-run JSON, and print the standard summary block. Returns the numeric
/// scores + path used to build the aggregate report.
async fn run_single_replicate(
    ctx: &ReplicateContext<'_>,
    run_id: &str,
) -> Result<ReplicateOutcome> {
    let started_at = Utc::now();
    let mut conn = connect_redis(ctx.p.redis_url.clone()).await?;

    let request = serde_json::json!({
        "investigation_id": run_id,
        "alert": ctx.alert_json,
        "correlation_context": null,
        "model": ctx.effective_model,
        "max_steps": ctx.p.max_steps,
        "multi_agent": true,
        "auto_route": false,
        "report_dir": null,
        "submitted_at": Utc::now().to_rfc3339(),
    });

    if !ctx.env_vars.is_empty() {
        let env_key = format!("ares:blue:inv:{run_id}:env_vars");
        let env_json = serde_json::to_string(ctx.env_vars)?;
        let _: () = conn.set(&env_key, &env_json).await?;
        let _: () = conn.expire(&env_key, 3600).await?;
    }

    BlueTaskQueue::submit_investigation_request(ctx.nats, &request)
        .await
        .context("submit investigation request to NATS")?;

    info!("investigation {run_id} submitted");

    let investigation_start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(45 * 60);
    let poll_interval = std::time::Duration::from_secs(10);

    loop {
        if investigation_start.elapsed() > timeout {
            bail!("investigation {run_id} timed out after 45 minutes");
        }

        let status_key = format!("ares:blue:inv:{run_id}:status");
        let status_raw: Option<String> = conn.get(&status_key).await?;

        if let Some(raw) = status_raw {
            if let Ok(status) = serde_json::from_str::<serde_json::Value>(&raw) {
                let state = status
                    .get("status")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown");

                match state {
                    "completed" | "escalated" => {
                        info!("investigation {run_id} completed (status={state})");
                        break;
                    }
                    "failed" => {
                        let err = status
                            .get("error")
                            .and_then(|e| e.as_str())
                            .unwrap_or("unknown error");
                        bail!("investigation {run_id} failed: {err}");
                    }
                    _ => {}
                }
            }
        }

        tokio::time::sleep(poll_interval).await;
    }

    let investigation_duration = investigation_start.elapsed().as_secs_f64();

    let red_state_path = ctx.snapshot_path.join("red-state.json");
    let (red_state, techniques) = load_red_state_from_file(&red_state_path)?;
    // Prefer the ENRICHED ground-truth.json written at capture time (attack
    // timeline + attacker-source IPs); the scorer used to regenerate a stripped
    // GT from red-state and ignore this file (#89 gap). Fall back to regeneration
    // only for older snapshots that predate the enrichment.
    let ground_truth = load_enriched_ground_truth(ctx.snapshot_path)
        .unwrap_or_else(|| create_ground_truth_from_red_state(&red_state, &techniques));

    let blue_reader = BlueStateReader::new(run_id.to_string());
    let blue_state = blue_reader
        .load_state(&mut conn)
        .await?
        .with_context(|| format!("no blue team state found for {run_id}"))?;

    let snap = InvestigationSnapshot::from_blue_state(&blue_state);
    let model_name = ctx.effective_model.unwrap_or("default");

    let eval_result = scorers::evaluate(
        &format!("bench-{run_id}"),
        &snap,
        &ground_truth,
        true,
        model_name,
        investigation_duration,
    );
    let gap_analysis = analyze_detection_gaps(&eval_result);

    let trigger_alert = match ctx.effective_trigger_mode {
        "alert-replay" => ctx
            .alert_json
            .get("labels")
            .and_then(|l| l.get("alertname"))
            .and_then(|n| n.as_str())
            .map(String::from),
        _ => None,
    };

    let result = BenchmarkResult {
        snapshot_id: ctx.manifest.operation_id.clone(),
        operation_id: ctx.manifest.operation_id.clone(),
        run_id: run_id.to_string(),
        replay_mode: ctx.p.replay_mode.clone(),
        trigger_mode: ctx.effective_trigger_mode.to_string(),
        trigger_alert,
        loki_mode: "ec2".to_string(),
        model: model_name.to_string(),
        started_at,
        completed_at: Utc::now(),
        quiet_period_secs: if ctx.session_started_at == started_at {
            ctx.quiet_period_secs
        } else {
            // Subsequent replicates skipped the quiet-period sleep — record
            // that explicitly rather than lying about the wait time.
            None
        },
        time_compression: None,
        investigation_duration_secs: investigation_duration,
        evaluation: eval_result.to_value(),
        gap_analysis: gap_analysis.to_markdown(),
    };

    let result_path = Path::new(&ctx.p.output_dir).join(format!("{run_id}.json"));
    fs::write(&result_path, serde_json::to_string_pretty(&result)?)
        .with_context(|| format!("write result: {}", result_path.display()))?;

    println!("Benchmark complete: {}", result_path.display());
    println!("  Run ID:         {run_id}");
    if ctx.effective_trigger_mode == "operation" {
        println!("  ⚠ SCORE INVALID: trigger=operation leaked ground truth (oracle mode).");
    }
    println!(
        "  Transcript:     {}/{}/{run_id}.jsonl  (team=blue → SQL)",
        std::env::var("ARES_SESSION_LOG_DIR")
            .unwrap_or_else(|_| "/var/log/ares/session".to_string()),
        ctx.manifest.operation_id
    );
    println!("  Mode:           {}", ctx.p.replay_mode);
    println!("  Operation:      {}", ctx.manifest.operation_id);
    if let Some(qp) = result.quiet_period_secs {
        println!("  Quiet period:   {qp:.0}s");
    }
    println!("  Grade:          {}", eval_result.grade());
    println!(
        "  Overall score:  {:.1}%",
        eval_result.overall_score * 100.0
    );
    println!(
        "  Technique coverage: {:.1}%",
        eval_result.technique_coverage * 100.0
    );
    println!(
        "  IOC detection:  {:.1}%",
        eval_result.ioc_detection_rate * 100.0
    );
    println!("  Investigation:  {investigation_duration:.1}s");
    println!("  Pass:           {}", eval_result.passed());

    Ok(ReplicateOutcome {
        overall_score: eval_result.overall_score,
        technique_coverage: eval_result.technique_coverage,
        ioc_detection_rate: eval_result.ioc_detection_rate,
        grade: eval_result.grade().to_string(),
        passed: eval_result.passed(),
        investigation_duration_secs: investigation_duration,
        result_path,
    })
}

/// Write the K-replicate aggregate summary JSON and print the noise-floor
/// stats to stdout.
#[allow(clippy::too_many_arguments)]
fn write_and_print_replicate_summary(
    output_dir: &str,
    session_stem: &str,
    operation_id: &str,
    effective_model: &Option<String>,
    session_started_at: chrono::DateTime<Utc>,
    replicates: &[ReplicateSummary],
    scores: &[f64],
) -> Result<()> {
    let stats = ScoreStats::from(scores);
    let summary_path = Path::new(output_dir).join(format!("{session_stem}-summary.json"));
    let payload = serde_json::json!({
        "session_id": session_stem,
        "operation_id": operation_id,
        "model": effective_model.as_deref().unwrap_or("default"),
        "started_at": session_started_at.to_rfc3339(),
        "completed_at": Utc::now().to_rfc3339(),
        "replicate_count": replicates.len(),
        "mean": stats.mean,
        "stddev": stats.stddev,
        "min": stats.min,
        "max": stats.max,
        "scores": scores,
        "replicates": replicates,
    });
    fs::write(&summary_path, serde_json::to_string_pretty(&payload)?)
        .with_context(|| format!("write summary: {}", summary_path.display()))?;

    println!("\nReplicate summary: {}", summary_path.display());
    println!("  Replicates:     {}", replicates.len());
    println!("  Mean score:     {:.1}%", stats.mean * 100.0);
    println!("  Stddev:         {:.1}%", stats.stddev * 100.0);
    println!("  Min:            {:.1}%", stats.min * 100.0);
    println!("  Max:            {:.1}%", stats.max * 100.0);
    Ok(())
}

/// Sample mean, sample stddev (n-1 denominator), min, and max of a slice
/// of scores. Empty input → all zeros; a single sample has undefined
/// stddev under the n-1 rule, so we report 0.0 there.
struct ScoreStats {
    mean: f64,
    stddev: f64,
    min: f64,
    max: f64,
}

impl ScoreStats {
    fn from(scores: &[f64]) -> Self {
        if scores.is_empty() {
            return Self {
                mean: 0.0,
                stddev: 0.0,
                min: 0.0,
                max: 0.0,
            };
        }
        let n = scores.len() as f64;
        let mean = scores.iter().sum::<f64>() / n;
        let stddev = if scores.len() < 2 {
            0.0
        } else {
            let var = scores.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / (n - 1.0);
            var.sqrt()
        };
        let min = scores.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = scores.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        Self {
            mean,
            stddev,
            min,
            max,
        }
    }
}

/// Load the enriched ground truth (attack timeline + attacker-source IPs) written
/// at capture time. Returns None (→ caller regenerates from red-state) when the
/// file is absent (legacy snapshots) or unparsable.
fn load_enriched_ground_truth(snapshot_path: &Path) -> Option<EvaluationGroundTruth> {
    let path = snapshot_path.join("ground-truth.json");
    let raw = std::fs::read_to_string(&path).ok()?;
    match serde_json::from_str::<EvaluationGroundTruth>(&raw) {
        Ok(gt) => {
            info!(
                "scoring against enriched ground-truth.json ({} timeline events, {} IOCs)",
                gt.expected_timeline.len(),
                gt.expected_iocs.len()
            );
            Some(gt)
        }
        Err(e) => {
            warn!("ground-truth.json present but unparsable ({e}); regenerating from red-state");
            None
        }
    }
}

/// Resolve snapshot location: use local dir override if provided, otherwise
/// download metadata from S3.
fn resolve_snapshot(
    snapshot_id: &str,
    snapshot_dir_override: Option<&str>,
    config: &SnapshotConfig,
) -> Result<(PathBuf, bool)> {
    if let Some(dir) = snapshot_dir_override {
        info!("using local snapshot directory: {dir}");
        return Ok((PathBuf::from(dir), false));
    }

    // Download metadata from S3 to a temp directory
    let tmp_dir = PathBuf::from(format!("/tmp/ares-benchmark-{snapshot_id}"));
    info!("downloading snapshot metadata from S3 for {snapshot_id}...");
    super::snapshot_s3::download_snapshot_metadata(
        snapshot_id,
        &config.aws_profile,
        &config.aws_region,
        &config.s3_bucket,
        &tmp_dir,
    )?;

    Ok((tmp_dir, true))
}

/// Load and validate the snapshot manifest.
fn load_manifest(snapshot_dir: &str) -> Result<SnapshotManifest> {
    let manifest_path = Path::new(snapshot_dir).join("manifest.json");
    let raw = fs::read_to_string(&manifest_path)
        .with_context(|| format!("read {}", manifest_path.display()))?;
    let manifest: SnapshotManifest = serde_json::from_str(&raw).context("parse manifest.json")?;
    info!(
        "loaded manifest: op={}, loki_source={}, chunks={}, alerts={}",
        manifest.operation_id, manifest.loki_source, manifest.loki_chunks, manifest.alerts_captured,
    );
    Ok(manifest)
}

/// Import all JSONL streams from a legacy snapshot into Loki.
///
/// Scans the `loki/` subdirectory for `.jsonl` files and pushes each
/// into Loki via the push API.
async fn import_all_streams(
    snapshot_dir: &str,
    _manifest: &SnapshotManifest,
    config: &BulkLokiConfig,
) -> Result<u64> {
    let loki_dir = Path::new(snapshot_dir).join("loki");
    let mut total: u64 = 0;

    if !loki_dir.exists() {
        info!("no loki/ directory in snapshot — nothing to import");
        return Ok(0);
    }

    for entry in fs::read_dir(&loki_dir)?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }

        let file = fs::File::open(&path).with_context(|| format!("open {}", path.display()))?;
        let reader = BufReader::new(file);
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");

        info!("importing stream {name} from {}", path.display());
        let entries = loki_bulk::import_stream(config, reader, 0).await?;
        info!("  {name}: {entries} entries imported");
        total += entries;
    }

    Ok(total)
}

/// Build an alert-replay trigger from the first fired alert in the snapshot.
fn build_alert_replay_trigger(
    snapshot_dir: &str,
    manifest: &SnapshotManifest,
) -> Result<serde_json::Value> {
    let alerts_path = Path::new(snapshot_dir).join("fired-alerts.json");
    let raw = fs::read_to_string(&alerts_path).context("read fired-alerts.json")?;
    let alerts: Vec<FiredAlert> = serde_json::from_str(&raw).context("parse fired-alerts.json")?;

    // Start at the first alert *at or after* the attack began — not the globally
    // earliest firing, which is usually pre-attack infra noise. The manifest
    // carries the attack start.
    let alert = alerts
        .iter()
        .find(|a| a.fired_at >= manifest.started_at)
        .or_else(|| alerts.first())
        .context("no fired alerts in snapshot — use --trigger-mode=operation instead")?;

    info!(
        "alert-replay trigger: {} at {}",
        alert.alert_name,
        alert.fired_at.to_rfc3339()
    );

    Ok(serde_json::json!({
        "labels": alert.labels,
        "annotations": alert.annotations,
        "startsAt": alert.fired_at.to_rfc3339(),
        "operation_context": {
            "operation_id": manifest.operation_id,
            "attack_window_start": alert.fired_at.to_rfc3339(),
            // Do NOT set attack_window_end — blue must determine scope
        },
    }))
}

/// Build an operation-mode trigger replicating blue_from_operation() logic.
fn build_operation_trigger(
    snapshot_dir: &str,
    manifest: &SnapshotManifest,
) -> Result<serde_json::Value> {
    let red_state_path = Path::new(snapshot_dir).join("red-state.json");
    let raw = fs::read_to_string(&red_state_path).context("read red-state.json")?;
    let state: serde_json::Value = serde_json::from_str(&raw).context("parse red-state.json")?;

    let op_id = &manifest.operation_id;
    let cred_count = state
        .get("all_credentials")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let host_count = state
        .get("all_hosts")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let has_da = state
        .get("has_domain_admin")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let target_ips: Vec<String> = state
        .get("all_hosts")
        .and_then(|v| v.as_array())
        .map(|hosts| {
            hosts
                .iter()
                .filter_map(|h| h.get("ip").and_then(|v| v.as_str()).map(String::from))
                .take(50)
                .collect()
        })
        .unwrap_or_default();

    let target_users: Vec<String> = state
        .get("all_credentials")
        .and_then(|v| v.as_array())
        .map(|creds| {
            creds
                .iter()
                .filter_map(|c| c.get("username").and_then(|v| v.as_str()).map(String::from))
                .take(50)
                .collect()
        })
        .unwrap_or_default();

    let techniques: Vec<String> = state
        .get("identified_techniques")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .take(20)
                .collect()
        })
        .unwrap_or_default();

    let window_start = manifest.started_at.to_rfc3339();
    let window_end = manifest.completed_at.to_rfc3339();

    Ok(serde_json::json!({
        "labels": {
            "alertname": format!("RedTeamOperation_{op_id}"),
            "severity": "critical",
            "source": "ares-red-team",
        },
        "annotations": {
            "summary": format!(
                "Red team operation {op_id} - {cred_count} credentials, {host_count} hosts"
            ),
            "description": format!(
                "Investigate blue team detection coverage for red team operation {op_id}. \
                 Attack window: {window_start} to {window_end}. Domain admin: {has_da}."
            ),
        },
        "operation_context": {
            "operation_id": op_id,
            "attack_window_start": window_start,
            "attack_window_end": window_end,
            "techniques_used": techniques,
        },
        "startsAt": window_start,
        "endsAt": window_end,
        "target_ips": target_ips,
        "target_users": target_users,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_stats_empty_input_is_zero() {
        let s = ScoreStats::from(&[]);
        assert_eq!(s.mean, 0.0);
        assert_eq!(s.stddev, 0.0);
        assert_eq!(s.min, 0.0);
        assert_eq!(s.max, 0.0);
    }

    #[test]
    fn score_stats_single_sample_stddev_is_zero() {
        let s = ScoreStats::from(&[0.72]);
        assert!((s.mean - 0.72).abs() < 1e-9);
        assert_eq!(s.stddev, 0.0);
        assert!((s.min - 0.72).abs() < 1e-9);
        assert!((s.max - 0.72).abs() < 1e-9);
    }

    #[test]
    fn score_stats_matches_sample_stddev() {
        // Sample stddev of [0.60, 0.70, 0.80] uses n-1 = 2 in the denominator:
        // variance = ((-.1)² + 0 + .1²) / 2 = 0.01 → stddev = 0.1.
        let s = ScoreStats::from(&[0.60, 0.70, 0.80]);
        assert!((s.mean - 0.70).abs() < 1e-9);
        assert!((s.stddev - 0.1).abs() < 1e-9);
        assert!((s.min - 0.60).abs() < 1e-9);
        assert!((s.max - 0.80).abs() < 1e-9);
    }

    #[test]
    fn provider_supports_seed_recognizes_openai_prefix() {
        assert!(provider_supports_seed(Some("openai/gpt-5.2")));
    }

    #[test]
    fn provider_supports_seed_warns_for_anthropic() {
        assert!(!provider_supports_seed(Some("anthropic/claude-opus-4-8")));
        assert!(!provider_supports_seed(Some("claude-cli/sonnet")));
        assert!(!provider_supports_seed(Some("ollama/llama3")));
    }

    #[test]
    fn provider_supports_seed_no_model_defaults_to_supported() {
        // Unknown model resolution → assume supported to avoid crying wolf on
        // the default blue model (OpenAI). Occasional false-negative warning
        // is preferable to a false-positive "your seed will be dropped".
        assert!(provider_supports_seed(None));
    }
}
