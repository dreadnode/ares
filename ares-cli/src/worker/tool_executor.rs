//! Thin tool executor loop for LLM-driven orchestration.
//!
//! When the Rust orchestrator drives agent loops via `ARES_LLM_MODEL`, it
//! issues a NATS request to `ares.tools.exec.{role}`. Workers subscribe as
//! a queue group so each request goes to exactly one worker, and reply on
//! the auto-generated reply inbox.
//!
//! ```text
//! loop {
//!     1. Receive NATS request on ares.tools.exec.{role} (queue group)
//!     2. Deserialize ToolExecRequest
//!     3. Execute tool via ares_tools::dispatch()
//!     4. Serialize ToolExecResponse
//!     5. Reply on msg.reply inbox
//! }
//! ```
//!

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn, Instrument};

use ares_core::nats::{self, NatsBroker};
use ares_core::telemetry::propagation::set_span_parent;
use ares_core::telemetry::spans::{
    trace_discovery, AgentSpanBuilder, SpanKind, Team, TraceDiscoveryParams,
};
use ares_core::telemetry::target::{extract_target_info, infer_target_type_from_info};

use crate::worker::config::WorkerConfig;
use crate::worker::credential_resolver::resolve_credentials;
use crate::worker::heartbeat::WorkerStatus;

// ─── Wire types (match orchestrator's tool_dispatcher.rs exactly) ────────────

/// Request from the orchestrator's RedisToolDispatcher.
#[derive(Debug, Deserialize)]
struct ToolExecRequest {
    call_id: String,
    task_id: String,
    tool_name: String,
    arguments: serde_json::Value,
    /// W3C traceparent header for cross-service span linking.
    #[serde(default)]
    traceparent: Option<String>,
    /// Operation ID for span correlation with dashboards.
    #[serde(default)]
    operation_id: Option<String>,
}

/// Response pushed back to the orchestrator.
#[derive(Debug, Serialize)]
struct ToolExecResponse {
    call_id: String,
    output: String,
    error: Option<String>,
    /// Structured discoveries parsed from the tool output.
    #[serde(skip_serializing_if = "Option::is_none")]
    discoveries: Option<serde_json::Value>,
    /// Typed classification of the failure, when the worker can determine
    /// one. The orchestrator's dispatcher copies this into the runner's
    /// [`ares_llm::ToolExecResult`] so pruning / cache decisions key off
    /// a variant instead of substring-matching. Absent on success and on
    /// failures where no discriminator is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_kind: Option<ares_llm::ToolFailureKind>,
}

// ─── Tool executor loop ─────────────────────────────────────────────────────

/// Default per-worker concurrent-tool cap. Each worker processes up to N
/// tool requests in parallel via `tokio::spawn`; the serial `.await` on
/// each dispatch was throttling effective fleet throughput to the number
/// of worker roles (7) regardless of how many permits `TOOL_PERMITS`
/// advertised. Kept conservative (3) so the fleet-wide peak stays under
/// the observed 10 GiB cgroup ceiling: at ~250 MB per netexec × 3 per
/// worker × 7 roles = ~5 GB peak, matching the original single-worker
/// TOOL_PERMITS=20 memory profile. Override via `ARES_WORKER_CONCURRENCY`.
const DEFAULT_WORKER_CONCURRENCY: usize = 3;

/// Environment variable override for [`DEFAULT_WORKER_CONCURRENCY`].
/// Values <1 are ignored (falls back to default).
const WORKER_CONCURRENCY_ENV: &str = "ARES_WORKER_CONCURRENCY";

fn worker_concurrency_from_env() -> usize {
    std::env::var(WORKER_CONCURRENCY_ENV)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_WORKER_CONCURRENCY)
}

/// Guard for the per-worker in-flight counter. Increments the counter on
/// construction (flipping `status_tx` to "busy" on the 0→1 transition) and
/// decrements on drop (flipping to "idle" on the 1→0 transition). Held for
/// the lifetime of a spawned `execute_and_respond` task so panics and early
/// returns can never leak the count.
struct InflightGuard {
    counter: Arc<AtomicUsize>,
    status_tx: tokio::sync::watch::Sender<WorkerStatus>,
}

impl InflightGuard {
    fn enter(
        counter: Arc<AtomicUsize>,
        status_tx: tokio::sync::watch::Sender<WorkerStatus>,
        tool_name: &str,
        call_id: &str,
    ) -> Self {
        let prev = counter.fetch_add(1, Ordering::SeqCst);
        if prev == 0 {
            let _ = status_tx.send(WorkerStatus {
                status: "busy".to_string(),
                current_task: Some(busy_current_task(tool_name, call_id)),
            });
        }
        Self { counter, status_tx }
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        let after = self.counter.fetch_sub(1, Ordering::SeqCst) - 1;
        if after == 0 {
            let _ = self.status_tx.send(WorkerStatus {
                status: "idle".to_string(),
                current_task: None,
            });
        }
    }
}

/// Run the tool execution loop until shutdown is signalled.
///
/// Subscribes to `ares.tools.exec.{role}` as a queue group so each request
/// goes to exactly one worker. Replies on the request's reply inbox.
///
/// Concurrency: each received request is dispatched into `tokio::spawn`
/// gated by a per-worker semaphore capped at [`DEFAULT_WORKER_CONCURRENCY`]
/// (default 3). The loop backpressures on `acquire_owned().await` when the
/// cap is reached — a full cap holds the next `sub.next()` fetch in
/// suspension, so NATS's queue-group rebalances to a worker with slack.
/// Ordering is not preserved across concurrent dispatches; the LLM's tool
/// calls are independent, so this is safe. Preserves the serial-loop's
/// memory guardrail via the process-wide `TOOL_PERMITS` semaphore inside
/// `CommandBuilder::execute()` plus the tighter per-worker cap here.
pub async fn run_tool_exec_loop(
    config: &WorkerConfig,
    conn: redis::aio::ConnectionManager,
    nats: NatsBroker,
    status_tx: tokio::sync::watch::Sender<WorkerStatus>,
    shutdown: Arc<tokio::sync::Notify>,
) -> anyhow::Result<()> {
    // Install the operation scope from ARES_OPERATION_ID so out-of-scope
    // single-IP tool calls get rejected before any subprocess runs. The worker
    // doesn't otherwise parse target_ips out of the env JSON; this is the
    // only path that needs them.
    let scope = ares_tools::scope::install_from_env();
    if !scope.is_unrestricted() {
        info!(
            target_ips = %scope.target_ips().join(","),
            "Worker installed operation scope — out-of-scope single-IP tool calls will be rejected"
        );
    }

    let subject = nats::tool_exec_subject(&config.worker_role);
    let queue_group = format!("ares-tools-{}", config.worker_role);

    let client = nats.client().clone();
    let mut sub = client
        .queue_subscribe(subject.clone(), queue_group.clone())
        .await?;
    info!(
        subject = %subject,
        queue_group = %queue_group,
        agent = %config.agent_name,
        "Starting tool executor loop (NATS queue subscribe)"
    );

    let unavailable_tools: Arc<Mutex<HashMap<String, UnavailableEntry>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let worker_permits = Arc::new(Semaphore::new(worker_concurrency_from_env()));
    let inflight = Arc::new(AtomicUsize::new(0));
    let worker_role = config.worker_role.clone();

    // Long-lived workers (EC2 systemd units) start with operation_id=None, so
    // the startup `/etc/hosts` sync in `worker::run` never fires — they only
    // learn the op from incoming requests. Bind the sync lazily off the first
    // request that carries one; without this, FQDN/Kerberos tools fail with
    // `getaddrinfo: Name or service not known`. Seeded with the startup op so
    // the K8s path (op known at boot) doesn't double-spawn.
    let mut hosts_guard = crate::worker::hosts::HostsSyncGuard::seeded(config.operation_id.clone());

    // Cracker-only: wipe hashcat's persistent potfile at every op transition
    // so plaintexts cracked in a prior op don't leak into the next as free
    // candidates in the known-password reuse pass (which would silently
    // inflate benchmark compromise numbers with prior ops' crack work). The
    // guard is fresh (not seeded with `config.operation_id`) so a worker
    // restart mid-op still wipes — a restarted worker cannot prove the
    // potfile is uncontaminated. Set `ARES_KEEP_POTFILE=1` to disable.
    let mut potfile_guard: Option<ares_tools::cracker::PotfileResetGuard> =
        if worker_role == "cracker" {
            Some(ares_tools::cracker::PotfileResetGuard::new())
        } else {
            None
        };

    loop {
        let next = tokio::select! {
            m = sub.next() => m,
            _ = shutdown.notified() => {
                info!("Tool executor: shutdown signalled, finishing");
                return Ok(());
            }
        };

        let Some(msg) = next else {
            warn!("Tool executor: subscription closed, exiting");
            return Ok(());
        };

        let request: ToolExecRequest = match serde_json::from_slice(&msg.payload) {
            Ok(r) => r,
            Err(e) => {
                warn!(err = %e, "Bad ToolExecRequest payload, skipping");
                continue;
            }
        };

        // Ensure the /etc/hosts sync is running for this request's operation so
        // FQDN/Kerberos-based tools can resolve DC and member-server names.
        if let Some(ref op) = request.operation_id {
            hosts_guard.ensure(&conn, op, &config.agent_name, shutdown.clone());
            if let Some(guard) = potfile_guard.as_mut() {
                guard.ensure(op);
            }
        }

        // Acquire the per-worker permit BEFORE spawning so the loop
        // backpressures on the cap. `acquire_owned` returns a permit whose
        // Drop releases the semaphore slot — moving it into the spawned
        // task ties the slot's lifetime to the task's, no matter how it
        // exits (Ok, error, panic).
        let permit = match worker_permits.clone().acquire_owned().await {
            Ok(p) => p,
            Err(e) => {
                // Only reachable if the semaphore is explicitly closed,
                // which we never do — treat as fatal.
                error!(err = %e, "worker semaphore closed unexpectedly, exiting loop");
                return Err(anyhow::anyhow!("worker semaphore closed: {e}"));
            }
        };

        let ti = extract_target_info(&request.arguments);
        let tt = infer_target_type_from_info(&ti);
        let mut span_builder = AgentSpanBuilder::new("tool_exec", &worker_role, Team::Red)
            .tool(&request.tool_name)
            .kind(SpanKind::Consumer);
        if let Some(ref ip) = ti.target_ip {
            span_builder = span_builder.target_ip(ip);
        }
        if let Some(ref fqdn) = ti.target_fqdn {
            span_builder = span_builder.target_fqdn(fqdn);
        }
        if let Some(ref user) = ti.target_user {
            span_builder = span_builder.target_user(user);
        }
        if let Some(target_type) = tt {
            span_builder = span_builder.target_type(target_type);
        }
        if let Some(ref op) = request.operation_id {
            span_builder = span_builder.operation_id(op);
        }
        let exec_span = span_builder.build();
        if let Some(ref tp) = request.traceparent {
            set_span_parent(&exec_span, tp);
        }

        let reply_to = msg.reply.clone();
        let client_for_reply = client.clone();
        // Clone the resolver-side Redis connection per-request. ConnectionManager
        // is cheap to clone (it wraps an Arc) and resolve_credentials mutates
        // the borrow during state reads — keeping a per-request copy avoids
        // interleaving with the next iteration's `sub.next()` await.
        let conn_for_resolver = conn.clone();
        let unavailable_for_task = unavailable_tools.clone();
        let guard = InflightGuard::enter(
            inflight.clone(),
            status_tx.clone(),
            &request.tool_name,
            &request.call_id,
        );

        tokio::spawn(
            async move {
                // Bind `permit` locally so its Drop releases the worker
                // semaphore slot exactly when this task ends — including
                // on panic, task cancellation, or early return from any
                // branch of `execute_and_respond`.
                let _permit = permit;
                let _guard = guard;
                execute_and_respond(
                    client_for_reply,
                    reply_to,
                    &request,
                    &unavailable_for_task,
                    conn_for_resolver,
                )
                .await;
            }
            .instrument(exec_span),
        );
    }
}

/// Build the error response for a tool marked unavailable on this worker
/// (binary missing). Surfaced as a free function so the wording stays in
/// lock-step with tests. Sets [`ares_llm::ToolFailureKind::BinaryNotFound`]
/// on the typed field so the runner can prune without falling back to
/// substring matching.
fn unavailable_tool_response(tool_name: &str, call_id: &str) -> ToolExecResponse {
    ToolExecResponse {
        call_id: call_id.to_string(),
        output: String::new(),
        error: Some(format!(
            "Tool '{tool_name}' is not installed on this worker. \
             Do not call this tool again — it failed to spawn previously."
        )),
        discoveries: None,
        failure_kind: Some(ares_llm::ToolFailureKind::BinaryNotFound),
    }
}

/// Exponential-backoff schedule for a tool that fails to spawn with ENOENT.
/// Deploys don't restart workers, so a flat TTL either re-probes far too
/// often for a genuinely-missing binary (burning LLM steps) or holds a
/// transient miss in the cache long past when the binary would have shown
/// up. This schedule self-heals fast on the first miss and backs off
/// exponentially on repeated misses: 1 min → 5 min → 30 min → 4 h.
/// The final rung acts as a cap: an operator who never `apt install`s the
/// tool will still see one probe every 4 hours per worker.
const UNAVAILABLE_BACKOFF: &[Duration] = &[
    Duration::from_secs(60),
    Duration::from_secs(300),
    Duration::from_secs(1800),
    Duration::from_secs(4 * 3600),
];

/// One entry in the `unavailable_tools` cache. `failures` indexes into
/// `UNAVAILABLE_BACKOFF` to pick the current cooldown; `marked_at` is
/// when the most-recent failure was recorded.
#[derive(Debug, Clone, Copy)]
struct UnavailableEntry {
    marked_at: Instant,
    failures: u32,
}

fn cooldown_for(failures: u32) -> Duration {
    let idx = failures
        .saturating_sub(1)
        .min(UNAVAILABLE_BACKOFF.len() as u32 - 1) as usize;
    UNAVAILABLE_BACKOFF[idx]
}

/// Tool execution failures that indicate the binary is genuinely absent
/// from PATH (ENOENT). The executor emits this exact phrasing only for
/// `io::ErrorKind::NotFound`; every other spawn error (EAGAIN, ENOMEM,
/// EMFILE, transient EACCES, /proc I/O hiccups) is reported as a
/// "transient spawn error" and must NOT poison the cache.
///
/// This is the string-only fallback for callers that don't have the
/// original `anyhow::Error` in hand. Prefer [`classify_dispatch_error`]
/// when you do — it downcasts to the typed [`ares_tools::SpawnErrorKind`]
/// marker and is not sensitive to wording drift.
///
/// Matching both `"failed to spawn"` AND `"is it installed?"` (not just
/// one) keeps arbitrary tool output that happens to contain the substring
/// from ever tripping the classifier.
fn is_tool_unavailable_error(err_str: &str) -> bool {
    err_str.contains("failed to spawn") && err_str.contains("is it installed?")
}

/// Classify a dispatch error into an optional
/// [`ares_llm::ToolFailureKind`]. Prefers the typed
/// [`ares_tools::SpawnErrorKind`] marker attached by
/// [`ares_tools::executor::CommandBuilder::execute`]; falls back to the
/// string classifier if the marker is missing (e.g., an error path in a
/// non-`CommandBuilder` code path). Returns `None` when neither signal
/// fires — the failure is a wrapper-level arg error, timeout, or other
/// non-spawn condition and the runner should not treat it as a spawn
/// failure.
fn classify_dispatch_error(err: &anyhow::Error) -> Option<ares_llm::ToolFailureKind> {
    if let Some(kind) = ares_tools::spawn_error_kind(err) {
        return Some(if kind.is_not_found() {
            ares_llm::ToolFailureKind::BinaryNotFound
        } else {
            ares_llm::ToolFailureKind::TransientSpawn
        });
    }
    // No typed marker — fall back to the string classifier so an in-flight
    // rollout where the worker binary has the classifier update but the
    // ares-tools library predates the marker still classifies ENOENT.
    if is_tool_unavailable_error(&err.to_string()) {
        return Some(ares_llm::ToolFailureKind::BinaryNotFound);
    }
    None
}

/// Convert a parsed-discoveries value into `Some(_)` only when it carries
/// at least one entry — avoids serialising an empty `discoveries: {}` blob.
fn discoveries_or_none(parsed: serde_json::Value) -> Option<serde_json::Value> {
    if parsed.as_object().is_none_or(|o| o.is_empty()) {
        None
    } else {
        Some(parsed)
    }
}

/// Render the error string for a tool that exited with a non-zero status.
fn tool_exit_error(exit_code: Option<i32>) -> String {
    format!("tool exited with code {exit_code:?}")
}

/// Build the `WorkerStatus.current_task` string used while a tool call is in
/// flight. Pulled out so the field shape stays in lock-step with consumers
/// that key off `tool_name:call_id`.
fn busy_current_task(tool_name: &str, call_id: &str) -> String {
    format!("{tool_name}:{call_id}")
}

/// Iterate a `discoveries` value and return `(disc_type, count)` for each
/// non-empty array. Used by the executor to emit one `trace_discovery` span
/// per non-empty discovery type. Pulled out as a free function so the
/// counting logic can be unit-tested without spinning up a tracer.
fn count_discovery_entries(discoveries: &serde_json::Value) -> Vec<(String, usize)> {
    let Some(obj) = discoveries.as_object() else {
        return Vec::new();
    };
    obj.iter()
        .filter_map(|(disc_type, items)| {
            let count = items.as_array().map(|a| a.len()).unwrap_or(0);
            (count > 0).then(|| (disc_type.clone(), count))
        })
        .collect()
}

/// Build the success-path [`ToolExecResponse`] (output + discoveries + error
/// derived from the process exit status). Pulled out so the response shape
/// can be unit-tested without spawning a tool subprocess.
fn build_success_response(
    call_id: &str,
    success: bool,
    exit_code: Option<i32>,
    combined: String,
    discoveries: Option<serde_json::Value>,
) -> ToolExecResponse {
    let (error, failure_kind) = if success {
        (None, None)
    } else {
        // Ran to completion but exited non-zero — a tool-level error, not a
        // spawn failure. Classify explicitly so the runner never confuses
        // it with the ENOENT path.
        (
            Some(tool_exit_error(exit_code)),
            Some(ares_llm::ToolFailureKind::ToolError),
        )
    };
    ToolExecResponse {
        call_id: call_id.to_string(),
        output: combined,
        error,
        discoveries,
        failure_kind,
    }
}

/// Build the error-path [`ToolExecResponse`] (dispatch failed before the
/// tool produced any output). `failure_kind` is the typed discriminator
/// resolved from the ares-tools error chain (via
/// [`ares_tools::spawn_error_kind`]) — `None` when the failure is neither
/// ENOENT nor a transient spawn error (e.g., wrapper-level arg validation).
fn build_error_response(
    call_id: &str,
    err_str: String,
    failure_kind: Option<ares_llm::ToolFailureKind>,
) -> ToolExecResponse {
    ToolExecResponse {
        call_id: call_id.to_string(),
        output: String::new(),
        error: Some(err_str),
        discoveries: None,
        failure_kind,
    }
}

/// Execute a tool call and reply on the NATS inbox.
///
/// Resolves credentials and Kerberos tickets from operation state before
/// dispatch. Pre-fix this path called `ares_tools::dispatch` directly with
/// the orchestrator-supplied arguments, which meant the entire credential
/// resolution layer (`worker::credential_resolver::resolve_credentials`) was
/// bypassed in production NATS mode — every cred-injection fix the
/// orchestrator made (Bug B's KRB5CCNAME wiring, Bug I's same-realm cred
/// precedence, etc.) only affected the in-process `LocalToolDispatcher` and
/// never reached real workers. The injection now mirrors
/// `LocalToolDispatcher::dispatch_tool` so the two paths stay in lock-step.
async fn execute_and_respond(
    client: async_nats::Client,
    reply_to: Option<async_nats::Subject>,
    request: &ToolExecRequest,
    unavailable_tools: &Arc<Mutex<HashMap<String, UnavailableEntry>>>,
    mut conn: redis::aio::ConnectionManager,
) {
    // Check the backoff cache under a briefly-held std::sync::Mutex — no
    // await point holds this lock, so it can't deadlock with concurrent
    // spawned tasks. If the entry exists but its cooldown has expired we
    // *don't* remove it here: the ENOENT handler below will refresh
    // `marked_at` and bump `failures` if the re-probe fails, and the
    // success branch clears the entry outright so a working tool
    // self-heals the cache.
    let skip_reason = {
        let g = unavailable_tools
            .lock()
            .expect("unavailable_tools mutex poisoned");
        g.get(&request.tool_name).and_then(|entry| {
            let cooldown = cooldown_for(entry.failures);
            let elapsed = Instant::now().duration_since(entry.marked_at);
            (elapsed < cooldown).then(|| (entry.failures, cooldown - elapsed))
        })
    };
    if let Some((failures, remaining)) = skip_reason {
        info!(
            tool = %request.tool_name,
            call_id = %request.call_id,
            failures,
            remaining_secs = remaining.as_secs(),
            "Skipping tool cached as ENOENT — next re-probe once cooldown expires"
        );
        let response = unavailable_tool_response(&request.tool_name, &request.call_id);
        send_reply(&client, reply_to.as_ref(), &response).await;
        return;
    }

    info!(
        tool = %request.tool_name,
        call_id = %request.call_id,
        task_id = %request.task_id,
        "Executing tool"
    );

    let di = extract_target_info(&request.arguments);
    let dt = infer_target_type_from_info(&di);

    // Resolve credentials from operation state. The LLM never passes secret
    // material — usernames + domains only. A cross-forest Kerberos coercion
    // may redirect to a `*_kerberos` variant (e.g. psexec → psexec_kerberos),
    // so track the effective tool name for the dispatch + parser calls.
    // On resolver error, fall back to the original arguments so the worker
    // never silently drops a tool call.
    let mut resolved_arguments = request.arguments.clone();
    let mut effective_tool_name: Cow<'_, str> = Cow::Borrowed(request.tool_name.as_str());
    match resolve_credentials(
        &mut conn,
        request.operation_id.as_deref(),
        &request.tool_name,
        &mut resolved_arguments,
    )
    .await
    {
        Ok(Some(renamed)) => {
            info!(
                from = %request.tool_name,
                to = %renamed,
                call_id = %request.call_id,
                "worker tool_executor: applying Kerberos variant redirect from credential_resolver"
            );
            effective_tool_name = Cow::Owned(renamed);
        }
        Ok(None) => {}
        Err(e) => {
            warn!(
                tool = %request.tool_name,
                call_id = %request.call_id,
                err = %e,
                "worker credential_resolver failed; continuing with original arguments"
            );
            resolved_arguments = request.arguments.clone();
        }
    }

    let response = match ares_tools::dispatch(&effective_tool_name, &resolved_arguments).await {
        Ok(output) => {
            // Dispatch returned Ok — the binary spawned. Clear any prior
            // ENOENT entry for this tool so a working tool self-heals the
            // cache without waiting for the backoff window to expire.
            {
                let mut g = unavailable_tools
                    .lock()
                    .expect("unavailable_tools mutex poisoned");
                if g.remove(effective_tool_name.as_ref()).is_some() {
                    info!(
                        tool = %effective_tool_name,
                        "Tool spawn succeeded — clearing prior ENOENT cache entry"
                    );
                }
            }
            let raw = output.combined_raw();
            let mut combined = output.combined();
            let success = output.success;
            let exit_code = output.exit_code;

            let discoveries = discoveries_or_none(ares_tools::parsers::parse_tool_output(
                &effective_tool_name,
                &raw,
                &resolved_arguments,
            ));

            // A zero-yield unauthenticated harvest (spray/roast) exits 0 and
            // masks its empty result as "success". Append an explicit advisory
            // so the LLM enumerates real users instead of re-spraying the same
            // canned wordlist. No-op for tools that aren't unauth harvests or
            // that actually produced loot.
            if success {
                if let Some(note) = ares_tools::parsers::empty_harvest_advisory(
                    &effective_tool_name,
                    discoveries.as_ref(),
                ) {
                    combined.push_str(&note);
                }
            }

            if let Some(ref disc) = discoveries {
                for (disc_type, _count) in count_discovery_entries(disc) {
                    let span = trace_discovery(TraceDiscoveryParams {
                        discovery_type: &disc_type,
                        source_agent: &effective_tool_name,
                        target_user: di.target_user.as_deref(),
                        target_domain: None,
                        target_ip: di.target_ip.as_deref(),
                        target_fqdn: di.target_fqdn.as_deref(),
                        target_type: dt,
                        operation_id: request.operation_id.as_deref(),
                        task_id: Some(request.task_id.as_str()),
                    });
                    let _guard = span.enter();
                }
            }

            build_success_response(&request.call_id, success, exit_code, combined, discoveries)
        }
        Err(e) => {
            let failure_kind = classify_dispatch_error(&e);
            // Only ENOENT-class failures poison the cache. TransientSpawn
            // (EAGAIN/ENOMEM/EMFILE) MUST NOT cache — that was the whole
            // point of the split; a transient at t=0 used to blacklist the
            // tool for the worker's lifetime. The runner still won't prune
            // on a TransientSpawn either (`ToolExecResult.failure_kind`
            // carries the discriminator; runner keys off BinaryNotFound
            // only), so a transient just surfaces the error to the LLM.
            if matches!(
                failure_kind,
                Some(ares_llm::ToolFailureKind::BinaryNotFound)
            ) {
                let mut g = unavailable_tools
                    .lock()
                    .expect("unavailable_tools mutex poisoned");
                let entry = g
                    .entry(effective_tool_name.to_string())
                    .and_modify(|e| {
                        e.failures = e.failures.saturating_add(1);
                        e.marked_at = Instant::now();
                    })
                    .or_insert(UnavailableEntry {
                        marked_at: Instant::now(),
                        failures: 1,
                    });
                warn!(
                    tool = %effective_tool_name,
                    failures = entry.failures,
                    cooldown_secs = cooldown_for(entry.failures).as_secs(),
                    "Tool binary not found (ENOENT) — backing off before next re-probe"
                );
            }
            warn!(
                tool = %effective_tool_name,
                call_id = %request.call_id,
                err = %e,
                failure_kind = ?failure_kind,
                "Tool execution failed"
            );
            build_error_response(&request.call_id, e.to_string(), failure_kind)
        }
    };

    debug!(
        tool = %effective_tool_name,
        call_id = %request.call_id,
        has_error = response.error.is_some(),
        "Tool result ready"
    );
    send_reply(&client, reply_to.as_ref(), &response).await;
}

async fn send_reply(
    client: &async_nats::Client,
    reply_to: Option<&async_nats::Subject>,
    response: &ToolExecResponse,
) {
    let Some(reply) = reply_to else {
        warn!(call_id = %response.call_id, "No reply subject — orchestrator will time out");
        return;
    };
    match serde_json::to_vec(response) {
        Ok(bytes) => {
            if let Err(e) = client.publish(reply.clone(), Bytes::from(bytes)).await {
                error!(call_id = %response.call_id, "Failed to publish reply: {e}");
            }
        }
        Err(e) => {
            error!(call_id = %response.call_id, "Failed to serialize reply: {e}");
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Dispatch/registry parity ──────────────────────────────────────────

    /// The worker dispatch table, read at compile time so the parity test
    /// below reads the real match arms rather than a hand-kept copy of them.
    const DISPATCH_SRC: &str = include_str!("../../../ares-tools/src/lib.rs");

    /// Names of the `certipy_*_full_chain` arms in `ares_tools::dispatch`.
    fn dispatchable_full_chains() -> std::collections::BTreeSet<&'static str> {
        DISPATCH_SRC
            .lines()
            .filter(|line| line.contains("=>"))
            .filter_map(|line| {
                let name = line.split('"').nth(1)?;
                (name.starts_with("certipy_") && name.ends_with("_full_chain")).then_some(name)
            })
            .collect()
    }

    #[test]
    fn every_dispatchable_certipy_chain_is_advertised_to_the_llm() {
        use ares_llm::tool_registry::{tools_for_role, AgentRole};

        let dispatched = dispatchable_full_chains();
        assert!(
            dispatched.len() >= 5,
            "dispatch scrape found only {dispatched:?} — the extraction broke, not the registry"
        );

        let advertised: std::collections::BTreeSet<String> = tools_for_role(AgentRole::Privesc)
            .into_iter()
            .map(|t| t.name)
            .collect();

        let missing: Vec<&str> = dispatched
            .iter()
            .copied()
            .filter(|name| !advertised.contains(*name))
            .collect();
        assert!(
            missing.is_empty(),
            "ares_tools::dispatch routes {missing:?} but the privesc tool registry does not \
             advertise them — the model cannot call them. Add a ToolDefinition in \
             ares-llm/src/tool_registry/privesc/adcs.rs."
        );
    }

    #[test]
    fn advertised_certipy_chains_have_required_selection_parameters() {
        use ares_llm::tool_registry::{tools_for_role, AgentRole};

        let tools = tools_for_role(AgentRole::Privesc);
        let required = |name: &str| -> Vec<String> {
            tools
                .iter()
                .find(|t| t.name == name)
                .unwrap_or_else(|| panic!("privesc registry missing {name}"))
                .input_schema
                .get("required")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        };

        let esc1 = required("certipy_esc1_full_chain");
        assert!(esc1.contains(&"upn".to_string()) && esc1.contains(&"sid".to_string()));

        let esc3 = required("certipy_esc3_full_chain");
        assert!(esc3.contains(&"agent_template".to_string()));

        let esc13_props = tools
            .iter()
            .find(|t| t.name == "certipy_esc13_full_chain")
            .expect("privesc registry missing certipy_esc13_full_chain")
            .input_schema["properties"]
            .as_object()
            .expect("esc13 schema properties")
            .clone();
        assert!(!esc13_props.contains_key("upn"));
        assert!(!esc13_props.contains_key("sid"));
    }

    // ── Per-worker concurrency (Serial-loop wedge fix) ────────────────────

    /// Env-var tests serialise on this mutex — process-wide `set_var` is
    /// not test-isolated, and cargo runs unit tests in parallel by default.
    /// Without the guard, the "default" test can observe the "override"
    /// test's leaked value and fail with a bogus assertion.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Drop guard that snapshots [`WORKER_CONCURRENCY_ENV`] on entry and
    /// restores it on scope exit. Combined with `ENV_LOCK`, this keeps
    /// each env-touching test hermetic against its sibling tests.
    struct EnvGuard {
        prior: Option<String>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }
    impl EnvGuard {
        fn acquire() -> Self {
            // If a sibling test panicked while holding the lock, PoisonError
            // still lets us proceed — we just want serialisation, not the
            // sibling's data.
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            Self {
                prior: std::env::var(WORKER_CONCURRENCY_ENV).ok(),
                _lock: lock,
            }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prior {
                Some(v) => std::env::set_var(WORKER_CONCURRENCY_ENV, v),
                None => std::env::remove_var(WORKER_CONCURRENCY_ENV),
            }
        }
    }

    #[test]
    fn worker_concurrency_default_when_env_unset() {
        let _g = EnvGuard::acquire();
        std::env::remove_var(WORKER_CONCURRENCY_ENV);
        assert_eq!(worker_concurrency_from_env(), DEFAULT_WORKER_CONCURRENCY);
    }

    #[test]
    fn worker_concurrency_ignores_zero_and_negative() {
        // Zero and negative overrides must not silently disable the worker —
        // fall back to the default so a fat-fingered env var can't wedge
        // the fleet.
        let _g = EnvGuard::acquire();
        std::env::set_var(WORKER_CONCURRENCY_ENV, "0");
        assert_eq!(worker_concurrency_from_env(), DEFAULT_WORKER_CONCURRENCY);
        std::env::set_var(WORKER_CONCURRENCY_ENV, "-1");
        assert_eq!(worker_concurrency_from_env(), DEFAULT_WORKER_CONCURRENCY);
        std::env::set_var(WORKER_CONCURRENCY_ENV, "not-a-number");
        assert_eq!(worker_concurrency_from_env(), DEFAULT_WORKER_CONCURRENCY);
    }

    #[test]
    fn worker_concurrency_env_override_takes_effect() {
        let _g = EnvGuard::acquire();
        std::env::set_var(WORKER_CONCURRENCY_ENV, "7");
        assert_eq!(worker_concurrency_from_env(), 7);
    }

    #[tokio::test]
    async fn inflight_guard_flips_busy_on_0_to_1_transition() {
        // Contract: entering the FIRST inflight guard flips the watch
        // channel to "busy". Subsequent guards (concurrent dispatches) do
        // NOT re-broadcast — the guard checks the pre-add counter.
        let (tx, rx) = tokio::sync::watch::channel(WorkerStatus {
            status: "idle".to_string(),
            current_task: None,
        });
        let counter = Arc::new(AtomicUsize::new(0));

        let g1 = InflightGuard::enter(counter.clone(), tx.clone(), "nmap_scan", "call-1");
        assert_eq!(rx.borrow().status, "busy");
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        let g2 = InflightGuard::enter(counter.clone(), tx, "secretsdump", "call-2");
        // Still busy; counter reflects the second in-flight dispatch.
        assert_eq!(rx.borrow().status, "busy");
        assert_eq!(counter.load(Ordering::SeqCst), 2);

        drop(g2);
        // Dropping the second guard while the first is still held must NOT
        // flip to idle — the 1→0 transition is the only trigger.
        assert_eq!(rx.borrow().status, "busy");
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        drop(g1);
        // Now the counter hits zero; flip back to idle.
        assert_eq!(rx.borrow().status, "idle");
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn inflight_guard_flips_idle_on_panic_via_drop() {
        // Contract: a spawned task that panics mid-execution still releases
        // its inflight slot because `InflightGuard: Drop` runs during
        // unwinding. Prevents a permanent "busy" report on a wedged worker.
        let (tx, rx) = tokio::sync::watch::channel(WorkerStatus {
            status: "idle".to_string(),
            current_task: None,
        });
        let counter = Arc::new(AtomicUsize::new(0));

        let counter_for_task = counter.clone();
        let tx_for_task = tx.clone();
        let handle = tokio::spawn(async move {
            let _guard =
                InflightGuard::enter(counter_for_task, tx_for_task, "kaboom", "panic-call");
            panic!("simulated tool executor panic");
        });

        // Await the task — panics propagate as a JoinError.
        let result = handle.await;
        assert!(result.is_err(), "expected the spawned task to panic");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "InflightGuard::Drop must fire during unwind to release the slot"
        );
        assert_eq!(rx.borrow().status, "idle");
    }

    #[tokio::test]
    async fn worker_permits_backpressure_at_cap() {
        // Contract: `acquire_owned().await` on a saturated semaphore
        // suspends until a permit is dropped. Verified by
        // 1. holding all N permits, then confirming `available_permits()`
        //    reaches zero,
        // 2. wrapping a fresh `acquire_owned` in `tokio::time::timeout` —
        //    it times out while the cap is held,
        // 3. dropping a held permit and confirming a subsequent
        //    `acquire_owned` completes promptly.
        // This is the same backpressure the worker loop relies on to keep
        // fleet-wide concurrent tool count within memory budget.
        use std::time::Duration;

        let permits = Arc::new(Semaphore::new(2));

        let p1 = permits.clone().acquire_owned().await.unwrap();
        let p2 = permits.clone().acquire_owned().await.unwrap();
        assert_eq!(permits.available_permits(), 0);

        // A fresh acquire under a tight timeout must fail with Elapsed
        // while the cap is saturated. Elapsed is the timeout arm's Err.
        let stuck =
            tokio::time::timeout(Duration::from_millis(25), permits.clone().acquire_owned()).await;
        assert!(
            stuck.is_err(),
            "acquire_owned should not have resolved while the cap was full"
        );

        drop(p1);
        // Slot freed — the next acquire completes well within the same
        // timeout budget.
        let p3 = tokio::time::timeout(Duration::from_millis(200), permits.clone().acquire_owned())
            .await
            .expect("acquire_owned failed to complete after a permit was dropped")
            .expect("semaphore closed unexpectedly");

        drop(p2);
        drop(p3);
        assert_eq!(permits.available_permits(), 2);
    }

    #[tokio::test]
    async fn unavailable_tools_read_write_across_tasks_no_deadlock() {
        // Contract: `unavailable_tools` is shared across concurrently
        // spawned dispatch tasks. The std::sync::Mutex is held only for
        // the duration of a HashMap contains/insert — never across an
        // await — so many concurrent tasks can safely serialize on it
        // without deadlocking each other or the outer loop's
        // `sub.next().await`.
        let set: Arc<Mutex<HashMap<String, UnavailableEntry>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // First writer marks "hashcat" as unavailable.
        let writer_set = set.clone();
        let writer = tokio::spawn(async move {
            writer_set.lock().expect("mutex poisoned").insert(
                "hashcat".to_string(),
                UnavailableEntry {
                    marked_at: Instant::now(),
                    failures: 1,
                },
            );
        });

        // Concurrent readers race the writer; either observation is valid,
        // but neither may deadlock.
        let mut readers = Vec::new();
        for _ in 0..8 {
            let r_set = set.clone();
            readers.push(tokio::spawn(async move {
                r_set
                    .lock()
                    .expect("mutex poisoned")
                    .contains_key("hashcat")
            }));
        }

        writer.await.unwrap();
        for r in readers {
            let _observed = r.await.unwrap();
        }

        // After all tasks settle, the writer's mutation is visible.
        assert!(set.lock().unwrap().contains_key("hashcat"));
    }

    #[test]
    fn cooldown_for_walks_the_backoff_schedule() {
        // failures=1 → schedule[0]; failures=2 → schedule[1]; and so on.
        // Anything beyond the last rung is clamped to the final entry so
        // an operator who never installs the tool still sees one re-probe
        // per max cooldown, not one per second.
        assert_eq!(cooldown_for(1), UNAVAILABLE_BACKOFF[0]);
        assert_eq!(cooldown_for(2), UNAVAILABLE_BACKOFF[1]);
        assert_eq!(cooldown_for(3), UNAVAILABLE_BACKOFF[2]);
        assert_eq!(cooldown_for(4), UNAVAILABLE_BACKOFF[3]);
        assert_eq!(cooldown_for(99), *UNAVAILABLE_BACKOFF.last().unwrap());
        // failures=0 shouldn't occur in practice (entries are inserted
        // with failures=1), but must not panic on underflow.
        assert_eq!(cooldown_for(0), UNAVAILABLE_BACKOFF[0]);
    }

    #[test]
    fn unavailable_entry_probe_eligibility_uses_backoff_cooldown() {
        // A stale entry (older than its cooldown) is eligible for re-probe.
        // A fresh entry inside its cooldown window is still skipped.
        let now = Instant::now();
        let cooldown = cooldown_for(1);

        let stale = UnavailableEntry {
            marked_at: now
                .checked_sub(cooldown * 2)
                .expect("clock underflow in test"),
            failures: 1,
        };
        let elapsed = now.duration_since(stale.marked_at);
        assert!(
            elapsed >= cooldown,
            "stale entry ({elapsed:?}) should be past cooldown ({cooldown:?})"
        );

        let fresh = UnavailableEntry {
            marked_at: now,
            failures: 1,
        };
        let elapsed = now.duration_since(fresh.marked_at);
        assert!(
            elapsed < cooldown,
            "fresh entry ({elapsed:?}) should be inside cooldown ({cooldown:?})"
        );
    }

    #[test]
    fn tool_exec_request_deserialize() {
        let json = r#"{
            "call_id": "nmap_scan_abc123",
            "task_id": "recon_def456",
            "tool_name": "nmap_scan",
            "arguments": {"target": "192.168.58.0/24"}
        }"#;
        let req: ToolExecRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.call_id, "nmap_scan_abc123");
        assert_eq!(req.tool_name, "nmap_scan");
        assert_eq!(req.task_id, "recon_def456");
    }

    #[test]
    fn tool_exec_response_serialize() {
        let resp = ToolExecResponse {
            call_id: "nmap_scan_abc123".into(),
            output: "Found 5 hosts".into(),
            error: None,
            discoveries: None,
            failure_kind: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("nmap_scan_abc123"));
        assert!(json.contains("Found 5 hosts"));
        // discoveries omitted when None
        assert!(!json.contains("discoveries"));
    }

    #[test]
    fn tool_exec_response_with_error() {
        let resp = ToolExecResponse {
            call_id: "x".into(),
            output: String::new(),
            error: Some("Connection refused".into()),
            discoveries: None,
            failure_kind: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["error"], "Connection refused");
    }

    #[test]
    fn tool_exec_response_with_discoveries() {
        let resp = ToolExecResponse {
            call_id: "nmap_abc".into(),
            output: "scan output".into(),
            error: None,
            discoveries: Some(serde_json::json!({
                "hosts": [{"ip": "192.168.58.10", "services": ["445/tcp"]}]
            })),
            failure_kind: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("discoveries"));
        assert!(json.contains("192.168.58.10"));
    }

    #[test]
    fn tool_exec_request_deserialize_with_traceparent() {
        let json = r#"{
            "call_id": "secretsdump_001",
            "task_id": "task_abc",
            "tool_name": "secretsdump",
            "arguments": {"target": "192.168.58.10", "domain": "contoso.local"},
            "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        }"#;
        let req: ToolExecRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.call_id, "secretsdump_001");
        assert_eq!(req.tool_name, "secretsdump");
        assert_eq!(
            req.traceparent.as_deref(),
            Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
        );
    }

    #[test]
    fn tool_exec_request_deserialize_with_operation_id() {
        let json = r#"{
            "call_id": "nmap_002",
            "task_id": "recon_task",
            "tool_name": "nmap_scan",
            "arguments": {"target": "192.168.58.0/24"},
            "operation_id": "op-20260422-abc123"
        }"#;
        let req: ToolExecRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.operation_id.as_deref(), Some("op-20260422-abc123"));
    }

    #[test]
    fn tool_exec_request_defaults_for_optional_fields() {
        let json = r#"{
            "call_id": "basic_001",
            "task_id": "task_001",
            "tool_name": "whoami",
            "arguments": {}
        }"#;
        let req: ToolExecRequest = serde_json::from_str(json).unwrap();
        assert!(req.traceparent.is_none());
        assert!(req.operation_id.is_none());
    }

    #[test]
    fn tool_exec_request_complex_arguments() {
        let json = r#"{
            "call_id": "netexec_003",
            "task_id": "lateral_task",
            "tool_name": "netexec_smb",
            "arguments": {
                "target": "192.168.58.10",
                "username": "admin",
                "password": "P@ssw0rd!",
                "domain": "contoso.local",
                "shares": true,
                "port": 445
            }
        }"#;
        let req: ToolExecRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.tool_name, "netexec_smb");
        assert_eq!(req.arguments["target"], "192.168.58.10");
        assert_eq!(req.arguments["domain"], "contoso.local");
        assert_eq!(req.arguments["shares"], true);
        assert_eq!(req.arguments["port"], 445);
    }

    #[test]
    fn tool_exec_response_empty_discoveries_omitted() {
        let resp = ToolExecResponse {
            call_id: "test_001".into(),
            output: "some output".into(),
            error: None,
            discoveries: None,
            failure_kind: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("discoveries"));
    }

    #[test]
    fn tool_exec_response_with_multiple_discovery_types() {
        let resp = ToolExecResponse {
            call_id: "nmap_004".into(),
            output: "scan output".into(),
            error: None,
            discoveries: Some(serde_json::json!({
                "hosts": [
                    {"ip": "192.168.58.10", "hostname": "dc01.contoso.local", "services": ["445/tcp", "88/tcp"]},
                    {"ip": "192.168.58.11", "hostname": "sql01.contoso.local", "services": ["1433/tcp"]}
                ],
                "services": [
                    {"port": 445, "protocol": "tcp", "service": "microsoft-ds"}
                ]
            })),
            failure_kind: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let hosts = parsed["discoveries"]["hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0]["ip"], "192.168.58.10");
        assert_eq!(hosts[1]["hostname"], "sql01.contoso.local");
    }

    #[test]
    fn tool_exec_response_serialization_roundtrip() {
        let resp = ToolExecResponse {
            call_id: "roundtrip_test".into(),
            output: "output with special chars: <>&\"'".into(),
            error: Some("exit code 1".into()),
            discoveries: Some(serde_json::json!({"credentials": []})),
            failure_kind: Some(ares_llm::ToolFailureKind::ToolError),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["call_id"], "roundtrip_test");
        assert_eq!(parsed["error"], "exit code 1");
        assert!(parsed["discoveries"]["credentials"].is_array());
    }

    #[test]
    fn tool_exec_response_error_message_format() {
        // Verify the format used in execute_and_respond for unavailable tools
        let tool_name = "nonexistent_tool";
        let error_msg = format!(
            "Tool '{}' is not installed on this worker. \
             Do not call this tool again — it failed to spawn previously.",
            tool_name
        );
        assert!(error_msg.contains("nonexistent_tool"));
        assert!(error_msg.contains("not installed"));
    }

    #[test]
    fn nats_subject_format() {
        let role = "recon";
        let subj = nats::tool_exec_subject(role);
        assert_eq!(subj, "ares.tools.exec.recon");
    }

    #[test]
    fn unavailable_tool_detection_keywords() {
        // Only the executor's ENOENT-specific wording counts. Transient
        // spawn errors (EAGAIN/ENOMEM/EMFILE/etc.) come through as
        // "transient spawn error for '...'" and must NOT trip the cache.
        let test_errors = [
            ("failed to spawn 'nmap' — is it installed?", true),
            (
                "transient spawn error for 'nmap' (WouldBlock): Resource temporarily unavailable",
                false,
            ),
            ("tool not installed: certipy", false),
            ("command not found", false),
            ("permission denied", false),
        ];

        for (err_str, expected_unavailable) in test_errors {
            let is_unavailable = is_tool_unavailable_error(err_str);
            assert_eq!(
                is_unavailable,
                expected_unavailable,
                "Error '{}' should {}mark tool as unavailable",
                err_str,
                if expected_unavailable { "" } else { "NOT " }
            );
        }
    }

    #[test]
    fn tool_exec_request_deserialize_rejects_missing_required() {
        // Missing call_id should fail
        let json = r#"{
            "task_id": "task_001",
            "tool_name": "nmap",
            "arguments": {}
        }"#;
        let result: Result<ToolExecRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn tool_exec_request_deserialize_rejects_missing_tool_name() {
        let json = r#"{
            "call_id": "call_001",
            "task_id": "task_001",
            "arguments": {}
        }"#;
        let result: Result<ToolExecRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn unavailable_tool_response_contains_tool_name() {
        let resp = unavailable_tool_response("certipy", "call_42");
        assert_eq!(resp.call_id, "call_42");
        assert_eq!(resp.output, "");
        assert!(resp.discoveries.is_none());
        let err = resp.error.as_deref().unwrap();
        assert!(err.contains("certipy"));
        assert!(err.contains("not installed"));
        assert!(err.contains("Do not call this tool again"));
    }

    #[test]
    fn unavailable_tool_response_round_trips_via_json() {
        let resp = unavailable_tool_response("hashcat", "abc");
        let json = serde_json::to_string(&resp).unwrap();
        // discoveries omitted when None
        assert!(!json.contains("discoveries"));
        assert!(json.contains("hashcat"));
    }

    #[test]
    fn is_tool_unavailable_error_classifies_spawn_failures() {
        // Only the executor's ENOENT-specific wording — with the em-dash
        // and question mark — counts. That phrasing is unlikely to appear
        // in any real tool output naturally.
        assert!(is_tool_unavailable_error(
            "failed to spawn 'nmap' — is it installed?"
        ));
        assert!(is_tool_unavailable_error(
            "failed to spawn 'certipy' — is it installed?"
        ));
    }

    #[test]
    fn is_tool_unavailable_error_rejects_unrelated_errors() {
        assert!(!is_tool_unavailable_error("connection refused"));
        assert!(!is_tool_unavailable_error("permission denied"));
        assert!(!is_tool_unavailable_error("invalid arguments"));
        assert!(!is_tool_unavailable_error("command not found"));
        // The tighter classifier rejects these — they lack the specific
        // em-dash + question-mark tail. The old, looser matcher tripped
        // on "not installed" appearing anywhere in tool output.
        assert!(!is_tool_unavailable_error("tool not installed: certipy"));
        assert!(!is_tool_unavailable_error(
            "failed to spawn process: No such file"
        ));
        // The executor's transient-spawn wording MUST NOT poison the cache
        // — that was the whole bug this fix was written to close.
        assert!(!is_tool_unavailable_error(
            "transient spawn error for 'nmap' (WouldBlock): Resource temporarily unavailable"
        ));
        assert!(!is_tool_unavailable_error(
            "transient spawn error for 'nmap' (OutOfMemory): Cannot allocate memory"
        ));
    }

    #[test]
    fn discoveries_or_none_drops_empty_object() {
        let v = serde_json::json!({});
        assert!(discoveries_or_none(v).is_none());
    }

    #[test]
    fn discoveries_or_none_drops_non_object() {
        // Arrays / strings / numbers should all be treated as "no discoveries"
        assert!(discoveries_or_none(serde_json::json!(null)).is_none());
        assert!(discoveries_or_none(serde_json::json!([])).is_none());
        assert!(discoveries_or_none(serde_json::json!("hi")).is_none());
        assert!(discoveries_or_none(serde_json::json!(42)).is_none());
    }

    #[test]
    fn discoveries_or_none_keeps_non_empty_object() {
        let v = serde_json::json!({"hosts": [{"ip": "192.168.58.10"}]});
        let kept = discoveries_or_none(v.clone());
        assert!(kept.is_some());
        assert_eq!(kept.unwrap(), v);
    }

    #[test]
    fn discoveries_or_none_keeps_empty_array_inside_object() {
        // Object with even an empty array is still non-empty at the top level
        let v = serde_json::json!({"credentials": []});
        let kept = discoveries_or_none(v.clone());
        assert_eq!(kept, Some(v));
    }

    #[test]
    fn tool_exit_error_renders_exit_code() {
        assert_eq!(tool_exit_error(Some(0)), "tool exited with code Some(0)");
        assert_eq!(tool_exit_error(Some(1)), "tool exited with code Some(1)");
        assert_eq!(tool_exit_error(None), "tool exited with code None");
    }

    #[test]
    fn build_success_response_success_omits_error() {
        let resp = build_success_response("call-1", true, Some(0), "ok\n".into(), None);
        assert_eq!(resp.call_id, "call-1");
        assert_eq!(resp.output, "ok\n");
        assert!(resp.error.is_none());
        assert!(resp.discoveries.is_none());
    }

    #[test]
    fn build_success_response_failure_records_exit_code() {
        let resp = build_success_response("call-2", false, Some(2), "err\n".into(), None);
        assert!(!resp.error.as_deref().unwrap().is_empty());
        assert!(resp.error.as_deref().unwrap().contains("Some(2)"));
        assert_eq!(resp.output, "err\n");
    }

    #[test]
    fn build_success_response_failure_with_no_exit_code() {
        // Tool was killed without an exit code (signal, etc.)
        let resp = build_success_response("call-3", false, None, String::new(), None);
        let err = resp.error.as_deref().unwrap();
        assert!(err.contains("None"));
    }

    #[test]
    fn build_success_response_carries_discoveries_when_present() {
        let disc = serde_json::json!({"hosts": [{"ip": "192.168.58.10"}]});
        let resp = build_success_response(
            "call-4",
            true,
            Some(0),
            "scan output".into(),
            Some(disc.clone()),
        );
        assert_eq!(resp.discoveries.as_ref().unwrap()["hosts"], disc["hosts"]);
        assert!(resp.error.is_none());
    }

    #[test]
    fn build_success_response_serializes_with_omitted_discoveries_when_none() {
        let resp = build_success_response("call-5", true, Some(0), "ok".into(), None);
        let json = serde_json::to_string(&resp).unwrap();
        // discoveries field skipped when None
        assert!(!json.contains("discoveries"));
    }

    #[test]
    fn build_error_response_zeroes_output_and_no_discoveries() {
        let resp = build_error_response("call-6", "spawn failure".into(), None);
        assert_eq!(resp.call_id, "call-6");
        assert!(resp.output.is_empty());
        assert!(resp.discoveries.is_none());
        assert_eq!(resp.error.as_deref(), Some("spawn failure"));
    }

    #[test]
    fn build_error_response_serializes_without_discoveries_field() {
        let resp = build_error_response("call-7", "bad".into(), None);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("discoveries"));
        assert!(json.contains("bad"));
    }

    #[test]
    fn busy_current_task_uses_colon_delimiter() {
        assert_eq!(
            busy_current_task("nmap_scan", "nmap_scan_abc123"),
            "nmap_scan:nmap_scan_abc123"
        );
    }

    #[test]
    fn busy_current_task_handles_empty_call_id() {
        // We never expect an empty call_id, but the format should be defensive
        assert_eq!(busy_current_task("whoami", ""), "whoami:");
    }

    #[test]
    fn count_discovery_entries_returns_per_type_counts() {
        let discoveries = serde_json::json!({
            "hosts": [{"ip": "192.168.58.10"}, {"ip": "192.168.58.11"}],
            "credentials": [{"username": "alice"}],
        });
        let mut entries = count_discovery_entries(&discoveries);
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            entries,
            vec![("credentials".to_string(), 1), ("hosts".to_string(), 2)],
        );
    }

    #[test]
    fn count_discovery_entries_skips_empty_arrays() {
        let discoveries = serde_json::json!({
            "hosts": [],
            "credentials": [{"username": "alice"}],
        });
        let entries = count_discovery_entries(&discoveries);
        assert_eq!(entries, vec![("credentials".to_string(), 1)]);
    }

    #[test]
    fn count_discovery_entries_skips_non_array_fields() {
        let discoveries = serde_json::json!({
            "hosts": "not-an-array",
            "credentials": [{"username": "alice"}],
        });
        let entries = count_discovery_entries(&discoveries);
        assert_eq!(entries, vec![("credentials".to_string(), 1)]);
    }

    #[test]
    fn count_discovery_entries_returns_empty_for_non_object() {
        assert!(count_discovery_entries(&serde_json::json!([])).is_empty());
        assert!(count_discovery_entries(&serde_json::json!("hi")).is_empty());
        assert!(count_discovery_entries(&serde_json::json!(42)).is_empty());
        assert!(count_discovery_entries(&serde_json::json!(null)).is_empty());
    }

    #[test]
    fn count_discovery_entries_returns_empty_for_empty_object() {
        assert!(count_discovery_entries(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn build_success_and_error_responses_share_call_id_field() {
        let s = build_success_response("xyz", true, Some(0), "ok".into(), None);
        let e = build_error_response("xyz", "bad".into(), None);
        let sj: serde_json::Value = serde_json::to_value(&s).unwrap();
        let ej: serde_json::Value = serde_json::to_value(&e).unwrap();
        assert_eq!(sj["call_id"], "xyz");
        assert_eq!(ej["call_id"], "xyz");
    }
}
