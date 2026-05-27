//! Ares Orchestrator — Rust-native orchestration loop.
//!
//! Startup sequence:
//!   1. Load config from env vars
//!   2. Connect to Redis
//!   3. Acquire the operation lock
//!   4. Load shared state from Redis
//!   5. Spawn background tasks: heartbeat monitor, result consumer, deferred
//!      processor, cost summary, automation tasks, exploitation workflow,
//!      discovery poller, state refresh
//!   6. Enter the main orchestration loop

mod automation;
mod automation_spawner;
#[cfg(feature = "blue")]
mod blue;
mod bootstrap;
pub(crate) mod callback_handler;
mod completion;
mod config;
mod cost_summary;
mod deferred;
mod dispatcher;
mod exploitation;
mod llm_runner;
mod monitoring;
mod output_extraction;
pub(crate) mod recovery;
mod result_processing;
mod results;
mod routing;
pub(crate) mod state;
pub(crate) mod strategy;
mod task_queue;
mod throttling;
mod tool_dispatcher;

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::signal;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use self::automation_spawner::spawn_automation_tasks;
use self::bootstrap::{bootstrap_meta, dispatch_initial_recon};
use self::config::OrchestratorConfig;
use self::cost_summary::spawn_cost_summary;
use self::deferred::DeferredQueue;
use self::dispatcher::Dispatcher;
use self::monitoring::{spawn_heartbeat_monitor, spawn_lock_keeper, AgentRegistry};
use self::results::spawn_result_consumer;
use self::routing::ActiveTaskTracker;
use self::state::SharedState;
use self::task_queue::TaskQueue;
use self::throttling::Throttler;

pub async fn run() -> Result<()> {
    let _telemetry = ares_core::telemetry::init_telemetry(
        ares_core::telemetry::TelemetryConfig::new("ares-orchestrator"),
    );
    run_inner().await
}

async fn run_inner() -> Result<()> {
    info!(
        version = env!("CARGO_PKG_VERSION"),
        "ares-orchestrator starting"
    );

    #[cfg(feature = "blue")]
    if std::env::var("ARES_BLUE_ONLY").as_deref() == Ok("1") {
        return run_blue_only().await;
    }

    // Load the YAML config first (optional — provides agent definitions, vuln priorities,
    // strategy settings, etc.). Must be loaded before OrchestratorConfig so strategy
    // resolution can merge YAML values.
    let ares_config = match ares_core::config::AresConfig::from_env() {
        Ok(cfg) => {
            info!(
                config_name = %cfg.operation.name,
                agent_roles = cfg.agents.len(),
                "Loaded YAML config"
            );
            Some(Arc::new(cfg))
        }
        Err(e) => {
            info!("No YAML config loaded (using env vars only): {e}");
            None
        }
    };

    let config = Arc::new(
        OrchestratorConfig::from_env_with_yaml(ares_config.as_deref())
            .context("Failed to load config from environment")?,
    );

    info!(
        operation_id = %config.operation_id,
        max_concurrent = config.max_concurrent_tasks,
        has_yaml_config = ares_config.is_some(),
        listener_ip = config.listener_ip.as_deref().unwrap_or("none"),
        strategy = ?config.strategy.preset,
        "Configuration loaded"
    );

    // Install the operation scope so `ares_tools::dispatch` rejects single-IP
    // tool invocations against hosts the operator never authorized. Empty
    // target_ips → unrestricted (legacy/test launches that didn't pass IPs).
    let scope = ares_tools::scope::OperationScope::new(config.target_ips.clone());
    ares_tools::scope::init_scope(scope);
    if !config.target_ips.is_empty() {
        info!(
            target_ips = %config.target_ips.join(","),
            "Installed operation scope — out-of-scope single-IP tool calls will be rejected"
        );
    }

    let queue = TaskQueue::connect(&config.redis_url, &config.nats_url)
        .await
        .context("Failed to connect to Redis/NATS")?;

    let acquired = queue
        .try_acquire_lock(&config.operation_id, config.lock_ttl)
        .await?;
    if !acquired {
        anyhow::bail!(
            "Operation {} is locked by another orchestrator",
            config.operation_id
        );
    }

    let mut shared_state = SharedState::new(config.operation_id.clone());

    // install a Nats-backed op-state recorder when NATS is
    // available. Redis remains authoritative until Phase 4; emit failures are
    // logged (see `emit_op_state`) but never abort the op.
    let nats_broker = queue.nats_broker();
    if let Some(broker) = nats_broker.clone() {
        shared_state.set_recorder(std::sync::Arc::new(
            ares_core::op_state_log::OpStateRecorder::nats(std::sync::Arc::new(broker)),
        ));
        info!("Op-state event log enabled (JetStream ARES_OPSTATE)");
    } else {
        info!("Op-state event log disabled — no NATS broker on TaskQueue");
    }

    // spawn the Postgres projector consumer when both NATS and a
    // database URL are available. The projector tails ARES_OPSTATE and
    // upserts each event into PG, replacing the manual `ares ops offload`
    // path with an always-current archive.
    let _projector_handle: Option<tokio::task::JoinHandle<()>> = match (
        nats_broker.clone(),
        std::env::var("ARES_DATABASE_URL").ok(),
    ) {
        (Some(broker), Some(database_url)) => {
            match ares_core::persistent_store::PersistentStore::connect(&database_url).await {
                Ok(store) => {
                    if let Err(e) = store.migrate().await {
                        warn!(err = %e, "Postgres projector: schema migration failed; continuing without projection");
                        None
                    } else {
                        let projector =
                            ares_core::persistent_store::OpStateProjector::new(store, broker);
                        match projector.spawn().await {
                            Ok(h) => Some(h),
                            Err(e) => {
                                warn!(err = %e, "Failed to spawn Postgres projector — events will accumulate in JetStream without PG sync");
                                None
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(err = %e, "Postgres projector: PG connect failed; continuing without projection");
                    None
                }
            }
        }
        (None, _) => None,
        (Some(_), None) => {
            debug!("ARES_DATABASE_URL not set — Postgres projector disabled");
            None
        }
    };

    shared_state.initialize_self_ips().await;

    // replay state from the JetStream event log instead of
    // loading from Redis. Falls through to Redis on failure or when the env
    // var is unset, so the default startup path is unchanged.
    let replay_enabled = std::env::var("ARES_USE_EVENT_LOG_REPLAY").as_deref() == Ok("1");
    let replayed = match (replay_enabled, nats_broker.as_ref()) {
        (true, Some(broker)) => match shared_state.load_from_event_log(broker).await {
            Ok(n) => {
                info!(events = n, "Loaded state from JetStream event log replay");
                true
            }
            Err(e) => {
                warn!(err = %e, "Event log replay failed; falling back to Redis");
                false
            }
        },
        (true, None) => {
            warn!("ARES_USE_EVENT_LOG_REPLAY=1 but no NATS broker; falling back to Redis");
            false
        }
        (false, _) => false,
    };
    if !replayed {
        shared_state
            .load_from_redis(&queue)
            .await
            .context("Failed to load state from Redis")?;
    }

    {
        let mut state = shared_state.write().await;
        if state.target_ips.is_empty() && !config.target_ips.is_empty() {
            state.target_ips = config.target_ips.clone();
            info!(
                target_domain = %config.target_domain,
                target_ips = ?config.target_ips,
                "Seeded target info from operation payload"
            );
        }
        // Seed target domain into state so automation tasks have it
        if !config.target_domain.is_empty() {
            let domain = config.target_domain.to_lowercase();
            if !state.domains.contains(&domain) {
                state.domains.push(domain.clone());
                // Also persist to Redis
                let domain_key = format!("ares:op:{}:domains", state.operation_id);
                let mut conn = queue.connection();
                let _: Result<(), _> =
                    redis::AsyncCommands::sadd(&mut conn, &domain_key, &domain).await;
                let _: Result<(), _> =
                    redis::AsyncCommands::expire(&mut conn, &domain_key, 86400i64).await;
                info!(domain = %domain, "Seeded target domain");
            }

            // Seed domain_controllers from target IPs so automation tasks
            // (AS-REP roast, Kerberoast, BloodHound, delegation enum) can fire
            // immediately without waiting for recon to report back.
            //
            // Probe ALL target IPs on port 88/389 to find every DC, then query
            // each DC's LDAP rootDSE (`defaultNamingContext`) to discover which
            // domain it serves. This eliminates the race condition where
            // automation tasks fire before recon discovers child-domain DCs
            // (e.g. child.contoso.local at 192.168.58.11 vs the parent
            // contoso.local at 192.168.58.10).
            if state.domain_controllers.is_empty() {
                let dc_map = bootstrap::discover_dc_domains(&config.target_ips, &domain).await;

                if !dc_map.is_empty() {
                    let dc_key = format!(
                        "{}:{}:{}",
                        ares_core::state::KEY_PREFIX,
                        state.operation_id,
                        ares_core::state::KEY_DC_MAP,
                    );
                    let domain_key = format!("ares:op:{}:domains", state.operation_id);
                    let mut conn = queue.connection();

                    for (dc_domain, dc_ip) in &dc_map {
                        let _: Result<(), _> =
                            redis::AsyncCommands::hset(&mut conn, &dc_key, dc_domain, dc_ip).await;
                        state
                            .domain_controllers
                            .insert(dc_domain.clone(), dc_ip.clone());

                        // Add discovered domains to the domains list so automation
                        // tasks can enumerate them (AS-REP roast, BloodHound, etc.)
                        if !state.domains.contains(dc_domain) {
                            state.domains.push(dc_domain.clone());
                            let _: Result<(), _> =
                                redis::AsyncCommands::sadd(&mut conn, &domain_key, dc_domain).await;
                        }

                        info!(
                            domain = %dc_domain,
                            dc_ip = %dc_ip,
                            "Seeded domain controller from bootstrap DC discovery"
                        );
                    }

                    let _: Result<(), _> =
                        redis::AsyncCommands::expire(&mut conn, &domain_key, 86400i64).await;

                    // Also register the credential's domain if not already mapped.
                    // The credential domain may differ from any discovered DC domain
                    // (e.g. if the credential is for a domain whose DC is behind a
                    // firewall and didn't respond to probes).
                    if let Some(ref cred) = config.initial_credential {
                        let cred_domain = cred.domain.to_lowercase();
                        if !cred_domain.is_empty()
                            && !state.domain_controllers.contains_key(&cred_domain)
                        {
                            // Use the first discovered DC as fallback for the
                            // credential's domain — better than no mapping at all.
                            let fallback_ip = &dc_map[0].1;
                            let _: Result<(), _> = redis::AsyncCommands::hset(
                                &mut conn,
                                &dc_key,
                                &cred_domain,
                                fallback_ip,
                            )
                            .await;
                            state
                                .domain_controllers
                                .insert(cred_domain.clone(), fallback_ip.clone());
                            if !state.domains.contains(&cred_domain) {
                                state.domains.push(cred_domain.clone());
                                let _: Result<(), _> = redis::AsyncCommands::sadd(
                                    &mut conn,
                                    &domain_key,
                                    &cred_domain,
                                )
                                .await;
                            }
                            info!(
                                cred_domain = %cred_domain,
                                dc_ip = %fallback_ip,
                                "Registered credential domain with fallback DC"
                            );
                        }
                    }
                } else {
                    warn!("No target IP responded on port 88/389 — DC will be discovered by recon");
                }
            }

            // Seed placeholder hosts for ALL target IPs so they appear in the
            // host list before recon runs and detect_dc() on service results
            // can trigger domain extraction.
            {
                let host_key = format!(
                    "{}:{}:{}",
                    ares_core::state::KEY_PREFIX,
                    state.operation_id,
                    ares_core::state::KEY_HOSTS,
                );
                let mut conn = queue.connection();
                for ip in &config.target_ips {
                    if !state.hosts.iter().any(|h| h.ip == *ip) {
                        let placeholder = ares_core::models::Host {
                            ip: ip.clone(),
                            hostname: String::new(),
                            os: String::new(),
                            roles: vec![],
                            services: vec![],
                            is_dc: false,
                            owned: false,
                        };
                        let data = serde_json::to_string(&placeholder).unwrap_or_default();
                        let _: Result<(), _> =
                            redis::AsyncCommands::rpush(&mut conn, &host_key, &data).await;
                        state.hosts.push(placeholder);
                    }
                }
                let _: Result<(), _> =
                    redis::AsyncCommands::expire(&mut conn, &host_key, 86400i64).await;
                info!(
                    count = config.target_ips.len(),
                    "Seeded placeholder hosts for all target IPs"
                );
            }
        }
    }

    if let Some(ref cred) = config.initial_credential {
        let credential = ares_core::models::Credential {
            id: uuid::Uuid::new_v4().to_string(),
            username: cred.username.clone(),
            password: cred.password.clone(),
            domain: cred.domain.clone(),
            source: "initial".to_string(),
            discovered_at: Some(chrono::Utc::now()),
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        };
        match shared_state.publish_credential(&queue, credential).await {
            Ok(true) => info!(
                username = %cred.username,
                domain = %cred.domain,
                "Seeded initial credential"
            ),
            Ok(false) => info!("Initial credential already exists (dedup)"),
            Err(e) => warn!("Failed to seed initial credential: {e}"),
        }
    }

    // Write operation metadata to Redis so workers can discover us
    bootstrap_meta(&queue, &config).await?;

    let tracker = ActiveTaskTracker::new();
    let registry = AgentRegistry::new();
    let throttler = Arc::new(Throttler::new(config.clone(), tracker.clone()));
    let deferred = Arc::new(DeferredQueue::new(queue.clone(), config.clone()));
    if let Err(e) = deferred.reconcile_total().await {
        warn!(err = %e, "Deferred queue counter reconcile failed at startup");
    }

    // Priority: ARES_LLM_MODEL env var > config YAML agents.orchestrator.model
    let model_spec = std::env::var("ARES_LLM_MODEL").ok().or_else(|| {
        let config_path = std::env::var("ARES_CONFIG")
            .unwrap_or_else(|_| "/ares/config/ares.yaml".to_string());
        std::fs::read_to_string(&config_path)
            .ok()
            .and_then(|content| {
                let yaml: serde_yaml::Value = serde_yaml::from_str(&content).ok()?;
                let model = yaml["agents"]["orchestrator"]["model"].as_str()?;
                // Prefix with "openai/" if no provider prefix present
                let spec = if model.contains('/') {
                    model.to_string()
                } else {
                    format!("openai/{model}")
                };
                info!(config = %config_path, model = %spec, "Model loaded from config YAML");
                Some(spec)
            })
    }).context("No LLM model configured — set ARES_LLM_MODEL or agents.orchestrator.model in config YAML")?;
    let (provider, model_name) =
        ares_llm::create_provider(&model_spec).context("Failed to create LLM provider")?;

    // Fail fast on org/auth misconfigurations before queueing any tasks. A
    // typical pitfall: `gpt-5.2` defaults are org-allowlisted at OpenAI, so
    // submitting a multi-host op against a non-allowlisted key would silently
    // burn through dispatch → LLM → 403 on every single task. A single
    // pre-flight call surfaces the error once, with a hint pointing at
    // `OPENAI_ORG_ID` / `ARES_LLM_MODEL`.
    if let Err(e) = preflight_llm_provider(provider.as_ref(), &model_name).await {
        error!(
            model = %model_name,
            "LLM preflight failed: {e:#} — aborting startup. Set ARES_LLM_MODEL to a widely-available model (e.g. openai/gpt-4o-mini) or ensure the org tied to the API key has access to this model."
        );
        return Err(e.context(format!("LLM preflight failed for model '{model_name}'")));
    }
    info!(model = %model_name, "LLM preflight ok");

    // Credential auth throttle — prevents AD account lockout by rate-limiting
    // auth-bearing tool calls per credential. Max 3 attempts per 30s window.
    // AD lockout: 3 bad attempts / 30 min. With multiple concurrent agents,
    // even correct passwords can fail if the account is already locked.
    let auth_throttle = tool_dispatcher::AuthThrottle::new(3, std::time::Duration::from_secs(30));

    // Choose tool dispatch strategy:
    // ARES_TOOL_DISPATCH=local → in-process via ares_tools::dispatch()
    // default → Redis queue for worker consumption (ares:tool_exec:{role})
    let tool_disp: Arc<dyn ares_llm::ToolDispatcher> =
        if std::env::var("ARES_TOOL_DISPATCH").as_deref() == Ok("local") {
            info!("Tool dispatch: local (in-process via ares-tools)");
            Arc::new(
                tool_dispatcher::LocalToolDispatcher::new(
                    queue.clone(),
                    config.operation_id.clone(),
                    auth_throttle.clone(),
                )
                .with_state(shared_state.clone()),
            )
        } else {
            info!("Tool dispatch: Redis queue (ares:tool_exec:{{role}})");
            Arc::new(
                tool_dispatcher::RedisToolDispatcher::new(
                    queue.clone(),
                    config.operation_id.clone(),
                    auth_throttle.clone(),
                )
                .with_state(shared_state.clone()),
            )
        };

    // Build sorted technique priorities for the LLM system prompt.
    let mut technique_priorities: Vec<(String, i32)> = config
        .strategy
        .weights
        .iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    technique_priorities.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));

    let llm_runner = Arc::new(llm_runner::LlmTaskRunner::new(
        provider,
        model_name.clone(),
        tool_disp,
        shared_state.clone(),
        config.strategy.llm_temperature,
        technique_priorities,
        config.listener_ip.clone().unwrap_or_default(),
    ));
    info!(
        model = %model_name,
        "LLM runner initialized — Rust drives all agent loops"
    );

    let dispatcher = Arc::new(Dispatcher::new(dispatcher::DispatcherDeps {
        queue: queue.clone(),
        tracker: tracker.clone(),
        throttler: throttler.clone(),
        deferred: deferred.clone(),
        state: shared_state.clone(),
        config: config.clone(),
        ares_config: ares_config.clone(),
        llm_runner: llm_runner.clone(),
    }));

    // Deferred initialization: the handler needs the dispatcher, which contains
    // the llm_runner, creating a circular dependency. OnceLock breaks the cycle.
    let callback_handler = Arc::new(
        callback_handler::OrchestratorCallbackHandler::new(shared_state.clone(), queue.clone())
            .with_dispatcher(dispatcher.clone()),
    );
    llm_runner.set_callback_handler(callback_handler);
    info!("Orchestrator callback handler wired (query + dispatch tools)");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Core infrastructure — lock keeper runs independently to prevent
    // lock expiry even if heartbeat sweeps or Redis calls hang.
    let lock_handle = spawn_lock_keeper(queue.clone(), config.clone(), shutdown_rx.clone());

    let hb_handle = spawn_heartbeat_monitor(
        queue.clone(),
        registry.clone(),
        tracker.clone(),
        dispatcher.credential_inflight.clone(),
        shared_state.clone(),
        config.clone(),
        shutdown_rx.clone(),
    );

    let (_result_handle, mut result_rx) = spawn_result_consumer(
        queue.clone(),
        tracker.clone(),
        dispatcher.credential_inflight.clone(),
        config.clone(),
        shutdown_rx.clone(),
    );

    let deferred_handle = deferred::spawn_deferred_processor(
        deferred.clone(),
        dispatcher.clone(),
        throttler.clone(),
        config.clone(),
        shutdown_rx.clone(),
    );

    let cost_handle = spawn_cost_summary(queue.clone(), config.clone(), shutdown_rx.clone());

    // Candidate-domain probe worker — verifies hostname-inferred domains
    // (e.g. `child.contoso.local` derived from `host.child.contoso.local`) via
    // `_ldap._tcp.dc._msdcs.<fqdn>` SRV lookups before promoting them.
    let probe_ctx = state::domain_probe::DomainProbeContext {
        state: shared_state.clone(),
        queue: queue.clone(),
        prober: Arc::new(state::domain_probe::DnsSrvProber::from_system()),
    };
    let probe_handle =
        state::domain_probe::spawn_domain_probe_worker(probe_ctx, shutdown_rx.clone());

    // Exploitation workflow
    let exploit_disp = dispatcher.clone();
    let exploit_shutdown = shutdown_rx.clone();
    let exploit_handle = tokio::spawn(async move {
        exploitation::exploitation_workflow(exploit_disp, exploit_shutdown).await
    });

    // Discovery poller
    let disc_disp = dispatcher.clone();
    let disc_shutdown = shutdown_rx.clone();
    let disc_handle =
        tokio::spawn(
            async move { result_processing::discovery_poller(disc_disp, disc_shutdown).await },
        );

    // State refresh
    let refresh_disp = dispatcher.clone();
    let refresh_shutdown = shutdown_rx.clone();
    let refresh_handle =
        tokio::spawn(
            async move { automation::state_refresh(refresh_disp, refresh_shutdown).await },
        );

    let auto_handles = spawn_automation_tasks(dispatcher.clone(), shutdown_rx.clone());

    // Inject observability URLs from YAML config into env vars (blue tools read env vars).
    #[cfg(feature = "blue")]
    if let Some(ref cfg) = ares_config {
        if let Some(ref obs) = cfg.observability {
            if !obs.loki_url.is_empty() && std::env::var("LOKI_URL").is_err() {
                std::env::set_var("LOKI_URL", &obs.loki_url);
            }
            if !obs.loki_auth_token.is_empty() && std::env::var("LOKI_AUTH_TOKEN").is_err() {
                std::env::set_var("LOKI_AUTH_TOKEN", &obs.loki_auth_token);
            }
            if !obs.prometheus_url.is_empty() && std::env::var("PROMETHEUS_URL").is_err() {
                std::env::set_var("PROMETHEUS_URL", &obs.prometheus_url);
            }
        }
    }
    #[cfg(feature = "blue")]
    let blue_handle = if std::env::var("ARES_BLUE_ENABLED").as_deref() == Ok("1") {
        // Create a separate LLM provider for the blue team
        let blue_model_spec = std::env::var("ARES_BLUE_LLM_MODEL")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| model_spec.clone());
        let (blue_provider, blue_model) = ares_llm::create_provider(&blue_model_spec)
            .context("Failed to create blue team LLM provider")?;

        let blue_disp: Arc<dyn ares_llm::ToolDispatcher> =
            if std::env::var("ARES_TOOL_DISPATCH").as_deref() == Ok("local") {
                Arc::new(tool_dispatcher::LocalToolDispatcher::new(
                    queue.clone(),
                    config.operation_id.clone(),
                    auth_throttle.clone(),
                ))
            } else {
                Arc::new(tool_dispatcher::RedisToolDispatcher::new(
                    queue.clone(),
                    config.operation_id.clone(),
                    auth_throttle.clone(),
                ))
            };

        info!(model = %blue_model, "Starting blue team orchestrator");
        Some((
            blue::spawn_blue_orchestrator(
                blue_provider,
                blue_model,
                blue_disp,
                config.redis_url.clone(),
                config.nats_url.clone(),
                shutdown_rx.clone(),
            ),
            blue::spawn_blue_auto_submit(
                queue.clone(),
                shared_state.clone(),
                config.clone(),
                blue_model_spec,
                shutdown_rx.clone(),
            ),
        ))
    } else {
        None
    };
    #[cfg(not(feature = "blue"))]
    let blue_handle: Option<(tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>)> = None;

    {
        let recovery_mgr = recovery::OperationRecoveryManager::new(
            config.redis_url.clone(),
            config.nats_url.clone(),
        );
        match recovery_mgr.recover(&config.operation_id).await {
            Ok(recovered) => {
                if !recovered.requeued_task_ids.is_empty() || !recovered.failed_task_ids.is_empty()
                {
                    info!(
                        requeued = recovered.requeued_task_ids.len(),
                        failed = recovered.failed_task_ids.len(),
                        "Recovery: re-dispatching interrupted tasks via LLM submission"
                    );
                }
                for task in recovered.tasks_to_redispatch {
                    match dispatcher
                        .do_submit(&task.task_type, &task.target_role, task.payload, 1)
                        .await
                    {
                        Ok(Some(tid)) => {
                            info!(
                                task_id = %tid,
                                task_type = %task.task_type,
                                role = %task.target_role,
                                retry = task.retry_count,
                                "Recovery: re-dispatched task via LLM runner"
                            );
                        }
                        Ok(None) => {
                            warn!(
                                task_type = %task.task_type,
                                role = %task.target_role,
                                "Recovery: task deferred or dropped during re-dispatch"
                            );
                        }
                        Err(e) => {
                            warn!(
                                task_type = %task.task_type,
                                err = %e,
                                "Recovery: failed to re-dispatch task"
                            );
                        }
                    }
                }
            }
            Err(e) => {
                // Recovery failure is non-fatal — we already loaded state above
                warn!(err = %e, "Recovery check failed (non-fatal, continuing)");
            }
        }
    }

    // On restart (e.g. re-running with BLUE_ENABLED after a completed op),
    // the previous run's stop signal may still be in Redis. Clear it so the
    // main loop doesn't exit immediately.
    {
        let mut conn = queue.connection();
        let stop_key = ares_core::state::build_key(&config.operation_id, "stop_requested");
        let _: Result<(), _> = redis::AsyncCommands::del(&mut conn, &stop_key).await;
    }

    let completion_disp = dispatcher.clone();
    let completion_state = shared_state.clone();
    let completion_shutdown = shutdown_rx.clone();
    let completion_handle = tokio::spawn(async move {
        completion::wait_for_completion(
            &completion_state,
            &completion_disp,
            completion_shutdown,
            std::time::Duration::from_secs(
                ares_config
                    .as_ref()
                    .map(|c| c.timeouts.operation_timeout)
                    .filter(|&t| t > 0)
                    .unwrap_or(7200),
            ),
            std::time::Duration::from_secs(10),
        )
        .await;
        info!("Completion monitor finished — operation complete");
    });

    info!(
        operation_id = %config.operation_id,
        automation_tasks = auto_handles.len(),
        "Orchestration loop started — all background tasks running"
    );

    // Wait briefly for workers to start and publish their tool inventories,
    // then warn loudly about any critical missing tools.
    {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let missing = monitoring::preflight_tool_check(&mut queue.connection()).await;
        if !missing.is_empty() {
            for (role, tools) in &missing {
                warn!(
                    role = %role,
                    missing = ?tools,
                    "PREFLIGHT: worker is missing critical tools — operations will be degraded"
                );
            }
        } else {
            info!("Preflight tool check passed — all critical tools available");
        }
    }

    if !config.target_ips.is_empty() {
        let recon_count = dispatch_initial_recon(&dispatcher, &config).await;
        info!(tasks = recon_count, "Initial recon dispatched");
    } else {
        warn!("No target IPs configured — skipping initial recon dispatch");
    }

    let mut stop_check = tokio::time::interval(std::time::Duration::from_secs(5));
    stop_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            // Process completed task results
            result = result_rx.recv() => {
                match result {
                    Some(completed) => {
                        result_processing::process_completed_task(
                            &completed,
                            &dispatcher,
                            &throttler,
                        ).await;
                    }
                    None => {
                        // Result consumer died — channel closed.
                        // Respawn it after a brief delay.
                        error!("Result consumer channel closed unexpectedly — restarting consumer");
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        let (_new_handle, new_rx) = spawn_result_consumer(
                            queue.clone(),
                            tracker.clone(),
                            dispatcher.credential_inflight.clone(),
                            config.clone(),
                            shutdown_rx.clone(),
                        );
                        result_rx = new_rx;
                    }
                }
            }

            // Poll for remote stop signal from `ares ops stop`
            _ = stop_check.tick() => {
                let mut conn = queue.connection();
                match ares_core::state::is_stop_requested(&mut conn, &config.operation_id).await {
                    Ok(true) => {
                        info!("Remote stop requested via Redis — shutting down");
                        break;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        warn!(err = %e, "Failed to check stop signal");
                    }
                }
            }

            // Graceful shutdown on SIGTERM / SIGINT
            _ = signal::ctrl_c() => {
                info!("Shutdown signal received");
                break;
            }
        }
    }

    info!("Shutting down background tasks...");
    let _ = shutdown_tx.send(true);

    // Blue investigations need time to finalize: score_against_ground_truth,
    // set_status("completed"), release_lock, generate_report. 10s was too short.
    let shutdown_timeout = std::time::Duration::from_secs(120);
    tokio::select! {
        _ = async {
            let _ = tokio::join!(
                lock_handle,
                hb_handle,
                deferred_handle,
                cost_handle,
                probe_handle,
                exploit_handle,
                disc_handle,
                refresh_handle,
                completion_handle,
            );
            for h in auto_handles {
                let _ = h.await;
            }
            if let Some((h, auto)) = blue_handle {
                let _ = h.await;
                let _ = auto.await;
            }
        } => {
            info!("All background tasks stopped");
        }
        _ = tokio::time::sleep(shutdown_timeout) => {
            warn!("Background task shutdown timed out");
        }
    }

    // Write completion metadata, status key, clear lock and active pointer.
    {
        let mut conn = queue.connection();
        let has_da = shared_state.read().await.has_domain_admin;
        let status = if has_da { "completed" } else { "stopped" };
        match ares_core::state::finalize_operation(&mut conn, &config.operation_id, status).await {
            Ok(()) => info!(
                operation_id = %config.operation_id,
                status = status,
                "Operation finalized in Redis"
            ),
            Err(e) => warn!(
                operation_id = %config.operation_id,
                err = %e,
                "Failed to finalize operation in Redis"
            ),
        }

        // Auto-generate the red team report and cache it at ares:op:{id}:report
        // so `ares ops report` / `task ec2:report` returns instantly from cache,
        // and write a markdown file to disk for direct pickup.
        match crate::ops::report::generate_and_cache_report(&mut conn, &config.operation_id).await {
            Ok(report) => {
                let output_dir =
                    std::env::var("ARES_REPORT_DIR").unwrap_or_else(|_| "/tmp/reports".to_string());
                let dir = format!("{output_dir}/red");
                let path = format!("{dir}/{}.md", config.operation_id);
                match std::fs::create_dir_all(&dir).and_then(|_| std::fs::write(&path, &report)) {
                    Ok(()) => info!(
                        operation_id = %config.operation_id,
                        path = %path,
                        bytes = report.len(),
                        "Auto-generated red team report"
                    ),
                    Err(e) => warn!(
                        operation_id = %config.operation_id,
                        path = %path,
                        err = %e,
                        "Failed to write auto-generated report to disk (still cached in Redis)"
                    ),
                }
            }
            Err(e) => warn!(
                operation_id = %config.operation_id,
                err = %e,
                "Failed to auto-generate red team report on completion"
            ),
        }
    }

    info!("ares-orchestrator stopped");
    Ok(())
}

/// Issue a minimal LLM chat request to verify the API key + model + org
/// permissions are good before queueing any tasks. The response content is
/// discarded. A non-retryable error (auth, org-restricted model, bad model
/// name) aborts startup; a retryable error (network, 5xx, rate limit) is
/// treated as a transient upstream blip and only warns.
async fn preflight_llm_provider(
    provider: &dyn ares_llm::LlmProvider,
    model_name: &str,
) -> Result<()> {
    use ares_llm::{ChatMessage, LlmError, LlmRequest, Role};

    // If the operator explicitly opts out (air-gapped tests, recorded
    // fixtures), skip the network call.
    if std::env::var("ARES_LLM_PREFLIGHT_SKIP").as_deref() == Ok("1") {
        info!("ARES_LLM_PREFLIGHT_SKIP=1; skipping LLM preflight ping");
        return Ok(());
    }

    let mut req = LlmRequest::new(model_name);
    // OpenAI reasoning models (gpt-5*, o1*, o3*, etc.) count internal
    // reasoning tokens against the completion budget. A budget of 1 isn't
    // enough to even emit reasoning, and the API returns a 400 "Could not
    // finish the message because max_tokens or model output limit was
    // reached" before we ever see a token of output — failing the preflight
    // for a perfectly-valid model. 64 leaves headroom for reasoning while
    // keeping the call cost negligible.
    req.max_tokens = 64;
    req.messages.push(ChatMessage::text(Role::User, "ping"));

    match provider.chat(&req).await {
        Ok(_) => Ok(()),
        Err(LlmError::AuthError(msg)) => Err(anyhow::anyhow!("authentication failed: {msg}")),
        Err(e) if !e.is_retryable() => Err(anyhow::anyhow!("LLM provider rejected preflight: {e}")),
        Err(e) => {
            warn!(err = %e, "LLM preflight returned a retryable error; continuing startup");
            Ok(())
        }
    }
}

/// Run in blue-only mode: just the investigation poller, no red team.
///
/// Requires only `ARES_REDIS_URL` and an LLM model. No operation ID needed.
#[cfg(feature = "blue")]
async fn run_blue_only() -> Result<()> {
    info!("Running in BLUE-ONLY mode (no red team orchestrator)");

    let redis_url = std::env::var("ARES_REDIS_URL")
        .or_else(|_| std::env::var("REDIS_URL"))
        .unwrap_or_else(|_| "redis://127.0.0.1:6379/0".to_string());
    let nats_url = ares_core::nats::NatsBroker::url_from_env();

    // Load YAML config for observability URLs
    if let Ok(cfg) = ares_core::config::AresConfig::from_env() {
        if let Some(ref obs) = cfg.observability {
            if !obs.loki_url.is_empty() && std::env::var("LOKI_URL").is_err() {
                std::env::set_var("LOKI_URL", &obs.loki_url);
            }
            if !obs.loki_auth_token.is_empty() && std::env::var("LOKI_AUTH_TOKEN").is_err() {
                std::env::set_var("LOKI_AUTH_TOKEN", &obs.loki_auth_token);
            }
            if !obs.prometheus_url.is_empty() && std::env::var("PROMETHEUS_URL").is_err() {
                std::env::set_var("PROMETHEUS_URL", &obs.prometheus_url);
            }
        }
    }

    let model_spec = std::env::var("ARES_LLM_MODEL")
        .or_else(|_| std::env::var("ARES_BLUE_LLM_MODEL"))
        .context("Set ARES_LLM_MODEL or ARES_BLUE_LLM_MODEL for blue-only mode")?;

    let (provider, model_name) =
        ares_llm::create_provider(&model_spec).context("Failed to create LLM provider")?;

    // Blue uses a simple Redis-based tool dispatcher (no operation-scoped auth throttle)
    let queue = self::task_queue::TaskQueue::connect(&redis_url, &nats_url)
        .await
        .context("Failed to connect to Redis/NATS")?;
    let auth_throttle = tool_dispatcher::AuthThrottle::new(3, std::time::Duration::from_secs(30));
    let blue_disp: Arc<dyn ares_llm::ToolDispatcher> =
        Arc::new(tool_dispatcher::RedisToolDispatcher::new(
            queue,
            "blue-orchestrator".to_string(),
            auth_throttle,
        ));

    info!(model = %model_name, redis = %redis_url, "Blue-only orchestrator ready");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let blue_handle = blue::spawn_blue_orchestrator(
        provider,
        model_name,
        blue_disp,
        redis_url,
        nats_url,
        shutdown_rx,
    );

    // Wait for shutdown signal
    signal::ctrl_c().await?;
    info!("Shutdown signal received");
    let _ = shutdown_tx.send(true);

    let shutdown_timeout = std::time::Duration::from_secs(120);
    tokio::select! {
        _ = blue_handle => {
            info!("Blue orchestrator stopped");
        }
        _ = tokio::time::sleep(shutdown_timeout) => {
            warn!("Blue orchestrator shutdown timed out");
        }
    }

    info!("ares-orchestrator (blue-only) stopped");
    Ok(())
}
