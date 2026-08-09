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

mod acl_graph;
mod automation;
mod automation_spawner;
#[cfg(feature = "blue")]
mod blue;
mod bootstrap;
pub(crate) mod callback_handler;
pub(crate) mod cleanup;
mod completion;
mod config;
mod cost_summary;
mod deferred;
mod dispatcher;
mod diversity;
pub(crate) mod exploitation;
pub(crate) mod flags;
pub(crate) mod llm_runner;
mod monitoring;
pub(crate) mod output_extraction;
pub(crate) mod proposals;
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
    // Op start time, for the Postgres finalize at op-end (ec2:launch flushes
    // Redis and starts a fresh orchestrator per op, so this ≈ op launch).
    let op_started_at = chrono::Utc::now();

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

    let mut config = OrchestratorConfig::from_env_with_yaml(ares_config.as_deref())
        .context("Failed to load config from environment")?;

    // When ARES_SCOPE_EXPAND_SUBNETS=1, fan target_ips out over the /24 of
    // any clustered targets. Lab launches (GOAD/CTF) pass just the known DC
    // IPs, but the actual attack surface (SQL/web/CA/workstation) lives
    // elsewhere in the same subnet. Without expansion the scope filter blocks
    // single-target tools against any host the subnet sweep discovers.
    let scope_expanded = config.expand_scope_to_subnets();
    if scope_expanded > 0 {
        info!(
            added_ips = scope_expanded,
            total_ips = config.target_ips.len(),
            "Expanded operation scope to clustered /24 subnets (ARES_SCOPE_EXPAND_SUBNETS=1)"
        );
    }

    let config = Arc::new(config);

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
        // Log just a count once expansion is in play — 5 IPs is fine to print,
        // 1270 IPs (5×254) is just noise.
        if config.target_ips.len() <= 16 {
            info!(
                target_ips = %config.target_ips.join(","),
                "Installed operation scope — out-of-scope single-IP tool calls will be rejected"
            );
        } else {
            info!(
                target_ip_count = config.target_ips.len(),
                first_ip = %config.target_ips[0],
                last_ip = %config.target_ips[config.target_ips.len() - 1],
                "Installed operation scope (expanded subnet) — out-of-scope single-IP tool calls will be rejected"
            );
        }
    }

    let queue = TaskQueue::connect(&config.redis_url, &config.nats_url)
        .await
        .context("Failed to connect to Redis/NATS")?;

    match queue
        .try_acquire_lock(&config.operation_id, config.lock_ttl)
        .await?
    {
        self::task_queue::LockAcquire::Acquired => {}
        self::task_queue::LockAcquire::Reclaimed => {
            warn!(
                operation_id = %config.operation_id,
                holder = self::task_queue::lock_holder_id(),
                "Operation lock reclaimed from a prior crashed run on this host"
            );
        }
        self::task_queue::LockAcquire::TakenOver { previous_holder } => {
            warn!(
                operation_id = %config.operation_id,
                previous_holder = %previous_holder,
                new_holder = self::task_queue::lock_holder_id(),
                "Operation lock forcibly taken over (ARES_LOCK_TAKEOVER=1)"
            );
        }
        self::task_queue::LockAcquire::Contested { current_holder } => {
            anyhow::bail!(
                "Operation {} is locked by another orchestrator (holder={}); set ARES_LOCK_TAKEOVER=1 to force takeover",
                config.operation_id,
                current_holder
            );
        }
    }

    let mut shared_state = SharedState::new(config.operation_id.clone());

    #[cfg(feature = "blue")]
    let blue_enabled = std::env::var("ARES_BLUE_ENABLED").as_deref() == Ok("1");
    #[cfg(not(feature = "blue"))]
    let blue_enabled = false;
    shared_state.set_blue_enabled(blue_enabled).await;

    if let Err(e) = ares_core::blue_invalidation::record_blue_team_enablement(
        &mut queue.connection(),
        &config.operation_id,
        blue_enabled,
    )
    .await
    {
        warn!(err = %e, "Failed to record blue-team enablement for the operation");
    }

    if let Some(cfg) = ares_config.as_deref() {
        shared_state
            .set_acl_publish_cap(cfg.operation.acl_publish_cap)
            .await;
    }

    shared_state
        .set_diversity_recording(
            config.strategy.emit_path_records,
            config.strategy.novelty_enabled,
            &config.strategy.novelty_scope,
        )
        .await;

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
    // Filter empty string: systemd-run --setenv=NAME (no value) always sets
    // NAME in the child env even when the parent has it unset, arriving as
    // literal "". Treating "" as Some(url) would drive PersistentStore::connect
    // into a doomed call every startup and log a misleading "PG connect failed".
    let _projector_handle: Option<tokio::task::JoinHandle<()>> = match (
        nats_broker.clone(),
        std::env::var("ARES_DATABASE_URL")
            .ok()
            .filter(|s| !s.is_empty()),
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

    // Build per-role provider map. The orchestrator's model is required (used
    // as fallback for any role missing an entry). All other roles default to
    // the orchestrator's model when their YAML block omits `model:`.
    //
    // Priority: ARES_LLM_MODEL env var > config YAML agents.{role}.model
    let yaml_doc: Option<serde_yaml::Value> = {
        let config_path =
            std::env::var("ARES_CONFIG").unwrap_or_else(|_| "/ares/config/ares.yaml".to_string());
        std::fs::read_to_string(&config_path)
            .ok()
            .and_then(|content| serde_yaml::from_str(&content).ok())
    };
    let env_override = std::env::var("ARES_LLM_MODEL").ok();
    let orch_spec = env_override
        .clone()
        .or_else(|| read_role_model(yaml_doc.as_ref(), "orchestrator"))
        .context(
            "No LLM model configured — set ARES_LLM_MODEL or agents.orchestrator.model in config YAML",
        )?;
    info!(model = %orch_spec, "Orchestrator model");

    let orchestrator_flags = yaml_doc
        .as_ref()
        .and_then(|doc| doc.get("orchestrator"))
        .cloned()
        .and_then(|v| serde_yaml::from_value::<ares_core::config::OrchestratorConfig>(v).ok())
        .unwrap_or_default();
    flags::init_config_defaults(orchestrator_flags);
    let (planner_on, planner_source) = flags::resolve_planner_enabled();
    let (mediation_on, mediation_source) = flags::resolve_mediation_enabled();
    info!(
        planner_enabled = planner_on,
        planner_source = planner_source.as_str(),
        mediation_enabled = mediation_on,
        mediation_source = mediation_source.as_str(),
        "Orchestrator flags"
    );

    let mut providers: std::collections::HashMap<
        ares_llm::tool_registry::AgentRole,
        llm_runner::RoleProvider,
    > = std::collections::HashMap::new();
    let role_yaml_names: &[(ares_llm::tool_registry::AgentRole, &str)] = &[
        (
            ares_llm::tool_registry::AgentRole::Orchestrator,
            "orchestrator",
        ),
        (ares_llm::tool_registry::AgentRole::Recon, "recon"),
        (
            ares_llm::tool_registry::AgentRole::CredentialAccess,
            "credential_access",
        ),
        (ares_llm::tool_registry::AgentRole::Cracker, "cracker"),
        (ares_llm::tool_registry::AgentRole::Acl, "acl"),
        (ares_llm::tool_registry::AgentRole::Privesc, "privesc"),
        (ares_llm::tool_registry::AgentRole::Lateral, "lateral"),
        (ares_llm::tool_registry::AgentRole::Coercion, "coercion"),
    ];
    let (fb_provider, fb_model_name) = ares_llm::create_provider(&orch_spec)
        .with_context(|| format!("Failed to create fallback LLM provider for '{orch_spec}'"))?;
    let fallback_provider = llm_runner::RoleProvider {
        provider: Arc::from(fb_provider),
        config: ares_llm::AgentLoopConfig::from_env(fb_model_name, config.strategy.llm_temperature),
    };

    for (role, yaml_key) in role_yaml_names {
        let spec =
            read_role_model(yaml_doc.as_ref(), yaml_key).unwrap_or_else(|| orch_spec.clone());
        let (provider, model_name) = ares_llm::create_provider(&spec)
            .with_context(|| format!("Failed to create LLM provider for role '{yaml_key}'"))?;
        let cfg = ares_llm::AgentLoopConfig::from_env(model_name, config.strategy.llm_temperature)
            .with_config_max_steps(
                ares_config
                    .as_ref()
                    .and_then(|c| c.agents.get(*yaml_key))
                    .map(|a| a.max_steps),
            )
            .with_config_max_tokens(
                ares_config
                    .as_ref()
                    .and_then(|c| c.agents.get(*yaml_key))
                    .and_then(|a| a.max_tokens),
            );
        info!(
            role = %yaml_key,
            model = %spec,
            max_steps = cfg.max_steps,
            max_tokens = cfg.max_tokens,
            "Per-role model"
        );
        providers.insert(
            *role,
            llm_runner::RoleProvider {
                provider: Arc::from(provider),
                config: cfg,
            },
        );
    }
    // Capture the fallback model name for downstream logging.
    let model_name = fallback_provider.config.model.clone();

    // Credential auth throttle — rate-limits auth-bearing tool calls per
    // credential so concurrent agents don't drive one account into lockout.
    //
    // The window is env-tunable because the safe value is a property of the
    // target domain (`lockoutObservationWindow`), not something to hardcode.
    // The previous default paired 3 attempts with 30 *seconds* while its
    // comment claimed "3 bad attempts / 30 min" and the module doc claimed
    // 60 seconds — three different numbers, none enforced as documented.
    // Defaults stay at the long-standing 3/30s so this change is a
    // documentation and tunability fix, not a silent throughput cut; raise
    // ARES_AUTH_THROTTLE_WINDOW_SECS toward the domain's real observation
    // window when spraying a lockout-enabled domain.
    let auth_throttle = tool_dispatcher::AuthThrottle::new(
        config::parse_env("ARES_AUTH_THROTTLE_MAX_ATTEMPTS", 3),
        std::time::Duration::from_secs(config::parse_env("ARES_AUTH_THROTTLE_WINDOW_SECS", 30)),
    );

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

    // Wrap the tool dispatcher so every successful mutating tool call — whether
    // LLM-driven or dispatched deterministically by an automation module — is
    // recorded to the operation's mutation journal for later teardown. One wrap
    // covers both paths because the LLM runner and every automation share this
    // same Arc via `LlmTaskRunner::tool_dispatcher()`.
    let tool_disp = cleanup::JournalingToolDispatcher::wrap(
        tool_disp,
        config.operation_id.clone(),
        queue.connection(),
    );

    // Build sorted technique priorities for the LLM system prompt.
    let mut technique_priorities: Vec<(String, i32)> = config
        .strategy
        .weights
        .iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    technique_priorities.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));

    // Snapshot the operation's target context once at runner creation so the
    // LLM system prompt stays byte-stable across every step (prefix caching).
    // Current discoveries — including target_dc_ip if recon updates it later —
    // flow through the task prompt's dynamic context block instead.
    let init_snapshot = shared_state.snapshot().await;
    let frozen_target_domain = if init_snapshot.target_domain.is_empty() {
        config.target_domain.clone()
    } else {
        init_snapshot.target_domain.clone()
    };
    let frozen_target_dc_ip = init_snapshot.target_dc_ip.clone();
    let frozen_target_dc_fqdn = init_snapshot.target_dc_fqdn.clone();
    let llm_runner = Arc::new(llm_runner::LlmTaskRunner::new(
        providers,
        fallback_provider,
        tool_disp,
        shared_state.clone(),
        technique_priorities,
        llm_runner::FrozenOpContext {
            target_domain: frozen_target_domain,
            target_dc_ip: frozen_target_dc_ip,
            target_dc_fqdn: frozen_target_dc_fqdn,
            listener_ip: config.listener_ip.clone().unwrap_or_default(),
        },
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

    let mut hb_handle = spawn_heartbeat_monitor(
        queue.clone(),
        registry.clone(),
        tracker.clone(),
        dispatcher.clone(),
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

    let proposal_sweeper_handle = if proposals::mediation_enabled() {
        info!(
            window_secs = dispatcher.proposals.window().as_secs(),
            "Orchestrator mediation ENABLED — automation dispatch routes through the orchestrator"
        );
        Some(proposals::spawn_proposal_sweeper(
            dispatcher.clone(),
            shutdown_rx.clone(),
        ))
    } else {
        None
    };

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

    let exploit_disp = dispatcher.clone();
    let exploit_shutdown = shutdown_rx.clone();
    let exploit_handle = tokio::spawn(async move {
        exploitation::exploitation_workflow(exploit_disp, exploit_shutdown).await
    });

    let disc_disp = dispatcher.clone();
    let disc_shutdown = shutdown_rx.clone();
    let disc_handle =
        tokio::spawn(
            async move { result_processing::discovery_poller(disc_disp, disc_shutdown).await },
        );

    let refresh_disp = dispatcher.clone();
    let refresh_shutdown = shutdown_rx.clone();
    let refresh_handle =
        tokio::spawn(
            async move { automation::state_refresh(refresh_disp, refresh_shutdown).await },
        );

    // Pre-op clean slate: wipe cross-op attacker-side residue (hashcat potfile,
    // ~/.nxc host/cred/share DBs + spider downloads, /tmp/ares-tickets ccaches)
    // BEFORE any automation dispatches a tool, so this op cannot "cheat" off a
    // prior op's crack/enumeration/ticket work. Complements the post-op target
    // teardown (`ares ops teardown`). Opt out with ARES_KEEP_WORKSPACE=1.
    // "Pre-op" must mean "this operation has not run anything yet", not "this
    // process just started". `load_from_redis` above rehydrates an in-progress
    // op, and restarting the orchestrator to pick up a rebuilt binary is
    // routine — so keying off process start wiped the forged inter-realm
    // ccaches and netexec enumeration the resumed op was still relying on.
    {
        let resumed = {
            let state = shared_state.read().await;
            !state.completed_tasks.is_empty()
        };
        if resumed {
            info!(
                "Skipping workspace sanitation — resuming an operation that has already run tasks"
            );
        } else {
            let report = ares_tools::sanitize::sanitize_workspace();
            info!(
                potfile_reset = report.potfile_reset,
                nxc_removed = report.nxc_paths_removed,
                ccaches_removed = report.ccaches_removed,
                "Pre-op attacker workspace sanitized"
            );
        }
    }

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
    // Resolve blue-team enablement ONCE per operation so the spawner and the
    // completion loop can't diverge. Two independent env reads at different
    // points in the orchestrator lifetime have gone out of sync in the past —
    // blue would spawn from mod.rs but the completion loop's own read of
    // ARES_BLUE_ENABLED would come back empty, so it never waited for
    // investigations to drain and blue got shot dead mid-lateral-analyst.
    #[cfg(feature = "blue")]
    let blue_handle = if blue_enabled {
        // Create a separate LLM provider for the blue team
        let blue_model_spec = std::env::var("ARES_BLUE_LLM_MODEL")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| orch_spec.clone());
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
                config.clone(),
                blue_model_spec,
                dispatcher.red_draining.clone(),
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
            blue_enabled,
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

        // Subnet sweep: when target IPs are clustered in /24s (typical for
        // lab/CTF engagements), also dispatch a sweep over each /24 to
        // discover non-DC hosts (SQL server, web server, ADCS, workstation).
        // Without this, the recon agent only ever probes the explicit IP
        // list — missing the bulk of the attack surface in lab scenarios.
        let sweep_count = bootstrap::dispatch_subnet_sweep(&dispatcher, &config).await;
        if sweep_count > 0 {
            info!(tasks = sweep_count, "Subnet sweep dispatched");
        }
    } else {
        warn!("No target IPs configured — skipping initial recon dispatch");
    }

    let mut stop_check = tokio::time::interval(std::time::Duration::from_secs(5));
    stop_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let (signal_tx, mut signal_rx) = tokio::sync::mpsc::channel::<()>(1);
    tokio::spawn(async move {
        crate::util::wait_for_shutdown_signal().await;
        let _ = signal_tx.send(()).await;
    });

    loop {
        tokio::select! {
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
                if hb_handle.is_finished() {
                    error!("Heartbeat monitor exited unexpectedly — stale-task reaping is down, restarting");
                    hb_handle = spawn_heartbeat_monitor(
                        queue.clone(),
                        registry.clone(),
                        tracker.clone(),
                        dispatcher.clone(),
                        shared_state.clone(),
                        config.clone(),
                        shutdown_rx.clone(),
                    );
                }

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
            _ = signal_rx.recv() => {
                info!("Shutdown signal received");
                break;
            }
        }
    }

    info!("Shutting down background tasks...");
    let _ = shutdown_tx.send(true);

    let shutdown_timeout = shutdown_grace(blue_enabled);
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
            if let Some(h) = proposal_sweeper_handle {
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

    // CAS release before the unconditional finalize DEL so a stray same-op
    // holder mismatch (should be impossible, but cheap to guard) doesn't
    // silently clobber someone else's lock.
    match queue.release_lock(&config.operation_id).await {
        Ok(true) => info!(
            operation_id = %config.operation_id,
            "Operation lock released on shutdown"
        ),
        Ok(false) => debug!(
            operation_id = %config.operation_id,
            "Operation lock already gone or held by another orchestrator at shutdown"
        ),
        Err(e) => warn!(
            operation_id = %config.operation_id,
            err = %e,
            "release_lock failed on shutdown"
        ),
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

        // Revert this operation's target mutations while the journal still
        // exists. `ec2:launch` flushes Redis, so the next operation's start
        // destroys the record teardown plans from — making shutdown the last
        // point at which the range can be put back.
        if cleanup::auto_teardown_enabled() {
            match cleanup::run_teardown_once(
                &mut conn,
                &config.operation_id,
                &cleanup::TeardownOptions {
                    dry_run: false,
                    only: None,
                },
            )
            .await
            {
                Ok(Some(report)) => info!(
                    operation_id = %config.operation_id,
                    total = report.total,
                    reverted = report.reverted,
                    verified = report.verified,
                    unverified = report.unverified,
                    skipped = report.skipped,
                    failed = report.failed,
                    "Post-operation teardown complete"
                ),
                Ok(None) => debug!(
                    operation_id = %config.operation_id,
                    "Post-operation teardown already ran during completion"
                ),
                Err(e) => warn!(
                    operation_id = %config.operation_id,
                    err = %e,
                    "Post-operation teardown failed — mutations remain on the target"
                ),
            }
        } else {
            info!(
                operation_id = %config.operation_id,
                "Post-operation teardown disabled by {} — target mutations left in place",
                cleanup::AUTO_TEARDOWN_ENV
            );
        }

        // Finalize the operation to the ares-history Postgres so runs stay
        // comparable (cost, domain-admin, entity counts). The live projector
        // keeps entity tables current during the op but has no completion event,
        // so it never stamps completed_at / DA / counts / cost — this is the
        // op-end finalize that fills them. No-op when ARES_DATABASE_URL is unset
        // (K8s/local); every step is fault-tolerant so a PG hiccup never fails
        // op teardown, and it's idempotent with the projector (ON CONFLICT
        // upserts on operations + the uq_* entity constraints).
        if let Some(database_url) = std::env::var("ARES_DATABASE_URL")
            .ok()
            .filter(|s| !s.is_empty())
        {
            match ares_core::persistent_store::PersistentStore::connect(&database_url).await {
                Ok(store) => {
                    let offload = {
                        let st = shared_state.read().await;
                        ares_core::persistent_store::OperationOffload {
                            operation_id: config.operation_id.clone(),
                            target_ip: config.target_ips.first().cloned(),
                            target_domain: (!config.target_domain.is_empty())
                                .then(|| config.target_domain.clone()),
                            environment: std::env::var("ARES_DEPLOYMENT")
                                .ok()
                                .filter(|s| !s.is_empty()),
                            started_at: op_started_at,
                            completed_at: Some(chrono::Utc::now()),
                            has_domain_admin: st.has_domain_admin,
                            has_golden_ticket: st.has_golden_ticket,
                            domain_admin_path: st.domain_admin_path.clone(),
                            da_hash_id: None,
                            credentials: st.credentials.clone(),
                            hashes: st.hashes.clone(),
                            hosts: st.hosts.clone(),
                            users: st.users.clone(),
                            vulnerabilities: st.discovered_vulnerabilities.clone(),
                            exploited_vulnerabilities: st.exploited_vulnerabilities.clone(),
                        }
                    };
                    match store.offload_operation(&offload).await {
                        Ok(_) => info!(
                            operation_id = %config.operation_id,
                            "Operation finalized to Postgres (ares-history)"
                        ),
                        Err(e) => warn!(
                            operation_id = %config.operation_id,
                            err = %e,
                            "PG finalize: offload_operation failed"
                        ),
                    }
                    // Token usage + cost from Redis → operations.total_cost/tokens.
                    match ares_core::token_usage::get_token_usage(&mut conn, &config.operation_id)
                        .await
                    {
                        Ok(Some(usage)) => {
                            let (total_cost, breakdown, _unpriced) =
                                ares_core::token_usage::estimate_usage_cost(&usage);
                            let model_usage = if usage.models.is_empty() {
                                serde_json::Value::Null
                            } else {
                                let mut m = serde_json::Map::new();
                                for (name, mu) in &usage.models {
                                    let cost = breakdown
                                        .iter()
                                        .find(|b| &b.model == name)
                                        .map(|b| b.cost)
                                        .unwrap_or(0.0);
                                    m.insert(
                                        name.clone(),
                                        serde_json::json!({
                                            "input_tokens": mu.input_tokens,
                                            "output_tokens": mu.output_tokens,
                                            "cost": cost,
                                        }),
                                    );
                                }
                                serde_json::Value::Object(m)
                            };
                            if let Err(e) = store
                                .update_cost(
                                    &config.operation_id,
                                    usage.input_tokens as i64,
                                    usage.output_tokens as i64,
                                    total_cost.unwrap_or(0.0),
                                    &model_usage,
                                )
                                .await
                            {
                                warn!(
                                    operation_id = %config.operation_id,
                                    err = %e,
                                    "PG finalize: update_cost failed"
                                );
                            }
                        }
                        Ok(None) => debug!(
                            operation_id = %config.operation_id,
                            "PG finalize: no token usage in Redis to record"
                        ),
                        Err(e) => warn!(
                            operation_id = %config.operation_id,
                            err = %e,
                            "PG finalize: token usage read failed"
                        ),
                    }
                }
                Err(e) => warn!(
                    operation_id = %config.operation_id,
                    err = %e,
                    "PG finalize: connect failed; operation not persisted to Postgres"
                ),
            }
        }
    }

    info!("ares-orchestrator stopped");
    Ok(())
}

/// Look up the model spec for a role from a parsed YAML doc.
///
/// Reads `agents.{role}.model`. If the value is a bare model name without a
/// provider prefix (e.g. `gpt-5.2`), prepends `openai/` so downstream
/// provider routing works.
fn read_role_model(yaml: Option<&serde_yaml::Value>, role: &str) -> Option<String> {
    let doc = yaml?;
    let model = doc["agents"][role]["model"].as_str()?;
    let spec = if model.contains('/') {
        model.to_string()
    } else {
        format!("openai/{model}")
    };
    Some(spec)
}

/// Grace period for background tasks to finish once shutdown is signalled.
///
/// Red's background tasks (heartbeat, cost tracking, probes) settle in
/// seconds, and 120s was ample for them. A blue investigation is a different
/// class of work entirely — a detection sweep plus a full LLM loop plus
/// scoring and report generation — and measures around 7-8 minutes. Under the
/// flat 120s budget any investigation still in flight when red finished was
/// killed outright.
///
/// That is not theoretical. On op-20260726-003632 an investigation started at
/// 00:51:17, the drain timed out at 00:54:58, and it died mid-sweep with zero
/// evidence recorded — leaving its status stuck at `in_progress` forever. It
/// was also the only investigation whose window covered the golden-ticket
/// phase of the attack, so the miss was a detection miss, not just a tidiness
/// problem. Red ops now finish in ~15 minutes rather than an hour, so
/// late-submitted investigations hit this constantly.
///
/// Override with `ARES_SHUTDOWN_TIMEOUT_SECS` when an operation needs longer.
fn shutdown_grace(blue_enabled: bool) -> std::time::Duration {
    const RED_ONLY_SECS: u64 = 120;
    const BLUE_DRAIN_SECS: u64 = 600;

    let default = if blue_enabled {
        BLUE_DRAIN_SECS
    } else {
        RED_ONLY_SECS
    };
    let secs = std::env::var("ARES_SHUTDOWN_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|s| *s >= 1)
        .unwrap_or(default);
    std::time::Duration::from_secs(secs)
}

/// Run in blue-only mode: just the investigation poller, no red team.
///
/// Requires only `ARES_REDIS_URL` and an LLM model. No operation ID needed.
/// Spawn an ephemeral in-process blue-orchestrator consumer, returning its join
/// handle and a shutdown sender. Lets `benchmark run` be self-contained — it
/// consumes and runs the investigation it submits without a separately-running
/// blue orchestrator, and the consumer dies with the process. Send `true` on the
/// returned sender to stop it. Uses the isolated `ARES_BLUE_TASKS` stream, so it
/// never interferes with a red fleet's `ARES_TASKS`.
#[cfg(feature = "blue")]
pub(crate) async fn spawn_inprocess_blue_consumer(
    model_spec: &str,
    redis_url: &str,
    nats_url: &str,
) -> Result<(tokio::task::JoinHandle<()>, watch::Sender<bool>)> {
    let (provider, model_name) =
        ares_llm::create_provider(model_spec).context("Failed to create LLM provider")?;
    let queue = self::task_queue::TaskQueue::connect_state_only(redis_url, nats_url)
        .await
        .context("Failed to connect to Redis/NATS for blue consumer")?;
    let auth_throttle = tool_dispatcher::AuthThrottle::new(3, std::time::Duration::from_secs(30));
    // The benchmark consumer is self-contained (no separate worker fleet). The
    // evidence validator's query-result store is a per-PROCESS static, so the
    // query and its follow-up `add_evidence` MUST run in the same process — under
    // Redis dispatch they land on different workers, the store is empty, and every
    // add_evidence is rejected ("value not found in any recorded query result"),
    // giving 0 evidence / 0 techniques. Default to local (in-process) dispatch,
    // which the old working recipe forced via ARES_TOOL_DISPATCH=local. Honor an
    // explicit ARES_TOOL_DISPATCH=redis for callers that do run a worker fleet.
    let dispatcher: Arc<dyn ares_llm::ToolDispatcher> =
        if std::env::var("ARES_TOOL_DISPATCH").as_deref() == Ok("redis") {
            info!("blue consumer tool dispatch: Redis queue");
            Arc::new(tool_dispatcher::RedisToolDispatcher::new(
                queue,
                "blue-orchestrator".to_string(),
                auth_throttle,
            ))
        } else {
            info!("blue consumer tool dispatch: local (in-process, shared evidence store)");
            Arc::new(tool_dispatcher::LocalToolDispatcher::new(
                queue,
                "blue-orchestrator".to_string(),
                auth_throttle,
            ))
        };
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    info!(model = %model_name, "in-process blue consumer spawned for replay");
    let handle = blue::spawn_blue_orchestrator(
        provider,
        model_name,
        dispatcher,
        redis_url.to_string(),
        nats_url.to_string(),
        shutdown_rx,
    );
    Ok((handle, shutdown_tx))
}

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

    // Blue uses a simple Redis-based tool dispatcher (no operation-scoped auth
    // throttle) and never polls task results, so it needs no result demux.
    let queue = self::task_queue::TaskQueue::connect_state_only(&redis_url, &nats_url)
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

    crate::util::wait_for_shutdown_signal().await;
    info!("Shutdown signal received");
    let _ = shutdown_tx.send(true);

    // Blue-only mode is nothing but investigations, so it always needs the
    // blue-sized drain.
    let shutdown_timeout = shutdown_grace(true);
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

#[cfg(test)]
mod shutdown_grace_tests {
    use super::shutdown_grace;

    #[test]
    fn shutdown_grace_scales_to_blue_and_honors_override() {
        // Single test on purpose: these cases all mutate the same env var, and
        // as separate #[test] fns they race under the default parallel runner.
        std::env::remove_var("ARES_SHUTDOWN_TIMEOUT_SECS");

        // A blue investigation is a sweep + full LLM loop + scoring + report,
        // measured at ~7.5 minutes. The old flat 120s killed any investigation
        // still in flight when red finished (op-20260726-003632), losing the
        // one whose window covered the golden-ticket phase.
        let blue = shutdown_grace(true);
        let red = shutdown_grace(false);
        assert!(
            blue.as_secs() >= 480,
            "blue drain must outlast a ~7.5min investigation, got {}s",
            blue.as_secs()
        );
        assert!(blue > red, "blue needs a longer drain than red-only");
        assert_eq!(red.as_secs(), 120, "red-only keeps the short budget");

        std::env::set_var("ARES_SHUTDOWN_TIMEOUT_SECS", "45");
        assert_eq!(shutdown_grace(true).as_secs(), 45);
        assert_eq!(shutdown_grace(false).as_secs(), 45);

        // Garbage and zero fall back to the default rather than disabling the
        // drain outright — a 0s grace would reintroduce the original bug.
        std::env::set_var("ARES_SHUTDOWN_TIMEOUT_SECS", "0");
        assert_eq!(shutdown_grace(false).as_secs(), 120);
        std::env::set_var("ARES_SHUTDOWN_TIMEOUT_SECS", "not-a-number");
        assert_eq!(shutdown_grace(false).as_secs(), 120);

        std::env::remove_var("ARES_SHUTDOWN_TIMEOUT_SECS");
    }
}
