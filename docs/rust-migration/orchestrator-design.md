# Ares Orchestrator: Python-to-Rust Migration Design

## Table of Contents

- [A. Component Inventory](#a-component-inventory)
- [B. Rust Crate Structure](#b-rust-crate-structure)
- [C. PyO3 Boundary](#c-pyo3-boundary)
- [D. Data Flow](#d-data-flow)
- [E. Migration Strategy](#e-migration-strategy)
- [F. Threading/Concurrency Model](#f-threadingconcurrency-model)

---

## A. Component Inventory

### A.1 asyncio.create_task (Background Asyncio Tasks)

These are spawned in `run_multi_agent_operation()`
and `RedTeamDispatcher.start()`.

#### `health_monitor`

- **Location**: `_orchestrator.py:776`
- **Purpose**: Checks agent heartbeats every 30s,
  marks agents offline after stale threshold
- **Move to Rust?** **Rust**
- **Rationale**: Pure polling + Redis reads.
  No Python logic needed.

#### `exploitation_workflow`

- **Location**: `_orchestrator.py:777` / `workflows.py:271`
- **Purpose**: Main exploit loop: dequeues vulns from ZSET,
  dispatches to workers, tracks results.
  Uses `asyncio.Semaphore(3)` for concurrency.
- **Move to Rust?** **Rust**
- **Rationale**: Core coordination. Semaphore maps to
  `tokio::sync::Semaphore`. The `_exploit_vulnerability`
  call dispatches via Redis and waits for results --
  no LLM call.

#### `lock_extender`

- **Location**: `_orchestrator.py:778`
- **Purpose**: Extends Redis operation lock every 600s
- **Move to Rust?** **Rust**
- **Rationale**: Trivial periodic Redis EXPIRE.

#### `auto_credential_expansion`

- **Location**: `_orchestrator.py:780`
- **Purpose**: Monitors for new creds, triggers
  `credential_expansion_loop` which dispatches
  lateral movement tasks
- **Move to Rust?** **Rust**
- **Rationale**: State polling + dispatch. The
  `credential_expansion_loop` creates tasks via Redis,
  no LLM.

#### `auto_credential_access`

- **Location**: `_orchestrator.py:782`
- **Purpose**: Proactively runs AS-REP roast, kerberoast,
  secretsdump, password spray when new creds/hashes
  appear. Complex phase-aware logic.
- **Move to Rust?** **Rust**
- **Rationale**: State polling + conditional dispatch.
  Significant business logic but no LLM calls.

#### `auto_crack_dispatch`

- **Location**: `_orchestrator.py:783`
- **Purpose**: Dispatches crack tasks for new hashes
  (Kerberoast, AS-REP, NTLM)
- **Move to Rust?** **Rust**
- **Rationale**: Simple hash scanning + dispatch.

#### `auto_mssql_detection`

- **Location**: `_orchestrator.py:784`
- **Purpose**: Scans hosts for MSSQL services,
  queues exploitation vulns
- **Move to Rust?** **Rust**
- **Rationale**: Service matching + vuln queue.

#### `auto_adcs_enumeration`

- **Location**: `_orchestrator.py:785`
- **Purpose**: Detects ADCS servers (CertEnroll share),
  dispatches certipy_find
- **Move to Rust?** **Rust**
- **Rationale**: State polling + conditional dispatch
  with retry tracking.

#### `auto_share_spider`

- **Location**: `_orchestrator.py:786`
- **Purpose**: Spiders readable shares for credentials
- **Move to Rust?** **Rust**
- **Rationale**: Share filtering + dispatch.

#### `auto_bloodhound`

- **Location**: `_orchestrator.py:787`
- **Purpose**: Dispatches BloodHound collection per domain
- **Move to Rust?** **Rust**
- **Rationale**: Credential/domain tracking + dispatch
  with retry.

#### `auto_coercion`

- **Location**: `_orchestrator.py:788`
- **Purpose**: Triggers ESC8 relay, DC coercion,
  LDAPS relay when conditions met
- **Move to Rust?** **Rust**
- **Rationale**: Conditional dispatch based on state
  predicates.

#### `auto_delegation_enumeration`

- **Location**: `_orchestrator.py:790`
- **Purpose**: Dispatches `find_delegation` for new creds
- **Move to Rust?** **Rust**
- **Rationale**: Simple cred scanning + dispatch.

#### `auto_local_admin_secretsdump`

- **Location**: `_orchestrator.py:793`
- **Purpose**: Dispatches secretsdump when admin creds
  detected
- **Move to Rust?** **Rust**
- **Rationale**: Admin cred detection + dispatch with
  retry tracking.

#### `auto_golden_ticket`

- **Location**: `_orchestrator.py:795`
- **Purpose**: Monitors for krbtgt hash, runs
  lookupsid and ticketer via kubectl exec
- **Move to Rust?** **Hybrid**
- **Rationale**: The golden ticket forging uses
  `KubernetesPodExecutor` to run impacket commands.
  The kubectl exec could be done from Rust, but the
  command construction has complex domain/SID logic.
  Keep Python for command building, Rust for scheduling.

#### `_heartbeat_monitor`

- **Location**: `_dispatcher.py:253`
- **Purpose**: Reads heartbeats from Redis, marks stale
  agents offline
- **Move to Rust?** **Rust**
- **Rationale**: Pure Redis polling.

#### `_maintenance_loop`

- **Location**: `_dispatcher.py:264`
- **Purpose**: Stale cleanup, task reconciliation,
  periodic checkpoint, Redis health checks, processes
  pending dispatches from threaded consumer
- **Move to Rust?** **Rust**
- **Rationale**: Core maintenance. The "pending dispatch"
  queue from threads disappears when Rust owns the
  event loop.

#### `_deferred_queue_processor`

- **Location**: `deferred_queue.py:251`
- **Purpose**: Processes ZSET-backed deferred task queue
  when capacity available
- **Move to Rust?** **Rust**
- **Rationale**: Redis ZSET operations + throttle checks.

### A.2 threading.Thread (OS Threads)

#### `orchestrator-result-consumer`

- **Location**: `monitoring.py:1180`
- **Purpose**: Consumes task results from Redis in a
  dedicated thread with its own event loop. Prevents
  LLM API timeouts on main loop from blocking result
  processing. Creates own `RedisTaskQueue`.
- **Move to Rust?** **Eliminated**
- **Rationale**: This thread exists because Python
  asyncio has a single-threaded event loop that blocks
  during LLM calls. Rust tokio is truly concurrent --
  result consumption is just another `tokio::spawn`.
  No thread needed.

#### Worker `_heartbeat_thread`

- **Location**: `_worker.py:375`
- **Purpose**: Sends heartbeats from worker in a
  separate thread because sync tool execution blocks
  the asyncio loop
- **Move to Rust?** **Stays Python** (worker side)
- **Rationale**: Workers remain Python. Their internal
  threading stays.

#### Worker `_state_subscriber_thread`

- **Location**: `_worker.py:385`
- **Purpose**: Subscribes to Redis pub/sub for state
  updates
- **Move to Rust?** **Stays Python** (worker side)
- **Rationale**: Workers remain Python.

### A.3 threading.Event (Thread Signaling)

#### `_result_consumer_stop_event`

- **Location**: `_dispatcher.py:136`
- **Purpose**: Signals threaded result consumer to stop
- **Rust Equivalent**: **Eliminated** -- no separate
  thread in Rust. Use `CancellationToken`.

#### `_checkpoint_requested`

- **Location**: `_dispatcher.py:158`
- **Purpose**: Threaded consumer signals main loop
  to checkpoint
- **Rust Equivalent**: **Eliminated** -- replaced by
  `tokio::sync::Notify` or just checkpoint inline
  since there's no thread boundary.

#### `_credential_access_requested`

- **Location**: `_dispatcher.py:162`
- **Purpose**: Threaded consumer signals credential
  access needed. Transferred to asyncio.Event by
  maintenance loop.
- **Rust Equivalent**: **Eliminated** -- replaced by
  `tokio::sync::Notify`. Direct notification, no
  thread transfer needed.

#### `_deferred_task_requested`

- **Location**: `_dispatcher.py:167`
- **Purpose**: Threaded consumer signals deferred tasks
  need processing
- **Rust Equivalent**: **Eliminated** -- deferred task
  enqueueing happens directly in the same tokio runtime.

#### `_dispatch_requested`

- **Location**: `_dispatcher.py:174`
- **Purpose**: Threaded consumer signals pending
  dispatches
- **Rust Equivalent**: **Eliminated** -- dispatches
  happen directly.

### A.4 threading.Lock (Mutexes)

#### `_pending_deferred_lock`

- **Location**: `_dispatcher.py:168`
- **Purpose**: Protects `_pending_deferred_tasks` list
  between threads
- **Rust Equivalent**: **Eliminated** -- no cross-thread
  communication needed in Rust.

#### `_pending_dispatch_lock`

- **Location**: `_dispatcher.py:175`
- **Purpose**: Protects `_pending_dispatches` list
  between threads
- **Rust Equivalent**: **Eliminated** -- same reason.

### A.5 asyncio.Lock

#### `_throttle_lock`

- **Location**: `_dispatcher.py:145` / `throttling.py:77`
- **Purpose**: Serializes final throttle check + submit
  in `_throttled_submit_task`
- **Rust Equivalent**: `tokio::sync::Mutex<()>` -- same
  purpose, holds during final check + Redis LPUSH.

### A.6 asyncio.Event

#### `_credential_access_event`

- **Location**: `_dispatcher.py:117`
- **Purpose**: Signals `_auto_credential_access` to wake
  up immediately when new creds arrive instead of
  waiting full interval
- **Rust Equivalent**: `tokio::sync::Notify`

### A.7 asyncio.Semaphore

#### `exploit_semaphore`

- **Location**: `workflows.py:311`
- **Purpose**: Limits concurrent exploits to 3
- **Rust Equivalent**: `tokio::sync::Semaphore::new(3)`

### A.8 asyncio.Future

#### `_task_futures`

- **Location**: `_dispatcher.py:132`
- **Purpose**: `dict[str, asyncio.Future]` for
  `wait_for_task()` -- allows callers to await a
  specific task completion
- **Rust Equivalent**:
  `DashMap<String, tokio::sync::oneshot::Sender<TaskResult>>`

---

## B. Rust Crate Structure

```text
ares-orchestrator/
+-- Cargo.toml
+-- src/
|   +-- main.rs              # tokio::main, CLI, signals
|   +-- config.rs            # Config from YAML/env
|   +-- state.rs             # SharedRedTeamState
|   |
|   +-- redis/
|   |   +-- mod.rs
|   |   +-- client.rs        # Redis/Sentinel + breaker
|   |   +-- task_queue.rs    # submit_task, poll, check
|   |   +-- state_backend.rs # cred/hash/host CRUD
|   |   +-- deferred.rs      # Deferred ZSET operations
|   |
|   +-- dispatch/
|   |   +-- mod.rs
|   |   +-- throttle.rs      # soft cap, hard cap, phase
|   |   +-- routing.rs       # request_crack, recon, etc.
|   |   +-- publishing.rs    # publish_credential, hash
|   |   +-- vulnerability.rs # ZSET vuln queue mgmt
|   |   +-- deferred.rs      # background processor
|   |   +-- results.rs       # complete_task, extraction
|   |
|   +-- orchestrator/
|   |   +-- mod.rs
|   |   +-- loop.rs          # run_multi_agent_operation
|   |   +-- monitoring.rs    # heartbeat, result, stale
|   |   +-- maintenance.rs   # checkpoint, health, recon
|   |   +-- automation.rs    # All auto_* tasks
|   |
|   +-- workflows/
|   |   +-- mod.rs
|   |   +-- exploitation.rs  # semaphore-gated exploits
|   |   +-- expansion.rs     # credential_expansion_loop
|   |   +-- golden_ticket.rs # hybrid Rust/Python
|   |
|   +-- models.rs            # Credential, Hash, Host...
|   |
|   +-- python/
|       +-- mod.rs
|       +-- bridge.rs        # PyO3 bridge to agent.run()
|       +-- types.rs         # Rust struct <-> Python dict
|
+-- python/                   # PyO3-callable functions
|   +-- __init__.py
|   +-- agent_runner.py       # Wraps dn.Agent.run()
|   +-- tools.py              # OrchestratorTools factory
|   +-- prompt_builder.py     # prompt template rendering
|
+-- tests/
    +-- test_throttle.rs
    +-- test_routing.rs
    +-- test_state.rs
```

### Key Design Decisions

1. **Flat dispatch module**: The Python mixin pattern
   (ThrottlingMixin, RoutingMixin, etc.) maps to
   separate Rust modules that operate on a shared
   `Dispatcher` struct via `impl Dispatcher` blocks
   in each file.

2. **Redis module isolation**: All Redis operations go
   through `redis/` with circuit breaker and retry
   logic. This mirrors the Python `BaseRedisBackend` +
   `BaseTaskQueue` hierarchy.

3. **Automation tasks as functions**: The `auto_*`
   background tasks are standalone async functions that
   take `Arc<Dispatcher>` -- same pattern as the Python
   module-level functions.

4. **Python bridge is thin**: Only the LLM agent step
   and nmap/kubectl command construction cross the PyO3
   boundary. Everything else is pure Rust.

---

## C. PyO3 Boundary

### C.1 Functions Rust Calls Into Python

```rust
// 1. Run the orchestrator LLM agent
//    Python: result = await orchestrator_agent.run(
//        initial_prompt
//    )
//    Returns: RunResult with stop_reason, steps,
//             error, messages
async fn run_orchestrator_agent(
    py: Python<'_>,
    model: &str,
    prompt: &str,
    tools: PyObject,     // OrchestratorTools instance
    max_steps: usize,
) -> PyResult<AgentRunResult>;

// 2. Create the orchestrator agent (one-time setup)
//    Python: agent = dn.Agent(
//        name=..., model=..., tools=..., ...
//    )
fn create_orchestrator_agent(
    py: Python<'_>,
    model: &str,
    max_steps: usize,
    dispatcher_bridge: PyObject,
) -> PyResult<PyObject>;

// 3. Build orchestrator prompt from Jinja2 templates
//    Python: prompt = _build_orchestrator_prompt(...)
fn build_orchestrator_prompt(
    py: Python<'_>,
    target_domain: &str,
    target_ips: Vec<String>,
    initial_credential: Option<CredentialData>,
) -> PyResult<String>;

// 4. Execute kubectl command for golden ticket forging
//    Python: stdout, stderr, rc = await executor
//        .execute(role, command, timeout)
async fn kubectl_exec(
    py: Python<'_>,
    namespace: &str,
    role: &str,
    command: Vec<String>,
    timeout_seconds: u32,
) -> PyResult<(String, String, i32)>;

// 5. Load agent instructions from Jinja2 templates
//    Python: instructions = load_agent_instructions(
//        AgentRole.ORCHESTRATOR
//    )
fn load_agent_instructions(
    py: Python<'_>,
    role: &str,
) -> PyResult<String>;

// 6. Generate report
//    Python: report_path, report_markdown =
//        _generate_multi_agent_report(state, ...)
fn generate_report(
    py: Python<'_>,
    state_dict: PyObject,
    report_dir: &str,
    exploitation_status: PyObject,
) -> PyResult<(String, String)>;
```

### C.2 Data That Crosses the Boundary

#### Rust -> Python

- **Orchestrator prompt**: `String`.
  Once at start + on crash retry.
- **OrchestratorTools dispatcher bridge**:
  `PyObject` wrapping Rust `Arc<Dispatcher>`.
  Once at setup.
- **State snapshot for tools**: Serialized dict
  (credentials, hosts, hashes).
  Per tool call that reads state.
- **kubectl exec params**:
  `(namespace, role, Vec<String>, timeout)`.
  ~1-5 per operation (golden ticket).

#### Python -> Rust

- **Agent run result** (stop_reason, steps, error):
  Rust struct via `#[pyclass]`.
  Once per agent run.
- **Tool call dispatches** (from OrchestratorTools):
  `dispatch_recon(domain, ips, ...)` calls back into
  Rust. Per LLM tool call (~50-200 per operation).
- **kubectl exec result**: `(String, String, i32)`.
  ~1-5 per operation.

### C.3 GIL Management

```rust
// PATTERN 1: Release GIL during Redis IO
// Redis operations are pure Rust (redis-rs), no GIL
// needed. The GIL is never held for Redis -- this is
// a major win.
async fn submit_task(
    &self, task: Task,
) -> Result<String> {
    // Pure Rust, no GIL
    self.redis
        .lpush(&queue_key, &serialized)
        .await?;
    Ok(task_id)
}

// PATTERN 2: Hold GIL during Python agent.run()
// The LLM call is the ONE place we need the GIL.
// But agent.run() is async Python, so we use
// pyo3-asyncio.
async fn run_agent(
    py: Python<'_>,
    agent: &PyObject,
    prompt: &str,
) -> PyResult<RunResult> {
    // Option A: pyo3-asyncio bridges Python async
    // to Rust async
    let result = pyo3_asyncio::tokio::into_future(
        agent.call_method1(py, "run", (prompt,))?
    )?.await?;

    // Option B: Release GIL, run Python in thread
    // agent.run() internally calls OpenAI API
    // (network IO). Python releases GIL during
    // httpx calls, so other Python threads can run.
    let result = py.allow_threads(|| {
        // Can't do this with async --
        // need pyo3-asyncio
    });

    Ok(parse_result(result))
}

// PATTERN 3: Tool callbacks from Python into Rust
// When the LLM calls dispatch_recon(),
// OrchestratorTools calls back into Rust. The GIL
// is held (we're in a Python tool function), but
// the Rust dispatch only does Redis IO (no GIL
// needed for redis-rs).
// Use py.allow_threads to release GIL while doing
// Redis:
#[pyfunction]
fn dispatch_recon(
    py: Python<'_>,
    domain: &str,
    ips: Vec<String>,
) -> PyResult<String> {
    let dispatcher = get_dispatcher();
    let task_id = py.allow_threads(|| {
        // Rust tokio runtime handles Redis IO
        // without GIL
        tokio::runtime::Handle::current()
            .block_on(async {
                dispatcher
                    .request_recon(domain, &ips)
                    .await
            })
    })?;
    Ok(task_id)
}
```

### C.4 Python Exception Handling

```rust
// All PyO3 calls return PyResult<T>.
// Map to Rust errors:
enum OrchestratorError {
    Python(PyErr),       // Python exception
    Redis(RedisError),   // Redis failure
    RateLimit(String),   // LLM rate limit
    AuthFailure(String), // Fatal: bad API key
    Timeout,             // Agent run timeout
    MaxCrashes,          // Exceeded crash limit
}

// Rate limit detection
// (mirrors _is_rate_limit_error):
fn is_rate_limit(err: &PyErr) -> bool {
    let msg = err.to_string().to_lowercase();
    msg.contains("rate limit")
        || msg.contains("429")
        || msg.contains("too many requests")
}

// The orchestrator crash recovery loop becomes:
loop {
    match run_agent(&agent, &prompt).await {
        Ok(result)
            if result.stop_reason == "error" =>
        {
            if is_rate_limit_error(&result.error) {
                rate_limit_retry(
                    &mut count, &delays,
                ).await?;
                continue;
            }
            if is_auth_error(&result.error) {
                return Err(
                    OrchestratorError::AuthFailure(
                        result.error,
                    ),
                );
            }
            crash_count += 1;
            // ... crash recovery logic
        }
        Ok(result) => break Ok(result),
        Err(e) if is_rate_limit(&e) => {
            /* retry */
        }
        Err(e) => {
            crash_count += 1;
            // ...
        }
    }
}
```

---

## D. Data Flow

### D.1 Task Lifecycle: Creation to Result

```text
        RUST (tokio)                PYTHON (worker)
  ========================    =======================

1. TRIGGER
   auto_credential_access
   detects new credential
   in state.all_credentials
        |
        v
2. THROTTLE
   _throttled_submit_task()
   - Check LLM task count
   - Phase-aware priority adj
   - Soft/hard cap logic
   - If over cap: enqueue to
     deferred ZSET
        |
        v
3. SUBMIT
   task_queue.submit_task()
   - Generate task_id (UUID)
   - Serialize TaskMessage
   - LPUSH to ares:tasks:{role}
   - Store TaskInfo in
     pending_tasks HashMap
        |
  ======|==============================
        |   Redis
        v
4. CONSUME
   ares:tasks:{role} LIST
                          <--- BRPOP ---
                          worker._worker_loop()
                          poll_task(role, timeout=5)
                               |
                               v
5. EXECUTE
                          _process_task(task)
                          - Build prompt from template
                          - Run LLM agent with tools
                          - Tools execute impacket/nmap
                          - Publish discoveries to Redis
                               |
                               v
6. RESULT
                          task_queue.send_result()
                LPUSH --> ares:results:{task_id}

  ======|==============================
        |
7. CONSUME
   result_consumer
   - Polls ares:results:{task_id}
     for all pending tasks
   - Batch pipeline check
   - On result found:
        |
        v
8. PROCESS
   complete_task()
   - Remove from pending_tasks
   - Extract creds/hashes/hosts
   - Call publish_credential()
   - Update vuln exploit status
   - Clear rate limit backoff
   - Signal credential_access_event
        |
        v
9. CASCADE
   publish_credential() triggers:
   - Immediate delegation check
   - Check pending constrained deleg
   - Signal auto_credential_access
   - Persist to Redis state backend
```

### D.2 Orchestrator Agent Flow (The ONE Python Path)

```text
RUST                  PYTHON                RUST
====                  ======                ====

run_multi_agent_operation()
  |
  v
Create Python   -->  dn.Agent(
agent via PyO3         model="gpt-4.1",
                       tools=[OrchestratorTools],
                       hooks=[...],
                       stop_conditions=[
                         tool_use("complete_op"),
                         tool_use("announce_da"),
                       ]
                     )
  |
  v
agent.run(prompt) -> LLM generates tool calls
                       |
                       v
                     OrchestratorTools
                       .dispatch_recon()
                       |
                       v
                     Calls back     -->  dispatcher
                     into Rust            .request_recon()
                     via PyO3             -> throttled submit
                     (GIL released        -> LPUSH to Redis
                      for Redis)
                       |
                       v
                     OrchestratorTools
                       .get_operation_summary()
                       |
                       v
                     Calls back     -->  state
                     into Rust            .to_summary_dict()
                     (reads state
                      snapshot)
                       |
                       v
                     ... more tool calls ...
                       |
                       v
                     complete_operation(summary)
                       |
                       v
Result returned  <-- RunResult(
to Rust                stop_reason="tool_use"
                     )
  |
  v
Post-run cleanup (Rust)
```

### D.3 Discovery Polling Flow (Real-Time Worker Discoveries)

```text
PYTHON (worker)           Redis
===============           =====

Tool discovers delegation
  |
  v
task_queue
  .publish_discovery()
  LPUSH -->
    ares:op:{id}:discoveries

                    RUST (orchestrator)
                    ===================

                    _poll_discoveries()
                    LRANGE + LTRIM
                         |
                         v
                    _process_realtime_
                      delegation_discovery()
                      -> queue_vulnerability()
                      -> request_exploit()
```

---

## E. Migration Strategy

### Phase 0: Foundation (Week 1-2)

**Goal**: Rust binary that connects to Redis and reads
state. No Python yet.

1. Set up `ares-orchestrator` crate with `tokio`,
   `redis-rs`, `serde`.
2. Implement `redis/client.rs` with Sentinel support
   and circuit breaker.
3. Implement `redis/state_backend.rs` -- read-only:
   load credentials, hashes, hosts from Redis
   HASH/LIST.
4. Implement `models.rs` with `serde::Deserialize`
   for all data types.
5. Write integration tests that connect to a running
   Redis and read real operation state.

**Verification**:
`cargo run -- --redis-url redis://... --operation-id op-xxx`
prints state summary.

### Phase 1: Task Queue (Week 2-3)

**Goal**: Rust can submit and consume tasks via Redis.

1. Implement `redis/task_queue.rs`: `submit_task()`,
   `check_result()`, `check_results_batch()`.
2. Implement `redis/deferred.rs`: ZSET operations for
   deferred queue.
3. Implement `dispatch/throttle.rs`: phase detection,
   soft/hard cap logic.
4. Implement `dispatch/routing.rs`: `request_crack()`,
   `request_recon()`, etc.

**Verification**: Submit a task from Rust, have a Python
worker consume it, verify result is readable from Rust.

### Phase 2: Background Tasks (Week 3-5)

**Goal**: All `auto_*` tasks run in Rust tokio.

1. Port `auto_crack_dispatch` (simplest: scan hashes,
   submit crack tasks).
2. Port `auto_mssql_detection`, `auto_share_spider`
   (simple state predicates).
3. Port `auto_bloodhound`, `auto_adcs_enumeration`
   (retry tracking logic).
4. Port `auto_credential_access` (most complex:
   multi-domain, phase-aware).
5. Port `auto_coercion`, `auto_delegation_enumeration`,
   `auto_local_admin_secretsdump`.
6. Port `exploitation_workflow` with semaphore-gated
   concurrent exploits.
7. Port result consumer, heartbeat monitor,
   maintenance loop.

**Verification**: Run Rust orchestrator with Python
workers against DreadGOAD. All background automation
fires. Compare task dispatch logs against Python
orchestrator baseline.

### Phase 3: PyO3 Bridge (Week 5-7)

**Goal**: Rust drives the LLM orchestrator agent via
PyO3.

1. Create `python/bridge.rs` with PyO3 module.
2. Implement `OrchestratorToolsBridge` that wraps Rust
   dispatcher for Python tool callbacks.
3. Implement `run_orchestrator_agent()` using
   `pyo3-asyncio` to bridge Python async agent.run().
4. Wire up crash recovery loop, rate limit handling.
5. Implement `_build_orchestrator_prompt()` Python call.

**Verification**: Full operation against DreadGOAD. LLM
agent dispatches tasks, background tasks process
results, DA achieved.

### Phase 4: Golden Ticket + Report (Week 7-8)

**Goal**: Complete feature parity.

1. Port `auto_golden_ticket` (hybrid: Rust scheduling,
   Python/kubectl for command execution).
2. Port `_wait_for_completion`,
   `_wait_for_golden_ticket`,
   `_wait_for_crack_tasks`.
3. Wire up report generation via PyO3.
4. Port recovery manager (`OperationRecoveryManager`).
5. Port `PersistentStore` offload.

**Verification**: Full operation with golden ticket
forging and report generation.

### Phase 5: Cutover (Week 8-9)

1. Build `ares-orchestrator` as a standalone binary
   in the Docker image.
2. Update K8s orchestrator deployment to run Rust
   binary instead of Python.
3. Keep Python workers unchanged.
4. Monitor for 1 week in dev environment.
5. Remove Python orchestrator code.

### Rollback Plan

At every phase, the Python orchestrator remains fully
functional. The Rust binary is opt-in via a deployment
flag (`ARES_ORCHESTRATOR=rust`). Rollback = change flag
back to `python`.

---

## F. Threading/Concurrency Model

### F.1 Concurrency Primitive Mapping

#### `asyncio.create_task(coro)`

- **Rust**: `tokio::spawn(future)`
- **Notes**: Returns `JoinHandle<T>` instead of
  `asyncio.Task`. Use `JoinSet` for managing groups.

#### `asyncio.sleep(n)`

- **Rust**: `tokio::time::sleep(Duration::from_secs_f64(n))`
- **Notes**: Direct mapping.

#### `asyncio.Lock`

- **Rust**: `tokio::sync::Mutex<()>`
- **Notes**: `Mutex<()>` when protecting a critical
  section (not data). `Mutex<T>` when guarding data.

#### `asyncio.Event`

- **Rust**: `tokio::sync::Notify`
- **Notes**: `Notify::notify_one()` +
  `Notify::notified().await`. For multi-consumer,
  use `broadcast`.

#### `asyncio.Semaphore(n)`

- **Rust**: `tokio::sync::Semaphore::new(n)`
- **Notes**: `semaphore.acquire().await` returns
  `SemaphorePermit`.

#### `asyncio.Future`

- **Rust**: `tokio::sync::oneshot::channel()`
- **Notes**: For `_task_futures`: sender stored in
  map, receiver awaited by caller.

#### `asyncio.wait_for(coro, timeout)`

- **Rust**: `tokio::time::timeout(dur, future)`
- **Notes**: Returns `Result<T, Elapsed>`.

#### `asyncio.gather(*tasks)`

- **Rust**: `futures::future::join_all(handles)`
- **Notes**: Or `JoinSet::join_all()`.

#### `asyncio.CancelledError`

- **Rust**: `JoinHandle.abort()` +
  check `JoinError::is_cancelled()`
- **Notes**: Cancellation is cooperative in tokio
  via `select!`.

#### `threading.Thread`

- **Rust**: `tokio::spawn` or
  `tokio::task::spawn_blocking`
- **Notes**: Most threads become `tokio::spawn`.
  CPU-bound work uses `spawn_blocking`.

#### `threading.Event`

- **Rust**: `tokio::sync::Notify` or
  `CancellationToken`
- **Notes**: Stop events -> `CancellationToken`.
  Signal events -> `Notify`.

#### `threading.Lock`

- **Rust**: `std::sync::Mutex` or
  `tokio::sync::Mutex`
- **Notes**: `std::sync::Mutex` for sync-only access.
  `tokio::sync::Mutex` if held across `.await`.

#### `asyncio.new_event_loop()` (in thread)

- **Rust**: N/A
- **Notes**: Eliminated. Tokio runtime is
  multi-threaded. All tasks share the runtime.

### F.2 Rust Concurrency Architecture

```text
tokio::main (multi-threaded runtime, 4-8 threads)
+-- spawn: run_orchestrator_agent()
|   +-- GIL held during agent.run()
|       +-- Tool callbacks release GIL for Redis
+-- spawn: result_consumer()
|   +-- Pure Rust, no GIL needed
+-- spawn: heartbeat_monitor()
+-- spawn: maintenance_loop()
+-- spawn: exploitation_workflow()
+-- spawn: deferred_queue_processor()
+-- spawn: auto_credential_access()
+-- spawn: auto_crack_dispatch()
+-- spawn: auto_mssql_detection()
+-- spawn: auto_adcs_enumeration()
+-- spawn: auto_share_spider()
+-- spawn: auto_bloodhound()
+-- spawn: auto_coercion()
+-- spawn: auto_delegation_enumeration()
+-- spawn: auto_local_admin_secretsdump()
+-- spawn: auto_golden_ticket()
+-- spawn: lock_extender()
+-- spawn: health_monitor()
```

### F.3 Shared State Design

The Python `SharedRedTeamState` is accessed from
multiple tasks. In Rust:

```rust
/// Core shared state -- wrapped in Arc for shared
/// ownership. Interior mutability via RwLock
/// (many readers, rare writers).
struct SharedState {
    inner: Arc<RwLock<SharedStateInner>>,
}

struct SharedStateInner {
    operation_id: String,
    target: Option<Target>,

    // Collections (append-mostly)
    credentials: Vec<Credential>,
    hashes: Vec<Hash>,
    hosts: Vec<Host>,
    shares: Vec<Share>,
    users: Vec<User>,

    // Maps
    domain_controllers: HashMap<String, String>,
    discovered_vulnerabilities:
        HashMap<String, VulnerabilityInfo>,
    pending_tasks: HashMap<String, TaskInfo>,
    completed_tasks: HashMap<String, TaskResult>,

    // Dedup sets
    processed_expansion_creds: HashSet<String>,
    processed_hash_lateral: HashSet<String>,
    processed_crack_requests: HashSet<String>,
    processed_delegation_creds: HashSet<String>,
    // ... (all other processed_* sets)

    // Flags
    has_domain_admin: bool,
    has_golden_ticket: bool,
    completed: bool,
}

impl SharedState {
    /// Non-blocking read access
    /// (most background tasks only need this)
    async fn read(
        &self,
    ) -> RwLockReadGuard<'_, SharedStateInner> {
        self.inner.read().await
    }

    /// Write access
    /// (credential publishing, task completion)
    async fn write(
        &self,
    ) -> RwLockWriteGuard<'_, SharedStateInner> {
        self.inner.write().await
    }

    /// Add credential with dedup check (write lock)
    async fn add_credential(
        &self, cred: Credential,
    ) -> bool {
        let mut state =
            self.inner.write().await;
        let dedup_key = format!(
            "{}:{}:{}",
            cred.domain.to_lowercase(),
            cred.username.to_lowercase(),
            &cred
                .password
                .as_deref()
                .unwrap_or("")[..8.min(
                    cred.password
                        .as_ref()
                        .map_or(0, |p| p.len()),
                )]
        );
        if state
            .credential_dedup
            .contains(&dedup_key)
        {
            return false;
        }
        state.credential_dedup.insert(dedup_key);
        state.credentials.push(cred);
        true
    }
}
```

### F.4 Why the Threaded Result Consumer Disappears

In Python, the orchestrator has this problem:

1. Main asyncio loop runs `agent.run(prompt)` which
   blocks on LLM API call for 10-60+ seconds.
2. During this time, NO other asyncio tasks can run
   (single-threaded event loop).
3. Result consumption, heartbeats, and stale cleanup
   all freeze.
4. Solution: spawn a separate thread with its own
   event loop for result consumption.

In Rust with tokio:

1. `agent.run()` is called via PyO3. It holds the GIL
   but the actual network IO in Python releases the
   GIL (httpx is async).
2. Even if the GIL is held, tokio's multi-threaded
   runtime continues running other tasks on other OS
   threads.
3. Result consumption runs as a regular `tokio::spawn`
   task -- it never blocks.
4. No threading hacks needed. The entire
   threading.Event / threading.Lock /
   pending_dispatch machinery vanishes.

This eliminates ~400 lines of thread-coordination code
(the `_threaded_result_consumer_loop`,
`_threaded_consume_results`, `_maintenance_loop`'s
dispatch transfer logic, and all the `threading.Event`
signaling).

### F.5 Cancellation Strategy

```rust
use tokio_util::sync::CancellationToken;

async fn run_operation(
    token: CancellationToken,
) {
    let mut join_set = JoinSet::new();

    // Spawn all background tasks with cloned
    // cancellation token
    let t = token.clone();
    join_set.spawn(async move {
        auto_credential_access(
            dispatcher.clone(), t,
        ).await
    });
    // ... spawn all other tasks

    // Run orchestrator agent
    let agent_result = tokio::select! {
        result = run_agent(&agent, &prompt)
            => result,
        _ = token.cancelled()
            => Err(OrchestratorError::Cancelled),
    };

    // Shutdown
    token.cancel(); // Signal all background tasks
    // Wait for graceful cleanup
    join_set.shutdown().await;
}
```
