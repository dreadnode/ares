# Ares Rust Migration Plan

## Motivation

- Replace Python asyncio orchestration with Rust/tokio
  -- eliminates GIL, threading hacks, cross-thread Future bugs
- Single binary deployment to K8s pods instead of syncing
  entire Python package tree
- Faster CLI startup (~5ms vs ~2s Python import chain)
- Shared model definitions owned by Rust, exposed to Python
  via PyO3

## Architecture End State

```text
Rust (tokio) -- owns the event loop
  |-- Polls Redis for results (no more threading.Event hacks)
  |-- Routes tasks to worker queues
  |-- Enforces throttle/concurrency limits
  |-- Manages heartbeats + operation locks
  +-- Calls into Python for:
        |-- orchestrator_agent.run(prompt)  # LLM step
        |-- publish_credential()            # business logic
        +-- create_role_hooks()             # agent setup

Python -- LLM/agent scripting layer
  |-- Rigging/dreadnode agent framework
  |-- Tool implementations (impacket, bloodhound, etc.)
  |-- Prompt templates (Jinja)
  +-- Agent factory + role hooks
```

## Deployment End State

```text
Container image:
  /usr/local/bin/ares-cli           # Rust binary (CLI)
  /usr/local/bin/ares-orchestrator  # Rust binary (orchestrator)
  /usr/local/bin/ares-worker        # Rust binary (worker loop)
  /opt/ares/agents/                 # Python agent scripts
  /opt/ares/templates/              # Jinja templates
  /opt/ares/venv/                   # Minimal Python venv
```

Dev sync = copy a few `.py` agent files.
Rust binary changes = rebuild image.

---

## Phase 0: Rust CLI (standalone, no Python dependency)

**Effort:** ~2-3 weeks

Rewrite the three ops CLIs as a single Rust binary.
No Python interop needed -- pure Redis/Postgres client.

### What gets rewritten

| Python Source | Lines | Rust Approach |
| --- | --- | --- |
| `cli_ops.py` | ~3000 | `clap` + `redis-rs` + `tokio` |
| `cli_blue_ops.py` | ~1400 | Same pattern |
| `cli_history.py` | ~600 | `clap` + `sqlx` (Postgres) |

### Key deliverables

- Single `ares-cli` binary with subcommands
  (`ops submit`, `ops loot`, `blue submit`,
  `history list`, etc.)
- Canonical Rust data models (`serde` structs) matching
  the Redis key/value schema:
  - `Credential`, `Hash` (with `aes_key`), `Host`,
    `Vulnerability`
  - `TaskMessage`, `TaskResult`
  - `OperationMetadata`, `AgentInfo`
- Redis key format compatibility
  (reads/writes same keys as Python)

### Starting point

Implement `ops submit` and `ops loot` first -- these
exercise the full Redis schema round-trip
(write operation -> read state back).

### What stays Python

`main.py` (blue agent runtime) -- it runs the actual LLM
agent loop, not just CLI commands.

---

## Phase 1: `ares-core` crate -- shared models + state backend

**Effort:** ~2 weeks

Extract Phase 0 models and Redis ops into a library crate.
Expose to Python via `maturin` + PyO3.

### Crate structure

```text
ares-core/
|-- src/
|   |-- models/       # Credential, Hash, Host, etc.
|   |-- state/        # RedisStateBackend
|   |-- queue/        # RedisTaskQueue
|   +-- python/       # PyO3 module bindings
|-- Cargo.toml
+-- pyproject.toml    # maturin build config
```

### What it replaces in Python

- `state_backend.py` -- drop-in replacement, Rust owns
  Redis connection pool
- `task_queue.py` -- task submission, polling,
  result retrieval
- `models.py` -- canonical types defined in Rust,
  exposed to Python as classes

### Key win

Eliminates the "threaded consumers CANNOT use main
thread's Redis client" class of bugs. Rust owns the
connection pool with proper Send + Sync guarantees.

---

## Phase 2: Rust async orchestration loop

**Status:** Core orchestration loop implemented.
All background automation tasks, exploitation workflow,
result processing, discovery polling, and shared state
management are complete.

Move the coordination layer from Python asyncio to
Rust/tokio.

### What moves to Rust

| Component | Current Python | Rust Replacement |
| --- | --- | --- |
| Task routing | `dispatcher/routing.py` | tokio tasks + channels |
| Result consumption | Threaded consumer w/ hacks | `tokio::select!` on Redis |
| Throttling | `dispatcher/throttling.py` | Atomic counters + semaphores |
| Heartbeat monitor | `dispatcher/monitoring.py` | tokio interval + Redis MGET |
| Deferred queue | `DeferredQueueMixin` | tokio interval + ZPOPMIN |
| Operation locks | `_extend_operation_lock()` | tokio interval + Redis SET EX |

### What stays in Python

| Component | Why |
| --- | --- |
| Orchestrator agent LLM loop | dreadnode/rigging framework |
| Worker agent LLM steps | rigging tool use framework |
| Tool implementations | impacket, bloodhound CLI wrappers |
| Prompt templates | Jinja2 |
| Publishing business logic | Complex conditional dispatch |
| Agent factory + role hooks | Configuration-driven |

### What gets eliminated

- All 14 `asyncio.create_task()` background tasks ->
  tokio task group
- `threading.Event` signaling between result consumer
  thread and main loop -> gone
- Lazy `asyncio.Lock` initialization hack ->
  `tokio::sync::Mutex` created at init
- Cross-thread Future safety issues ->
  Rust ownership model prevents them
- Python asyncio event loop entirely from the hot path

### Interface boundary

Rust orchestrator calls into Python via PyO3 for LLM
steps:

```rust
// Rust side
let result = Python::with_gil(|py| {
    let agent_module = py.import("ares.agents")?;
    agent_module.call_method1("run_step", (prompt,))
})?;
```

Python agent code remains synchronous from its
perspective -- Rust handles all async coordination.

### Implemented modules

| Module | Lines | Purpose |
| --- | --- | --- |
| `state.rs` | ~370 | `SharedState` with `Arc<RwLock<...>>` |
| `dispatcher.rs` | ~280 | Central `Dispatcher` |
| `automation.rs` | ~530 | All 11 `auto_*` background tasks |
| `exploitation.rs` | ~140 | Semaphore-gated exploit dispatch |
| `result_processing.rs` | ~270 | Result payload parsing |
| `main.rs` | ~200 | Wires components, spawns tasks |

### Background tasks (all tokio::spawn)

| Task | Interval | Python Equivalent |
| --- | --- | --- |
| `result_consumer` | 500ms | `_threaded_result_consumer_loop` |
| `heartbeat_monitor` | 30s | `_heartbeat_monitor` |
| `deferred_processor` | 10s | `_deferred_queue_processor` |
| `cost_summary` | 120s | `_periodic_token_usage_summary` |
| `exploitation_workflow` | 5s | `exploitation_workflow` |
| `discovery_poller` | 5s | `_poll_discoveries` |
| `state_refresh` | 10s | Periodic Redis state sync |
| `auto_crack_dispatch` | 15s | `_auto_crack_dispatch` |
| `auto_mssql_detection` | 30s | `_auto_mssql_detection` |
| `auto_adcs_enumeration` | 30s | `_auto_adcs_enumeration` |
| `auto_share_spider` | 30s | `_auto_share_spider` |
| `auto_bloodhound` | 30s | `_auto_bloodhound` |
| `auto_delegation_enum` | 30s | `_auto_delegation_enumeration` |
| `auto_coercion` | 30s | `_auto_coercion` |
| `auto_local_admin` | 30s | `_auto_local_admin_secretsdump` |
| `auto_cred_access` | 15s + Notify | `_auto_credential_access` |
| `auto_cred_expansion` | 15s | `auto_credential_expansion` |
| `auto_golden_ticket` | 30s | `_auto_golden_ticket` |

### What's eliminated vs Python

- `threading.Event` x5 -> `tokio::sync::Notify`
  (1 instance for credential_access)
- `threading.Lock` x2 -> eliminated
  (no cross-thread state)
- `asyncio.Lock` x1 -> `tokio::sync::Mutex` in throttler
- `threading.Thread` (result consumer) ->
  `tokio::spawn` (no separate event loop)
- All `_pending_dispatch` / `_pending_deferred` queues ->
  direct dispatch in same runtime

### Remaining work for Phase 2

- [ ] Wire up PyO3 bridge to call actual Python agent
  `run()` (currently mock)
- [ ] Crash recovery loop with rate limit / auth error
  detection
- [ ] Report generation via PyO3
- [ ] `_wait_for_completion` / `_wait_for_golden_ticket`
  wait loops
- [ ] ACL chain automation (`auto_acl_steps`)
- [ ] Recovery manager (`OperationRecoveryManager`)

---

## Phase 3: Result parsing + output extraction

**Effort:** ~2 weeks

Move regex-heavy parsing from Python to Rust. Currently
holds the GIL during CPU-bound string processing.

### What moves

- Secretsdump output -> credential/hash/AES key
  extraction
- BloodHound output -> host/trust/delegation parsing
- Domain SID extraction from tool output
- Impacket output parsing (lookupsid, getTGT, etc.)

### Approach

Rust `regex` crate with compiled patterns. Exposed to
Python via PyO3 if needed, or called directly from the
Rust orchestrator (Phase 2).

---

## Phase 4: Worker task loop

**Effort:** ~2 weeks

Rust binary on worker pods owns the task consumption loop.

### Architecture

```text
ares-worker (Rust binary)
  |-- BLPOP on role-specific Redis queue
  |-- Deserialize TaskMessage
  |-- Call into Python for LLM agent step (PyO3)
  |-- Parse result (Rust, Phase 3)
  |-- Serialize TaskResult
  +-- LPUSH to result queue
```

### Deployment win

Worker pod needs: one Rust binary + ~10 Python agent
script files + minimal venv (rigging + dreadnode).
No more full package sync, no more PVC corruption
causing `ImportError` on random `.py` files.

---

## What Stays Python Forever

- **Rigging/dreadnode agent framework** -- the LLM
  orchestration layer
- **LLM tool definitions** -- decorated Python functions
- **Prompt templates** -- Jinja2 `.md.jinja` files
- **`main.py` blue agent runtime** -- unless dreadnode
  gets Rust bindings
- **MCP integration** -- Python-native protocol

This is fine. Python becomes a scripting engine for
"do one LLM step" -- stateless, synchronous functions
called by Rust.

---

## Rust Toolchain

| Crate | Purpose |
| --- | --- |
| `clap` | CLI argument parsing |
| `tokio` | Async runtime |
| `redis-rs` | Redis client (async) |
| `sqlx` | Postgres (async, compile-time checked) |
| `serde` / `serde_json` | Serialization (JSON format) |
| `regex` | Output parsing |
| `pyo3` | Python FFI (Phase 1+) |
| `maturin` | Build Python extensions from Rust |
| `tracing` | Structured logging (replaces loguru) |
| `tower` | Middleware (circuit breaker, retry) |

---

## Redis Schema Contract

The Redis key/value format is the contract between Rust
and Python. Both sides must agree on:

```text
Key patterns:
  ares:operations                     # Op queue (LIST)
  ares:op:{op_id}:credentials         # HASH
  ares:op:{op_id}:hashes              # HASH
  ares:op:{op_id}:hosts               # LIST: JSON
  ares:op:{op_id}:vulnerabilities     # HASH
  ares:op:{op_id}:metadata            # HASH
  ares:op:{op_id}:domain_sids         # HASH
  ares:op:{op_id}:domain_controllers  # HASH
  ares:tasks:{role}                   # Task queues
  ares:results:{task_id}              # Results (TTL 24h)
  ares:heartbeat:{agent}              # STRING, TTL
  ares:lock:{op_id}                   # STRING, TTL
```

Any schema changes must be coordinated across both Rust
and Python during the migration period.

---

## First Move

Create `ares-cli/` Rust workspace in the repo. Implement
`ops submit` and `ops loot` as proof of concept --
validates the full Redis schema round-trip from Rust.
