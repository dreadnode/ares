# Ares Rust Migration TODO

## Current State

### Already Done (Polish/Maintain)

- [x] **ares-cli** — 50+ commands, pure Rust (no PyO3)
- [x] **ares-core models** — all red+blue team types ported
- [x] **ares-core parsing** — secretsdump, kerberos, netexec, etc.
- [x] **ares-core state backend** — full Redis CRUD (red+blue)
- [x] **ares-core config** — YAML + env vars
- [x] **ares-core reports** — tera-based report generation
- [x] **ares-orchestrator automation** — 12+ background tasks
- [x] **ares-orchestrator recovery** — dedup, requeue, normalize
- [x] **ares-worker task loop** — heartbeat, PyO3 bridge
- [x] **Token usage tracking** — per-model cost estimation
- [x] **PyO3 extension module** — `ares_core` via maturin
- [x] **`extension-module` feature gating** — properly separated
- [x] **PyO3 bridge tests** — mock + feature-gated integration
- [x] **Persistent store (Postgres)** — sqlx queries, Alembic

### Should Stay in Python

- Agent creation & factories (rigging/dreadnode SDK)
- Tool implementations (impacket, nmap, bloodhound)
- LLM prompt building (Jinja2 templates)
- Blue team investigation logic (evidence scoring)
- Eval framework

---

## Migration Tasks (Priority Order)

### P0: Wire in `ares_core` Python Extension ✅

> `extraction.py` imports ares_core with fallback;
> `result_processing.py` delegates to extraction.py

- [x] Replace Python parsing in `result_processing.py`
- [x] Replace kerberos hash extraction
- [x] Replace netexec host parsing
- [x] Replace delegation parsing
- [x] Replace share parsing
- [x] Replace domain SID extraction
- [x] Add integration tests (45 tests)

### P1: Replace Python CLI with Rust CLI ✅

> Rust ares-cli has 50+ commands.
> Python CLI only needed for submit commands.

- [x] Audit Python CLI vs Rust CLI — identify gaps
- [x] Fill missing commands: submit, from-operation
- [x] Update Taskfiles to point at Rust binary
- [x] Deprecate Python CLI entry points

### P2: Orchestrator PyO3 Bridge (Rust to Python) ✅

> Mock + feature-gated integration tests added.
> Bridge verified with --features python.

- [x] Integration tests (feature-gated, #[ignore])
- [x] Test GIL release during Redis IO
- [x] Test graceful shutdown with in-flight call
- [x] Verify build with `--features python`
- [x] Benchmark GIL contention (concurrent mock tests)
- [ ] Run `#[ignore]` tests in full k8s environment

### P3: Port Recovery System ✅

> `ares-orchestrator/src/recovery.rs` — full recovery
> with dedup, requeue, normalization

- [x] Port `OperationRecoveryManager` to Rust
- [x] Checkpoint serialization/deserialization
- [x] State reconstruction from Redis on restart
- [x] Stale task detection and requeue
- [x] Hash deduplication (AS-REP, Kerberoast, NTLM)
- [x] State normalization (NetBIOS to FQDN)
- [x] OperationResumeHelper with analysis methods
- [x] 18 unit tests
- [ ] Integration test: kill/restart/verify (needs k8s)

### P4: Port Report Generation ✅

> `ares-core/src/reports.rs` — tera-based templates

- [x] Add `tera` dependency to ares-core
- [x] Port red team report templates to tera
- [x] Port `RedTeamReportGenerator` logic
- [x] Port blue team report templates
- [x] Port `BlueTeamReportGenerator` logic
- [x] Wire into ares-cli `ops report` command
- [x] 9 unit tests
- [x] Verify output matches Python reports (visual diff)

### P5: Blue Team State Backend ✅

> `ares-core/src/state/mod.rs` — BlueStateReader

- [x] Port `SharedBlueTeamState` models to Rust
- [x] Port `BlueStateReader` Redis operations (20+ methods)
- [x] Add blue state commands to ares-cli
- [x] Add PyO3 bindings for blue team types

### P6: Persistent Store (Postgres) ✅

> sqlx queries complete; Alembic migration gap fixed

- [x] Port SQLAlchemy models to sqlx queries
- [x] Port investigation/operation history queries
- [x] Port cost offload (token usage to Postgres)
- [x] Port `ares-cli history` commands to use sqlx
- [x] Alembic migration 002 for token usage columns
- [x] Updated Python OperationRecord model

---

## Remaining Work (Polish)

### Short-term

- [x] Deprecate Python CLI entry points
- [ ] Run PyO3 bridge `#[ignore]` tests in k8s
- [x] Visual diff of Rust vs Python report output
- [x] End-to-end integration test

### Future

- [x] Split ares-core into lib + cdylib (already done)
- [x] Profile and optimize hot parsing paths
- [x] Add structured logging to CLI (tracing already wired)
