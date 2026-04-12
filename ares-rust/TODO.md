<!-- markdownlint-disable MD013 -->
# Ares Rust Migration: Status

## Phase 1: Blue Team Python-to-Rust Conversion — COMPLETE

All items completed. 425 tests pass, 0 failures.

### Completed

#### High Priority (Done)

- [x] **Grafana API Client** — `ares-tools/src/blue/grafana.rs`
  - `get_alerts`, `get_annotations`, `search_dashboards`, `get_dashboard`
  - Registered in tool registry for all blue roles

- [x] **Evidence Auto-Chaining** — `ares-orchestrator/src/blue/chaining.rs`
  - `EVIDENCE_CHAIN_MAP` (7 evidence types), `CRITICAL_USERS` (5 users)
  - Auto-dispatch follow-up tasks, escalation detection
  - Wired into `investigation.rs` post-task-completion
  - 13 unit tests

#### Medium Priority (Done)

- [x] **Investigation Tools** — `ares-tools/src/blue/investigation.rs`
  - `add_evidence`, `record_timeline_event`, `add_technique`, `add_lateral_connection`, `get_investigation_summary`
  - All Redis-backed, registered in tool registry per role

- [x] **Learning Tools** — `ares-tools/src/blue/learning.rs`
  - `lookup_technique` (~40 embedded AD/Windows techniques), `suggest_techniques`
  - 10 unit tests

- [x] **Task Prompt Templates** — `ares-llm/src/prompt/blue.rs`
  - `user_investigation` and `host_investigation` Tera templates
  - Wired into `generate_blue_task_prompt()`

- [x] **Shared Investigation State** — handled by investigation tools
  - Tools write directly to Redis via `BlueStateWriter` key patterns
  - Multiple workers share state through Redis dedup (HSETNX)

#### Low Priority (Done)

- [x] **Evidence Validation** — `ares-tools/src/blue/validation.rs`
  - Type checking (13 known types), IP validation, technique ID format
  - Pyramid of Pain auto-assignment
  - Integrated into `add_evidence()` tool
  - 22 unit tests

- [x] **Query Resilience** — `ares-core/src/state/circuit_breaker.rs`
  - `CircuitBreaker` with Closed/Open/HalfOpen states
  - Configurable threshold and recovery timeout
  - Generic `execute()` wrapper for async operations
  - 10 unit tests

- [x] **Persistent Store Config** — `ares-core/src/persistent_store/config.rs`
  - `PersistentStoreConfig` + `RetentionConfig` from env vars
  - `from_config()` constructors on `PersistentStore` and `HistoricalQueryService`

- [x] **Blue Team Reports** — `ares-core/src/reports/blueteam.rs`
  - `generate_investigation()` for single-investigation reports
  - `generate_from_states()` for multi-investigation aggregation
  - Investigation report Tera template with Pyramid of Pain scoring
  - `ares blue report` CLI command

---

## Phase 2: Correlation & Analysis Engine — COMPLETE

Ported 3 Python modules to `ares-core/src/correlation/`. 467 tests pass, 0 failures.

### Completed

- [x] **Alert Correlation** — `ares-core/src/correlation/alert.rs`
  - `AlertCluster` with IOC extraction (hosts, users, IPs, techniques)
  - `AlertCorrelator` with similarity scoring and clustering
  - Configurable threshold (default 0.3), operation ID tie-breaking
  - 12 unit tests

- [x] **Red-Blue Correlation Engine** — `ares-core/src/correlation/redblue.rs`
  - `RedBlueCorrelator` with report loading, activity matching, gap detection
  - Hierarchical MITRE technique matching (T1003 matches T1003.006)
  - Detection rate, false positive rate, mean-time-to-detect metrics
  - `TechniqueCoverage` per-technique breakdown
  - Markdown report generation with executive summary
  - 14 unit tests

- [x] **Lateral Movement Analyzer** — `ares-core/src/correlation/lateral.rs`
  - `LateralGraph` with host connection tracking and investigation state
  - `LateralMovementAnalyzer` with 8 lateral movement pattern detectors
  - Pivot suggestions with priority ranking and Loki query templates
  - Attack path reconstruction via DFS
  - MITRE technique auto-mapping per connection type
  - 12 unit tests

- [x] **CLI Command** — `ares ops correlate`
  - `--reports-dir` for report file directory
  - `--time-window` configurable matching window (default 30 min)
  - `--json` for machine-readable output
  - Saves correlation reports to reports directory

---

## Phase 3: Evaluation Framework — COMPLETE

Port `src/ares/eval/` (4,234 lines) to Rust. 509 tests pass, 0 failures.

### High Priority (Done)

- [x] **Scorers** — `ares-core/src/eval/scorers.rs`
  - 6 scorer functions: stage_progress, ioc_detection, technique_coverage, pyramid_elevation, timeline_accuracy, evidence_quality
  - Composite `score_investigation_overall()` with weighted average
  - `evaluate()` builds full `EvaluationResult` from snapshot + ground truth
  - Fuzzy IOC matching (hostname, domain\user, user@domain)
  - Timeline matching: regex, substring, keyword overlap
  - 12 unit tests

- [x] **Gap Analysis** — `ares-core/src/eval/gap_analysis.rs`
  - `DetectionRecommendation`, `GapAnalysisReport` with `to_markdown()`
  - `analyze_detection_gaps()` — IOC gaps, technique gaps, alert/pyramid/completion checks
  - 13 technique-specific recommendation mappings (T1003, T1558.003, T1649, etc.)
  - IOC-type-specific recommendations (ip, user, hostname/domain, hash)
  - Priority-sorted output with executive summary
  - 11 unit tests

### Medium Priority (Done)

- [x] **Ground Truth** — `ares-core/src/eval/ground_truth.rs`
  - `ExpectedIOC`, `ExpectedTechnique` (parent/child matching), `ExpectedTimelineEvent`, `ExpectedShare`, `ExpectedVulnerability`
  - `EvaluationGroundTruth` with filter methods, threshold defaults
  - `is_technique_required()`, `get_techniques_for_vuln_type()` with 18 vuln-to-technique mappings
  - `create_ground_truth_from_red_state()` — transforms `SharedRedTeamState` into ground truth
  - Handles hosts, users, credentials, hashes, shares, vulnerabilities with technique mapping
  - IOC deduplication by value, technique deduplication by ID
  - 7 unit tests

- [x] **Results Aggregation** — `ares-core/src/eval/results.rs`
  - `EvaluationResult` with `passed()`, `grade()`, `to_value()`, `to_summary()`
  - `DatasetEvaluationResult` with aggregation (pass_rate, avg scores, grade distribution)
  - 4 unit tests

### Lower Priority (Done)

- [x] **Detection Playbook** — already complete in `ares-cli/src/detection/`
  - 6 files: 16 MITRE technique detection builders, LogQL queries, markdown output
  - No additional porting needed — Python `detection_playbook.py` fully covered

- [x] **Evaluation Workflow** — `ares-core/src/eval/workflow.rs`
  - `EvaluationScenario` and `EvaluationDataset` with directory/JSON loaders
  - `SavedRedState` lenient deserializer for saved state JSON files
  - `load_red_state_from_file()` — JSON → `SharedRedTeamState` + techniques
  - `evaluate_scenario()` — load → ground truth → score → gap analysis
  - `evaluate_dataset()` — aggregate into `DatasetEvaluationResult`
  - `save_evaluation_result()` and `save_gap_analysis()` file output
  - `ModelCost` and `estimate_cost()` for token usage estimation
  - 5 unit tests

- [x] **CLI Command** — `ares ops evaluate`
  - `--states-dir` for batch evaluation of all JSON files in directory
  - `--state-file` for single file evaluation
  - `--output-dir` for results output (default: `./eval_results`)
  - `--json` for machine-readable output
  - `--save` to persist results and gap analysis to disk

---

## Phase 4: Orchestrator Tool Handlers — COMPLETE

Orchestrator query and dispatch tools wired up. 518 tests pass, 0 failures.

### CallbackHandler Trait (Done)

- [x] **CallbackHandler trait** — `ares-llm/src/agent_loop.rs`
  - `async fn handle_callback(&self, call: &ToolCall) -> Option<Result<CallbackResult>>`
  - `run_agent_loop()` accepts `Option<Arc<dyn CallbackHandler>>` — custom handler tried first, then built-in
  - `LlmTaskRunner.with_callback_handler()` builder on orchestrator side

### Missing Built-in Callbacks (Done)

- [x] **Built-in callback handlers** — `ares-llm/src/agent_loop.rs`
  - `report_crack_failed` — records hash crack failure
  - `report_lateral_success` — records successful lateral movement
  - `report_lateral_failed` — records failed lateral movement with reason
  - `complete_operation` — marks operation complete, maps to TaskComplete

### Orchestrator State Query Tools (Done)

- [x] **OrchestratorCallbackHandler** — `ares-orchestrator/src/callback_handler.rs`
  - `get_credential_summary` — credentials grouped by domain with admin counts
  - `get_hash_summary` — hashes grouped by type with cracked/uncracked counts
  - `get_all_credentials` — paginated credential listing (limit/offset)
  - `get_all_hashes` — paginated hash listing (limit/offset)
  - `get_hash_value` — lookup specific hash by username/domain/type (returns raw value + AES key)
  - `get_pending_tasks` — list all pending tasks with status and timing
  - `get_agent_status` — read heartbeats from Redis for all active agents
  - 9 unit tests

### Orchestrator Dispatch Tools (Done)

- [x] **Dispatch tool definitions** — `ares-llm/src/tool_registry/orchestrator_tools.rs`
  - `dispatch_recon` — submit recon task with target IP and techniques
  - `dispatch_credential_access` — submit credential access task (secretsdump, kerberoast, etc.)
  - `dispatch_lateral_movement` — submit lateral movement to target host
  - `dispatch_privesc_exploit` — submit exploit task for discovered vulnerability
  - `dispatch_coercion` — submit coercion/relay attack
  - All routed as callbacks via `OrchestratorCallbackHandler`, backed by `Dispatcher`

---

## Phase 5: Wiring & Integration — COMPLETE

Callback handler wired end-to-end, missing tools added, template aligned. 520 tests pass, 0 failures.

### Callback Handler Wiring (Done)

- [x] **OnceLock deferred initialization** — `ares-orchestrator/src/llm_runner.rs`
  - Changed `callback_handler` from `Option<Arc<dyn CallbackHandler>>` to `OnceLock<Arc<dyn CallbackHandler>>`
  - `set_callback_handler(&self, handler)` — interior-mutable setter breaks circular dependency
  - `execute_task` reads handler via `self.callback_handler.get().cloned()`
  - Circular dependency: handler needs Dispatcher → contains LlmTaskRunner → needs handler

- [x] **Wired in main.rs** — `ares-orchestrator/src/main.rs`
  - Creates `OrchestratorCallbackHandler` with `SharedState` + `TaskQueue` + `Dispatcher`
  - Calls `llm_runner.set_callback_handler()` after `Dispatcher` creation
  - All 14 orchestrator callback tools now reachable end-to-end

### Additional Tools (Done)

- [x] **`dispatch_crack` tool** — `ares-llm/src/tool_registry/orchestrator_tools.rs`
  - Hash cracking dispatch: hash_value, hash_type, username, domain, use_john, priority
  - Callback handler constructs `Hash` struct and calls `dispatcher.request_crack()`
  - Registered in CALLBACK_TOOLS

- [x] **`get_operation_summary` callback** — `ares-orchestrator/src/callback_handler.rs`
  - Consolidated view: target info, credential/hash counts, DA status, vulnerabilities, tasks
  - Already defined in reporting tools (available to all roles)
  - Callback handler provides real state data for orchestrator; graceful fallback for workers

- [x] **Builtin callback fallbacks** — `ares-llm/src/agent_loop.rs`
  - All 14 orchestrator-only tools have graceful fallback in `handle_builtin_callback`
  - Workers that accidentally call orchestrator tools get helpful message instead of panic

### Template Update (Done)

- [x] **Orchestrator template** — `ares-llm/templates/redteam/agents/orchestrator.md.tera`
  - Updated all tool references to match actual Rust tool names
  - Added "Available Tools" section with query and dispatch tool tables
  - Fixed: `dispatch_crack_hash` → `dispatch_crack`, `start_coercion` → `dispatch_coercion`
  - Removed references to Python-era tools (queue_vulnerability, announce_domain_admin, etc.)
  - Priority workflow updated with correct dispatch_* syntax
  - 11 unit tests for callback handler (was 9)

---

## Phase 6: Exploit Prompts, Integration Tests & Smoke Test — COMPLETE

Exploit prompt templates, callback handler integration tests, and end-to-end smoke test binary. 530 tests pass, 0 failures.

### Exploit Prompt Templates (Done)

- [x] **Trust key extraction** — `ares-llm/src/prompt/exploit/trust.rs`
  - `generate_trust_key_prompt()` — 4-step guided workflow: extract_trust_key → get_sid → create_inter_realm_ticket → secretsdump_kerberos
  - Child-to-parent detection: `vuln_type == "child_to_parent"` OR domain ends with `.{trusted_domain}`
  - ExtraSid with RID 519 (Enterprise Admins) for intra-forest escalation
  - Alternative `raise_child` automated fallback for child-to-parent
  - AES256 requirement note for Windows Server 2016+ (RC4 → KDC_ERR_TGT_REVOKED)
  - SID filtering warning for cross-forest (blocks RID < 1000)
  - Credential lookup from state snapshot if not in payload
  - 2 unit tests

- [x] **MSSQL lateral enumeration** — `ares-llm/src/prompt/exploit/mssql.rs`
  - `generate_mssql_lateral_prompt()` — credential validation, impersonation enumeration, linked server discovery
  - NTLM coercion via xp_dirtree for relay attacks
  - Injects available credentials from state snapshot
  - Routed for `mssql_access` and `mssql_lateral` vuln_types
  - 1 unit test

- [x] **Exploit routing** — `ares-llm/src/prompt/exploit/mod.rs`
  - `trust_key` / `cross_forest` / `child_to_parent` → `trust::generate_trust_key_prompt()`
  - `mssql_access` / `mssql_lateral` → `mssql::generate_mssql_lateral_prompt()`

### Integration Tests (Done)

- [x] **Callback handler integration tests** — `ares-orchestrator/src/callback_handler.rs`
  - `test_full_summary_with_populated_state` — operation summary with hosts, creds, hashes, DCs, vulns
  - `test_credential_summary_multi_domain` — multi-domain credential grouping
  - `test_hash_value_case_insensitive_lookup` — case-insensitive username matching
  - `test_hash_value_filter_by_type` — hash type filtering (NTLM, AES256)
  - `test_all_dispatch_tools_fail_without_dispatcher` — all 5 dispatch tools fail gracefully without wired dispatcher
  - `test_all_callback_tools_recognized` — all CALLBACK_TOOLS routed (no unknown tools)
  - `test_all_hashes_pagination_large` — pagination correctness with 50-hash dataset
  - 8 new tests (19 total in callback_handler)

### Smoke Test Binary (Done)

- [x] **End-to-end smoke test** — `ares-llm/examples/smoke_test.rs`
  - Mock LLM provider (scripted nmap_scan → task_complete sequence)
  - Mock tool dispatcher (canned nmap output with host discoveries)
  - Exercises full pipeline: Tera template rendering → prompt generation → tool registry → agent loop
  - Verifies: TaskComplete outcome, step count, tool dispatch count, discovery accumulation
  - Run: `cargo run --example smoke_test`

---

## Phase 7: Orchestrator Unit Test Coverage — COMPLETE

Unit tests for state management, result processing, and LLM runner. Refactored discovery parsing into pure functions. 570 tests pass, 0 failures.

### State Management (Done)

- [x] **StateInner tests** — `ares-orchestrator/src/state/inner.rs`
  - Initialization verifies all 19 dedup sets created
  - `is_processed` / `mark_processed` dedup logic
  - Idempotent processing, independent set isolation
  - Exploited vulnerability tracking, MSSQL enum tracking
  - Domain controller map operations
  - Dedup set constant completeness check
  - 10 unit tests

- [x] **SharedState tests** — `ares-orchestrator/src/state/shared.rs`
  - Snapshot of empty state, snapshot reflects mutations
  - Snapshot independence (copy semantics — mutations after snapshot don't leak)
  - Vulnerability snapshot with discovered + exploited sets
  - Key generation: `vuln_queue_key()`, `discovery_key()`
  - 7 unit tests

### Result Processing (Done)

- [x] **Discovery parsing** — `ares-orchestrator/src/result_processing.rs`
  - Refactored `extract_discoveries()` into pure `parse_discoveries()` + async publishing
  - `ParsedDiscoveries` struct: credentials, hashes, hosts, users, vulnerabilities
  - Credential sources: array, single, cracked password
  - Malformed entry graceful skipping
  - Mixed payload with all discovery types
  - `has_domain_admin_indicator()` pure function: explicit flag, krbtgt hash (case-insensitive)
  - 16 unit tests

### LLM Runner (Done)

- [x] **Role mapping** — `ares-orchestrator/src/llm_runner.rs`
  - Exhaustive `role_for_task_type` coverage: all recon aliases, credential_access aliases
  - Unmapped types (command, unknown, empty string)
  - `build_system_prompt()` for all 8 agent roles
  - `build_task_prompt()` known types + fallback for unknown types
  - 8 unit tests (was 1)
