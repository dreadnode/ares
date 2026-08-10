# Ares architecture

The mental model you need before you read Ares code or diagnose an op. Every claim is cited to `file:line` at HEAD — verify before you trust, and re-verify before you quote a number back at the operator.

## The six that cost the most when you get them wrong

1. **There is no orchestrator tick.** 62 independent `auto_*` tokio tasks each own their own `tokio::time::interval` (5s–60s), plus ten infra loops spawned separately. `automation_spawner.rs:35-96` (62 `spawn_auto!` invocations, confirmed by count), `mod.rs:661-755`. If you are hunting "the loop that decided X", you are hunting one of ~72 loops — find it by its log line, not by reading `mod.rs`.

2. **The LLM agent loop runs inside the orchestrator process, not in a worker.** `submit_to_llm` does `tokio::spawn(runner.execute_task(...))` (`dispatcher/submission.rs:405-406`). Workers only execute individual tool calls. Every "the agent decided X" line is in `orchestrator.log`, never in `<role>.log`.

3. **The `ares.tasks.{role}` JetStream path is dead in production.** Its only publisher, `TaskQueue::submit_task`, is `#[cfg(test)]` (`task_queue.rs:436-437`), as is `task_subject_for_priority` (`task_queue.rs:379-380`). The source comment says it outright: "production red-team dispatch runs in-process" (`task_queue.rs:399`). Do not read `worker/task_loop/executor.rs::map_technique_to_tool` to explain why a technique never ran — nothing consults it. The live worker path is `ares.tools.exec.{role}`.

4. **A large share of high-value techniques never reaches an LLM.** 25 automation call sites dispatch a tool straight through `tool_dispatcher().dispatch_tool(...)`. Enumerate them with `rg -n '\.dispatch_tool\(' ares-cli/src/orchestrator/automation/` (25 hits): ESC1/3/4/8/13 chains, ADCS find, GPO abuse, MSSQL impersonation and link pivot, AS-REP roast, trust forge/enum, `find_delegation`, hashcat, secretsdump, S4U, SID-history enum, credential reuse. **Only 13 of the 25 carry the `direct tool, no LLM` marker string**, so `rg -n 'direct tool, no LLM' -g'*.rs'` (13 hits) undercounts the surface — it misses `find_delegation` (`delegation.rs:124`) and hashcat (`crack.rs:358`) entirely. `Starting LLM agent loop` will never show any of them.

   These bypass `process_completed_task`, so the *result-consumer* stages never run. Parser discoveries still reach state: `dispatch_tool` pushes them to `ares:discoveries:{op}` before returning (`redis_dispatcher.rs:281-290`) and the 5s poller drains them. What is lost is the secondary raw-text pass and the `exploit_*` result hooks, so each site compensates itself — `crack.rs:404-425` replays both extractors; the ADCS/GPO sites instead pair an explicit scoreboard write (`mark_adcs_esc_exploited`, `adcs_exploitation.rs:985`; `mark_exploited`, `gpo.rs:419`, rationale at `gpo.rs:313-317`).

5. **LLM-asserted findings cannot reach state.** `report_finding` / `report_lateral_success` produce `CallbackResult::LlmFinding` → `outcome.llm_findings`, deliberately a different field from `outcome.discoveries` (`dispatcher/submission.rs:421-426`). Only *tool output* publishes, via two passes in `process_completed_task`: `extract_discoveries` over the `discoveries` key (parsers), then a regex pass `extract_from_raw_text` over the raw `tool_outputs` array (`result_processing/mod.rs:201-218`, body at `:1991-2013`), provenance-gated. What can never publish is LLM-*authored* content: `outcome.llm_findings`, and the payload root's `summary` / `result` / `output` fields, which are excluded by name (`mod.rs:1998-2001`). "The agent said it got DA but nothing was recorded" is the firewall working, not a bug.

6. **The op can legitimately run to 2× `timeouts.operation_timeout`.** Hard cap = `max_runtime.saturating_mul(2)` (`completion.rs:469`); the soft cap only stops the op when there is no DA yet *or* all forests are already dominated (`completion.rs:414-418`). Shipped soft budget is 3600s (`config/ares.yaml:200`), so 2h is a normal ceiling, not a hang.

## Crates

Four workspace members (`Cargo.toml:3`), one binary: `ares` from `ares-cli` (`ares-cli/Cargo.toml:7-8`). `blue` is a default feature in all four (`ares-{core,cli,llm,tools}/Cargo.toml`, `default = ["blue"]`), so a normal build has everything.

| Crate | Owns | Does NOT |
|---|---|---|
| `ares-core` | models, Redis key names (`state/keys.rs`), NATS subjects + streams (`nats.rs`), YAML config deserialization (`config/`), telemetry, `replay_clock.rs`, `token_usage.rs`, op-state event log (`op_state_log.rs`), detection catalog, report renderers | know about agents, tools, or LLMs |
| `ares-tools` | one wrapper module per role (`recon.rs`, `credential_access/`, `acl.rs`, `privesc/`, `lateral/`, `coercion.rs`, `cracker.rs`), `executor.rs` (`CommandBuilder`), `parsers/` (the only authoritative discovery source), `concurrency.rs`, `scope.rs`, `sanitize.rs`, `redact.rs`, `mutation.rs` | talk to Redis/NATS for dispatch; know roles-as-agents |
| `ares-llm` | `tool_registry/` (JSON schemas per role), `prompt/` (embedded Tera templates), `provider/` (anthropic, openai, ollama, claude-cli), `agent_loop/` (step loop, context compaction, retry, session log), `routing/` (DC/credential/domain enrichment). Library only — no `[[bin]]` | read `config/ares.yaml`; every knob arrives as a struct field or `ARES_*` env var |
| `ares-cli` | `orchestrator/` (automations, dispatcher, state, result processing, completion, cleanup, blue), `worker/`, `ops/` (CLI), `blue/`, `benchmark/`, `history/`, `transport.rs` (`--k8s` / `--ec2` re-exec), `dedup/` (loot-presentation identity dedup) | — |

**Two unrelated functions named `tools_for_role`.** `ares-llm/src/tool_registry/mod.rs:282` returns LLM JSON schemas. The second is **generated at build time** into `$OUT_DIR/tool_tables.rs` by `ares-cli/build.rs:1,74` from `tools.yaml`, and `include!`d at `ares-cli/src/worker/tool_check.rs:17`; it returns expected *binary* names. Its definition is not in the committed tree — `rg tools_for_role` finds only the `ares-llm` one plus callers (and, if you have built, a copy under `target*/`). If you are chasing worker binary inventory, read `tools.yaml` and `build.rs`, not the tool registry.

**`ares-cli/src/dedup/` is not the automation dedup.** It is identity normalisation for reporting (`dedup_credentials` / `dedup_hashes` / `dedup_users` at `ops/loot/format/json.rs:8`) plus `is_ghost_machine_account` (`automation/rbcd.rs:17`). Automation dedup lives in `orchestrator/state/dedup.rs`.

## Processes and what actually crosses the wire

```
ares orchestrator                      one process, mod.rs:68 run_inner
  ├─ 62 auto_* automation tasks        automation_spawner.rs:35-96
  ├─ lock keeper + heartbeat monitor   mod.rs:661,663
  ├─ result consumer (500ms)           mod.rs:673; results.rs:42
  ├─ deferred processor (10s)          mod.rs:681; deferred.rs:633
  ├─ cost summary                      mod.rs:689
  ├─ domain probe worker               mod.rs:699
  ├─ exploitation workflow (5s)        mod.rs:706; exploitation.rs:82
  ├─ discovery poller (5s)             mod.rs:714; discovery_polling.rs:20
  ├─ state refresh (10s)               mod.rs:720; automation/refresh.rs:14
  ├─ completion monitor (10s)          mod.rs:897-909
  ├─ blue runner + blue auto-submit    mod.rs:810,818 (only when ARES_BLUE_ENABLED=1, mod.rs:779)
  └─ N in-flight agent loops           one tokio::spawn per dispatched task

ares worker    (one systemd unit per role: ares@<role>.service)
  └─ tool_exec loop: NATS queue_subscribe(ares.tools.exec.<role>,
                                          queue group "ares-tools-<role>")
                                       worker/tool_executor.rs:174-186
```

The main `tokio::select!` loop does no periodic work of its own — it drains completed results, polls the Redis stop flag every 5s, and catches ctrl-c (`mod.rs:960-1007`). A hung automation is invisible to it.

| Transport | Carries | Cite |
|---|---|---|
| NATS core req/reply | tool dispatch `ares.tools.exec.{role}` → auto reply inbox | `ares-core/src/nats.rs:48,103`; `worker/tool_executor.rs:174-179` |
| NATS JetStream `ARES_TASKS` | `ares.tasks.results.{task_id}` — how the in-process agent loop hands its `TaskResult` back | `nats.rs:63,71`; `task_queue.rs:507-518` |
| NATS JetStream `ARES_OPSTATE` | op-state event log, replayed by `ares ops replay` | `nats.rs:80` |
| Redis | all state, dedup sets, deferred ZSETs, vuln queue, heartbeats, discovery list | see `references/state-and-redis.md` |
| `ares.tasks.{role}` / `ares.tasks.urgent.{role}` | **nothing in production** — publisher is `#[cfg(test)]` | `task_queue.rs:436-437` |

`ARES_WORKER_MODE=tool_exec` is set by the unit template `ansible/roles/redis/templates/ares@.service.j2:19`. Absent or unparsable → `WorkerMode::Task`, the dormant path (`worker/config.rs:112-116`). `ARES_TOOL_DISPATCH=local` swaps the NATS dispatcher for in-process `ares-tools` (`mod.rs:564-566`, logs `Tool dispatch: local (in-process via ares-tools)`).

## Agent roles → owns → key files

Seven roles. There is **no Orchestrator role** in `ares_llm::tool_registry::AgentRole` (`tool_registry/mod.rs:24-32`) — the `agents.orchestrator:` block in `config/ares.yaml:122-124` supplies only the fallback model spec (`mod.rs:488-493`), and its `tools:` list is inert.

| Role (`as_str`) | `parse()` aliases | Owns (dispatch surface) | Shipped model / max_steps | Tool composition | Key files |
|---|---|---|---|---|---|
| `recon` | — | host/user/share/trust enumeration, BloodHound, DNS, subnet sweep; also the **only** worker with netexec | `gpt-5-mini` / 100 (`config/ares.yaml:154-155`) | `recon::tool_definitions()` **+ the full `credential_access::netexec_tools::definitions()`** (`tool_registry/mod.rs:285-293`) | `ares-tools/src/recon.rs`, `automation/{bloodhound,dns_enum,share_enum}.rs` |
| `credential_access` | — | kerberoast, AS-REP, secretsdump, lsassy, NTDS | `gpt-5` / 100 (`:161-162`) | `credential_access::tool_definitions()` | `ares-tools/src/credential_access/`, `automation/credential_access.rs` |
| `cracker` | `crack` | hashcat/john | `gpt-5-mini` / 150 (`:168-169`) | `cracker::tool_definitions()` + `cracker::callback_definitions()` | `ares-tools/src/cracker.rs`, `automation/crack.rs` (dispatches **direct**, no LLM) |
| `acl` | `acl_analysis` | DACL/ACL edge abuse, bloodyAD, pywhisker, targeted kerberoast | `gpt-5.2` / 150 (`:173-174`) | `acl::tool_definitions()` | `ares-tools/src/acl.rs`, `orchestrator/acl_graph.rs`, `automation/{acl,acl_discovery,dacl_abuse}.rs` |
| `privesc` | `privesc_enumeration` | ADCS (certipy), delegation, ticket forging, CVE exploits — **plus MSSQL** | `gpt-5.2` / 100 (`:178-179`) | `privesc::tool_definitions()` + `lateral::mssql::definitions()` + `lateral::execution::secretsdump_kerberos_definition()` (`tool_registry/mod.rs:296-306`) | `ares-tools/src/privesc/`, `automation/{adcs_exploitation,s4u,rbcd,trust}.rs` |
| `lateral` | `lateral_movement` | psexec/wmiexec/smbexec/evil-winrm/RDP/SSH, PtH, MSSQL | `gpt-5` / 300 (`:185-186`) | `lateral::tool_definitions()` + `lateral::callback_definitions()` | `ares-tools/src/lateral/`, `automation/{winrm_lateral,rdp_lateral,pth_spray}.rs` |
| `coercion` | — | Responder, mitm6, PetitPotam, DFSCoerce, all ntlmrelayx variants | `gpt-5-mini` / 30 (`:192-193`) | `coercion::tool_definitions()` | `ares-tools/src/coercion.rs`, `automation/{coercion,ntlm_relay,*_coercion}.rs` |
| *(all)* | — | — | fallback 75 | `+ reporting::tool_definitions()` `+ callback_tool_definitions()` (`tool_registry/mod.rs:311-320`), then `strip_secrets_from_all()` (`:324`) | — |

**Trap — role toolsets are code, not config.** `agents.<role>.tools` in `config/ares.yaml` is decorative; `tools_for_role` is the only source (`tool_registry/mod.rs:282`). Editing YAML tool lists changes nothing.

**Trap — `ARES_AGENT_MAX_STEPS` flattens every role.** If the var is merely *set* (even to garbage) `with_config_max_steps` returns early and discards all per-role YAML values (`agent_loop/config.rs:92-97`). Setting it to debug one role drops `lateral` from 300 and `coercion` from 30 to the same number.

**Trap — 14 tools are cross-routed to the `recon` worker** regardless of the calling role, because only that image has netexec (`RECON_ROUTED_TOOLS`, `tool_dispatcher/mod.rs:72-87`; `resolve_queue_role`, `:327-334`). A `password_spray` issued by `credential_access` appears in `recon.log`.

Task-type → role fallback map is `llm_runner.rs:306-321`. The `target_role` **argument** passed by the caller to `do_submit_outcome` (`submission.rs:226`) wins over it, but only when `AgentRole::parse` accepts the string (aliases at `tool_registry/mod.rs:48-58`); anything unparsable falls through to `role_for_task_type` (`submission.rs:243-244`). Both unmapped → `warn!("No LLM role mapping for task type or target role, dropping")` (`submission.rs:246-252`).

**Trap — `target_role` is not a payload key.** `rg -n '"target_role"' ares-cli/src ares-llm/src` returns zero hits: no code reads it out of a task payload. Writing `"target_role": "privesc"` into an injected vuln or a deferred payload does nothing.

## Three dispatch paths — know which one you are debugging

| Path | Entry | Produces an LLM loop? | Result handling |
|---|---|---|---|
| **Automation → LLM** | `auto_*` → `throttled_submit_outcome` (`submission.rs:45`) → `do_submit_outcome` (`:223`) → `submit_to_llm` (`:269`) | yes, `tokio::spawn` in-process (`:405`) | `send_result` → JetStream → result consumer → `process_completed_task` |
| **Automation → direct tool** | `auto_*` → `llm_runner.tool_dispatcher().dispatch_tool(role, task_id, call)` — 25 sites (e.g. `automation/crack.rs:358`, `automation/gpo.rs:407`) | **no** | bypasses `process_completed_task`; parser discoveries still land via `ares:discoveries:{op}` (`redis_dispatcher.rs:281-290`), but the raw-text pass and `exploit_*` hooks do not run — each site compensates itself (`crack.rs:404-425` replays both extractors; ADCS/GPO write the scoreboard mark directly) |
| **Generic vuln queue** | `exploitation_workflow` (`exploitation.rs:82`) pops `ares:op:{op}:vuln_queue` → `exploit` task → LLM | yes | as row 1 |

`do_submit_outcome` is the single choke point for **LLM-routed** dispatch — automation→LLM submits, the generic exploit path and the deferred drain (`submission.rs:230-233`).

**Trap — the red-dispatch freeze is not total.** `do_submit_outcome` is the *only* consumer of `is_red_draining()` (`submission.rs:235`; `rg -n 'is_red_draining' ares-cli/src` returns exactly two hits — the definition at `dispatcher/mod.rs:190` and that one call). The 25 direct `dispatch_tool` automation sites never consult it, and their loops only exit on `shutdown_rx`, which is not signalled until the process tears down. After `mark_red_draining()` those loops keep firing real tools at the target for the whole red drain, teardown and blue wait. Expect live tool activity in `<role>.log` after "Red dispatch frozen" — that is the design, not a leak, but do not tell an operator the range is quiet.

**`is_automation_owned_vuln` deletes ~25 vuln types from the generic path** (`exploitation.rs:22-64`): both delegation kinds, `rbcd`, `child_to_parent`, `forest_trust_escalation`, SMB/LDAP signing, the seven ACL primitives, `shadow_credentials`, `sid_history_abuse`, `seimpersonate`, `ntlm_relay`, `laps_abuse`/`laps_reader`, every `EXPLOITABLE_ESC_TYPES` member (`exploitation.rs:18,55`), and any `gpo_*` prefix. Those are dispatched by their own automation. `ntlmv1_downgrade` is deliberately *not* owned and stays on the LLM path (`exploitation.rs:34-38`, asserted at `:450,455-456`).

Exploitation is capped at `MAX_CONCURRENT_EXPLOITS = 3` with a 120s per-vuln cooldown (`exploitation.rs:68,71`) and abandons a vuln after `MAX_EXPLOIT_FAILURES = 5` (`state/dedup.rs:20`) — ~10 min ceiling per stuck vuln.

**`NON_LLM_TYPES = ["crack", "command"]` (`routing.rs:116`) means "not throttled", not "no LLM".** It only makes the throttler return `Allow` immediately (`throttling.rs:100-103`) and excludes the task from `llm_task_count`. `crack` avoids the LLM because `automation/crack.rs` dispatches the tool directly, not because of this list.

## Throttle → wait → defer → drop

`Throttler::check` (`throttling.rs:94-185`), in order:

1. non-LLM task types → `Allow`.
2. global backoff active (set by 3 rate-limit errors) → `Wait(remaining)`.
3. `llm_count >= hard_cap` (`hard_cap = 1.5 × max_concurrent_tasks`, `config.rs:286-288`): `acl_chain_step` is always-bypass and unlimited (`:119-130, :237`); a critical-path task bypasses up to `MAX_BYPASS_TASKS = 10` (`:52,132-152`); otherwise `Defer`.
4. `llm_count >= max_concurrent_tasks`: allow if this role is under `max_tasks_per_role`, else `Defer` (`:158-173`).
5. under `dispatch_delay` since last dispatch → `Wait(delta)`.

**`is_critical_path` has three shapes, not one** (`throttling.rs:241-296`): an `exploit` task (`CRITICAL_PATH_TASK_TYPES`, `:21`) whose payload `vuln_type` is in `CRITICAL_PATH_VULN_TYPES` (`:31-43`, 11 entries); *any* `privesc_enumeration` whose `techniques[]` contains a string matching `delegation` (`:263-277`); *any* `coercion` whose `techniques[]` contains `ntlmrelayx_to_adcs` or `petitpotam` (`:279-293`). Count all three when you are reconciling hard-cap bypasses.

`Wait` sleeps then re-checks **exactly once**; anything but `Allow` on the recheck goes to the deferred queue (`submission.rs:123-146`). Each submit records an `automation.dispatch` span whose `automation.decision` is one of `allow`, `defer`, `wait`, `wait_allow`, `wait_defer`, `drop_assist_abandoned` (`submission.rs:52-146`).

**One more gate, after the throttler already said `Allow`: per-credential concurrency.** `submit_to_llm` calls `credential_inflight.try_acquire(cred_key)` (`submission.rs:280-282`); on failure it enqueues to the deferred queue and returns `Deferred`, or `Dropped` if that queue is full. It logs only `debug!("Credential concurrency limit reached, deferring task")` (`:283-286`) and `warn!("Deferred queue full while gating on cred — task dropped")` (`:298-301`). The span already recorded `automation.decision=allow` at `:109-110` before `do_submit_outcome` was called, so **an allowed task with no `Routing task to LLM runner` line is usually this gate**. The slot is released by whichever of the result consumer or the stale reaper evicts the tracker entry (`submission.rs:626-631`).

| Env var | Default | Cite |
|---|---|---|
| `ARES_MAX_CONCURRENT_TASKS` | 12 (hard cap 18) | `config.rs:192`, `:286` |
| `ARES_MAX_TASKS_PER_ROLE` | 3 | `config.rs:198` |
| `ARES_DISPATCH_DELAY_MS` | 200 | `config.rs:199` |
| `ARES_DEFERRED_POLL_INTERVAL_SECS` | 10 | `config.rs:197` |
| `ARES_DEFERRED_TASK_MAX_AGE_SECS` | 300 | `config.rs:204` |
| `ARES_MAX_DEFERRED_PER_TYPE` / `_TOTAL` | 50 / 200 | `config.rs:205-206` |
| `ARES_STALE_TASK_TIMEOUT_SECS` | 300 | `config.rs:200` |
| `ARES_NON_LLM_TASK_TIMEOUT_SECS` | 6000 (deliberately above the 5700s tool timeout) | `config.rs:201-203` |

Full env catalog lives in `references/config-and-env.md` — do not re-derive it here.

**Trap — a task marked `failed` at 300s may still be running.** `cleanup_stale_tasks` (`monitoring.rs:340-400`) reaps tracker entries older than `stale_task_timeout`, **halved to 150s whenever `llm_count >= hard_cap`** (`:351-355`), logs `warn!("Removing stale task")` with `age_secs` (`:376-381`), releases the credential-inflight slot (`:387-391`) and calls `set_task_status(task_id, "failed")` (`:396`). The spawned agent loop is **not** aborted — it keeps running, keeps pushing discoveries, and may later `send_result` successfully. So "task failed" here is a tracker eviction, not a task outcome. `crack` and `command` are exempted to `ARES_NON_LLM_TASK_TIMEOUT_SECS` by `stale_threshold_for` (`:327-337`) precisely because a hashcat run was being reaped at `age_secs=329` (`:356-363`).

**Trap — `throttled_submit` cannot tell "safely queued" from "lost".** It maps both `Deferred` and `Dropped` to `Ok(None)` (`submission.rs:36-37`). Any caller that marks dedup on "dispatched" must use `throttled_submit_outcome` (`:45`). A full deferred queue is a `warn!("Deferred queue full, task dropped (will retry next tick)")`, not an error (`:172-176`).

**Trap — assist-abandoned patterns vanish silently.** A `(task_type, target, principal)` pattern that previously ended in `RequestAssistance` is refused for a TTL, returning `Dropped` with only a `debug!` (`submission.rs:86-99`). It looks exactly like the automation never fired.

## Dedup: four independent layers

Confusing these is the classic misdiagnosis. They do not share storage.

| Layer | Key | Identity hashed | Cite |
|---|---|---|---|
| Automation dedup sets | `ares:op:{op}:dedup:{set_name}`, SADD + `EXPIRE 86400` | whatever the automation passes (64 `DEDUP_*` set names) | `state/dedup.rs:133-153`; names at `state/mod.rs:27-121` |
| Deferred producer-side | `ares:deferred:{op}:{task_type}:sigs` (SET) beside the ZSET | `(task_type, target_role, technique, target_ip\|dc_ip\|target, credential_key, finding_key)` — timestamp and priority **excluded** | `deferred.rs:32, 111-165`; `finding_key` at `:167-198` |
| Exploited / superseded | `ares:op:{op}:exploited`, `:superseded` | `vuln_id`, plus computed supersedes written into the same set | `state/dedup.rs:32-128` |
| Loot presentation | in-memory at render time | credential/hash/user identity normalisation | `ares-cli/src/dedup/`, `ops/loot/format/json.rs:8` |

Deferred ZSET score is `priority × 1e9 + enqueue_millis` (`deferred.rs:107-110`) — priority buckets dominate, FIFO only within a bucket. The Lua enqueue returns `1` accepted, `0` per-type full, `-1` global full, `-2` identical member, `-3` duplicate signature (`deferred.rs:46-49`).

**`finding_key` is load-bearing.** It reads `(vuln_id, acl_type, source_user, target_user)` from the payload root *and* from a nested `step` object, because `auto_acl_chain_follow` wraps the edge under `step`. Without it every ACL edge in a domain hashes identically and paths 2..N are retired as dispatched — the documented 19,453-collected / 1-acted-on gap (`deferred.rs:118-127`).

**Dedup mostly survives restart.** Every set carries `EXPIRE 86400` (`state/dedup.rs:151-152`) and `load_from_redis` rehydrates all 64 sets (`state/persistence.rs:65-79`), so an orchestrator restarted inside 24h inherits prior decisions and many automations appear never to fire again. Two exceptions: `DEDUP_TRUST_FOLLOW` is DELETEd on load so the trust path re-fires against the new binary (`state/persistence.rs:42-63`, logs `Cleared trust_follow dedup on op load — trust workflow will re-fire`; test at `:582`), and `unpersist_dedup` (`:158-178`) is the programmatic retry path.

**Exploited counts are inflated on purpose.** `mark_exploited` SADDs computed supersede ids into the *same* `exploited` set and mirrors them into `superseded` (`state/dedup.rs:32-128`). Diff the two sets before quoting an "exploited" number.

## One task end to end

Automation → LLM → worker tool → back to state. Log strings below are verbatim; grep them exactly.

| # | Hop | Code | Verbatim log (level) |
|---|---|---|---|
| 0 | orchestrator boots the loops | `automation_spawner.rs:98`, `mod.rs:919` | `Automation tasks spawned` (info, `count=62`) then `Orchestration loop started — all background tasks running` (info) |
| 0b | supporting loops announce | `results.rs:42`, `exploitation.rs:90`, `completion.rs:476` | `Result consumer started` / `Exploitation workflow started (max concurrent: 3)` / `Completion monitor started` |
| 1 | an `auto_*` loop finds work and submits | `submission.rs:52-58` | span `automation.dispatch` with `task_type`, `target_role`, `priority`, `automation.decision` |
| 2 | throttler verdict | `throttling.rs:127,140,149,154,167,171` | `Hard cap: …` / `Soft cap: …` — info for the allow-paths at `:127,149,167`; debug for the defers at `:154,171`; **the bypass-cap defer at `:140` is `warn`**, so it is the only defer visible at `RUST_LOG=info` |
| 2b | deferred instead | `deferred.rs:751-753` | `Deferred queue drain cycle` (info, `dispatched=N`) — **emitted only when `dispatched > 0`**. A saturated throttler makes the drain re-enqueue and `break` with `dispatched=0` (`deferred.rs:743-747`), so silence means "no capacity", not "no drain loop". Confirm the loop is alive with `ZCARD ares:deferred:{op}:{task_type}` instead |
| 2c | credential gate, after the throttler said allow | `submission.rs:278-310` | `Credential concurrency limit reached, deferring task` (**debug**) or `Deferred queue full while gating on cred — task dropped` (warn) — the wedge where the span says `allow` but step 3 never logs |
| 3 | choke point admits it | `submission.rs:322` | `Routing task to LLM runner (Rust agent loop)` (info; `task_id`, `task_type`, `role`) |
| 4 | agent loop starts in-process | `llm_runner.rs:151-157` | `Starting LLM agent loop` (info; `task_id`, `task_type`, `role`, `tools=<count>`) — **this is the count of real agent tasks; do not measure provider HTTP calls** |
| 5 | model picks a tool, dispatcher sends it | `redis_dispatcher.rs:222` | `Dispatching tool call to worker` (debug; `tool`, `call_id`, `subject`, `effective_role`) inside span `dispatch.{tool}` |
| 6 | worker receives | `worker/tool_executor.rs:185,544` | `Starting tool executor loop (NATS queue subscribe)` at boot; `Executing tool` (info; `tool`, `call_id`, `task_id`) per call |
| 6b | worker skipped it | `tool_executor.rs:532` | `Skipping tool cached as ENOENT — next re-probe once cooldown expires` (info; `failures`, `remaining_secs`) |
| 7 | worker replies | `tool_executor.rs:695` | `Tool result ready` (debug; `tool`, `call_id`, `has_error`) |
| 8 | orchestrator receives | `redis_dispatcher.rs:275` | `Tool result received` (debug) |
| 9 | discoveries pushed **before** the loop ends | `redis_dispatcher.rs:281-290`; key `ares:discoveries:{op}` (`state/mod.rs:126`) | — |
| 9b | poller drains them (5s) | `discovery_polling.rs:20,46` | `Processing real-time discoveries` (info; `count`) |
| 10 | tool pruned mid-task | `agent_loop/runner.rs:608,662,678` | `Tool binary not found (ENOENT from worker) — removing from available tools for the rest of this task` / `Tool exceeded max call limit — removing from available tools` / `Removed tools from active definitions` |
| 11 | loop ends | `llm_runner.rs:323-376` | one line per `LoopEndReason` — see the table below; the happy path is `Task completed via LLM: {result}` (info; `steps`, `tool_calls`, `input_tokens`, `output_tokens`) |
| 12 | result published to JetStream `ares.tasks.results.{task_id}` | `submission.rs:631-638`; `task_queue.rs:507-518` | — |
| 13 | result consumer → main loop → processing | `mod.rs:963-971`; `result_processing/mod.rs:151` | `Task completed successfully` (info) or `Task failed` (warn) |
| 14 | parser discoveries published to state | `result_processing/mod.rs:184-199` | — (`extract_discoveries` reads **only** the `discoveries` key) |
| 14b | secondary regex pass over raw stdout | `result_processing/mod.rs:201-218`, body `:1991-2013` | — (`extract_from_raw_text` also publishes credentials/hashes/hosts, but reads **only** `tool_outputs` — real tool stdout. The LLM-authored `summary` / `result` / `output` fields at the payload root are never fed to any extractor, `mod.rs:1998-2001`) |

**Step 11 has seven terminal shapes.** Only the first is success; the rest are the ones you grep when an automation "did nothing" (`llm_runner.rs:323-376`):

| `LoopEndReason` | Level | Verbatim log |
|---|---|---|
| `TaskComplete` | info | `Task completed via LLM: {result}` (`:332`) |
| `RequestAssistance` | warn | `LLM agent requested assistance: {issue}` (`:339`) |
| `MaxSteps` | warn | `LLM agent hit max steps limit` (`:346`) |
| `EndTurn` | **debug** | `LLM agent ended turn: {content}` (`:353`) |
| `MaxTokens` | warn | `LLM agent hit max tokens` (`:360`) |
| `BudgetExceeded` | warn | `LLM agent budget circuit breaker tripped: {reason}` (`:367`) |
| `Error` | warn | `LLM agent loop error: {err}` (`:374`) |

`EndTurn` at debug is the silent one: at `RUST_LOG=info` a model that just stopped talking leaves `Starting LLM agent loop` with no matching terminal line.

The nine callbacks the agent loop handles in-process without touching a worker are `CALLBACK_TOOLS` (`tool_registry/mod.rs:66-79`): `task_complete`, `request_assistance`, `report_crack_failed`, `report_finding`, `report_lateral_success`, `report_lateral_failed`, `record_compromised_host`, `list_credentials`, `get_operation_summary`. `record_credential` and `record_timeline_event` were removed from that list on purpose (`:75-76`).

**Trap — step 9 happens even when step 11 fails.** Discoveries land in Redis before the agent loop returns. A task that ends in `MaxSteps` or `Error` still contributed real state; never conclude "nothing was found" from the loop outcome.

**Trap — the old pruning string is gone.** `Tool binary not found (spawn failed) — removing from available tools` has zero hits at HEAD. A runbook still grepping it reports "no cascade" during a live cascade. Current strings are the two in step 10 plus the worker-side `Tool binary not found (ENOENT) — backing off before next re-probe` (`tool_executor.rs:677`).

**Trap — the orchestrator waits 95 minutes for a tool reply.** `DEFAULT_TOOL_TIMEOUT_SECS = 95 * 60` (`tool_dispatcher/mod.rs:68`), and the NATS request is sent with `.timeout(None)` so async_nats' 10s client default cannot preempt it (`redis_dispatcher.rs:237-242`). A worker that never replies burns the full 95 minutes. Note the stale reaper will have marked that task `failed` at 300s (or 150s) while it was still waiting — see the trap under the throttle env table.

**Trap — steps 5-8 do not exist under `ARES_TOOL_DISPATCH=local`.** That swaps in `LocalToolDispatcher` (`mod.rs:564-566`, banner `Tool dispatch: local (in-process via ares-tools)`), the standalone attacker-VM configuration. There is no worker, so `Starting tool executor loop`, `Executing tool`, `Tool result ready` and `Tool result received` never appear. The only per-call marker is `debug!("Executing tool locally")` (`tool_dispatcher/local.rs:74`). Grepping for the worker strings on such a box reports "no tools ran" during a healthy op.

## Completion, freeze, teardown

`evaluate_completion` is a pure function (`completion.rs:399-441`), priority order exactly:

1. `completed` flag → `Stop("operation marked completed")`
2. `elapsed >= hard_max` → `Stop("hard max runtime exceeded")` — `hard_max = soft × 2` (`:469`)
3. `elapsed >= soft_max` **and** (no DA **or** all forests dominated) → `Stop("max runtime exceeded")`; with DA and an undominated forest it falls through and extends
4. no DA → `Continue`
5. `stop_on_domain_admin` → `Stop("domain admin achieved (stop_on_domain_admin)")`
6. `stop_on_golden_ticket` → stop only once `has_golden_ticket`
7. default mode: undominated forests remain → `Continue`; all dominated → `BeginGracePeriod`, then `Stop("all forests dominated (post-exploitation complete)")` once **180s hardcoded** grace elapses (`:520,534-541`)

`undominated_forests_empty` requires *both* `undominated_forests().is_empty()` **and** `is_multi_forest_op_complete()`, and is computed only in default mode — forced `false` under either stop flag (`completion.rs:507-511`).

Stop-flag source is `operation.stop_on_domain_admin` / `stop_on_golden_ticket` read straight off config (`completion.rs:454-464`). **`continue_after_da` is never consulted here** — it only stops individual automation loops from idling. `docs/strategy.md` is wrong on this.

Then, in this deliberate order:

```
mark_red_draining()            completion.rs:562  → AtomicBool, dispatcher/mod.rs:185-191
  ↳ every subsequent do_submit_outcome drops the task     submission.rs:235-240
red drain, capped 300s, polls tracker + Redis pending + deferred every 10s   completion.rs:571-619
target mutation teardown (mutation journal)              completion.rs:632-659
blue investigation wait                                   (only when blue enabled)
```

Teardown precedes the blue wait on purpose — the source records a live run that reported completion at 17:06 and did not revert until 17:24 (`completion.rs:623-631`).

Greps for the terminal phase. **Run these on the box** — `/var/log/ares/orchestrator.log` exists only on the EC2 host (`.taskfiles/ec2/scripts/launch-orchestrator.sh.tmpl:89`) and is root-owned, so every one of them fails verbatim on a workstation. Wrap each in `task ec2:exec` (`.taskfiles/ec2/Taskfile.yaml:1472`) with `sudo`:

```bash
task ec2:exec EC2_NAME=kali-ares CMD="sudo rg -a 'Completion condition met' /var/log/ares/orchestrator.log"      # completion.rs:552 — fields reason, elapsed_secs, has_domain_admin, has_golden_ticket
task ec2:exec EC2_NAME=kali-ares CMD="sudo rg -a 'Red dispatch frozen' /var/log/ares/orchestrator.log"           # completion.rs:563
task ec2:exec EC2_NAME=kali-ares CMD="sudo rg -a 'Red draining — dropping task' /var/log/ares/orchestrator.log"  # submission.rs:238 (debug level)
task ec2:exec EC2_NAME=kali-ares CMD="sudo rg -a 'All forests dominated — starting' /var/log/ares/orchestrator.log"  # completion.rs:538 — 180s grace, op is NOT stuck
```

The blue wait is bounded, not open-ended: `resolve_blue_drain_budget` (`completion.rs:230-238`, called at `:721-723`) honours `ARES_BLUE_DRAIN_MAX_SECS` and otherwise defaults to `BLUE_INVESTIGATION_TIMEOUT_SECS + BLUE_DRAIN_SLACK_SECS` = 2700 + 600 = **3300s** (`:190,205`). Empty, non-numeric, negative and `0` values all fall back to the default (`:1943-1946`).

**Trap — an op that looks hung after "Completion condition met" is usually blue.** Red is frozen; the operation stays `running` until blue investigations drain. Check `red_completed_at` / `red_completion_reason` / `red_blocked_on_blue` in `ares:op:{op}:meta` (`completion.rs:812-822`).

**Trap — the soft budget is 7200s, not 3600s, when no config loads.** `wait_for_completion` is called with `config.timeouts.operation_timeout` filtered to `> 0` and `.unwrap_or(7200)` (`mod.rs:903-907`). With the shipped `config/ares.yaml:200` (3600s) the hard ceiling is 2h; with no config it is **4h**.

**Trap — the result consumer can die and silently respawn.** If its channel closes, the main loop logs `error!("Result consumer channel closed unexpectedly — restarting consumer")` (`mod.rs:975`), sleeps 2s and calls `spawn_result_consumer` again. One of those lines in a log is a real lifecycle failure, not noise; results in flight across the gap are what to check next.

**Trap — `ares ops stop` before the orchestrator boots is a no-op.** `run_inner` DELETEs `ares:op:{id}:stop_requested` at startup (`mod.rs:888-892`) so a stale flag cannot kill a restart. The main loop polls the key every 5s (`mod.rs:989-994`).

## Firewalls the design deliberately puts in your way

Each of these looks like a bug the first time.

| Symptom | Cause | Cite |
|---|---|---|
| LLM "found" a credential; state has nothing | `record_credential` and `record_timeline_event` are disabled stubs that return guidance text and persist nothing | `callback_handler/mod.rs:60-80` |
| A shell tool clearly printed a user list; nothing extracted | `LlmDirectedShell` provenance suppresses **all** extraction for `smbexec`/`wmiexec`/`psexec`/`evil_winrm`/`mssql_command`/… | `output_extraction/mod.rs:200-206`; classes at `tool_registry/provenance.rs:23-37,89` |
| An enumerator printed `[+] user:pass`; no credential recorded | `AttributeEnumerator` provenance allows users/hosts/shares but suppresses credentials/hashes (attacker-plantable `description` fields) | `output_extraction/mod.rs:222-227` |
| A hallucinated `dispatch_recon` / `complete_operation` call did nothing | 17 removed names stay trapped in-process so they cannot become real tasks | `tool_registry/mod.rs:89-112` |
| The model never sees a password field — **with two exemptions** | The 21 keys in `SECRET_SCHEMA_KEYS` are stripped by `strip_secrets_from_all`; the worker's credential resolver injects them at dispatch. Exempt: `password_spray.password` stays visible because it is input data, not a credential to resolve (`exposed_secret_keys`, `:163-168`), and the six `CALLBACK_NAMES_WITH_SECRETS` tools return early and are not stripped at all (`:149-156`, early return `:176-178`) | keys `tool_registry/mod.rs:122-144`; strip call `:324` |

## Where to go instead of here

Routing map: `SKILL.md`. Nearest neighbours only:

| Question | Asset |
|---|---|
| "This op is stuck / slow / broken" | skill `ares-debug` — probe ladder and wedge signatures. Its deploy/restart semantics and Redis key TYPEs are correct; two things are stale (see below). |
| Mistakes this assistant actually makes on this repo; the evidence contract before claiming anything works | `references/hard-won-lessons.md` — read first, always |
| Redis key names, types and verbs | `references/state-and-redis.md` |
| Tool binaries, dispatch/registry parity, CI gates | `references/tools-and-gates.md` |
| Log/span/LogQL catalog, OTel service names | `references/observability.md` |
| Deploy paths, restart semantics | `references/deployment.md` |

### Corrections to `ares-debug`, verified at HEAD

`SKILL.md:116` gives the writer verb for `:hashes` as `hset`; that is the AES-upgrade path (`ares-core/src/state/reader.rs:432`) — the **insert** verb is `hset_nx` (`:414`). Everything else in that table is right: the TYPE column is correct throughout and the `:creds` → `:credentials` warning at `SKILL.md:110` is ground truth. The table omits two keys: `:domains` SET via `sadd` (`reader.rs:362`) and `:techniques` SET via `sadd` (`:585`). Full table in `references/state-and-redis.md`.

Deploy/restart semantics in `ares-debug` are also correct and do not need re-deriving here (`SKILL.md:396-405`); `references/deployment.md` is the single authority for that.

The two things that **are** stale:

1. `SKILL.md:285` — the worker's `unavailable_tools` is described as a permanent per-process `HashSet` with "no TTL, no re-probe". It is a `HashMap<String, UnavailableEntry>` on a 60 s → 300 s → 1800 s → 4 h backoff (`ares-cli/src/worker/tool_executor.rs:351-372`), cleared outright by one successful spawn (`:592-601`). See `references/tools-and-gates.md`.
2. `SKILL.md:49`, `:269`, `:274` grep `Tool binary not found (spawn failed)` — see the trap below.

## Marked UNVERIFIED

- Exact per-role LLM tool **counts** (e.g. "recon = 36 tools"). Composition is verified from `tool_registry/mod.rs:282-327`; the totals are not, because they require building and running the registry. Read the real number from `Starting LLM agent loop`'s `tools=` field (`llm_runner.rs:151-157`) or a session-log `start` record.
- The claim that exactly ten infra loops always run: nine are unconditional at `mod.rs:661-755` plus the completion monitor at `:897`; blue adds two more under `ARES_BLUE_ENABLED=1` (`mod.rs:779,810,818`). Count re-derived by reading spawn sites, not asserted by any test.
