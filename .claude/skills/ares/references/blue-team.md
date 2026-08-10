# Blue team

Blue is a detection-and-investigation system: a deterministic code sweep of the whole detection catalog runs **before** an LLM hunter loop, and the result is scored as a MITRE-ID join against red's own record. It is **detect-only by default and on every shipped deploy path**.

Routing map: `SKILL.md`. Nearest neighbour: live-op triage of a stuck operation belongs to `ares-debug`.

## Read this first

1. **`ARES_DEPLOYMENT` unset silently widens every query; mismatched silently zeroes it.** `build_selector` appends `, deployment="<val>"` only when the env var is set (`ares-tools/src/blue/detection/mod.rs:37-42`). Unset ⇒ label omitted ⇒ every template spans other ranges' logs. Wrong value ⇒ zero rows, HTTP 200, no error. This is the single most common "all 55 templates fired zero" cause.
2. **`failed` is not `no_match`.** A template whose Loki query errored lands in `SweepOutcome.failed` and its technique is **UNCHECKED, not clean** (`ares-cli/src/orchestrator/blue/sweep.rs:526-531`). The prompt says so verbatim (`sweep.rs:588-593`). Never conclude "blue missed nothing" from a sweep with a nonzero `failed` count.
3. **Coverage is an ID join with no sibling matching.** `red_parent == blue_parent && (red == red_parent || blue == blue_parent)` (`ares-core/src/correlation/redblue/engine.rs:70-72`). T1003 ↔ T1003.006 hits in both directions. T1558.001 vs T1558.003 is a **permanent miss** no matter how well blue detected the behaviour. Prefer base IDs on templates.
4. **`detect_golden_ticket` and `detect_silver_ticket` cannot fire, on purpose.** They exist only so T1558.001 / T1558.002 survive the grounding gate. The real rules are absence-of-partner-event correlations in `sweep.rs`. `detections.yaml:461-471` spells out that dropping a stage to "fix" silver turns it into a rule matching every SMB/LDAP/MSSQL/WinRM access in the domain.
5. **Auto-submit is the only path that writes an operation coverage scorecard.** The runner reads `operation_id` from the request's *top level* (`ares-cli/src/orchestrator/blue/runner.rs:264-267`) and never falls back to the alert — inside blue, `alert.operation_context` is read only for `attack_window_start` (`sweep.rs:495`). Only `auto_submit.rs:298` sets it at the top level. `blue from-operation` buries it in `alert.operation_context` (`ares-cli/src/blue/submit.rs:180-181`); red's own completion submitter does the same (`orchestrator/completion.rs:907-913`) and its published request has no `operation_id` key at all (`completion.rs:953-965`); `benchmark replay` omits it too (`ares-cli/src/benchmark/replay.rs:527-537`). `operation_id = None` skips `generate_operation_coverage_report` (`investigation.rs:410-412`). Symptom: the investigation report lands in `blue/investigations/` and no `blue/{op}.md` appears. Fix: run `ares blue report --operation-id <op>` (or `task blue:reports:consolidate`) by hand.
6. **Submits and queries can still land on different backends — but only via `blue:multi:remote`.** As of 2026-08-08 `blue:submit` uses `{{.TRANSPORT_ARGS}}` like every read task (default `--ec2 kali-ares`), so it agrees with them. `blue:multi:remote` and `blue:multi:logs` remain hardwired to `kubectl exec … deploy/ares-blue-orchestrator`. Symptom of the mismatch: "Investigation submitted: inv-…" then `task blue:multi:list` shows nothing — you submitted to K8s and queried EC2. `BLUE_TRANSPORT` now also accepts `local`.
7. **`ares blue delete` leaves the lock and the queued request.** See [Redis keys and the resurrection trap](#redis-keys-and-the-resurrection-trap).

## Pipeline

| Stage | Where | Notes |
|---|---|---|
| Submit | `ares blue submit` / `blue from-operation` | **Enqueue only.** Publishes to NATS, prints `Status: submitted` (`ares-cli/src/blue/submit.rs:94-101,258-264`) |
| Auto-submit | `orchestrator/blue/auto_submit.rs` | Only when `ARES_BLUE_ENABLED=1`; re-fires when red's milestone level *increases* |
| Runner | `orchestrator/blue/runner.rs:236+` | **Serial** — one investigation at a time, no spawn, 2700s cap |
| Deterministic sweep | `orchestrator/blue/sweep.rs` | Whole catalog in code, **before** the LLM |
| LLM loop | `orchestrator/blue/investigation.rs:203-204` | `max_steps: 75`, `max_tool_calls_per_name: 25` — both hardcoded |
| Inline chains | `investigation.rs:419-423` | `MAX_INLINE_CHAINS = 4`, `CHAINED_HUNTS_TIMEOUT_SECS = 420` |
| Ticket re-check | `sweep::recheck_golden_tickets` / `recheck_silver_tickets` | Run again at close (`investigation.rs:342-345`) |
| Score + report | `ares-core/src/eval/`, `ares-core/src/reports/blueteam/` | Coverage joined against red state read from Redis |

**Sub-agents run inline, not on workers.** Triage / ThreatHunter / LateralAnalyst / EscalationTriage are dispatched inside the orchestrator process. Blue workers poll `ares.blue.tasks.{role}` (`ares-core/src/nats.rs:50,109`) and nothing in production publishes there — **an idle blue worker fleet is normal, not a stall**.

Four submitters publish to the queue. Only one is scorecard-capable:

| Submitter | Top-level `operation_id`? | Scorecard |
|---|---|---|
| `auto_submit.rs:289-302` | **yes** (`:298`) | `blue/{op}.md` written automatically |
| `blue submit` / `blue from-operation` (`submit.rs`) | no — only in `alert.operation_context` (`:180-181`) | none |
| red completion (`orchestrator/completion.rs:953-965`) | no | none |
| `benchmark replay` (`ares-cli/src/benchmark/replay.rs:527-537`) | no | none |

`multi_agent` and `auto_route` are in every request body and **the runner reads neither** (`rg -n 'auto_route\|multi_agent' ares-cli/src/orchestrator/blue/` hits only `auto_submit.rs:295-296`). `task blue:submit MULTI_AGENT=true` and `ares blue submit --no-auto-route` (`ares-cli/src/cli/blue.rs:154-156`, no task exposes it) therefore change nothing about how the investigation runs.

Auto-submit milestone levels (`auto_submit.rs:48-59`; `INITIAL_DELAY_SECS = 90`, `CHECK_INTERVAL_SECS = 30` at `:30,33`):

| Level | Condition |
|---|---|
| 3 | `red_completed_at` or `completed_at` set (red terminal) |
| 2 | `has_domain_admin` |
| 1 | ≥5 credentials **and** ≥3 vulns (`MIN_CREDENTIALS_DEEP`/`MIN_VULNS_DEEP`, `auto_submit.rs:26-27`) |
| 0 | nothing yet |

A manual `task blue:multi:remote` on an `ARES_BLUE_ENABLED=1` op usually creates a duplicate. Check `blue operation-status` first.

## Detection catalog

Single file: `ares-core/src/detection/detections.yaml`, `include_str!`'d into a `OnceLock` with `.expect("detections.yaml is invalid")` (`ares-core/src/detection/mod.rs:87-91`). **Compile-time embedded — editing it needs a rebuild and redeploy, invalid YAML panics on first use, there is no runtime reload.**

Verified aggregates:

| Metric | Value |
|---|---|
| Templates | 55 (`rg -c '^  detect_[a-z0-9_]+:$' ares-core/src/detection/detections.yaml`) |
| Alias strings | 6 across 5 templates — `detect_account_enumeration`, `detect_password_spray`, `detect_gpp_password`, `detect_credentials_in_files`, `detect_certificate_abuse`, `detect_bloodhound_collection` (`detections.yaml:191,479,542,658,691`) |
| Distinct `mitre_id` | 39 |
| Tactic split | credential_access 17, discovery 11, execution 9, privilege_escalation 9, lateral_movement 6, collection 1, defense_evasion 1, persistence 1 |
| Severity split | high 22, medium 18, critical 15 (no `low`) |
| `list_detection_templates` rows | 55 + 6 aliases + `get_host_activity` + `get_user_activity` = **63** (`ares-tools/src/blue/detection/catalog.rs:16-35`) — the printed count is never the template count |

Field semantics (`ares-core/src/detection/mod.rs:25-57`):

| Field | Required | Effect |
|---|---|---|
| *map key* | yes | The template name. There is no `id:` field |
| `description` | yes | Header text; also the `technique_name` written by `add_technique` |
| `mitre_id` | yes | **The only thing that scores.** Copied verbatim into blue state (`sweep.rs:1250,1259`) |
| `tactic` | yes | Maps to `evidence_type` via `evidence_type_for_tactic` |
| `severity` | yes | critical 0.9 / high 0.8 / medium 0.6 / else 0.5 confidence |
| `aliases` | no | Resolvable by `find_template`; listed separately |
| `log_source` | no (`windows-security`) | Selects the `job=` label. Only `detect_remote_registry_start` uses `windows-system` |
| `event_ids` | no | 1 ⇒ `\|= "id"`, 2+ ⇒ `\|~ "(a\|b)"` |
| `patterns` | no | ONE OR-stage |
| `filter_stages` | no | N stages: OR within a stage, AND between stages |
| `exclude_patterns` | no | Appended as `` !~ `(?i)(…)` ``. **Undocumented in the YAML's own field block** (`detections.yaml:150-166`) — easy to typo. Four templates use it: `detect_dcsync` (`:360`), `detect_dcsync_replication` (`:377`), `detect_s4u_delegation` (`:520`), `detect_valid_account_reuse` (`:621`) |
| `host_as_filter` | no | Appends `\|= "<host>"` when a host is supplied. Only `detect_port_scanning` sets it |
| `connection_types` | no | Feeds `templates_for_connection_type` and derives `mitre_for_connection_type` |
| `red_team_tool`, `auto_pivot` | no | **No effect on the query.** Both render into `format_header` (`ares-tools/src/blue/detection/templates.rs:18-31`); `red_team_tool` also appears in every `list_detection_templates` row as `tool=` (`catalog.rs:16-18,25`), and `auto_pivot` is asserted by `tests.rs:186-206`. Not unreferenced — don't drop them |

**No `deny_unknown_fields` on `TemplateEntry`** (`mod.rs:25-26`) — a typo'd key is silently dropped and the rule quietly loses that filter.

### LogQL composition

`ares-tools/src/blue/detection/config.rs` `build_template_logql`, in order: selector → event-ID filter → `patterns` → each `filter_stages` entry → `exclude_patterns` → optional host line filter.

**Any stage with more than one term or a regex metacharacter must reach Loki inside a backtick raw string.** LogQL double-quoted strings take Go escape rules, so `cmd\.exe` arrives as the invalid escape `\.` and Loki answers 400 — correctly non-retryable, so it surfaces as one WARN line. This previously killed all 15 `filter_stages` templates at once (`ares-tools/src/blue/detection/mod.rs:72-89`). `is_regex_pattern` treats `. * + ? ( ) [ ] { } | ^ $ \` as metacharacters (`mod.rs:62-70`).

**Hostname is a regex label match**, `computer=~"host"` (`mod.rs:44-46`), not equality — a bare IP or short name partially matches the FQDN.

**Loki stores the Windows event XML JSON-escaped**, so field-anchored templates match `..u003e` (the escaped `'>` between a field name and its value) and anchor values with `.u003c`. A plain-text pattern matches nothing and the rule silently passes everything (`detections.yaml:447-451`).

### Degenerate entries — know these before you read a scorecard

| Template | ID | Behaviour |
|---|---|---|
| `detect_golden_ticket` | T1558.001 | **Cannot fire.** Grounding anchor only. Real rule = 4769-with-no-4768 in `sweep.rs` |
| `detect_silver_ticket` | T1558.002 | **Cannot fire.** Stage 3 requires `TicketEncryptionType` on a 4624 line, a field no 4624 carries (`detections.yaml:434-476`). Real rule = 4624-Kerberos-without-4769 |
| `detect_asrep_roasting_bulk` | T1558.004 | **Always fires.** No `patterns`, no `filter_stages` — renders to `{job="windows-security"} \|= "4768"` and matches every TGT request (`detections.yaml:426-432`). Treat a T1558.004 credit as suspect unless `detect_asrep_roasting` (the `PreAuthType`-anchored one) also fired |

## The deterministic sweep

`sweep::run_detection_sweep(investigation_id, attack_start)`, called at `investigation.rs:152-158` **before** the LLM loop. All 55 templates concurrently, `target_host = None`, 2h lookback.

Constants (`sweep.rs`): `DEFAULT_SWEEP_CONCURRENCY = 6` (`:42`), `DEFAULT_SWEEP_TIMEOUT_SECS = 360` (`:47`), `SWEEP_HOURS_BACK = 2` (`:51`), `MAX_REPORTED_ORPHANS = 20` (`:188`).

Detection queries are **hard-clamped to 2h** regardless of what the agent asks (`hours_back.min(2)`, `ares-tools/src/blue/detection/runner.rs:72`) — wider windows time out through the Grafana proxy. `event_count` saturates at `DETECTION_ENTRY_LIMIT = 100` (`runner.rs:155`), so "fired with 100 events" means "≥100" and event count cannot be used to judge a rule's precision.

### Outcome buckets — only one of these means "clean"

| Bucket | Meaning | Recorded to state? |
|---|---|---|
| `fired` | ≥1 event inside the attack window | **yes** — 3 writes each |
| `out_of_window` | Matched, but all events predate `alert.operation_context.attack_window_start` | **no, deliberately** (`sweep.rs:502-507`) |
| `no_match` | Ran, zero events — **the only true clean** | no |
| `failed` | Query errored — technique **UNCHECKED** | no |
| `not_run` | The 360s cap aborted the JoinSet first | no |

**`out_of_window` is defensive and currently unreachable from the sweep.** `run_detection_sweep` passes `attack_start` as `not_before` (`sweep.rs:832-838`) and `scan_start` clamps the query start *up* to it (`Some(nb) if nb > lookback => nb`, `ares-tools/src/blue/detection/runner.rs:67-77`), so every returned event is already ≥ `attack_start` and `attributable()` is always true. The ticket-correlation `FiredDetection`s carry `first_event_at: None` / `last_event_at: None` (`sweep.rs:457-468`) and hit `attributable`'s `_ => true` arm. Same caveat on the `Detections fired outside the attack window` log line (`sweep.rs:942`) — if you ever see it, the clamp broke; don't go hunting `attack_window_start`.

### What a fired detection writes (`sweep.rs:1240-1290`)

| Tool | Payload |
|---|---|
| `add_technique` | `technique_id` = template `mitre_id`, `technique_name` = description |
| `add_evidence` | `value` = the MITRE ID (auto-passes grounding), `source` = `detection_sweep:{template}`, `pyramid_level` = `"ttps"`, `timestamp` = first event |
| `record_timeline_event` | `"Baseline detection {template} fired: …"`, `source` = `detection_sweep` |

**Sweep evidence lands at pyramid level `ttps`**, so any report summing all sources reads "reached TTP level" the instant the sweep runs at all. `ares-core/src/reports/blueteam/provenance.rs:1-30` exists solely to split sweep-produced from analyst-produced tallies — read the `analyst_*` fields to see what the LLM actually found. An analyst re-running a catalog template through `run_detection_query` gets the same `detection_sweep` prefix (`runner.rs:35-48`), so it is **not** counted as independent analyst evidence.

## Forged-ticket correlations

Two rules live in code, not YAML, because the signal is the *absence* of a partner event and no line filter can express absence (`sweep.rs:53-106`).

| Rule | `source` | ID | Candidate side | Baseline side | Default baseline |
|---|---|---|---|---|---|
| Golden | `golden_ticket_correlation` | T1558.001 | 4769 per account, 2h | 4768 per account | `DEFAULT_GOLDEN_BASELINE_HOURS = 8` (`sweep.rs:162`) |
| Silver | `silver_ticket_correlation` | T1558.002 | 4624 LogonType 3 + Kerberos, non-machine accounts, 2h | 4769 per account | `DEFAULT_SILVER_BASELINE_HOURS = 12` (`sweep.rs:173`) |

The windows are deliberately asymmetric — the silver baseline must exceed the max ticket lifetime; a test asserts `DEFAULT_SILVER_BASELINE_HOURS > MAX_TICKET_LIFETIME_HOURS` and `> DEFAULT_GOLDEN_BASELINE_HOURS` (`sweep.rs:2193-2199`).

**Both run twice** — once in the opening sweep, once at investigation close via `recheck_golden_tickets` / `recheck_silver_tickets` (`investigation.rs:342-345`), because domain compromise is red's last phase and the opening window closes before it happens.

Machine accounts (name ending `$`) are dropped from the **silver** candidate set only (`sweep.rs:184,408`). An empty baseline is `NoBaseline`/inconclusive, never "clean" — a broken baseline query would otherwise report the whole domain as forged.

Orphan account names go to `record_timeline_event`, **not** `add_evidence`: `account@domain` is a derived identity normalised from two fields across two event types and appears verbatim in no raw log line, so the evidence grounding gate would refuse it.

**Disabling `ARES_BLUE_GOLDEN_TICKET_CORRELATION` or `ARES_BLUE_SILVER_TICKET_CORRELATION` removes the only path to T1558.001 / T1558.002.** So does `ARES_BLUE_DETERMINISTIC_SWEEP=0`, which short-circuits both rechecks.

## Investigation lifecycle

`run_investigation` (`investigation.rs`): inject `:env_vars` into process env → `initialize` → `acquire_lock` (SETNX + EXPIRE 3600, `blue_writer.rs:331-344`) → status `in_progress` (`:142`) → sweep → LLM loop → inline chains → ticket recheck → eval scoring → final status (`:395`) → `release_lock` (`:400`) → reports.

| Status | Written by | `completed_at` stamped? |
|---|---|---|
| `in_progress` | `investigation.rs:142` | — |
| `completed` | `process_outcome` `TaskComplete`/`EndTurn` (`:661,673`) | yes |
| `escalated` | `process_outcome` `RequestAssistance` (`:665`) | yes |
| `failed` | `MaxSteps`, `MaxTokens`, `BudgetExceeded`, `Error` (`:677-689`) | yes |
| `timed_out` | `runner.rs:382-384` (2700s) | **no** |
| `superseded` | `runner.rs:345-347` | **no** |

`set_status` stamps `completed_at` only for `completed | escalated | failed` (`blue_writer.rs:401`), so `timed_out` / `superseded` investigations look open-ended in every reader. All five are terminal per `blue_status_is_terminal` (`blue_writer.rs:415`).

**`ares blue runtime` never shows Duration for a live investigation.** `runtime.rs:46` computes elapsed only when `status == "running"`, but the writer only ever writes `"in_progress"` (`investigation.rs:142`). `blue operation-status` handles both.

Runner constants (`runner.rs:24-33`): `INVESTIGATION_TIMEOUT_SECS = 2700`, `SUPERSEDE_POLL_SECS = 10`, `STALE_INVESTIGATION_THRESHOLD_SECS = 3000`, `STALE_CHECK_INTERVAL_SECS = 300`.

**Periodic stale reaping only fires on an empty poll**, plus one unconditional sweep at orchestrator startup (`runner.rs:178-179`). The 300s cleanup marks `in_progress` entries older than 3000s as failed, but only when `pop_investigation_request` returned `None` (`runner.rs:417-424`). A permanently busy queue means orphans from a previous process are not reaped **until the orchestrator restarts** — restart before hand-fixing state.

**Supersede is advisory.** `ares:blue:inv:{id}:supersede` is a SETEX string polled every 10s; an investigation inside one long tool call yields only when that call returns (`blue_writer.rs:426-433`).

## Redis keys and the resurrection trap

Prefixes: `ares:blue:inv` and `ares:blue:lock` (`ares-core/src/state/keys.rs:100,104`). **Every key `blue_writer.rs` writes gets `EXPIRE 86400`** (`blue_writer.rs:43-45` onward) — not just `:status`. Two exceptions in the namespace:

- `:env_vars` is written outside `blue_writer` with a **3600s** TTL (`submit.rs:83-86,244-247`, `completion.rs:975-981`, `replay.rs:540-543`).
- `:evidence` refreshes its TTL **only when HSETNX actually inserted** (`if added { expire(…) }`, `blue_writer.rs:43-46`) — a key receiving nothing but duplicate writes ages out on its original TTL.

Note the TYPEs differ from the red-side keys with the same names (red `hosts`/`users` are LISTs; blue's are SETs).

| Key | TYPE | Read with | Writer |
|---|---|---|---|
| `ares:blue:inv:{id}:status` | STRING (JSON) | `GET` | `set_ex …, 86400` (`blue_writer.rs:408`) |
| `ares:blue:inv:{id}:meta` | HASH | `HGETALL` | `hset` (`:288,305-320`) — **existence here is what makes an id enumerable** |
| `ares:blue:inv:{id}:evidence` | HASH (HSETNX dedup) | `HLEN` / `HGETALL` | `:43` |
| `ares:blue:inv:{id}:timeline` | LIST | `LLEN` / `LRANGE 0 -1` | `rpush` (`:58`) |
| `ares:blue:inv:{id}:techniques` | SET | `SCARD` / `SMEMBERS` | `sadd` (`:70`) |
| `ares:blue:inv:{id}:tactics` | SET | `SMEMBERS` | `sadd` (`:82`) |
| `ares:blue:inv:{id}:technique_names` | HASH | `HGETALL` | `hset` (`:95`) |
| `ares:blue:inv:{id}:hosts` | SET (lowercased) | `SMEMBERS` | `sadd` (`:107`) |
| `ares:blue:inv:{id}:users` | SET (lowercased) | `SMEMBERS` | `sadd` (`:119`) |
| `ares:blue:inv:{id}:query_types` | SET | `SMEMBERS` | `sadd` (`:131`) |
| `ares:blue:inv:{id}:queries` | LIST | `LRANGE 0 -1` | `rpush` (`:144`) |
| `ares:blue:inv:{id}:lateral` | LIST | `LRANGE 0 -1` | `rpush` (`:157`) |
| `ares:blue:inv:{id}:pivot_queue` / `:chain_queue` | LIST | `LRANGE 0 -1` | `rpush` (`:169,181`) |
| `ares:blue:inv:{id}:recommendations` | LIST | `LRANGE 0 -1` | `rpush` (`:219`) |
| `ares:blue:inv:{id}:triage:decision` | STRING (JSON) | `GET` | `set_ex` (`:232`) |
| `ares:blue:inv:{id}:triage:records` | LIST | `LRANGE 0 -1` | `rpush` (`:244`) |
| `ares:blue:inv:{id}:tasks:pending` / `:tasks:completed` | HASH | `HGETALL` | `hset` (`:257,272`) |
| `ares:blue:inv:{id}:supersede` | STRING, TTL 86400 | `GET` | `set_ex` (`:431`) |
| `ares:blue:inv:{id}:env_vars` | STRING (JSON), **TTL 3600** | `GET` | `submit.rs:83-86,244-247` |
| `ares:blue:lock:{id}` | STRING (SETNX), TTL 3600 | `EXISTS` | `blue_writer.rs:331-344` |
| `ares:blue:active_investigations` | SET | `SMEMBERS` | `keys.rs:181` |
| `ares:blue:op:{op}:investigations` | SET, **TTL 7d** | `SMEMBERS` | `submit.rs:250-252` |
| `ares:blue:tasks:*` / `ares:blue:results:*` / `ares:blue:heartbeat:*` | — | — | declared at `keys.rs:172,175,178`; **matched by no cleanup path below** |
| `ares:blue:investigations` | — | — | **legacy**, superseded by NATS (`keys.rs:184`) |

**The lock TTL is fixed, not sliding.** `acquire_lock` sets 3600s once (`blue_writer.rs:331-344`); `BlueStateWriter::extend_lock` (`:346-358`) exists but has **no production caller** — the only hits are its own tests (`:861-869`). It happens to exceed `INVESTIGATION_TIMEOUT_SECS` (2700), so today it is benign.

NATS is the real queue (`ares-core/src/nats.rs`): subject `ares.blue.investigations` (`:52`) on stream `ARES_BLUE_TASKS` (`:73`), plus the unused `ares.blue.tasks.{role}` (`:50`).

### The resurrection trap

**Symptom:** you deleted an investigation and it comes back — either as a live run, or forever as `submitted` in `blue operation-status`.

**Cause, three parts:**

1. `ares blue delete` scans only `ares:blue:inv:{id}:*` and SREMs the active set (`ares-cli/src/blue/delete.rs:27-38`). `ares:blue:lock:{id}` does **not** match that glob and survives.
2. Nothing drains the JetStream request. Selective cleanup never touches the stream; only `blue cleanup --all` calls `stream.purge()` on `ARES_BLUE_TASKS` (`delete.rs:173-183`). A queued request pops later and the investigation runs again.
3. `blue operation-status` treats a missing `:status` key as `"submitted"` (`ares-cli/src/blue/operation.rs:201-211`) while the id stays in `ares:blue:op:{op}:investigations` — so the corpse is counted forever.

**Fix:**

Targeted first — this is enough to un-stick one investigation and destroys nothing else:

```bash
# What the runner still believes is live
redis-cli --scan --pattern 'ares:blue:lock:*'
redis-cli DEL 'ares:blue:lock:<inv-id>'
redis-cli SREM 'ares:blue:op:<op-id>:investigations' '<inv-id>'
```

Only reach for the full reset when you genuinely want every op's blue state gone:

```bash
# Full reset including the JetStream backlog. ALWAYS dry-run first.
task blue:multi:cleanup ALL=true DRY_RUN=true
task blue:multi:cleanup ALL=true
```

`--dry-run` is checked before `--force` (`delete.rs:147-151`), so `ALL=true DRY_RUN=true` is safe.

**`blue cleanup --all` DELs every key both scans return** — `ares:blue:inv:*` and `ares:blue:op:*` (`delete.rs:125-127`), deleted at `:163-170`. That destroys the op→inv index for **every operation on the box**, not just the one you are fixing, with the same permanent consequence as `delete-operation`. `ares:blue:lock:*`, `ares:blue:tasks:*`, `ares:blue:results:*` and `ares:blue:heartbeat:*` match neither scan and survive — delete those by hand.

**`ares blue delete-operation` deletes every investigation in the operation, not just the index.** It SCANs and DELs all `ares:blue:inv:{inv}:*` keys for every id in the op set (`delete.rs:87-94`) — evidence, timeline, techniques, queries, status — SREMs them from `ares:blue:active_investigations` (`:96-102`), then DELs `ares:blue:op:{op}:investigations` (`:104`). Nothing about the operation's blue state survives and `blue report --operation-id` can never be regenerated. `task blue:multi:delete-operation` passes `--force` (`.taskfiles/blue/Taskfile.yaml:533`), and neither `delete` nor `delete-operation` has a `--dry-run` at all — only `cleanup` does (`ares-cli/src/cli/blue.rs:86-117`). No prompt, no preview.

## Grounding gates — what blue is allowed to record

Five checks in `ares-tools/src/blue/investigation/write.rs` and `validation.rs`. Refusals come back as `Ok(ToolOutput{success:false})`, **not** `Err` — matching only on `Err` swallows them. Grep `Blue state write rejected` (`sweep.rs:1158`).

**Row 2 is the exception: it is not a gate.** Technique-list grounding drops bad entries and lets the parent write succeed (`write.rs:59-77`) — it is the only refusal with no operator-visible failure. Its sole trace is the `Dropped ungrounded MITRE technique` WARN.

| Gate | Rule | On failure |
|---|---|---|
| Technique grounding | The ID must match some template's `mitre_id` under the parent/child join (`write.rs:28-52`) | `add_technique` **errors**: "is not covered by any detection template, so it can never be credited against red team ground truth" |
| Technique-list grounding | Same rule applied to an evidence `mitre_techniques[]` (`write.rs:54-78`) | Entry **silently dropped**, `warn!("Dropped ungrounded MITRE technique")` |
| Evidence value | Must appear verbatim in a recorded query result; MITRE IDs auto-pass (`write.rs:100-112`) | `"Evidence rejected: value '…' was not found in any recorded query result."` |
| Technique ID syntax | `^T\d{4}(\.\d{3})?$` (`ares-tools/src/blue/validation.rs:104-107`), checked **before** catalog lookup | `T15581` fails on format; `T1558.999` fails on coverage |
| Evidence type | One of 13 (`validation.rs:16-31`) | validation failure |

The 13 valid `evidence_type` values: `suspicious_ip`, `malicious_process`, `lateral_movement`, `credential_access`, `persistence_mechanism`, `c2_communication`, `privilege_escalation`, `network_artifact`, `file_artifact`, `registry_artifact`, `log_entry`, `user_activity`, `authentication_event`.

## The red/blue technique-ID join

`RedBlueCorrelator::techniques_match` (`ares-core/src/correlation/redblue/engine.rs:57-73`) is shared by `RedTeamCoverage::compute` (`ares-core/src/reports/blueteam/coverage.rs:17-19`) and `ground_technique` (`write.rs:37-42`), so the report, `ares ops correlate` and the write gate cannot disagree.

| red | blue | match |
|---|---|---|
| T1003 | T1003 | yes (case-insensitive) |
| T1003 | T1003.006 | yes — parent covers child |
| T1003.006 | T1003 | yes — child evidences parent |
| T1558.001 | T1558.003 | **no** — siblings never match |
| any | missing | no |

**Consequence: a hit requires a template carrying a matching `mitre_id`.** If red stamps an ID no template covers, `add_technique` refuses it and it becomes a permanent "missed" that no prompt work can close. Seven such IDs exist today (computed by joining `TOOL_TO_TECHNIQUE`, `ares-core/src/telemetry/mitre.rs:73+`, against the catalog's 39 IDs under this predicate):

| Un-creditable ID | Red tools that stamp it |
|---|---|
| T1068 | `nopac`, `printnightmare` |
| T1136.002 | `add_computer` |
| T1187 | `coercer`, `dfscoerce`, `mssql_ntlm_coerce`, `petitpotam`, `petitpotam_unauth` |
| T1222.001 | `adminsd_holder_add_ace`, `bloodyad_add_genericall`, `dacl_edit` |
| T1484.001 | `dnstool`, `pygpoabuse_immediate_task`, `sharpgpoabuse` |
| T1518.001 | `zerologon_check` |
| T1556.006 | `certipy_shadow`, `pywhisker` |

Closing one of these means **adding a detection template carrying that ID (or its parent)**, not tuning blue's prompt.

A second red-side ID source exists: `exploitation_techniques(vuln_id)` in `ares-cli/src/orchestrator/result_processing/timeline.rs`, guarded by the test `every_emitted_technique_is_coverable_by_the_blue_catalog`. Adding a vuln type there without a template breaks that test.

## Scoring — two independent paths

**In-process eval** (`ares-core/src/eval/scorers/scoring.rs:466-493`). Weights: IOC 3.5, technique 3.5, phase 3.5, pyramid 3.0, evidence 3.0, and timeline 3.5 **only when `expected_timeline` is non-empty** — otherwise it is dropped and the rest renormalize, because a vacuous 1.0 would inflate the overall by its full 17.5%.

Grades (`ares-core/src/eval/results.rs:139-150`): A ≥0.90, B ≥0.80, C ≥0.70, D ≥0.60, else F. `passed()` additionally requires `ioc_detection_rate ≥ 0.5` **and** `technique_coverage ≥ 0.6` (`:131-136`).

Evidence quality is **precision against ground truth**, not self-reported confidence — fabricated or irrelevant evidence directly lowers the score.

**Report scorecard** (`ares-core/src/reports/blueteam/coverage.rs:52-60+`). Red's set = `all_techniques` ∪ every `mitre_techniques[]` on `all_timeline_events`; blue's = `identified_techniques` ∪ every evidence item's `mitre_techniques[]`; both uppercased. Fields: `red_technique_count`, `detected_count`, `missed_count`, `detection_rate_display`, `detected[]` (with `matched_by`), `missed[]`, `blue_only[]`.

**`n/a` ≠ 0%.** With red state missing from Redis the report renders with `coverage: None` (`ares-core/src/reports/blueteam/generator/from_states.rs:30`) and declares coverage unmeasured rather than failing. **The `## Red Team Activity Coverage` heading proves nothing** — it is emitted unconditionally (`comprehensive_report.md.tera:57`) and only the body switches on `coverage` (`:59`, else-branch `:103-108`). Grep the rendered report for the literal `**Not measured.**` instead.

`task blue:multi:techniques` reads only `:techniques`, so it can be a **subset** of what the scorecard credits (which also counts evidence-attached IDs).

Report paths (`ares-cli/src/blue/report.rs:127-156`):

| Form | Path |
|---|---|
| `blue report --operation-id <op>` | `{output_dir}/blue/{op}.md` — **the only form carrying the scorecard** |
| `blue report --investigation-id <inv>`, and the `--latest` fallback to an investigation | `{output_dir}/blue/investigations/{inv}.md`, **always** |

`save_investigation_report` takes an `op_id: Option<&str>` but both call sites pass `None` (`report.rs:26,52`), so the `{output_dir}/blue/{op}/{inv}.md` arm (`report.rs:148`) is dead code — don't go looking in a directory that is never created. The runner's own auto-report hardcodes the same investigations path (`ares-cli/src/orchestrator/blue/investigation.rs:562-564`).

Runner-side report root: `request.report_dir` > `ARES_REPORT_DIR` > `~/.ares/reports` (`investigation.rs:502-512`).

**`ares blue report --regenerate` is silently ignored** — bound to `_regenerate` and never read (`report.rs:15`). `task blue:reports:consolidate REGENERATE=true` therefore does nothing different.

## Response actuators vs detect-only

**Blue never touches AD.** The only planned actuator that shipped is a *simulation*: `confirm_escalation` carries a `containment_action` enum, each confirmation emits an OTel span, and — only when opted in — publishes an op-state event to NATS.

| Slug | Op-state payload when containment is ON | Notes |
|---|---|---|
| `disable_ad_account` | `CredentialRevoked{username,domain}` | target parsed as `user@domain` |
| `isolate_host_firewall` | `HostIsolated{ip,hostname}` | IP-parse branch; a **hostname** target leaves `ip` empty and the state key is `ip` only |
| `revoke_krbtgt` | `KrbtgtRotated{domain}` | target is the realm |
| `revoke_certificate` | `CertificateRevoked{serial}` | target is the serial |
| `escalate_to_human` | **none** — the default | `payload_for_containment` returns `None` (`simulated_response.rs:72-116`) |

**`downgrade_escalation` is a separate tool, not a `containment_action` value.** The enum has exactly the five above (`ares-llm/src/tool_registry/blue/callbacks.rs:150-154`); `downgrade_escalation` is its own `ToolDefinition` (`callbacks.rs:166-188`) with its own handler (`ares-cli/src/orchestrator/blue/callbacks.rs:436-452`). It emits a simulated-response span and nothing else, so false positives still register as spans.

The gate: `std::env::var("ARES_BLUE_SIMULATED_CONTAINMENT").as_deref() == Ok("1")` (`ares-cli/src/orchestrator/blue/runner.rs:193-194`) — **strict string equality**, so `true` / `yes` / `on` leave containment OFF. Contrast `ARES_BLUE_ALLOW_RULE_CREATION`, which accepts `1|true|yes|on` trimmed and lowercased (`ares-core/src/detection/mod.rs:73-80`). Two blue toggles, two truthiness contracts.

**The variable is read in exactly one file and set nowhere in the repo** (`rg -l ARES_BLUE_SIMULATED_CONTAINMENT` → one file, `runner.rs`; the three hits there are the comment at `:190`, the read at `:194`, the log line at `:198` — `rg -c` prints that `3` and is not a contradiction). Like every other `ARES_BLUE_*` knob except `ARES_BLUE_ENABLED` / `ARES_BLUE_LLM_MODEL`, it is absent from the `systemd-run --setenv=` allowlist (see [Env knobs](#env-knobs)). **Every shipped op has run detect-only.**

**The span is emitted unconditionally, containment on or off** (`callbacks.rs:405-422` emits before the publish; `simulated_response.rs:122-127` short-circuits only the publish). Span name is the literal `blue.simulated_response.<action_type>` via `otel.name`; the tracing target is `ares.blue.simulated_response` (`simulated_response.rs:52-55`). **Span counts are not evidence blue contained anything.**

Only the `escalation_triage` sub-agent has `confirm_escalation` (`ares-llm/src/tool_registry/blue/mod.rs:69`, `callbacks.rs:112+`). If escalation triage is never reached, zero containment spans are emitted no matter how good the detections are. `confidence` is a **required** schema field (`callbacks.rs:163`) that no handler reads — there is no threshold gate and no `blue:` section in `config/ares.yaml`.

### "Blue containment" in the log usually is not blue

**Symptom:** `Dropping deferred task — invalidated by blue containment` (`ares-cli/src/orchestrator/deferred.rs:683`) with blue detect-only or off entirely.

**Cause:** red's own failure-string classifier is **completely ungated** — a bare block in `process_completed_task` with no env var or feature flag (`ares-cli/src/orchestrator/result_processing/mod.rs:551-560`). It classifies ordinary tool failures as containment:

| Marker | Gate | Effect |
|---|---|---|
| `KDC_ERR_CLIENT_REVOKED` | password-backed technique | revokes on **first** sight (`containment_recovery.rs:131`) |
| `KDC_ERR_CLIENT_REVOKED` | cert-backed technique | `CertificateRevoked` with `serial: String::new()` (`:176`) — never matches a real serial |
| generic auth-reject strings | needs `CREDENTIAL_REVOKE_MIN_OBSERVATIONS = 2` for the same principal (`:139`) | below threshold logs `containment: weak credential-reject below revocation threshold` |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | **deliberately excluded** (`:115`) | routine kerberoast/AS-REP enumeration emits it |
| `KRB_AP_ERR_MODIFIED` | — | `KrbtgtRotated` on the realm |

**Containment-invalidated deferred tasks are deleted, not requeued** (`deferred.rs:678-686`), with no counter anywhere. For a red verification run whose result depends on deferred work, disable blue entirely.

## Task index

`.taskfiles/blue/Taskfile.yaml`, 22 tasks, three backends. **The task name does not tell you which.**

| Task | Backend | Wraps | Notes |
|---|---|---|---|
| `blue:poll` | LOCAL | `ares blue watch` | Infinite loop, no dedup — resubmits every `POLL_INTERVAL` (default 30) |
| `blue:once` | LOCAL | `blue from-operation` | No precondition guard; tees to `{{.LOG_DIR}}/blue-<ts>.log` |
| `blue:submit ALERT=x.json` | TRANSPORT | `blue submit "$(cat …)"` | Replaced `blue:investigate` + `blue:multi` (2026-08-08). Honors `MULTI_AGENT`; alert passed by value so it resolves on the far side. Does **not** send `--grafana-api-key` — SSM would persist it in CloudTrail |
| `blue:multi:remote` | `kubectl exec` | `blue from-operation` | K8s-hardwired. `MAX_STEPS` now overridable (absorbed `blue:once:remote`, which was identical bar `--max-steps`) |
| `blue:multi:list` | TRANSPORT | `blue list` | Hides `--latest` / `--operation-id` / `--json` |
| `blue:multi:status` | TRANSPORT | `blue status` | `--latest` prefers a **locked** (running) investigation |
| `blue:multi:evidence` | TRANSPORT | `blue evidence` | `JSON=true` |
| `blue:multi:techniques` | TRANSPORT | `blue techniques` | Subset of what the scorecard credits |
| `blue:multi:runtime` | TRANSPORT | `blue runtime` | No Duration while running (see lifecycle) |
| `blue:multi:triage-status` | TRANSPORT | `blue triage-status` | Task omits the CLI's `--json` |
| `blue:multi:operation-status` | TRANSPORT | `blue operation-status` | `WATCH=N` blocks until all terminal, **no timeout** — see below |
| `blue:multi:delete` | TRANSPORT | `blue delete --force` | **Always `--force`.** Leaves lock + NATS + op-set |
| `blue:multi:delete-operation` | TRANSPORT | `blue delete-operation --force` | **Deletes every investigation's state plus the op→inv index.** No prompt, no dry-run |
| `blue:multi:cleanup` | TRANSPORT | `blue cleanup` | `ALL=true` ⇒ `--all --force`, purges JetStream, no prompt |
| `blue:multi:logs` | TRANSPORT | `kubectl logs -f` (k8s) / `ec2:logs` (ec2) / `tail -f` (local) | **Blocks.** Transport-aware since 2026-08-08. On EC2 blue has no process of its own — it runs inside the orchestrator (`ARES_BLUE_ENABLED=1`), so the task tails `/var/log/ares/orchestrator.log` filtered to `blue|investigation|inv-`;`ALL=true` drops the filter and `ROLE` is K8s-only. K8s label selectors are still not defined in this repo |
| `blue:reports:consolidate` | TRANSPORT + fetch-back | `blue report` | **The scorecard task.** `REGENERATE` is a no-op |
| `blue:playbook` | TRANSPORT (**red** deploy under k8s) | `ops export-detection --json` | Red-side playbook. Rewritten 2026-08-08 to stream JSON over stdout into `{{.OUTPUT_DIR}}/blue/<op>_detection_playbook.json`; the `JSON` var is gone |
| `blue:reports:list` / `:latest` | local fs | — | Read `REPORT_DIR`, not `OUTPUT_DIR` |
| `blue:reports:clean` | local fs | — | Interactive `read -p`; **hangs under `task -y`** |

```bash
# Score the latest op (the only path that reliably produces a scorecard)
task blue:reports:consolidate LATEST=true OUTPUT_DIR=./reports

# Progress roll-up — BLOCKS until every investigation is terminal, with no timeout
# (operation.rs:30-46). A corpse left in ares:blue:op:{op}:investigations by
# `blue delete` reports as "submitted" forever (:201-211), and "submitted" counts
# as active (:219-221) — so this never returns until you SREM it. Ctrl-C is the only exit.
task blue:multi:operation-status LATEST=true WATCH=10

# Query the cluster instead of the default EC2 box
task blue:multi:list BLUE_TRANSPORT=k8s K8S_NAMESPACE=attack-simulation

# Scripted output — the tasks hide the CLI's flags
ares --ec2 kali-ares blue list --json
ares --ec2 kali-ares blue operation-status --latest --json
```

Task-surface traps:

- **`task blue:poll:local` does not exist.** The task is `blue:poll` (the name in `.claude/CLAUDE.md`'s quick reference is wrong).
- **The 1Password fallbacks are dead code.** `grep .env … | cut | tr -d '"' || op item get …` — the pipeline's exit status is `tr`'s, always 0, so the `||` branch can never fire (`.taskfiles/blue/Taskfile.yaml:32-39`). A key missing from `.env` exports as an **empty string** and surfaces as a provider 401 deep inside the pod.
- **Empty `GRAFANA_URL` fails differently per task.** Local tasks pass it unquoted and last ⇒ clap "a value is required". Remote tasks quote it ⇒ `Some("")`, which slips past the `Grafana URL required` bail (`ares-cli/src/blue/submit.rs:157`) and then returns zero Loki hits with no error.
- **`EC2_NAME` defaults differ by namespace.** Blue's own default is `kali-ares` (`.taskfiles/blue/Taskfile.yaml:17`); the root `Taskfile.yaml`'s default differs and is **not** forwarded into the blue include (root `Taskfile.yaml:80-97` forwards neither `EC2_NAME` nor `LOKI_URL`).
- **`PROFILE` / `REGION` at `.taskfiles/blue/Taskfile.yaml:9-10` are dead** — never referenced. Use `EC2_PROFILE` / `EC2_REGION`. `DREADNODE_API_KEY` is computed at file scope and used by zero tasks.
- **`blue:playbook` used to fetch nothing back, silently — fixed 2026-08-08.** The task `kubectl cp`'d `/tmp/reports/{op}_detection_playbook.{json,md}` while the CLI wrote `/tmp/reports/{op}/detection_playbook.{json,md}` (a per-op subdirectory, `ares-cli/src/detection/mod.rs:39-56`); the paths never matched, both `cp`s ended in `2>/dev/null || true`, and the `saved to` echo never fired. It now uses `--json`, which prints to stdout and writes no files (`mod.rs:35-38`) — so it rides any transport and the task writes the file locally. The markdown variant still only exists where the CLI runs: `ares ops export-detection <op> --output-dir <dir>`.
- **`blue:reports:consolidate` screen-scrapes stdout** with `sed -n 's/.* saved to //p' | tail -1`, keyed on the literals `Operation report saved to {path}` / `Investigation report saved to {path}` (`report.rs:27,32,43,53`). Change either message and the fetch-back dies with "could not determine remote report path".
- **Both transports pin `RUST_LOG=error` remotely** (`ares-cli/src/transport.rs`) — no local `RUST_LOG` makes `task blue:multi:*` verbose.
- **Investigation IDs are second-resolution** (`inv-%Y%m%d-%H%M%S`, `submit.rs:51,226`) — two submits inside one second collide on the same keyspace.

## Env knobs

**`task ec2:launch` drops almost all of these.** The `systemd-run --setenv=` allowlist (`.taskfiles/ec2/scripts/launch-orchestrator.sh.tmpl:66-88`) forwards only `ARES_DEPLOYMENT`, `ARES_BLUE_ENABLED`, `ARES_BLUE_LLM_MODEL`, `GRAFANA_URL`, `GRAFANA_SERVICE_ACCOUNT_TOKEN` and `LOKI_URL` of the set below. Every other `ARES_BLUE_*` knob — deterministic sweep, both ticket correlations, both baseline-hours, sweep concurrency/timeout, rule creation, max steps, drain, simulated containment — plus `ARES_REPORT_DIR`, `ARES_SESSION_LOG_DIR`, `ARES_LLM_TEMPERATURE` and `ARES_LLM_SEED`, is absent from the allowlist and from every manifest and taskfile in the repo. Exporting one before `task ec2:launch` does nothing; edit the template or the knob is a no-op on EC2.

| Var | Default | Effect | Source |
|---|---|---|---|
| `ARES_DEPLOYMENT` | unset | Injects `deployment="…"` into every LogQL selector | `ares-tools/src/blue/detection/mod.rs:38` |
| `ARES_BLUE_ENABLED` | off | `=1` spawns blue + auto-submit inside the red orchestrator | `orchestrator/mod.rs:779` |
| `ARES_BLUE_ONLY` | off | `=1` blue-only orchestrator, before config load | `orchestrator/mod.rs:78` |
| `ARES_BLUE_DETERMINISTIC_SWEEP` | on | `0/false/no/off` disables the catalog sweep **and both ticket rechecks** | `sweep.rs:1344-1352` |
| `ARES_BLUE_GOLDEN_TICKET_CORRELATION` | on | disables the only path to T1558.001 | `sweep.rs:1356-1358` |
| `ARES_BLUE_SILVER_TICKET_CORRELATION` | on | disables the only path to T1558.002 | `sweep.rs:1362-1364` |
| `ARES_BLUE_GOLDEN_BASELINE_HOURS` | 8 | golden baseline width, clamped ≥ 2 | `sweep.rs:1378-1406` |
| `ARES_BLUE_SILVER_BASELINE_HOURS` | 12 | silver baseline width, clamped ≥ 2 | `sweep.rs:1387-1406` |
| `ARES_BLUE_SWEEP_CONCURRENCY` | 6 | max concurrent Loki detection queries | `sweep.rs:1408-1414` |
| `ARES_BLUE_SWEEP_TIMEOUT_SECS` | 360 | wall-clock cap; overflow ⇒ `not_run` | `sweep.rs:1417-1423` |
| `ARES_BLUE_SIMULATED_CONTAINMENT` | off | strict `"1"` — wires the NATS op-state recorder | `runner.rs:193-194` |
| `ARES_BLUE_ALLOW_RULE_CREATION` | off | `1\|true\|yes\|on` — exposes `create_detection_rule` | `ares-core/src/detection/mod.rs:65-80` |
| `ARES_BLUE_LLM_MODEL` | orchestrator spec | blue's LLM | `orchestrator/mod.rs:785` |
| `ARES_BLUE_MAX_STEPS` | 75 | **INERT.** Sets `request["max_steps"]` (`completion.rs:948,958`), which the runner never reads (`runner.rs:240-278`); the loop hardcodes 75 (`investigation.rs:203`) | `orchestrator/completion.rs:948` |
| `ARES_BLUE_DRAIN_MAX_SECS` | — | how long red waits for blue to drain at completion | `orchestrator/completion.rs` |
| `ARES_SESSION_LOG_DIR` | unset (logging off) | Captures the blue transcript — messages + tool calls, the **only** way to see what the hunter actually did | `SessionLogConfig::from_env()` at `investigation.rs:208`, `callbacks.rs:149`; resolved in `ares-llm/src/agent_loop/config.rs:281-305` |
| `ARES_LLM_TEMPERATURE` / `ARES_LLM_SEED` | provider defaults | Deterministic blue sampling at all three layers (root loop, sub-agents, tool loop); set by `benchmark run --temperature/--seed` | `investigation.rs:30-44,213-214`; `callbacks.rs:153-154` |
| `ARES_REPORT_DIR` | `~/.ares/reports` | report root; `request.report_dir` wins | `investigation.rs:502-512` |
| `GRAFANA_URL` / `GRAFANA_SERVICE_ACCOUNT_TOKEN` | — | `from-operation` **hard-fails** without both | `ares-cli/src/blue/submit.rs:157,160` |
| `LOKI_URL` / `LOKI_AUTH_TOKEN` | — | fallback only — see below | `ares-tools/src/blue/loki.rs:48-50` |

**Loki resolution is Grafana-proxy-first**, contradicting the module doc comment directly above it: `GET {GRAFANA_URL}/api/datasources/uid/loki` → `/api/datasources/proxy/{id}` (cached in a `OnceCell`), then `LOKI_URL`, then `http://localhost:3100` (`ares-tools/src/blue/loki.rs:31-50`). Since every blue task exports `GRAFANA_URL`, the proxy always wins — and proxy IDs renumber when a datasource is recreated. **There is no MCP anywhere in the blue runtime.**

**`:env_vars` has a 3600s TTL** (`submit.rs:86,247`) and is injected only `if std::env::var(key).is_err()` (`investigation.rs:114-116`) — a pre-set orchestrator env var wins and is never clobbered. An investigation queued behind a long-running one for over an hour starts with **no Grafana credentials** and every Loki query fails.

**Five `max_steps` budgets are in play and only two are live.**

| Budget | Value | Live? |
|---|---|---|
| Root investigation loop | 75 hardcoded (`investigation.rs:203-204`, `max_tool_calls_per_name: 25`) | **yes** |
| Every dispatched blue sub-agent | 50 hardcoded (`callbacks.rs:145-146`, `max_tool_calls_per_name: 25`) | **yes** — governs Triage / ThreatHunter / LateralAnalyst / EscalationTriage and every inline chained hunt |
| `request["max_steps"]` | 75 / `ARES_BLUE_MAX_STEPS` / CLI `--max-steps` | no — the runner reads only `investigation_id` / `alert` / `model` / `operation_id` / `report_dir` (`runner.rs:240-278`) |
| CLI `--max-steps` default | 25 (`ares-cli/src/cli/blue.rs:149-150,174-175,196-197`) | no |
| `MAX_STEPS_BLUE` 50 / `MAX_STEPS_BLUE_ONCE` 15 (root `Taskfile.yaml:110-111`) | passed as `--max-steps` | no |

**The live sub-agent 50 and the inert `MAX_STEPS_BLUE` 50 are indistinguishable in a transcript.** A hunt truncated at 50 steps is the sub-agent budget, not the task var — raising `MAX_STEPS_BLUE` will not move it.

## Log strings to grep

| Verdict | String | Source |
|---|---|---|
| progress | `Received investigation request` | `runner.rs:280` |
| progress | `Starting deterministic baseline detection sweep` (field `templates=`) | `sweep.rs:803-807` |
| progress | `Baseline detection sweep complete` (fields `fired/out_of_window/no_match/failed/not_run/timed_out/golden_ticket/silver_ticket`) | `sweep.rs:986-997` |
| progress | `Operation coverage report written` | `investigation.rs:635-640` |
| **config** | `Blue orchestrator: detect-only (simulated containment OFF)` | `runner.rs:196-199` |
| **config** | `Blue orchestrator: simulated containment ON — op-state recorder wired to NATS` | `runner.rs:204` |
| **stall** | no `Received investigation request` after a submit | orchestrator down, wrong NATS, or busy — the runner is **serial** |
| **stall** | `Detection queries errored — these techniques are UNCHECKED, not clean` | `sweep.rs:982` |
| **stall** | `Detections fired outside the attack window — not attributed to this operation` | `sweep.rs:942` — **cannot fire today**; the `not_before` clamp (`detection/runner.rs:67-77`) makes `out_of_window` unreachable. If you see it, the clamp broke |
| **stall** | `Blue state write rejected` | `sweep.rs:1158` — grounding/validation refusal, not transport |
| **stall** | `Dropped ungrounded MITRE technique` | `write.rs:65-70` |
| **stall** | `Evidence rejected: value '…' was not found in any recorded query result` | `write.rs:107-111` |
| **stall** | `Forged-ticket correlation found a forgery on the closing re-check` | `sweep.rs:1113` — the opening sweep missed it |
| **stall** | `Dropping deferred task — invalidated by blue containment` | `deferred.rs:683` — **usually red's own classifier** |
| **stall** | `Dropping vuln — {target host isolated \| krbtgt rotated \| certificate revoked \| bound principal revoked}` | `exploitation.rs:174,187,201,226` |
| **stall** | `containment: weak credential-reject below revocation threshold` | `result_processing/mod.rs:593` |

Prompt markers confirming the LLM saw the sweep: `## Baseline detection sweep — ALREADY COMPLETED` (`sweep.rs:556`), `Ran and returned no matches (do NOT re-query)` (`sweep.rs:584`).

## Related

- Banned lab tokens in detection fixtures and templates: allowed values only — see `references/tools-and-gates.md#test-conventions`.
- **A MITRE ID red stamps with no matching `mitre_id` in `detections.yaml` is a permanent miss** — the scorecard is an exact-or-parent/child ID join, never siblings. Zero occurrences today for `T1187`, `T1068`, `T1222.001`, `T1484.001`, `T1518.001`, `T1556.006`, `T1136.002`, all of which `ares-core/src/telemetry/mitre.rs:138-148` stamps. The add-a-tool gate list is in `references/tools-and-gates.md`.
- `docs/blue.md` predates the deterministic sweep, the NATS migration and simulated containment. Treat it as a conceptual map: its tool names, evidence types, `blue_team:` config block and adaptive-query-limit section do not match code. **UNVERIFIED:** the full extent of its staleness beyond the items contradicted above.
- `docs/blue-response-actuators.md` describes a responder VM, mTLS gRPC actuators, a blocklist file, Postgres `blue_actions` tables and `ares blue rollback` — **none exist in this repo**. Only the simulation half shipped. **UNVERIFIED:** whether any of it landed outside this repo.
- Target-side questions (which credential unlocks what, ACL chains, ADCS templates) route to `dreadgoad-expert` — but that agent **fails on every call** via model-level safeguards. Read the lab docs directly rather than rewording to evade.
