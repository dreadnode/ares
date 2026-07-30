# Running operations

One binary, three transports, two launch planes. EC2 `kali-ares` is the default plane; K8s `attack-simulation` is the alternative. Nearly every task is a wrapper over `ares ops <subcmd>`.

Build/deploy internals: `references/deployment.md`. Redis key inventory: `references/state-and-redis.md`. Diagnosing a *wedged* op: the `ares-debug` skill. Executing a ≥3-step workflow: the `ares-operator` agent (one-shot commands run inline — don't dispatch an agent for a single `task ec2:runtime`). This doc is launch → watch → read → report → clean up → prove.

`rg` cannot see the Taskfiles without `--hidden`; `.taskfiles` is a dot-directory.

## Read this first

1. **`Status: stopped` is treated as SUCCESS by every watch loop.** `ops status` emits only `completed`, `running`, or `stopped` (`ares-cli/src/ops/status.rs:28-34`) — there is no `failed`. A crashed orchestrator, a killed op, and a never-claimed op all read `stopped`, and both `ec2:watch` (`.taskfiles/ec2/Taskfile.yaml:1040-1045`) and `red:multi`'s FOLLOW loop (`.taskfiles/red/Taskfile.yaml:139-145`) `break`/`exit 0` on it. **A green exit is not evidence the objective was met.** Read the report's `## Executive Summary` and `### Key Events`.
2. **Every `inject-*` task is SILENT on success.** All result reporting is `tracing::info!` (`ares-cli/src/ops/inject.rs:48,53,219,224,258,368,373,397,440,444`), and both remote transports force `RUST_LOG=error` on the re-exec'd process (`ares-cli/src/transport.rs:169`, `:414`). Success, "already exists", and no-op are indistinguishable — all print nothing. Only the bail path (`No state found for operation: <id>`) prints. Confirm with `ops loot` / `ops inspect-vulns`.
3. **`--latest` means newest `started_at`, NOT the running op.** `resolve_latest_operation` collects `is_running` and never reads it (`ares-core/src/state/operations.rs:336-389`); the doc comment says so explicitly and a regression test locks it in (`:886 resolve_latest_operation_picks_newest_even_when_older_is_running`). Launch a second op and every `LATEST=true` retargets instantly.
4. **`red:ec2:multi` cannot report failure, and it kills the previous op.** Its submit step carries `ignore_error: true` (`.taskfiles/red/Taskfile.yaml:925`), so the task exits 0 whether or not the orchestrator started. The launch template `systemctl stop ares-orchestrator.service` + `pkill -f 'ares orchestrator'` first (`.taskfiles/ec2/scripts/launch-orchestrator.sh.tmpl:53-55`) — **a second launch silently terminates the first op.**
5. **`ec2:launch` destroys the box's Redis.** `FLUSH_REDIS` defaults `true` → `redis-cli FLUSHDB` (`.taskfiles/ec2/Taskfile.yaml:1089,1256-1257`) plus `ares ops sanitize` (`:1343`). Every prior op's loot, cached report, and **mutation journal** on that box is unrecoverable. Fetch reports before the next launch. Teardown normally already ran automatically at the prior op's completion (`ARES_AUTO_TEARDOWN` is ON by default — see Teardown below), but an op that was killed, crashed, or ran with it disabled never got the pass, and after a FLUSHDB there is no journal left to run it from.
6. **The default `STATUS=running` on `red:multi:tasks:list` returns nothing for a red op.** Red dispatch is in-process, and it writes `in_progress` at dispatch (`ares-cli/src/orchestrator/dispatcher/submission.rs:361-363`) then `completed`/`failed` on result (`ares-cli/src/orchestrator/task_queue.rs:519-525`). `running` is written only by the NATS worker task loop (`ares-cli/src/worker/task_loop/result_handler.rs:36`), and `pending` only by a `#[cfg(test)]` helper (`task_queue.rs:436,469`). Use `STATUS=in_progress` for live work, `STATUS=all` for everything.

## Planes and transports

`--k8s <ns>` / `--ec2 <name>` are argv shims handled in `main()` *before* clap parses: strip the transport flags, re-exec the rest remotely, exit.

| Transport | Mechanism | Where it lands | Deadline | Needs local `ares`? |
|---|---|---|---|---|
| (none) | in-process | Redis from `--redis-url` → `ARES_REDIS_URL` → `REDIS_URL` → `redis://localhost:6379` (`ares-cli/src/redis_conn.rs:9-13`), 30 s response timeout | n/a | yes |
| `--k8s <ns>` | `kubectl exec -i -n <ns> deploy/<d> -- env RUST_LOG=error ares …` (`transport.rs:169`) | `ares-blue-orchestrator` if **any argv token equals `blue`**, else `ares-orchestrator` (`transport.rs:143-148`); pin with `--k8s-deploy` | kubectl's | yes (shim only) |
| `--ec2 <name>` | SSM `AWS-RunShellScript` running `RUST_LOG=error ares …` (`transport.rs:414`) | Name-tag glob `*<name>*`, **first** InstanceId returned; a literal `i-…` (≥10 chars) skips the lookup (`transport.rs:205-207`) | 3000 s poll (`transport.rs:426`) | yes (shim only) |

`--ec2-profile` defaults `lab`, `--ec2-region` defaults `us-west-1` (`ares-cli/src/cli/mod.rs:56-62`). If `AWS_ACCESS_KEY_ID` is exported, `--profile` is dropped entirely (`transport.rs:193-199`).

**Local Redis is needed only by a bare `ares ops …`.** With a transport flag, Redis is resolved on the pod/box. But seven `ec2:*` tasks shell the *local* binary with `--ec2` and gate on `command -v ./target/release/ares` — the shared `*ares-cli-executable` precondition **defined and first used** at `.taskfiles/ec2/Taskfile.yaml:587` (inside `ec2:stop-op`, `:578`), re-referenced at `:603` (kill), `:621` (teardown), `:843` (loot), `:859` (runtime), `:962` (ops), `:999` (watch). `ec2:launch` is an eighth with its own conditional gate (`:1114`), which fires whenever `WAIT=true` — the default (`:1098`) — because it hands off to `ec2:watch`; launch with `WAIT=false` to skip it. `BUILD_TOOL=remote` (the deploy default) never produces that binary — build it with `cargo build --release -p ares-cli`, or route around it entirely (`references/deployment.md`, "Binary-free equivalents"). `ec2:report`, `ec2:ops:ids`, `ec2:status` and `ec2:exec` need **no** local binary; they run the box's `ares` over SSM. The `--k8s` red tasks have no such precondition and fail with a bare shell "no such file".

**Task var resolution, verified empirically against go-task 3.52.0 from the repo root:** the include's own `vars:` win over what the root forwards. `task -v ec2:exec CMD=probe --dry` with all AWS env unset resolved `EC2_NAME=kali-ares`, `AWS_REGION=us-west-1`, `AWS_PROFILE=lab` — the root Taskfile's `EC2_NAME: ares-tools` (`Taskfile.yaml:134`) and `AWS_REGION: us-east-1` (`:137`) are dead for every `ec2:*` and `red:ec2:*` task. `red:ec2:multi` declares the same defaults at task level (`.taskfiles/red/Taskfile.yaml:780-782`). The `desc:` strings that say `[EC2_NAME=ares-tools]` are wrong.

**Two AWS identities, two regions.** The attacker box resolves under `AWS_PROFILE`/`AWS_REGION`; the *targets* resolve under `TARGET_PROFILE`/`TARGET_REGION` (default `lab`/`us-east-1`, `Taskfile.yaml:125-126`, used at `.taskfiles/red/Taskfile.yaml:84,642-649`). `No running EC2 instances found matching Name tag filter` on the target lookup means `TARGET_*` is wrong, not `AWS_PROFILE`.

## Launch a red op

### EC2 — the normal launcher

```bash
task red:ec2:multi TARGET=dreadgoad DOMAIN=<lab-root-domain> EC2_NAME=kali-ares

# A literal IP list skips the AWS Name-tag lookup entirely
task red:ec2:multi TARGET=192.168.58.10,192.168.58.11 DOMAIN=contoso.local
```

Requires a repo-root `.env` (sourced at `.taskfiles/red/Taskfile.yaml:874`). Defaults: `EC2_NAME=kali-ares`, `AWS_PROFILE=lab`, `AWS_REGION=us-west-1`, `STRATEGY=comprehensive`, `BLUE_ENABLED=1`, `EC2_DEPLOYMENT=alpha-operator-range` (`.taskfiles/red/Taskfile.yaml:777-791`).

**`TARGET` and `DOMAIN` are not declared on this task** — they fall through to the root Taskfile's baked-in lab defaults (`Taskfile.yaml:128-129`). Omitting `DOMAIN=` does **not** fail; it silently launches against the baked-in lab root domain. Same trap class as `ec2:launch`'s hardcoded credential defaults below.

**The trap is only real when `TARGET` is overridden and `DOMAIN` is not.** For the default `TARGET=dreadgoad` (`Taskfile.yaml:128`) the paired `DOMAIN` default at `:129` already *is* the correct lab root — retyping it by hand adds transcription risk for no gain, and the value is a banned token this skill may not print. Read it from `Taskfile.yaml:129`; do not copy it into a transcript. Pass `DOMAIN=` explicitly for any other target.

Mechanism: sets `ares:operation:active` over SSM (`:863`), sed-substitutes 16 `__TOKEN__` placeholders into `.taskfiles/ec2/scripts/launch-orchestrator.sh.tmpl` (`:892-907`; `:908` is the template-path redirect), and `systemd-run --unit=ares-orchestrator.service --slice=system-ares.slice --collect` with the whole request JSON in `ARES_OPERATION_ID` (`tmpl:18,61-95`). Caps `MemoryHigh=8G` / `MemoryMax=10G` / `TasksMax=4096` / `OOMScoreAdjust=-500`; pins `ARES_MAX_CONCURRENT_TASKS=8` (`tmpl:42`); **appends** to `/var/log/ares/orchestrator.log`.

The payload carries only `operation_id`, `target_domain`, `target_ips`, `model`, `strategy` (`:887`). `MAX_STEPS_RED`, `TARGET_ENV` and `RESUME` are declared but never reach the box on this path. No credential is seeded — this is a blind start.

### EC2 — the escape hatch (`ec2:launch`)

Self-described in-tree as "a direct-launch escape hatch (not the normal launcher)" (`.taskfiles/ec2/Taskfile.yaml:1105-1107`).

| | `red:ec2:multi` | `ec2:launch` |
|---|---|---|
| Process | `systemd-run` in `system-ares.slice`, 8G/10G caps | bare `nohup … &` inside amazon-ssm-agent's cgroup, **no caps** (`:1344`) |
| `orchestrator.log` | appends | `>` **truncates** per launch |
| `ARES_BLUE_ENABLED` | from `BLUE_ENABLED` | hardcoded `1` (`:1330`); its `BLUE_MODE` var (`:1107`) is dead |
| `FLUSHDB` + `ops sanitize` | no | **yes**, both |
| Seeded credential | none | `initial_credential` always present |
| Strategy knobs | `STRATEGY` only | `STRATEGY`, `EXCLUDE_TECHNIQUES`, `CONTINUE_AFTER_DA` |
| `WAIT` | n/a | defaults **`true`** (`:1098`) → blocks in `ec2:watch` up to `MAX_WAIT=7200` |

Its `DOMAIN`/`CRED_USER`/`CRED_PASS`/`CRED_DOMAIN` defaults are real lab loot values baked into the file (`:1066,1072-1074`; `.taskfiles` is exempt from the token sweep). **Passing an empty CLI var does not clear them** — go-task's `| default` fires on empty, verified. There is no blind-start option through `ec2:launch`.

### EC2 — the root one-shot (`task run`)

`task run` (`Taskfile.yaml:160-208`) chains `ec2:stop` → `red:ec2:multi`, so it carries **both** blast radii: it kills whatever op is running, and the launch template stops + `pkill`s again. `WAIT` and `CAPTURE` both default `"false"` (`:164-165`); either set to `true` hands off to `task ec2:watch LATEST=true` (`:175`) and blocks up to `MAX_WAIT`. The `CAPTURE=true` branch additionally runs `lsof -ti:16379 | xargs kill` (`:194`) — killing any unrelated local process on that port — then backgrounds an SSM port-forward and runs `ares benchmark capture --wait-for-flush`, which itself waits on a Loki flush. Do not run it from an agent.

### K8s

```bash
task red:multi TARGET=dreadgoad IPS=192.168.58.10,192.168.58.11 DOMAIN=contoso.local
task red:multi TARGET=dreadgoad IPS=... FOLLOW=false     # submit only, no 2h block

# Resume from checkpoint — delegates to red:multi with RESUME=true, TARGET=TARGETS
task red:multi:resume OPERATION_ID=op-xxx DOMAIN=contoso.local TARGETS=192.168.58.10
```

`red:multi:resume` (`.taskfiles/red/Taskfile.yaml:747-767`) requires all three vars — `OPERATION_ID`, `DOMAIN`, `TARGETS` — with no `LATEST` support, and note it spells the IP list `TARGETS=`, not `IPS=`.

Defaults: `FOLLOW=true`, `POLL_INTERVAL=30`, `MAX_WAIT=7200`, `OUTPUT_DIR=./reports`, `OPERATION_ID=op-$(date +%Y%m%d-%H%M%S)` (`.taskfiles/red/Taskfile.yaml:25-49`). `MAX_STEPS_RED=150` is **not** in that block — it is a root var (`Taskfile.yaml:112`) forwarded into the include (`Taskfile.yaml:41`) and passed as `--max-steps` at `.taskfiles/red/Taskfile.yaml:102`.

**Always pass `IPS=`.** Without it the task adds `--resolve-targets`, which shells out to the `aws` binary *inside the orchestrator pod* — the Taskfile's own comment at `:79-80` says the pod has no `aws` CLI.

This task hand-rolls `kubectl exec` rather than using the `--k8s` shim, so it can inject env vars, and it derives the Redis URL from the `redis-secret` Secret on your laptop, falling back to **unauthenticated** `redis://redis:6379` if the read fails (`:40-47`).

**K8s submit only ENQUEUES.** `ops submit` RPUSHes the request onto the Redis list `ares:operations` (`ares-cli/src/ops/submit.rs:214`). The only in-tree consumer is `ares ops claim-next` (BRPOP, `ares-cli/src/ops/queue.rs:47-58`), driven by a shell wrapper patched onto the deployment (`.taskfiles/remote/orchestrator-wrapper-patch.json`). Treat "submitted" as "queued". Inspect the backlog non-destructively with `redis-cli lrange ares:operations 0 -1` — `red:multi:list` shows operation *state*, not this queue.

`ops submit` hard-bails when no model resolves, and when the model starts with `gpt-` and `OPENAI_API_KEY` is unset **in the pod** (`submit.rs:166-179`). `MODEL=` reaches the op only via `--model`; the `ARES_MODEL_OVERRIDE` env the task also sets is read only by the blue auto-submit path.

## Watch it

```bash
# EC2 — non-blocking, agent-safe
task ec2:ops:ids EC2_NAME=kali-ares            # STARTED_AT | STATUS | OP_ID; no local binary
task ec2:runtime EC2_NAME=kali-ares LATEST=true
task ec2:status  EC2_NAME=kali-ares

# EC2 — BLOCKING up to MAX_WAIT (2h), auto-fetches the report on terminal state
task ec2:watch EC2_NAME=kali-ares LATEST=true

# K8s
task red:multi:status LATEST=true
task red:multi:watch  LATEST=true ONCE=true    # single terminal-state check + fetch
task red:multi:list                            # ops queue: per-op DA / GT / vuln / exploited
```

Both watch loops parse `^Status:` (and `^Operation:`) out of `ops status` stdout — a format change breaks them silently. `red:multi:watch` is the only red task where `LATEST` defaults to `true` (`.taskfiles/red/Taskfile.yaml:325`); without `ONCE=true` it polls to `MAX_WAIT` then exits 1.

The `failed|cancelled` arms in both loops (`.taskfiles/red/Taskfile.yaml:146`, `:384`) are unreachable — `ops status` never emits those.

**`ec2:ops:ids` and `ops status` disagree for the whole blue-drain window.** `list-ops.sh` checks `ares:lock:<op>` **first**, then `meta.completed_at`, and never reads `red_completed_at` (`.taskfiles/ec2/scripts/list-ops.sh:23-28`). `ops status` checks `completed_at || red_completed_at` first and only then the lock (`ares-cli/src/ops/status.rs:28-34`). Between red finishing and `finalize_operation` clearing the lock (`ares-core/src/state/operations.rs:225,240-241`) — up to the blue drain's length — `ec2:ops:ids` reports `running` while `ec2:runtime` / `ec2:watch` / `ops status` report `completed`. Trust `ops status` for "is red done"; trust `ec2:ops:ids` for "has the orchestrator exited".

## What healthy progress looks like

**Measured 2026-07-30 over n=47 DA ops in the local `reports/red/` corpus** (94 `op-*.md` at the time; 48 started on/after 2026-07-23). `reports/` is **gitignored** (`.gitignore:10`) — the corpus exists only on this checkout, grows with every op, and cannot be reproduced from a clean clone. Re-derive before quoting: parse `**Started**`, `**Duration**`, and the `CRITICAL: Domain Admin achieved` timeline rows out of `reports/red/op-*.md`.

| Milestone | Measured (n=47) |
|---|---|
| First `CRITICAL: Domain Admin achieved` after `**Started**` | min 1.6 min, **median 4.1**, p90 8.8, max 13.2 |
| Total `**Duration**` (DA ops) | min 11.7 min, **median 18.8**, p90 30.7, max 48.5 |
| Soft runtime cap | `timeouts.operation_timeout: 3600` (`config/ares.yaml:200`) |
| Hard runtime cap | 2× soft = 7200 s (`ares-cli/src/orchestrator/completion.rs:469`) |
| Post-dominance grace before stop | hardcoded 180 s (`completion.rs:520`) |
| Heartbeat considered STALE | age > interval × 3; default interval 30 s → 90 s (`ares-core/src/state/operations.rs:55,89-99`) |

An op that has not hit DA by ~15 minutes is outside the whole observed distribution. That is the cheapest wedge signal you have; escalate to `ares-debug`.

Terminal strings written to `red_completion_reason` (`completion.rs:409-441`): `operation marked completed`, `hard max runtime exceeded`, `max runtime exceeded`, `domain admin achieved (stop_on_domain_admin)`, `golden ticket forged (stop_on_golden_ticket)`, `all forests dominated (post-exploitation complete)`. Both `stop_on_*` flags ship `false` (`config/ares.yaml:38-39`).

**`Status: completed` fires when RED finishes, not the whole op.** `red_completed_at` is set before the orchestrator's blue drain, deliberately, so watch loops fetch the red report without waiting on blue (`ares-cli/src/ops/status.rs:24-31`). A `running` op with `red_completed_at` set is not wedged.

Timeline prefixes that mark real progress: `Hash discovered:`, `Credential discovered:`, `Vulnerability exploited:`, `Golden ticket forged for domain …`, `CRITICAL: Domain Admin achieved for <d> via …`. The non-progress one is `Exploit attempted but failed: … — Assistance needed: …` — that text is the failing agent's confabulated account of its own failure, not a bug report (see `ares-debug`).

### Watch for a milestone without blocking the turn

`ec2:watch` is banned for agents (2 h block). Poll instead, in the background, with `Monitor` or `Bash(run_in_background)` — foreground `sleep` is blocked.

```bash
OP=op-YYYYMMDD-HHMMSS
until [ "$(task ec2:exec EC2_NAME=<pinned> \
      CMD="redis-cli hget ares:op:$OP:meta has_domain_admin" | tr -d '[:space:]')" = "true" ]; do
  sleep 60
done
```

Swap the field for `has_golden_ticket`, or for `red_completed_at` (non-empty = red finished). Three traps, all established elsewhere in the skill:

- **Meta values are JSON-encoded.** `has_domain_admin` comes back bare `true`; a *string* field such as `target_domain` comes back **with quotes**, so `[ "$x" = "<domain>" ]` silently never matches (`references/state-and-redis.md`, trap 4). Strip with `sed -E 's/^"(.*)"$/\1/'`.
- `redis-cli` on the box needs `sudo` in some invocations — if the value comes back empty, run the probe once by hand before trusting the loop. Empty output from `ec2:exec` is a broken command, not a real negative.
- **Escalate on the published threshold**: no DA by ~15 min is outside the whole observed distribution (median 4.1, p90 8.8) — hand off to `ares-debug` rather than continuing to poll.

## Read loot and state

```bash
# EC2 (default plane) — ec2:loot needs ./target/release/ares locally
task ec2:loot EC2_NAME=kali-ares LATEST=true [JSON=true]

# EC2, binary-free: runs the box's own ares against the box's own Redis
task ec2:exec EC2_NAME=kali-ares CMD='ares ops loot --latest --json'
task ec2:exec EC2_NAME=kali-ares CMD='ares ops inspect-vulns --latest --json'
task ec2:exec EC2_NAME=kali-ares CMD='ares ops tasks --latest --status all'

# K8S ONLY — no EC2 wrapper exists for either of the bottom two
task red:multi:loot LATEST=true
task red:multi:inspect-vulns LATEST=true JSON=true    # discovered vs exploited per vuln_type
task red:multi:tasks:list LATEST=true STATUS=all      # NOT the default STATUS=running
```

**`inspect-vulns` and `tasks:list` have no `ec2:*` wrapper.** Their only Taskfile home is `.taskfiles/red/Taskfile.yaml:208` and `:229`, both `{{.ARES_CLI}} --k8s {{.K8S_NAMESPACE}} ops …`. On the EC2 plane use `ares --ec2 kali-ares ops inspect-vulns --latest --json` (needs the local shim) or the `ec2:exec` form above (does not). Same class of gap as the `inject-*` wrappers (`.taskfiles/red/Taskfile.yaml:478`, `:566`), which are also `--k8s` only. Flags verified at `ares-cli/src/cli/ops.rs:79-104`; `ec2:exec` is bounded by its hardcoded 60 s SSM budget (`.taskfiles/ec2/Taskfile.yaml:1488`) and SSM's ~24 KB stdout cap, so keep the query narrow.

- **`DIFF=true` with `WATCH=0` becomes an infinite 10 s watch loop** — the CLI promotes `watch=0 && diff` → `watch=10` (`ares-cli/src/ops/loot/mod.rs:28`), and **both** `red:multi:loot` and `ec2:loot` emit `--diff` with no `--watch` (`.taskfiles/ec2/Taskfile.yaml:850`; `ec2:loot` has no `WATCH` var to set). Over `--ec2` you also block on the 3000 s SSM poll (`transport.rs:426`).
- `red:multi:loot` exposes no `JSON` var; `ec2:loot` does.
- `ops tasks` SCANs the **global** `ares:task_status:*` keyspace and filters by `operation_id` client-side (`ares-cli/src/ops/tasks.rs:18-52`); the status filter is exact string equality. Records carry a 24 h TTL.
- `--role` takes the underscore form (`credential_access`, `lateral`). The `replay:*` tasks use pod-name spellings (`credential-access`, `lateral-movement`) — a different vocabulary.
- `cancelled` and `retrying` pass the Taskfile's `VALID_STATUSES` gate (`.taskfiles/red/Taskfile.yaml:221`) but nothing ever writes them.

**Redis key types** — ground truth is `ares-core/src/state/keys.rs`, the writer verbs in `ares-core/src/state/reader.rs`, and — for `completed_tasks`/`exploited`/`superseded` — the orchestrator's own publishing/dedup modules. The `ares-debug` skill's table (`.claude/skills/ares-debug/SKILL.md:112-121`) agrees on all eight keys it lists; the SET rows below are the ones it omits. There is no `:creds` key; the wrong *verb* is loud (`WRONGTYPE`), the wrong *key name* is a silent `0`.

| Key (`ares:op:{id}:…`) | Type | Writer | Count | Dump |
|---|---|---|---|---|
| `meta` | HASH | `hset` (`reader.rs:450`) | `HLEN` | `HGETALL` / `HMGET` |
| `credentials` | HASH | `hset_nx` (`:273`) | `HLEN` | `HGETALL` |
| `hashes` | HASH | `hset_nx` (`:414`) / `hset` (`:432`) | `HLEN` | `HGETALL` |
| `vulns` | HASH | `hset_nx` (`:289`) | `HLEN` | `HGETALL` |
| `completed_tasks` | HASH | `hset` (`orchestrator/state/publishing/entities.rs:377`; own 86 400 s TTL at `:379`) | `HLEN` | `HGETALL` |
| `hosts` | **LIST** | `rpush` (`:322`) | `LLEN` | `LRANGE k 0 -1` |
| `users` | **LIST** | `rpush` (`:350`) | `LLEN` | `LRANGE k 0 -1` |
| `timeline` | **LIST** | `rpush` (`:573`) | `LLEN` | `LRANGE k -50 -1` |
| `domains`, `techniques` | SET | `sadd` (`reader.rs:362,585`) | `SCARD` | `SMEMBERS` |
| `exploited`, `superseded` | SET | `sadd`/`srem` (`orchestrator/state/dedup.rs:78-84`) — reader.rs only *reads* them (`:147,156`) | `SCARD` | `SMEMBERS` |
| `teardown_claimed` | STRING | `set_nx` (`orchestrator/cleanup/mod.rs:54`) — `EXISTS` means the automatic teardown pass already fired | `EXISTS` | `GET` |

Full inventory (locks, dedup sets, deferred ZSETs, blue keys, token usage): `references/state-and-redis.md`.

## Reports

```bash
task ec2:report EC2_NAME=kali-ares OPERATION_ID=op-xxx [REGENERATE=true] [OUTPUT_DIR=./reports]
task red:multi:report LATEST=true REGENERATE=true
task red:reports:list      # ls -lht ./reports/red/*.md
task red:reports:latest    # cat the newest
```

Reports land at `<OUTPUT_DIR>/red/<op_id>.md` (`ares-cli/src/ops/report.rs:78-84`) **on the machine that ran the generator** — over `--ec2` without the `ec2:report` wrapper, that is the box.

- **Without `REGENERATE=true` you get the CACHED report** from `ares:op:{id}:report` (`report.rs:20-27`), TTL'd with `OP_RETENTION_TTL_SECS = 86_400` (`ares-core/src/state/keys.rs:19`). The line reads `Report saved to <path> (cached)`. A mid-op fetch caches a partial report, but the orchestrator overwrites it from live state at finalize (`ares-cli/src/orchestrator/mod.rs:1084` → `generate_and_cache_report`, which unconditionally `SET`s the key and re-applies the TTL, `ops/report.rs:64-73`). The stale snapshot survives the full 24 h **only when the orchestrator never reaches finalize** — a crash, `ec2:stop`, `ec2:restart` or `pkill` — which is exactly when you most want `REGENERATE=true`.
- `ec2:report` generates into `/tmp/reports` on the box, sed-parses `Report saved to <path>.md` out of stdout, then streams the file back in 12000-byte `dd | base64` chunks with byte-count **and** sha256 verification (`.taskfiles/ec2/Taskfile.yaml:889-953`). A wording change to that `println!` breaks the fetch.
- The K8s path's `kubectl cp` is `2>/dev/null || true` (`.taskfiles/red/Taskfile.yaml:283`) — a failed copy is silent, and with >1 orchestrator replica the label-selector pod may not be the one that generated the file.
- Blue: `task blue:reports:consolidate OPERATION_ID=op-xxx` → `./reports/blue/`. Its fetch is a single un-chunked `cat` over SSM (`.taskfiles/blue/Taskfile.yaml:294`) with no checksum, so a large report truncates silently at SSM's ~24 KB output cap; the only guard is `[ -s ]`.

## Stop, kill, clean up, tear down

```bash
task ec2:stop-op  EC2_NAME=kali-ares LATEST=true                 # graceful: ares ops stop
task ec2:stop     EC2_NAME=kali-ares                             # DESTRUCTIVE to a running op
task ec2:kill     EC2_NAME=kali-ares ALL=true                    # DESTRUCTIVE: stop + DELETE
task ec2:teardown EC2_NAME=kali-ares LATEST=true DRY_RUN=true    # reverse target mutations
task red:multi:delete  OPERATION_ID=op-xxx                       # DESTRUCTIVE, unconfirmed
task red:multi:cleanup MAX_AGE_HOURS=24                          # GC non-running ops
task red:multi:kill    ALL=true                                  # DESTRUCTIVE + cluster-wide
```

- **Bare `ops kill` (no id, no `--all`) kills every running op EXCEPT the "latest"** — and "latest" is a **lexicographic** sort of running ids (`ares-cli/src/ops/kill.rs:33,49-51`), not chronological. Whichever id sorts last is the one kept — for `op-YYYYMMDD-HHMMSS` ids that coincides with chronological, but any custom prefix reorders it in whichever direction the prefix falls relative to `op-` (`sweep-`, `z…` survive; `bench-`, `blue-`, `dg-` get killed first). With exactly one running op it refuses and tells you to pass `--all`. No in-tree launcher mints a non-`op-` id.
- `ops kill` is stop **+ delete**: `kill_one` calls `request_stop_operation` then `delete_operation`, which SCAN-deletes every `ares:op:{id}:*` key plus the lock (`kill.rs:62-73`). Loot and the cached report go with it.
- `red:multi:kill` then `kubectl rollout restart`s **every** statefulset in the namespace not matching `blue|redis` (`.taskfiles/red/Taskfile.yaml:438-445`). Cluster-wide blast radius.
- `red:multi:delete` always passes `--force`, so the CLI's stdin `[y/N]` (`ares-cli/src/ops/delete.rs:25-33`) never fires. Over `--ec2` there is no stdin at all: an unforced `delete` reads EOF and prints `Cancelled` while exiting 0.
- **`ops cleanup` silently SKIPS any id whose first 18 bytes are not `op-YYYYMMDD-HHMMSS`** — the parser requires the `op-` prefix and `len >= 18`, then slices bytes `3..11` / `12..18` (`ops/delete.rs:81-97`). A **trailing suffix is fine and still gets cleaned**: `op-20260407-091000-abc123` parses (regression test `parse_operation_timestamp_with_suffix`, `delete.rs:119-127`). A different prefix, a shorter id, or non-numeric bytes in those slices logs a `warn!` (invisible under a transport) and leaks forever.
- `ops teardown` replays the op's mutation journal against the **target DC** — see the next section; it also runs automatically.
- `ares ops sanitize` wipes the *attacker* side: hashcat potfile, `~/.nxc` SQLite DBs / spider_plus downloads / screenshots, and `/tmp/ares-tickets` ccaches (`ares-tools/src/sanitize.rs:1-34`). Opt out with `ARES_KEEP_WORKSPACE=1`. No task wrapper; only `ec2:launch` runs it.

Fleet control on the box: `task ec2:start` brings Redis + NATS + history Postgres back after `ec2:stop` (`.taskfiles/ec2/Taskfile.yaml:539-540`) — nothing else does. `task ec2:setup` is the readiness check (impacket-drift guard, fleet up, Redis/NATS smoke test, `:498-499`); with the `ares@*` workers down, dispatches return `no responders` and the op wedges at zero progress (`.taskfiles/ec2/Taskfile.yaml:11-13`). Other unlisted `ec2:*` tasks: `deploy:config` (`:465`), `history-db` (`:518`), `hashcat` (`:652`), `setup:tools` (`:1399`), `logrotate` (`:1413`).

### Teardown

**It runs automatically, and it is ON by default.** `auto_teardown_enabled()` is true unless `ARES_AUTO_TEARDOWN` is `0`/`false`/`no`/`off` (trimmed + lowercased, `ares-cli/src/orchestrator/cleanup/mod.rs:31,67-76`). Two call sites, deliberately:

| Call site | Fires | File |
|---|---|---|
| completion monitor | the instant red drains, **before** the blue wait | `ares-cli/src/orchestrator/completion.rs:632` |
| orchestrator shutdown | fallback for ops that never reach a completion decision (deadline, stop request, crash) | `ares-cli/src/orchestrator/mod.rs:1116` |

Whichever fires first claims the pass with `SETNX ares:op:{id}:teardown_claimed`; the loser returns `None` instead of dispatching a second set of inverses (`cleanup/mod.rs:34,48-58`). The claim is never cleared, so the *automatic* pass runs once per op ever. `ares ops teardown` calls `run_teardown` directly and ignores the claim — it is always available as a manual re-run.

**Two tool lists, and the bigger one is not teardown's.** `REVERSIBLE_TOOLS` — 26 entries (`ares-tools/src/mutation.rs:45-72`) — is the *pre-flight mutation gate*: it decides whether a mutating tool may run at all and be journalled. What teardown can actually undo is the undo registry (`ares-cli/src/orchestrator/cleanup/registry.rs:243`), 17 match arms; every other tool falls through to `Reversibility::Unsupported` / `no known inverse for this tool` (`registry.rs:373-376`).

| Class | Tools | Auto-reverts? |
|---|---|---|
| `Clean` | `rbcd_write`, `bloodyad_add_group_member`, `addspn`; `add_computer` / `nopac` **only** with a captured `created_computer` hint; `pywhisker` **only** with a captured `device_id` | **yes** |
| `NeedsCapture` | `dacl_edit`, `bloodyad_add_genericall`, `mssql_enable_xp_cmdshell`, `bloodyad_set_object_attr`, `certipy_account_update`, `certipy_ca` (add-officer), `krbrelayup`, plus the hint-less `add_computer`/`nopac`/`pywhisker` | no |
| `Hard` | `adminsd_holder_add_ace`, `pygpoabuse_immediate_task`, `sharpgpoabuse`, `certipy_template_esc4` | no |
| `Impossible` | `bloodyad_set_password` — also the sole `IRREVERSIBLE_TOOLS` member (`mutation.rs:38`), refused at dispatch unless `ARES_ALLOW_IRREVERSIBLE_MUTATION` is set (`mutation.rs:35`) | no |
| `Unsupported` | the remaining `REVERSIBLE_TOOLS` entries — `certipy_esc4_full_chain`, `certipy_esc7_full_chain`, `certipy_shadow`, `dnstool`, `mssql_linked_enable_xpcmdshell`, `ntlmrelayx_to_adcs`, `ntlmrelayx_to_ldaps`, `printnightmare`, `targeted_kerberoast`, and `certipy_ca` on any non-officer sub-action | no |

Only `Clean` carries an `inverse`; the other four print a plan and stop (`registry.rs:66-67`). **A `DRY_RUN=true` plan with many rows can still revert nothing** — read the class labels, not the row count.

Output is `Teardown complete: N verified, N reverted (unprobed), N unverified, N skipped, N failed, N unresolved (of N).` plus a `Needs attention (not auto-reverted):` list (`cleanup/engine.rs:466,488`). `ares ops teardown` exits **non-zero** when `failed` or `unresolved` is non-zero (`ares-cli/src/ops/teardown.rs:39-43`, `engine.rs:95-96`), so a task can gate on it.

Scope one tool: `task ec2:teardown EC2_NAME=kali-ares LATEST=true ONLY=rbcd_write` (`.taskfiles/ec2/Taskfile.yaml:617,628`).

Set `ARES_AUTO_TEARDOWN=0` and back-to-back ops **do** leave every mutation on the lab — and `ec2:launch`'s FLUSHDB then destroys the journal that would have reversed them.

## Injecting state

All injects bail with `No state found for operation: {id}` until the orchestrator has initialised state (`ares-cli/src/ops/inject.rs:27,162,241,328,389,415`). After a launch, wait for the op to materialise.

```bash
task red:multi:inject-credential OPERATION_ID=op-xxx USERNAME=alice PASSWORD='P@ssw0rd!' DOMAIN=contoso.local IS_ADMIN=true
task red:multi:inject-hash       OPERATION_ID=op-xxx USERNAME=svc_sql HASH=<lm>:<nt> DOMAIN=contoso.local [AES_KEY=<aes256>]
task red:multi:inject-host       OPERATION_ID=op-xxx IP=192.168.58.240 HOSTNAME=dc01.contoso.local DC=true
task red:multi:inject-domain-sid OPERATION_ID=op-xxx DOMAIN=contoso.local SID=S-1-5-21-...
task red:multi:inject-vulnerability OPERATION_ID=op-xxx VULN_TYPE=constrained_delegation TARGET_IP=192.168.58.240 \
  TARGET_HOSTNAME=dc01.contoso.local TARGET_SPN=cifs/dc01.contoso.local ACCOUNT_NAME=svc_sql DOMAIN=contoso.local
task red:multi:inject-trust      OPERATION_ID=op-xxx DOMAIN=fabrikam.local TRUST_TYPE=forest DIRECTION=bidirectional
task red:multi:backfill-domains  OPERATION_ID=op-xxx
```

**Every inject wrapper is `--k8s` only** (`.taskfiles/red/Taskfile.yaml:478,502,524,543,566,591`). For EC2 call the CLI: `ares --ec2 kali-ares ops inject-credential …`. To see the otherwise-suppressed result, bypass the shim: `task ec2:exec CMD='RUST_LOG=info ares ops inject-credential …'`.

| Trap | Detail |
|---|---|
| `USERNAME=krbtgt` / `administrator` on `inject-hash` | sets `has_domain_admin=true` in op meta as a side effect (`inject.rs:352-363`) — poisons the report's DA claim and can terminate the op under `stop_on_domain_admin` |
| `inject-hash` type/source | the task exposes only `--domain`/`--aes-key`, so everything is recorded `hash_type: NTLM`, `source: manual-inject` |
| `VULN_TYPE` is unvalidated | bare `String`, no `value_parser`. A typo creates a permanently orphaned vuln with no error |
| Injected vuln priority | hardcoded `99` with the comment `// Default priority; config lookup would go here` (`inject.rs:211`) — `vulnerability_priorities` in `config/ares.yaml` does not apply to injections |
| `vuln_id` is derived | `{vuln_type}_{target_ip}_{account_name or "manual"}` (`inject.rs:192-201`); re-injecting the same triple is a no-op. You cannot re-arm a vuln by re-injecting |
| `DETAILS` must be valid JSON | `serde_json::from_str(&details_json).unwrap_or_default()` silently swallows malformed input (`inject.rs:166`); its keys override the auto-built `target_ip`/`domain`/… because `extend` runs last (`:190`) |
| Automation-owned vuln types create **no** LLM exploit task | `is_automation_owned_vuln` removes the delegation / ACL / ADCS / `gpo_*` families from the generic exploitation ZSET (`ares-cli/src/orchestrator/exploitation.rs:22-65`) — you are waiting on that automation's tick, and priority 99 is harmless there |
| `(N subscribers notified)` | always `0` — `publish_state_update` returns `Ok(0)` unconditionally after a best-effort NATS publish (`ares-core/src/state/operations.rs:18-46`). Never read it as liveness |

Two GOAD-lab composite injectors exist at `.taskfiles/red/Taskfile.yaml:633` and `:709`; they resolve host IPs from **AWS EC2** while injecting into **K8s** Redis, and the second sleeps a fixed 15 s racing state creation. Lab-specific — never copy their hostname strings into repo code.

## The `ares ops` command tree

`ares [--redis-url U] [--env-file F] [--secrets-from 1password] [--k8s NS | --ec2 NAME [--ec2-profile P] [--ec2-region R]] ops <subcmd>`

| Subcommand | Args / key flags | Backend | Task wrapper |
|---|---|---|---|
| `submit` | `<target> <domain>`, `--ips`, `--operation-id`, `--username/--password/--ntlm-hash`, `--model`, `--max-steps` (200), `--env`, `--resume`, `--pin-active`, `--resolve-targets`, `--follow` | Redis (+AWS) | `red:multi` |
| `list` | `--latest` | Redis | `ec2:ops` |
| `queue` | — | Redis | `red:multi:list` |
| `claim-next` | `--timeout` (30) | Redis — **BRPOP, destructive** | none |
| `status` | `[op]`, `--latest` | Redis | `red:multi:status` |
| `runtime` | `[op]`, `--latest` | Redis | `red:multi:runtime`, `ec2:runtime` |
| `loot` | `[op]`, `--latest`, `--json`, `--watch N`, `--diff` | Redis | `red:multi:loot`, `ec2:loot` |
| `tasks` | `[op]`, `--latest`, `--status` (`running`), `--role` | Redis | `red:multi:tasks:list` |
| `inspect-vulns` | `[op]`, `--latest`, `--json` | Redis | `red:multi:inspect-vulns` |
| `report` | `[op]`, `--latest`, `--regenerate`, `--output-dir` | Redis + local FS | `red:multi:report`, `ec2:report` |
| `export-detection` | `[op]`, `--latest`, `--output-dir`, `--json`, `--no-markdown` | Redis + local FS | `blue:playbook` (K8s only, pinned `--k8s-deploy ares-orchestrator`; `kubectl cp`s the `_detection_playbook.json`/`.md` back — `.taskfiles/blue/Taskfile.yaml:205-221`) |
| `stop` | `[op]`, `--latest` | Redis | `ec2:stop-op` |
| `kill` | `[op]`, `--all` | Redis | `red:multi:kill`, `ec2:kill` |
| `delete` | `<op>`, `--force` | Redis (+stdin) | `red:multi:delete` |
| `cleanup` | `--max-age-hours` (24) | Redis | `red:multi:cleanup` |
| `teardown` | `[op]`, `--latest`, `--dry-run`, `--only <tool>` | Redis + **target network** | `ec2:teardown` |
| `sanitize` | — | local FS only | none |
| `backfill-domains` | `<op>` | Redis | `red:multi:backfill-domains` |
| `inject-credential` | `<op> <user> <pass>`, `--domain`, `--source`, `--is-admin` | Redis | `red:multi:inject-credential` |
| `inject-hash` | `<op> <user> <hash>`, `--domain`, `--hash-type`, `--source`, `--aes-key` | Redis | `red:multi:inject-hash` |
| `inject-host` | `<op> <ip> <hostname>`, `--dc` | Redis | `red:multi:inject-host` |
| `inject-domain-sid` | `<op> <domain> <sid>` | Redis | `red:multi:inject-domain-sid` |
| `inject-vulnerability` | `<op> <vuln_type> <target_ip>`, `--target-hostname`, `--target-spn`, `--account-name`, `--domain`, `--details` | Redis | `red:multi:inject-vulnerability` |
| `inject-trust` | `<op> <domain>`, `--trust-type`, `--direction`, `--flat-name`, `--sid-filtering` | Redis | `red:multi:inject-trust` |
| `force-inter-realm-forge` | `<op>`, `--source/--target/--trust-key/--aes-key/--*-sid/--target-dc-*` | Redis (queued) | `red:multi:force-inter-realm-forge` |
| `sessions` | `list` \| `show` \| `replay` | **local FS only** | none |
| `replay` | `<op>`, `--until`, `--until-count`, `--json` | **NATS only** — ignores `--redis-url` | none |
| `offload-cost` | `[op]`, `--latest` | Redis **and** Postgres | none |
| `correlate` | `--reports-dir`, `--time-window`, `--json` | local FS (`blue` feature) | none |
| `evaluate` | `--states-dir`/`--state-file`, `--output-dir`, `--save`, `--json` | local FS (`blue` feature) | none |

Source: `ares-cli/src/cli/ops.rs:37-473`, `ares-cli/src/cli/mod.rs:28-62`. Sibling top-level commands: `blue`, `benchmark`, `history`, `config`, `orchestrator`, `worker` — see `references/blue-team.md`, `references/benchmarks-and-replay.md`, `references/config-and-env.md`.

## The `LATEST=true` convention

`LATEST=true` maps to `--latest`, resolved by `resolve_operation_id` → `resolve_latest_operation` (`ares-cli/src/redis_conn.rs:25-40`): SCAN `ares:op:*:meta`, sort by `started_at` DESC, fall back to op_id DESC. Running-ness is ignored. The "Using latest operation: {id}" line is `info!` — suppressed under `--k8s`/`--ec2`, so you cannot see which op was targeted.

| Task | `LATEST` default |
|---|---|
| `red:multi:loot` / `:status` / `:inspect-vulns` / `:tasks:list` / `:runtime` / `:report` | `""` — precondition requires `OPERATION_ID` or `LATEST=true` |
| `red:multi:watch` | **`true`** |
| `ec2:loot` / `ec2:runtime` / `ec2:report` / `ec2:watch` | **`true`** |
| `ec2:ops` / `ec2:stop-op` / `ec2:teardown` | `false` |
| `red:multi:delete` / `:backfill-domains` / all `inject-*` / all launchers | no `LATEST` support — `OPERATION_ID` is mandatory |

## Destructive / blocking / interactive matrix

| Command | Class | Why |
|---|---|---|
| `task ec2:logs` | **INTERACTIVE — never from an agent** | `aws ssm start-session` + `tail -f`; never terminates. Use `ec2:logs:fetch` or `ec2:exec CMD='tail -n 200 …'` |
| `task ec2:redis:forward` / `ec2:nats:forward` | **INTERACTIVE + side effect** | foreground port-forward; first pipes `lsof -ti:16379` (`:14222` for nats) into `xargs kill`, killing unrelated local processes |
| `task remote:logs` | **BLOCKING by default** | `FOLLOW` defaults `true` → `kubectl logs -f`. Pass `FOLLOW=false` |
| `ec2:watch`, `ec2:launch` (`WAIT=true`), `red:multi` (`FOLLOW=true`), `red:multi:watch` (no `ONCE`) | **BLOCKING** ≤ `MAX_WAIT=7200` | |
| `task red:multi:loot DIFF=true` | **never returns** | promoted to a 10 s watch loop |
| `task ec2:loot DIFF=true` | **never returns** | same promotion; `ec2:loot` declares no `WATCH` var at all (`.taskfiles/ec2/Taskfile.yaml:834-850`), and over `--ec2` your shell additionally blocks on the 3000 s SSM poll (`transport.rs:426`) |
| `task ec2:launch` | **DESTRUCTIVE** | `redis-cli FLUSHDB` + `ares ops sanitize` |
| `task red:ec2:multi` | **DESTRUCTIVE to a running op** | template stops + `pkill`s the prior orchestrator |
| `task run` | **DESTRUCTIVE to a running op, twice over** | chains `ec2:stop` then `red:ec2:multi` (`Taskfile.yaml:160,167-168`) |
| `task run WAIT=true` / `CAPTURE=true` | **BLOCKING** ≤ `MAX_WAIT` **+ side effect** | hands off to `ec2:watch LATEST=true` (`Taskfile.yaml:175`); the `CAPTURE` branch also runs `lsof -ti:16379 \| xargs kill` (`:194`), killing unrelated local processes on that port, then backgrounds an SSM port-forward |
| `task ec2:stop` | **DESTRUCTIVE to a running op** | `systemctl stop` + `pkill`, no finalize |
| `task ec2:restart` | **DESTRUCTIVE to a running op** | chains `ec2:stop` (`systemctl stop` + `pkill`) then `ec2:start` (`.taskfiles/ec2/Taskfile.yaml:630-635`); does **not** bounce the `ares@*` worker fleet |
| `task ec2:kill` / `task red:multi:kill` | **DESTRUCTIVE** | stop **+ delete** all `ares:op:{id}:*`; bare form keeps only the lexicographically-last running op |
| `task red:multi:kill` | **DESTRUCTIVE, cluster-wide** | rollout-restarts every non-`blue`/`redis` statefulset in the namespace |
| `task red:multi:delete` | **DESTRUCTIVE, unconfirmed** | hardcodes `--force` |
| `task red:multi:cleanup` | **DESTRUCTIVE** | deletes non-running ops older than `MAX_AGE_HOURS` |
| `task ec2:teardown` | **DESTRUCTIVE to the lab** | writes to the target DC; run `DRY_RUN=true` first |
| `task ec2:deploy` | **interrupts a live op** | restarts every **active** `ares@*.service` unless `SKIP_RESTART=true` (`.taskfiles/ec2/Taskfile.yaml:249-256`, `:447-453`); prints `no ares@ worker units active — skipping restart` when none are up |
| `task k8s:reset` | **DESTRUCTIVE, shared** | `pkill`s local `red:multi` shells (`.taskfiles/k8s/Taskfile.yaml:50-64`), then wipes cluster Redis |
| `task red:multi:replay:clear CONFIRM=true` | **DESTRUCTIVE** | `rm -f` the recording on one or all agent pods |
| `ares ops claim-next` | **DESTRUCTIVE** | BRPOPs a queued request out from under the dispatcher |
| `ares ops sanitize` | **DESTRUCTIVE to the attacker workspace** | deletes the hashcat potfile, `~/.nxc` DBs / spider_plus downloads / screenshots, `/tmp/ares-tickets` ccaches (`ares-tools/src/sanitize.rs:1-34`); `ARES_KEEP_WORKSPACE=1` opts out |
| `ares ops delete` (raw, no `--force`) | **INTERACTIVE** | stdin `[y/N]`; over `--ec2` it reads EOF and prints `Cancelled` with exit 0 |

**`ec2:deploy` bounces only `--state=active` `ares@*` units; `ec2:restart` bounces none.** To bounce workers alone: `task ec2:exec EC2_NAME=kali-ares CMD='systemctl restart "ares@*.service"'`. Full semantics — the two copies of the restart block, `SKIP_RESTART`, and why an inactive unit keeps its stale binary — live in `references/deployment.md`.

## "I changed code — now prove it works"

The only thing that proves an edit shipped is a check against the **deployed binary**. Build internals: `references/deployment.md`. Rust code questions: the `rust-ares-expert` agent.

### EC2 (default plane)

```bash
# 1. Gate locally — the exact string CI and the pre-commit hook both run
cargo clippy --workspace --all-targets -- -D warnings
cargo test

# 2. Build + install + bounce the worker fleet (ships your WORKING TREE, uncommitted included)
S3_BUCKET=<bucket> task -y ec2:deploy EC2_NAME=kali-ares

# 3. GATE: assert your literal is in the DEPLOYED binary, not the local one.
#    Outer double quotes, inner SINGLE quotes — see the ec2:exec caveat below.
task ec2:exec EC2_NAME=kali-ares CMD="grep -ac -- 'your log literal' /usr/local/bin/ares"

# 4. Confirm the fleet came back and tools resolve
task ec2:status EC2_NAME=kali-ares
task ec2:exec EC2_NAME=kali-ares CMD='which nmap nxc certipy hashcat'

# 5. Clear the field. The last op almost certainly tore itself down already
#    (ARES_AUTO_TEARDOWN is ON by default); this is the belt-and-braces re-run
#    that covers a killed/crashed op, and the manual path ignores the claim key.
task ec2:teardown EC2_NAME=kali-ares LATEST=true DRY_RUN=true    # inspect classes first
task ec2:teardown EC2_NAME=kali-ares LATEST=true
task -y ec2:kill  EC2_NAME=kali-ares ALL=true

# 5b. Fleet readiness — with the ares@* workers down, every dispatch returns
#     "no responders" and the op wedges at zero progress
task ec2:setup EC2_NAME=kali-ares

# 6. Launch ONE op, non-blocking
task red:ec2:multi TARGET=dreadgoad DOMAIN=<lab-root-domain> EC2_NAME=kali-ares

# 7. Poll — do NOT ec2:watch from an agent, it blocks 2h
task ec2:ops:ids EC2_NAME=kali-ares
task ec2:runtime EC2_NAME=kali-ares LATEST=true

# 8. Pull the log window for YOUR op and grep for your change's evidence
task ec2:logs:fetch EC2_NAME=kali-ares ROLE=orchestrator OP_ID=op-YYYYMMDD-HHMMSS LINES=4000

# 9. Fetch the report; read the Executive Summary + Key Events, not the exit code
task ec2:report EC2_NAME=kali-ares OPERATION_ID=op-YYYYMMDD-HHMMSS
```

- **Step 3 caveat:** the deploy profile is `dev-deploy` — `opt-level = 2`, thin LTO, `strip = "symbols"` (`Cargo.toml:54-61`) — so const-folded literals can vanish. Format-string and `contains(...)` literals survive; a `starts_with` literal historically did not. `grep -ac -- '<STR>'` is a BRE inside single quotes: no single quotes, escape metacharacters.
- **`ec2:exec` caveat — a quoting error reports itself as `CMD required`.** The precondition is `sh: test -n "{{.CMD}}"` (`.taskfiles/ec2/Taskfile.yaml:1478`), and go-task substitutes `CMD` into it raw. A CMD containing a **double-quoted segment with whitespace inside** re-splits `test`'s arguments and the task dies with `task: CMD required.` / `precondition not met`, exit **201** — which reads as "you forgot CMD", not "your quoting broke". Verified empirically: `CMD='grep -ac -- "hello world" /usr/local/bin/ares'` → exit 201; `CMD="grep -ac -- 'hello world' /usr/local/bin/ares"` → exit 0; `CMD='echo "x"'` → exit 0; `CMD='echo "x y"'` → exit 201.
- **`ec2:exec` caveat (cont.):** go-task shell-evaluates CLI var values **locally**, so `CMD='echo $(hostname)'` reports your laptop. For anything with mixed quotes, newlines or `$( )`, base64-wrap it: `CMD="echo <b64> | base64 -d | bash"`. SSM's `StandardOutputContent` truncates silently at ~24 KB — the comment is in `logs:fetch` (`.taskfiles/ec2/Taskfile.yaml:737-739`) but the cap applies to every `run_ssm_cmd`, `ec2:exec` included.
- **Step 8 caveat:** `ROLE=all` iterates a role named `lateral_movement`, which does not exist (`.taskfiles/ec2/Taskfile.yaml:742`). The real unit and log are `lateral`. `ROLE=all` emits an empty `===FILE:/var/log/ares/lateral_movement.log===` section and never fetches `lateral.log`. Use `ROLE=lateral`.
- `ec2:deploy` also chains `deploy:config`, pushing `./config/ares.yaml` → `/etc/ares/config.yaml` (`.taskfiles/ec2/Taskfile.yaml:459-462`). **`config/ares.yaml` is read by the orchestrator only — no worker reads it.** `ares-cli/src/worker/mod.rs:23` loads `WorkerConfig::from_env()` and nothing else; `AresConfig::from_env` appears only at `ares-cli/src/orchestrator/mod.rs:85` and `:1392`, and `read_role_model` only at `:491`/`:522`. So a config-only push takes effect on the **next op launch** — each launch execs a fresh orchestrator process that re-reads `/etc/ares/config.yaml`. Bouncing `ares@*.service` neither helps nor is needed; deploy's restart step matters for binary changes only.

### K8s

`.claude/CLAUDE.md` prescribes, verbatim:

```bash
task -y k8s:reset && task -y k8s:deploy && task -y red:multi TARGET=dreadgoad
```

**Always append `IPS=<ips>`** — that part is not in CLAUDE.md. Without it the task adds `--resolve-targets`, which shells out to `aws` inside the orchestrator pod, and the pod has no `aws` CLI (`.taskfiles/red/Taskfile.yaml:79-80`).

`k8s:reset` kills local `red:multi` shells and wipes shared Redis — a shared-cluster nuke; coordinate first. `.claude/CLAUDE.md` also prescribes `task remote:sync:full TEAM=blue` for blue; `references/deployment.md` records that task as dead in the current tree.

### `testes.sh` — the untracked one-shot harness

`/Users/l/dreadnode/ares/testes.sh` runs the whole sequence above with a two-stage binary-freshness gate (`target/.deploy/ares.sha256` mtime, else a `Deploy SHA:` grep, compared to `sha256sum /usr/local/bin/ares`) plus an optional `GATE_STRING` presence check. Knobs: `EC2_NAME`, `AWS_REGION`, `TARGET`, `DOMAIN`, `SKIP_DEPLOY`, `SKIP_RESTART`, `SKIP_KILL`, `BLUE`, `BLUE_MODEL` (forwarded as `BLUE_LLM_MODEL`, `testes.sh:271`), `CRED_USER`/`CRED_PASS`/`CRED_DOMAIN`, `GATE_STRING`, `ALLOW_PROD`, `POLL_INTERVAL`, `MAX_WAIT`, `OUTPUT_DIR`, `ARES_CLI`, `BUILD_TOOL`, and **`S3_BUCKET` — required unless `SKIP_DEPLOY=1`; the script hard-fails without it** (`testes.sh:113-114`). Traps:

- **`BLUE=0` does not disable blue.** It is passed as `BLUE_ENABLED=` to `ec2:launch`, which declares no such var and hardcodes `export ARES_BLUE_ENABLED=1` (`.taskfiles/ec2/Taskfile.yaml:1330`). `BLUE=0` only skips the script's own blue reporting.
- **The "blind start" default is not blind.** Empty `CRED_USER`/`CRED_PASS`/`DOMAIN` let `ec2:launch`'s hardcoded lab credential and domain defaults through.
- Its step-3 `ec2:restart` does **not** drop the workers' in-memory unavailable-tool cache; only `ec2:deploy`'s `ares@*.service` restart does. `SKIP_DEPLOY=1` therefore keeps a poisoned cache — and skips `deploy:config`.
- `SKIP_RESTART=1` does not reach `ec2:deploy`'s opt-out, which compares against the literal string `"true"`.
- **Its header comment on `BUILD_TOOL` is stale.** `testes.sh:60-61` says the default is `auto` (local cross-compile); the real default is `remote` (`.taskfiles/ec2/Taskfile.yaml:73`), which is why no local `./target/release/ares` appears after a deploy.
- It uses `ec2:launch`, so **every run FLUSHDBs the box's Redis**.

## Worker roles, units, logs

| Role | systemd unit (EC2) | NATS tool subject | Log file |
|---|---|---|---|
| `recon` | `ares@recon.service` | `ares.tools.exec.recon` | `/var/log/ares/recon.log` |
| `credential_access` | `ares@credential_access.service` | `ares.tools.exec.credential_access` | `credential_access.log` |
| `cracker` | `ares@cracker.service` | `ares.tools.exec.cracker` | `cracker.log` |
| `acl` | `ares@acl.service` | `ares.tools.exec.acl` | `acl.log` |
| `privesc` | `ares@privesc.service` | `ares.tools.exec.privesc` | `privesc.log` |
| `lateral` | `ares@lateral.service` | `ares.tools.exec.lateral` | `lateral.log` (**`ec2:logs:fetch ROLE=all` misses this**) |
| `coercion` | `ares@coercion.service` | `ares.tools.exec.coercion` | `coercion.log` |
| orchestrator | transient `ares-orchestrator.service` (or `nohup`) | publisher | `orchestrator.log` |

Roles from `ansible/roles/redis/defaults/main.yml:66-73`. Red *agent loops* run in-process inside the orchestrator; the worker pods/units exist for **tool execution** only — see `references/architecture.md`.

## Route elsewhere

Routing map: `SKILL.md`. Nearest neighbours only:

| Question | Go to |
|---|---|
| "This op is stuck / slow / making no progress" | skill `ares-debug` (its Redis-type table at `SKILL.md:112-121` agrees with the one above; this doc adds the SET keys) |
| Redis key inventory, snapshot diffs, reaching EC2 Redis | `references/state-and-redis.md` |
| Build/deploy internals, binary-free equivalents, K8s rollout | `references/deployment.md` |
| Loki/Tempo queries, span catalog, label values | `references/observability.md` |

Test data: allowed values only — see `references/tools-and-gates.md#test-conventions`. `dreadgoad` is fine; it is a `TARGET=` value, not a domain, which is why lab domains appear in the commands above.
