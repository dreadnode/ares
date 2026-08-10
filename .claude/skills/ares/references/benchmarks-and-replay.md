# Benchmarks, sweeps, replay, reports

Fleet-scale work: the `benchmark:` task namespace, blue-team replay record/playback, the diversity knobs **as they ship today**, eval scoring and gap analysis, and the on-disk artifact layout.

Routing map: `SKILL.md`. Nearest neighbours only: running the diversity sweep end-to-end → `attack-path-diversity-sweep` skill (**its Step 1 is stale** — use the knob table below); knob precedence and the env table → `references/config-and-env.md`.

Test data: allowed values only — see `references/tools-and-gates.md#test-conventions`.

## Read this before you run anything

1. **`benchmark:generalize` can never produce a score. Every op reports `no-score`, `mean_score: null`.** The task reads `jq -r '.evaluation.overall_score // empty'` (`.taskfiles/benchmark/Taskfile.yaml:463`), but `BenchmarkResult.evaluation` is `eval_result.to_value()` (`ares-cli/src/benchmark/replay.rs:651`) which nests the score at `.evaluation.scores.overall` (`ares-core/src/eval/results.rs:163-170`). Nothing in the tree writes `evaluation.overall_score`. With `FAIL_UNDER` set it exits 1 on `FAIL_UNDER=$FU set but no mean score computed` (`:543`). Scrape the score yourself (recipe below).

2. **`benchmarks/holdout.yaml` ships 5 placeholder op IDs (`op-20260901-000001` … `-000005`) that map to no capture.** Its own header says so verbatim. Running `benchmark:generalize` unedited launches and terminates 5 EC2 instances, serially, replaying snapshots that do not exist.

3. **`--wait-for-flush` is not a flag.** Verified against the built binary: `ares benchmark capture --wait-for-flush op-x` → `error: unexpected argument '--wait-for-flush' found`, exit 2. The real flag is the inverted `--no-wait-for-flush`; waiting is the DEFAULT (`ares-cli/src/cli/benchmark.rs:40-45`). Root `Taskfile.yaml:205` still passes it, so **`task run CAPTURE=true` dies at the capture step**. `README.md:443` and `docs/benchmark-replay.md:53` repeat the error. **The working auto-capture is `task ec2:launch … CAPTURE=true`** (`.taskfiles/ec2/Taskfile.yaml:1103`, block `:1377-1393`) — its capture call omits the flag (`:1388-1391`). Its own inline comment at `:1375` still names `--wait-for-flush`, but the command is right.

4. **`MAX_WAIT` on `diversity-sweep` is per op, not per sweep.** Default 7200s, so `N=10` is a 20-hour worst case. An op that never registers prints `Operation <op> not found` with no `Status:` line (`ares-cli/src/ops/status.rs:17-20`), the poll's `sed -n 's/^Status: //p'` yields empty, and the `*)` "no status yet" branch (`Taskfile.yaml:700`) burns the whole budget.

5. **A stale `ares:lock:<op>` makes a dead op read `running`.** Status is derived, never stored: `completed_at || red_completed_at` → `completed`; else lock exists → `running`; else `stopped` (`ops/status.rs:28-34`; `ares-core/src/state/reader.rs:179-187` is a bare `EXISTS ares:lock:<op>`). **This is not what stalls a sweep.** The preflight WARN (`Taskfile.yaml:625-630`) fires on locks belonging to *other* op ids, while the sweep's poll queries the freshly-minted `OP_ID` it was handed (`ares-cli/src/redis_conn.rs:30-32`) — another op's leftover cannot make op 1 read `running`. A genuinely stale lock also self-clears inside `ARES_LOCK_TTL_SECS` = 300s (`ares-cli/src/orchestrator/config.rs:196`), because `extend_lock` only EXPIREs while the recorded holder still matches (`orchestrator/task_queue.rs:685-697`); the Taskfile says as much at `:629`. What the WARN actually tells you is that a prior op may still be **live** and contending for `ares:operation:active`. The only thing that burns MAX_WAIT is the never-registering op in item 4.

6. **Teardown is `trap cleanup EXIT` only** (`Taskfile.yaml:126`, `:212`) — but go-task installs its own INT/TERM handler, cancels the command and lets the EXIT trap run, so **Ctrl-C does tear the stack down**. Verified on task 3.52.0: single SIGINT, double SIGINT and SIGTERM each print `task: Signal received` and then run the nested `benchmark:replay:teardown` to completion. **A third Ctrl-C does not** — go-task prints `Signal received for the third time: "interrupt". Forcing shutdown` and exits without firing the trap, leaking the EC2. Same for SIGKILL and laptop death, and for a teardown that itself fails — swallowed as a WARN (`:123-124`, `:209-210`). One more nuance: the trap does not fire until the in-flight command returns, so an interrupt during a 45-min `replay:run` tears down only once that command exits. Hunt leaks by tag (below).

7. **The diversity knobs SHIP ENABLED.** `docs/attack-path-diversity.md:12,98` and `.claude/skills/attack-path-diversity-sweep/SKILL.md:3,24,35` all still say "off by default" / "SHIPS DISABLED" / "Uncomment". Stale since `72a40f02` (#361, 2026-07-29). `config/ares.yaml:104-116` ships all four on, and `ares-cli/src/orchestrator/strategy.rs:856-866` is a test that fails if you turn them off.

## Task index — `.taskfiles/benchmark/Taskfile.yaml`

894 lines, 9 tasks, included at root `Taskfile.yaml:28-33` as namespace `benchmark`. File-scope `set: [errexit, pipefail]` (`:71`); most cmd blocks redeclare `set -euo pipefail`.

| Task | Lines | Requires | Ops run | Ordering | Blocks until done? | Danger |
|---|---|---|---|---|---|---|
| `benchmark:replay` | 93-141 | `OP_ID` | 1 blue investigation | single | **YES** — provision + run + teardown all foreground | creates and terminates a real EC2; teardown runs on EXIT incl. Ctrl-C — leaks only on a 3rd Ctrl-C, SIGKILL, or a failed teardown |
| `benchmark:replay:run` | 143-175 | `STACK_IP`, `OP_ID` | 1 blue investigation | single | **YES** — 45-min hard cap per replicate | nothing destructive; needs in-VPC reach + NATS + Redis |
| `benchmark:replay:loop` | 177-247 | `OP_ID` | N blue investigations | **SEQUENTIAL**, one shared stack | **YES**, each | EC2 held for the whole loop; a failed iteration WARNs and continues, a failed `HOOK` aborts |
| `benchmark:replay:provision` | 249-375 | `OP_ID` + 3 `BENCHMARK_*` preconditions | — | single | n/a | leaves an EC2 RUNNING on success; 1800s SSM budget |
| `benchmark:replay:teardown` | 377-386 | `INSTANCE_ID` | — | single | n/a | **DESTRUCTIVE, unconfirmed** — `terminate-instances` with no tag check |
| `benchmark:replay:ami:current` | 388-398 | — | — | — | n/a | read-only |
| `benchmark:generalize` | 400-551 | preconditions: holdout file, `yq`, `jq` | N blue investigations | **SEQUENTIAL**, its own provision+teardown per op | **YES**, each (it loops `benchmark:replay`, not `:run`) | N full EC2 cycles, hours; scoring broken; all per-op output hidden in `replay.log` |
| `benchmark:diversity-sweep` | 552-776 | `N`, `TARGET` | N **red** ops | **SEQUENTIAL by construction** (`:648-649`) | **YES** — the wait is hand-rolled here | real red ops; up to N×MAX_WAIT; `RESET=true` wipes ALL novelty scopes; force-stops a lingering op |
| `benchmark:diversity-diff` | 778-894 | `BEFORE`, `AFTER` | — | — | n/a | read-only; markdown fallback is broken (below) |

**Why the sweep owns its own wait loop.** `red:ec2:multi` is submit-only: its submit step carries `ignore_error: true` (`.taskfiles/red/Taskfile.yaml:925`) and it has no FOLLOW/MAX_WAIT var, so it returns 0 in ~13s whether or not the op started. The in-file comment at `:651-656` documents the pre-#361 bug where passing `FOLLOW=true` did nothing and the "sequential" loop fired every op concurrently, recording all of them as successes. The poll lives at `:688-703`. `ec2:watch` is not a substitute: it breaks on `completed|stopped` alike and exits 0 for both (`.taskfiles/ec2/Taskfile.yaml:1041-1045`), and `stopped` is exactly what a never-started op looks like.

**`Status: completed` fires on `red_completed_at`, before the blue drain** (`ops/status.rs:24-27`, up to 45m). Op N+1 therefore starts while blue is still consuming op N. The sweep's post-op guard (`:716-725`) only kills an op still reading `running`.

**Any EC2 sweep you write yourself must re-implement that poll.** `red:ec2:multi` is the only submit-only red task. The waiting red tasks exist — they are just k8s/local-CLI shaped, never SSM, which is exactly why the sweep hand-rolls its own loop.

| Task | Lines | Waits? | How |
|---|---|---|---|
| `red:ec2:multi` | `.taskfiles/red/Taskfile.yaml:773-925` | **NO** | no FOLLOW/MAX_WAIT/POLL_INTERVAL var anywhere in the body; submit step ends `ignore_error: true` (`:925`) |
| `red:multi` | `:21-156` | **YES, by default** | `FOLLOW` defaults `true` (`:27`), `POLL_INTERVAL` 30 (`:28`), `MAX_WAIT` 7200 (`:29`); loop `:122-155` polls `ares --k8s … ops status` (`:131`) and auto-fetches the report |
| `red:multi:watch` | `:320-395` | **YES** | poll-to-terminal, `MAX_WAIT` 7200 (`:327`), loop `:350-395`, status at `:357`. `ONCE=true` exits after the first terminal op |
| `ec2:watch` | `.taskfiles/ec2/Taskfile.yaml:985-1057` | **YES, but useless as a gate** | breaks on `completed` and `stopped` alike (`:1041-1045`) — `stopped` is what a never-started op looks like |
| `ec2:launch` | `.taskfiles/ec2/Taskfile.yaml:1062-1393` | **YES** (`WAIT` defaults `true`, `:1098`) | `MAX_WAIT` 7200 (`:1100`); `FLUSH_REDIS` defaults `true` (`:1089`) so it wipes novelty memory first; `CAPTURE=true` (`:1103`) auto-captures after the op |

### Copy-pasteable

```bash
# Full blue replay: provision → investigate → teardown
task benchmark:replay OP_ID=op-20260706-123045

# Provision only. Exactly two lines hit stdout; every diagnostic is >&2 on purpose.
eval "$(task benchmark:replay:provision OP_ID=op-20260706-123045 | grep -E '^(STACK_IP|INSTANCE_ID)=')"

# Warm-stack tuning loop (K-of-N averaging when HOOK is omitted)
task benchmark:replay:loop OP_ID=op-20260706-123045 ITERATIONS=8 QUIET_PERIOD=0 \
  HOOK='python -m vibe_gepa.update --op-id "$OP_ID" --iter "$ITERATION"'

# Noise floor on one stack: 5 replicates, seeded (OpenAI only)
task benchmark:replay:run STACK_IP=192.168.58.5 OP_ID=op-20260706-123045 REPLICATES=5 SEED=42

task benchmark:replay:teardown INSTANCE_ID=i-abc123
task benchmark:replay:ami:current

# Which replay stacks leaked?
aws ec2 describe-instances \
  --filters "Name=tag:ares:component,Values=benchmark-replay" "Name=instance-state-name,Values=running" \
  --query 'Reservations[].Instances[].[InstanceId,Tags[?Key==`ares:operation`]|[0].Value]' --output table
```

**Two tag values, one word apart.** AMIs are resolved on `tag:ares:component=benchmark-replay-stack` (`:274`, `:396`; set by the bake at `warpgate-templates/templates/ares-replay-stack/warpgate.yaml:113`). Launched **instances** are tagged `ares:component=benchmark-replay` (`:309`), alongside `ares:operation=<OP_ID>` and `Name=ares-replay-<OP_ID>`. Search the wrong one and you find nothing. A setup failure that ALSO fails teardown self-labels `ares:orphan=true` + `ares:orphan-reason=ssm-setup-failed` (`:350-351`).

**`replay:provision` stdout is a protocol, not a log.** Only `STACK_IP=` / `INSTANCE_ID=` reach stdout (`:374-375`); callers awk-parse them at `:113-114` and `:199-200`. Add one un-redirected `echo` — or merge `2>&1` before the grep — and both callers die with `provision did not produce STACK_IP/INSTANCE_ID`.

**Preconditions bite out of the box — but only where something provisions.** The repo `.env` declares `BENCHMARK_SECURITY_GROUP_ID` / `BENCHMARK_INSTANCE_PROFILE` / `BENCHMARK_SUBNET_ID` with empty values. All three `preconditions:` blocks sit on `replay:provision` alone (`:253-259`); the only other `preconditions:` key in the file is `generalize`'s holdout/`yq`/`jq` gate (`:413`). So `benchmark:replay:provision` exits 201 directly, and `benchmark:replay` / `:loop` / `benchmark:generalize` fail through it. `replay:run`, `replay:teardown` and `replay:ami:current` declare none and are unaffected — the warm-stack loop above needs only `STACK_IP`. Verified with `--dry`: `provision` → 201 (`task: BENCHMARK_SECURITY_GROUP_ID is required (see .env.example)`), `replay:run STACK_IP=… OP_ID=…` → 0, `replay:teardown INSTANCE_ID=…` → 0, `replay:ami:current` → 0.

## Red-side replay recording was a dead surface — the tasks are gone

Asked to "record and replay" a red op, you may still find references to four `red:multi:replay:*` tasks (`copy`, `cat`, `list`, `clear`). They were removed on 2026-08-08. They `kubectl cp`/`exec`'d `/ares/replay/recording.jsonl` on `ares-<role>-agent-0` pods, and **nothing in the tree ever wrote that path** — `rg 'recording\.jsonl'` and `rg 'ares/replay'` matched only `.taskfiles/red/Taskfile.yaml` itself, no Rust. `red:multi:replay:copy` defaulted to `./recordings`, which is why that directory shows up empty.

The real replay surface is `benchmark capture` → `benchmark:replay`, below.


## `ares benchmark` CLI surface

The whole subtree is `#[cfg(feature = "blue")]`. `blue` is in default features, but a `--no-default-features` build produces an `ares` with no `benchmark` verb — indistinguishable from a stale deploy.

| Subcommand | Flag | Default | Note |
|---|---|---|---|
| `capture` | `<operation_id>` / `--latest` | — | bails when the op has no `completed_at` (`capture.rs:99`) |
| | `--output-dir` | `benchmarks` | lands in `<dir>/<op-id>/` |
| | `--pre-window-hours` / `--post-window-minutes` | 6 / 360 | Loki export window |
| | `--no-upload` | false | skips the `aws s3 sync` |
| | `--attacker-ips` (comma) | empty | stored as **required** IOCs, `source: attacker_infrastructure` |
| | `--no-wait-for-flush` | false — **waiting is the default** | the only flush flag |
| | `--flush-timeout-mins` | 60 | on timeout it WARNs and proceeds; never fails |
| `load` | `<snapshot_dir>`, `--loki-url`, `--loki-token` | — | **no-op for every modern snapshot** (below) |
| `run` | `<snapshot>` (op id) | — | positional |
| | `--stack-ip` | — (`required = true`) | private IP of a provisioned stack |
| | `--snapshot-dir` | none → S3 temp download | the ONLY way Tempo traces reach the push |
| | `--replay-mode` | `timeline` | `timeline`\|`static`; anything else `bail!`s (`replay.rs:117-122`) |
| | `--trigger-mode` | `alert-replay` | `timeline` force-overrides to `alert-replay` (`replay.rs:314-319`) |
| | `--output-dir` | `benchmark-results` | Taskfile overrides to `./reports` |
| | `--model` | none | falls back `ARES_BLUE_LLM_MODEL` → `ARES_LLM_MODEL` → `openai/gpt-5.2` |
| | `--max-steps` | **25** | Taskfile passes 50; also becomes `ARES_REPLAY_MAX_STEPS` |
| | `--quiet-period` | random 60–300s | timeline only; `0` skips |
| | `--clock` | `step` | `step`\|`wallclock`; **NOT validated** (below) |
| | `--seed` | none | → `ARES_LLM_SEED`; **OpenAI only**; forces temperature 0 when `--temperature` unset |
| | `--temperature` | none | → `ARES_LLM_TEMPERATURE`; always wins over the seed implication |
| | `--replicates` | 1 | K>1 also writes `<session>-summary.json`; sequential, same stack |
| `list` | — | — | one `aws s3 cp` per snapshot prefix; unparsable manifests are warn-and-skipped |

Source: `ares-cli/src/cli/benchmark.rs:1-162`.

**`capture` reads the BOX's Redis, and `--redis-url` is not a `benchmark` flag.** It is global on `ares` (`ares-cli/src/cli/mod.rs:32-34`, `global = true`, env `ARES_REDIS_URL`), so it is absent from the table above. Both shipped capture recipes SSM-forward the instance's 6379 to local 16379 and pass `--redis-url redis://localhost:16379` (root `Taskfile.yaml:193-207`; `.taskfiles/ec2/Taskfile.yaml:1382-1391`). A bare `ares benchmark capture <op>` from a laptop therefore hits localhost Redis and dies at step 1/5 with `no state found for operation: <op>` (`capture.rs:94-97`) — or `Failed to connect to Redis` if nothing is listening. Forward first, or use `task ec2:launch … CAPTURE=true`, which does it for you and also passes the instance's private IP as `--attacker-ips` (`:1379-1390`).

**Taskfile defaults deliberately diverge from clap.** `MAX_STEPS` 50 (`:100,150,186,408`) vs `--max-steps` 25; `OUTPUT_DIR` `./reports` vs `benchmark-results`. In `step` clock mode `max_steps` **is** the clock denominator (`ares-core/src/replay_clock.rs:103-109,150-153`), so a hand-run `ares benchmark run` unfolds the same attack across half as many steps. It is not the same experiment.

**Empty Taskfile vars are dropped from the command line** (`{{if .SEED}}--seed …{{end}}`, `:170-175`), so a mistyped var name silently degrades to the CLI default instead of erroring.

## Replay: capture → provision → playback → score

`ares benchmark run` spawns an **in-process** blue NATS consumer once per session (`replay.rs:379-402`), so the blue side needs no `ares worker` units — unlike the red sweep, whose entire preflight exists because red tool calls route over NATS to `ares@<role>.service`. It still needs reachable NATS and Redis.

**What `run` overwrites in the process env from `--stack-ip`** (`replay.rs:129-155`): `LOKI_URL` :3100, `GRAFANA_URL` :3000, `PROMETHEUS_URL` :9090, `TEMPO_URL` :3200, plus `ARES_SESSION_TEAM=blue` and `ARES_SESSION_LOG_DIR` (default `/var/log/ares/session`). Transcripts land at `<session_dir>/<op_id>/<run_id>.jsonl`, joinable to red on `op_id`.

### Replay-stack services

| Service | compose (source of truth) | warpgate bake pre-pull | Port | Provision verifies? | Used by `benchmark run` |
|---|---|---|---|---|---|
| loki | `grafana/loki:3.7.4` | `grafana/loki:3.6.7` | 3100 | YES `/ready` | YES |
| prometheus | `prom/prometheus:v3.13.1` | `prom/prometheus:v3.11.3` | 9090 | YES `/-/ready` | YES |
| grafana | `grafana/grafana:13.1.1` | `grafana/grafana:12.3.1` | 3000 | YES `/api/health` | YES |
| tempo | `grafana/tempo:3.0.2` | `grafana/tempo:2.9.0` | 3200, 4318 | **NO** | YES (`TEMPO_URL`, OTLP push) |
| mimir | `grafana/mimir:3.1.4` | `grafana/mimir:3.0.4` | 9009 | NO | parity only |
| alertmanager | `prom/alertmanager:v0.33.1` | `prom/alertmanager:v0.28.1` | 9093 | NO | parity only |

`benchmarks/replay-stack/docker-compose.yml:16-80`; `warpgate.yaml:74-79`. **All six tags disagree today**, and `ares-cli/src/benchmark/versions.rs:11` pins the capture-time promtool at `prom/prometheus:v3.11.3` — two minors behind the replay Prometheus its blocks must load (v3.11.3 vs `docker-compose.yml:28`'s v3.13.1). Both files' comments say the lists MUST stay in sync. Consequence: the AMI's cache is 0-for-6 useful, every provision re-pulls all six.

Verification probes only 3 of 6 (`:359-364`), 30 attempts × 2s each. **Tempo :3200 is never probed**, so an empty attack-graph panel passes provisioning silently.

Prometheus runs `--storage.tsdb.retention.time=10y` (`docker-compose.yml:35-39`) on purpose: captured blocks carry historical timestamps and the default 15d retention reaps them the moment a snapshot is replayed >15 days after capture.

### Provisioning mechanics

- Root EBS is derived from the AMI's own snapshot size, floored at 40 GB (`:292-299`). A hardcoded 20 was rejected `InvalidBlockDeviceMapping` after the bake grew root to 40 GB.
- The IP read is the **private** IP (`:315-316`). Verify and the subsequent `benchmark run` both need in-VPC reachability. `BENCHMARK_SKIP_STACK_VERIFY=1` (`:357`) is the laptop escape hatch — without it, a laptop outside the VPC fails the curl gate and the task **tears down a perfectly healthy stack** (`:365-369`).
- The SSM setup script is an **unquoted heredoc** (`SETUP_SCRIPT=$(cat <<EOF`, `:321`). Any `$VAR` you add to the body expands on your laptop, not on the instance. Latent today — the body only uses `{{...}}` template refs.
- No baked AMI ⇒ stock AL2023 fallback (~10 min slower) unless `BENCHMARK_REQUIRE_BAKED_AMI=1` (`:277-289`). The Taskfile's own remediation is `warpgate build ares-replay-stack --only 'ami.*'` (`:280`); `docs/benchmark-replay.md` documents a different invocation. UNVERIFIED which one your warpgate accepts.

### `SNAPSHOT_DIR` does not change what the stack ingests

The setup script always runs `aws s3 sync s3://$BENCHMARK_S3_BUCKET/snapshots/$OP_ID/ /opt/snap/` (`:341`) and then `SNAPSHOT_DIR=/opt/snap GRAFANA_URL=http://localhost:3000 bash /opt/replay-stack/setup.sh` (`:342`). `--snapshot-dir` only redirects where the **local** `ares benchmark run` reads manifest / red-state / ground-truth ("overrides S3 download for local testing", `cli/benchmark.rs:89-91`). A local-only snapshot scores an investigation against whatever Loki the stack actually staged.

Related: without `--snapshot-dir`, exactly four files come down from S3 — `manifest.json`, `red-state.json`, `ground-truth.json`, `fired-alerts.json` (`snapshot_s3.rs:135-140`). `tempo/traces.jsonl.gz` is not among them, so `push_traces_bundle` logs `no Tempo bundle in snapshot — skipping push` and returns `Ok(0)` (`tempo_push.rs:35-39`) even though capture uploaded it.

Passing `SNAPSHOT_DIR` to `benchmark:generalize` applies ONE directory to EVERY op in the held-out set (`:453`), silently replaying the same capture N times. Leave it unset for a real sweep.

### Capture crosses two AWS accounts

| Leg | Bucket | Region | Profile |
|---|---|---|---|
| source Loki chunks | `dev-argonaut-loki` | `us-west-2` | `infrastructure` |
| snapshot upload | `ares-benchmark-us-west-1` | `us-west-1` | `lab` |

`ares-cli/src/benchmark/capture.rs:27-39` (`LOKI_S3_BUCKET` / `_REGION` / `_PROFILE` override the first). Note `BENCHMARK_AWS_PROFILE` has opposite defaults per direction: capture upload defaults to `lab` (`capture.rs:37`), the read path defaults to `""` = default credential chain / instance role (`snapshot_s3.rs:22`, `append_aws_opts` omits `--profile` when empty).

### Traps in the record path

- **No `GRAFANA_URL` ⇒ silent thin snapshot.** Alerts, metrics, dashboards, annotations and Tempo traces all skip with an info line (`capture.rs:774`, shared gate at `:863-867`) and capture exits 0. It surfaces much later as `no fired alerts in snapshot — use --trigger-mode=operation instead` (`replay.rs:897`) — which steers you into the contaminated oracle mode.
- **`ares benchmark load` imports nothing for any snapshot produced today.** `run_load` short-circuits `loki_source == "s3-chunks"` to a print-and-return (`replay.rs:68-80`). Only legacy `api-export` snapshots are actually pushed. No Taskfile invokes it.
- Tempo capture uses a **narrower** window than everything else: attack ±30 min (`capture.rs:189`, `metrics_start`/`metrics_end`), not the padded −6h/+360m export window.

### Replicates

Zero-indexed: `REPLICATES=3` → `inv-<ts>-r0.json`, `-r1`, `-r2`, plus `inv-<ts>-summary.json`. `REPLICATES=1` → plain `inv-<ts>.json`, no summary (`replay.rs:423-428`, `:655`, `:715`). One stack, one shared consumer, strictly sequential. **A single failing replicate bails the whole run before the summary is written** (`run_single_replicate(...).await?` at `:430`; `run_result?` at `:452` precedes the summary write) — the K-of-N estimate is lost. Per-replicate ceiling: 45 min, 10s Redis poll on `ares:blue:inv:<run_id>:status` (`:553-556`); `completed`/`escalated` succeed, `failed` bails. Only replicate 0 pays the quiet period; later ones record `quiet_period_secs: null` rather than lying (`:639-646`).

`--seed` reaches **only** OpenAI. `provider_supports_seed` returns false for `anthropic/`, `claude-cli/`, `ollama/` prefixes — those warn and sample normally (`replay.rs:253-263`). A "seeded" Anthropic replicate set is not deterministic. Bare model names with no provider prefix are optimistically assumed to honour it.

### `--trigger-mode operation` is an oracle

`build_operation_trigger` hands the agent the ground-truth techniques, IOCs, creds and hosts the scorer grades. The runner prints `⚠ SCORE INVALID: trigger=operation leaked ground truth (oracle mode).` per run (`replay.rs:662`) and a stderr block containing `this score is CONTAMINATED` at session end (`:456-461`). Never report that number. `--replay-mode timeline` (the default) force-overrides the trigger to `alert-replay`, so oracle mode is only reachable via `--replay-mode static`.

### Replay clock

| `ARES_REPLAY_CLOCK_MODE` | `replay_now()` | `replay_clamp_end()` | Use |
|---|---|---|---|
| unset → Frozen | START (or `Utc::now` with no anchor) | **None — no clamp** | legacy back-compat / live |
| `static` | END | **None — no clamp** | whole concluded attack visible up front |
| `step` (timeline default) | START + span × clamp(step / max_steps) | `Some(replay_now)` | deterministic — the scoring mode |
| `wallclock` | START + elapsed, capped at END | `Some(replay_now)` | real-time demos, not scoring |

`ares-core/src/replay_clock.rs:94-101`, `:139-173`. **`--clock` is the one mode flag with no validation** — `--replay-mode` and `--trigger-mode` both `bail!`, but `mode()` maps anything unrecognised to `Mode::Frozen`, which returns `None` from `replay_clamp_end()`. A `CLOCK=wall-clock` typo silently produces an **unclamped** run where the agent can query the whole attack from step 0, with no warning and an inflated score.

`ARES_REPLAY_MAX_STEPS` falls back to 50 inside the clock (`:103-109`) while `--max-steps` defaults to 25. The step counter is a process-global `AtomicU64` advanced once per agent turn (`replay_clock.rs:49,122-124`; `ares-llm/src/agent_loop/runner.rs:318` calls `advance_step()`, **not** `set_step()` as `docs/benchmark-replay.md:255` claims), while `max_steps` is a per-agent budget — with several blue agents the clock saturates at attack-end once the first agent exhausts its budget.

## Diversity knobs, as they ship today

`config/ares.yaml:96-118`. Running a sweep is the `attack-path-diversity-sweep` skill's job — this section is only the current ground truth for the knobs, because that skill's Step 1 is stale.

| YAML key (under `operation:`) | Shipped | Rust struct default | Env override | JSON payload |
|---|---|---|---|---|
| `selection_temperature` | **0.7** | 0.0 | `ARES_SELECTION_TEMPERATURE` | yes |
| `novelty.enabled` | **true** | false | `ARES_NOVELTY_ENABLED` | no |
| `novelty.scope` | `per-campaign` | `"per-campaign"` | **none** | no |
| `randomize_entry_foothold` | **true** | false | **none — YAML only** | no |
| `emit_path_records` | **true** | false | `ARES_EMIT_PATH_RECORDS` | no |
| `acl_publish_cap` (adjacent anti-flood knob) | 200 | 200 | none | no |

Struct defaults `strategy.rs:91-95`; env branches `:223`, `:244`, `:247`; the YAML block at `:236-243` assigns novelty/randomize/emit **unconditionally**, clobbering any JSON payload. Pinned on by the `shipped_config_enables_diversity_knobs` test (`strategy.rs:856-866`, `include_str!` of the shipped config). `selection_temperature` is clamped at 0 from below (`:233`), never from above.

**You cannot fully restore determinism with env vars.** `ARES_SELECTION_TEMPERATURE=0 ARES_NOVELTY_ENABLED=0` covers two knobs; `randomize_entry_foothold` and `novelty.scope` have no env override at all (`rg 'ARES_RANDOMIZE'` → zero hits). A bit-identical repro needs a config edit plus a deploy.

**`per-campaign` is a literal string, not a per-campaign namespace.** `novelty_key(scope) = format!("ares:novelty:{scope}:steps")` (`diversity.rs:56-58`). With the shipped config every op on the box shares one set, `ares:novelty:per-campaign:steps`. `CAMPAIGN=` in the sweep names the output directory only (`:562-579,665,733`) — it is never plumbed to the scope. The sweep skill's "Also becomes the novelty-memory scope" is wrong.

**Where each mechanism actually reaches:**

| Site | File:line | temperature > 0 | novelty |
|---|---|---|---|
| `pop_next_vuln` (exploitation vuln queue) | `exploitation.rs:323,340-351,370-388` | leaves atomic `ZPOPMIN` for a `ZRANGEBYSCORE` peek of top-24 + softmax + `ZREM` | **YES** — `+NOVELTY_PENALTY` per already-walked step |
| `DeferredQueue::pop_best` | `deferred.rs:386-393` | softmax over one candidate per per-type ZSET, on raw `t.priority` (drops the `score()` enqueue-time tiebreak) | **NO** — never consulted |
| `dispatch_initial_recon` | `bootstrap.rs:388-403` | n/a | n/a — `entry_ips.shuffle()` only |

`NOVELTY_PENALTY = 4.0`, `CANDIDATE_LIMIT = 24` (`diversity.rs:31,35`). At T=0.7 a seen step is down-weighted ~300× but never unreachable. Note the diversity path replaces an atomic pop with peek-then-`ZREM`, safe only under single-orchestrator ownership (`exploitation.rs:392-394`) — a second concurrent orchestrator double-dispatches. That is the harder reason the sweep must stay sequential.

**`randomize_entry_foothold` does not pick a credential.** It shuffles the order of `config.target_ips` for the initial recon fan-out. With one target IP it is a no-op.

**`PathStep.foothold` is always `"-"`.** The single `record_step` call site passes `None` (`state/dedup.rs:103-113`); `diversity.rs:172` does `foothold.unwrap_or("-")`. Entry-point diversity is unmeasurable from sweep output — the CSV has no foothold column anyway (`:577`).

**`technique` in the CSV is a lowercased ares `vuln_type`, not an ATT&CK ID** (`diversity.rs:173`). Do not join it against blue `detections.yaml` `mitre_id`s.

**Runtime ground truth is one log line.** Every op logs `Strategy resolved` at INFO with `selection_temperature`, `novelty_enabled`, `randomize_entry_foothold`, `emit_path_records` (`strategy.rs:251-263`).

```bash
task ec2:exec EC2_NAME=kali-ares CMD='sudo grep -a "Strategy resolved" /var/log/ares/orchestrator.log | tail -1'
# What the sweep preflight actually greps (note: /etc/ares/config.yaml, not git):
task ec2:exec EC2_NAME=kali-ares CMD='grep -E "^  (selection_temperature|randomize_entry_foothold|emit_path_records):" /etc/ares/config.yaml; grep -E "^  novelty:|^    enabled:" /etc/ares/config.yaml'
```

Config resolution prefers `./config/ares.yaml` in cwd, then `/ares/config/ares.yaml`, then `/etc/ares/config.yaml` (`ares-core/src/config/mod.rs:19-24`), with `ARES_CONFIG` overriding all three — so a checkout on the box can win over the file the preflight inspected.

## Telling a real sweep from a vacuous one

Start with the campaign directory. It has three diagnosable shapes.

| On-disk signature | Diagnosis |
|---|---|
| `ops.txt` **0 bytes** + header-only `coverage.csv`, matching mtimes | Died in the PREFLIGHT block. Block 1 creates both files (`:577-578`), block 2 `exit 1`s. Live example: `reports/diversity/t07-n10-20260730/` — 34 B / 0 B, both Jul 29 23:39. |
| `ops.txt` populated with op IDs **seconds apart**, no `FAILED` suffix | Ran on a pre-#361 Taskfile (or a hand-rolled loop with no wait) and fanned all N ops out concurrently. Live example: `reports/diversity/smoke-n5-20260730/ops.txt` — 23:22:42, :22:55, :23:08, :23:22, i.e. ~13 s apart. **#361 (`72a40f02`, 2026-07-29 23:37) added the poll** — that is the cutoff for dating an `ops.txt`, not #362. #362 (`46ee14d3`, 2026-07-30 00:37) layered the worker/lock preflight on top; its only Taskfile hunk is `@@ -605,6 +605,30 @@`. |
| `ops.txt` has completed op IDs but there is **no `red/` subdirectory** | `task ec2:report` failed for every op; the sweep only WARNs (`:708-710`). Both existing campaigns show this. |

**A header-only `coverage.csv` is a hard failure (`exit 1`, `:766-771`), not a zero-finding success.** The task's own message names two causes; there are four:

1. Ops never reached `completed` — cross-check `ops.txt`.
2. `emit_path_records` is false on the box.
3. **Ops completed having exploited nothing.** `record_step` fires exclusively from `SharedState::mark_exploited` (`state/dedup.rs:103`), so a sweep where every op finishes clean but exploits nothing legitimately writes zero path records. Not named by the error text.
4. **`jq` is missing on your box.** `:752-753` suppress jq's stderr and `:754` `continue`s on an empty technique. `diversity-sweep` has no `jq` precondition (`:554-555` is `requires: vars: [N, TARGET]` only) — unlike `generalize`, which preconditions on both `yq` and `jq` (`:413-419`).

**coverage.csv counts FAILED ops too.** The pull loop reads every line of `ops.txt` and strips the failure suffix with `op=${op%% *}` (`:741-742`), so the op count in the CSV can exceed the `OK` count printed by `grep -cv 'FAILED'` (`:727`). Read `ops.txt` before trusting either.

**`coverage.csv` answers "what was walked", never "what was never walked".** Its header is `op_id,step_index,technique,target` (`:577`) and every row comes from `record_step`, so the file is a positive-only list; `diversity-diff` is a BEFORE/AFTER set-diff over the same positive lists. "Which techniques were never exploited" needs a **denominator**, and there are two different ones — say which you measured:

| Question | Denominator | How |
|---|---|---|
| Discovered but never exploited | the op's own `vulns` HASH | union `ares ops inspect-vulns --json` (discovered vs exploited per `vuln_type`) across every op id in `ops.txt` — `task ec2:exec EC2_NAME=<pinned> CMD='ares ops inspect-vulns <op> --json'` |
| Never even discovered | the static candidate list | `is_automation_owned_vuln`'s ~25 exact arms plus the `gpo_` prefix and `EXPLOITABLE_ESC_TYPES` (`ares-cli/src/orchestrator/exploitation.rs:22-64`), plus the `vulnerability_priorities` keys in `config/ares.yaml` |

The two mean different things and a reader will assume the first. Also note `technique` in the CSV is a lowercased ares `vuln_type`, not an ATT&CK ID.

**Expect `exploited` count > `path_record` length as normal.** Superseded vulns are credited into the exploited SET but never recorded — `walked_step` is `primary.map(...)` only (`state/dedup.rs:49-67`), pinned by `mark_exploited_records_walked_step_for_primary_only` (`:668`). A vuln absent from the in-memory `discovered_vulnerabilities` map records nothing even though the SADD still happens.

**The delta is enumerable: `ares:op:<op>:superseded`.** `mark_exploited` SADDs every superseded id into both the exploited SET and this second SET, and SREMs the primary from it (`state/dedup.rs:70-89`; suffix `KEY_SUPERSEDED = "superseded"`, `ares-core/src/state/keys.rs:44`), 86400s TTL. The report renderer subtracts it — `exploited = exploited_set.contains(id) && !superseded` — and prints `SUPERSEDED (goal reached via another path; this technique unproven)` instead of `EXPLOITED` (`ares-core/src/reports/context.rs:291-292,315-321`). That is also why `diversity-diff`'s markdown fallback taking `EXPLOITED` only is correct rather than lossy: it matches `record_step`'s primary-only semantics exactly.

```bash
task ec2:exec EC2_NAME=kali-ares CMD='redis-cli SCARD ares:op:'"$OP"':exploited; redis-cli SCARD ares:op:'"$OP"':superseded; redis-cli LLEN ares:op:'"$OP"':path_record'
```

**All recorder Redis failures are debug-level and swallowed** — `path record rpush failed`, `coverage sadd failed`, `novelty sadd failed` (`diversity.rs:179,184,191`) — and `novelty_seen` fails open to all-false (`:138-141`). An empty record with correct config needs `RUST_LOG=debug` to explain itself.

**The preflight lies in two directions:**

- The temperature regex `^  selection_temperature: 0*\.[1-9]|^  selection_temperature: [1-9]` (`:598`) rejects a legitimate `0.05` as "0 or missing", and requires exactly two-space indent. Its remediation still says "Uncomment the diversity knobs" (`:600`) — they have been uncommented since #361.
- The novelty check is a bare unanchored `grep -q 'enabled: true'` (`:603`) over the combined output of two greps. Any `enabled: true` in that output satisfies it. It is a WARN, not a gate.

**The worker gate is real and worth keeping.** `:614-620` aborts on `no 'ares worker' processes on <box> — every op would stall with no NATS consumer.` `task ec2:deploy` does not reliably fix this — it bounces only units already `--state=active` and `ec2:restart` bounces none (`references/deployment.md`). Start them explicitly:

```bash
task ec2:exec EC2_NAME=kali-ares \
  CMD='for r in recon credential_access lateral privesc acl coercion cracker; do systemctl start ares@$r; done'
```

**`diversity-diff`'s markdown fallback can never resolve a target.** Its awk sets `tgt` only on `/^- \*\*IP\*\*:/` (`:809`), but the vulnerability block emits `- **Target IP**:` (`ares-core/templates/redteam/reports/comprehensive_report.md.tera:187`); the only `- **IP**:` line (`:87`) is under a `###` host heading. `/^#### /` resets `tgt="unknown"` at the top of every vuln block (`:808`). So a `BEFORE=reports/red` comparison reports every pair as `<technique>:unknown`, inflating "AFTER-only pairs (novel)" and zeroing "Overlap". Technique set-diff and the top-20 table are still valid. Both sides agree on *what* counts — markdown takes `EXPLOITED` only (`:810`), matching `record_step`'s primary-only semantics.

**`RESET=true` is global, not per-campaign.** `redis-cli --scan --pattern "ares:novelty:*:steps" | xargs -r redis-cli del` (`:643-646`) wipes every scope, including other campaigns'. Separately, `task ec2:launch` defaults `FLUSH_REDIS=true` → `redis-cli FLUSHDB` (`.taskfiles/ec2/Taskfile.yaml:1089,1256-1257`), so the normal launch path destroys the cross-run memory a sweep depends on. `task k8s:reset` does NOT: it deletes `ares:op:*`, `ares:tool_exec:*`, `ares:lock:*`, `ares:tasks:*`, `ares:results:*`, `ares:operation:*:state`, `ares:operation:*:checkpoint_time`, `ares:operations:*:status`, plus the fixed keys `ares:operations` and `ares:operation:active` (`.taskfiles/k8s/Taskfile.yaml:155-172`) — `ares:novelty:*` matches none of them. It *does* clear `ares:lock:*`, which is the fastest way to shed the stale locks in item 5.

**A cheaper coverage source the sweep ignores.** `record_step` also SADDs the canonical step key into `ares:op:<op>:coverage`, a deduped SET (`diversity.rs:66-68,182-185`). The sweep only LRANGEs the ordered LIST (`:746`) and rebuilds uniqueness in awk; the LIST has no membership check, so repeated `mark_exploited` calls duplicate rows while `coverage` stays clean.

## Eval, scoring, gap analysis

`overall_score` is a weighted mean (`ares-core/src/eval/scorers/scoring.rs:466-493`):

| Dimension | Weight |
|---|---|
| IOC detection | 3.5 / 17.5% |
| Technique coverage | 3.5 / 17.5% |
| Pyramid elevation | 3.0 / 15% |
| Evidence quality | 3.0 / 15% |
| Phase coverage | 3.5 / 17.5% |
| Timeline accuracy | 3.5 / 17.5% — **dropped, weights renormalized, when `expected_timeline` is empty** |

The timeline drop is deliberate: `score_timeline_accuracy` returns a vacuous 1.0 with no ground-truth timeline, which would inflate overall by its full weight. Consequence: **two snapshots of the same op with and without a recorded timeline are not score-comparable.** Only `benchmark capture` populates `expected_timeline` (from `ares:op:<op>:timeline`); `create_ground_truth_from_red_state` hardcodes it empty, so live and `ops evaluate` runs never score it.

`grade()`: A ≥ 0.9, B ≥ 0.8, C ≥ 0.7, D ≥ 0.6, else F. `passed()`: overall ≥ 0.6 **and** ioc ≥ 0.5 **and** technique ≥ 0.6 — so a D-grade run can still be `passed: false` (`ares-core/src/eval/results.rs:131-149`).

`gap_analysis` in the result JSON is markdown from `analyze_detection_gaps(&eval_result)` (`replay.rs:16,619,652`) — it walks `missed_iocs` / `missed_techniques` and emits per-item recommendations.

**Reading a score by hand** (works around the `generalize` bug):

```bash
jq -r '[.run_id, .trigger_mode, .evaluation.status.grade,
        (.evaluation.scores.overall*100|tostring+"%")] | @tsv' reports/inv-*.json
# K>1 aggregate instead:
jq -r '{mean, stddev, min, max, replicate_count}' reports/inv-*-summary.json
```

**`generalize`'s glob is fragile.** `ls -1t "$OP_OUT_DIR"/inv-*.json | head -1` (`:461`) also matches the K-replicate aggregate `inv-<ts>-summary.json`, which has no `.evaluation` key at all (its score is top-level `mean`) and is written last. Latent only because `generalize` never forwards `SEED`/`TEMPERATURE`/`REPLICATES` — its `benchmark:replay` call passes only OP_ID / OUTPUT_DIR / SNAPSHOT_DIR / MODEL / MAX_STEPS / CLOCK / REPLAY_MODE / TRIGGER_MODE / QUIET_PERIOD (`:450-459`). Held-out runs are therefore always 1 replicate at provider-default temperature — the generalization number carries the full sampling noise.

**`FAIL_UNDER` cannot gate at exactly zero** — both `"0"` and `"0.0"` disable it (`:541`) — and it shells out to `bc -l` (`:533`) and `awk` (`:546`), neither preconditioned.

**`ares ops evaluate` is a ground-truth/gap generator, not a measurement.** It scores an empty `InvestigationSnapshot::default()` (`ares-core/src/eval/workflow/runner.rs:94-98`), so its grade is always the zero baseline. With `--save` it writes `eval_{eval_id}_{op_id}.json` and `gap_analysis_{eval_id}_{op_id}.md` into `--output-dir` (default `./eval_results`; `ares-cli/src/cli/ops.rs:395-411`, `runner.rs:135-153`).

**The tuning/eval firewall is a comment, not enforcement.** `.taskfiles/benchmark/Taskfile.yaml:13-21` and `benchmarks/holdout.yaml` name `benchmark:generalize` as the only legitimate consumer of the held-out set; nothing stops a tuning driver from reading the file.

## On-disk layout: `reports/` and `logs/`

Both are gitignored (`.gitignore:9-11`). `benchmarks/*` is too, except `replay-stack/` and `holdout.yaml` (`:50-53`).

```
reports/                      # root Taskfile.yaml:113 REPORT_DIR
  red/<op_id>.md              red comprehensive report; ops/report.rs:79 appends red/ itself
  blue/<op_id>.md             operation-scoped blue report — the ONLY one with the red-vs-blue scorecard
  blue/investigations/<inv_id>.md   per-investigation report, no coverage section
  blue/<op_id>/<inv_id>.md    investigation nested under its op (when op_id is supplied)
  blue/<op_id>_detection_playbook.json  task blue:playbook (JSON only, under blue/ since 2026-08-08;
                                        the .md is written only where the CLI runs, via --output-dir)
  diversity/<CAMPAIGN>/
    coverage.csv              header: op_id,step_index,technique,target
    ops.txt                   one op- per completed op, or "op-… FAILED submit" / "op-… FAILED <status>"
    red/<op_id>.md            per-op red report fetched by ec2:report
  generalize/
    generalize-summary.json   {holdout_file, generated_at, total_ops, scored_ops, mean_score, median_score, per_op[]}
    <op_id>/replay.log        ALL stdout+stderr of the nested benchmark:replay
    <op_id>/inv-<ts>.json     BenchmarkResult
  inv-<ts>.json               replay / replay:run default OUTPUT_DIR=./reports
  inv-<ts>-r0.json … -r<K-1>.json + inv-<ts>-summary.json   when REPLICATES=K>1
eval_results/                 ares ops evaluate --save
logs/                         # root Taskfile.yaml:114 LOG_DIR
  red-ec2-<op_id>-<ts>.log    side effect of red:ec2:multi, NOT in the campaign dir
  red-multi-<op_id>-<ts>.log
  blue-<ts>.log               task blue:once (`.taskfiles/blue/Taskfile.yaml:68`, LOGFILE at :81). There is no blue:poll:local; the polling task is blue:poll (:49) and it writes no logfile
recordings/                   # NOT gitignored. Leftover from red:multi:replay:copy, removed 2026-08-08;
                              # always empty — nothing ever wrote the recordings it copied
/var/log/ares/session/<op_id>/<run_id>.jsonl    blue transcripts, team=blue
```

Writers: `.taskfiles/benchmark/Taskfile.yaml:573-578,682,706,713,755` (sweep), `:424,442-443,507-518` (generalize); `replay.rs:655,715`; `ares-cli/src/ops/report.rs:78-85`; `ares-cli/src/blue/report.rs:126-156`; `.taskfiles/ec2/Taskfile.yaml:916` (the `red/` prefix on fetch); `.taskfiles/red/Taskfile.yaml:49,813`; `.taskfiles/blue/Taskfile.yaml:81,237-238,286`.

**`ares ops report` serves the CACHE unless you pass `--regenerate`.** The orchestrator caches the rendered markdown at `ares:op:<op>:report` on completion, TTL `OP_RETENTION_TTL_SECS` = 86400 (`ops/report.rs:20-27,66-73`; `ares-core/src/state/keys.rs:19`). A report fetched hours later silently omits any later state writes.

**Silent template downgrade.** `generate_comprehensive(...).or_else(|_| generate_summary(...))` (`ops/report.rs:60-61`) — a Tera error yields a shorter report with different sections and no error message. Missing Hashes/Trust-Key sections means the comprehensive render failed, not "no data".

**`generalize` swallows all per-op output into `<op_dir>/replay.log`** (`:450-460`). A run that provisions, investigates for up to 45 min and tears down prints nothing between one "replaying <op>" line and the next.

## Environment variables

| Var | Read by | Default | Note |
|---|---|---|---|
| `BENCHMARK_SECURITY_GROUP_ID` | Taskfile `:83`, precondition | — REQUIRED | SG must open 3000/3100/9090/3200 to the investigator |
| `BENCHMARK_INSTANCE_PROFILE` | Taskfile `:84`, precondition | — REQUIRED | IAM role needs S3 read on the snapshot bucket |
| `BENCHMARK_SUBNET_ID` | Taskfile `:85`, precondition | — REQUIRED | must be reachable from wherever `benchmark run` executes |
| `BENCHMARK_S3_BUCKET` | Taskfile `:87`; `capture.rs`; `snapshot_s3.rs` | `ares-benchmark-us-west-1` | same literal in all three |
| `BENCHMARK_INSTANCE_TYPE` | Taskfile `:81` | `t3.medium` | hosts 6 containers |
| `BENCHMARK_REQUIRE_BAKED_AMI` | Taskfile `:90,278` | `0` | `1` = fail instead of stock-AL2023 fallback |
| `BENCHMARK_AMI_ID` | Taskfile `:268` (raw `${...:-}`) | unset | pins an AMI, bypassing tag lookup AND fallback |
| `BENCHMARK_SKIP_STACK_VERIFY` | Taskfile `:357` (raw) | `0` | `1` = skip the three health probes |
| `BENCHMARK_AWS_PROFILE` / `BENCHMARK_AWS_REGION` | **Rust only** — `snapshot_s3.rs:18-42`, `capture.rs:35-38` | capture `lab`/`us-west-1`; read path `""`/`us-west-1` | **never read by the Taskfile**, though `docs/benchmark-replay.md:37` lists the region as a Taskfile prerequisite |
| `LOKI_S3_BUCKET` / `_REGION` / `_PROFILE` | `capture.rs:52-61` | `dev-argonaut-loki` / `us-west-2` / `infrastructure` | different account AND region from the benchmark bucket; absent from `.env.example` |
| `ARES_SELECTION_TEMPERATURE` / `ARES_NOVELTY_ENABLED` / `ARES_EMIT_PATH_RECORDS` | `strategy.rs:223,244,247` | from YAML | the only diversity env overrides that exist |
| `ARES_REPLAY_CLOCK_MODE` / `_START` / `_END` / `ARES_REPLAY_MAX_STEPS` | `replay_clock.rs` | set by `benchmark run` | unrecognised MODE ⇒ Frozen ⇒ no clamp |

**Region split — this one costs an hour.** The benchmark Taskfile defaults `AWS_REGION` to `us-west-1` and honours `env AWS_REGION` then `AWS_DEFAULT_REGION` (`:80`). The **root** Taskfile defaults it to `us-east-1` and honours only `env AWS_DEFAULT_REGION` (`Taskfile.yaml:137`; `TARGET_REGION` likewise at `:126`). The include block forwards **only `ARES_CLI` and `AWS_PROFILE`** (`Taskfile.yaml:28-33`). So `AWS_REGION=us-west-1 task benchmark:diversity-sweep` SSMs a `us-west-1` box while the nested `task red:ec2:multi` resolves its box *and its targets* in `us-east-1`. Export `AWS_DEFAULT_REGION` too.

**`EC2_NAME` resolution.** Root forwards `EC2_NAME` into the red namespace (`Taskfile.yaml:57`), but the include's own task-level default wins — `.taskfiles/red/Taskfile.yaml:780` resolves `kali-ares`. Root-Taskfile defaults do **not** shadow an include's `vars:` block; see `references/config-and-env.md` for the empirical check. The sweep pins it explicitly anyway (`.taskfiles/benchmark/Taskfile.yaml:557`, passed at `:679`).

## Redis keys

| Key | Type | Written by | Lifecycle |
|---|---|---|---|
| `ares:op:<op>:path_record` | LIST (RPUSH) | `record_step` when `emit_path_records` | no explicit TTL in `diversity.rs`; swept by the 86400s op-retention pass. Read by the sweep via `redis-cli --no-raw LRANGE` (`:746`) |
| `ares:op:<op>:coverage` | SET of `technique:target` | same call site | same; **never read by the sweep** |
| `ares:novelty:<scope>:steps` | SET of `technique:target` | `record_step` when `novelty_enabled` | **no TTL, and does NOT match `ares:op:*`** — survives `k8s:reset` and op retention indefinitely |
| `ares:op:<op>:exploited` | SET of vuln_id | `mark_exploited` (`state/dedup.rs:78-86`) | includes superseded ids; 86400s TTL |
| `ares:op:<op>:superseded` | SET of vuln_id | same call site (`dedup.rs:70-89`) | subset of `:exploited` whose technique was never proven. Explains `exploited` > `path_record`; drives the report's `SUPERSEDED` status (`reports/context.rs:291-292,315-321`). 86400s TTL, only set when non-empty (`:87-89`) |
| `ares:op:<op>:vuln_queue` | ZSET, score = strategy-effective priority (no time term) | vuln publish | the softmax input; 86400s TTL refreshed on publish |
| `ares:lock:<op>` | STRING, TTL 300s (`ARES_LOCK_TTL_SECS`) | orchestrator | its existence is the entire basis of `Status: running` |
| `ares:operation:active` | STRING | every `red:ec2:multi` submit (`.taskfiles/red/Taskfile.yaml:863`) | why sweep ops must not overlap |
| `ares:op:<op>:report` | STRING (markdown) | `generate_and_cache_report` | 86400s; served by `ops report` unless `--regenerate` |
| `ares:blue:inv:<run_id>:status` | STRING (JSON) | blue consumer | polled every 10s by `benchmark run`; `completed`/`escalated` break, `failed` bails |
| `ares:blue:inv:<run_id>:env_vars` | STRING (JSON) | `replay.rs:540-543` | per-investigation env handoff, 3600s TTL |
| `ares:op:<op>:timeline` | LIST | red runtime | empty ⇒ timeline dimension dropped from the score |

`diversity.rs:50-68`; `ares-core/src/state/keys.rs:4,7,19,40,44`.

```bash
task ec2:exec EC2_NAME=kali-ares CMD='redis-cli SCARD ares:novelty:per-campaign:steps'
task ec2:exec EC2_NAME=kali-ares CMD='redis-cli --scan --pattern "ares:novelty:*:steps"'
task ec2:exec EC2_NAME=kali-ares CMD='redis-cli --no-raw LRANGE ares:op:'"$OP"':path_record 0 -1'
task ec2:exec EC2_NAME=kali-ares CMD='redis-cli SMEMBERS ares:op:'"$OP"':coverage'
task ec2:exec EC2_NAME=kali-ares CMD='redis-cli ZRANGE ares:op:'"$OP"':vuln_queue 0 -1 WITHSCORES'
```

`redis-cli type <key>` before guessing a verb: a wrong verb gives a loud `WRONGTYPE`, a wrong key name gives a silent `0`.

## Stale sources — do not quote these

| Source | Stale claim | Reality |
|---|---|---|
| `docs/benchmark-replay.md:46,53,391,393`; `README.md:420,443`; root `Taskfile.yaml:182,205,207`; `docs/exercise-replay.md:140`; `.taskfiles/ec2/Taskfile.yaml:1375` (comment only — the command below it is correct) | `--wait-for-flush` | flag does not exist (exit 2). It is `--no-wait-for-flush`; waiting is the default (`cli/benchmark.rs:40-45`) |
| `docs/benchmark-replay.md:97` | `TIME_COMPRESSION=10` | not a task var, not a CLI flag; `BenchmarkResult.time_compression` is hardcoded `None` (`replay.rs:649`) |
| `docs/benchmark-replay.md:58` | `task ec2:wait … CAPTURE=true` | no such task. It is `ec2:watch` (`.taskfiles/ec2/Taskfile.yaml:985`), which has no `CAPTURE` var. `CAPTURE` belongs to root `task run` (`Taskfile.yaml:165`) and to `ec2:launch` (`.taskfiles/ec2/Taskfile.yaml:1103`) — **only the `ec2:launch` path works**: its capture call omits `--wait-for-flush` (`:1388-1391`), while root `task run` still passes it (`Taskfile.yaml:205`) and exits 2 |
| `docs/benchmark-replay.md:255` | runner calls `set_step(step)` | runner calls `advance_step()` (`ares-llm/src/agent_loop/runner.rs:318`); `set_step` is documented test-only |
| `docs/benchmark-replay.md:306` | `evaluation.overall_score` | real path is `.evaluation.scores.overall` |
| `docs/benchmark-replay.md:37` | `BENCHMARK_AWS_REGION` is a Taskfile prerequisite | the Taskfile reads `AWS_REGION`/`AWS_DEFAULT_REGION`; `BENCHMARK_AWS_*` is Rust-only |
| `docs/attack-path-diversity.md:12,98` | knobs "off by default" | all four ship on (`config/ares.yaml:104-116`) |
| `.claude/skills/attack-path-diversity-sweep/SKILL.md:3,24,35` | "SHIPS DISABLED" / "All four default to off" / "Uncomment" | ships enabled; a test fails if you disable them |
| `.claude/skills/attack-path-diversity-sweep/SKILL.md:62` | `CAMPAIGN` "Also becomes the novelty-memory scope" | scope is the literal config string; all runs share `ares:novelty:per-campaign:steps` |
| `.taskfiles/benchmark/Taskfile.yaml:600` | "Uncomment the diversity knobs in config/ares.yaml" | already uncommented |
| `docs/exercise-replay.md` | `ares exercise` verb, manifest v2, six replay modes, cosign/OCI distribution | design doc only. No `Exercise` variant in `ares-cli/src/cli/mod.rs`; `MANIFEST_VERSION = 1` (`manifest.rs:10`); `versions.rs` is 11 lines holding one pinned image constant, not a schema loader |
| `docs/exercise-replay.md:150,151` | Tempo capture/replay ❌ BLOCKING | both shipped — `capture.rs` `tempo_traces_captured`, `benchmark/tempo_push.rs` |
| `docs/exercise-replay.md:6-7,271` | links `benchmark-replay-strategy.md`, `benchmark-replay-timeline-spec.md`, `docs/exercise-compatibility.md` | none of the three exist |

Two things the `ares-debug` skill already gets right — do not "correct" them: `SKILL.md:110-123` carries the verified key/TYPE table (`:credentials` HASH, `:hosts` / `:users` LIST — matches `ares-core/src/state/keys.rs:23,27,29`), and `:396-398` correctly distinguishes `ec2:restart` (never touches `ares@*.service`) from `ec2:deploy` (restarts only units already `--state=active`).
