---
name: ares
description: Operating, debugging, deploying and reasoning about the Ares autonomous red/blue AD attack platform in this repo. Use for launching or stopping red ops (task red:ec2:multi, ec2:launch, red:multi) and blue investigations, reading loot/reports/scorecards, deploying or gating a binary on EC2 kali-ares / k8s attack-simulation / the proxmox attacker VM, inspecting Redis op state and key types, LogQL/Loki, Tempo/OTEL and Grafana-MCP queries against ares, config/ares.yaml or ARES_* env questions, per-role model assignment, benchmark/replay/diversity-sweep/eval work, the tool catalog and tool-failure strings, CI gates and pre-commit hooks, and the banned-lab-token test-data rule. Also use whenever a claim about ares needs verifying before it is stated — the reference set here carries file:line citations and the mistakes this assistant has repeatedly made on this repo.
---

# Ares

Router + non-negotiables. The detail lives in `references/`; every claim there is cited to `file:line` at HEAD.

## Before you touch anything

Sourced from `references/hard-won-lessons.md` — 30 rules mined from 209 sessions where the operator had to correct this assistant. **Read that file first.** Each rule below names the check that satisfies it.

- **Test data is a closed set.** Only `contoso.local` / `fabrikam.local`, `192.168.58.x`, `dc01`/`dc02`/`sql01`/`web01`/`ws01`/`ca01`, `alice`/`bob`/`carol`/`admin`/`svc_*`, `P@ssw0rd!`. Gate with `scripts/goad-token-sweep.sh` — never by eyeballing, and **never** by widening the Write hook's bypass `case` list. The three enforcers, their divergences and their coverage holes are tabulated once, in `references/tools-and-gates.md#the-banned-token-sweep`; do not restate them elsewhere.
  - **This skill directory is unswept by both automated layers.** `scripts/goad-token-sweep.sh:36` exempts all of `.claude/`, and its whole-tree mode enumerates `git ls-files` (`:41-47`) — `.claude/skills/ares/**` is untracked at HEAD (`git ls-files .claude` lists only the three agents and the `ares-debug` / `attack-path-diversity-sweep` skills). Only the PreToolUse Write/Edit hook covers it, so a file arriving here by `cp`/`mv`/`rsync` is never scanned. Passing the paths to the script explicitly does **not** help — its exempt filter runs on `"$@"` too (`:52`), so it exits 0 vacuously. Borrow the regex:

    ```bash
    bash -c 'eval "$(sed -n "23,29p" scripts/goad-token-sweep.sh)"; grep -rHniE "$banned" .claude/skills/ares/'
    ```

  - That hook is itself **operator-local and untracked** — `.gitignore:31-35` ignores `.claude/*` and un-ignores only `agents/` and `skills/**`. It is wired at `.claude/settings.json:10` as a bare command path, which requires the exec bit; at HEAD the file is mode 644. Verify before relying on it: `test -x .claude/hooks/check-banned-strings.sh`.
- **Pin the EC2 box to an explicit instance id + region before the first remote command, and pin it twice.** `AWS_REGION` alone selects staging (`us-west-1`, profile `lab`) vs prod (`us-east-1`); `EC2_NAME=kali-ares` is a `*kali-ares*` glob that matches in both. Default to staging; touch prod only when the user says "prod" in that message. `task ec2:launch` runs `redis-cli FLUSHDB` on whatever it resolves.

  ```bash
  AWS_PROFILE=lab AWS_REGION=us-west-1 task ec2:resolve EC2_NAME=kali-ares   # prints id+IP+Name for EVERY match
  ```

  SSM-backed tasks honour `EC2_INSTANCE_ID` (`run-ssm.sh:69-73`); CLI-backed ones (`ec2:runtime/loot/ops/watch/kill/stop-op/teardown`, `blue:*`) do not — pin those as `EC2_NAME=i-…` and pass `AWS_PROFILE=`/`AWS_REGION=` explicitly, because clap hard-defaults `lab`/`us-west-1` and ignores your exports. `ec2:report` is SSM-backed despite looking like the others (`.taskfiles/ec2/Taskfile.yaml:878-900`).
- **Never attribute an op result to your change until a literal NEW with that change is present in the deployed binary.** `task ec2:exec EC2_NAME=<pinned> CMD="grep -ac -- '<literal>' /usr/local/bin/ares"` must be ≥ 1. **Outer double quotes, inner single** — the inverted form dies with `CMD required` / exit 201 whenever the literal contains a space (`.taskfiles/ec2/Taskfile.yaml:1477-1479`; empirically verified in `references/operations.md`), and gate literals are normally log sentences. Pick the literal from a `contains("…")`, `format!`/`bail!`/`panic!` fragment, or `.arg("…")` — **never** `starts_with`/`ends_with`/`==`, which the `dev-deploy` profile folds out. A failed gate means your change did not ship; there is no other reading.
- **Progress is a state diff, not liveness.** Two Redis snapshots 60 s apart that show objective state advancing. Process up, workers `active`, Redis ping, ≥80% cache hit and climbing tokens are all compatible with a wedged op — token churn plus a high cache-hit rate is the *signature* of the wedge, not evidence of health.
- **Never run an interactive or blocking command from an agent.** Banned: `task ec2:logs` (interactive SSM session, never terminates), `task ec2:redis:forward` / `ec2:nats:forward` (foreground, and each `xargs kill`s whatever holds its local port), `task ec2:watch`, `task ec2:launch` (`WAIT` defaults `true`), `task red:multi` (`FOLLOW` defaults `true`), `red:multi:watch` without `ONCE=true`, `task remote:logs` (`FOLLOW` defaults `true`), `task run WAIT=true|CAPTURE=true`, `ec2:loot`/`red:multi:loot` with `DIFF=true` (promoted to a 10 s watch loop), `task blue:multi:operation-status WATCH=…` (no timeout), `task blue:reports:clean` (`read -p`, hangs under `task -y`), `ares ops delete` without `--force`. Use `ec2:logs:fetch`, `ec2:exec CMD='tail -n 200 …'`, `ec2:ops:ids`, `ec2:runtime` instead.
- **Never read an exit code through a pipe.** The Bash tool's zsh inherits `pipefail`, so a pipeline can invent or hide a failure: `cmd >/tmp/out 2>&1; echo "REAL_EXIT=$?"; rg -n 'pattern' /tmp/out`. A trailing `rg` in a compound call sets the call's exit code.
- **Base64-wrap any remote command containing a double quote, `$( )`, or a space-in-arg.** `{{.CMD}}` is spliced textually into `run_ssm_cmd`; `$( )` evaluates **locally**. `B64=$(printf '%s' '<script>' | base64 | tr -d '\n'); task ec2:exec EC2_NAME=<pinned> CMD="echo $B64 | base64 -d | bash"`. **Empty output from `ec2:exec` is a broken command, not a real negative**, and the `CMD required` / exit-201 message is a lie about emptiness.
- **Read each Redis key with the verb its TYPE demands.** Wrong verb → loud `WRONGTYPE`; wrong *key name* → a silent `0` that reads exactly like an empty op. There is no `:creds` key. Table below; full catalog in `references/state-and-redis.md`.
- **Zero grep hits prove nothing until the pattern is validated against a line you know exists.** `/var/log/ares/*.log` is ANSI-painted, so any `field=value` anchor matches nothing; `grep -a` is mandatory, strip escapes with `s/\x1b\[[0-9;]*[a-zA-Z]//g`, scope to the bare op id (not `op.id=`) plus a timestamp window, and include the rotated/`zgrep` sibling.
- **Generated text is not evidence.** An LLM task summary, a timeline `Assistance needed:` string, or a subagent's conclusion is confabulation until resolved against raw tool output (`ares ops sessions replay <op> <task>`), Redis, or the box. The code agrees: agent assertions live in a separate `llm_findings` field, never authoritative state.
- **Treat `/Users/l/dreadnode/ares` as a checkout other sessions are mutating.** Re-read `git -C /Users/l/dreadnode/ares branch --show-current && git status --porcelain` after every pause; work in your own worktree; stage explicit paths; never `rebase`/`pull`/`stash`/`restore`/`reset --hard`/force-push there.
- **Score a dreadgoad op on `Domains (n/3 compromised, n/2 forests)` plus the per-domain tree line** — a domain counts only with `DA` + a `krbtgt: <types>` detail + a matching `dc_secretsdump_<domain>` EXPLOITED row. Neither `ops runtime` nor `ops loot` subtracts supersede credits; only `ops report` does.
- **Never cheat the benchmark.** No potfile/`--show` recovery, no operator-known wordlists, no `redis-cli hset` into `ares:op:*`. If you hand-patched state, say so in the same breath and re-run clean. Disclose the seeded `initial_credential` whenever you quote a result.
- **Resolve AWS auth yourself** — never tell the user to run `aws sso login` or `assume`; for profile `lab` it *fails*. `unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN; AWS_PROFILE=lab AWS_REGION=us-west-1 command aws sts get-caller-identity`.
- **Do not stall the turn.** You have SSM reach into the box; "I'd need the op logs" is never a reason to hand back after the user said "fix it".

### Before you say it works — the evidence contract

| Claim | Evidence that settles it |
|---|---|
| The change shipped | `Build SHA`/`Deploy SHA` from *this* run + `GATE_STRING` found in `/usr/local/bin/ares`; binary mtime newer than the commit; the op started **after** the deploy finished |
| Workers run the new code | deploy's restart block printed `restarting: ares@…`, not `no ares@ worker units active — skipping restart`; then `task ec2:status` |
| The op is healthy | `task ec2:runtime … OPERATION_ID=op-…` read in full + two state snapshots 60 s apart showing advance |
| The op terminated | `Status: completed` **and** runtime/tokens/cost stopped climbing. `Completion condition met` only freezes red dispatch and opens a drain window (300 s red, up to 3300 s blue) |
| The bug is fixed | the originally-failing operation re-run against the deployed binary. `cargo test`, clippy, `--help` and green CI are never verification. State-shape or report changes need a **fresh live op** — `ops report --regenerate` cannot surface a key that did not exist when that state was written |
| A detection fires | the composed LogQL from the tool result replayed against live Loki stage by stage, with `ARES_DEPLOYMENT` confirmed equal to the shipper's `deployment` label; `ares blue evidence <inv-id> --json` for provenance |
| Any number | which counter, from which command, for which op id — and whether supersede credits were subtracted |

Absence of a warning log is never a success verdict. If the path only logs on failure, add the success-side log.

## Route the ask

| Ask | Go to |
|---|---|
| The mistakes we keep making here; is my claim already known-false | `references/hard-won-lessons.md` — **read first**, includes a "rules that expired" list |
| Crate boundaries, the (non-)tick, roles→toolsets, dispatch paths, one task end to end, completion/freeze | `references/architecture.md` |
| Launch / loot / report / stop / inject; the `ares ops` tree; `LATEST=true`; "I changed code, now prove it"; **poll for DA/krbtgt without blocking the turn**; which read commands are k8s-only | `references/operations.md` |
| Build + ship to EC2 / k8s / proxmox / local; `BUILD_TOOL`; systemd units; post-deploy worker bounce | `references/deployment.md` |
| Redis key catalog, TYPEs, meta/completion fields, timeline shapes, queues, dedup, locks, snapshot recipes | `references/state-and-redis.md` |
| Loki labels + working LogQL, Tempo/OTEL spans and the env var that silences export, Grafana MCP; **why LLM/tool latency is unrecoverable with OTLP off** | `references/observability.md` |
| Detection catalog, deterministic sweep, investigation lifecycle + lock keys, technique-ID join, scorecards | `references/blue-team.md` |
| `benchmark:` tasks, replay record/playback, eval/scoring, `reports/` + `logs/` layout, real-vs-vacuous sweeps; **building a denominator for "never exploited"** | `references/benchmarks-and-replay.md` |
| `config/ares.yaml` block by block, per-role models **and how to prove one activated**, the `ARES_*` env table, secrets, precedence | `references/config-and-env.md` |
| Which binary a tool spawns, timeout/kill semantics, failure strings, CI gates + pre-commit hooks, **the full add-a-tool gate list**, the banned-token rule (authoritative) | `references/tools-and-gates.md` |
| **A live op is stuck / slow / crashing / a worker crash-loops** | skill `ares-debug` — it owns wedge signatures and the Step 0..9 probe ladder. **Do not re-derive them here** |
| Run a diversity sweep end to end (knobs on, `benchmark:diversity-sweep`, read `coverage.csv`, iterate temperature) | skill `attack-path-diversity-sweep` for the workflow; knob truth below |
| Execute a multi-step ares workflow (≥3 dependent commands: launch → monitor → deploy → inject → report) | agent `ares-operator`. **One-shot commands run inline** — never dispatch an agent for a single `task ec2:runtime` |
| Trace a code path through the crates, a build error, "where is X implemented" | agent `rust-ares-expert` |
| Target-lab questions (accounts, ACL chains, ADCS templates, trusts, "what does this credential unlock") | agent `dreadgoad-expert` **fails on every call** via model-level safeguards. Read the DreadGOAD docs and `docs/goad-checklist.md` directly; never reword a prompt to evade a refusal |

### `ares-debug` is stale on two facts — do not copy them forward

Its Redis key/TYPE table (`SKILL.md:110-123`) and its deploy/restart section (`:396-405`) are **correct** — do not "fix" them. The two that are stale:

| Its claim | Truth at HEAD |
|---|---|
| `SKILL.md:285` — the worker's `unavailable_tools` is a per-process `HashSet<String>`, "no TTL, no re-probe", entries "persist across every subsequent op the same worker handles" | It is a `HashMap<String, UnavailableEntry>` with exponential re-probe backoff 60 s → 300 s → 1800 s → 4 h, final rung a cap (`ares-cli/src/worker/tool_executor.rs:351-372`), and **one successful spawn removes the entry outright** (`:592-601`). Only typed `BinaryNotFound` poisons it. Detail: `references/tools-and-gates.md` |
| `SKILL.md:49`, `:269`, `:274` grep `Tool binary not found (spawn failed)` | That string has **zero hits in `ares-*/src` at HEAD** — the grep reports "no cascade" during a live cascade. Current strings: `Tool binary not found (ENOENT from worker) — removing from available tools for the rest of this task` (`ares-llm/src/agent_loop/runner.rs:608`), `Tool binary not found (ENOENT) — backing off before next re-probe` (`ares-cli/src/worker/tool_executor.rs:677`), `Skipping tool cached as ENOENT` (`:532`) |

Both are worked examples of the same rule: every claim needs a `file:line`.

**Diversity knobs ship ON, not off.** `config/ares.yaml:104-116` sets `selection_temperature: 0.7`, `novelty.enabled: true` / `scope: per-campaign`, `randomize_entry_foothold: true`, `emit_path_records: true` (turned on by `72a40f02`). The comment block at `:97` claiming they "default to today's deterministic behaviour", and the sweep skill's Step 1 "All four default to off", are both stale. **Precedence is not the generic env > JSON > YAML** for these four: `strategy.rs:236-243` assigns `novelty.enabled`, `novelty.scope`, `randomize_entry_foothold` and `emit_path_records` from YAML unconditionally, clobbering any JSON payload; only `selection_temperature` (`:223`), `novelty.enabled` (`:244`) and `emit_path_records` (`:247`) have env overrides. `randomize_entry_foothold` and `novelty.scope` are YAML-only. See `references/config-and-env.md`.

## 60-second orientation

One binary, `ares`, built from a four-crate workspace: `ares-core` (models, Redis key names, NATS subjects, YAML config, detection catalog, report renderers), `ares-tools` (one wrapper module per role + `executor.rs` + the parsers that are the only authoritative discovery source), `ares-llm` (tool registry schemas, Tera prompts, providers, agent loop), `ares-cli` (**orchestrator and worker are modules inside it** — never `ares-orchestrator/`). The orchestrator is one process running ~72 independent tokio loops (62 `auto_*` automations plus ten infra loops) — **there is no orchestrator tick**; find the loop by its log line. The LLM agent loop runs *in-process inside the orchestrator*, so every "the agent decided X" line is in `orchestrator.log`; workers only execute individual tool calls off NATS `ares.tools.exec.{role}`. Seven roles (`recon`, `credential_access`, `cracker`, `acl`, `privesc`, `lateral`, `coercion`), each with a code-defined toolset — the `agents.<role>.tools` YAML list is decorative. Three dispatch paths: automation→LLM, automation→**direct tool** (25 call sites that never touch an LLM), and the generic vuln queue. Redis is the sole authority for state; logs and traces are derived. Blue runs inside the same orchestrator process when `ARES_BLUE_ENABLED=1` and is scored as a MITRE-ID join against red's own record.

Establish where things stand:

```bash
git -C /Users/l/dreadnode/ares branch --show-current && git -C /Users/l/dreadnode/ares status --porcelain
AWS_PROFILE=lab AWS_REGION=us-west-1 task ec2:resolve EC2_NAME=kali-ares      # pin the box FIRST
task ec2:ops:ids EC2_NAME=<pinned>                                           # STARTED_AT | STATUS | OP_ID; no local binary needed
task ec2:runtime EC2_NAME=<pinned> OPERATION_ID=op-…                         # domains, split vuln counters, tokens
task ec2:status  EC2_NAME=<pinned>                                           # 7 ares@ units, redis, nats, disk, hashcat
task ec2:exec    EC2_NAME=<pinned> CMD='redis-cli hmget "ares:op:<id>:meta" has_domain_admin has_golden_ticket red_completed_at red_completion_reason red_blocked_on_blue'
```

`task ec2:report`, `ec2:ops:ids`, `ec2:status` and `ec2:exec` need no local binary. The other `ec2:*` CLI tasks gate on `./target/release/ares` (`.taskfiles/ec2/Taskfile.yaml:587`); `BUILD_TOOL=remote`, the deploy default, never produces it — build it with `cargo build --release -p ares-cli`, or route around it with `task ec2:exec EC2_NAME=<pinned> CMD='ares ops loot --latest --json'` (the box's own binary against the box's own Redis).

Healthy: DA lands at a median 4.1 min, p90 8.8; total duration median 18.8 min. No DA by ~15 min is outside the whole observed distribution — escalate to `ares-debug`. **Those numbers were measured 2026-07-30 over n=47 DA ops in the local, gitignored `reports/red/` corpus** (`.gitignore:10`) — they are not reproducible from a clean clone and drift with every op. Re-derive before quoting; the recipe is in `references/operations.md`.

### Fresh clone, first five minutes

```bash
cargo build --release -p ares-cli                 # the CLI-backed ec2:* tasks need this; no task builds it
set -a; . ./.env; set +a                          # S3_BUCKET (.env.example:33); `task setup-env` is `cp -n` (Taskfile.yaml:238) — never overwrites, never says it skipped
AWS_PROFILE=lab AWS_REGION=us-west-1 task ec2:resolve EC2_NAME=kali-ares   # pin the box
```

Skip step 1 only if you stay on `ec2:exec` / `ec2:ops:ids` / `ec2:status` / `ec2:report`. `.env.example` is incomplete (`OTEL_TRACES_ENDPOINT`, `ALLOY_LOKI_ENDPOINT` are missing) — see `references/config-and-env.md`.

## Repo map

| Path | Holds |
|---|---|
| `ares-core/` | models, `state/keys.rs`, `nats.rs`, config deserialization, telemetry, detection catalog, eval + report renderers |
| `ares-tools/` | per-role tool wrappers, `executor.rs`, `parsers/`, `scope.rs`, `mutation.rs`, `sanitize.rs`, `blue/` detection + Loki client |
| `ares-llm/` | `tool_registry/` (JSON schemas per role), `prompt/` (embedded Tera), `provider/`, `agent_loop/`, `routing/`. Library only |
| `ares-cli/` | the `ares` binary: `orchestrator/` (automations, dispatcher, result processing, completion, blue), `worker/`, `ops/`, `blue/`, `benchmark/`, `transport.rs` |
| `config/ares.yaml` | the only per-role model lever; `operation.*`, timeouts, vulnerability priorities, diversity knobs. Much of the rest is parsed and never read |
| `tools.yaml` | build-time manifest of expected binaries per role (read by `build.rs`, `panic!`s on malformed) |
| `.taskfiles/{ec2,red,blue,k8s,remote,benchmark,obs,proxmox}/` | every `task` namespace. A dot-directory — `rg`/`fd` need `--hidden` |
| `scripts/` | `goad-token-sweep.sh` (banned-token gate), `env-from-secrets.sh` (regenerates `.env`, truncating) |
| `ansible/` | box provisioning, `ares@.service.j2` unit template, vector/Loki shipper config |
| `docs/` | `red.md`, `blue.md`, `strategy.md`, `infrastructure.md`, `attack-path-diversity.md`, `benchmark-replay.md`, `goad-checklist.md` (the lab spec). Several are stale — verify against HEAD |
| `reports/` (gitignored) | `red/<op>.md`, `blue/<op>.md` (the only file with the red-vs-blue scorecard), `blue/investigations/`, `diversity/<campaign>/coverage.csv`, `generalize/` |
| `logs/` (gitignored) | `red-ec2-<op>-<ts>.log`, `red-multi-…`, `blue-<ts>.log` — launcher-side transcripts, not the box's `/var/log/ares/` |
| `GAPS.md` | **untracked**, operator-local. Holds the `### Claimed work` table (only a `Verified: op` marker closes a row) |
| `task ec2:e2e` | The deploy→gate→launch→watch harness (`.taskfiles/ec2/scripts/e2e-op.sh`; was the untracked `testes.sh` until 2026-08-08). Read it before diagnosing an op, and fix it rather than hand-rolling its sequence |
