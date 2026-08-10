---
name: ares-debug
description: Diagnose a stuck, slow, or broken Ares operation by triangulating across three data sources — SSM (live ares logs + Redis on EC2), Grafana Loki (historical logs via mcp__grafana__query_loki_logs), and OTEL traces in Tempo. Use when an operation is hung/wedged, a worker keeps crashing, the orchestrator stops making progress, or a task fails with no obvious local clue. Default deployment is EC2 (`kali-ares`); K8s notes included for completeness.
---

# Debugging Ares

You are debugging a running or recent Ares operation. Pick the cheapest source first; only escalate if it doesn't answer the question.

## Read this before you do anything

**Do not declare an op healthy from process liveness, NATS/Redis ping, or token-rate alone.** A wedged Ares op happily presents as `status=running`, workers `active`, Redis green, cache hit ≥80%, and tokens climbing — while making zero external progress for hours. This has happened. Don't repeat it.

**The only valid "healthy" verdict requires a comparison:**

1. Compare *this op's* objective state now vs. 60s ago — `has_domain_admin`, domain compromise count, hosts owned, creds, hashes, vulns exploited. If none changed, that's churn, not progress.
2. Compare this op to recent ops' baseline. Pull `ares ops list` and look at how long prior ops took to hit DA / 2nd domain. **If this op is more than ~2× slower to a milestone the last 3 ops hit, treat it as wedged regardless of token rate.**

Token churn is the signature of the LLM re-evaluating the same frozen state every tick; high cache-hit rate (>80%) on a slow op is a *symptom of the wedge*, not evidence of health.

**Worker per-role log mtimes are not a signal.** In steady state the orchestrator centralizes everything via NATS into `/var/log/ares/orchestrator.log`; per-role files (`recon.log`, `cracker.log`, etc.) stay near-empty. Don't read into stale mtimes.

## Before you propose a code fix

Ares timeline events (`evt-exploit-fail-*` in `ares:op:*:timeline`) and "Assistance needed" strings the LLM emits ("the tool schema does not accept X", "current toolset lacks Y", "tool requires password but only hash available") are the failing LLM agent's confabulated explanation of its own failure — **not a bug report**. The agent does not know its own tool schemas or the orchestrator's dispatch layer, and it will invent plausible-sounding gaps that don't exist.

Before recommending a fix from one:

1. Open the tool wrapper in `ares-tools/src/**/*.rs` — does the tool actually accept the arg the LLM said was missing?
2. Open the LLM-facing schema in `ares-llm/src/tool_registry/**/*.rs` — does it declare the field?
3. Open the automation dispatcher in `ares-cli/src/orchestrator/automation/*.rs` — does it inject the credential/state from Redis into the payload?

If all three already do the thing, the LLM was confabulating. The real failure is elsewhere — the tool ran and hit a Kerberos error, dispatch timed out, worker didn't have the credential in state, etc. Grep the orchestrator log for the actual dispatch record + tool stdout/stderr; those are ground truth. Timeline events are not.

## Tight-loop / wedge signatures (grep the orchestrator tail for these first)

Run Step 0, then **before drawing any conclusion** grep the tail of `orchestrator.log` for each pattern below. If any hit, that's almost certainly your wedge:

| Pattern (regex) | Means |
|---|---|
| `clearing dedup for retry` | Wrapper-level retry loop; same task being re-dispatched every tick |
| `Dispatching <same_tool> ... <same_target>` repeated ≥3× | Automation hot loop with no backoff |
| `KDC_ERR_TGT_REVOKED\|KDC_ERR_S_PRINCIPAL_UNKNOWN\|KDC_ERR_PREAUTH_FAILED\|TGT has been revoked` | Kerberos error that will not self-heal; orchestrator may be retrying anyway |
| `tool exited with code Some\(0\)` followed by stderr content | Zero-exit-with-error: wrapper treats stderr-on-zero-exit as transient and re-tries |
| Same `task_id` shape (e.g. `trust_raise_child_<hex>`) repeated with distinct hex per tick | Dedup key churning instead of blacklisting |
| `Processing real-time discoveries count=1` ticking every 5s with no other state change | Orchestrator stuck in discovery-replay loop |

If you don't see these but the op is slow vs. baseline, escalate to Loki / Tempo for cross-tick LLM latency or tool-call stalls.

## What goes where

| Source            | Latency  | Coverage                                        | How to query                                             |
|-------------------|----------|-------------------------------------------------|----------------------------------------------------------|
| `task ec2:status` (with `AWS_PROFILE=personal AWS_REGION=us-east-1`) | seconds  | Worker process state, Redis ping                | Bash                                                     |
| `task ec2:runtime` (same prefix)                                     | seconds  | Per-op token/cost/domain banner                 | Bash                                                     |
| Loki (Grafana)                                                       | seconds  | Historical `/var/log/ares/*.log` + syslog/auth  | `mcp__grafana__query_loki_logs` (datasourceUid `loki`)   |
| Tempo (Grafana)                                                      | seconds  | OTEL traces of LLM calls + tool dispatch        | `mcp__grafana__*` Tempo proxy tools                      |
| SSM `task ec2:exec` (same prefix)                                    | ~5-15s   | Anything on the host (redis-cli, journalctl)    | Bash, never `tail -f`                                    |
| `task ec2:logs`                                                      | streaming| Live tail of one role's log                     | **DO NOT use in Claude** — it's an interactive SSM session |

**Rule:** never run `task ec2:logs` from an agent — it opens an interactive SSM session that won't terminate. Always use Loki (preferred) or `task ec2:exec AWS_PROFILE=personal AWS_REGION=us-east-1 CMD='tail -n 200 /var/log/ares/<role>.log'`.

**AWS auth:** every `task ec2:*` command in this skill must run against the `personal` profile in `us-east-1`. The `lab` SSO profile is unreliable and the EC2 box lives in `us-east-1` under `personal`.

Either export once per shell:

```bash
export AWS_PROFILE=personal
export AWS_DEFAULT_REGION=us-east-1
export TARGET_PROFILE=personal
export TARGET_REGION=us-east-1
```

…or prefix every invocation with `AWS_PROFILE=personal AWS_REGION=us-east-1`. The commands below use the prefix form so they're copy-paste-safe in a fresh shell.

## Step 0 — mandatory baseline triage (run all in parallel, on every invocation)

Do not skip any of these. Do not respond to the user with a verdict until you've inspected each output. The point of this step is to make it impossible to declare "healthy" without the evidence.

```bash
# 0a. Current op id + status
task ec2:ops AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares LATEST=true

# 0b. Current op objective state + tokens
task ec2:runtime AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares LATEST=true

# 0c. Process / Redis / NATS health
task ec2:status AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares

# 0d. The single most important probe — orchestrator tail. Grep it for the wedge signatures listed above.
task ec2:exec AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares \
  CMD='tail -n 300 /var/log/ares/orchestrator.log'

# 0e. Historical baseline — last several ops, to compare runtime-to-milestone
ares --ec2 kali-ares --ec2-profile personal --ec2-region us-east-1 ops list | head -20

# 0f. Failed tasks for the current op
ares --ec2 kali-ares --ec2-profile personal --ec2-region us-east-1 ops tasks --latest --status failed | head -80
```

Pull `op-YYYYMMDD-HHMMSS` from 0a/0b and use that as `$OP` below. After collecting:

1. Grep the 0d output for each pattern in the "Tight-loop / wedge signatures" table. **If any hits ≥3 times, you have your root cause; jump to reporting.**
2. Compare 0b's `Domains compromised` and `Vulns exploited` against the runtime banner of recent ops in 0e. If the prior 3 ops compromised more domains in less time at this point, the current op is regressed regardless of how healthy 0a/0c look.
3. Read 0f — the failure mode of the first 5-10 failed tasks usually points at the role/tool that's flailing.

Only proceed past Step 0 to deeper probes (Loki, Tempo, SSM journals) if none of the above lands a verdict.

## Step 1 — fast triage (Loki, last hour)

Loki has every ares log line shipped from the EC2 box. Datasource UID is `loki`. Logs are JSON; the actual line is in the `message` field, with labels `app="ares"`, `deployment="alpha-operator-range-kali-ares"`, `job=<role>.log`.

Run these in parallel:

```
mcp__grafana__query_loki_logs
  datasourceUid: "loki"
  logql: '{app="ares", deployment="alpha-operator-range-kali-ares"} |~ "(?i)error|fatal|panic|traceback|RUST_BACKTRACE"'
  limit: 30
```

```
mcp__grafana__query_loki_logs
  datasourceUid: "loki"
  logql: '{app="ares", deployment="alpha-operator-range-kali-ares", job="orchestrator.log"} |~ "WARN|ERROR"'
  limit: 30
```

Narrow by role when you know the suspect: change `job="orchestrator.log"` to one of
`recon.log`, `credential_access.log`, `cracker.log`, `acl.log`, `privesc.log`, `lateral.log`, `coercion.log`.

Narrow by op id (substring match on the log line):

```
logql: '{app="ares", deployment="alpha-operator-range-kali-ares"} |= "op-20260630-201500"'
```

Use `query_loki_stats` first when you're guessing the selector — it tells you whether the stream has any entries before you waste a `query_loki_logs` call.

## Step 2 — failed tasks (operation-level)

```bash
task red:multi:tasks:list LATEST=true STATUS=failed   # K8s
ares --ec2 kali-ares --ec2-profile personal --ec2-region us-east-1 ops tasks --latest --status failed   # EC2
```

Failed tasks include the worker's error message and the role that failed. Cross-reference against Loki by role + timestamp.

## Step 3 — wedge detection (objective state frozen)

**The canonical wedge is NOT "tokens flatlined" — tokens almost always keep climbing during a wedge because the LLM re-evaluates the same frozen state every tick.** The canonical wedge is "objective state frozen while tokens climb." Probe state, not tokens:

```bash
# Snapshot 1
task ec2:exec AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares \
  CMD='redis-cli hmget "ares:op:'"$OP"':meta" has_domain_admin has_golden_ticket target_ips initialized; echo ---; redis-cli scard "ares:op:'"$OP"':creds" 2>/dev/null; redis-cli scard "ares:op:'"$OP"':hashes" 2>/dev/null; redis-cli scard "ares:op:'"$OP"':hosts" 2>/dev/null'
# wait 60s
# Snapshot 2 — same command. Diff the two. Identical = wedge.
```

Cross-check against tokens: pull `ec2:runtime` at both snapshots. **Tokens climbing + state identical = textbook wedge.** Tokens climbing + state changing = healthy. Tokens flatlined + state identical = orchestrator hung (rarer).

If wedged, two further probes pinpoint where:

```bash
# Outbound HTTPS from orchestrator — zero connections = LLM API stall
task ec2:exec AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares CMD='ORCH=$(pgrep -f "ares orchestrator" | head -1); echo "orch_pid=$ORCH"; sudo ss -tnp 2>/dev/null | grep "pid=$ORCH" | grep -v 127.0.0.1 | wc -l'
```

```
# Loki search for retry/throttle/dedup markers in the last 30 minutes
mcp__grafana__query_loki_logs
  datasourceUid: "loki"
  logql: '{app="ares", deployment="alpha-operator-range-kali-ares", job="orchestrator.log"} |~ "clearing dedup for retry|KDC_ERR_|Task deferred|throttler|stale|wedge"'
  limit: 80
```

Remedy depends on root cause:

- Hot retry loop on a tool (`clearing dedup for retry`) → fix the dedup/blacklist logic in the relevant `automation/auto_*.rs`; in the meantime `task ec2:stop-op ... LATEST=true` to stop the burn.
- LLM API stall → restart workers, check the model provider's status: `task ec2:restart AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares` (preserves Redis state).
- State frozen but no signature → escalate to Tempo (Step 7) to find the slow span.

## Step 4 — worker crash loop

A specific role keeps respawning. Check systemd journal via SSM:

```bash
task ec2:exec AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares CMD='systemctl status ares@recon --no-pager | head -30'
task ec2:exec AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares CMD='journalctl -u ares@recon -n 100 --no-pager'
```

(Substitute `recon` with the failing role: `credential_access`, `cracker`, `acl`, `privesc`, `lateral`, `coercion`.)

If OOM-killed, check the cgroup:

```bash
task ec2:exec AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares CMD='dmesg -T | grep -iE "killed process|oom" | tail -20'
```

The system-ares.slice caps memory at 12G global, ~2G per worker (see `.taskfiles/ec2/scripts/setup.sh:160`). Worker OOM = a tool process (netexec, hashcat, etc.) blew up inside the worker's cgroup.

## Step 5 — Redis state introspection

```bash
task ec2:exec AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares CMD='redis-cli ping'
task ec2:exec AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares CMD='redis-cli info keyspace'
task ec2:exec AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares CMD='redis-cli keys "ares:operation:*" | head -20'
task ec2:exec AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares CMD='redis-cli get ares:operation:active'
task ec2:exec AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares CMD='redis-cli hgetall "ares:op:'"$OP"':meta"'
```

For loot or shared state, prefer the typed CLI over raw Redis:

```bash
task ec2:loot AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares LATEST=true        # users, creds, hashes, hosts
task ec2:loot AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares LATEST=true DIFF=true  # only what changed since last call
```

To run blue-team queries or arbitrary `ares` commands against EC2 Redis locally, port-forward:

```bash
task ec2:redis:forward AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares   # blocks in foreground — DO NOT run from an agent
```

If you need local access from an agent, use `ec2:exec` with `redis-cli` instead.

## Step 6 — NATS broker

NATS is the task/RPC broker. If workers are alive but no tasks dispatch:

```bash
task ec2:exec AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares CMD='curl -s http://127.0.0.1:8222/varz | jq ".connections, .in_msgs, .out_msgs, .slow_consumers"'
task ec2:exec AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares CMD='curl -s http://127.0.0.1:8222/connz | jq ".num_connections, [.connections[].name]"'
task ec2:exec AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares CMD='systemctl status nats-server --no-pager | head -15'
```

## Step 7 — OTEL traces (LLM + tool call timing)

OTEL traces ship to Tempo with `service.name=ares-orchestrator|ares-<role>-agent` and `deployment.environment=staging`, `attack.team=red`. Use the Grafana Tempo proxy tools — search by `service.name` and op id (op id is set as a span attribute by the orchestrator).

Useful when:

- You want to see the LLM call latency that's stalling a tick
- A specific tool call is silent in logs but you want to confirm it ran
- You need to attribute time spent across roles for a long-running op

If Tempo search returns nothing, the orchestrator may not be exporting — verify with:

```bash
task ec2:exec AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares CMD='grep OTEL_EXPORTER /etc/ares/env'
```

## Step 8 — verify deploy state (binary mismatch)

A common false positive: the local CLI and the EC2 binary diverge.

```bash
ares --version                                                                                                          # local
task ec2:exec AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares CMD='/usr/local/bin/ares --version'          # remote
task ec2:exec AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares CMD='stat -c "%y %s" /usr/local/bin/ares'    # mtime + size
```

If you just landed code, re-deploy before continuing to debug. Canonical "upload updated code, then run a fresh op against dreadgoad" one-liner (Apple-Silicon-safe — `DOCKER_DEFAULT_PLATFORM` forces an x86 build, the S3 bucket is the alpha-operator-range artifact store):

```bash
DOCKER_DEFAULT_PLATFORM=linux/amd64 task -y ec2:deploy EC2_NAME=kali-ares S3_BUCKET=dread-infra-alpha-operator-range-prod-us-east-1 \
  && task -y red:ec2:multi TARGET=dreadgoad EC2_NAME=kali-ares
```

(Both halves rely on `AWS_PROFILE=personal AWS_REGION=us-east-1` being exported or prefixed. Drop the `&&` and run just the first half for a deploy-only.)

Faster deploy-only when you don't need to publish to S3 (builds natively on EC2):

```bash
task ec2:deploy AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares BUILD_TOOL=remote
```

## Step 9 — kill, clear, retry (last resort)

Don't do this until you've captured logs and runtime — these are destructive.

```bash
task ec2:stop-op AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares LATEST=true   # graceful stop of one op
task ec2:stop    AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares                # stop all workers (keeps Redis)
task ec2:restart AWS_PROFILE=personal AWS_REGION=us-east-1 EC2_NAME=kali-ares                # restart workers (keeps Redis state)
```

To actually wipe state, use the CLI cleanup command instead of FLUSHALL:

```bash
ares --ec2 kali-ares --ec2-profile personal --ec2-region us-east-1 ops cleanup --max-age-hours 0
```

## K8s deployment notes

Same triage flow, different transport:

| EC2 command                                | K8s equivalent                                  |
|--------------------------------------------|-------------------------------------------------|
| `task ec2:status`                          | `task remote:status`                            |
| `task ec2:exec CMD='...'`                  | `kubectl exec -n attack-simulation <pod> -- ...`|
| `task ec2:logs ROLE=orchestrator`          | `task remote:logs ROLE=orchestrator`            |
| `task ec2:redis:forward`                   | `kubectl port-forward -n attack-simulation svc/redis 6379:6379` |
| Loki query (same Grafana)                  | Filter on `namespace="attack-simulation"` instead of `deployment="alpha-operator-range-kali-ares"` |

## Reference: Loki labels seen on grafana.techvomit.xyz

- `app`: `ares` covers everything ares writes
- `deployment`: `alpha-operator-range-kali-ares` for the EC2 box
- `environment`: `prod` or `local`
- `job`: `orchestrator.log`, `recon.log`, `credential_access.log`, `cracker.log`, `acl.log`, `privesc.log`, `lateral.log`, `coercion.log`, `syslog`, `auth.log`, `user-data`, `ansible`
- `service_name`: `ares`, `ares-orchestrator`, `ares-<role>-agent`, also blue: `ares-blue-orchestrator`, `ares-blue-triage`, etc.
- `host`: `kali`

If a label value is missing from this list, run `mcp__grafana__list_loki_label_values` to discover what's actually shipping.

## Reporting

When you finish debugging, return a short report:

- **Op id**, current `status`, runtime, token total, **objective state** (domains compromised, hosts owned, creds, hashes).
- **Baseline comparison** in one line: how this op's progress curve compares to the last 2-3 ops at the same runtime. Skip only if no prior op exists.
- **Verdict**: `healthy / wedged / crashed / slow-vs-baseline / unknown`. **Never** say "healthy" without citing two state snapshots 60s apart that show state advancing, or fresh log lines showing tool calls succeeding in the last minute.
- **Root cause** in one sentence, with the SSM/Loki/CLI evidence that pins it (quote the log line; cite the failed-task `task_type` and `role`).
- **Next action** — restart, redeploy, inject state, file a bug — and the exact command(s) to run.

Do not narrate every probe. The user wants the answer and the command to fix it, not the journey. But do not skip probes either: if you find yourself drafting a "healthy" verdict without having grepped the orchestrator tail for the wedge signatures and pulled `ares ops list` for baseline, stop and go back to Step 0.
