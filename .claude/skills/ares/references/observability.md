# Observability: Loki, Tempo, Grafana, OTEL

How to see what ares did. Three independent pipelines, three different latencies, one shared property: **all three fail silently.** For triaging a *live* wedged op use the `ares-debug` skill; this is the reference catalog behind it.

## Read this first

1. **OTLP export is a silent no-op when no endpoint env var is set.** `try_init_otel_provider` returns `None` with no warning and no log line (`ares-core/src/telemetry/init.rs:156`, `:114-121`). A healthy-looking process with an empty Tempo pane is the expected, undiagnosable-from-logs state. The **only** positive gate is the string `telemetry initialized with OTLP exporter` (`init.rs:105-108`).
2. **`RUST_LOG` gates trace export, not just console noise.** `EnvFilter` is a registry layer applied *before* the OTel layer (`init.rs:99-103`) and every ares span is `info_span!`. `RUST_LOG=warn` exports zero spans while looking like a normal quiet run. `ares-cli/src/transport.rs:169,414` deliberately runs remote CLI invocations under `RUST_LOG=error` — those emit no traces at all.
3. **`ARES_DEPLOYMENT` unset silently drops the `deployment=` label from every blue selector** (`ares-tools/src/blue/detection/mod.rs:37-46`) and your query spans every other range's logs. Set to a *wrong* value and you get zero rows with a 200 OK. This is the single most common cause of "all 55 detections fired zero". **The knob is `EC2_DEPLOYMENT`**, default `alpha-operator-range` (`.taskfiles/ec2/Taskfile.yaml:84`, `.taskfiles/red/Taskfile.yaml:790`): `ec2:launch` writes it into `/etc/ares/env` (`Taskfile.yaml:1281`) and re-exports it (`:1331`); `red:ec2:multi` substitutes it for `__ARES_DEPLOYMENT__` (`.taskfiles/red/Taskfile.yaml:906` → `launch-orchestrator.sh.tmpl:40`).
4. **ANSI escapes are written into `/var/log/ares/*.log`, and only the `message` text escapes them.** tracing-subscriber's fmt layer does not TTY-detect — its `is_ansi` default is `cfg!(feature="ansi") && NO_COLOR unset` (`tracing-subscriber-0.3.23/src/fmt/fmt_layer.rs:739-745`) — and ares never calls `.with_ansi(false)` (`init.rs:84-89`). `DefaultVisitor::record_debug` writes `message` unpainted (`src/fmt/format/mod.rs:1317-1324`) but paints **every other field name and its `=`** italic/dimmed (`:1332-1338`); span fields inherit the same `is_ansi` (`fmt_layer.rs:880`). So `grep 'tool.name="X"'` and `|= "tool=X"` return **0 hits** even when the tool ran. **Never anchor a grep or LogQL filter on `field=value` — match the message text or the bare value.** grep also treats these files as binary and goes silent; `grep -a` is mandatory.
5. **Loki is minutes behind for ares' own logs, seconds behind for Windows events.** `/var/log/ares/*.log` ships Vector → S3 with a 300s batch timeout (`ansible/roles/vector/defaults/main.yml:42`) then SQS → home-cluster Vector → Loki (`vector.yaml.j2:1-3`). Windows targets push straight to Loki through Alloy. **Loki is not a live tail for ares.** Use SSM for the last minute.
6. **`otel.status_message` is not a `tracing-opentelemetry` sentinel.** The crate recognises `otel.status_description` (`tracing-opentelemetry-0.33.0/src/layer.rs:33`); ares records `otel.status_message` (`spans/builder.rs:54-68`). The OTLP `Status.message` is therefore always empty. Searching Tempo by status description finds nothing — filter on the `otel.status_message` / `error.message` **attributes**.

## Which source answers which question

| Source | Latency | Coverage | How |
|---|---|---|---|
| `redis-cli` on the box | instant | Ground truth op state. Logs and traces are derived; Redis is authoritative. | see `references/state-and-redis.md` |
| `task ec2:exec … CMD='grep -a …'` | ~5-15s (SSM poll; **60s cap** — `.taskfiles/ec2/Taskfile.yaml:1488` passes `run_ssm_cmd … 60`. `run-ssm.sh:119`'s `${3:-120}` is a fallback no ares task uses) | Everything on the box, live. Only source for the last minute. | Bash; `grep -a` required |
| JSONL session logs on the box | instant | Full LLM transcript per task: messages, tool calls, results. Neither Loki nor Tempo. | `ares ops sessions list\|show\|replay` (`ares-cli/src/ops/sessions.rs:9-22`); files at `{dir}/{op_id}/{task_id}.jsonl` (`ares-llm/src/agent_loop/session_log.rs:81`) |
| Loki — ares logs (`app="ares"`) | **minutes** (300s S3 batch + cluster replay) | Historical `/var/log/ares/*.log`, syslog, auth.log, user-data.log, across ops | `mcp__grafana__query_loki_logs`, `datasourceUid: "loki"` |
| Loki — Windows events (`job="windows-security"`) | seconds (Alloy `loki.write` direct) | Target-side 4624/4662/4768/4769/5140/7045… — what blue queries | same |
| Tempo | ~5s batch (`OTEL_BSP_SCHEDULE_DELAY` default 5000ms, `opentelemetry_sdk-0.32.1/src/trace/span_processor.rs`) | Span timing: LLM latency, tool dispatch, cross-service parenting, decisions. **Nothing at all if the endpoint var is unset.** | `mcp__grafana__*` Tempo proxy; TraceQL on `attack_operation_id` |
| Prometheus / spanmetrics | seconds | Span-derived counters only — **ares emits zero OTLP metrics** (`Cargo.toml:47`, `features = ["trace"]`) | `mcp__grafana__query_prometheus` |
| Grafana annotations | seconds | Blue investigation lifecycle markers, tags default `ares,investigation` | `mcp__grafana__get_annotations` |
| Postgres `otel_spans` | — | Table exists (`ares-core/migrations/20260615120100_analytical.sql:81-97`) but **nothing in this repo writes to it.** Treat as empty. | UNVERIFIED whether any out-of-repo ingester populates it |
| `task ec2:logs ROLE=…` | streaming | one role's log | **Never from an agent** — `aws ssm start-session` with `AWS-StartInteractiveCommand` (`.taskfiles/ec2/Taskfile.yaml:664-685`); it will not terminate |

Cheapest first: Redis → SSM grep → Loki → Tempo. Only go to Tempo after confirming export is on.

---

## Loki

### How ares logs get there

**Trap — the Vector shipper is opt-in and off by default.** Symptom: `{app="ares"}` returns nothing at all, and you blame Loki or the 300s batch. Cause: the role is imported `when: vector_s3_enabled | bool`, and `vector_s3_enabled` defaults to `false` (`ansible/playbooks/ares/goad_attack_box_configure.yml:32`, `:111-114`, driven by env `VECTOR_S3_ENABLED`); `vector_s3_bucket` defaults to `""` (`ansible/roles/vector/defaults/main.yml:20`). With it off, `/var/log/ares/*.log` reaches nothing but the box — the Alloy config that *is* applied unconditionally ships only syslog/auth.log/user-data.log and shell history (`goad_attack_box.yml:208-227`). Fix: before concluding anything from an empty result, run `mcp__grafana__query_loki_stats` / `list_loki_label_values` for `app` and confirm the stream exists.

`ansible/roles/vector/templates/vector.yaml.j2` — Vector tails files, stamps four fields, writes gzip JSON to S3; a home-cluster Vector polls the bucket via SQS and replays into Loki.

```
sources.ares_logs.include = /var/log/ares/*.log, /var/log/syslog, /var/log/auth.log, /var/log/user-data.log
transforms.add_labels:
  .deployment  = vector_deployment_name    # default "alpha-operator-range"
  .environment = vector_environment        # default "prod"
  .app         = "ares"
  .job         = basename(.file)           # -> "orchestrator.log", "recon.log", "syslog", …
sinks.s3: codec json, gzip, batch timeout 300s / 10 MiB
```

`job` is the **file basename including `.log`** (`vector.yaml.j2:25-27`) — `job="orchestrator.log"`, never `job="orchestrator"`. **That rule is Vector-only.** The Linux Alloy config on the same box hard-codes suffix-less job names for the system files — `job="syslog"`, `job="auth"`, `job="user-data"`, plus `job="zsh_history"` / `job="bash_history"` (`ansible/playbooks/ares/goad_attack_box.yml:210-213`, `:221-224`) — so those three files exist under two different `job` spellings depending on which shipper delivered them.

Windows targets ship separately through the **external** `l50.bulwark.alloy` role (`ansible/playbooks/windows/target_setup.yml:25`). The `job="windows-security"` / `job="windows-system"` labels and the `computer` / `deployment` values it stamps are **not verifiable from this checkout** — confirm with `mcp__grafana__list_loki_label_values` before trusting a selector.

### Label catalog

| Label | Values | Provenance |
|---|---|---|
| `app` | `ares` | code-verified, `vector.yaml.j2:24` |
| `deployment` | Vector role default `alpha-operator-range` (`vector/defaults/main.yml:28`), overridden per-op by `EC2_DEPLOYMENT` → `ARES_DEPLOYMENT`; Alloy stamps `goad-attack-box` (`goad_attack_box.yml:36`, `goad_attack_box_configure.yml:21`) | code-verified. **No Rust, ansible or Taskfile source ever sets `alpha-operator-range-kali-ares`** — the only in-repo occurrences are operator-local agent docs that hard-code it (`.claude/skills/ares-debug/SKILL.md:127+`, `.claude/agents/ares-operator.md:274`). Treat it as an operator override and confirm with `list_loki_label_values` |
| `environment` | `prod` (Vector role default, `vector/defaults/main.yml:29`); on the attack box overridden to `{{ alloy_env }}` = `$ENVIRONMENT` or `goad` (`goad_attack_box_configure.yml:20`, `:117`); `dev` in `playbooks/linux/attacker_setup.yml:7` and `playbooks/windows/target_setup.yml:7` | code-verified. There is no `local` value anywhere in the repo |
| `job` (ares) | `orchestrator.log`, `recon.log`, `credential_access.log`, `cracker.log`, `acl.log`, `privesc.log`, `lateral.log`, `coercion.log`, `syslog`, `auth.log`, `user-data.log` | basenames of `vector_log_includes` × `redis_ares_worker_roles` (`ansible/roles/redis/defaults/main.yml:66-73`) |
| `job` (Windows) | `windows-security`, `windows-system` | code-verified as query constants, `ares-tools/src/blue/detection/mod.rs:22-23` |
| `computer` | FQDN — matched with `=~`, so a bare IP or short name partially matches | `detection/mod.rs:29-46` |
| `namespace` | `attack-simulation` (K8s only) | operator-observed; use instead of `deployment=` on K8s |
| `service_name` | `ares`, `ares-orchestrator`, `ares-<role>-agent` | operator-observed; nothing in this repo stamps it |
| `host` | `constants.hostname` — the box's own hostname | code-verified, Alloy `stage.static_labels` (`goad_attack_box.yml:238`, `:255`; `goad_attack_box_configure.yml:79`, `:96`; `playbooks/linux/attacker_setup.yml:81`, `:98`) |
| `server`, `instance_id`, `os` | `{{ alloy_server_id }}` (defaults `""`), `{{ ansible_ec2_instance_id }}`, `linux` | code-verified, same Alloy blocks. **Alloy-only** — Vector stamps none of these |
| `log_type`, `user` | `attack_activity`; `kali` / `root` | code-verified, Alloy shell-history streams only (`goad_attack_box.yml:219-224`, `:232-240`) |

**`{job="eventlog"}` does not exist.** It appears only in `docs/grafana_mcp_usage.md:37,54,78,89` and `docs/blue.md:435,443,446`. Both docs are stale (May 2026) and their tool-call examples also use parameter names no tool accepts. Trust `ares-tools/src/blue/mod.rs` and `detections.yaml`, not those two files.

### Log line shape

Vector's S3 sink encodes each event as JSON (`vector.yaml.j2:38-39`), so the Loki line is a JSON object and the ares log text is in **`message`**. Inside `message` is tracing-subscriber's default `Format<Full>` with target/thread/file/line suppressed (`init.rs:84-89`; `show_target` defaults false at `init.rs:33`):

```
2026-07-30T09:22:14.881234Z  INFO ares.agent{otel.name=tool.secretsdump agent.role=credential_access …}: message text field=value
```

The JSON envelope around it is Vector's: `message`, `file`, `host`, `source_type`, `timestamp`, plus the four stamped fields (`vector.yaml.j2:22-27`).

Values recorded as `&str` are Debug-quoted (`tool.name="secretsdump"`); values recorded with `%` are unquoted. **Output goes to stderr, not stdout** (`init.rs:85`) — `2>/dev/null` blinds you.

**Trap — the ANSI escapes survive into Loki, JSON-escaped.** On disk a field renders as `<ESC>[3mtool<ESC>[0m<ESC>[2m=<ESC>[0msecretsdump` (`<ESC>` = 0x1b). Vector JSON-encodes the whole line, so each 0x1b arrives inside `message` as a six-character JSON unicode escape (the `u001b` form, same shape as the `..u003e` case below). Either way the *name* and the `=` are fenced off from the value by escape runs; only the *value* is contiguous. Same class of trap as the `..u003e` JSON-escaped XML shape blue must match (see "Working LogQL — blue"): **filter on the message text or the bare value, never on `field=value`.**

### Working LogQL — red

Substitute your own `deployment`. The repo default is `alpha-operator-range` (`.taskfiles/ec2/Taskfile.yaml:84`); anything else is an operator override. **`alpha-operator-range-kali-ares` is set by no source in this checkout** — it appears only in the operator-local `ares-debug` skill and `.claude/agents/ares-operator.md:274`, which hard-code it. Confirm with `mcp__grafana__list_loki_label_values` before trusting any of these — a wrong value returns zero rows with a 200 OK.

```logql
# everything ares wrote, errors only
{app="ares", deployment="<your-deployment>"} |~ "(?i)error|fatal|panic|RUST_BACKTRACE"

# one role
{app="ares", deployment="<your-deployment>", job="credential_access.log"} |~ "WARN|ERROR"

# scope to one op — the op id is a substring of the line, NOT a label
{app="ares", deployment="<your-deployment>"} |= "op-20260730-092214"

# tool attribution: the executor's INFO line (tool_executor.rs:540-545). The message
# text is plain, but `tool` is an event FIELD — its name and `=` are ANSI-painted,
# so `|= "tool=secretsdump"` matches nothing. Filter on the bare value.
{app="ares", deployment="<your-deployment>"} |= "Executing tool" |= "secretsdump"

# K8s instead of EC2
{namespace="attack-simulation"} |~ "(?i)error|panic"
```

### Working LogQL — blue

Blue never hand-writes a selector; `build_selector` composes it (`detection/mod.rs:37-48`):

```logql
# ARES_DEPLOYMENT set, no host
{job="windows-security", deployment="<your-deployment>"} |= "4769" |~ `(?i)(TicketEncryptionType..u003e0x17)`

# with a host — REGEX match against the FQDN label
{job="windows-security", deployment="…", computer=~"dc01"} |~ `(?i)(nmap|masscan)` |= "dc01"
```

Two rules that are not optional:

- **Field-anchored patterns must use the JSON-escaped XML shape Loki stores.** The `>` after a field name is a literal escape sequence, matched as `..u003e` (two dots absorb backslash+quote); values terminate with `.u003c`. A plain-text pattern matches nothing and the filter silently passes everything through.
- **Any stage containing a regex metacharacter must reach Loki inside a backtick raw string.** LogQL double-quoted strings apply Go escape rules, so `cmd\.exe` arrives as the invalid escape `\.` → `400 Bad Request`, correctly non-retryable, one WARN line. That once killed all 15 `filter_stages` templates at once (`detection/mod.rs:72-89`). `is_regex_pattern` (`:62-70`) treats `. * + ? ( ) [ ] { } | ^ $ \` as metacharacters; a single literal without one takes the fast `|=` path.

Catalog semantics — which template matches what, and how coverage is scored — live in `references/blue-team.md` ("Detection catalog", "Scoring — two independent paths"). This doc owns the transport.

### ares' own Loki client — caps and refusals

`ares-tools/src/blue/loki.rs`. Endpoint resolution is **Grafana datasource proxy → `LOKI_URL` → `http://localhost:3100`** (`loki.rs:39-61`). The module header at `loki.rs:5-9` lists it backwards; the doc comment at `:33` and the code are right.

| Behaviour | Value | Where |
|---|---|---|
| Proxy base URL | `GET {GRAFANA_URL}/api/datasources/uid/loki` → `.id` → `{GRAFANA_URL}/api/datasources/proxy/{id}` | `loki.rs:76-91` |
| Auth token | `GRAFANA_SERVICE_ACCOUNT_TOKEN`, falling back to `GRAFANA_API_KEY` (loki.rs only) | `loki.rs:70-72` |
| Proxy result cached | process-lifetime `OnceCell` — fixing `GRAFANA_URL` mid-run does nothing | `loki.rs:29, :39-42` |
| `query_loki_logs` limit | default 50, **hard `.min(100)`** | `loki.rs:340` |
| Bare selector | **rejected client-side and returned as SUCCESS** | `loki.rs:344-354` |
| `execute_parallel_queries` | `.take(5)`, `Semaphore::new(2)` — queries 6+ dropped without warning | `loki.rs:951-953` |
| detection `hours_back` | `.min(2)` at every entry point, whatever the model asks for | `detection/runner.rs:19,72,170,227,267` |
| detection event count | saturates at `DETECTION_ENTRY_LIMIT = 100` | `detection/runner.rs:155` |
| per-attempt timeout | `LOKI_TIMEOUT_SECS`, default 90 | `loki.rs:104-110` |
| retry budget | `LOKI_QUERY_BUDGET_SECS`, **defaults to one attempt's timeout** so a hung query gets zero retries | `loki.rs:152-178` |
| `get_loki_label_values` | sends **no** start/end — Loki's server-side default lookback applies, unwidenable | `loki.rs:905-917` |

**Trap — rejected is not empty.** The bare-selector refusal goes through `make_output` (`loki.rs:349`): `exit_code: 0, success: true`. Anyone reading exit codes treats a rejected query as "ran, no hits". Trigger set is `|=`, `|~`, `| json`, `| logfmt`; a label matcher plus only a `!~` negative filter is still rejected.

**Trap — trailing newline in `GRAFANA_URL` or the token** fails at the reqwest *builder* stage, is classified non-retryable, and surfaces as `Loki request could not be constructed …` (`loki.rs:403-412`). Inspect the string, not the network.

**Trap — Prometheus has no Grafana-proxy fallback.** `PROMETHEUS_URL` only, default `http://localhost:9090` (`ares-tools/src/blue/prometheus.rs:11-12`). On a box where only `GRAFANA_URL` is set, Loki works and all three Prometheus tools fail — which reads as "Prometheus is down".

### The ANSI trap when reading files directly

systemd appends both streams straight into the log file with no TTY (`ansible/roles/redis/templates/ares@.service.j2:24-25`) and the fmt layer colours anyway.

```bash
# WRONG — 0 hits even when the tool ran. Bytes are <ESC>[3mtool.name<ESC>[0m<ESC>[2m=<ESC>[0m"X".
# `grep -a` does NOT fix this: -a only stops grep classifying the file as binary,
# it does not remove escape bytes. Any `name=` adjacency is unmatchable.
grep 'tool.name="secretsdump"' /var/log/ares/orchestrator.log

# -a is mandatory: escapes make grep classify these files as binary and go silent.
# Safe because "Executing tool" is message text, not a field=value pair.
sudo grep -a 'Executing tool' /var/log/ares/orchestrator.log

# strip for reading
sudo sed $'s/\x1b\\[[0-9;]*[a-zA-Z]//g' /var/log/ares/orchestrator.log | less

# count tool invocations from the span context — STRIP FIRST, then match
sudo sed $'s/\x1b\\[[0-9;]*[a-zA-Z]//g' /var/log/ares/orchestrator.log \
  | grep -o 'tool\.name="[a-z_]*"' | sort | uniq -c | sort -rn
```

`NO_COLOR=1` in the unit environment is the only kill switch (`fmt_layer.rs:739-745`); it appears nowhere in the repo. `task ec2:logs:fetch` strips ANSI locally (`.taskfiles/ec2/Taskfile.yaml:735`); raw `ec2:exec` + `tail` does not.

**`task ec2:logs:fetch ROLE=all` misses one role and invents another.** Its loop iterates `… lateral_movement coercion …` (`.taskfiles/ec2/Taskfile.yaml:742`) but the deployed role is `lateral` (`ansible/roles/redis/defaults/main.yml:72`), so `/var/log/ares/lateral.log` is never fetched and `lateral_movement.log` does not exist. `ROLE=all` fans out one SSM call per role specifically because remote concatenation blows past **SSM's ~24KB `StandardOutputContent` cap** and silently truncates (`.taskfiles/ec2/Taskfile.yaml:737-739`). Always scope with `OP_ID=` and `SINCE=`.

---

## Tempo / OTEL

### The env vars, and what each does when unset

| Var | Read by | Effect | When unset |
|---|---|---|---|
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | `init.rs:139` + otlp SDK | Primary gate. Must start `http://` or `https://`. Under `http/protobuf` it is used **verbatim** — no `/v1/traces` appended. | falls through to the generic var |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `init.rs:140` + SDK | Secondary gate. SDK appends `/v1/traces` under HTTP. | **OTLP disabled, silently** |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `init.rs:170` | Exactly `http/protobuf` → `with_http()`. **Anything else, including unset, → gRPC `with_tonic()`.** The signal-specific `…_TRACES_PROTOCOL` spelling has no effect on ares' branch. | gRPC exporter aimed at your HTTP endpoint |
| `OTEL_RESOURCE_ATTRIBUTES` | `init.rs:196-208` + SDK | comma-separated `k=v` appended to the Resource | no extra attributes. **Workers get it from a second source the orchestrator does not use:** `Environment=OTEL_RESOURCE_ATTRIBUTES={{ redis_ares_otel_resource_attributes }}` in the unit (`ares@.service.j2:21`), fed by `ansible/roles/redis/defaults/main.yml:60` |
| `OTEL_SERVICE_NAME` | SDK only | **ineffective** — ares pushes `service.name` after the detectors (`init.rs:191-194`) and explicitly `continue`s on that key | n/a |
| `RUST_LOG` | `init.rs:81-82` | global filter for console **and** span creation | in-code defaults are CLI `warn,ares_cli=info` (`main.rs:70`) and orchestrator/worker plain `info` (`init.rs:32`) — but **on EC2 the value is already pinned to `info` by the deploy, so the in-code default never applies**: `launch-orchestrator.sh.tmpl:17`, `.taskfiles/ec2/Taskfile.yaml:1328`, and `ares@.service.j2:20`. To change it for a trace-export experiment, edit those three sites; exporting `RUST_LOG` in your SSM shell will not reach the process |
| `NO_COLOR` | tracing-subscriber | non-empty is the only way to stop ANSI landing in log files | colour ON |
| `OTEL_TRACES_ENDPOINT` | **go-task only** | source value the taskfiles map onto `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | **no default** (`Taskfile.yaml:131`), absent from `.env.example` → traces off |

Three failure signatures, all different:

```bash
# 1. Never set -> NOTHING is logged. Absence of the success line is the only tell.
sudo grep -a 'telemetry initialized with OTLP exporter' /var/log/ares/orchestrator.log

# 2. Set-but-empty / non-absolute -> raw eprintln, no timestamp, no level (it is printed
#    before the subscriber is installed).  init.rs:149-152, :162
sudo grep -aE 'OTEL endpoint is set but empty|ignoring OTEL endpoint: not an absolute URL' /var/log/ares/*.log

# 3. Read what the LIVE process has — /etc/ares/env can be stale vs the transient
#    unit's --setenv snapshot (launch-orchestrator.sh.tmpl:83-88)
sudo tr '\0' '\n' < /proc/$(pgrep -f 'ares orchestrator' | head -1)/environ \
  | grep -E '^(OTEL_|RUST_LOG|NO_COLOR|ARES_DEPLOYMENT|ARES_OPERATION_ID)'
```

**Forgetting `OTEL_TRACES_ENDPOINT=` produces set-but-empty, which is worse than unset.** The EC2 env-file writer emits `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=''` unconditionally (`.taskfiles/ec2/Taskfile.yaml:1294`); `launch-orchestrator.sh.tmpl:12` then sources `/etc/ares/env` with `set -a` **before** its own correctly-guarded export at `:43-48`, so the guard cannot save you — the empty value is already exported and rides through `--setenv=OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` (`:86`). Both the orchestrator and every `ares@<role>.service` worker land on the `OTEL endpoint is set but empty` path. Grep for that line before assuming the collector is down.

**There are two EC2 launch paths and only one uses that template.** `task red:ec2:multi` substitutes `launch-orchestrator.sh.tmpl` (`.taskfiles/red/Taskfile.yaml:892-908`) and spawns it under `systemd-run` (tmpl `:61-95`). `task ec2:launch` (`.taskfiles/ec2/Taskfile.yaml:1062`) does **not** — it builds an inline script that sources `/etc/ares/env` (`:1322`), unconditionally re-exports `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` (`:1332`) and `nohup`s the binary (`:1344`). Same empty-endpoint outcome, but there is no transient unit and no `--setenv` snapshot to diff against.

To actually turn traces on:

> **Destructive — this starts a real operation.** The launcher stops `ares-orchestrator.service` and `pkill`s any running orchestrator before spawning (`launch-orchestrator.sh.tmpl:52-56`), so it kills whatever op is in flight. Run it only when you intend a fresh op.

```bash
task red:ec2:multi TARGET=dreadgoad OTEL_TRACES_ENDPOINT=https://<alloy-host>/v1/traces
```

The value is substituted for `__OTEL_TRACES_ENDPOINT__` (`.taskfiles/red/Taskfile.yaml:907`) and paired with `OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf`, so **the URL must already end in `/v1/traces`**.

### service.name — the only shapes ares ever emits

| Process | `service.name` | Source |
|---|---|---|
| `ares <any subcommand except orchestrator/worker>` | `ares-cli` | `ares-cli/src/main.rs:64-71` |
| `ares orchestrator` (**including the in-process blue orchestrator**) | `ares-orchestrator` | `ares-cli/src/orchestrator/mod.rs:62-64` |
| `ares worker`, mode task or tool_exec | `ares-{role}-agent`, underscores→dashes | `ares-cli/src/worker/config.rs:108` |
| `ares worker`, mode `blue_task` | `ares-blue-{role}` | `ares-cli/src/worker/mod.rs:26-32` — **nothing deploys this mode**; the unit hardcodes `ARES_WORKER_MODE=tool_exec` (`ares@.service.j2:19`). Do not expect these services in Tempo. |

Deployed worker services: `ares-recon-agent`, `ares-credential-access-agent`, `ares-cracker-agent`, `ares-acl-agent`, `ares-privesc-agent`, `ares-lateral-agent`, `ares-coercion-agent` (`ansible/roles/redis/defaults/main.yml:66-73` × `worker/config.rs:108`).

**`peer.service` points at a phantom node.** The orchestrator dispatcher emits `ares-worker-{role}` (`redis_dispatcher.rs:157`), matching no real `service.name`. The service graph draws an edge to something that never emits spans. Never join on `peer.service`.

**`ares --redis-url … worker` panics on startup.** `main.rs:64-66` only inspects `args().nth(1)`, and every global flag is `global = true` (`cli/mod.rs:33-62`), so a flag before the subcommand makes the CLI init telemetry and the worker init it again → `failed to set global default subscriber` (`tracing-subscriber-0.3.23/src/util.rs:92-95`). Subcommand first, always.

### Resource attributes on every exported span

| Attribute | Value | Overridable? |
|---|---|---|
| `service.name` | per-process (above) | **No** — `init.rs:202-204` skips the key |
| `service.namespace` | literal `attack-simulation` (`init.rs:193`) | **No.** Same string as the K8s namespace, so namespace filtering in Tempo is ambiguous between the two meanings. |
| `deployment.environment` | `staging` — hardcoded in **every** deploy path | nominally yes; in practice a production op still ships `staging` |
| `attack.team` | `red` — hardcoded in every deploy path, **including the box that runs blue** | same |
| `telemetry.sdk.*` | auto (`Resource::builder()` detectors) | no |
| `busy_ns` / `idle_ns` (span-level) | auto on every span — `tracked_inactivity` defaults true (`tracing-opentelemetry-0.33.0/src/layer.rs:664`) and is never disabled | no |

Hardcode sites: `.taskfiles/ec2/Taskfile.yaml:1296` and `:1334`, `.taskfiles/ec2/scripts/launch-orchestrator.sh.tmpl:47`, `ansible/roles/redis/defaults/main.yml:60`. Consequence: **every blue span carries resource `attack.team=red` while its span attribute says `attack_team="blue"`.** Filter on the span attribute.

### Span catalog — tracing name vs Tempo name

The `tracing` name is what you grep in **logs**; the Tempo span name comes from the `otel.name` sentinel (`layer.rs:30`). Different strings, same span.

| tracing name | Tempo `otel.name` | kind | Emitter | Key attributes |
|---|---|---|---|---|
| `ares.agent` | `tool.{tool}` when a tool is set, else the builder `name` | internal/client/server/producer/consumer | `AgentSpanBuilder` — all tool + service spans | schema below (`spans/builder.rs:243-286`) |
| `ares.agent` via `trace_tool_call` | `tool.{tool}` | internal | agent loop: external + callback tools | role, target, `op.id`, `task.id`, deferred status (`spans/helpers.rs:24-53`) |
| `ares.agent` via `producer_span` | `dispatch.{tool}` | producer | `RedisToolDispatcher` | `peer.service=ares-worker-{role}`; status recorded after the NATS round-trip (`redis_dispatcher.rs:155-164`, `:297`) |
| `ares.agent` name `tool_exec` | `tool.{tool}` | consumer | worker tool executor; remote parent from `request.traceparent` | worker role, extracted target, `operation_id` (`worker/tool_executor.rs:264-286`) |
| `ares.discovery` | `discovery.{plural_key}` — `discovery.hosts`, `discovery.credentials`, … | (unset) | worker, one per non-empty discovery array | `discovery.type`, `discovery.source_agent`, `service.namespace="ares"`, `attack_phase="discovery"` (`helpers.rs:66-86`, `tool_executor.rs:628-641`) |
| `ares.discovery` | `discovery.domain_admin` | (unset) | milestone publisher | `attack_path`, `attack.depth`, hardcoded `mitre.technique.id=T1003.006` / `mitre.tactic=credential-access`; `task.id` deliberately empty (`helpers.rs:132-153`) |
| `ares.decision` | `decision.{role}` | (unset) | agent loop, per LLM tool selection | `decision.tool_chosen`, `decision.tools_considered` (**first 5, comma-joined**), `decision.tools_considered_count` (untruncated), `decision.confidence` (`helpers.rs:99-126`) |
| `ares.blue.simulated_response` | `blue.simulated_response.{action_type}` | internal | blue callbacks | `otel.status_code` **hardcoded `OK`**, `attack_team="blue"`, `investigation.id`, `simulated_response.*` (`simulated_response.rs:45-66`) |
| `agent.loop` | `agent.loop` | (unset) | one per agent task | `op.id`, `task.id`, `agent.role`, `agent.model` (`runner.rs:171-177`) |
| `llm.call` | `llm.call` | (unset) | **one per retry attempt** | `llm.model`, `llm.attempt`, input/output/cache tokens, `llm.duration_ms`, `llm.stop_reason`, `llm.error` (`retry.rs:26-64`) |
| `exec.command` | `exec.{resolved_program}` | client | process executor | `process.executable.name`, `process.command_line` (redacted), `process.exit_code`, `tool.timed_out`, `tool.duration_ms` (`executor.rs:282-295`) |
| `exec.relay` | `exec.impacket-ntlmrelayx` | client | coercion relay spawn | `relay.pid`; **no status fields** (`coercion.rs:584-586`) |
| `automation.task` | `automation.task` | (unset) | one long-lived span per background loop | `automation.kind` = the `auto_*` fn name (`automation_spawner.rs:25`) |
| `automation.dispatch` | `automation.dispatch` | (unset) | `throttled_submit_outcome` | `task_type`, `target_role`, `priority`, `automation.decision` (`submission.rs:52-58`) |
| `automation.request_*` (11) | same string — **no `otel.name`**, so tracing name == Tempo name | (unset) | `#[instrument(name = …)]` on the task builders (`dispatcher/task_builders.rs:199,297,330,358,391,426,512,647,672,695,721`) | per-builder `fields(…)` only — `target_ip`, `domain`, `technique`, `username`, `priority`. **No `op.id`, no `attack_operation_id`.** |

The eleven: `automation.request_recon`, `_low_hanging_fruit`, `_credential_access`, `_secretsdump`, `_secretsdump_hash`, `_lateral`, `_exploit`, `_bloodhound`, `_share_enumeration`, `_share_spider`, `_coercion`.

### AgentSpanBuilder attribute schema

`spans/builder.rs:243-286`. The duplicates and empty-string conventions are load-bearing.

| Attribute | Note |
|---|---|
| `otel.name` / `otel.kind` / `otel.status_code` | sentinels. `otel.kind` values are lowercase `internal\|client\|server\|producer\|consumer` |
| `otel.status_message` / `error.message` | **plain attributes**, not sentinels. `""` on success, error text on failure. |
| `attack_team`, `agent.role`, `attack_phase` | `attack_phase` is `""` for an unknown role |
| `mitre.tactic`, `mitre.technique.id` | tactic from the technique prefix, falling back to the role map; `""` when the tool is unmapped |
| `tool.name` **and** `attack_tool_name` | same value under two names |
| `attack_tool_category` vs `tool.provisioned_category` | hand-maintained map vs `tools.yaml` category — different things |
| `tool.binary` | the binary the fn actually invokes, from `tools.yaml` via `ares-core/build.rs` |
| `tool.status` | legacy free-text `success` / `error`, kept for older queries |
| `destination.address` | FQDN, **falling back to the IP** |
| `server.address` | FQDN only — **empty for IP-only targets.** Key the attack graph on `destination.address`. |
| `destination.ip` | validated single IP; CIDR and multi-token values rejected twice (`builder.rs:96-115`, `telemetry/target.rs`) — LLM agents pass whole nmap argument strings in `target` |
| `attack_operation_id` **and** `op.id` | same value; `attack_operation_id` retained for existing dashboards |
| `task.id` | one agent-loop run, **not** the operation. Deliberately distinct from `op.id`; `ares-llm/tests/span_regressions.rs` asserts they never conflate. |

**Everything unset is `""`, never absent** (~15 `.unwrap_or("")` at `builder.rs:255-283`; successful spans set `otel.status_message=""` and `error.message=""` rather than omitting them, `builder.rs:62-67`). TraceQL existence predicates therefore match every span. Use `!= ""`.

### TraceQL that works

```traceql
{ .attack_operation_id = "op-20260730-092214" }        # the exact query benchmark capture uses
{ resource.service.name = "ares-credential-access-agent" }
{ name = "tool.secretsdump" }                          # NOT "ares.agent"
{ .otel.status_message != "" }                         # errors; status DESCRIPTION is always empty
{ .op.id = "op-…" && .agent.role = "acl" }
{ name =~ "decision\\..*" }
```

`attack_operation_id` is the load-bearing search key — but **it is not on every span.** It is emitted only by `AgentSpanBuilder` (`spans/builder.rs:281`), the discovery / decision / domain-admin helpers (`spans/helpers.rs:82`, `:122`, `:149`) and the blue simulated-response span (`simulated_response.rs:59`). It is **absent** from `exec.command`, `exec.relay`, `llm.call`, `agent.loop` (which records `op.id` only) and every `automation.*` span. Tempo *search* still returns the whole trace — one matching span is enough (`ares-cli/src/benchmark/capture.rs:1447`) — but a span-level predicate `{ .attack_operation_id = … }` silently drops those families. Scope them by trace id or `.task.id` instead. Traces are fetched at `{GRAFANA_URL}/api/datasources/proxy/uid/{tempo_uid}/api/search` and `/api/traces/{id}` (`capture.rs:1443`, `:1490`). The Tempo datasource is resolved by `type == "tempo"` **only, never by name**, deliberately, so a rename cannot silently drop traces (`capture.rs:1392-1396`) — unlike Prometheus, which capture pins by both type and name (`capture.rs:972-1029`).

### Latency numbers are span-only — there is no second source

**`llm.duration_ms` and `tool.duration_ms` exist nowhere but on the span.** `llm.duration_ms` is recorded at `ares-llm/src/agent_loop/retry.rs:36,44`; `tool.duration_ms` at `ares-tools/src/executor.rs:294,312`. Neither appears in any `tracing` event, session-log field, report or Redis key (grepped across `ares-llm/src/agent_loop/`, `ares-cli/src/orchestrator/tool_dispatcher/`, `ares-tools/src/executor.rs`, `ares-cli/src/worker/tool_executor.rs`).

Consequence for "how slow were the LLM calls / tool dispatches in the last op": **if OTLP was off — the documented default on both EC2 launch paths — the number is not recoverable for an op that already ran.** No amount of Redis, log or report digging produces it. Gate before you promise anything:

```bash
task ec2:exec EC2_NAME=<pinned> \
  CMD='sudo grep -a "telemetry initialized with OTLP exporter" /var/log/ares/orchestrator.log'
```

Empty ⇒ traces were off ⇒ the honest answer is "not recoverable; relaunch with `OTEL_TRACES_ENDPOINT=…`", and note that a relaunch **starts a new op**.

The one fallback is coarse: every session-JSONL entry carries an RFC3339 `ts` (`ares-llm/src/agent_loop/session_log.rs:113-127`), so `ares ops sessions replay <op> <task>` supports wall-clock deltas between turns. That measures turn-to-turn wall clock, not the provider call, and cannot separate retries the way per-attempt `llm.call` spans do (one span **per retry attempt**, `retry.rs:26-40`).

Scoping: `llm.call` carries `task.id` (`retry.rs:39`) but **no `op.id` and no `attack_operation_id`** — `task.id` is the only span-level key for it.

### Status, deferral, and what is simply missing

- Only `AgentSpanBuilder` spans, `exec.command`, and the blue simulated-response span set `otel.status_code`. `agent.loop`, `llm.call`, `automation.*`, `exec.relay` export as `STATUS_CODE_UNSET`.
- `defer_status()` leaves the status fields `tracing::field::Empty`; forgetting `record_span_status` leaves the span permanently statusless (`builder.rs:179-182`). Deferred callers: the orchestrator dispatcher, the worker `tool_exec` consumer span, and every `trace_tool_call`.
- Blue containment spans are created and immediately dropped with `let _ =` — near-zero duration **by design**, they are decision markers counted by spanmetrics (`simulated_response.rs:41-44`). **Count them, do not time them.** They also hardcode `otel.status_code = "OK"`, so a blue containment span can never be errored.
- **ares emits no OpenTelemetry metrics.** `opentelemetry_sdk` is `features = ["trace"]` (`Cargo.toml:47`). Every `traces_spanmetrics_*` series in Grafana is derived server-side by the Collector's spanmetrics processor from these spans (`spans/builder.rs:44-50`).

### Trace propagation

`traceparent` is injected into the `ToolExecRequest` and travels **over NATS**, not Redis, despite the module doc at `propagation.rs:1-6` (`redis_dispatcher.rs:201-215` → `nats::tool_exec_subject`; worker `set_span_parent` at `tool_executor.rs:284-286`). File and struct names in that subsystem lag the Redis→NATS migration.

The W3C propagator is registered **inside** `try_init_otel_provider`, after the endpoint checks (`init.rs:166-167`). With traces off, `inject_traceparent` returns `None` with no error and worker spans would be orphan roots.

`ARES_OPERATION_ID` accepts a bare id **or** a JSON envelope `{"operation_id":"…"}`; the agent loop parses both and falls back to the literal string `unknown` when absent (`runner.rs:195-212`). The EC2 launcher exports the JSON form (`.taskfiles/ec2/Taskfile.yaml:1335`).

### Building / testing telemetry

The whole module is behind a **non-default** cargo feature (`ares-core/Cargo.toml:44-53`; `default = ["blue"]`).

```bash
cargo test -p ares-core --features telemetry     # without this, zero telemetry tests compile or run
cargo test -p ares-llm --test span_regressions   # guards op.id/task.id separation, per-attempt llm.call spans
```

---

## Grafana

### Datasource UIDs

The UID `loki` is **hard-pinned as a string literal in two independent places** — there is no env var and no config key for it, contrary to `docs/grafana_mcp_usage.md:130-131`. `GrafanaConfig` (`ares-core/src/config/sections.rs`) has no datasource field at all.

- `ares-tools/src/blue/loki.rs:76` — `GET {grafana}/api/datasources/uid/loki`
- `ares-tools/src/blue/grafana/rules.rs:107` — `"datasourceUid": "loki"` in every generated alert rule

| UID | Name | Type | Replay URL | Used by |
|---|---|---|---|---|
| `loki` | Loki | loki | `http://loki:3100` (isDefault) | blue proxy resolution; alert-rule query stage; `mcp__grafana__query_loki_logs` |
| `prometheus` | Prometheus | prometheus | `http://prometheus:9090` | benchmark capture, resolved by `type==prometheus` **and** `name=="Prometheus"` |
| `tempo` | Tempo | tempo | `http://tempo:3200` | trace capture; resolved by type only |
| `mimir`, `alertmanager` | — | — | replay stack only | not used by ares code |

The replay stack mirrors argonaut's UIDs on purpose so blue's proxy resolution works unchanged offline (`benchmarks/replay-stack/grafana/provisioning/datasources/datasources.yaml:2-3`).

**`ares-redteam` in `config/ares.yaml:296` is not a dashboard UID.** Its only reader is a `println!` in `ares config` (`ares-cli/src/config.rs:142`). There are **zero dashboard JSON files in the repo** — nothing provisions an ares dashboard, so you must `search_dashboards` to find one. The only UID ares provisions is the alert **folder** `ares-security`, rule group `ares-detections` (`grafana/rules.rs:65-92`).

### Which MCP tool for which job

`mcp__grafana__*` is an **operator-side Claude Code capability**, not part of ares. There is no `.mcp.json` in the repo and no MCP client in the Rust workspace — the only `mcp` string in any `.rs` file is a 1Password item *name* (`ares-cli/src/secrets.rs:17`). Blue's own Grafana/Loki access is hand-rolled reqwest, dispatched from the table at `ares-tools/src/blue/mod.rs`.

| Tool | Use it for |
|---|---|
| `mcp__grafana__query_loki_stats` | **First**, whenever you are guessing a selector — tells you whether the stream has entries before you burn a log query. **No ares equivalent exists.** |
| `mcp__grafana__query_loki_logs` | Primary historical log query. `datasourceUid: "loki"` + LogQL **with a line filter**. |
| `mcp__grafana__list_loki_label_names` / `list_loki_label_values` | Discover what is actually shipping. **Mandatory for Windows labels** — those are stamped by an external Ansible collection and cannot be verified from this checkout. Unlike ares' `get_loki_label_values`, these accept a time range. |
| `mcp__grafana__list_datasources` / `get_datasource_by_uid` | Confirm the `loki` UID resolves before blaming blue's proxy resolution. |
| `mcp__grafana__search_dashboards` / `get_dashboard_by_uid` / `get_dashboard_panel_queries` | Locate a dashboard (no UID is discoverable from the repo) and lift its LogQL/PromQL verbatim rather than re-deriving it. |
| `mcp__grafana__get_annotations` | Read back blue investigation lifecycle markers — tags default `ares,investigation` (`grafana/annotate.rs:21`). |
| `mcp__grafana__list_alert_rules` / `get_alert_rule_by_uid` | Inspect rules ares created in folder `ares-security` / group `ares-detections`. |
| `mcp__grafana__query_prometheus` | PromQL — prefer over ares' `query_prometheus`, which has no proxy fallback. |
| `mcp__grafana__generate_deeplink` | Shareable Explore/dashboard URL for a report. |

### Known MCP quirks

- **Metric queries can drop labels.** When a metric-query result disagrees with expectation, replicate the underlying LogQL stage-by-stage against Loki rather than trusting the metric. (Operator-observed; not repo-verifiable.)
- **The setup doc's 1Password coordinates are wrong.** `docs/topics/grafana-mcp-setup.md:41` says `op item get "Dev Grafana" --fields api-token`; the real item is **`Ares Grafana MCP`**, field **`grafana-token`** (`ares-cli/src/secrets.rs:15-19`, `Taskfile.yaml:378`). Worse, the doc wraps it in `2>/dev/null`, so the failure is silent and you register an MCP server with an empty token — every call then 401s. Gate with `task ares:config:check`.
- **`docs/blue.md:473` links `grafana-mcp-setup.md` relative to `docs/`** — broken; the file is at `docs/topics/grafana-mcp-setup.md`.
- **The three analyst images bake in `mcp-grafana` v0.11.6 but set no `GRAFANA_URL` or token** — `ares-blue-triage-agent`, `ares-blue-threat-hunter-agent`, `ares-blue-lateral-analyst-agent` (`warpgate-templates/templates/<name>/warpgate.yaml:46-61`). The binary ships present and unwired. **`ares-blue-agent` does not ship `mcp-grafana` at all** — it is a `cargo build` of the ares binary (`ares-blue-agent/warpgate.yaml:42-55`).
- **`get_grafana_alerts` (ares' own tool) aborts its three-endpoint fallback on anything but a 404** (`grafana/query.rs:53-55`). A 401 on `/api/alertmanager/grafana/api/v2/alerts` kills the chain even though the provisioning endpoint would have worked.
- **Replay mode rewrites Grafana/Loki reads behind your back** — `get_grafana_alerts` discards your `state` filter and becomes a 24h annotation lookup, `get_grafana_annotations` overrides any caller-supplied `to`, and `query_loki_logs` clamps `end_time` to the replay clock and returns prose for a future window (`grafana/query.rs:21-27`, `:104-110`; `loki.rs:331-338`). **Never conclude "the alert isn't there" from a replay run.**

### Reaching Grafana and Loki from a laptop

```bash
task obs:forward     # blocks; Ctrl+C tears both down via an EXIT trap
export LOKI_URL=http://localhost:3100
export GRAFANA_URL=http://localhost:3000
```

`.taskfiles/obs/Taskfile.yaml` is three tasks (`forward`, `stop`, `status`). What matters:

- **Loki and Grafana are exposed on service port 80** in-cluster; 3100/3000 are the local side only (`:29-34`).
- **`obs:stop` — which `obs:forward` runs first — does `lsof -ti:3100 | xargs kill` and the same on 3000** (`:79-80`). It kills *any* local process on those ports.
- **`obs:status` reporting HTTP 200 on :3000 proves nothing** — the probe cannot tell the tunnel from any other local listener. Cross-check the `pgrep` count line (`:87-92`).
- **There is no Tempo or Prometheus forward.** Tempo is reachable only through the Grafana datasource proxy; the replay stack serves Tempo on `:3200`.
- Only `OBS_CONTEXT` comes from `.env`; namespace, service names and ports are Taskfile-local defaults absent from `.env.example` — override on the command line.
- **`GRAFANA_URL` beats `LOKI_URL` at runtime** (`loki.rs:39-46`). To force direct Loki you must *unset* `GRAFANA_URL` or its token.
- The header comment at `:16` claims `scripts/env-from-secrets.sh` "pins the secret to these URLs". **It does not** — it writes `GRAFANA_URL`/`LOKI_URL` verbatim from Secrets Manager, so regenerating `.env` silently overwrites the localhost exports.

### YAML config → env, one direction only

`config/ares.yaml`'s `observability:` block back-fills `LOKI_URL`, `LOKI_AUTH_TOKEN`, `PROMETHEUS_URL` **only when the env var is unset** (`ares-cli/src/orchestrator/mod.rs:757-771`). Shipped `loki_url` is `""` (`config/ares.yaml:307`) and `loki_auth_token` is absent from the block, so those two back-fill nothing.

**Trap — `PROMETHEUS_URL` is not the same story, and it inverts the "Prometheus is down" diagnosis above.** Shipped `prometheus_url: "http://localhost:9090"` (`config/ares.yaml:308`) is non-empty, and the EC2 env-file writer never emits `PROMETHEUS_URL` (`.taskfiles/ec2/Taskfile.yaml:1265-1309`) — so on every EC2 orchestrator the guard at `mod.rs:767-769` fires and **actively pins `PROMETHEUS_URL` to loopback.** The Prometheus tools are not falling through to a bare default; they are being pointed at a port nothing listens on. Fix it in the YAML, not the environment.

The `logging:` block in `config/ares.yaml` is **dead config** — it deserialises into `LoggingConfig` and nothing reads it. `RUST_LOG` plus the systemd `StandardOutput=append:` redirect are the real controls.

`ops submit` propagates `GRAFANA_URL` and `GRAFANA_SERVICE_ACCOUNT_TOKEN` to the orchestrator but **not** `LOKI_URL`, `LOKI_AUTH_TOKEN`, `PROMETHEUS_URL` or `TEMPO_URL` — `OPS_ENV_VAR_NAMES` (`ares-cli/src/ops/submit.rs:34-57`) omits all four, while the `#[cfg(feature = "blue")]` `BLUE_ENV_VAR_NAMES` at `:12-32` lists every one (`LOKI_URL` at `:17`). Diffing the two lists is the check; `LOKI_URL` is the omission most likely to bite a blue-enabled orchestrator. On EC2, `launch-orchestrator.sh.tmpl:66-88` does `--setenv=LOKI_URL` and `--setenv=GRAFANA_URL` but never `LOKI_AUTH_TOKEN` / `PROMETHEUS_URL` / `TEMPO_URL` — those reach the process only by way of `/etc/ares/env` being sourced.

---

## Where else to look

Routing map: `SKILL.md`. Nearest neighbours only:

| Question | Go to |
|---|---|
| "this op is stuck / slow / crashing" | skill `ares-debug` — probe ladder, wedge signatures, tool-pruning cascade. Its Redis key/type table at `SKILL.md:110-123` is correct (verified against `state/keys.rs:22-72` and `state/reader.rs`); `references/state-and-redis.md` is the fuller version. Only nit: for `:hashes` it lists the AES-upgrade verb (`hset`, `reader.rs:432`) and omits the insert verb (`hset_nx`, `reader.rs:414`) — `references/state-and-redis.md` carries both. |
| what a detection template actually matches, how coverage is scored | `references/blue-team.md` |
| every `ARES_*` / provider env var and its precedence | `references/config-and-env.md` |
| replay stack, benchmark capture, Tempo re-push | `references/benchmarks-and-replay.md` |

Test data: allowed values only — see `references/tools-and-gates.md#test-conventions`.
