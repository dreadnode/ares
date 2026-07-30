# Deployment + build

Four targets run the same single `ares` binary: **EC2 `kali-ares`** (default, SSM), **K8s `attack-simulation`** (imperative `kubectl cp` into live pods), **Proxmox/Ludus attacker VM** (standalone, SSH), **local**. Every **remote** path installs to `/usr/local/bin/ares`; the local target installs nothing and leaves the binary in `target/` (`Taskfile.yaml:292-297`).

Getting code onto a box and proving what landed is this doc. Debugging a live op is `ares-debug`. Executing a multi-step launch/monitor/report workflow is the `ares-operator` agent — a single one-shot command runs inline, don't dispatch an agent for it.

`rg`/`fd` will not see `.taskfiles/` without `--hidden`. It is a dot-directory.

## Read this first

1. **`task ec2:restart` does NOT restart workers.** It is literally `- task: stop` + `- task: start` (`.taskfiles/ec2/Taskfile.yaml:630-635`). `stop` = `systemctl stop ares-orchestrator.service` + `pkill -f "ares orchestrator"` (`:572-575`); `start` = redis-server/nats-server/postgresql (`:552-557`). Neither touches `ares@<role>.service`. The `SKIP_RESTART=true` warning at `:253` and `:450` tells you to run `task ec2:restart` — **that advice is wrong**. Bounce workers with `task ec2:exec CMD='systemctl restart "ares@*.service"'`.
2. **`task ec2:deploy` DOES restart workers by default** — `.taskfiles/ec2/Taskfile.yaml:255-257` and `:452-454` glob `systemctl list-units --type=service --state=active "ares@*.service"` and restart the matches. Two consequences: deploying mid-op kills the workers servicing it, and if no unit is currently `active` it prints `no ares@ worker units active — skipping restart` and ships new code that nothing executes. (`ares-debug` Step 8 documents the same `--state=active` catch — `.claude/skills/ares-debug/SKILL.md:287,398-405`.)
3. **`BUILD_TOOL=remote` (the default) ignores `BUILD_PROFILE`, `RUST_TARGET`, `CARGO_BUILD_JOBS` and `MAX_OPEN_FILES`.** The SSM payload hardcodes `cargo build --profile dev-deploy -p ares-cli` and `target/dev-deploy/ares` (`.taskfiles/ec2/Taskfile.yaml:218-219`). `task ec2:deploy BUILD_PROFILE=release` is a silent no-op.
4. **`ec2:deploy` tars your WORKING TREE.** `SRC_PATHS="Cargo.toml Cargo.lock Cross.toml tools.yaml ares-core/ ares-cli/ ares-llm/ ares-tools/ benchmarks/"` (`:194-198`), uncommitted edits included. The deployed binary may correspond to no commit. Gate it by grepping a unique string in `/usr/local/bin/ares` — and prefer `contains`/format-string literals, since `starts_with` literals get folded out by the optimizer.
5. **`AWS_REGION` + `AWS_PROFILE` alone pick which physical box you hit.** There is no prod/staging flag anywhere. Resolution is a substring glob `Name=tag:Name,Values=*kali-ares*` (`.taskfiles/ec2/scripts/run-ssm.sh:47`, `ares-cli/src/transport.rs:207-209`). README documents the normal box as `lab`/`us-west-1` (`README.md:134`) and the alternate as `--ec2-profile prod --ec2-region us-east-1` (`README.md:215`). No confirmation prompt, no account check.
6. **On K8s, deploy order is load-bearing and one-directional.** `kubectl cp` writes `/usr/local/bin/ares` in the container filesystem; any later pod restart reverts to the image binary. `k8s:deploy` rolls out *before* deploying binaries (`.taskfiles/k8s/Taskfile.yaml:31` then `:34`). Running `remote:rollout` after `remote:rust:deploy` throws the deploy away.
7. **`task remote:sync:full TEAM=blue` — the command `.claude/CLAUDE.md` prescribes for blue — is dead.** It operates on `src/ares/**` (`.taskfiles/remote/Taskfile.yaml:245,265-266`); `src/` does not exist in this repo (verified: `ls src` → No such file or directory). It prints per-pod sync failures and exits 0. **`task remote:sync` is dead for the identical reason** — its desc advertises `FILES=src/ares/core/worker.py` (`remote:28`) and its body `find src/ares -name "*.py"` (`remote:87`), `kubectl cp` into `$PVC_PATH/src/ares/…` (`remote:116,148`). Both are Python-era leftovers; the tree is Rust. Use `task k8s:deploy TEAM=blue`.

## Environment matrix

| Target | Entrypoint | Transport | Redis / NATS | Binary install | Config path |
|---|---|---|---|---|---|
| EC2 `kali-ares` (**default**, red+blue) | `task run` / `red:ec2:multi` / `ec2:deploy` | AWS SSM `AWS-RunShellScript` | box-local `127.0.0.1:6379` / `:4222` (monitor `:8222`) | `install -m 755` → `/usr/local/bin/ares` | `/etc/ares/config.yaml` |
| K8s `attack-simulation` | `k8s:deploy` / `remote:*` | `kubectl cp` / `kubectl exec` | in-cluster pod `app=redis` | `kubectl cp` → `/usr/local/bin/ares` (**ephemeral**) | `/ares/config/ares.yaml` (PVC) |
| Proxmox VMID 200 `attacker-1` | `proxmox:*` (**not wired in**, see below) | `ssh -J <proxmox-host>` + `scp` | VM-local `localhost:6379` / `:4222` | `sudo install -m 755` → `/usr/local/bin/ares` | `/etc/default/ares` env + config search |
| Local | `rust:build` / `rust:release` | none | whatever `ARES_REDIS_URL` names | `target/release/ares` (**no install step**) | `./config/ares.yaml` — **not honored by `ares orchestrator`, see below** |

Binary config search order: `$ARES_CONFIG` first (**hard-fails** if the path is missing — it does not fall through), then `./config/ares.yaml`, `/ares/config/ares.yaml`, `/etc/ares/config.yaml` (`ares-core/src/config/mod.rs:20-24`, resolver at `:84-106`).

**That order governs `AresConfig::from_env()` only (`config/mod.rs:76-79`). `ares orchestrator` does a second, separate read for the per-role model map that bypasses it entirely** — `ARES_CONFIG` or a hardcoded `/ares/config/ares.yaml`, with no fall-through to `./config/ares.yaml` or `/etc/ares/config.yaml` (`ares-cli/src/orchestrator/mod.rs:481-487`). When that read yields nothing and `ARES_LLM_MODEL` is unset, the orchestrator aborts with `No LLM model configured — set ARES_LLM_MODEL or agents.orchestrator.model in config YAML` (`:488-494`). It never bites on EC2 because both orchestrator launchers export the path explicitly — `export ARES_CONFIG=/etc/ares/config.yaml` at `launch-orchestrator.sh.tmpl:41` and `.taskfiles/ec2/Taskfile.yaml:1329` (via `ARES_REMOTE_CONFIG`, `:66`). **For a local orchestrator run the matrix's `./config/ares.yaml` is not enough — set `ARES_CONFIG` (or `ARES_LLM_MODEL`) yourself.** (Unrelated but adjacent: the K8s `ops submit` exec also pins `ARES_CONFIG="/etc/ares/config.yaml"` at `.taskfiles/red/Taskfile.yaml:94`, which is *not* the `/ares/config/ares.yaml` the matrix gives for pods — UNVERIFIED which of the two exists in the pod image.)

Observability is a **separate EKS cluster** reached by `task obs:forward`, not part of any deployment path. That belongs to `references/observability.md`.

---

## EC2 `kali-ares` — the default target

### Instance resolution

Both resolvers glob the Name tag over running instances in the ambient profile/region, but they differ on ambiguity:

| Resolver | Behavior on multiple matches | Source |
|---|---|---|
| `run-ssm.sh` (`task ec2:*`) | sorts `LaunchTime` desc with InstanceId tiebreak, takes newest, prints a yellow WARN + the full candidate list to stderr | `.taskfiles/ec2/scripts/run-ssm.sh:40-63` |
| Rust CLI (`ares --ec2 …`) | takes the first whitespace token of an unordered `describe-instances`, warns about nothing | `ares-cli/src/transport.rs:231-237` |

Two escape hatches: `EC2_INSTANCE_ID=i-…` bypasses the tag lookup in `resolve_instance_id` only (`run-ssm.sh:69-77` — `resolve_instance_ip` and `resolve_targets` ignore it); and the Rust CLI accepts a literal id, `--ec2 i-0abc…` short-circuits when the name starts `i-` and is ≥10 chars (`transport.rs:204-207`).

**Effective defaults are `kali-ares` / `lab` / `us-west-1`,** from the ec2 include's own vars (`.taskfiles/ec2/Taskfile.yaml:35,39,40`). Verified empirically on task 3.52.0 with all AWS env unset — `task -v --dry ec2:resolve` renders `Name=tag:Name,Values=*kali-ares*` and `--region "us-west-1"`.

**The `desc:` strings lie.** Most still say `[EC2_NAME=ares-tools]` (`:91,:119,:499,:1473`), and the root Taskfile declares `EC2_NAME: ares-tools` (`Taskfile.yaml:134`) and `AWS_REGION: us-east-1` (`:137`). Neither wins. In go-task 3.52 the include's vars leak globally in **both** directions — `task -v --dry run` renders `kali-ares` / `us-west-1` even inside the *root* `run` task's own commands.

**Target-range resolution uses different vars than the box.** `TARGET_PROFILE` / `TARGET_REGION` (`Taskfile.yaml:125-126`, defaults `lab` / `us-east-1`) resolve `TARGET=dreadgoad` into a comma-joined list of private IPs (`.taskfiles/red/Taskfile.yaml:792-803`); an IP-looking `TARGET` short-circuits the lookup. So one `task run` legitimately talks to `us-west-1` for the attack box and `us-east-1` for the range.

**Exported session creds silently drop `--profile`.** If `AWS_ACCESS_KEY_ID` is set (granted/assume/aws-vault), `AWS_PROFILE_ARG` renders empty and `AWS_PROFILE_EXPORT` emits `unset AWS_PROFILE` (`.taskfiles/ec2/Taskfile.yaml:44-61`). Any `AWS_PROFILE=` you pass on the task line is ignored and the ambient session is used instead.

### `task ec2:deploy` — what actually ships

```bash
task ec2:deploy EC2_NAME=kali-ares S3_BUCKET=<bucket>                    # remote build + worker restart
task ec2:deploy EC2_NAME=kali-ares S3_BUCKET=<bucket> SKIP_RESTART=true  # op in flight
task ec2:deploy:config S3_BUCKET=<bucket>                                # config only, restarts nothing
```

Preconditions: `aws sts get-caller-identity` succeeds, and `S3_BUCKET` is non-empty (`:139-142`). `S3_BUCKET` has no default (`:63`) — it must come from `.env` / env, and the bucket must live in the **same account as the instance** (the box pulls with its instance profile). `jq` is a hard, undeclared local dependency of every SSM call (`run-ssm.sh:123`); a missing `jq` surfaces as a bare `jq: command not found`.

Remote-build path (`BUILD_TOOL=remote`, the default):

1. tar the working-tree `SRC_PATHS` (+ `.cargo/` if present) → `s3://$S3_BUCKET/ares-deploy/ares-src.tar.gz` (`:194-204`)
2. SSM: untar into `/var/tmp/ares-build`, `cargo build --profile dev-deploy -p ares-cli`, sha256 the artifact, `install -m 755` to `/usr/local/bin/ares`, re-sha the installed file and **hard-fail on mismatch** (`:206-227`, 1800s SSM budget)
3. restart active `ares@*.service` units unless `SKIP_RESTART=true` (`:250-259`, 60s budget)
4. chain `deploy:config` (`:461-464`)

`config/` is deliberately **not** in the tarball — it ships only via the chained `deploy:config` step, and nothing restarts after that, so live workers keep serving the old config until bounced.

#### What `ec2:deploy` cannot ship

`SRC_PATHS` is the whole shipping manifest. **`ansible/` and `.taskfiles/` are not in it.**

| Edit | Ships with `ec2:deploy`? | How it actually reaches the box |
|---|---|---|
| `ares-core/`, `ares-cli/`, `ares-llm/`, `ares-tools/`, `benchmarks/`, `Cargo.*`, `Cross.toml`, `tools.yaml` | yes | tarball → S3 → remote `cargo build` |
| `config/ares.yaml` | no (not in tarball) | chained `ec2:deploy:config` → S3 → `/etc/ares/config.yaml` |
| `ansible/roles/redis/templates/ares@.service.j2`, `system-ares.slice.j2`, `defaults/main.yml` — **the systemd units and cgroup caps below** | **no** | AMI re-bake, or the playbook over SSM. Provisioning is baked (`.taskfiles/ec2/scripts/setup.sh:4-8`); `ec2:logrotate` is the only `ansible-playbook` invocation in `.taskfiles/` (`.taskfiles/ec2/Taskfile.yaml:1465`) and it runs `logrotate.yml`, nothing else |
| `.taskfiles/ec2/scripts/launch-orchestrator.sh.tmpl` | n/a — **ships from your local working tree on every launch** | `red:ec2:multi` seds the template and pipes the rendered text straight into `run_ssm_cmd` (`.taskfiles/red/Taskfile.yaml:895-910`) |

That last row is the exact inverse of the ansible row and is worth internalizing: **editing the orchestrator's cgroup caps, `ARES_MAX_CONCURRENT_TASKS`, or env exports in `launch-orchestrator.sh.tmpl` takes effect on the very next `red:ec2:multi` with no deploy at all** — while editing the *worker* unit under `ansible/` takes effect never, until you re-bake.

`/tmp` is deliberately avoided for the build dir: on `kali-ares` it is a 7.7G tmpfs swept daily by `systemd-tmpfiles-clean` (age 10d), which reaped aged cargo build-script `OUT_DIR`s while their fingerprints survived → ENOENT on `include!(OUT_DIR/…)`. `/var/tmp` is on `/` with a 30d age (`:76-83`).

### BUILD_TOOL matrix

| Value | What runs | Notes |
|---|---|---|
| `remote` (default) | native `cargo build --profile dev-deploy -p ares-cli` on the box | Only path that ignores `BUILD_PROFILE`/`RUST_TARGET`/`JOBS`. Chosen because arm64 Macs crash rustc under qemu (`:69-72`) |
| `auto` | Darwin+`cross` → `cross`; else `cargo-zigbuild` → `zigbuild`; else `cross`; else `cargo` | `:152-163`; exports `PATH=$HOME/.cargo/bin` first (`:146`) |
| `cross` | `cross build $PROFILE_FLAG --target … -p ares-cli` with `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc`, `AWS_LC_SYS_CMAKE_BUILDER=1` | `:331-338` |
| `zigbuild` | `cargo zigbuild $PROFILE_FLAG --target … -p ares-cli` | `:339-341`. Fails on macOS — aws-lc-sys breaks under Zig's `ar` wrapper |
| `cargo` | plain `cargo build --target …` with a WARN | `:342-345` |

The unknown-value error lists `auto, cross, zigbuild, cargo` (`:346-349`) — **`remote` is missing from that list** because the remote branch exits earlier. Do not read it as "remote is invalid".

### S3 artifact layout

Prefix is `ares-deploy` (`:125`, `:470`).

| Object | Written by | Read by |
|---|---|---|
| `s3://$S3_BUCKET/ares-deploy/ares-src.tar.gz` | `ec2:deploy` (remote path) | box-side `cargo build` |
| `s3://$S3_BUCKET/ares-deploy/ares` | `ec2:deploy` (**local cross-compile path only**) | box-side `install` (`:393`, `:421`) |
| `s3://$S3_BUCKET/ares-deploy/config.yaml` | `ec2:deploy:config` | `/etc/ares/config.yaml` (`:485-489`) |
| `target/.deploy/ares.sha256` (local file) | local cross-compile path (`:389-390`) | expected-sha gate on the box |

`ec2:logrotate` reuses `S3_BUCKET` as `ansible_aws_ssm_bucket_name` (`:1459`).

### systemd units, cgroups, paths on the box

| Component | Unit / path | Limits | Source |
|---|---|---|---|
| Workers ×7 | `ares@{recon,credential_access,cracker,acl,privesc,lateral,coercion}.service` → `/usr/local/bin/ares worker` | `MemoryHigh=1500M`, `MemoryMax=2G`, `TasksMax=256`, `Delegate=yes`, `Slice=system-ares.slice`, `Restart=on-failure` / `RestartSec=5` | `ansible/roles/redis/templates/ares@.service.j2:8,22-34`; values `ansible/roles/redis/defaults/main.yml:40-44`; role list `:66-73` |
| Fleet slice | `system-ares.slice` | `MemoryMax=12G`, `MemoryHigh=10G`, `TasksMax=8192` | `system-ares.slice.j2:5-8`; values `redis/defaults/main.yml:50-54` |
| Orchestrator | `ares-orchestrator.service`, **transient** via `systemd-run --slice=system-ares.slice --collect` | `MemoryHigh=8G`, `MemoryMax=10G`, `TasksMax=4096`, `OOMScoreAdjust=-500` | `.taskfiles/ec2/scripts/launch-orchestrator.sh.tmpl:61-95` |
| Redis / NATS / Postgres | `redis-server` (fallback `redis`), `nats-server`, `postgresql` | — | `.taskfiles/ec2/Taskfile.yaml:552-557` |
| Logs | `/var/log/ares/%i.log` per worker, `/var/log/ares/orchestrator.log` | append; no rotation until `ec2:logrotate` runs | `ares@.service.j2:24-25`; tmpl `:89-90` |

The transient unit exists specifically so tool subprocesses don't inherit `amazon-ssm-agent`'s cgroup and get `CONSTRAINT_MEMCG` OOM-killed (`launch-orchestrator.sh.tmpl:1-6`). **The "3G cgroup" comment at `tmpl:34` is stale** — the shipped per-worker cap is 2G max / 1500M high.

Worker env is `EnvironmentFile=-/etc/ares/env` plus unit-level `Environment=` lines: `HOME=/root` (needed for hashcat's potfile wipe — without it the resolver returns None, the wipe silently no-ops, and the prior op's cracked plaintexts leak forward), `ARES_WORKER_ROLE=%i`, `ARES_WORKER_MODE=tool_exec`, `RUST_LOG=info` (`ares@.service.j2:9-21`).

`ARES_TOOL_DISPATCH` is intentionally left **unset** by the launcher so tools route over NATS into the worker cgroups (`launch-orchestrator.sh.tmpl:33-34`). `status.sh:16-24` prints which mode is live.

### Two orchestrator launch paths that are not equivalent

| | `red:ec2:multi` (normal) | `ec2:launch` (escape hatch) |
|---|---|---|
| Mechanism | renders `launch-orchestrator.sh.tmpl` → `systemd-run --unit=ares-orchestrator.service --slice=system-ares.slice` | plain `nohup /usr/local/bin/ares orchestrator` (`.taskfiles/ec2/Taskfile.yaml:1344`) |
| cgroup | `system-ares.slice`, own limits | inherits amazon-ssm-agent's — the exact OOM condition the template header warns about |
| `ARES_MAX_CONCURRENT_TASKS` | pinned to 8 (`tmpl:42`) | never set → code default 12 (`ares-cli/src/orchestrator/config.rs:192`) |
| Redis | untouched | `FLUSH_REDIS=true` by default → `redis-cli FLUSHDB` (`:1089`, `:1257`) |
| Blocking | no | `WAIT=true` by default, ≤7200s (`:1098-1100`) |

`ec2:launch` also carries hardcoded real-lab domain/user/password defaults (`:1066`, `:1072-1074`) — never let them be used implicitly. Its `BLUE_MODE` var is declared at `:1107` and referenced nowhere; `export ARES_BLUE_ENABLED=1` is hardcoded at `:1330`, so you cannot turn blue off through it. Prefer `red:ec2:multi`.

**`EC2_DEPLOYMENT` silently decides whether blue works at all.** Default `alpha-operator-range` (`.taskfiles/ec2/Taskfile.yaml:84`, commented "Loki deployment label for blue team queries"; same default at `.taskfiles/red/Taskfile.yaml:790`). It reaches the box two ways — baked into `/etc/ares/env` as `ARES_DEPLOYMENT` by `ec2:launch` (`:1281`) and exported by the launcher (`:1331`), or sed'd into the template's `__ARES_DEPLOYMENT__` by `red:ec2:multi` (`red:906` → `launch-orchestrator.sh.tmpl:40,83`). The blue side reads it as the Loki `deployment` label (`ares-tools/src/blue/detection/mod.rs:38`, `ares-tools/src/blue/investigation/write.rs:610,654`, `ares-cli/src/orchestrator/blue/callbacks.rs:95`, `investigation.rs:177`) and the orchestrator stamps it as the run environment (`ares-cli/src/orchestrator/mod.rs:1176`). A wrong value does not error — blue just queries a label that matches no logs, for the whole op.

**`ec2:launch` depends on two Secrets Manager items, and only one of them is fatal.** `SECRETS_ID` (default `ares/api-keys`, `:1075`) must yield JSON with `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`; an empty fetch **exits 1** with `Failed to fetch API keys from Secrets Manager` (`:1181-1191`). `RDS_SECRET_ID` (default `ares/rds/master`, `:1084`) only builds `ARES_DATABASE_URL`; a failed read is a **WARN** — `SQL history persistence disabled for this op` (`:1222-1233`) — and the op launches without SQL history.

`ec2:launch` rewrites `/etc/ares/env` atomically (mktemp + `chmod 600` + mv, `:1265-1309`). `GRAFANA_URL`, `LOKI_URL` and `ARES_DATABASE_URL` are each gated behind a 3-second `/dev/tcp` probe **from the box** and are simply omitted, with a `SKIP: … unreachable from box` line on stderr, when it fails. The op still launches; blue tooling and SQL history just silently no-op. It also pins `ARES_HASHCAT_WORKLOAD=4` (code default 3 — the headless T4 starves at `-w2`) and `HOME=/root` (`:1283-1292`).

### ec2 task index

| Task | Line | Purpose | Agent-safety |
|---|---|---|---|
| `ec2:resolve` | 90 | print id/IP/Name for **all** running matches | safe |
| `ec2:deploy` | 118 | build + install + restart workers + push config | **destructive to a running op**; 15-25 min cold |
| `ec2:deploy:config` | 465 | config → `/etc/ares/config.yaml` | mutating, no restart |
| `ec2:setup` | 498 | readiness only: impacket-shadow guard, `enable --now` nats + 7 `ares@` units, Redis/NATS smoke test | mutating |
| `ec2:history-db` | 518 | provision box-local `ares_history` Postgres | rewrites `pg_hba.conf` |
| `ec2:start` / `ec2:stop` | 539 / 562 | infra up / orchestrator down | `stop` kills a live op's orchestrator |
| `ec2:restart` | 630 | `stop` + `start` — **not** workers | misnamed |
| `ec2:status` | 640 | Redis/NATS/dispatch-mode/per-role unit state/orchestrator PID/hashcat/disk | safe |
| `ec2:hashcat` | 652 | running hashcat PIDs, mode, `--session` | safe |
| `ec2:logs` | 664 | live `tail -f` over an interactive SSM session | **AGENT-UNUSABLE — never terminates** |
| `ec2:logs:fetch` | 687 | pull a role log locally, remote `OP_ID`/`SINCE` filter, ANSI stripped | safe; see the `lateral` bug below |
| `ec2:redis:forward` / `ec2:nats:forward` | 779 / 805 | SSM port-forward 6379→16379, 4222→14222 | **AGENT-UNUSABLE**; each `lsof -ti:PORT \| xargs kill` first |
| `ec2:ops:ids` | 968 | op ids + started_at + derived status straight from Redis, **no local binary needed** | best read-only option |
| `ec2:watch` | 985 | poll to terminal then chain `ec2:report` | **blocks ≤2h**; treats `stopped` as success |
| `ec2:launch` | 1062 | direct-launch escape hatch | FLUSHDB + 2h block by default |
| `ec2:setup:tools` | 1399 | apt+pipx pentest tool install | can reintroduce the impacket shadow `ec2:setup` removes |
| `ec2:logrotate` | 1413 | the only `ansible-playbook` invocation in `.taskfiles` | mutating |
| `ec2:exec` | 1472 | arbitrary shell via `AWS-RunShellScript`, 60s | the agent-safe substitute for `ec2:logs` |

`ec2:stop-op` / `kill` / `teardown` / `loot` / `runtime` / `ops` / `watch` sit behind the `*ares-cli-executable` precondition (`:587-589`) requiring `./target/release/ares` locally — which **no ec2 task ever builds under any `BUILD_TOOL`**: `remote` never builds locally at all, and the local cross paths write `target/{{RUST_TARGET}}/$BIN_SUBDIR/ares` (`.taskfiles/ec2/Taskfile.yaml:353,365`) where `BIN_SUBDIR` is `BUILD_PROFILE` (`:266-273`, `:359-364`), defaulting to `dev-deploy` (`:75`). Even `BUILD_PROFILE=release` yields `target/x86_64-unknown-linux-gnu/release/ares`, never `./target/release/ares`. On a fresh clone they fail with a misleading "build it first" while the box is perfectly healthy. Build it yourself with `task rust:release` (or `cargo build --release -p ares-cli`).

**Binary-free equivalents.** `ec2:exec` runs the *box's* `ares` against the box's own Redis, so every gated read has a substitute:

```bash
task ec2:ops:ids EC2_NAME=<pinned>                                              # purpose-built, no CLI
task ec2:exec EC2_NAME=<pinned> CMD='ares ops list'
task ec2:exec EC2_NAME=<pinned> CMD='ares ops loot --latest --json'
task ec2:exec EC2_NAME=<pinned> CMD='ares ops runtime --latest'
task ec2:exec EC2_NAME=<pinned> CMD='ares ops inspect-vulns --latest --json'
task ec2:exec EC2_NAME=<pinned> CMD='ares ops tasks --latest --status all'
```

Flags verified at `ares-cli/src/cli/ops.rs:95-104` (`InspectVulns` takes `operation_id`, `--latest`, `--json`). Two caps apply to all of them: `ec2:exec` hardcodes a 60 s SSM budget (`.taskfiles/ec2/Taskfile.yaml:1488`) with no override var, and SSM's `StandardOutputContent` truncates silently near 24 KB — so use `--json` and narrow the query rather than dumping a whole op.

### EC2 gotchas

- **`task ec2:logs:fetch ROLE=all` silently never fetches the lateral-movement log.** The loop hardcodes `lateral_movement` (`:742`) but the role, unit and file are `lateral` (`redis/defaults/main.yml:72`, `/var/log/ares/lateral.log`). You get a `===FILE:…lateral_movement.log===` header with nothing under it and no error. `ROLE=lateral` works.
- **SSM `StandardOutputContent` truncates around 24KB, silently** — the Taskfile calls this out as the reason `ROLE=all` fans out one call per role (`:740-742`). Any large `ec2:exec` output loses its tail at exit 0. Chunk it (as `ec2:report` does at 12000 bytes/call) or narrow the query.
- **`red:ec2:multi`'s submit step is `ignore_error: true`** (`.taskfiles/red/Taskfile.yaml:925`, inside `ec2:multi:` which starts at `:773`). A failed orchestrator launch prints ERROR and the task still exits 0 — scripted sweeps record a successful submit for an op that never started.
- **`task run CAPTURE=true` always fails at the capture step.** `Taskfile.yaml:205` passes `--wait-for-flush`, which does not exist; the real flag is the inverse `--no-wait-for-flush` (waiting is the default, `ares-cli/src/cli/benchmark.rs:41-45`). The printed recovery hint repeats the same bad flag. `task run` opens unconditionally with `ec2:stop` (`:167`) — that half fires on every invocation. The `lsof -ti:16379 | xargs kill` (`:194`) is **not** unconditional: its cmd block early-exits on `CAPTURE != true` (`:176`, default `false` at `:165`), so only `CAPTURE=true` kills whatever holds local port 16379 — without checking whose forward it is — before opening its own.
- **`ares --ec2 …` re-execs the whole CLI on the box before clap parses** (`ares-cli/src/main.rs:34-40`), polling to a 3000s deadline (`transport.rs:426`). Without `--ec2` the identical-looking command talks to **local** Redis and dies with connection-refused on a laptop.
- **`.taskfiles/ec2/scripts/setup.sh` sets no resource limits** despite the name — provisioning moved into the Ansible AMI bake (`.taskfiles/ec2/scripts/setup.sh:3-11`; invoked as the SSM payload from `.taskfiles/ec2/Taskfile.yaml:512`). There is no `scripts/setup.sh` at the repo root. Read `ansible/roles/redis/defaults/main.yml` and `ansible/roles/base/defaults/main.yml` for limits, not that script.
- `run_ssm_cmd` failing with `StatusDetails == Undeliverable` means PingStatus is likely ConnectionLost; recovery is `aws ec2 reboot-instances`, not a permissions fix (`run-ssm.sh:165-168`).
- **`run_ssm_cmd`'s 3rd arg is both the local poll budget and SSM's own `--timeout-seconds`** (`run-ssm.sh:119` default 120, passed through at `:131`) — there is no way to poll longer than SSM will run the command. `ec2:deploy` passes 1800 for the build (`.taskfiles/ec2/Taskfile.yaml:234`); **`ec2:exec` hardcodes 60** (`:1488`) with no override var, so any `CMD=` that needs longer than a minute dies there. For long work, either call `run_ssm_cmd` yourself after sourcing `run-ssm.sh` or background it on the box (`nohup … &`) and poll with a second `ec2:exec`.

---

## The post-deploy worker-restart requirement

**Installing a new binary without restarting the units ships nothing.** systemd keeps the pre-deploy process alive on the same NATS subscription, still executing the old code — a running process does not reload its own binary. That is the mechanism behind the "workers stuck on a 34h-old in-memory ares" wedge documented in `ec2:deploy`'s own comment block (`.taskfiles/ec2/Taskfile.yaml:239-249`).

A separate, often-conflated per-process cache: the worker's unavailable-tool map is an `Arc<Mutex<HashMap<String, UnavailableEntry>>>` created **once per worker process**, right after the NATS queue subscribe (`ares-cli/src/worker/tool_executor.rs:188-189`). It is **not permanent and not keyed by operation**:

| | Behavior | Source |
|---|---|---|
| What poisons it | ENOENT only (`ToolFailureKind::BinaryNotFound`). EAGAIN/ENOMEM/EMFILE/transient EACCES are explicitly **not** cached | `tool_executor.rs:374-378`, gate at `:656-659` |
| How long | exponential backoff 1 min → 5 min → 30 min → 4 h, final rung is a cap (one re-probe every 4 h per worker) | `UNAVAILABLE_BACKOFF`, `:343-356`; expiry check `:512-525` |
| What clears it early | a successful spawn removes the entry outright — a working tool self-heals | `:587-600` |

So a genuine miss survives across ops on the same worker process, but it does not survive a restart and it does not survive the backoff. Do not diagnose "tool disappeared forever" from this — check the current log strings and the actual binary on PATH. **`Tool binary not found (spawn failed)` is dead**: zero hits in `ares-*/src` at HEAD, so grepping it reports "no cascade" during a live cascade. Use `Tool binary not found (ENOENT)` (`ares-cli/src/worker/tool_executor.rs:677`), `Tool binary not found (ENOENT from worker)` (`ares-llm/src/agent_loop/runner.rs:608`) and `Skipping tool cached as ENOENT` (`tool_executor.rs:532`). Full cache semantics and the other verbatim strings: `references/tools-and-gates.md`.

```bash
# What deploy does for you — but only for units already --state=active
task ec2:exec EC2_NAME=kali-ares CMD='systemctl restart "ares@*.service"'
task ec2:exec EC2_NAME=kali-ares CMD='systemctl is-active ares@recon.service ares@cracker.service'

# Prove the binary landed — never trust the task's success message alone
task ec2:exec EC2_NAME=kali-ares CMD='sha256sum /usr/local/bin/ares; ls -l /usr/local/bin/ares'
task ec2:exec EC2_NAME=kali-ares CMD='strings /usr/local/bin/ares | grep -c "<a-literal-you-just-added>"'
```

On K8s the equivalent gate is `task remote:check TEAM=red` (`.taskfiles/remote/Taskfile.yaml:588-722`) — a sha256 local-vs-pod comparison that exits 1 on any DIFFERS/MISSING. **It is not part of `k8s:deploy`.** Run it explicitly.

---

## K8s `attack-simulation`

Namespace default `attack-simulation` (`Taskfile.yaml:124`); absent from `.env.example`, so effectively hardcoded. `.taskfiles/k8s` is a 5-task shim; `.taskfiles/remote` holds the 11 tasks doing the kubectl work.

### `task k8s:deploy` pipeline

`TEAM` defaults to `red` here (`.taskfiles/k8s/Taskfile.yaml:24`) but to `all` in every `remote:*` task (`.taskfiles/remote/Taskfile.yaml:16`) — a bare `task remote:rollout` restarts **both** teams.

| # | Step | Resolves to | Failure mode |
|---|---|---|---|
| 1 | `:remote:rust:build` | `cross` (macOS) / `cargo-zigbuild` / `cargo`, `--release --target <auto-arch>`, **no `-p ares-cli`** (`remote:557-568`) | arch auto-detect silently falls back to `x86_64-unknown-linux-gnu` when kubectl can't reach the cluster (`remote:526-534`) |
| 2 | `:remote:orchestrator:patch-wrapper` | `kubectl patch deployment ares-orchestrator --type=json --patch-file .taskfiles/remote/orchestrator-wrapper-patch.json` | **hardcodes the RED deployment** (`remote:582`) — `TEAM=blue` still patches red. `--type=json` `replace` is a no-op when unchanged, so re-running does not force a rollout |
| 3 | `:remote:rollout` | `kubectl rollout restart` deployments+statefulsets by component label, orchestrator separately | every status wait is `--timeout=60s … \|\| true` (`remote:395-397`) — "All pods restarted" is not readiness |
| 4 | `:remote:rust:deploy` | `kubectl cp target/<arch>/release/ares → /usr/local/bin/ares` + `chmod +x` (`remote:777-781`) | selects `--field-selector=status.phase=Running`, which still matches **Terminating** pods; the blue branch collects only the blue *orchestrator*, never blue workers (`remote:762-768`) |
| 5 | `k8s:sync:config` | `kubectl cp config/ares.yaml → /ares/config/ares.yaml` | hardcodes red selectors (`k8s:81,:87`); failures are WARN-only, exit 0 |
| 6 | *(not run)* `remote:check` | sha256 gate | must be invoked manually |

**The K8s build is unscoped and that is why it is slow.** `remote:rust:build` builds the **whole workspace** — `cross build --release --target <arch>` / `cargo zigbuild --release --target <arch>` with no `-p` (`remote:557-568`) — while the EC2 SSM payload is `cargo build --profile dev-deploy -p ares-cli` (`.taskfiles/ec2/Taskfile.yaml:218`). The build knobs differ accordingly and are not interchangeable between the two paths:

| Var | K8s (`remote:`) | EC2 (`ec2:`) |
|---|---|---|
| scope | whole workspace, `--release` | `-p ares-cli`, `--profile dev-deploy` |
| `MAX_OPEN_FILES` | `8192` (`remote:535`) | `65536` (`ec2:123`) |
| `CARGO_BUILD_JOBS` | `4` (`remote:536`) | `0` = unlimited (`ec2:124`) |
| where it builds | your laptop, cross-compiled | the box, natively |

No image build and no Helm/Flux apply in this path. Two competing config channels exist:

- `k8s:sync:config` — `kubectl cp config/ares.yaml → /ares/config/ares.yaml`, search path #2, immediate.
- `remote:rust:deploy:config` — creates/updates ConfigMap `ares-config` with key `config.yaml` and nothing else (`.taskfiles/remote/Taskfile.yaml:800-813`). **Where it lands in the pod is UNVERIFIED from this repo**: nothing here mounts it (`rg -l --hidden 'ares-config'` matches only that Taskfile and these reference docs), and there is no `k8s/`, `helm/`, `manifests/` or `charts/` directory — the mount is defined in the Flux/Helm repo. `/etc/ares/config.yaml` (search path #3) is the assumption, not a proven fact. It needs a pod restart either way.

**If** the ConfigMap does mount at path #3 **and** `ARES_CONFIG` is unset in the pod, the cp'd `/ares/config/ares.yaml` wins (`ares-core/src/config/mod.rs:20-24,84-106`) and a ConfigMap update appears to do nothing. Check `kubectl exec -n attack-simulation <pod> -c orchestrator -- env | grep ARES_CONFIG` before believing either channel — an `ARES_CONFIG` set in the pod spec beats both.

### Selectors and names worth grepping

| String | Kind | Where |
|---|---|---|
| `app.kubernetes.io/name=ares-orchestrator` / `…=ares-blue-orchestrator` | orchestrator selectors | `remote:20-21` |
| `ares.dreadnode.io/component=red-team` / `…=blue-team` | worker selectors | `remote:18-19` |
| `ares.dreadnode.io/role=<role>` | per-agent | `remote:450,489` |
| `ares.dreadnode.io/role != "atomic"` | jq exclusion | `k8s:89`, `remote:52` — **absent** from `rust:deploy`/`check`, which will therefore push into atomic pods |
| `app=redis`, secret `redis-secret` key `.data.password` | Redis pod + auth | `k8s:131-137` |
| container `orchestrator` | `-c` for every orchestrator exec/cp | `k8s:14`, `remote:10` |

`ares --k8s <ns>` re-execs as `kubectl exec -i -n <ns> deploy/<deploy> -- env RUST_LOG=error ares <args>` with **no `-c`**, landing in container 0. Deployment is auto-detected: any argv token equal to `blue` selects `ares-blue-orchestrator`, else `ares-orchestrator` (`ares-cli/src/transport.rs:143-149,160-172`).

### What `task k8s:reset` actually clears

Two halves: SIGTERM local processes matching the literal `red:multi` (`k8s:50-65` — nothing in-cluster), then `k8s:redis:clear`, a per-pattern server-side Lua SCAN+UNLINK (`k8s:153-172`).

| Pattern | Real? | Ground truth |
|---|---|---|
| `ares:operation:*:state` | **no** | prefix is `ares:op` (`ares-core/src/state/keys.rs:4`) |
| `ares:operation:*:checkpoint_time` | **no** | no such key is written anywhere |
| `ares:operations:*:status` | **no** | real key is `ares:op:{id}:status` (`keys.rs:87`) |
| `ares:lock:*` | yes | `keys.rs:7` |
| `ares:tasks:*`, `ares:results:*`, `ares:tool_exec:*` | legacy | red work now rides JetStream subjects `ares.tasks.{role}` / `ares.tools.exec.{role}` (`ares-core/src/nats.rs:7-9`) |
| `ares:operations` (DEL) | yes | the submit LIST (`ares-cli/src/ops/submit.rs:214`) |
| `ares:operation:active` (DEL) | yes | written by `ops submit --pin-active` (`submit.rs:199-202`) |
| `ares:op:*` | yes — **this is what actually wipes red state** | also removes `ares:op:active`, written by the orchestrator (`ares-cli/src/orchestrator/bootstrap.rs:360`) |

Both `ares:operation:active` and `ares:op:active` are real keys, written by different code paths — don't "fix" either as a typo.

**Not cleared by reset — these survive a "clean slate":** every `ares:blue:*` form (`ares:blue:inv:*`, `ares:blue:lock:*`, `ares:blue:investigations`, `ares:blue:active_investigations` — `keys.rs:100,104,181,184`), `ares:task_status:*` (`keys.rs:10`), `ares:heartbeat:*`, `ares:deferred:*`, and the NATS JetStream queues (nothing in `.taskfiles/k8s` or `/remote` mentions NATS at all). A queued blue investigation resurrects in your next op; stale heartbeats make dead workers look alive.

**`k8s:reset` is a shared-cluster nuke** — it kills every operator's ops, not just yours.

`task k8s:redis:list`'s "operation status keys" section scans the stale `ares:operations:*:status` (`k8s:201`) and therefore always prints `(none)`. Do not read that as "no ops".

### Other K8s traps

- **`TEAM=blue` is half-implemented**: patch-wrapper hardcodes red (`remote:582`), `sync:config` hardcodes red selectors (`k8s:81,87`), `rust:deploy` / `check` reach only the blue orchestrator (`remote:762-768`, `:636-644`). Blue workers keep the image binary forever.
- **`task remote:logs ROLE=orchestrator` blocks forever** — `FOLLOW` defaults to `true` (`remote:478`). Pass `FOLLOW=false`.
- **`task remote:status` never reports `credential_access`** — its loop is `for role in orchestrator recon cracker acl privesc lateral coercion` (`remote:445`) while `config/ares.yaml` defines 8 agents.
- The `NAMESPACE` var `k8s:deploy` passes to `:remote:rollout` (`k8s:32`) is never read; only `K8S_NAMESPACE` matters.
- `resolve_pod` returns the name **with** the `pod/` kind prefix and picks the newest match (`.taskfiles/k8s/scripts/resolve.sh:24-39`). Fine for `kubectl exec`, silently wrong pasted into `kubectl cp`.
- Root `task rust:build` (cargo debug) and `task remote:rust:build` (cross-compiled release for pods) are different things with confusable names; `k8s:deploy` calls the latter.

---

## Proxmox / Ludus attacker VM

**`proxmox` is not in the root Taskfile's `includes:`** — verified: `rg -n proxmox Taskfile.yaml` returns nothing, and `task --list-all` shows `obs:*` but no `proxmox:*`. Every `task proxmox:…` in the README, in the file's own header, and in memory is currently dead. Running the file directly with `-t` also breaks: it cross-calls `task remote:rust:build` (`:137`), `task proxmox:watch` (`:254`) and `task proxmox:report` (`:433`) by namespaced name, and its `DEFAULT_MODEL` var awks a repo-root-relative `config/ares.yaml` (`:51-52`). To use it, re-add a `proxmox:` entry to `includes:`.

Single VM running Redis + NATS + orchestrator + tools with `ARES_TOOL_DISPATCH=local`. All access is `ProxyJump` through the Proxmox host — the attacker VLAN is not routable from the laptop.

| Var | Default | Line |
|---|---|---|
| `PROXMOX_SSH_HOST` | `proxmox` (must exist in `~/.ssh/config`) | `:35` |
| `ATTACKER_VMID` / `ATTACKER_NAME` / `ATTACKER_USER` | `200` / `attacker-1` / `kali` | `:37-39` |
| `TEMPLATE_VMID` | `111` (the `ares-attack-box-proxmox` warpgate template) | `:41` |
| `BRIDGE` / `VLAN_TAG` | `vmbr1001` / `10` | `:43-44` |
| `RUST_TARGET` / `LOCAL_BIN` / `REMOTE_BIN` | `x86_64-unknown-linux-gnu` / `target/<t>/release/ares` / `/usr/local/bin/ares` | `:54-58` |
| `ATTACKER_IP` | `sh:` — SSH to Proxmox, `qm guest cmd <VMID> network-get-interfaces`, first non-loopback IPv4 | `:62-75` |

`ATTACKER_IP` is a `sh:` var, so it fires on **every** proxmox task invocation, including `proxmox:destroy` — which defaults to `ATTACKER_VMID=200`, the primary box, guarded only by `CONFIRM=yes` (`:622-638`).

`DEFAULT_IPS` (`:46`) and `DEFAULT_DOMAIN` (`:47`) are hardcoded real-lab values — **do not copy them into repo code, tests, or docs**; they are banned tokens (see below). Pass `IPS=` / `DOMAIN=` per run. There is no auto-discovery from the Ludus range.

`task proxmox:deploy` = `deploy:build` → `deploy:push` → `deploy:env` → `deploy:restart` (`:122-129`):

- **build** delegates to `task remote:rust:build`, which fires a `kubectl get nodes -n attack-simulation` arch probe it has no use for (go-task always evaluates `sh:` vars).
- **push** is `scp -J <proxmox>` then `sudo install -m 755 /tmp/ares /usr/local/bin/ares && ares --version` (`:148-152`). The precondition only checks the local file exists — it does not gate on the binary containing your change.
- **env** reconciles `ARES_LLM_MODEL` / `OPENAI_BASE_URL` / `OLLAMA_BASE_URL` into `/etc/default/ares` (0600 root), **deleting** any key whose resolved value is blank (`:164-181`). `config/ares.yaml` currently has no `llm:` block and the orchestrator model matches neither `ollama/*` nor `openai/*`, so both `*_BASE_URL` lines get stripped. It never writes `OPENAI_API_KEY` — that must be placed out of band, even though `proxmox:submit` sources the file specifically to obtain it.
- **restart** stops the latest op, pkills orchestrator + dispatcher, `KEYS 'ares:lock:*' | xargs redis-cli DEL`, then nohups `/usr/local/bin/ares-dispatch.sh` sourcing `/etc/default/ares` + `/etc/ares/secrets.env` (`:200-206`). **Deleting the locks makes any op that has not written `completed_at`/`red_completed_at` report `stopped`** — status precedence is completion timestamps first, lock existence only as the fallback (`ares-cli/src/ops/status.rs:28-34`; `is_running` is the lock check at `ares-core/src/state/reader.rs:179-187`). A finished op still reads `completed`; an in-flight one flips to `stopped`, which a concurrent `proxmox:watch` treats as terminal — it scp's back a partial report. (The SSM listing path inverts the precedence, checking the lock first, then `completed_at` — `.taskfiles/ec2/scripts/list-ops.sh:23-29`.)

**`/usr/local/bin/ares-dispatch.sh` is not in this repo** — `rg` finds it only as a path string inside the proxmox Taskfile. `proxmox:deploy` ships only the `ares` binary; the dispatcher wrapper must already be on the box or submits queue forever.

Three env files with three owners, easy to patch the wrong one: `/etc/default/ares` (proxmox Taskfile, sourced by the dispatcher), `/etc/ares/secrets.env` (crackd creds), `/etc/ares/env` (the ansible-managed `EnvironmentFile=` for `ares@.service`). `deploy:restart` sources only the first two.

---

## Local

```bash
task rust:build      # cargo build            -> target/debug/ares
task rust:release    # cargo build --release  -> target/release/ares   <- what ARES_CLI points at
task rust:check      # cargo check
task rust:test       # cargo test
```

`ARES_CLI` defaults to `./target/release/ares` (`Taskfile.yaml:122`). `task rust:deploy` is **K8s only** — it delegates to `remote:rust:deploy:quick` (`Taskfile.yaml:318-321`); it has nothing to do with EC2.

Rust is pinned to **1.94.0 by mise only** (`mise.toml`); there is no `rust-toolchain.toml`, so a shell without mise builds with whatever stable is installed while CI floats to `dtolnay/rust-toolchain@stable`. Gate clippy with an explicit newer toolchain before claiming a change is clean.

## Cross-compilation reality on Apple Silicon

Everything downstream is x86_64 Linux. Two independent code paths make the same non-obvious choice, and it inverts the usual advice:

**On macOS, prefer `cross` over `cargo-zigbuild`.** `aws-lc-sys` (pulled by rustls/reqwest) breaks under zigbuild's Zig `ar` wrapper on Darwin. `.taskfiles/ec2/Taskfile.yaml:152-154`, `.taskfiles/remote/Taskfile.yaml:554-559`. On Linux, prefer zigbuild (no Docker overhead).

On an arm64 host the `cross` path additionally sets, automatically:

| Export | Why | Source |
|---|---|---|
| `DOCKER_DEFAULT_PLATFORM=linux/amd64` | cross-rs images publish amd64 only; without it Docker reports "no match for platform in manifest" | `.taskfiles/ec2/Taskfile.yaml:320-323` |
| `RUST_MIN_STACK=16777216` | qemu-user segfaults rustc's default 8 MiB stack on short invocations like `rustc -vV` | `:326-327` |
| sccache **skipped** | its `rustc -vV` probe runs inside the emulated container and SIGSEGVs; override with `ARES_FORCE_SCCACHE=1` | `:306-311` |
| `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc`, `AWS_LC_SYS_CMAKE_BUILDER=1` | container ships the `x86_64-linux-gnu-` prefix; the CC builder trips a GCC memcmp bug | `:333-337` |

This whole class of pain is why `BUILD_TOOL` defaults to `remote` on the EC2 path — the box builds natively and none of it applies (`:69-72`). The K8s path has no remote option, so it eats the cross-compile. `MAX_OPEN_FILES` is pinned with `ulimit -n` before cargo because Zig 0.15+ rejects an unlimited *hard* fd limit mid-link and macOS defaults to `hard=RLIM_INFINITY` (`.taskfiles/ec2/Taskfile.yaml:276-285`).

K8s target arch is auto-detected from `kubectl get nodes … nodeInfo.architecture`, mapping `arm64`→`aarch64-unknown-linux-gnu`, `amd64`→`x86_64-unknown-linux-gnu`, with a silent x86_64 fallback (`.taskfiles/remote/Taskfile.yaml:526-534`). Do not pass `RUST_TARGET` by hand.

## EC2 command → K8s equivalent

| Intent | EC2 | K8s |
|---|---|---|
| Build + install the binary | `task ec2:deploy S3_BUCKET=…` | `task k8s:deploy [TEAM=red\|blue]` |
| Build only | (implicit in `ec2:deploy`) | `task remote:rust:build` |
| Install only | (implicit; local path pulls from S3) | `task remote:rust:deploy [TEAM=…]` |
| Build + install, no rollout | `BUILD_TOOL=…` + `SKIP_RESTART=true` | `task remote:rust:deploy:quick` |
| **Verify what landed** | `task ec2:exec CMD='sha256sum /usr/local/bin/ares'` | `task remote:check [TEAM=…]` (exits 1 on mismatch) |
| Push config | `task ec2:deploy:config` | `task k8s:sync:config` (or `remote:rust:deploy:config` for the ConfigMap) |
| Restart workers | `task ec2:exec CMD='systemctl restart "ares@*.service"'` | `task remote:rollout [TEAM=…]` — **then re-run `rust:deploy`** |
| Restart infra | `task ec2:restart` (orchestrator + redis/nats/pg) | no equivalent — pods are managed |
| Health / process state | `task ec2:status` | `task remote:status` (omits `credential_access`) |
| Logs, one-shot | `task ec2:logs:fetch ROLE=<role>` / `ec2:exec CMD='tail -n 200 …'` | `task remote:logs ROLE=<role> FOLLOW=false` |
| Logs, follow | `task ec2:logs` (**agent-unusable**) | `task remote:logs ROLE=<role>` (FOLLOW defaults true) |
| Wipe operation state | `task ec2:launch FLUSH_REDIS=true` (also relaunches) or `ec2:exec CMD='redis-cli FLUSHDB'` | `task k8s:reset` / `k8s:redis:clear` (**shared-cluster nuke**) |
| List ops without a local binary | `task ec2:ops:ids` | `task k8s:redis:list` (its status section is stale) |
| Run any `ares` subcommand remotely | `ares --ec2 kali-ares <cmd>` | `ares --k8s attack-simulation <cmd>` |
| Arbitrary shell | `task ec2:exec CMD='…'` | `kubectl exec -n attack-simulation <pod> -- …` |

No EC2 equivalent exists for `k8s:reset` (single box vs shared cluster); no K8s equivalent exists for `ec2:setup`, `ec2:history-db`, `ec2:logrotate` or `ec2:setup:tools` (AMI-baked / cluster-managed).

## Test-data rule

Allowed values only — see `references/tools-and-gates.md#test-conventions` for the authoritative list, the three-enforcer divergence table and the coverage holes. The one deploy-specific consequence: the sweep exempts `Taskfile.yaml`, `.taskfiles/`, `config/ares.yaml`, `.claude/`, `.gemini/`, `demo/` and `safe/` (`scripts/goad-token-sweep.sh:36`), which is exactly why the proxmox and root Taskfiles legally hold real lab defaults you must never propagate outward.

## Route elsewhere

| Question | Go to |
|---|---|
| "This op is stuck / slow / crashing" | skill `ares-debug` (its Redis key-type table at `SKILL.md:112` agrees with `references/state-and-redis.md`; the `:creds` vs `:credentials` warning above it at `:110` is correct and load-bearing) |
| "Launch / monitor / report an op" (≥3 dependent commands) | agent `ares-operator`; single commands run inline |
| "Where is X implemented in the crates" / build errors | agent `rust-ares-expert` |
| "What does this credential unlock in the lab" | agent `dreadgoad-expert` — **known to fail on every call** via model-level safeguards. Read the DreadGOAD docs directly; do not reword the prompt to evade |
| Running a diversity sweep | skill `attack-path-diversity-sweep` |
| The mistakes this assistant actually makes on this repo | `references/hard-won-lessons.md` — read it first |
