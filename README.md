# Ares - Autonomous Security Operations Agent

<!-- BEGIN_AUTO_BADGES -->

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/dreadnode/ares/blob/main/LICENSE)
[![Tests](https://github.com/dreadnode/ares/actions/workflows/rust.yaml/badge.svg)](https://github.com/dreadnode/ares/actions/workflows/rust.yaml)
[![Pre-Commit](https://github.com/dreadnode/ares/actions/workflows/pre-commit.yaml/badge.svg)](https://github.com/dreadnode/ares/actions/workflows/pre-commit.yaml)
[![codecov](https://codecov.io/github/dreadnode/ares/graph/badge.svg)](https://codecov.io/github/dreadnode/ares)

<!-- END_AUTO_BADGES -->

LLM-coordinated autonomous security operations platform with two modes:

**Red Team** - 7 specialized agents orchestrated by an LLM coordination loop that autonomously chains 64+ Active Directory attack tools across the full kill chain, from recon through domain dominance. 14 concurrent automation modules monitor discovered state and dispatch attack chains without manual sequencing.

**Blue Team** - Multi-agent SOC investigation system that queries live Loki logs and Prometheus metrics, runs MITRE ATT&CK-mapped detection templates, tracks lateral movement, and writes detection rules back to Grafana. Evidence-driven chaining automatically dispatches follow-up investigations as new indicators surface.

## Table of Contents

- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [EC2 workflow (kali-ares)](#ec2-workflow-kali-ares)
- [CLI Reference](#cli-reference)
- [Red Team Operations](#red-team-operations)
- [Blue Team Investigations](#blue-team-investigations)
- [Benchmark Replay](#benchmark-replay)
- [Infrastructure](#infrastructure)
- [Development](#development)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [License](#license)

## Architecture

Ares is a Rust workspace that compiles to a single `ares` binary with
subcommands (`ares ops`, `ares orchestrator`, `ares worker`, `ares blue`,
`ares history`, `ares config`):

| Crate        | Purpose                                                   |
| ------------ | --------------------------------------------------------- |
| `ares-cli`   | Unified binary - CLI, orchestrator, and worker            |
| `ares-core`  | Shared models, state management, Redis schema, telemetry  |
| `ares-llm`   | LLM providers (Anthropic, OpenAI, Ollama) + tool registry |
| `ares-tools` | Tool dispatch and execution framework                     |

### Red Team Multi-Agent System

```
Local (this machine)              Remote (K8s or EC2)
────────────────────              ───────────────────
ares --k8s / --ec2        →      ares orchestrator (LLM coordination loop)
  or `task` commands              ares worker x7 (recon, credential_access,
                                    cracker, acl, privesc, lateral, coercion)
                                  Redis (state store + message broker)
```

The orchestrator dispatches tasks to specialized worker agents via Redis
queues. Workers execute tools (nmap, secretsdump, hashcat, etc.) and push
results back. The orchestrator never executes exploitation tools directly.

**Agent Roles:**

- **RECON**: Network scanning, BloodHound, user/share enumeration
- **CREDENTIAL_ACCESS**: secretsdump, kerberoasting, AS-REP roasting, password spray
- **CRACKER**: Offline hash cracking with hashcat/john
- **ACL**: BloodHound collection, ACL edge enumeration and ranked candidate paths, per-edge ACL primitives (shadow credentials, WriteDACL)
- **PRIVESC**: ADCS (ESC1-8), delegation attacks, MSSQL exploitation
- **LATERAL**: PSExec/WMI/WinRM, credential harvesting from compromised hosts
- **COERCION**: Responder, ntlmrelayx, PetitPotam

### Blue Team Multi-Agent System

```
Local (this machine)              Remote (K8s or EC2)
────────────────────              ───────────────────
ares --k8s / --ec2        →      ares orchestrator (investigation coordination)
  or `task` commands              ares worker x4 (triage, threat_hunter,
                                    lateral_analyst, escalation_triage)
                                  Redis (state store + message broker)
                                  Grafana (Loki logs + Prometheus metrics)
```

The blue orchestrator dispatches investigation tasks to specialized agents
via Redis queues. Agents query Loki/Prometheus for evidence and report
findings back. The orchestrator chains follow-up investigations based on
discovered evidence types.

**Agent Roles:**

- **ORCHESTRATOR**: Investigation lifecycle management, evidence-driven task chaining, report generation
- **TRIAGE**: Initial alert assessment, severity routing, first-pass IOC extraction, datasource discovery
- **THREAT_HUNTER**: Deep investigation with MITRE-mapped detection templates, evidence validation, attack chain reconstruction
- **LATERAL_ANALYST**: Multi-host compromise tracking, lateral movement graph construction, scope expansion
- **ESCALATION_TRIAGE**: High/critical severity review, escalation decisions, cross-investigation correlation

## Quick Start

**Prerequisites:**

- [Rust](https://rustup.rs/) (stable toolchain)
- [Task](https://taskfile.dev/installation/) (recommended)
- [1Password CLI](https://developer.1password.com/docs/cli/get-started/)
  for credential management (optional - `.env` file also supported)
- Redis (for orchestrator/worker communication)

**Build:**

```bash
# Clone and build
git clone https://github.com/dreadnode/ares.git && cd ares
task rust:build          # debug build
task rust:release        # release build (recommended)

# Verify
./target/release/ares --help
```

**Configure:**

```bash
# Option 1: .env file
cp .env.example .env
# Edit .env with your API keys (ANTHROPIC_API_KEY, GRAFANA_SERVICE_ACCOUNT_TOKEN, etc.)

# Option 2: 1Password (auto-loaded by CLI)
# Configure items in 1Password, CLI loads them at startup

# Verify configuration
task ares:config:check
```

## EC2 workflow (kali-ares)

The default deployment for ops is EC2 (`kali-ares` in the `lab` account,
`us-west-1`). Observability lives in the `infrastructure` account's plundr
cluster; the box reaches it directly, the laptop reaches it via kubectl
port-forward.

**One-time setup:**

```bash
# 1. AWS SSO — lab (kali-ares + secret) + infrastructure (plundr EKS)
aws sso login --profile lab
aws sso login --profile infrastructure

# 2. Register the plundr EKS context (for obs:forward)
aws eks update-kubeconfig --profile infrastructure --region us-west-2 \
  --name dev-argonaut --alias plundr

# 3. Apple Silicon: enable Docker Desktop → Settings → General →
#    "Use Rosetta for x86_64/amd64 emulation" (task ec2:deploy cross-compiles
#    amd64 under Rosetta; QEMU segfaults rustc)

# 4. Populate .env from AWS Secrets Manager
./scripts/env-from-secrets.sh
```

**Common gotchas:**

- Tailscale MagicDNS (100.100.100.100) will eat EKS API endpoint lookups if
  the node isn't approved by the tailnet admin. Sign in to Tailscale or add
  a `/etc/hosts` override for the EKS API endpoint.
- `task ec2:deploy` must use an S3 bucket in the **same account** as
  `kali-ares` (currently the lab account). Pass `S3_BUCKET=ares-benchmark-us-west-1`
  when deploying, or set it in `.env`.

**Run an op:**

```bash
task run                              # fire-and-forget (blue enabled by default)
task run WAIT=true                    # wait for op completion, auto-fetch red report
task run WAIT=true CAPTURE=true       # wait + capture Loki snapshot to S3 (waits
                                      #   for Loki flush, ~5 min after op end);
                                      #   prints the exact benchmark:replay command
```

**Evaluate blue via replay:**

```bash
# Provisions a fresh replay stack, imports the captured Loki timeline,
# runs a blue investigation against it, scores, tears down. Deterministic —
# rerun anytime without re-running red.
task benchmark:replay OP_ID=op-YYYYMMDD-HHMMSS
```

Reports land in `./reports/blue/investigations/inv-*.md` with IOC-detection
score, MITRE technique coverage, and grade.

**Blue tooling on the laptop (optional):**

```bash
# Port-forward plundr Loki+Grafana to localhost so ares blue commands
# work from the laptop.
task obs:forward     # keep running in a separate terminal
task obs:status      # health check the tunnels
```

## CLI Reference

The `ares` binary is the unified interface for all operations. It supports
transparent remote execution via transport flags.

### Transport Flags

```bash
# K8s: execute on orchestrator pod via kubectl
ares --k8s ares-red ops loot --latest
ares --k8s ares-blue blue status --latest

# EC2: execute on instance via AWS SSM
ares --ec2 kali-ares ops loot --latest

# Override defaults
ares --k8s ares-red --k8s-deploy ares-orchestrator ops list
ares --ec2 kali-ares --ec2-profile prod --ec2-region us-east-1 ops list
```

| Flag                      | Default     | Description                                    |
| ------------------------- | ----------- | ---------------------------------------------- |
| `--k8s <NAMESPACE>`       |             | K8s namespace (triggers kubectl exec)          |
| `--k8s-deploy <NAME>`     | auto-detect | K8s deployment name                            |
| `--ec2 <NAME_TAG>`        |             | EC2 Name tag (triggers SSM execution)          |
| `--ec2-profile <PROFILE>` | `lab`       | AWS CLI profile                                |
| `--ec2-region <REGION>`   | `us-west-1` | AWS region                                     |
| `--env-file <PATH>`       | auto `.env` | Load env vars from file                        |
| `--secrets-from <SOURCE>` |             | Load secrets from provider (e.g., `1password`) |

### Commands

**`ops`** - Red team operation management:

| Subcommand                                         | Description                     |
| -------------------------------------------------- | ------------------------------- |
| `submit`                                           | Submit a new red team operation |
| `list`                                             | List all operations             |
| `status [--latest]`                                | Operation status                |
| `loot [--latest] [--watch N] [--diff]`             | Credentials, hashes, hosts      |
| `tasks [--latest] [--status STATUS] [--role ROLE]` | Task listing                    |
| `runtime [--latest]`                               | Operation runtime               |
| `report [--latest] [--regenerate]`                 | Generate report                 |
| `inject-credential`                                | Inject credential into state    |
| `inject-hash`                                      | Inject hash into state          |
| `inject-host`                                      | Inject host into state          |
| `inject-vulnerability`                             | Inject vulnerability into state |
| `inject-domain-sid`                                | Inject domain SID               |
| `stop [--latest]`                                  | Graceful shutdown               |
| `kill [--all]`                                     | Stop + delete operations        |
| `delete <ID> --force`                              | Delete operation data           |
| `cleanup [--max-age-hours N]`                      | Clean old checkpoints           |
| `export-detection [--latest]`                      | Detection playbook export       |
| `correlate`                                        | Red-blue correlation analysis   |
| `evaluate`                                         | Evaluate blue team detection    |

**`blue`** - Blue team investigation management:

| Subcommand                                | Description                           |
| ----------------------------------------- | ------------------------------------- |
| `submit <ALERT_JSON>`                     | Submit investigation from alert       |
| `from-operation [--latest]`               | Submit from red team operation alerts |
| `watch [--poll-interval N]`               | Continuous poll mode                  |
| `list`                                    | List investigations                   |
| `status [--latest]`                       | Investigation status                  |
| `evidence [--latest]`                     | Collected evidence                    |
| `techniques [--latest]`                   | MITRE ATT&CK techniques               |
| `triage-status [--latest]`                | Triage decision audit trail           |
| `operation-status [--latest] [--watch N]` | Aggregate status                      |
| `report [--latest] [--regenerate]`        | Generate report                       |
| `cleanup [--all] [--max-age-hours N]`     | Clean investigations                  |

**`history`** - Historical queries (PostgreSQL):

| Subcommand                            | Description             |
| ------------------------------------- | ----------------------- |
| `list [--domain D] [--since-days N]`  | List past operations    |
| `get <ID>`                            | Detailed operation info |
| `search-creds [--domain D] [--admin]` | Search credentials      |
| `search-hashes [--cracked]`           | Search hashes           |
| `mitre-coverage [--since-days N]`     | Technique coverage      |
| `cost [--since-days N]`               | Token usage and cost    |

**`config`** - Configuration management:

| Subcommand                         | Description          |
| ---------------------------------- | -------------------- |
| `show [--models]`                  | Show resolved config |
| `validate`                         | Validate config file |
| `set-model <ROLE> <MODEL> [--all]` | Set LLM model        |

## Red Team Operations

### Start an Operation

```bash
# Via Taskfile (recommended)
task red:multi TARGET=dreadgoad DOMAIN=contoso.local

# Via CLI directly
ares ops submit dreadgoad contoso.local \
  --ips 192.168.58.10,192.168.58.11 \
  --model gpt-5.2 --follow

# EC2
task ec2:launch DOMAIN=contoso.local TARGETS=192.168.58.10,192.168.58.11
```

### Monitor

```bash
ares --k8s ares-red ops status --latest
ares --k8s ares-red ops loot --latest --watch 10
ares --k8s ares-red ops tasks --latest --status failed
ares --k8s ares-red ops runtime --latest
task remote:logs ROLE=orchestrator
```

### Inject State (Unblock Stuck Operations)

```bash
ares --k8s ares-red ops inject-credential op-xxx administrator P@ssw0rd \
  --domain contoso.local

ares --k8s ares-red ops inject-hash op-xxx krbtgt \
  "aad3b435b51404eeaad3b435b51404ee:313b6f423a..." \
  --domain contoso.local --aes-key "f8b6c5e4d3a2b109..."

ares --k8s ares-red ops inject-host op-xxx 192.168.58.20 dc01.fabrikam.local

ares --k8s ares-red ops inject-domain-sid op-xxx \
  --domain child.contoso.local --sid "S-1-5-21-..."
```

### Reports

```bash
ares --k8s ares-red ops report --latest
ares --k8s ares-red ops report --latest --regenerate
ares --k8s ares-red ops export-detection --latest
```

### Operation Phases

1. **Initial Access** - RECON scans, COERCION starts Responder, CREDENTIAL_ACCESS sprays
2. **Enumeration** - BloodHound, Kerberoasting, AS-REP roasting, hash cracking
3. **Privilege Escalation** - ADCS exploitation, delegation attacks, ACL edge abuse (individual rights; end-to-end ACL escalation is not yet demonstrated)
4. **Lateral Movement** - PSExec/WMI/WinRM, credential harvesting on compromised hosts
5. **Domain Dominance** - DCSync, golden ticket generation, operation report

See [Red Team Architecture](docs/red.md) for detailed documentation and
[Attack Strategy Configuration](docs/strategy.md) for technique weights,
path diversity controls, and strategy presets.

## Blue Team Investigations

The blue team runs autonomous SOC investigations against Grafana alerts. Each
investigation dispatches specialized agents that query Loki and Prometheus,
extract IOCs, validate evidence against query results, map findings to MITRE
ATT&CK techniques, and climb the Pyramid of Pain from hash values toward TTPs.

### Investigation Stages

1. **Triage** - Parse alert, discover datasources, first-pass IOC extraction via Loki/Prometheus (8-12 queries)
2. **Causation** - Root cause analysis, precursor attack identification, attack chain reconstruction (14 queries)
3. **Lateral Movement** - Multi-host scope expansion, lateral movement graph construction, pivot detection (20 queries)
4. **Synthesis** - Evidence consolidation, MITRE mapping, Pyramid of Pain assessment, report generation (20 queries)

### Key Capabilities

- **Detection Templates**: Pre-built MITRE-mapped LogQL queries covering credential dumping (T1003), DCSync (T1003.006), Kerberoasting (T1558), lateral movement (T1550.002), ADCS exploitation (T1649), golden tickets (T1558.001), and more
- **4 Question Engines**: Precursor attack chain, MITRE Navigator, Pyramid of Pain climber, and detection recipes drive investigation toward complete attack chain coverage
- **Evidence Validation**: Auto-extracted IOCs from query results are validated against recent data with confidence scoring (15% penalty for unvalidated evidence)
- **Investigation Learning**: Historical investigation store tracks query effectiveness, false positive patterns, and technique frequency across investigations
- **Red-Blue Correlation**: Links red team attack activities to blue team detections, surfaces detection gaps, and scores coverage by MITRE technique
- **Evidence-Driven Chaining**: Discovered evidence types automatically trigger follow-up investigations (e.g., `credential_access` evidence chains to threat hunt, `lateral_movement` chains to lateral analysis)

### Quick Start

```bash
# Start investigation from latest red team operation
task blue:once LATEST=true

# Or via K8s multi-agent orchestrator
task blue:multi:remote LATEST=true

# Monitor progress
task blue:multi:status LATEST=true
task blue:multi:operation-status LATEST=true WATCH=10

# View results
task blue:multi:evidence LATEST=true
task blue:multi:techniques LATEST=true
task blue:reports:consolidate LATEST=true
```

### Key Tasks

| Task                       | Description                              |
| -------------------------- | ---------------------------------------- |
| `blue:once`                | Single investigation from red op (local) |
| `blue:once:remote`         | Single investigation (K8s)               |
| `blue:multi:remote`        | Multi-agent investigation (K8s)          |
| `blue:investigate`         | Submit a specific alert JSON file        |
| `blue:poll`                | Continuous poll mode                     |
| `blue:multi:status`        | Investigation status                     |
| `blue:multi:evidence`      | Collected evidence                       |
| `blue:multi:techniques`    | MITRE techniques identified              |
| `blue:multi:logs`          | Follow blue team logs                    |
| `blue:reports:consolidate` | Generate report from Redis state         |
| `blue:playbook`            | Export detection playbook                |
| `blue:multi:cleanup`       | Clean up old investigations              |

See [Blue Team Documentation](docs/blue.md) for full command reference.

## Benchmark Replay

Snapshot a completed red op's observability state and re-run the blue team
against it, so iterative blue-side changes are comparable across runs. The
workflow splits by concern:

- `ares benchmark capture` — dumps Loki, Prometheus (as TSDB blocks), Grafana
  dashboards, and fired alerts to S3. `--wait-for-flush` blocks until Loki's
  ingester lands the attack window (otherwise the snapshot silently misses it).
- `task benchmark:replay:provision` / `:teardown` — EC2 lifecycle for the
  replay-stack box (all AWS-CLI orchestration in Taskfile, not Rust).
- `ares benchmark run --stack-ip <ip>` — submits the investigation, polls
  Redis, computes the score. `--seed` / `--temperature` / `--replicates` cut
  LLM sampling noise so a real score change is distinguishable from variance.
- `task benchmark:replay:run STACK_IP=<ip> OP_ID=<op>` — runs one investigation
  against an already-provisioned stack, no teardown. Reuses the stack across
  many runs.
- `task benchmark:replay OP_ID=<op>` — end-to-end wrapper: provision → run →
  teardown (deferred via shell `trap`, fires on failure too).
- `task benchmark:replay:loop OP_ID=<op> ITERATIONS=<n>` — provision once,
  iterate N times, teardown. Optional `HOOK=<cmd>` runs between iterations
  with `STACK_IP` / `OP_ID` / `ITERATION` exported — for a tuning driver
  (e.g. Vibe Gepa) to rewrite prompts in place without reprovisioning.
- `task benchmark:generalize` — sweeps the held-out attack set from
  `benchmarks/holdout.yaml` and reports per-op + aggregate score. The
  held-out corpus is off-limits to any tuning process; it's the only
  measure of generalization.

```bash
# Capture from a completed op
ares benchmark capture op-20260706-123045 --wait-for-flush

# List captured snapshots
ares benchmark list

# End-to-end replay
task benchmark:replay OP_ID=op-20260706-123045

# Or split provision/run/teardown when iterating against one stack
eval "$(task benchmark:replay:provision OP_ID=op-20260706-123045 | grep -E '^(STACK_IP|INSTANCE_ID)=')"
task benchmark:replay:run STACK_IP="$STACK_IP" OP_ID=op-20260706-123045
task benchmark:replay:teardown INSTANCE_ID="$INSTANCE_ID"

# Tuning loop: 8 iterations against a warm stack, prompt update between each
task benchmark:replay:loop OP_ID=op-20260706-123045 ITERATIONS=8 \
  HOOK='python -m vibe_gepa.update --op-id "$OP_ID" --iter "$ITERATION"'

# K-of-N averaging: 5 replicates against a warm stack, seeded for determinism
# Mean/stddev/min/max land in <output-dir>/<session>-summary.json
task benchmark:replay:run STACK_IP="$STACK_IP" OP_ID=op-20260706-123045 \
  REPLICATES=5 SEED=42 OUTPUT_DIR=./reports

# Generalization sweep against the held-out set
task benchmark:generalize FAIL_UNDER=0.6
```

Provisioning prefers a pre-baked `ares-replay-stack` AMI
(`warpgate build ares-replay-stack --only 'ami.*'`); it falls back to stock
AL2023 if none is published (set `BENCHMARK_REQUIRE_BAKED_AMI=1` to fail
instead).

See [Benchmark Replay Operator Guide](docs/benchmark-replay.md) for env-var
setup, replay modes (`timeline` vs `static`), AMI baking, and troubleshooting.

## Infrastructure

### Repository Layout

```text
ares-cli/                         # Unified binary (CLI + orchestrator + worker)
ares-core/                        # Shared library (models, state, telemetry)
ares-llm/                         # LLM provider abstraction
ares-tools/                       # Tool dispatch framework

config/                           # Configuration files
  ares.yaml                       # Master config (models, timeouts, capabilities)

ansible/                          # Ansible collection: dreadnode.nimbus_range v1.5.0
  playbooks/ares/                 # Agent provisioning playbooks
  roles/                          # 14 roles (8 agent tool roles + base + infra)

warpgate-templates/               # Container image build templates
  ares-python-base/               # Base: Kali + security tool dependencies
  ares-python-orchestrator/       # Orchestrator: Rust binary + Redis
  ares-python-worker/             # Generic worker
  ares-python-{recon,credential-access,cracker,acl,privesc,lateral-movement,coercion}-agent/
  ares-python-blue-{agent,triage-agent,threat-hunter-agent,lateral-analyst-agent}/

infra/                            # Terragrunt deployment configs
modules/                          # Terraform modules
```

### Building

```bash
# Rust binaries
task rust:build              # debug
task rust:release            # release
task rust:test               # tests
task rust:check              # compile check

# Deploy to K8s
task remote:rust:deploy              # cross-compile + kubectl cp
task remote:rust:deploy:config       # push config YAML as ConfigMap
task remote:check                    # verify binary sync

# Deploy to EC2
task ec2:deploy                      # cross-compile + S3 + SSM install
task ec2:deploy:config               # push config.yaml
```

### Container Images

Built with [Warpgate](https://github.com/cowdogmoo/warpgate). Each template
uses Ansible playbooks for tool provisioning:

```bash
PROVISION_REPO_PATH=./ansible warpgate build warpgate-templates/ares-python-base
PROVISION_REPO_PATH=./ansible warpgate build warpgate-templates/ares-python-recon-agent
```

See [Infrastructure Reference](docs/infrastructure.md) for full deployment
documentation.

## Development

### Prerequisites

- [Rust](https://rustup.rs/) (stable)
- [pre-commit](https://pre-commit.com/)
- [Task](https://taskfile.dev/installation/) (recommended)

### Build & Test

```bash
task rust:build          # debug build
task rust:release        # release build
task rust:test           # run tests
task rust:check          # compile check only
cargo clippy --workspace # lint
cargo fmt --all          # format
```

### Deploy & Test on Remote

```bash
# Deploy to K8s pods
task remote:rust:deploy

# Verify binaries match
task remote:check

# Check pod health
task remote:status
```

#### EC2 Clean Test Cycle

Full reset on an EC2 instance: stop workers and any running op, deploy
fresh binaries, wipe Redis, restart workers, then launch a new operation.
EC2 equivalent of the K8s `task -y k8s:reset && task -y k8s:deploy && task -y red:multi`
shortcut.

`ec2:deploy` requires `S3_BUCKET` (binary staging bucket) — export it or
pass on each invocation.

```bash
export S3_BUCKET=your-deploy-bucket

EC2_NAME=kali-ares
TARGET=dreadgoad
BLUE_ENABLED=1

task ec2:stop       EC2_NAME=$EC2_NAME                                 # stop workers
task ec2:stop-op    EC2_NAME=$EC2_NAME LATEST=true                     # stop running op
task -y ec2:deploy  EC2_NAME=$EC2_NAME                                 # cross-compile + ship binary
task ec2:exec       EC2_NAME=$EC2_NAME CMD="redis-cli FLUSHALL"        # wipe Redis
task ec2:start      EC2_NAME=$EC2_NAME                                 # start workers
task -y red:ec2:multi TARGET=$TARGET EC2_NAME=$EC2_NAME BLUE_ENABLED=$BLUE_ENABLED
```

If the host shell raises `nofile` above ~65k (some tuned shells go to
1048576), the zig 0.16 linker invoked by cross-compilation will fail.
Clamp before running `ec2:deploy`: `ulimit -n 65536`.

## Configuration

### Config File

The master config lives at `config/ares.yaml` and is the **single source of truth** for the model. It defines:

- **[Attack strategy](docs/strategy.md)** - technique weights, path diversity, completion modes
- Per-role LLM model assignments
- Optional LLM endpoint overrides (`llm.ollama_base_url` / `llm.openai_base_url`)
- Agent capabilities and tool inventories
- Operation timeouts and limits
- Vulnerability exploitation priorities
- Recovery and context management settings

```bash
ares config show --models              # show model assignments
ares config set-model orchestrator gpt-5.2
ares config set-model --all gpt-5.2
ares config validate
```

#### Changing the model

Edit `config/ares.yaml` once — everything else derives from it, so you never
hand-edit Taskfiles or the attacker env file:

```bash
task config:set-model-all -- anthropic/claude-opus-4-8   # writes agents.*.model
```

- **Taskfile defaults** (`MODEL`, proxmox `DEFAULT_MODEL`) are read from
  `agents.orchestrator.model` at runtime — no hardcoded value. A per-invocation
  `MODEL=<spec>` still overrides.
- **Attacker VM env** (`/etc/default/ares`, which wins at runtime) is regenerated
  from config by `task proxmox:deploy:env` — run via `task proxmox:deploy`
  (build → push → env → restart) or standalone followed by `deploy:restart`.

For local / OpenAI-compatible models, also set the endpoint in the `llm:` block
(commented out by default). `deploy:env` writes the matching `*_BASE_URL` for the
active provider and **strips the stale one** so a hosted API never inherits a dead
LAN endpoint:

```yaml
llm:
  # ollama_base_url: "http://192.168.58.25:11434"   # for ollama/<model>
  # openai_base_url: "http://192.168.58.25:8080/v1" # for openai/<model> (llama-server, vLLM, Gemini-compat)
```

### Environment Variables

**LLM Providers** (at least one required):

| Variable            | Default                  | Description                       |
| ------------------- | ------------------------ | --------------------------------- |
| `ANTHROPIC_API_KEY` |                          | Anthropic API key (Claude models) |
| `OPENAI_API_KEY`    |                          | OpenAI API key (GPT models)       |
| `OLLAMA_BASE_URL`   | `http://localhost:11434` | Ollama server URL (`ollama/<model>`)              |
| `OPENAI_BASE_URL`   |                          | Override for OpenAI-compatible endpoints (llama-server, vLLM, Gemini's `/v1beta/openai`) |

> On the proxmox attacker VM these base URLs are populated in `/etc/default/ares`
> by `task proxmox:deploy:env` from the `llm:` block in `config/ares.yaml` — see
> [Changing the model](#changing-the-model).

**Model Selection:**

The base model comes from `config/ares.yaml` (see [Changing the model](#changing-the-model)).
These env vars override it; they apply in different contexts rather than as one
linear chain:

| Variable                     | Applies to                  | Description                                                                 |
| ---------------------------- | --------------------------- | -------------------------------------------------------------------------- |
| `ARES_LLM_MODEL`             | orchestrator process        | Wins over the config YAML at runtime. Auto-synced from config by `proxmox:deploy:env`. |
| `ARES_BLUE_LLM_MODEL`        | blue team orchestrator      | Blue-side model (falls back to the red model if unset).                     |
| `ARES_MODEL_FOR_<ROLE>`      | orchestrator (per role)     | Routes one role to a cheaper/different model, e.g. `ARES_MODEL_FOR_RECON=openai/gpt-5-mini`. Logged at INFO when it fires. |
| `ARES_MODEL_FOR_DEFAULT`     | orchestrator (per role)     | Applies to roles not individually overridden by `ARES_MODEL_FOR_<ROLE>`.    |
| `ARES_ORCHESTRATOR_MODEL` / `ARES_MODEL` | `ops submit` (no `--model`) | Fallback the submit CLI uses when `--model` is omitted: `--model` > `ARES_ORCHESTRATOR_MODEL` > `ARES_MODEL`. |

Precedence is per-context, not a single chain:

- **`ops submit`** picks the op's model: `--model` flag > `ARES_ORCHESTRATOR_MODEL` > `ARES_MODEL`.
- **orchestrator process** (standalone / proxmox): `ARES_LLM_MODEL` > `config/ares.yaml`.
- **per-role** (within the orchestrator): `ARES_MODEL_FOR_<ROLE>` > `ARES_MODEL_FOR_DEFAULT` > the resolved base model.

**Infrastructure:**

| Variable             | Default                    | Description                                           |
| -------------------- | -------------------------- | ----------------------------------------------------- |
| `ARES_REDIS_URL`     | `redis://127.0.0.1:6379/0` | Redis URL (falls back to `REDIS_URL`)                 |
| `ARES_CONFIG`        | auto-discovered            | Path to `ares.yaml` config file                       |
| `ARES_DATABASE_URL`  |                            | PostgreSQL URL (persistent store, disabled if absent) |
| `ARES_TOOL_DISPATCH` | `redis`                    | Set to `local` for in-process tool execution          |

**Blue Team:**

| Variable                        | Default                 | Description                            |
| ------------------------------- | ----------------------- | -------------------------------------- |
| `ARES_BLUE_ENABLED`             |                         | Set to `1` to activate blue team       |
| `ARES_BLUE_MAX_STEPS`           | `75`                    | Max agent loop steps per investigation |
| `ARES_REPORT_DIR`               | `$HOME/ares_reports`    | Report output directory                |
| `GRAFANA_URL`                   | `http://localhost:3000` | Grafana instance URL                   |
| `GRAFANA_SERVICE_ACCOUNT_TOKEN` |                         | Grafana service account token          |
| `LOKI_URL`                      | `http://localhost:3100` | Loki endpoint for LogQL queries        |
| `LOKI_AUTH_TOKEN`               |                         | Bearer token for Loki auth             |
| `PROMETHEUS_URL`                | `http://localhost:9090` | Prometheus endpoint for PromQL         |

**Orchestrator Tuning:**

| Variable                       | Default | Description                                 |
| ------------------------------ | ------- | ------------------------------------------- |
| `ARES_OPERATION_ID`            |         | Operation ID (or JSON payload with targets) |
| `ARES_TARGET_DOMAIN`           |         | Target AD domain                            |
| `ARES_TARGET_IPS`              |         | Comma-separated target IPs                  |
| `ARES_INITIAL_CREDENTIAL`      |         | Seed credential (`user:pass@domain`)        |
| `ARES_MAX_CONCURRENT_TASKS`    | `8`     | Max concurrent tasks across roles           |
| `ARES_MAX_TASKS_PER_ROLE`      | `3`     | Max in-flight tasks per role                |
| `ARES_STALE_TASK_TIMEOUT_SECS` | `900`   | Stale task timeout (seconds)                |
| `ARES_LOCK_TTL_SECS`           | `300`   | Operation lock TTL                          |

**Worker Tuning:**

| Variable                  | Default  | Description                               |
| ------------------------- | -------- | ----------------------------------------- |
| `ARES_WORKER_ROLE`        |          | Agent role (required for workers)         |
| `ARES_WORKER_MODE`        | `task`   | Mode: `task`, `tool_exec`, or `blue_task` |
| `ARES_AGENT_TASK_TIMEOUT` | `600`    | Max seconds per task                      |
| `ARES_POD_NAME`           | hostname | Worker pod identity in Redis              |

### Observability

Ares supports OpenTelemetry for traces and metrics, with console and OTLP
export. Grafana integration provides dashboards for operation monitoring
via the [Grafana MCP](docs/grafana_mcp_usage.md) server.

## Contributing

Open a PR against `main`. Run `pre-commit` before pushing - the CI will reject commits that fail the hooks. Include tests for any new tool or agent behavior.

## License

This project is licensed under the MIT License - see the
[LICENSE](LICENSE) file for details.

## Security

For security vulnerabilities, please see our [Security Policy](SECURITY.md).
