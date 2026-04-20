# Ares - Autonomous Security Operations Agent

<!-- BEGIN_AUTO_BADGES -->

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/dreadnode/ares/blob/main/LICENSE)
[![Tests](https://github.com/dreadnode/ares/actions/workflows/rust.yaml/badge.svg)](https://github.com/dreadnode/ares/actions/workflows/rust.yaml)
[![Pre-Commit](https://github.com/dreadnode/ares/actions/workflows/pre-commit.yaml/badge.svg)](https://github.com/dreadnode/ares/actions/workflows/pre-commit.yaml)

<!-- END_AUTO_BADGES -->

LLM-coordinated autonomous security operations platform with two modes:

**Red Team** - 7 specialized agents orchestrated by an LLM coordination loop that autonomously chains 64+ Active Directory attack tools across the full kill chain, from recon through domain dominance. 14 concurrent automation modules monitor discovered state and dispatch attack chains without manual sequencing.

**Blue Team** - Multi-agent SOC investigation system that queries live Loki logs and Prometheus metrics, runs MITRE ATT&CK-mapped detection templates, tracks lateral movement, and writes detection rules back to Grafana. Evidence-driven chaining automatically dispatches follow-up investigations as new indicators surface.

## Table of Contents

- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Red Team Operations](#red-team-operations)
- [Blue Team Investigations](#blue-team-investigations)
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
| `ares-cli`   | Unified binary — CLI, orchestrator, and worker            |
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
- **ACL**: BloodHound path analysis, ACL abuse (shadow credentials, WriteDACL)
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
3. **Privilege Escalation** - ADCS exploitation, delegation attacks, ACL abuse
4. **Lateral Movement** - PSExec/WMI/WinRM, credential harvesting on compromised hosts
5. **Domain Dominance** - DCSync, golden ticket generation, operation report

See [Red Team Architecture](docs/red.md) for detailed documentation.

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

## Configuration

### Config File

The master config lives at `config/ares.yaml`. It defines:

- Per-role LLM model assignments
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

### Environment Variables

**LLM Providers** (at least one required):

| Variable            | Default                  | Description                       |
| ------------------- | ------------------------ | --------------------------------- |
| `ANTHROPIC_API_KEY` |                          | Anthropic API key (Claude models) |
| `OPENAI_API_KEY`    |                          | OpenAI API key (GPT models)       |
| `OLLAMA_BASE_URL`   | `http://localhost:11434` | Local Ollama server URL           |

**Model Selection:**

| Variable                  | Default | Description                                                             |
| ------------------------- | ------- | ----------------------------------------------------------------------- |
| `ARES_LLM_MODEL`          |         | Primary model (`anthropic/<model>`, `openai/<model>`, `ollama/<model>`) |
| `ARES_ORCHESTRATOR_MODEL` |         | Override model for orchestrator                                         |
| `ARES_WORKER_MODEL`       |         | Override model for workers                                              |
| `ARES_BLUE_LLM_MODEL`     |         | Override model for blue team                                            |
| `ARES_MODEL`              |         | Generic fallback for both sides                                         |
| `ARES_AGENT_<ROLE>_MODEL` |         | Per-role override (e.g. `ARES_AGENT_RECON_MODEL`)                       |

Precedence (highest first):
`ARES_AGENT_<ROLE>_MODEL` > `ARES_ORCHESTRATOR_MODEL`/`ARES_WORKER_MODEL` > `ARES_MODEL` > `ARES_LLM_MODEL` > config file.

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

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Run pre-commit checks
5. Submit a pull request

## License

This project is licensed under the MIT License - see the
[LICENSE](LICENSE) file for details.

## Security

For security vulnerabilities, please see our [Security Policy](SECURITY.md).
