# Ares - Autonomous Security Operations Agent

<!-- BEGIN_AUTO_BADGES -->

[![Rust](https://github.com/dreadnode/ares/actions/workflows/rust.yaml/badge.svg)](https://github.com/dreadnode/ares/actions/workflows/rust.yaml)
[![Pre-Commit](https://github.com/dreadnode/ares/actions/workflows/pre-commit.yaml/badge.svg)](https://github.com/dreadnode/ares/actions/workflows/pre-commit.yaml)
[![License](https://img.shields.io/github/license/dreadnode/ares?label=License&style=flat&color=blue&logo=github)](https://github.com/dreadnode/ares/blob/main/LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)

<!-- END_AUTO_BADGES -->

LLM-coordinated autonomous security operations platform with two modes:

**Red Team** — 7 specialized agents (recon, credential access, cracker, ACL,
privesc, lateral movement, coercion) orchestrated by an LLM coordination loop
that autonomously chains 64+ Active Directory attack tools across the full kill
chain: network discovery, credential harvesting (Kerberoast, AS-REP, secretsdump,
LAPS, GPP), hash cracking, privilege escalation (ADCS, delegation, trust abuse,
ACL exploitation), lateral movement (PSExec/WMI/WinRM/MSSQL), and domain
dominance (golden tickets, multi-forest traversal). 14 concurrent automation
modules continuously monitor discovered state and dispatch attack chains without
manual sequencing.

**Blue Team** — Multi-agent SOC investigation system (triage, threat hunter,
lateral analyst, escalation) that queries live Loki logs and Prometheus metrics,
runs MITRE ATT&CK-mapped detection templates, auto-extracts and validates IOCs,
tracks lateral movement paths across hosts, learns from past investigations to
reduce false positives, climbs the Pyramid of Pain from network artifacts to
TTPs, and writes detection rules back to Grafana. Evidence-driven chaining
automatically dispatches follow-up investigations as new indicators surface.

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

Ares is a Rust workspace with six crates:

| Crate               | Binary              | Purpose                                                  |
| ------------------- | ------------------- | -------------------------------------------------------- |
| `ares-cli`          | `ares-cli`          | Unified CLI — ops, blue, history, config management      |
| `ares-orchestrator` | `ares-orchestrator` | LLM-powered coordination loop, task dispatch, strategy   |
| `ares-worker`       | `ares-worker`       | Task execution agents (one per role, K8s or EC2)         |
| `ares-core`         | —                   | Shared models, state management, Redis schema, telemetry |
| `ares-llm`          | —                   | LLM providers (Anthropic, OpenAI, Ollama) + tool registry|
| `ares-tools`        | —                   | Tool dispatch and execution framework                    |

### Red Team Multi-Agent System

```
Local (this machine)              Remote (K8s or EC2)
────────────────────              ───────────────────
ares-cli --k8s / --ec2    →      ares-orchestrator (LLM coordination loop)
  or `task` commands              ares-worker x7 (recon, credential_access,
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
ares-cli --k8s / --ec2    →      ares-orchestrator (investigation coordination)
  or `task` commands              ares-worker x4 (triage, threat_hunter,
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
  for credential management (optional — `.env` file also supported)
- Redis (for orchestrator/worker communication)

**Build:**

```bash
# Clone and build
git clone https://github.com/dreadnode/ares.git && cd ares
task rust:build          # debug build
task rust:release        # release build (recommended)

# Verify
./target/release/ares-cli --help
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

The `ares-cli` binary is the unified interface for all operations. It supports
transparent remote execution via transport flags.

### Transport Flags

```bash
# K8s: execute on orchestrator pod via kubectl
ares-cli --k8s ares-red ops loot --latest
ares-cli --k8s ares-blue blue status --latest

# EC2: execute on instance via AWS SSM
ares-cli --ec2 kali-ares ops loot --latest

# Override defaults
ares-cli --k8s ares-red --k8s-deploy ares-orchestrator ops list
ares-cli --ec2 kali-ares --ec2-profile prod --ec2-region us-east-1 ops list
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

**`ops`** — Red team operation management:

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

**`blue`** — Blue team investigation management:

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

**`history`** — Historical queries (PostgreSQL):

| Subcommand                            | Description             |
| ------------------------------------- | ----------------------- |
| `list [--domain D] [--since-days N]`  | List past operations    |
| `get <ID>`                            | Detailed operation info |
| `search-creds [--domain D] [--admin]` | Search credentials      |
| `search-hashes [--cracked]`           | Search hashes           |
| `mitre-coverage [--since-days N]`     | Technique coverage      |
| `cost [--since-days N]`               | Token usage and cost    |

**`config`** — Configuration management:

| Subcommand                         | Description          |
| ---------------------------------- | -------------------- |
| `show [--models]`                  | Show resolved config |
| `validate`                         | Validate config file |
| `set-model <ROLE> <MODEL> [--all]` | Set LLM model        |

## Red Team Operations

### Start an Operation

```bash
# Via Taskfile (recommended)
task red:multi TARGET=dreadgoad DOMAIN=sevenkingdoms.local

# Via CLI directly
ares-cli ops submit dreadgoad sevenkingdoms.local \
  --ips 192.168.58.10,192.168.58.11 \
  --model gpt-5.2 --follow

# EC2
task ec2:launch DOMAIN=sevenkingdoms.local TARGETS=192.168.58.10,192.168.58.11
```

### Monitor

```bash
ares-cli --k8s ares-red ops status --latest
ares-cli --k8s ares-red ops loot --latest --watch 10
ares-cli --k8s ares-red ops tasks --latest --status failed
ares-cli --k8s ares-red ops runtime --latest
task remote:logs ROLE=orchestrator
```

### Inject State (Unblock Stuck Operations)

```bash
ares-cli --k8s ares-red ops inject-credential op-xxx administrator P@ssw0rd \
  --domain contoso.local

ares-cli --k8s ares-red ops inject-hash op-xxx krbtgt \
  "aad3b435b51404eeaad3b435b51404ee:313b6f423a..." \
  --domain sevenkingdoms.local --aes-key "f8b6c5e4d3a2b109..."

ares-cli --k8s ares-red ops inject-host op-xxx 192.168.58.20 dc01.essos.local

ares-cli --k8s ares-red ops inject-domain-sid op-xxx \
  --domain north.sevenkingdoms.local --sid "S-1-5-21-..."
```

### Reports

```bash
ares-cli --k8s ares-red ops report --latest
ares-cli --k8s ares-red ops report --latest --regenerate
ares-cli --k8s ares-red ops export-detection --latest
```

### Operation Phases

1. **Initial Access** — RECON scans, COERCION starts Responder, CREDENTIAL_ACCESS sprays
2. **Enumeration** — BloodHound, Kerberoasting, AS-REP roasting, hash cracking
3. **Privilege Escalation** — ADCS exploitation, delegation attacks, ACL abuse
4. **Lateral Movement** — PSExec/WMI/WinRM, credential harvesting on compromised hosts
5. **Domain Dominance** — DCSync, golden ticket generation, operation report

See [Red Team Architecture](docs/red.md) for detailed documentation.

## Blue Team Investigations

The blue team runs autonomous SOC investigations against Grafana alerts. Each
investigation dispatches specialized agents that query Loki and Prometheus,
extract IOCs, validate evidence against query results, map findings to MITRE
ATT&CK techniques, and climb the Pyramid of Pain from hash values toward TTPs.

### Investigation Stages

1. **Triage** — Parse alert, discover datasources, first-pass IOC extraction via Loki/Prometheus (8-12 queries)
2. **Causation** — Root cause analysis, precursor attack identification, attack chain reconstruction (14 queries)
3. **Lateral Movement** — Multi-host scope expansion, lateral movement graph construction, pivot detection (20 queries)
4. **Synthesis** — Evidence consolidation, MITRE mapping, Pyramid of Pain assessment, report generation (20 queries)

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
ares-cli/                         # CLI binary crate
ares-core/                        # Shared library (models, state, telemetry)
ares-llm/                         # LLM provider abstraction
ares-orchestrator/                # Orchestrator binary crate
ares-tools/                       # Tool dispatch framework
ares-worker/                      # Worker binary crate

config/                           # Configuration files
  ares.yaml                       # Master config (models, timeouts, capabilities)

ansible/                          # Ansible collection: dreadnode.nimbus_range v1.5.0
  playbooks/ares/                 # Agent provisioning playbooks
  roles/                          # 14 roles (8 agent tool roles + base + infra)

warpgate-templates/               # Container image build templates
  ares-base/                      # Base: Kali + security tool dependencies
  ares-orchestrator/              # Orchestrator: Rust binary + Redis
  ares-worker/                    # Generic worker
  ares-{recon,credential-access,cracker,acl,privesc,lateral-movement,coercion}-agent/
  ares-blue-{agent,triage-agent,threat-hunter-agent,lateral-analyst-agent}/

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
PROVISION_REPO_PATH=./ansible warpgate build warpgate-templates/ares-base
PROVISION_REPO_PATH=./ansible warpgate build warpgate-templates/ares-recon-agent
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
ares-cli config show --models              # show model assignments
ares-cli config set-model orchestrator gpt-5.2
ares-cli config set-model --all gpt-5.2
ares-cli config validate
```

### Environment Variables

| Variable                        | Required | Description                                      |
| ------------------------------- | -------- | ------------------------------------------------ |
| `ANTHROPIC_API_KEY`             | Yes*     | Anthropic API key (Claude models)                |
| `OPENAI_API_KEY`                | Yes*     | OpenAI API key (GPT models)                      |
| `GRAFANA_URL`                   | Blue     | Grafana instance URL                             |
| `GRAFANA_SERVICE_ACCOUNT_TOKEN` | Blue     | Grafana service account token                    |
| `DREADNODE_API_KEY`             | No       | Dreadnode platform token for observability       |
| `ARES_REDIS_URL`                | No       | Redis URL (default: `redis://localhost:6379`)    |
| `ARES_LLM_MODEL`                | No       | Default LLM model override                       |
| `ARES_CONFIG`                   | No       | Config file path (default: `./config/ares.yaml`) |

\* At least one LLM provider key required. Supports Anthropic, OpenAI, and Ollama (local, no key needed).

**Model Override Precedence** (highest first):
`ARES_AGENT_<ROLE>_MODEL` > `ARES_ORCHESTRATOR_MODEL`/`ARES_WORKER_MODEL` > `ARES_MODEL` > config file.

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
