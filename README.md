# Ares - Autonomous Security Operations Agent

<!-- BEGIN_AUTO_BADGES -->

[![Tests](https://github.com/dreadnode/ares/actions/workflows/tests.yaml/badge.svg)](https://github.com/dreadnode/ares/actions/workflows/tests.yaml)
[![Pre-Commit](https://github.com/dreadnode/ares/actions/workflows/pre-commit.yaml/badge.svg)](https://github.com/dreadnode/ares/actions/workflows/pre-commit.yaml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

<!-- END_AUTO_BADGES -->

Autonomous security agent with dual capabilities: **Blue Team** (SOC alert
investigation) and **Red Team** (penetration testing). Built with the Dreadnode
Agent SDK and MITRE ATT&CK framework.

## Table of Contents

- [Capabilities](#capabilities)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Blue Team Investigation Workflow](#blue-team-investigation-workflow)
- [Red Team Operation Workflow](#red-team-operation-workflow)
- [Blue Team Evaluation](#blue-team-evaluation)
- [Development](#development)
- [Configuration](#configuration)
- [Observability](#observability)
- [Contributing](#contributing)
- [License](#license)

## Capabilities

### Blue Team - SOC Investigation

- Polls Grafana for firing alerts
- Autonomously investigates Windows security events
- Queries Loki for logs (Event IDs 4624, 4662, etc.)
- Maps findings to MITRE ATT&CK techniques
- Generates markdown reports with timeline and recommendations
- Detects DCSync, authentication patterns, and attack indicators

### Evaluation Framework

- Measures blue team investigation effectiveness against red team ground truth
- Scores IOC detection, MITRE technique coverage, Pyramid of Pain elevation,
  timeline accuracy, and evidence quality
- Supports both real Grafana alert polling and synthetic alert injection
- Generates gap analysis reports with prioritized detection recommendations
- CI-compatible with JSON output, exit codes, and configurable pass thresholds
- Dataset evaluation for batch scoring across multiple scenarios

### Red Team - Multi-Agent Penetration Testing

**Multi-Agent Architecture:**

- Orchestrator coordinates 7 specialized worker agents via Redis
- Each agent runs in its own Kubernetes pod with role-specific tools
- Shared state enables credential/hash broadcasting across agents
- Phase-aware task prioritization
  (initial access → enumeration → privesc → lateral → DA)

**Agent Roles:**

- **RECON**: Network scanning, BloodHound, user/share enumeration
- **CREDENTIAL_ACCESS**: secretsdump, kerberoasting, AS-REP roasting, password spray
- **CRACKER**: Offline hash cracking with hashcat/john
- **ACL**: BloodHound path analysis, ACL abuse (shadow credentials, WriteDACL)
- **PRIVESC**: ADCS (ESC1-8), delegation attacks, MSSQL exploitation
- **LATERAL**: PSExec/WMI/WinRM, credential harvesting from compromised hosts
- **COERCION**: Responder, ntlmrelayx, PetitPotam

**Attack Capabilities:**

- Autonomous Active Directory enumeration
- Credential harvesting (secretsdump, kerberoasting, AS-REP roasting)
- Password hash cracking (hashcat, John the Ripper)
- SMB share pilfering for embedded credentials
- BloodHound integration for ACL abuse paths
- ADCS exploitation (ESC1-15 vulnerabilities)
- Golden ticket generation for domain persistence
- Delegation attacks (RBCD, unconstrained, constrained)

## Quick Start

**Prerequisites:**

- Python 3.11+
- [uv](https://docs.astral.sh/uv/getting-started/installation/) package manager
- [Task](https://taskfile.dev/installation/) (optional but recommended)
- [1Password CLI](https://developer.1password.com/docs/cli/get-started/)
  for credential management
- [mcp-grafana](https://github.com/grafana/mcp-grafana) MCP server:
  `go install github.com/grafana/mcp-grafana/cmd/mcp-grafana@latest`

**Setup:**

```bash
# 1. Clone and install
git clone https://github.com/dreadnode/ares.git && cd ares
uv sync

# 2. Configure API keys in 1Password (or set environment variables):
#    - "Dreadnode Dev Platform" -> api-key field
#    - "Ares Grafana MCP" -> grafana-token field
#    - "Dreadnode Claude" -> dreadnode-api-key field

# 3. Verify configuration
task ares:config:check
# Expected output: ✓ All configuration checks passed

# 4. Run the blue team agent (polls Grafana for alerts)
task blue:poll
```

**Verification:**

```bash
# Confirm installation
uv run python -m ares --help
# Should display available commands: investigate-alert, multi-agent, worker, evaluate, evaluate-dataset, version
```

**Without 1Password:**

```bash
# Create .env file with your credentials
cp .env.example .env
# Edit .env with your API keys

# Run using local environment
task blue:poll:local
```

## Usage

### Using Taskfile (Recommended)

The easiest way to run Ares is using the provided Taskfile with 1Password integration:

```bash
# Check configuration and 1Password access
task ares:config:check

# Blue Team: Run SOC agent in poll mode
task blue:poll

# Blue Team: Process current alerts once and exit
task blue:once

# Blue Team: Investigate a specific alert from JSON file
task blue:investigate ALERT=test-alerts/example-alert.json

# View investigation reports
task blue:reports:list        # List all reports
task blue:reports:latest      # Show latest report
```

**Available Tasks:**

| Command                              | Description                                                  |
| ------------------------------------ | ------------------------------------------------------------ |
| `task blue:poll`                     | Run blue team agent in poll mode (checks Grafana every 30s)  |
| `task blue:once`                     | Run blue team once and exit                                  |
| `task blue:poll:local`               | Run blue team using .env file instead of 1Password           |
| `task blue:investigate ALERT=<file>` | Investigate a specific alert from JSON file                  |
| `task ares:config:check`             | Verify configuration and 1Password access                    |
| `task ares:config:show`              | Display current configuration (no secrets)                   |
| `task blue:reports:list`             | List all investigation reports                               |
| `task blue:reports:latest`           | Show the most recent report                                  |
| `task blue:reports:clean`            | Delete all reports (asks for confirmation)                   |
| `task blue:mitre:test`               | Test MITRE ATT&CK data loading                               |

**Red Team Tasks (Multi-Agent):**

| Command                                | Description                                                  |
| -------------------------------------- | ------------------------------------------------------------ |
| `task red:multi TARGET=<name>`         | Run multi-agent red team operation                           |
| `task red:multi:status LATEST=true`    | Check operation status                                       |
| `task red:multi:loot LATEST=true`      | Show discovered credentials, hashes, hosts                   |
| `task red:multi:list`                  | List all operations                                          |
| `task remote:logs ROLE=orchestrator`   | Tail orchestrator logs                                       |
| `task remote:sync:full`                | Sync local code to K8s pods                                  |
| `task red:multi:sync:align`            | Full sync + Redis clear + pod rollout                        |

See [Taskfile Usage Guide](docs/taskfile_usage.md) for detailed documentation.

### Direct CLI Usage (Advanced)

#### Blue Team - Poll Mode (Continuous)

Run Ares in continuous polling mode to automatically investigate alerts:

```bash
# Set required environment variables
export GRAFANA_SERVICE_ACCOUNT_TOKEN="your-grafana-token"  # pragma: allowlist secret
export ANTHROPIC_API_KEY="your-anthropic-key"  # pragma: allowlist secret
export DREADNODE_API_KEY="your-dreadnode-key"  # optional  # pragma: allowlist secret

# Run the blue team agent (continuous polling)
uv run python -m ares \
  --args.model claude-sonnet-4-20250514 \
  --args.grafana-url https://grafana.example.com \
  --args.poll-interval 30 \
  --args.max-steps 30 \
  --args.report-dir ./reports

# Run once and exit (process current alerts only)
uv run python -m ares --args.once
```

#### Blue Team - Single Alert Investigation

Investigate a specific alert by providing it as JSON:

```bash
uv run python -m ares investigate-alert test-alerts/example-alert.json \
  --args.model claude-sonnet-4-20250514 \
  --args.grafana-url https://grafana.example.com \
  --args.max-steps 30
```

#### Red Team - Multi-Agent Operation

Run a coordinated multi-agent penetration test:

```bash
# Run multi-agent operation
uv run ares multi-agent contoso.local "192.168.58.10,192.168.58.11" \
  --args.model gpt-4o \
  --multi-args.redis-url redis://redis:6379

# Run a worker agent (typically started by K8s, but can be run manually)
uv run ares worker lateral op-12345678 \
  --worker-args.redis-url redis://redis:6379
```

### Command-Line Options

**Agent Arguments (`--args.*`):**

| Option                 | Default                         | Description                               |
| ---------------------- | ------------------------------- | ----------------------------------------- |
| `--args.model`         | `claude-sonnet-4-20250514`      | LLM model to use                          |
| `--args.grafana-url`   | `https://grafana.dev.plundr.ai` | Grafana URL for alerts and MCP            |
| `--args.poll-interval` | `30`                            | Seconds between alert polls               |
| `--args.max-steps`     | `30`                            | Maximum LLM round trips per investigation |
| `--args.report-dir`    | `./reports`                     | Directory for markdown reports            |
| `--args.once`          | `false`                         | Process current alerts once and exit      |

**Stop Conditions:**

The agent stops when **any** of these conditions are met:

- `complete_investigation()` tool is called (normal completion)
- `escalate_investigation()` tool is called (escalation to human)
- 5 Loki/Prometheus queries executed
- 20 total tool calls made (prevents infinite loops)
- `max_steps` LLM round trips reached

**Timeout Behavior:**

The agent has multiple timeout layers:

- Hard timeout: `max_steps × 60 seconds` (1 minute per step)
- Watchdog thread: Force-exits if timeout exceeded
- When using Taskfile, defaults are 15 steps (once mode) or 50 steps (polling mode)

**Dreadnode Platform Arguments (`--dn-args.*`):**

| Option                   | Default                           | Description                   |
| ------------------------ | --------------------------------- | ----------------------------- |
| `--dn-args.server`       | `https://platform.dev.plundr.ai/` | Dreadnode platform server URL |
| `--dn-args.token`        | from `DREADNODE_API_KEY`          | Dreadnode API token           |
| `--dn-args.organization` | `ares`                            | Dreadnode organization name   |
| `--dn-args.workspace`    | `ares-protocol`                   | Dreadnode workspace name      |
| `--dn-args.project`      | `ares-soc`                        | Dreadnode project name        |

## Blue Team Investigation Workflow

The SOC agent follows a structured 4-stage investigation process:

### 1. Triage (WHAT is happening?)

- Parse alert payload
- Generate initial questions using question engines
- Execute parallel queries to gather evidence
- Understand what triggered the alert

### 2. Causation (WHY did it happen?)

- Expand time windows to find precursor events
- Trace back through the attack chain
- Build a coherent timeline
- Identify root cause

### 3. Lateral Movement (What is the SCOPE?)

- Investigate across multiple dimensions:
  - Same host: What else is this host doing?
  - Same user: Where else has this user been?
  - Same indicators: Where else do these IOCs appear?
- Track host and user investigations
- Determine blast radius

### 4. Synthesis (Generate report)

- Review all findings
- Assess Pyramid of Pain state (are we at TTPs?)
- Generate comprehensive markdown report
- Provide actionable recommendations

## Question Engines

### MITRE ATT&CK Navigator

Generates questions based on:

- **Follow-on techniques**: What techniques commonly follow identified
  ones?
- **Tactical gaps**: What attack phases haven't we checked?
- **Evidence mapping**: How does evidence map to MITRE techniques?

### Pyramid of Pain Climber

The Pyramid of Pain ranks indicators by difficulty for adversaries to change:

```text
       6. TTPs (Tough!) ← GOAL
      5. Tools (Challenging)
     4. Network/Host Artifacts (Annoying)
    3. Domain Names (Simple)
   2. IP Addresses (Easy)
  1. Hash Values (Trivial)
```

The engine generates questions to climb from trivial indicators to
behavioral TTPs.

## Investigation Reports

Generated reports include:

- **Executive Summary**: Key findings, scope, and risk assessment
- **Timeline**: Chronological sequence of events
- **Evidence Table**: All collected indicators with pyramid levels
- **MITRE ATT&CK Mapping**: Identified techniques and tactics
- **Pyramid of Pain Assessment**: Indicator distribution and elevation score
- **Scope Analysis**: Affected hosts, users, and timeframes
- **Recommendations**: Containment, detection rules, and follow-up actions

Example report location: `reports/inv-<id>-<timestamp>.md`

## Red Team Operation Workflow

The multi-agent red team system follows a phase-driven attack workflow:

### Phase 1: Initial Access

- RECON scans networks, enumerates hosts/users/shares
- COERCION starts Responder for LLMNR/NBT-NS poisoning
- CREDENTIAL_ACCESS attempts password spraying

### Phase 2: Enumeration (First Credentials)

- RECON runs BloodHound collection for attack path analysis
- CREDENTIAL_ACCESS performs Kerberoasting, AS-REP roasting
- CRACKER cracks discovered hashes
- Orchestrator queues vulnerabilities for exploitation

### Phase 3: Privilege Escalation

- PRIVESC exploits ADCS vulnerabilities (ESC1-8), delegation attacks
- ACL exploits WriteDACL, shadow credentials, targeted Kerberoast
- Credential expansion loop continues

### Phase 4: Lateral Movement

- LATERAL moves to new hosts with discovered credentials
- CREDENTIAL_ACCESS runs secretsdump on each compromised host
- CRACKER processes new hashes

### Phase 5: Domain Dominance

- DCSync to extract all domain hashes
- Golden ticket generation for persistence
- Operation completion with full report

### Running Multi-Agent Operations

```bash
# Run multi-agent operation (requires K8s cluster with agents deployed)
task red:multi TARGET=dreadgoad DOMAIN=contoso.local

# Monitor operation progress
task red:multi:loot LATEST=true WATCH=10

# View orchestrator logs
task remote:logs ROLE=orchestrator FOLLOW=true
```

Example report location: `reports/redteam-<operation-id>_report.md`

See [Red Team Architecture](docs/red.md) for detailed multi-agent documentation.

## Blue Team Evaluation

The evaluation framework measures how effectively the blue team SOC agent
detects and investigates red team activities. It uses the red team's operation
state as ground truth — extracting expected IOCs, MITRE techniques, timeline
events, and vulnerabilities — then scores the blue team's investigation against
those expectations.

### Commands

#### Single Scenario

Evaluate the blue team against one red team operation:

```bash
# Evaluate with real Grafana alerts
uv run ares evaluate ./red_state.json \
  --args.model claude-sonnet-4-20250514 \
  --args.grafana-url https://grafana.example.com

# Evaluate with synthetic alerts (no Grafana required)
uv run ares evaluate ./red_state.json --eval-args.synthetic

# CI mode: JSON output, exit code 0/1 based on thresholds
uv run ares evaluate ./red_state.json \
  --eval-args.ci \
  --eval-args.synthetic \
  --eval-args.min-score 0.6 \
  --eval-args.min-ioc-rate 0.5 \
  --eval-args.min-technique-rate 0.5
```

#### Dataset Evaluation

Evaluate against multiple scenarios at once:

```bash
# From a directory of red team state JSON files
uv run ares evaluate-dataset ./red_states/

# From a dataset manifest JSON file, with parallel execution
uv run ares evaluate-dataset ./scenarios.json \
  --eval-args.parallel 4 \
  --eval-args.output-dir ./results/
```

#### Evaluation Arguments (`--eval-args.*`)

| Option                           | Default          | Description                                     |
| -------------------------------- | ---------------- | ----------------------------------------------- |
| `--eval-args.output-dir`         | `./eval_results` | Directory for evaluation result JSON files      |
| `--eval-args.poll-timeout`       | `60`             | Seconds to wait for Grafana alerts per scenario |
| `--eval-args.ci`                 | `false`          | CI mode — JSON to stdout, exit code 0/1         |
| `--eval-args.synthetic`          | `false`          | Use synthetic alerts instead of polling Grafana |
| `--eval-args.min-score`          | `0.5`            | Minimum overall score to pass (CI mode)         |
| `--eval-args.min-ioc-rate`       | `0.5`            | Minimum IOC detection rate to pass (CI mode)    |
| `--eval-args.min-technique-rate` | `0.5`            | Minimum technique coverage to pass (CI mode)    |
| `--eval-args.parallel`           | `1`              | Concurrent scenarios for dataset evaluation     |

### Scoring

Each investigation is scored across six dimensions, grouped into three
categories:

| Component          | Category     | Effective Weight |
| ------------------ | ------------ | ---------------- |
| IOC Detection      | Detection    | 17.5%            |
| Technique Coverage | Detection    | 17.5%            |
| Pyramid Elevation  | Quality      | 15%              |
| Evidence Quality   | Quality      | 15%              |
| Stage Progress     | Completeness | 17.5%            |
| Timeline Accuracy  | Completeness | 17.5%            |

**Category weights:** Detection 35%, Quality 30%, Completeness 35%.

**Component details:**

- **IOC Detection** — Compares evidence found against expected IOCs (IPs,
  hostnames, users, hashes). Uses fuzzy matching for hostnames and
  `domain\user` formats. Required IOCs are weighted 60%, optional 40%.
- **Technique Coverage** — Compares identified MITRE techniques against
  expected techniques. Supports parent/sub-technique matching (T1003 matches
  T1003.001 and vice versa). Required techniques weighted 60%, optional 40%.
- **Pyramid Elevation** — Measures how high up the Pyramid of Pain the
  investigation climbed. 70% weight on highest level reached, 30% on the ratio
  of evidence at Tools/TTPs level.
- **Evidence Quality** — Evaluates average confidence (40%), validation rate
  (30%), and TTP-level evidence ratio (30%).
- **Stage Progress** — How far through the investigation stages the agent
  progressed: Triage (0.25), Causation (0.50), Lateral (0.75), Synthesis (1.0).
- **Timeline Accuracy** — Matches investigation timeline events against
  expected events using regex, substring, and keyword overlap matching (60%),
  plus technique association accuracy (40%).

Results are graded A through F based on overall score, with pass/fail
determined by configurable thresholds on overall score, IOC detection rate,
and technique coverage.

### Synthetic Alerts

The `--eval-args.synthetic` flag bypasses Grafana polling and generates a
synthetic alert from the red team ground truth. The alert type and severity
are chosen based on the most significant expected techniques:

| Technique Pattern | Alert Name                  | Severity |
| ----------------- | --------------------------- | -------- |
| T1003 (cred dump) | `CredentialDumpingDetected` | Critical |
| T1558 (Kerberos)  | `KerberosAttackDetected`    | Critical |
| T1021 (lateral)   | `LateralMovementDetected`   | High     |
| Other             | `SuspiciousActivity`        | Warning  |

This is useful for testing investigation quality in isolation without
requiring a live Grafana instance. Note that synthetic mode always reports
`alert_fired: true`, so it does not test detection coverage.

### Gap Analysis

After evaluation, the framework can generate a gap analysis report identifying:

- Missed IOCs and techniques with prioritized recommendations
- Missing alert coverage (no alert fired)
- Low Pyramid of Pain elevation with log source recommendations
- Incomplete investigations with workflow improvement suggestions

Recommendations are categorized (log source, detection rule, query,
training) and prioritized (critical, high, medium, low) with MITRE technique
mappings and implementation hints.

## Development

### Prerequisites

- Python 3.11+
- [uv](https://github.com/astral-sh/uv) or pip
- [pre-commit](https://pre-commit.com/)
- [Task](https://taskfile.dev/installation/) (optional)

### Setup Development Environment

```bash
# Install dependencies
uv pip install -e ".[dev]"

# Set up pre-commit hooks
pre-commit install

# Run tests
pytest

# Run linting
ruff check .

# Run type checking
mypy src/
```

### Common Development Tasks

```bash
# Run all pre-commit checks
pre-commit run --all-files

# Format code
ruff format .

# Run tests with coverage
pytest --cov=src tests/
```

## Configuration

### Environment Variables

**Blue Team (SOC Investigation):**

| Variable                        | Required | Description                                                |
| ------------------------------- | -------- | ---------------------------------------------------------- |
| `GRAFANA_URL`                   | Yes      | Grafana instance URL (e.g., `https://grafana.example.com`) |
| `GRAFANA_SERVICE_ACCOUNT_TOKEN` | Yes      | Grafana service account token for API access               |
| `ANTHROPIC_API_KEY`             | Yes      | Anthropic API key for Claude models                        |
| `DREADNODE_API_KEY`             | No       | Dreadnode platform token for observability                 |

**Red Team (Penetration Testing):**

| Variable            | Required | Description                                |
| ------------------- | -------- | ------------------------------------------ |
| `ANTHROPIC_API_KEY` | Yes      | Anthropic API key for Claude models        |
| `DREADNODE_API_KEY` | No       | Dreadnode platform token for observability |

**Multi-Agent Model Overrides:**

| Variable                  | Required | Description                                                   |
| ------------------------- | -------- | ------------------------------------------------------------- |
| `ARES_MODEL`              | No       | Default model for all multi-agent roles                       |
| `ARES_ORCHESTRATOR_MODEL` | No       | Override orchestrator model                                   |
| `ARES_WORKER_MODEL`       | No       | Override all worker models                                    |
| `ARES_AGENT_<ROLE>_MODEL` | No       | Role-specific model override (e.g., `ARES_AGENT_RECON_MODEL`) |

Precedence (highest first): `ARES_AGENT_<ROLE>_MODEL` >
`ARES_ORCHESTRATOR_MODEL`/`ARES_WORKER_MODEL` > `ARES_MODEL` > config file.

**Note:** `GRAFANA_API_KEY` is deprecated. Use `GRAFANA_SERVICE_ACCOUNT_TOKEN`
instead. See [Grafana's service account
documentation](https://grafana.com/docs/grafana/latest/administration/service-accounts/)
for details.

### Supported LLM Models

Ares uses [litellm](https://github.com/BerriAI/litellm) format for model
selection:

- `claude-sonnet-4-20250514` (recommended)
- `gpt-4o`
- `gpt-4-turbo`
- Any other litellm-compatible model

## Observability

Ares integrates with the Dreadnode Platform at
<https://platform.dev.plundr.ai/> for comprehensive observability:

- **Metrics**: Evidence count, pyramid levels, tool usage
- **Traces**: Full investigation execution traces
- **Logs**: Structured logs with context
- **Artifacts**: Evidence items, questions, and reports

### Configuring the Platform

The Dreadnode platform can be configured via command-line arguments or
environment variables:

```bash
# Via command line (blue team)
uv run python -m ares \
  --dn-args.server https://platform.dev.plundr.ai/ \
  --dn-args.token your-api-token \
  --dn-args.organization ares \
  --dn-args.workspace ares-protocol \
  --dn-args.project ares-soc

# Via environment variable
export DREADNODE_API_KEY="your-dreadnode-api-key"  # pragma: allowlist secret
```

The default platform URL is `https://platform.dev.plundr.ai/`

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Run pre-commit checks
5. Submit a pull request

## License

This project is licensed under the Apache License 2.0 - see the
[LICENSE](LICENSE) file for details.

## Security

For security vulnerabilities, please see our [Security Policy](SECURITY.md).

## Acknowledgments

- Built with
  [Dreadnode Agent SDK](https://github.com/dreadnode/agent-sdk)
- MITRE ATT&CK data via
  [TAXII server](https://github.com/mitre-attack/attack-stix-data)
- Pyramid of Pain concept by
  [David J. Bianco](http://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)
