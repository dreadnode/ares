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

### Red Team - Penetration Testing

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
task ares:blue:
```

**Verification:**

```bash
# Confirm installation
uv run python -m ares --help
# Should display available commands: investigate-alert, red-team
```

**Without 1Password:**

```bash
# Create .env file with your credentials
cp .env.example .env
# Edit .env with your API keys

# Run using local environment
task ares:blue:local:
```

## Usage

### Using Taskfile (Recommended)

The easiest way to run Ares is using the provided Taskfile with 1Password integration:

```bash
# Check configuration and 1Password access
task ares:config:check

# Blue Team: Run SOC agent in poll mode
task ares:blue:

# Blue Team: Process current alerts once and exit
task ares:blue:once:

# Blue Team: Investigate a specific alert from JSON file
task ares:investigate ALERT=test-alerts/example-alert.json

# Red Team: Run penetration testing agent (resolves target via AWS EC2 Name tag)
task -y ares:red TARGET=dreadgoad

# Red Team: Direct IP target (bypasses EC2 discovery)
task ares:red: TARGET=192.168.56.100

# View investigation reports
task ares:reports:list        # List all reports
task ares:reports:latest      # Show latest report
```

**Available Tasks:**

| Command                              | Description                                                  |
| ------------------------------------ | ------------------------------------------------------------ |
| `task ares:blue:`                    | Run blue team agent in poll mode (checks Grafana every 30s)  |
| `task ares:blue:once:`               | Run blue team once and exit                                  |
| `task ares:blue:local:`              | Run blue team using .env file instead of 1Password           |
| `task ares:investigate ALERT=<file>` | Investigate a specific alert from JSON file                  |
| `task ares:red TARGET=<filter>`      | Run red team agent (resolves target via EC2 Name tag filter) |
| `task ares:red: TARGET=<ip>`         | Run red team agent against direct IP address                 |
| `task ares:red:local: TARGET=<ip>`   | Run red team using .env file instead of 1Password            |
| `task ares:config:check`             | Verify configuration and 1Password access                    |
| `task ares:config:show`              | Display current configuration (no secrets)                   |
| `task ares:reports:list`             | List all investigation reports                               |
| `task ares:reports:latest`           | Show the most recent report                                  |
| `task ares:reports:clean`            | Delete all reports (asks for confirmation)                   |
| `task ares:mitre:test`               | Test MITRE ATT&CK data loading                               |

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

#### Red Team - Penetration Testing

The red team agent supports two targeting modes:

**EC2 Target Discovery (Recommended):**

When using the Taskfile, provide an EC2 Name tag filter instead of an IP address.
The task queries AWS EC2 to find running instances where the Name tag contains
your filter string, then uses the first matching instance's private IP.

```bash
# Discover target via AWS EC2 Name tag filter
# Finds instances where Name tag contains "dreadgoad"
task -y ares:red TARGET=dreadgoad
```

This uses `aws ec2 describe-instances` with:

- Filter: `Name=instance-state-name,Values=running`
- Query: Instances where `Name` tag contains the TARGET value
- Returns: First matching instance's `PrivateIpAddress`

**Direct IP Target:**

For direct IP targeting (bypasses EC2 discovery):

```bash
# Direct IP address
task ares:red: TARGET=192.168.56.100

# Or via CLI
uv run python -m ares red-team 192.168.56.100 \
  --args.model claude-sonnet-4-20250514 \
  --args.max-steps 30 \
  --args.report-dir ./reports
```

**Red Team Prerequisites:** The target environment must have penetration testing
tools installed (nmap, netexec, impacket-scripts, hashcat, john, certipy-ad,
bloodhound-python).

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

The red team agent follows a priority-driven attack workflow:

### Priority 0: ADCS Vulnerabilities

When certificate template vulnerabilities (ESC1-15) are discovered, immediately
exploit them for potential direct path to Domain Admin.

### Priority 1: KRBTGT Hash

When a krbtgt hash is found, generate golden tickets for persistent domain
access and cross-domain escalation.

### Priority 2: Administrator Hash

When Administrator hashes are found, immediately use domain_admin_checker on
all targets and run secretsdump across the environment.

### Priority 3: Credential Expansion

For each new credential discovered:

1. Check for privilege escalation paths (BloodHound ACL abuse, ADCS, delegation)
2. Enumerate users and shares on all targets
3. Pilfer accessible shares for embedded credentials
4. Kerberoast and AS-REP roast with new credentials
5. Crack discovered hashes and loop back

Example report location: `reports/redteam-<operation-id>_report.md`

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

# Via command line (red team)
uv run python -m ares red-team 192.168.56.100 \
  --dn-args.project ares-redteam

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
