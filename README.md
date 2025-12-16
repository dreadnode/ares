# Ares - Autonomous SOC Investigation Agent

<!-- BEGIN_AUTO_BADGES -->
<div align="center">

[![Pre-Commit](https://github.com/dreadnode/python-template/actions/workflows/pre-commit.yaml/badge.svg)](https://github.com/dreadnode/python-template/actions/workflows/pre-commit.yaml)
[![Renovate](https://github.com/dreadnode/python-template/actions/workflows/renovate.yaml/badge.svg)](https://github.com/dreadnode/python-template/actions/workflows/renovate.yaml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

</div>
<!-- END_AUTO_BADGES -->

[![Pre-Commit](https://github.com/dreadnode/python-template/actions/workflows/pre-commit.yaml/badge.svg)](https://github.com/dreadnode/python-template/actions/workflows/pre-commit.yaml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Autonomous security investigation agent that polls Grafana for alerts, queries
Loki/Prometheus, and generates investigation reports with MITRE ATT&CK
mappings.

## What It Does

- Polls Grafana for firing alerts
- Autonomously investigates Windows security events
- Queries Loki for logs (Event IDs 4624, 4662, etc.)
- Maps findings to MITRE ATT&CK techniques
- Generates markdown reports with timeline and recommendations
- Detects DCSync, authentication patterns, and attack indicators

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
#    - "claude.ai" -> dreadnode-api-key field

# 3. Verify configuration
task ares:config:check

# 4. Run the agent (polls Grafana for alerts)
task ares:run
```

**Without 1Password:**

```bash
# Create .env file with your credentials
cp .env.example .env
# Edit .env with your API keys

# Run using local environment
task ares:run:local
```

## Usage

### Using Taskfile (Recommended)

The easiest way to run Ares is using the provided Taskfile with 1Password integration:

```bash
# Check configuration and 1Password access
task ares:config:check

# Run Ares in poll mode (retrieves API keys from 1Password automatically)
task ares:run

# Investigate a specific alert from JSON file
task ares:investigate ALERT=test-alerts/example-alert.json

# View investigation reports
task ares:reports:list        # List all reports
task ares:reports:latest      # Show latest report
```

**Available Tasks:**

| Command | Description |
| ------- | ----------- |
| `task ares:run` | Run agent in poll mode (checks Grafana every 30s) |
| `task ares:run:local` | Run using .env file instead of 1Password |
| `task ares:investigate ALERT=<file>` | Investigate a specific alert from JSON file |
| `task ares:config:check` | Verify configuration and 1Password access |
| `task ares:config:show` | Display current configuration (no secrets) |
| `task ares:reports:list` | List all investigation reports |
| `task ares:reports:latest` | Show the most recent report |
| `task ares:reports:clean` | Delete all reports (asks for confirmation) |
| `task ares:mitre:test` | Test MITRE ATT&CK data loading |

See [Taskfile Usage Guide](docs/taskfile_usage.md) for detailed documentation.

### Direct CLI Usage (Advanced)

#### Poll Mode (Continuous)

Run Ares in continuous polling mode to automatically investigate alerts:

```bash
# Set required environment variables
export GRAFANA_SERVICE_ACCOUNT_TOKEN="your-grafana-token"  # pragma: allowlist secret
export ANTHROPIC_API_KEY="your-anthropic-key"  # pragma: allowlist secret
export DREADNODE_API_KEY="your-dreadnode-key"  # optional  # pragma: allowlist secret

# Run the agent
uv run python -m src \
  --args.model claude-sonnet-4-20250514 \
  --args.grafana-url https://grafana.example.com \
  --args.poll-interval 30 \
  --args.max-steps 150 \
  --args.report-dir ./reports
```

#### Single Alert Investigation

Investigate a specific alert by providing it as JSON:

```bash
# Using environment variables (as above)
uv run python -m src investigate-alert test-alerts/example-alert.json \
  --args.model claude-sonnet-4-20250514 \
  --args.grafana-url https://grafana.example.com \
  --args.max-steps 150
```

### Command-Line Options

**Agent Arguments (`--args.*`):**

| Option | Default | Description |
| ------ | ------- | ----------- |
| `--args.model` | `claude-sonnet-4-20250514` | LLM model to use |
| `--args.grafana-url` | `https://grafana.dev.plundr.ai` | Grafana URL for alerts and MCP |
| `--args.poll-interval` | `30` | Seconds between alert polls |
| `--args.max-steps` | `150` | Maximum agent steps per investigation |
| `--args.report-dir` | `./reports` | Directory for markdown reports |

**Dreadnode Platform Arguments (`--dn-args.*`):**

| Option | Default | Description |
| ------ | ------- | ----------- |
| `--dn-args.server` | `https://platform.dev.plundr.ai/` | Dreadnode platform server URL |
| `--dn-args.token` | from `DREADNODE_API_KEY` | Dreadnode API token |
| `--dn-args.organization` | `ares` | Dreadnode organization name |
| `--dn-args.workspace` | `ares-protocol` | Dreadnode workspace name |
| `--dn-args.project` | `ares-soc` | Dreadnode project name |

## Investigation Workflow

Ares follows a structured 4-stage investigation process:

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

| Variable | Required | Description |
| -------- | -------- | ----------- |
| `GRAFANA_URL` | Yes | Grafana instance URL (e.g., `https://grafana.example.com`) |
| `GRAFANA_SERVICE_ACCOUNT_TOKEN` | Yes | Grafana service account token for API access |
| `ANTHROPIC_API_KEY` | Yes | Anthropic API key for Claude models |
| `DREADNODE_API_KEY` | No | Dreadnode platform token for observability |

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
# Via command line
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
