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

```bash
# Install
git clone https://github.com/dreadnode/ares.git && cd ares
uv venv && source .venv/bin/activate
uv pip install -e .

# Configure API keys in 1Password:
# - "Dreadnode Dev Platform" -> api-key
# - "Grafana" -> api-key
# - "Anthropic" -> api-key

# Check config
task ares:config:check

# Run
task ares:run
```

## Usage

### Using Taskfile (Recommended)

The easiest way to run Ares is using the provided Taskfile with 1Password integration:

```bash
# Check configuration and 1Password access
task ares:config:check

# Run Ares in poll mode (retrieves API keys from 1Password)
task ares:run

# Investigate a specific alert
task ares:investigate ALERT=alert.json

# View investigation reports
task ares:reports:list
task ares:reports:latest
```

See [Taskfile Usage Guide](docs/taskfile_usage.md) for detailed documentation.

### Direct CLI Usage

#### Poll Mode (Continuous)

Run Ares in continuous polling mode to automatically investigate alerts:

```bash
uv run python -m ares \
  --model claude-sonnet-4-20250514 \
  --grafana-url http://grafana:3000 \
  --loki-url http://loki:3100 \
  --prometheus-url http://prometheus:9090 \
  --poll-interval 30 \
  --report-dir ./reports
```

#### Single Alert Investigation

Investigate a specific alert by providing it as JSON:

```bash
uv run python -m ares investigate-alert alert.json
```

### Command-Line Options

```text
--model              LLM model to use (default: claude-sonnet-4-20250514)
--grafana-url        Grafana URL (default: http://localhost:3000)
--grafana-api-key    Grafana API key (or set GRAFANA_API_KEY env var)
--loki-url           Loki URL for log queries (default: http://localhost:3100)
--prometheus-url     Prometheus URL for metrics (default: http://localhost:9090)
--poll-interval      Seconds between alert polls (default: 30)
--max-steps          Maximum agent steps per investigation (default: 150)
--report-dir         Directory for markdown reports (default: reports)
```

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

- `GRAFANA_API_KEY`: Grafana API key for alert polling
- `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`: LLM provider API key
- `DREADNODE_API_KEY`: Dreadnode platform token (optional)

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
