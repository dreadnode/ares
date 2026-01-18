# Taskfile Usage for Ares

This document describes how to use the Taskfile to run and manage the Ares
security agents (Blue Team SOC and Red Team penetration testing).

## Prerequisites

1. **Task**: Install from https://taskfile.dev/installation/
2. **1Password CLI**: Install from https://developer.1password.com/docs/cli/get-started/
3. **uv**: Python package manager (installed via the setup process)

## Quick Start

### 1. Trust Remote Taskfiles (First Time Only)

The first time you run tasks, you'll need to trust the remote taskfiles:

```bash
task --trust
```

### 2. Check Configuration

Verify your configuration and 1Password access:

```bash
task ares:config:check
```

This will check:

- Python and uv installation
- Dreadnode platform configuration
- 1Password CLI access
- API key availability in 1Password

### 3. Run Ares

Start the Blue Team agent in poll mode (automatically polls Grafana for alerts):

```bash
task ares:blue:
```

Or run the Red Team agent against a target:

```bash
# Discover target via AWS EC2 Name tag filter
task -y ares:red TARGET=dreadgoad

# Or use a direct IP address
task ares:red: TARGET=192.168.1.100
```

This will:

1. Retrieve API keys from 1Password:
   - `Dreadnode Dev Platform` → `api-key` field
   - `Ares Grafana MCP` → `grafana-token` field (blue team only)
   - `claude.ai` → `dreadnode-api-key` field
2. Start the agent with the configured platform (https://platform.dev.plundr.ai/)

## Available Tasks

### Blue Team Tasks

#### `task ares:blue:`

Run Blue Team agent in poll mode with 1Password API keys.

**Example:**

```bash
# Use default configuration
task ares:blue:

# Custom Grafana URL
task ares:blue: GRAFANA_URL=http://grafana.example.com:3000

# Custom model
task ares:blue: MODEL=gpt-4o

# Override all agents with one value (single- or multi-agent)
task ares:blue: MODEL_ALL=gpt-4o

# Custom poll interval (60 seconds)
task ares:blue: POLL_INTERVAL=60
```

#### `task ares:blue:once:`

Run Blue Team agent once and exit (processes current alerts only).

```bash
task ares:blue:once:
```

#### `task ares:blue:local:`

Run Blue Team using `.env` file instead of 1Password.

```bash
# Create .env file first
cp .env.example .env
# Edit .env with your API keys

# Run with .env
task ares:blue:local:
```

### Red Team Tasks

#### `task ares:red TARGET=<filter>`

Run Red Team agent with automatic EC2 target discovery.

**How Target Discovery Works:**

When you provide a non-IP target (like `dreadgoad`), the task queries AWS EC2 to
find running instances where the Name tag contains your filter string:

```bash
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running" \
  --query "Reservations[*].Instances[?contains(Tags[?Key=='Name'].Value|[0], 'TARGET')].PrivateIpAddress"
```

The first matching instance's private IP is used as the target.

**Example:**

```bash
# EC2 target discovery - finds instances with "dreadgoad" in Name tag
task -y ares:red TARGET=dreadgoad

# Custom model and max steps
task -y ares:red TARGET=dreadgoad MODEL=claude-sonnet-4-20250514 MAX_STEPS=300

# Override all agents with one value
task -y ares:red TARGET=dreadgoad MODEL_ALL=gpt-5.2 MAX_STEPS=300

# Custom AWS profile and region
task -y ares:red TARGET=dreadgoad PROFILE=production REGION=us-east-1
```

#### `task ares:red: TARGET=<ip>`

Run Red Team agent against a direct IP address (bypasses EC2 discovery).

```bash
task ares:red: TARGET=192.168.1.100
```

#### `task ares:red:local: TARGET=<ip>`

Run Red Team using `.env` file instead of 1Password.

```bash
task ares:red:local: TARGET=192.168.1.100
```

#### Multi-Agent Operations

##### `task ares:red:multi TARGET=<target>`

Run multi-agent red team operation with clean, sequential output.

**Example:**

```bash
# Run against dreadgoad in us-west-1
task ares:red:multi TARGET=dreadgoad DOMAIN=sevenkingdoms.local \
  MODEL_ALL=gpt-5.2 \
  TARGET_REGION=us-west-1 \
  TARGET_PROFILE=lab
```

**Output:**

```text
🔍 Resolved 'dreadgoad' via AWS EC2 (lab/us-west-1)
✅ Found 5 target(s): 10.1.2.183,10.1.2.240,10.1.2.239,10.1.2.146,10.1.2.92

🎯 Operation ID: op-20260117-182705
🌐 Target domain: sevenkingdoms.local
🖥️  Target IPs: 10.1.2.183,10.1.2.240,10.1.2.239,10.1.2.146,10.1.2.92
🔌 K8s namespace: attack-simulation
📡 Redis: authenticated connection
📝 Logging to: ./logs/red-multi-op-20260117-182705-20260117-182707.log

🚀 Submitting operation to orchestrator service...
```

**Key Features:**

- **Sequential output**: All status information appears in proper order
- **Computed variables**: AWS lookups, Redis passwords, and operation IDs
  calculated before output
- **Clean structure**: Each phase (resolution → configuration → submission →
  logs) runs sequentially
- **Auto-logging**: All output captured to timestamped log files in `./logs/`

**Variables:**

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `TARGET` | *(required)* | EC2 Name tag filter or IP address |
| `DOMAIN` | `example.local` | Active Directory domain name |
| `OPERATION_ID` | `op-YYYYMMDD-HHMMSS` | Custom operation ID (auto-generated) |
| `RESUME` | `false` | Resume from checkpoint (`true`/`false`) |
| `TARGET_PROFILE` | `lab` | AWS profile for EC2 discovery |
| `TARGET_REGION` | `us-west-2` | AWS region for EC2 discovery |
| `K8S_NAMESPACE` | `attack-simulation` | Kubernetes namespace for agents |
| `MODEL_ALL` | *(see below)* | Override all agent models |

**Managing Operations:**

Tail logs for a specific multi-agent operation:

```bash
task ares:logs:operation OPERATION_ID=op-xxx
task ares:logs:operation OPERATION_ID=op-xxx FOLLOW=true LINES=200
```

Check operation status:

```bash
task ares:red:multi:status OPERATION_ID=op-xxx
```

List all multi-agent operations:

```bash
task ares:red:multi:list
```

List multi-agent operations and their Redis queue state:

```bash
task ares:red:multi:queue
```

Clear multi-agent Redis operation cache (drops ops/locks/status):

```bash
task ares:red:multi:redis:clear
```

List multi-agent Redis operations, statuses, and locks:

```bash
task ares:red:multi:redis:list
```

#### `task ares:investigate`

Investigate a specific alert from a JSON file.

**Example:**

```bash
# Create alert.json with alert data
cat > alert.json <<EOF
{
  "labels": {
    "alertname": "HighCPUUsage",
    "severity": "warning",
    "instance": "web-01",
    "job": "kubernetes-nodes"
  },
  "annotations": {
    "summary": "High CPU usage detected",
    "description": "CPU usage is above 80% for 5 minutes"
  },
  "startsAt": "2024-01-15T10:00:00Z"
}
EOF

# Investigate the alert
task ares:investigate ALERT=alert.json
```

### Configuration

#### `task ares:config:check`

Check configuration and verify 1Password access.

**Example:**

```bash
task ares:config:check
```

**Output:**

```text
Checking Ares configuration...

Environment:
  Python: Python 3.11.7
  uv: uv 0.1.0

Configuration:
  Platform: https://platform.dev.plundr.ai/
  Organization: ares
  Workspace: ares-protocol
  Project: ares-soc
  Model: claude-sonnet-4-20250514
  Grafana: https://grafana.dev.plundr.ai

Checking 1Password CLI access...
  ✅ 1Password CLI installed: 2.24.0
  ✅ Dreadnode API key accessible
  ✅ Grafana API key accessible
  ✅ Anthropic API key accessible

Configuration check complete
```

#### `task ares:config:show`

Display current configuration (without secrets).

**Example:**

```bash
task ares:config:show
```

### Reports

#### `task ares:reports:list`

List all investigation reports.

**Example:**

```bash
task ares:reports:list
```

#### `task ares:reports:latest`

Display the most recent investigation report.

**Example:**

```bash
task ares:reports:latest
```

#### `task ares:reports:clean`

Remove all investigation reports (prompts for confirmation).

**Example:**

```bash
task ares:reports:clean
```

### Development

#### `task ares:version`

Show Ares version information.

**Example:**

```bash
task ares:version
```

#### `task ares:mitre:test`

Test MITRE ATT&CK data loading.

**Example:**

```bash
task ares:mitre:test
```

**Output:**

```text
✅ Loaded 642 techniques
✅ Loaded 14 tactics

Sample technique:
  ID: T1059.001
  Name: PowerShell
  Tactic: execution
```

## Configuration Variables

All tasks support the following configuration variables:

| Variable | Default | Description |
| --- | --- | --- |
| `MODEL` | `gpt-5.2` | LLM model to use |
| `MODEL_ALL` | `""` | Override all agents with one model value |
| `MODEL_ORCHESTRATOR` | `""` | Override multi-agent orchestrator model |
| `MODEL_WORKER` | `""` | Override multi-agent worker models |
| `MODEL_ENUM` | `""` | Override enum agent model |
| `MODEL_CRACKER` | `""` | Override cracker agent model |
| `MODEL_ACL` | `""` | Override ACL agent model |
| `MODEL_PRIVESC` | `""` | Override PrivEsc agent model |
| `MODEL_LATERAL` | `""` | Override lateral agent model |
| `MODEL_POISONING` | `""` | Override poisoning agent model |
| `MODEL_ATOMIC` | `""` | Override atomic agent model |
| `GRAFANA_URL` | `https://grafana.dev.plundr.ai` | Grafana URL for alerts |
| `POLL_INTERVAL` | `30` | Seconds between alert polls |
| `MAX_STEPS` | `50` | Maximum agent steps for polling mode (Taskfile override, code default is 30) |
| `MAX_STEPS_ONCE` | `15` | Maximum agent steps for once/investigate modes |
| `REPORT_DIR` | `./reports` | Directory for markdown reports |
| `DREADNODE_SERVER_URL` | `https://platform.dev.plundr.ai/` | Dreadnode platform URL |
| `DREADNODE_ORGANIZATION` | `ares` | Dreadnode organization name |
| `DREADNODE_WORKSPACE` | `ares-protocol` | Dreadnode workspace name |
| `DREADNODE_PROJECT` | `ares-soc` | Dreadnode project name |

**Model precedence (multi-agent):**

1. `MODEL_ENUM` / `MODEL_CRACKER` / `MODEL_ACL` / `MODEL_PRIVESC` /
   `MODEL_LATERAL` / `MODEL_POISONING` / `MODEL_ATOMIC`
2. `MODEL_ORCHESTRATOR` (orchestrator only)
3. `MODEL_WORKER` (all non-orchestrator agents)
4. `MODEL_ALL`
5. `MODEL`

**Stop Conditions:**

The agent will stop when **any** of these conditions are met:

- Agent calls `complete_investigation()` (normal completion)
- Agent calls `escalate_investigation()` (escalation to human)
- 5 Loki/Prometheus queries executed
- **20 total tool calls made** (prevents infinite loops)
- `max_steps` LLM round trips reached

**Timeout Behavior:**

The agent has multiple timeout layers:

- Hard timeout: `max_steps × 60 seconds` (1 minute per step)
- Watchdog thread: Force-exits if timeout exceeded

| Mode | Default Steps | Max Timeout |
| --- | --- | --- |
| `ares:blue:once:` | 15 | ~15 minutes |
| `ares:blue:local:once:` | 15 | ~15 minutes |
| `ares:investigate` | 15 | ~15 minutes |
| `ares:blue:` (polling) | 50 | ~50 minutes per alert |
| `ares:blue:local:` (polling) | 50 | ~50 minutes per alert |

**Example with custom variables:**

```bash
task ares:run \
  MODEL=gpt-4o \
  GRAFANA_URL=http://grafana.prod.example.com:3000 \
  LOKI_URL=http://loki.prod.example.com:3100 \
  PROMETHEUS_URL=http://prometheus.prod.example.com:9090 \
  POLL_INTERVAL=60 \
  MAX_STEPS=200 \
  REPORT_DIR=./production-reports \
  DREADNODE_PROJECT=ares-prod
```

## 1Password Setup

### Required Items

Ares expects the following items in 1Password:

1. **Dreadnode Dev Platform** (Required)
   - Field: `api-key`
   - Used for: Platform observability and tracing

2. **Ares Grafana MCP** (Required for Blue Team)
   - Field: `grafana-token`
   - Used for: Alert polling and Loki/Prometheus queries

3. **claude.ai** (Required)
   - Field: `dreadnode-api-key`
   - Used for: Claude model inference

### Creating 1Password Items

If items don't exist, create them:

```bash
# Create Dreadnode item
op item create \
  --category="API Credential" \
  --title="Dreadnode Dev Platform" \
  api-key="your-dreadnode-api-key"

# Create Grafana item
op item create \
  --category="API Credential" \
  --title="Ares Grafana MCP" \
  grafana-token="your-grafana-token"

# Create Anthropic item
op item create \
  --category="API Credential" \
  --title="claude.ai" \
  dreadnode-api-key="your-anthropic-api-key"
```

### Verifying 1Password Access

Test that you can retrieve the API keys:

```bash
# Test Dreadnode key
op item get "Dreadnode Dev Platform" --fields api-key --reveal

# Test Grafana key
op item get "Ares Grafana MCP" --fields grafana-token --reveal

# Test Anthropic key
op item get "claude.ai" --fields dreadnode-api-key --reveal
```

## Common Workflows

### Blue Team Development Workflow

```bash
# 1. Check configuration
task ares:config:check

# 2. Test MITRE data loading
task ares:mitre:test

# 3. Run Blue Team agent in poll mode
task ares:blue:

# 4. In another terminal, check reports
task ares:reports:list

# 5. View latest report
task ares:reports:latest
```

### Blue Team Production Workflow

```bash
# Run with production configuration
task ares:blue: \
  GRAFANA_URL=http://grafana.prod.example.com:3000 \
  DREADNODE_PROJECT=ares-prod \
  POLL_INTERVAL=60
```

### Single Alert Investigation

```bash
# 1. Create alert JSON
cat > suspicious-activity.json <<EOF
{
  "labels": {
    "alertname": "SuspiciousProcessExecution",
    "severity": "high",
    "host": "web-01"
  }
}
EOF

# 2. Investigate
task ares:investigate ALERT=suspicious-activity.json

# 3. View report
task ares:reports:latest
```

### Red Team Workflow

```bash
# 1. Run red team agent (discovers target via EC2 Name tag)
task -y ares:red TARGET=dreadgoad

# Or target a specific IP directly
task ares:red: TARGET=192.168.1.100

# 2. Monitor progress (reports generated on completion)
task ares:reports:latest
```

### Remote Dev Workflow

Use remote tasks to sync code to running pods and manage dev PVCs.

```bash
# One-time sync of current branch changes
task remote:sync:branch

# Full sync of src/ares tree
task remote:sync:full

# Clear dev code from PVCs (wipes /ares/src/ares in pods)
task remote:pvc:clear CONFIRM=true
```

## Troubleshooting

### 1Password CLI Not Found

```bash
# Install 1Password CLI
# macOS
brew install --cask 1password-cli

# Linux
curl -sS https://downloads.1password.com/linux/keys/1password.asc | \
sudo gpg --dearmor --output /usr/share/keyrings/1password-archive-keyring.gpg
```

### API Key Not Found

If you get "API key not found" errors:

1. Check 1Password item names match exactly:
   - "Dreadnode Dev Platform"
   - "Grafana"
   - "Anthropic"

2. Verify field name is "api-key"

3. Ensure you're signed into 1Password CLI:

   ```bash
   op signin
   ```

### Task Not Trusted

```bash
# Trust remote taskfiles
task --trust

# Or trust permanently
echo 'export TASK_X_REMOTE_TASKFILES=1' >> ~/.bashrc
source ~/.bashrc
```

## Additional Tasks

The Taskfile also includes standard development tasks:

- `task init` - Initialize project
- `task clean` - Clean Python artifacts
- `task mypy` - Run type checking
- `task ruff` - Run linting
- `task pytest` - Run tests
- `task pre-commit:run-hooks` - Run pre-commit hooks

For a complete list of available tasks:

```bash
task --list
```
