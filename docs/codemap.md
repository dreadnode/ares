# Ares Codemap

This document provides a comprehensive map of the Ares codebase structure,
helping developers navigate and understand the project organization.

## Project Overview

**Ares** is an autonomous security operations agent with dual capabilities:

- **Blue Team**: SOC alert investigation and threat hunting
- **Red Team**: Penetration testing and Active Directory exploitation

Built on the Dreadnode Agent SDK and MITRE ATT&CK framework, it uses
LLM-powered autonomous agents for both defensive and offensive security
operations.

## Directory Structure

```text
ares/
├── src/ares/                    # Main Python package
│   ├── core/                    # Core framework and infrastructure
│   ├── tools/                   # Tool implementations (red/blue/shared)
│   ├── agents/                  # Agent orchestrators
│   ├── integrations/            # Third-party integrations
│   ├── reports/                 # Report generation
│   ├── templates/               # Jinja2 templates for prompts
│   ├── main.py                  # CLI entry point
│   └── cli_ops.py               # CLI operations
├── tests/                       # Test suite (60+ files)
├── docs/                        # Documentation
├── config/                      # Configuration files
├── scripts/                     # Utility scripts
├── .taskfiles/                  # Task runner definitions
└── .github/                     # CI/CD workflows
```

## Core Package (`src/ares/core/`)

The central framework for both blue and red team operations.

### Primary Components

| File | Purpose |
| ---- | ------- |
| `dispatcher.py` | Red team task dispatcher - orchestrates worker agents |
| `worker.py` | Worker agent implementation for executing specialized tasks |
| `orchestrator.py` | Multi-agent orchestration and coordination |
| `models.py` | Data models (Credential, Host, Evidence, Target, etc.) |
| `task_queue.py` | Redis-based task queue for multi-agent coordination |
| `persistence.py` | State persistence and serialization |
| `recovery.py` | Operation checkpoint and recovery management |

### Supporting Components

| File | Purpose |
| ---- | ------- |
| `config.py` | Configuration loading and environment management |
| `correlation.py` | Evidence correlation and timeline generation |
| `engines.py` | Question generation engines (MITRE, pyramid climb, attack chains) |
| `evidence_validation.py` | Evidence validation and deduplication |
| `k8s_executor.py` | Kubernetes pod execution interface |
| `lateral_analyzer.py` | Graph-based lateral movement analysis |
| `messages.py` | Message serialization for inter-agent communication |
| `orchestrator_client.py` | Client for communicating with orchestrator |
| `orchestrator_service.py` | Orchestrator service pod implementation |
| `query_resilience.py` | Query retry logic and resilience patterns |
| `redis_client.py` | Redis client wrapper |
| `remote.py` | Remote execution on Kubernetes pods |
| `templates.py` | Jinja2 template loading and rendering |
| `workflows.py` | Credential expansion and exploitation workflows |

### Factories (`src/ares/core/factories/`)

| File | Purpose |
| ---- | ------- |
| `red_agents.py` | Red team agent factory |
| `red_factory.py` | Red team dispatcher and worker creation |
| `blue_factory.py` | Blue team agent factory |

## Tools (`src/ares/tools/`)

### Red Team Tools (`tools/red/`)

| File | Purpose |
| ---- | ------- |
| `credential_discovery.py` | Kerberoasting, AS-REP roasting, password spray, hash extraction |
| `reconnaissance.py` | Network scanning, user enumeration, share discovery |
| `orchestrator.py` | Orchestrator-specific tool dispatch and reporting |
| `kerberos_attacks.py` | Kerberos delegation attacks, ticket generation |
| `lateral_movement.py` | PSExec, WMI, SMB execution, host compromise |
| `acl_attacks.py` | ACL abuse, BloodHound integration, privilege escalation paths |
| `coercion.py` | NTLM coercion, responder integration, relay attacks |
| `cve_exploits.py` | ADCS exploitation (ESC1-15), direct CVE exploitation |
| `common.py` | Shared utilities (parsing, error handling) |
| `reporting.py` | Operation summary and result reporting |

### Blue Team Tools (`tools/blue/`)

| File | Purpose |
| ---- | ------- |
| `investigation.py` | Core investigation workflows |
| `grafana.py` | Grafana alert polling and querying |
| `query_templates.py` | Loki log query templates for Windows events |
| `observability.py` | Prometheus/Grafana metric queries |
| `actions.py` | Investigation action implementations |
| `learning.py` | Machine learning for anomaly detection |

### Shared Tools (`tools/shared/`)

| File       | Purpose                              |
| ---------- | ------------------------------------ |
| `mitre.py` | MITRE ATT&CK framework integration   |

## Agents (`src/ares/agents/`)

### Blue Team (`agents/blue/`)

| File                    | Purpose                          |
| ----------------------- | -------------------------------- |
| `soc_investigator.py`   | SOC investigation orchestrator   |

### Red Team (`agents/red/`)

| File           | Purpose                            |
| -------------- | ---------------------------------- |
| `pentester.py` | Penetration testing orchestrator   |

## Data Models (`src/ares/core/models.py`)

### Investigation Models

- `InvestigationState` - Complete investigation state
- `InvestigativeQuestion` - Generated questions
- `QuestionSource` - Question generation engine
- `InvestigationStage` - Investigation workflow stage
- `Evidence` - Discovered evidence

### Red Team Models

- `RedTeamState` - Single-agent red team state
- `SharedRedTeamState` - Multi-agent shared state
- `Target` - Target system configuration
- `Host` - Discovered host with services
- `Credential` - Username/password/hash/token
- `Hash` - Password hash with cracking status
- `User` - Domain user with flags
- `Share` - SMB share configuration
- `VulnerabilityInfo` - Discovered vulnerabilities
- `TaskInfo` / `TaskResult` - Task tracking
- `AgentRole` - Agent role enumeration (RECON, CREDENTIAL_ACCESS, etc.)
- `AgentInfo` / `AgentLocalState` - Agent state tracking

### Other Models

- `PyramidLevel` - Pyramid of Pain levels (1-6)
- `TimelineEvent` - Timeline entry with MITRE technique
- `TaskStatus` - Task execution status

## Templates (`src/ares/templates/`)

```text
templates/
├── agent/                   # Agent system prompts
│   ├── initial_alert_prompt.md.jinja
│   └── system_instructions.md.jinja
├── engines/                 # Question generation engines
│   ├── attack_chains.yaml
│   ├── climb_strategies.yaml
│   ├── detection_recipes.yaml
│   └── mitre_*.md.jinja
├── reports/                 # Report sections
│   ├── executive_summary.md.jinja
│   ├── timeline.md.jinja
│   ├── mitre_mapping.md.jinja
│   └── recommendations.md.jinja
├── redteam/
│   ├── agents/              # Agent-specific templates
│   │   ├── orchestrator.md.jinja
│   │   ├── recon.md.jinja
│   │   ├── credential_access.md.jinja
│   │   ├── cracker.md.jinja
│   │   ├── acl.md.jinja
│   │   ├── privesc.md.jinja
│   │   ├── lateral.md.jinja
│   │   └── coercion.md.jinja
│   └── reports/             # Operation reports
└── tools/                   # Tool prompts
```

## CLI Entry Points (`src/ares/main.py`)

| Command | Purpose |
| ------- | ------- |
| `ares investigate-alert` | Investigate a Grafana alert |
| `ares red-team` | Run single-agent red team operation |
| `ares multi-agent-red` | Run multi-agent red team operation |
| `ares worker` | Run worker agent |
| `ares orchestrator` | Run orchestrator service |
| `ares loot` | Extract operation state |
| `ares config` | Show configuration |

## Configuration

### Project Configuration (`pyproject.toml`)

- Python 3.10-3.13 support
- Dependencies: dreadnode, redis, kubernetes, boto3, httpx, cyclopts
- pytest with asyncio mode
- mypy strict type checking
- ruff linting

### Multi-Agent Configuration (`config/multi-agent-production.yaml`)

Agent configurations for:

- Orchestrator
- RECON
- CREDENTIAL_ACCESS
- CRACKER
- ACL
- PRIVESC
- LATERAL
- COERCION

Each agent defines: model selection, max_steps, pod_selector, capabilities.

## Multi-Agent Architecture

```text
Orchestrator Pod (ares-orchestrator)
    ↓ Redis pub/sub
Worker Pods:
    ├── RECON (ares-recon-agent)
    ├── CREDENTIAL_ACCESS (ares-credential-agent)
    ├── CRACKER (ares-cracker-agent)
    ├── ACL (ares-acl-agent)
    ├── PRIVESC (ares-privesc-agent)
    ├── LATERAL (ares-lateral-agent)
    └── COERCION (ares-coercion-agent)
```

**Key Principles:**

1. Orchestrator coordinates, workers execute
2. Workers are specialists with domain-specific tools
3. Shared state via Redis

**Pod Labels:**

- All agents: `ares.dreadnode.io/component=red-team`
- Orchestrator: `app.kubernetes.io/name=ares-orchestrator`
- Workers: `ares.dreadnode.io/role={enum,cracker,acl,privesc,lateral,coercion}`

**Namespace:** `attack-simulation`

## Tests (`tests/`)

### Test Categories

| Category | Files |
| -------- | ----- |
| Core Framework | `test_dispatcher.py`, `test_worker.py`, `test_orchestrator.py`, `test_task_queue.py` |
| Models & State | `test_models.py`, `test_persistence.py` |
| Multi-Agent | `test_multi_agent_workflow.py`, `test_red_agents.py`, `test_red_factory.py` |
| Red Team Tools | `test_recon_toolset.py`, `test_lateral_movement.py`, `test_orchestrator_tools.py` |
| Blue Team Tools | `test_actions.py`, `test_grafana.py`, `test_investigation_tools.py` |
| Reports | `test_reports_investigation.py`, `test_reports_redteam.py` |
| Integration | `tests/integration/test_multi_agent_workflow.py` |

### Test Fixtures (`tests/conftest.py`)

- Alert fixtures (sample_alert, critical_alert, kerberoasting_alert)
- Investigation state fixtures
- Red team state fixtures
- MITRE technique fixtures

## Documentation (`docs/`)

| File | Purpose |
| ---- | ------- |
| `index.md` | Landing page |
| `red.md` | Red team multi-agent architecture (AUTHORITATIVE) |
| `blue.md` | Blue team investigation workflow |
| `contributing.md` | Contribution guidelines |
| `grafana_mcp_usage.md` | Grafana MCP integration guide |
| `prompt_templates.md` | LLM prompt template documentation |
| `remote-development.md` | K8s remote development guide |
| `taskfile_usage.md` | Task runner command reference |

## Quick Reference

### Key Files to Understand the System

1. `docs/red.md` - Multi-agent architecture principles
2. `src/ares/core/models.py` - Data model definitions
3. `src/ares/core/dispatcher.py` - Task coordination logic
4. `src/ares/core/worker.py` - Worker agent implementation
5. `config/multi-agent-production.yaml` - Agent configurations

### Entry Points to Understand Flow

1. `src/ares/main.py` - CLI commands
2. `src/ares/agents/red/pentester.py` - Red team orchestrator
3. `src/ares/agents/blue/soc_investigator.py` - Blue team orchestrator
4. `src/ares/core/orchestrator.py` - Multi-agent coordination
5. `src/ares/core/task_queue.py` - Message passing

### Core Dependencies

- **dreadnode** - Agent SDK
- **cyclopts** - CLI framework
- **loguru** - Logging
- **httpx** - HTTP client
- **redis** - Multi-agent coordination
- **kubernetes** - K8s integration
- **boto3** - AWS integration
