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
│   ├── eval/                    # Evaluation framework
│   ├── templates/               # Jinja2 templates for prompts
│   ├── main.py                  # CLI entry point
│   └── cli_ops.py               # CLI operations
├── tests/                       # Test suite
├── docs/                        # Documentation
├── config/                      # Configuration files
├── scripts/                     # Utility scripts
├── .taskfiles/                  # Task runner definitions
└── .github/                     # CI/CD workflows
```

## Core Package (`src/ares/core/`)

The central framework for both blue and red team operations.

### Primary Components

| File/Package | Purpose |
| ---- | ------- |
| `dispatcher/` | Red team task dispatcher - orchestrates worker agents |
| `worker/` | Worker agent implementation for executing specialized tasks |
| `orchestrator/` | Multi-agent orchestration and coordination |
| `replay/` | Deterministic replay for debugging and testing |
| `factories/` | Agent and worker factory implementations |
| `models.py` | Data models (Credential, Host, Evidence, Target, etc.) |
| `task_queue.py` | Redis-based task queue for multi-agent coordination |
| `persistence.py` | State persistence and serialization |
| `recovery.py` | Operation checkpoint and recovery management |
| `state_backend.py` | Redis state backend for persistent storage |
| `workflows.py` | Credential expansion and exploitation workflows |

### Supporting Components

| File | Purpose |
| ---- | ------- |
| `config.py` | Configuration loading and environment management |
| `correlation.py` | Red-Blue correlation and timeline generation |
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
| `alert_correlation.py` | Alert clustering for blue team investigations |
| `capability_registry.py` | Agent capability registration and lookup |
| `context_manager.py` | Context window management and compaction |
| `tool_retrieval.py` | Dynamic tool loading and retrieval |
| `litellm_env.py` | LiteLLM environment configuration |
| `rigging_patches.py` | Rigging framework patches and extensions |
| `exceptions.py` | Custom exception definitions |
| `logging_utils.py` | Logging utilities |

### Dispatcher (`src/ares/core/dispatcher/`)

| File | Purpose |
| ---- | ------- |
| `_dispatcher.py` | Core dispatcher implementation |
| `routing.py` | Task routing and role-based dispatch |
| `throttling.py` | Task throttling and rate limiting |
| `persistence.py` | Dispatcher state persistence to Redis |
| `result_processing.py` | Task result processing and state updates |
| `publishing.py` | Credential/hash broadcasting to shared state |
| `vulnerability.py` | Vulnerability queue management |
| `deferred_queue.py` | Deferred task queue for delayed execution |
| `monitoring.py` | Operation monitoring and health checks |
| `announcements.py` | Domain admin and completion announcements |
| `status.py` | Operation status tracking |
| `extraction.py` | Result extraction from task outputs |
| `acl_chains.py` | ACL attack chain processing |
| `agents.py` | Agent registration and management |

### Worker (`src/ares/core/worker/`)

| File | Purpose |
| ---- | ------- |
| `_worker.py` | Core worker agent implementation |
| `operations.py` | Worker operation handlers |
| `prompts.py` | Worker prompt generation |
| `dc_resolution.py` | Domain controller resolution logic |
| `cleanup.py` | Worker cleanup and shutdown |

### Orchestrator (`src/ares/core/orchestrator/`)

| File | Purpose |
| ---- | ------- |
| `_orchestrator.py` | Core orchestrator implementation |

### Replay (`src/ares/core/replay/`)

| File | Purpose |
| ---- | ------- |
| `store.py` | Replay data storage |
| `determinism.py` | Deterministic replay utilities |
| `wrappers.py` | Tool wrappers for replay capture |

### Factories (`src/ares/core/factories/`)

| File | Purpose |
| ---- | ------- |
| `red_agents.py` | Red team agent factory and toolset assignment |
| `blue_factory.py` | Blue team agent factory |

## Tools (`src/ares/tools/`)

### Red Team Tools (`tools/red/`)

| File/Directory | Purpose |
| ---- | ------- |
| `credential_discovery/` | Credential discovery module (see below) |
| `reconnaissance.py` | Network scanning, user enumeration, share discovery |
| `orchestrator.py` | Orchestrator-specific tool dispatch and reporting |
| `kerberos_attacks.py` | Kerberos delegation attacks, ticket generation, ADCS |
| `lateral_movement.py` | PSExec, WMI, SMB execution, host compromise |
| `acl_attacks.py` | ACL abuse, BloodHound integration, privilege escalation paths |
| `privilege_escalation.py` | Local privilege escalation tools |
| `coercion.py` | NTLM coercion, responder integration, relay attacks |
| `cve_exploits.py` | CVE exploitation tools |
| `common.py` | Shared utilities (parsing, error handling) |
| `reporting.py` | Operation summary and result reporting |

#### Credential Discovery (`tools/red/credential_discovery/`)

| File | Purpose |
| ---- | ------- |
| `discovery.py` | Password spray, username=password, LDAP descriptions |
| `harvesting.py` | secretsdump, kerberoast, AS-REP roast, credential extraction |
| `cracking.py` | Hash cracking with hashcat and john |
| `pilfering.py` | Share spidering, GPP passwords, SYSVOL scripts |

#### Tool Classes (Exported from `tools/red/__init__.py`)

| Class | Purpose |
| ---- | ------- |
| `NetworkEnumerationTools` | nmap, user/share enumeration, domain info |
| `BloodHoundTools` | AD relationship mapping, attack path analysis |
| `PostureValidationTools` | Access validation and reachability checks |
| `CredentialDiscoveryTools` | Password spray, username=password, LDAP search |
| `CredentialHarvestingTools` | secretsdump, kerberoast, AS-REP roast |
| `SharePilferingTools` | GPP passwords, SYSVOL scripts, share spidering |
| `CrackingTools` | hashcat, john |
| `ACLExploitTools` | bloodyAD, pywhisker, dacledit, targeted kerberoast |
| `CertipyTools` | ADCS exploitation (ESC1-ESC8) |
| `DelegationTools` | Constrained/unconstrained delegation attacks |
| `GMSATools` | gMSA password extraction |
| `GoldenTicketTools` | Kerberos ticket forging |
| `TrustAttackTools` | Domain/forest trust attacks |
| `MSSQLTools` | SQL Server attacks, linked server pivoting |
| `CVEExploitTools` | Known vulnerability exploits |
| `LateralMovementTools` | psexec, evil-winrm, wmiexec, smbexec |
| `PrivilegeEscalationTools` | Local privilege escalation |
| `CoercionTools` | PetitPotam, Coercer, PrinterBug |
| `CoercionNetworkTools` | Responder, ntlmrelayx, mitm6 |
| `OrchestratorTools` | Dispatch functions for worker agents |
| `CrackerCallbackTools` | Cracker callback functions |
| `LateralCallbackTools` | Lateral movement callback functions |
| `RedTeamReportingTools` | Status reporting, operation control |

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

Red team agents are now created dynamically via `core/factories/red_agents.py`.
The orchestrator runs in `core/orchestrator/` and workers run in `core/worker/`.

## Evaluation Framework (`src/ares/eval/`)

| File | Purpose |
| ---- | ------- |
| `workflow.py` | Evaluation runner and scenario execution |
| `results.py` | Evaluation result models and aggregation |
| `scorers.py` | IOC detection and technique coverage scoring |
| `ground_truth.py` | Ground truth extraction from red team state |
| `detection_playbook.py` | Detection playbook generation from red ops |
| `gap_analysis.py` | Detection gap analysis between red and blue |

## Reports (`src/ares/reports/`)

| File | Purpose |
| ---- | ------- |
| `investigation.py` | Blue team investigation report generation |
| `redteam.py` | Red team operation report generation |
| `blueteam.py` | Blue team consolidated operation reports |
| `user_summary.py` | User-facing summary generation |

## Data Models (`src/ares/core/models.py`)

### Investigation Models

- `InvestigationState` - Complete investigation state
- `InvestigativeQuestion` - Generated questions
- `QuestionSource` - Question generation engine
- `InvestigationStage` - Investigation workflow stage
- `Evidence` - Discovered evidence

### Red Team Models

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
├── blueteam/                # Blue team templates
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
│   │   ├── coercion.md.jinja
│   │   └── system_instructions.md.jinja
│   └── reports/             # Operation reports
├── tools/                   # Tool prompts
└── README.md.j2             # Template documentation
```

## CLI Entry Points (`src/ares/main.py`)

| Command | Purpose |
| ------- | ------- |
| `ares` (default) | Run blue team in poll mode (Grafana alerts) |
| `ares investigate-alert` | Investigate a specific alert (JSON file or string) |
| `ares multi-agent` | Run multi-agent red team operation |
| `ares worker` | Run specialized worker agent |
| `ares evaluate` | Evaluate blue team against red team state |
| `ares evaluate-dataset` | Evaluate against a dataset of red team operations |
| `ares version` | Print version information |

Additional CLI commands are in `cli_ops.py`:

| Function | Purpose |
| -------- | ------- |
| `loot` | Extract operation state from Redis |
| `status` | Check operation status |
| `list_operations` | List all operations |
| `inject_credential` | Inject credential into running operation |
| `inject_vulnerability` | Inject vulnerability into running operation |

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
    ↓ Redis task queues + pub/sub
Worker Pods:
    ├── RECON (ares-recon-agent)
    ├── CREDENTIAL_ACCESS (ares-credential-access-agent)
    ├── CRACKER (ares-cracker-agent)
    ├── ACL (ares-acl-agent)
    ├── PRIVESC (ares-privesc-agent)
    ├── LATERAL (ares-lateral-movement-agent)
    └── COERCION (ares-coercion-agent)
```

**Key Principles:**

1. Orchestrator coordinates, workers execute
2. Workers are specialists with domain-specific tools
3. Shared state via Redis (write-through cache pattern)

**For detailed agent configuration (max_steps, tool classes, model selection):**
See [Agent Quick Reference](red.md#agent-quick-reference) in `docs/red.md`.

**Pod Labels:**

- Orchestrator: `app.kubernetes.io/name=ares-orchestrator`
- Workers: `ares.dreadnode.io/role={recon,credential_access,cracker,acl,privesc,lateral,coercion}`

**Namespace:** `attack-simulation`

## Tests (`tests/`)

### Test Categories

| Category | Files |
| -------- | ----- |
| Core Framework | `test_dispatcher.py`, `test_worker.py`, `test_orchestrator.py`, `test_task_queue.py` |
| Models & State | `test_models.py`, `test_persistence.py`, `test_state_backend.py` |
| Multi-Agent | `test_multi_agent_workflow.py`, `test_red_agents.py` |
| Red Team Tools | `test_recon_toolset.py`, `test_lateral_movement.py`, `test_orchestrator_tools.py` |
| Blue Team Tools | `test_actions.py`, `test_grafana.py`, `test_investigation_tools.py` |
| Reports | `test_reports_investigation.py`, `test_reports_redteam.py` |
| Evaluation | `test_eval_workflow.py`, `test_scorers.py` |
| Integration | `tests/integration/` |

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

1. `docs/red.md` - Multi-agent architecture principles (includes Agent Quick Reference)
2. `docs/blue.md` - Blue team investigation workflow
3. `src/ares/core/models.py` - Data model definitions
4. `src/ares/core/dispatcher/` - Task coordination logic
5. `src/ares/core/worker/` - Worker agent implementation
6. `src/ares/core/orchestrator/` - Orchestrator implementation
7. `config/multi-agent-production.yaml` - Agent configurations

### Entry Points to Understand Flow

1. `src/ares/main.py` - CLI commands
2. `src/ares/agents/blue/soc_investigator.py` - Blue team orchestrator
3. `src/ares/core/orchestrator/_orchestrator.py` - Red team orchestrator
4. `src/ares/core/worker/_worker.py` - Worker agent task loop
5. `src/ares/core/task_queue.py` - Message passing
6. `src/ares/core/factories/red_agents.py` - Agent creation and toolsets

### Core Dependencies

- **dreadnode** - Agent SDK
- **rigging** - LLM interaction framework
- **cyclopts** - CLI framework
- **loguru** - Logging
- **httpx** - HTTP client
- **redis** - Multi-agent coordination
- **kubernetes** - K8s integration
- **boto3** - AWS integration
- **litellm** - LLM provider abstraction
