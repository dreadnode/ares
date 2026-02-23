# Ares Documentation

Welcome to the Ares documentation.
Ares is an autonomous security operations agent with dual capabilities:
**Blue Team** (SOC investigation) and **Red Team** (penetration testing).

## Quick Links

- [Taskfile Usage Guide](taskfile_usage.md)
- [Grafana MCP Integration](grafana_mcp_usage.md)
- [Prompt Templates](prompt_templates.md)
- [Contributing Guide](contributing.md)
- [Blue Team Operations](blue.md)
- [Red Team Operations](red.md)
- [Red Team Phase Priority](phase-priority.md) - Agent utility by engagement phase

## Overview

Ares provides autonomous security operations through two specialized agents:

**Blue Team Agent** - Transforms security alerts into actionable threat
intelligence through question-driven investigations. Uses MITRE ATT&CK
framework and Pyramid of Pain methodology.

**Red Team Agent** - Autonomous penetration testing for Active Directory
environments. Systematically enumerates, harvests credentials, and attempts
domain admin access.

Built with the [Dreadnode Agent SDK](https://github.com/dreadnode/agent-sdk).

## Key Capabilities

### Blue Team (SOC Investigation)

- Autonomous Grafana alert investigation
- MITRE ATT&CK technique mapping
- Pyramid of Pain-based analysis elevation
- Multi-stage investigation workflow (Triage, Causation, Lateral, Synthesis)
- Integration with Grafana, Loki, and Prometheus via MCP
- Comprehensive markdown reporting

### Red Team (Penetration Testing)

- Active Directory enumeration (hosts, users, shares)
- Credential harvesting (secretsdump, kerberoasting, AS-REP roasting)
- Password hash cracking (hashcat, John the Ripper)
- BloodHound integration for ACL abuse paths
- ADCS exploitation (ESC1-15 vulnerabilities)
- Golden ticket generation
- Delegation attacks (RBCD, unconstrained, constrained)

## Getting Started

For installation instructions and usage examples, see the project README in the
root directory or visit the GitHub repository.

## Repository Layout

```text
ares/
├── src/ares/                    # Main package
│   ├── agents/                  # Agent orchestrators
│   │   ├── blue/                # SOC investigation agent
│   │   └── red/                 # Penetration testing agent
│   ├── core/                    # Core models and engines
│   │   ├── dispatcher/          # Task dispatch and routing
│   │   ├── worker/              # Worker agent implementation
│   │   ├── orchestrator/        # Orchestrator implementation
│   │   ├── factories/           # Agent factories
│   │   └── replay/              # Deterministic replay
│   ├── eval/                    # Evaluation framework
│   ├── integrations/            # External integrations (MITRE)
│   ├── reports/                 # Report generators
│   ├── templates/               # Jinja2 prompt templates
│   │   ├── blueteam/            # Blue team templates
│   │   ├── engines/             # Question engine templates
│   │   ├── redteam/             # Red team agent templates
│   │   └── reports/             # Report templates
│   └── tools/                   # Agent toolsets
│       ├── blue/                # Blue team tools
│       ├── red/                 # Red team tools
│       └── shared/              # Shared tools (MITRE)
├── config/                      # Configuration files
├── tests/                       # Test suite
├── docs/                        # Documentation
└── reports/                     # Generated reports
```

## Development

For development setup and contribution guidelines, see the
[Contributing Guide](contributing.md).
