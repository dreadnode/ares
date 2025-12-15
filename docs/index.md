# Ares Documentation

Welcome to the Ares documentation.
Ares is an autonomous Security Operations Center (SOC) investigation agent.

## Quick Links

- [Project README](../README.md)
- [Contributing Guide](contributing.md)
- [Security Policy](../SECURITY.md)
- [Changelog](../CHANGELOG.md)

## Overview

Ares transforms security alerts into actionable threat intelligence through
autonomous, question-driven investigations.
Built with the Dreadnode Agent SDK, it systematically analyzes security events
using MITRE ATT&CK framework and the Pyramid of Pain methodology.

## Key Capabilities

- Autonomous alert investigation
- MITRE ATT&CK technique mapping
- Pyramid of Pain-based analysis elevation
- Multi-stage investigation workflow
- Integration with Grafana, Loki, and Prometheus
- Comprehensive markdown reporting

## Getting Started

See the [README](../README.md) for installation instructions and usage
examples.

## Repository Layout

```text
ares/
├── src/ares/           # Main source code
├── tests/              # Test suite
├── docs/               # Documentation
├── reports/            # Generated investigation reports
└── pyproject.toml      # Project configuration
```

## Development

For development setup and contribution guidelines, see the
[Contributing Guide](contributing.md).
