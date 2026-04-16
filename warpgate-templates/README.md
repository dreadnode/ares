# Dreadnode Warpgate Templates

**Production-ready templates for building security tools and infrastructure using Warpgate.**

[![Pre-Commit](https://github.com/dreadnode/warpgate-templates/actions/workflows/pre-commit.yaml/badge.svg)](https://github.com/dreadnode/warpgate-templates/actions/workflows/pre-commit.yaml)
[![Validate Templates](https://github.com/dreadnode/warpgate-templates/actions/workflows/validate-templates.yaml/badge.svg)](https://github.com/dreadnode/warpgate-templates/actions/workflows/validate-templates.yaml)
[![Build and Push](https://github.com/dreadnode/warpgate-templates/actions/workflows/build-and-push-templates.yaml/badge.svg)](https://github.com/dreadnode/warpgate-templates/actions/workflows/build-and-push-templates.yaml)

---

## Overview

Dreadnode's template collection for [Warp Gate](https://github.com/cowdogmoo/warpgate) - a robust, automatable engine for building multi-architecture containers and golden images.

This repository provides production-ready templates for various security tools and frameworks, including:

- **Ares framework** - Specialized security assessment agents for Active Directory penetration testing, network enumeration, and credential cracking
- **Ares blue team** - Defensive security agents for incident triage, threat hunting, and lateral movement analysis
- **GPU-accelerated cracking** - CUDA/OpenCL hashcat images with NVIDIA GPU support
- **Ray cluster** - Base images and job runners for distributed computing with Ray (.NET and ADS experiments)
- **Crucible challenges** - FastAPI-based challenge images for CTF platforms with optional PyTorch support
- **GOAD infrastructure** - Pre-baked Windows Server AMIs for Game of Active Directory lab deployments

Templates support multi-architecture builds (amd64/arm64) where applicable and are designed for container-native and cloud deployments.

## Quick Start

```bash
# Install warpgate
go install github.com/CowDogMoo/warpgate/cmd/warpgate@latest

# Build an Ares agent
warpgate build templates/ares-base/warpgate.yaml --arch amd64

# Build and push to registry
warpgate build templates/ares-recon-agent/warpgate.yaml \
  --arch amd64 \
  --registry ghcr.io/dreadnode \
  --push
```

## Available Templates

### Ares Agent Templates

| Template | Description | Base Image | Platforms |
| -------- | ----------- | ---------- | --------- |
| [ares-base](./templates/ares-base) | Base Ares framework with Python and core dependencies | kalilinux/kali-rolling | Container (amd64, arm64) |
| [ares-orchestrator](./templates/ares-orchestrator) | Redis-based multi-agent coordinator | python:3.13.7-slim | Container (amd64, arm64) |
| [ares-worker](./templates/ares-worker) | Task polling agent for orchestration | ares-base | Container (amd64, arm64) |
| [ares-acl-agent](./templates/ares-acl-agent) | Active Directory ACL exploitation agent | ares-base | Container (amd64, arm64) |
| [ares-coercion-agent](./templates/ares-coercion-agent) | NTLM relay and authentication coercion tools | ares-base | Container (amd64, arm64) |
| [ares-cracker-agent](./templates/ares-cracker-agent) | Password cracking agent with hashcat and john | ares-base | Container (amd64, arm64) |
| [ares-credential-access-agent](./templates/ares-credential-access-agent) | Kerberos attacks and credential dumping tools | ares-base | Container (amd64, arm64) |
| [ares-lateral-movement-agent](./templates/ares-lateral-movement-agent) | Post-exploitation lateral movement tools | ares-base | Container (amd64, arm64) |
| [ares-privesc-agent](./templates/ares-privesc-agent) | Privilege escalation tools | ares-base | Container (amd64, arm64) |
| [ares-recon-agent](./templates/ares-recon-agent) | Network reconnaissance and AD enumeration tools | ares-base | Container (amd64, arm64) |

### Ares Blue Team Templates

| Template | Description | Base Image | Platforms |
| -------- | ----------- | ---------- | --------- |
| [ares-blue-agent](./templates/ares-blue-agent) | Defensive security operations agent | ares-base | Container (amd64, arm64) |
| [ares-blue-triage-agent](./templates/ares-blue-triage-agent) | Initial incident assessment and alerting | ares-base | Container (amd64, arm64) |
| [ares-blue-threat-hunter-agent](./templates/ares-blue-threat-hunter-agent) | Proactive threat detection and investigation | ares-base | Container (amd64, arm64) |
| [ares-blue-lateral-analyst-agent](./templates/ares-blue-lateral-analyst-agent) | Lateral movement detection and analysis | ares-base | Container (amd64, arm64) |

### GPU-Accelerated Cracking Templates

| Template | Description | Base Image | Platforms |
| -------- | ----------- | ---------- | --------- |
| [ares-cracker-base-gpu](./templates/ares-cracker-base-gpu) | Base image with CUDA/OpenCL GPU-accelerated hashcat | nvidia/cuda:12.6.0-runtime-ubuntu24.04 | Container (amd64) |
| [ares-cracker-agent-gpu](./templates/ares-cracker-agent-gpu) | Ares cracking agent with GPU-accelerated hashcat | ares-cracker-base-gpu | Container (amd64) |

### Ray Cluster Templates

| Template | Description | Base Image | Platforms |
| -------- | ----------- | ---------- | --------- |
| [ray-dotnet](./templates/ray-dotnet) | Ray cluster base image with .NET SDK support | Dockerfile | Container (amd64, arm64) |
| [ray-dotnet-job](./templates/ray-dotnet-job) | Ray .NET job runner with source code baked in | ray-dotnet | Container (amd64, arm64) |
| [ray-ads](./templates/ray-ads) | Ray cluster base image for ADS experiments | Dockerfile | Container (amd64, arm64) |
| [ray-ads-job](./templates/ray-ads-job) | Ray ADS job runner with source code baked in | ray-ads | Container (amd64, arm64) |

### Crucible Challenge Templates

| Template | Description | Base Image | Platforms |
| -------- | ----------- | ---------- | --------- |
| [crucible-challenge-core](./templates/crucible-challenge-core) | FastAPI challenge base with Gunicorn and uv | python:3.11-slim | Container (amd64, arm64) |
| [crucible-challenge-torch](./templates/crucible-challenge-torch) | Challenge image with PyTorch (CPU) | python:3.11-slim | Container (amd64, arm64) |
| [crucible-challenge-torch-gpu](./templates/crucible-challenge-torch-gpu) | Challenge image with PyTorch (CUDA GPU) | python:3.11-slim | Container (amd64) |

### GOAD Infrastructure Templates

| Template | Description | Base Image | Platform |
| -------- | ----------- | ---------- | -------- |
| [goad-dc-base](./templates/goad-dc-base) | Windows Server 2019 with AD DS role pre-installed | Windows Server 2019 | AMI (us-west-1) |
| [goad-dc-base-2016](./templates/goad-dc-base-2016) | Windows Server 2016 with AD DS role pre-installed | Windows Server 2016 | AMI (us-west-1) |
| [goad-mssql-base](./templates/goad-mssql-base) | Windows Server 2019 with MSSQL Express 2019 | Windows Server 2019 | AMI (us-west-1) |
| [goad-mssql-base-2016](./templates/goad-mssql-base-2016) | Windows Server 2016 with MSSQL Express 2019 | Windows Server 2016 | AMI (us-west-1) |
| [goad-member-base](./templates/goad-member-base) | Windows Server 2019 with IIS pre-installed | Windows Server 2019 | AMI (us-west-1) |
| [goad-member-base-2016](./templates/goad-member-base-2016) | Windows Server 2016 with IIS pre-installed | Windows Server 2016 | AMI (us-west-1) |

### Template Comparison

| Feature | Base | Recon | Coercion | Cracker | Credential | ACL | Lateral | Privesc |
| ------- | ---- | ----- | -------- | ------- | ---------- | --- | ------- | ------- |
| **Python 3.13.7** | Y | Y | Y | Y | Y | Y | Y | Y |
| **Ares Framework** | Y | Y | Y | Y | Y | Y | Y | Y |
| **uv Package Manager** | Y | Y | Y | Y | Y | Y | Y | Y |
| **Network Tools (nmap, etc)** | | Y | | | | | | |
| **Impacket** | | Y | | | Y | | Y | |
| **NetExec** | | Y | | | | | | |
| **BloodHound Python** | | Y | | | | | | |
| **Responder** | | | Y | | | | | |
| **mitm6** | | | Y | | | | | |
| **Coercer** | | | Y | | | | | |
| **Hashcat** | | | | Y | | | | |
| **John the Ripper** | | | | Y | | | | |
| **Kerberos Tools** | | | | | Y | | | |
| **bloodyAD** | | | | | | Y | | |
| **evil-winrm** | | | | | | | Y | |
| **lsassy** | | | | | | | Y | |

## Features

### Template Capabilities

- **Multi-Architecture**: Native builds for amd64 and arm64
- **Modular Design**: Choose the right agent for your needs
- **Optimized**: Aggressive cleanup for minimal image sizes
- **Python 3.13.7**: Latest Python runtime with modern tooling
- **uv Package Manager**: Fast dependency management
- **Security Focused**: Pre-configured AD assessment tools
- **Container-Native**: Designed for orchestrated deployments

## Usage Guide

### Prerequisites

- [Warp Gate](https://github.com/cowdogmoo/warpgate) CLI tool (`>= 3.0.0`)
- Docker or Podman for container builds

### Building Templates

#### Build Base Agent

```bash
# Single architecture
warpgate build templates/ares-base/warpgate.yaml --arch amd64

# Multi-architecture
warpgate build templates/ares-base/warpgate.yaml --arch amd64,arm64
```

#### Build Specialized Agents

```bash
# Cracker agent for password recovery
warpgate build templates/ares-cracker-agent/warpgate.yaml \
  --arch amd64 \
  --registry ghcr.io/dreadnode \
  --push

# Recon agent for network reconnaissance
warpgate build templates/ares-recon-agent/warpgate.yaml \
  --arch amd64 \
  --registry ghcr.io/dreadnode \
  --push
```

### Using Built Images

```bash
# Run base agent
docker run -it ghcr.io/dreadnode/ares-base:latest bash

# Run cracking workload
docker run -it ghcr.io/dreadnode/ares-cracker-agent:latest \
  hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# Run reconnaissance scan
docker run -it ghcr.io/dreadnode/ares-recon-agent:latest \
  netexec smb 192.168.1.0/24 -u user -p password

# Orchestrate multiple agents for comprehensive assessment
docker run -d ghcr.io/dreadnode/ares-recon-agent:latest netexec smb 192.168.1.0/24
docker run -d ghcr.io/dreadnode/ares-cracker-agent:latest hashcat -m 1000 hashes.txt
```

## Template Structure

Each template directory contains:

```text
template-name/
├── warpgate.yaml          # Main template configuration
└── README.md              # Template-specific documentation
```

### Template Configuration Format

Templates use YAML format with the following structure:

```yaml
metadata:
  name: template-name
  version: 1.0.0
  description: Description of what this template provides
  author: Dreadnode <info@dreadnode.io>
  license: MIT
  tags:
    - ares
    - security
  requires:
    warpgate: ">=3.0.0"

name: template-name
version: latest

base:
  image: ubuntu:22.04
  pull: true
  privileged: true

provisioners:
  - type: shell
    inline:
      - apt-get update
      - apt-get install -y package-name

targets:
  - type: container
    platforms:
      - linux/amd64
      - linux/arm64
```

## Ares Framework

The Ares framework provides a modular approach to building security assessment capabilities:

### Core Principles

1. **Modularity**: Choose components based on your needs
2. **Extensibility**: Easy to extend with custom agents
3. **Orchestration**: Designed for distributed deployments
4. **Python-First**: Built on modern Python 3.13.7
5. **Container-Native**: Optimized for container environments

### Use Cases

- **Active Directory Assessments**: Comprehensive AD penetration testing with Ares agents
- **Network Enumeration**: Service discovery and reconnaissance
- **Password Recovery**: Credential cracking and analysis
- **Security Research**: Building custom security tools
- **Red Team Operations**: Offensive security tooling
- **Blue Team Operations**: Defensive security with incident triage, threat hunting, and lateral movement analysis
- **GPU-Accelerated Cracking**: CUDA-powered password recovery with NVIDIA GPU support
- **Distributed Computing**: Ray cluster jobs for .NET and ADS experiments
- **CTF Challenges**: Build and deploy Crucible challenges with FastAPI and optional ML capabilities
- **Lab Environments**: Deploy GOAD infrastructure with pre-baked Windows Server AMIs

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines on:

- Creating new templates
- Improving existing templates
- Reporting issues
- Submitting pull requests

### Template Validation

Before submitting a template, validate it:

```bash
warpgate validate templates/your-template/warpgate.yaml
```

## Repository Structure

```text
warpgate-templates/
├── templates/                         # All template definitions
│   ├── ares-base/                     # Ares framework base image
│   ├── ares-orchestrator/             # Multi-agent coordinator
│   ├── ares-worker/                   # Task polling agent
│   ├── ares-acl-agent/                # AD ACL exploitation
│   ├── ares-blue-agent/               # Blue team defensive agent
│   ├── ares-blue-lateral-analyst-agent/ # Lateral movement analysis
│   ├── ares-blue-threat-hunter-agent/ # Proactive threat hunting
│   ├── ares-blue-triage-agent/        # Incident triage
│   ├── ares-coercion-agent/           # NTLM relay tools
│   ├── ares-cracker-agent/            # Password cracking (CPU)
│   ├── ares-cracker-agent-gpu/        # Password cracking (GPU)
│   ├── ares-cracker-base-gpu/         # GPU hashcat base image
│   ├── ares-credential-access-agent/  # Kerberos attacks
│   ├── ares-lateral-movement-agent/   # Post-exploitation
│   ├── ares-privesc-agent/            # Privilege escalation
│   ├── ares-recon-agent/              # Network reconnaissance
│   ├── crucible-challenge-core/       # FastAPI challenge base
│   ├── crucible-challenge-torch/      # Challenge with PyTorch CPU
│   ├── crucible-challenge-torch-gpu/  # Challenge with PyTorch GPU
│   ├── goad-dc-base/                  # GOAD DC (Server 2019)
│   ├── goad-dc-base-2016/             # GOAD DC (Server 2016)
│   ├── goad-mssql-base/               # GOAD MSSQL (Server 2019)
│   ├── goad-mssql-base-2016/          # GOAD MSSQL (Server 2016)
│   ├── goad-member-base/              # GOAD Member (Server 2019)
│   ├── goad-member-base-2016/         # GOAD Member (Server 2016)
│   ├── ray-ads/                       # Ray ADS base image
│   ├── ray-ads-job/                   # Ray ADS job runner
│   ├── ray-dotnet/                    # Ray .NET base image
│   └── ray-dotnet-job/                # Ray .NET job runner
├── .github/
│   └── workflows/                     # CI/CD for template validation
├── README.md                          # This file
├── CONTRIBUTING.md                    # Contribution guidelines
├── LICENSE                            # Repository license
└── .warpgate-version                  # Warpgate compatibility info
```

## License

This repository is licensed under the MIT License - see [LICENSE](./LICENSE) file for details.

## Documentation

### Core Documentation

- **[Warpgate Installation](https://github.com/cowdogmoo/warpgate/blob/main/docs/installation.md)** - Install the Warpgate CLI
- **[Usage Guide](https://github.com/cowdogmoo/warpgate/blob/main/docs/usage-guide.md)** - Common workflows and examples
- **[Template Reference](https://github.com/cowdogmoo/warpgate/blob/main/docs/template-reference.md)** - Complete YAML syntax reference

### Template Development

- **[Contributing Guide](./CONTRIBUTING.md)** - How to create and submit templates

## Support

Need help or want to contribute?

- **Issues**: [Report bugs or request features](https://github.com/dreadnode/warpgate-templates/issues)
- **Discussions**: [Ask questions and share ideas](https://github.com/dreadnode/warpgate-templates/discussions)
- **Warpgate Project**: [Main Warpgate Repository](https://github.com/cowdogmoo/warpgate)

## Built With

This project leverages industry-standard tools:

- **[Warpgate](https://github.com/cowdogmoo/warpgate)** - Template build engine
- **[Docker](https://www.docker.com/)** - Container runtime
- **[BuildKit](https://github.com/moby/buildkit)** - Advanced image builds
- **[GitHub Actions](https://github.com/features/actions)** - CI/CD automation
- **[Python 3.13.7](https://www.python.org/)** - Modern Python runtime
- **[uv](https://github.com/astral-sh/uv)** - Fast Python package manager

## Related Projects

- **[Warpgate](https://github.com/cowdogmoo/warpgate)** - Core build engine and CLI
- **[Dreadnode Platform](https://dreadnode.io)** - Enterprise security platform
- **[Ares Framework](https://github.com/dreadnode/ares)** - Modular security agents

---

**Maintained by [Dreadnode](https://dreadnode.io)** | **License: [MIT](./LICENSE)**
