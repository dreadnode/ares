# Ares Warpgate Templates

**Production-ready templates for building Ares red/blue team agent images and AMIs with Warpgate.**

[![Validate Templates](https://github.com/l50/ares/actions/workflows/validate-templates.yaml/badge.svg)](https://github.com/l50/ares/actions/workflows/validate-templates.yaml)
[![Test Template Builds](https://github.com/l50/ares/actions/workflows/test-template-builds.yaml/badge.svg)](https://github.com/l50/ares/actions/workflows/test-template-builds.yaml)
[![Build and Push](https://github.com/l50/ares/actions/workflows/build-and-push-templates.yaml/badge.svg)](https://github.com/l50/ares/actions/workflows/build-and-push-templates.yaml)

---

## Overview

This directory contains [Warpgate](https://github.com/cowdogmoo/warpgate) templates for building the container images and AMIs that make up the Ares multi-agent system.

Each template provisions a specific role: orchestrators, workers, the CLI, the golden Kali AMI, and the specialized red/blue team agents that ship with Ares.

- **Red team agents** - Recon, ACL exploitation, coercion, credential access, password cracking, lateral movement, and privilege escalation
- **Blue team agents** - Triage, threat hunting, and lateral movement analysis
- **Coordination** - Orchestrator and worker images
- **CLI** - Pure Rust `ares` binary in a minimal container
- **GPU cracking** - CUDA-accelerated hashcat base and agent
- **Golden AMI** - Kali AMI with the full Ares toolchain pre-installed

Container templates produce multi-arch images (`linux/amd64` and `linux/arm64`) unless they depend on CUDA, in which case they are `amd64` only.

## Quick Start

```bash
# Install warpgate
go install github.com/CowDogMoo/warpgate/cmd/warpgate@latest

# Build the base image
warpgate build templates/ares-base/warpgate.yaml --arch amd64

# Build and push a specialized agent
warpgate build templates/ares-recon-agent/warpgate.yaml \
  --arch amd64,arm64 \
  --registry ghcr.io/l50 \
  --push
```

A `GITHUB_TOKEN` environment variable is required for any template that clones the Ares repository (everything except `ares-base` and `ares-cracker-base-gpu`).

## Available Templates

### Core

| Template | Description | Base Image | Platforms |
| -------- | ----------- | ---------- | --------- |
| [ares-base](./templates/ares-base) | Kali-based image with Python 3.13, Rust, Ansible, and core dependencies | `kalilinux/kali-rolling` | `linux/amd64`, `linux/arm64` |
| [ares-cli](./templates/ares-cli) | Minimal image containing the pure Rust `ares` CLI binary | `debian:trixie-slim` | `linux/amd64`, `linux/arm64` |
| [ares-orchestrator](./templates/ares-orchestrator) | Ares orchestrator (`ares orchestrator`) with embedded Python for LLM agent steps | `debian:trixie-slim` | `linux/amd64`, `linux/arm64` |
| [ares-worker](./templates/ares-worker) | Ares worker (`ares worker`) with embedded Python for LLM agent steps | `debian:trixie-slim` | `linux/amd64`, `linux/arm64` |
| [ares-golden-image](./templates/ares-golden-image) | Kali AMI pre-loaded with all Ares red team tools and Alloy telemetry | Kali Linux AMI | AMI (`us-west-1`, `x86_64`) |
| [ares-replay-stack](./templates/ares-replay-stack) | AL2023 AMI with Docker + the 6 replay-stack observability images pre-pulled, consumed by `ares benchmark run` | Amazon Linux 2023 AMI | AMI (`us-west-1`, `x86_64`) |

### Red Team Agents

| Template | Description | Base Image | Platforms |
| -------- | ----------- | ---------- | --------- |
| [ares-recon-agent](./templates/ares-recon-agent) | Network reconnaissance and AD enumeration | `debian:trixie-slim` | `linux/amd64`, `linux/arm64` |
| [ares-acl-agent](./templates/ares-acl-agent) | Active Directory ACL exploitation | `debian:trixie-slim` | `linux/amd64`, `linux/arm64` |
| [ares-coercion-agent](./templates/ares-coercion-agent) | NTLM relay and authentication coercion | `debian:trixie-slim` | `linux/amd64`, `linux/arm64` |
| [ares-credential-access-agent](./templates/ares-credential-access-agent) | Kerberos attacks and credential dumping | `debian:trixie-slim` | `linux/amd64`, `linux/arm64` |
| [ares-cracker-agent](./templates/ares-cracker-agent) | Password cracking with hashcat and john (CPU-only) | `debian:trixie-slim` | `linux/amd64`, `linux/arm64` |
| [ares-lateral-movement-agent](./templates/ares-lateral-movement-agent) | Post-exploitation lateral movement | `debian:trixie-slim` | `linux/amd64`, `linux/arm64` |
| [ares-privesc-agent](./templates/ares-privesc-agent) | Windows and Linux privilege escalation | `debian:trixie-slim` | `linux/amd64`, `linux/arm64` |

### Blue Team Agents

| Template | Description | Base Image | Platforms |
| -------- | ----------- | ---------- | --------- |
| [ares-blue-agent](./templates/ares-blue-agent) | General defensive security operations agent | `debian:trixie-slim` | `linux/amd64`, `linux/arm64` |
| [ares-blue-triage-agent](./templates/ares-blue-triage-agent) | Initial incident assessment and alerting | `debian:trixie-slim` | `linux/amd64`, `linux/arm64` |
| [ares-blue-threat-hunter-agent](./templates/ares-blue-threat-hunter-agent) | Proactive threat detection and investigation | `debian:trixie-slim` | `linux/amd64`, `linux/arm64` |
| [ares-blue-lateral-analyst-agent](./templates/ares-blue-lateral-analyst-agent) | Lateral movement detection and analysis | `debian:trixie-slim` | `linux/amd64`, `linux/arm64` |

### GPU-Accelerated Cracking

| Template | Description | Base Image | Platforms |
| -------- | ----------- | ---------- | --------- |
| [ares-cracker-base-gpu](./templates/ares-cracker-base-gpu) | Pre-compiled CUDA/OpenCL hashcat base image | `nvidia/cuda:12.6.0-runtime-ubuntu24.04` | `linux/amd64` |
| [ares-cracker-agent-gpu](./templates/ares-cracker-agent-gpu) | Ares cracking agent with CUDA-accelerated hashcat | `ares-cracker-base-gpu` | `linux/amd64` |

## Usage

### Prerequisites

- [Warpgate](https://github.com/cowdogmoo/warpgate) CLI (`>= 1.0.0`)
- Docker or Podman for container builds
- AWS credentials for AMI builds (`ares-golden-image`, `ares-replay-stack`)
- `GITHUB_TOKEN` for templates that clone the Ares repository

### Building

```bash
# Single architecture
warpgate build templates/ares-base/warpgate.yaml --arch amd64

# Multi-architecture
warpgate build templates/ares-recon-agent/warpgate.yaml --arch amd64,arm64

# Build and push to a registry
warpgate build templates/ares-cracker-agent/warpgate.yaml \
  --arch amd64,arm64 \
  --registry ghcr.io/l50 \
  --push
```

### Validating

```bash
warpgate validate templates/ares-recon-agent/warpgate.yaml
```

### Running Built Images

```bash
# CLI
docker run --rm ghcr.io/l50/ares-cli:latest --help

# Orchestrator (entrypoint: ares orchestrator)
docker run -it ghcr.io/l50/ares-orchestrator:latest

# Worker (entrypoint: ares worker)
docker run -it ghcr.io/l50/ares-worker:latest

# Recon agent
docker run -it ghcr.io/l50/ares-recon-agent:latest \
  netexec smb 192.168.1.0/24 -u user -p password

# CPU cracking
docker run -it ghcr.io/l50/ares-cracker-agent:latest \
  hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# GPU cracking (requires NVIDIA Container Toolkit)
docker run --rm --gpus all ghcr.io/l50/ares-cracker-agent-gpu:latest \
  hashcat -m 1000 -a 0 hashes.txt rockyou.txt
```

## Template Layout

Each template directory contains:

```text
template-name/
├── warpgate.yaml   # Warpgate template configuration
└── README.md       # Template-specific documentation
```

The `warpgate.yaml` files follow this general shape:

```yaml
metadata:
  name: template-name
  version: 1.0.0
  description: What this template provides
  author: Dreadnode <info@dreadnode.io>
  license: MIT
  tags: [ares, ...]
  requires:
    warpgate: ">=1.0.0"

name: template-name
version: latest

base:
  image: debian:trixie-slim@sha256:...
  pull: true

sources:
  - name: ares
    git:
      repository: https://github.com/l50/ares.git
      ref: main
      auth:
        token: ${GITHUB_TOKEN}

provisioners:
  - type: file
    source: ${sources.ares}
    destination: /tmp/ares-build
  - type: shell
    inline:
      - cargo build --release --bin ares
  - type: ansible
    playbook_path: ${PROVISION_REPO_PATH}/playbooks/ares/recon.yml

targets:
  - type: container
    platforms:
      - linux/amd64
      - linux/arm64
```

Most agent templates use a three-stage provisioning pipeline: build the Rust `ares` binary from source, install Python and Ansible tooling, then run the role-specific Ansible playbook from `nimbus_range` to install the toolchain.

## Directory Structure

```text
warpgate-templates/
├── templates/
│   ├── ares-base/                          # Kali base image with Python + Rust toolchain
│   ├── ares-cli/                           # Minimal image with the Rust ares CLI
│   ├── ares-orchestrator/                  # Multi-agent coordinator
│   ├── ares-worker/                        # Task polling worker
│   ├── ares-golden-image/                  # Kali AMI with all red team tools
│   ├── ares-replay-stack/                  # AL2023 AMI with Docker + replay-stack images pre-pulled
│   ├── ares-recon-agent/                   # Network and AD reconnaissance
│   ├── ares-acl-agent/                     # AD ACL exploitation
│   ├── ares-coercion-agent/                # NTLM relay / coercion
│   ├── ares-credential-access-agent/       # Kerberos and credential dumping
│   ├── ares-cracker-agent/                 # CPU password cracking
│   ├── ares-cracker-agent-gpu/             # GPU password cracking
│   ├── ares-cracker-base-gpu/              # CUDA hashcat base image
│   ├── ares-lateral-movement-agent/        # Post-exploitation lateral movement
│   ├── ares-privesc-agent/                 # Privilege escalation
│   ├── ares-blue-agent/                    # Blue team defensive base
│   ├── ares-blue-triage-agent/             # Incident triage
│   ├── ares-blue-threat-hunter-agent/      # Threat hunting
│   └── ares-blue-lateral-analyst-agent/    # Lateral movement analysis
├── .hooks/                                 # Pre-commit hooks
├── .pre-commit-config.yaml
├── .gitignore
└── README.md
```

## Documentation

- **[Warpgate](https://github.com/cowdogmoo/warpgate)** - Build engine and CLI
- **[Ares](https://github.com/l50/ares)** - The Ares red/blue team framework
- **[Issues](https://github.com/l50/ares/issues)** - Bug reports and feature requests

---

**Maintained by [Dreadnode](https://dreadnode.io)**
