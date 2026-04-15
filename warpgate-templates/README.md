# Ares Warpgate Templates

[Warpgate](https://github.com/cowdogmoo/warpgate) templates for building Ares
agent container images. Each template produces a Docker image provisioned with
specialized security tooling via the `dreadnode.nimbus_range` Ansible collection.

## Build Chain

```text
kalilinux/kali-rolling
  └── ares-base (Python 3.13 + uv + Ansible base role)
        ├── ares-recon-agent             (+recon_tools)
        ├── ares-credential-access-agent (+credential_access_tools)
        ├── ares-cracker-agent           (+cracking_tools, CPU)
        ├── ares-acl-agent               (+acl_tools)
        ├── ares-privesc-agent           (+privesc_tools)
        ├── ares-lateral-movement-agent  (+lateral_movement_tools)
        ├── ares-coercion-agent          (+coercion_tools)
        ├── ares-blue-agent              (base blue team)
        ├── ares-blue-triage-agent       (+grafana-mcp)
        ├── ares-blue-threat-hunter-agent (+grafana-mcp)
        ├── ares-blue-lateral-analyst-agent (+grafana-mcp)
        └── ares-worker                  (generic worker)

nvidia/cuda:12.6.0-runtime-ubuntu24.04
  └── ares-cracker-base-gpu (hashcat from source + CUDA)
        └── ares-cracker-agent-gpu       (+wordlists, john)

python:3.13.7-slim
  └── ares-orchestrator (ares framework, no Ansible)
```

## Templates

### Red Team Agents

| Template | Ansible Role | Key Tools | Arch |
| --- | --- | --- | --- |
| `ares-recon-agent` | `recon_tools` | nmap, netexec, bloodhound, certipy | amd64, arm64 |
| `ares-credential-access-agent` | `credential_access_tools` | sprayhound, lsassy, impacket, kerberoasting | amd64, arm64 |
| `ares-cracker-agent` | `cracking_tools` | hashcat (CPU), john, rockyou, seclists | amd64, arm64 |
| `ares-cracker-base-gpu` | `cracking_tools` | hashcat (CUDA), pre-compiled GPU base | amd64 |
| `ares-cracker-agent-gpu` | `cracking_tools` | hashcat (CUDA), john, rockyou, seclists | amd64 |
| `ares-acl-agent` | `acl_tools` | bloodyAD, pywhisker, dacledit | amd64, arm64 |
| `ares-privesc-agent` | `privesc_tools` | certipy, krbrelayx, nopac, potato, WinPEAS | amd64, arm64 |
| `ares-lateral-movement-agent` | `lateral_movement_tools` | evil-winrm, xfreerdp, lsassy, pth-toolkit | amd64, arm64 |
| `ares-coercion-agent` | `coercion_tools` | Responder, mitm6, Coercer, ntlmrelayx | amd64, arm64 |

### Blue Team Agents

| Template | Description | Arch |
| --- | --- | --- |
| `ares-blue-agent` | Base defensive agent | amd64, arm64 |
| `ares-blue-triage-agent` | Alert triage with Grafana MCP | amd64, arm64 |
| `ares-blue-threat-hunter-agent` | Proactive threat hunting with Grafana MCP | amd64, arm64 |
| `ares-blue-lateral-analyst-agent` | Lateral movement detection with Grafana MCP | amd64, arm64 |

### Orchestration

| Template | Description | Arch |
| --- | --- | --- |
| `ares-base` | Base image for all Kali-based agents | amd64, arm64 |
| `ares-orchestrator` | Coordinates multi-agent operations via Redis | amd64, arm64 |
| `ares-worker` | Generic worker that polls Redis for tasks | amd64, arm64 |

## Quick Start

### Prerequisites

- [Warpgate](https://github.com/cowdogmoo/warpgate) CLI
- Docker (with BuildKit)
- `PROVISION_REPO_PATH` pointing to the `ansible/` directory

### Building

```bash
export PROVISION_REPO_PATH=./ansible

# Build base first (all Kali-based agents depend on it)
warpgate build warpgate-templates/ares-base

# Build a specific agent
warpgate build warpgate-templates/ares-recon-agent

# Build all agents
for t in warpgate-templates/ares-*/; do
  warpgate build "$t"
done
```

### GPU Images

GPU templates require NVIDIA Container Toolkit on the build host:

```bash
# Build the GPU base (hashcat compiled from source with CUDA)
warpgate build warpgate-templates/ares-cracker-base-gpu

# Build the GPU cracker agent
warpgate build warpgate-templates/ares-cracker-agent-gpu

# Run with GPU access
docker run --gpus all -it ares-cracker-agent-gpu:latest
```

### Pushing to GHCR

```bash
echo $GITHUB_TOKEN | docker login ghcr.io -u YOUR_USERNAME --password-stdin

docker tag ares-recon-agent:latest ghcr.io/dreadnode/ares-recon-agent:latest
docker push ghcr.io/dreadnode/ares-recon-agent:latest
```

### Validating

```bash
warpgate validate warpgate-templates/ares-recon-agent
```

## Template Structure

Each template directory contains:

- `warpgate.yaml` -- Build configuration (base image, provisioners, targets)
- `README.md` -- Template-specific documentation

For more information, see the [Warpgate documentation](https://github.com/cowdogmoo/warpgate).
