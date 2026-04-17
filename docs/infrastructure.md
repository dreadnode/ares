<!-- markdownlint-disable MD013 -->

# Infrastructure Reference

This document covers how to build agent container images and manage the
provisioning pipeline.

## Overview

Ares agents run as container images built with
[Warpgate](https://github.com/cowdogmoo/warpgate) and provisioned with the
`dreadnode.nimbus_range` Ansible collection. Deploy them however fits your
environment -- Kubernetes, Docker Compose, standalone containers, or bare metal.

## Directory Layout

```text
ansible/                            Ansible collection (dreadnode.nimbus_range v1.5.0)
  galaxy.yml                        Collection metadata (namespace: dreadnode, name: nimbus_range)
  requirements.yml                  Collection dependencies (amazon.aws, ansible.windows, etc.)
  ansible.cfg                       Ansible config (connection plugins, timeouts)
  playbooks/
    ares/                           Agent provisioning playbooks
      base.yml                      Base image (Python 3.13.7, uv, workspace /ares)
      recon.yml                     Recon agent (nmap, netexec, bloodhound, certipy)
      credential_access.yml         Credential agent (sprayhound, lsassy, impacket)
      cracker.yml                   Cracker agent (hashcat, john, wordlists)
      acl_abuse.yml                 ACL agent (bloodyAD, pywhisker, dacledit)
      privesc.yml                   Privesc agent (certipy, krbrelayx, potato, nopac)
      lateral_movement.yml          Lateral agent (evil-winrm, xfreerdp, pth-*)
      coercion.yml                  Coercion agent (responder, mitm6, ntlmrelayx)
      goad_attack_box.yml           All-in-one GOAD attack workstation
    linux/
      attacker_setup.yml            Linux attacker box (SSM + CloudWatch + Fluent Bit)
      sliver.yml                    Sliver C2 server setup
    windows/
      target_setup.yml              Windows target telemetry setup
  roles/
    base/                           System deps + workspace setup
    recon_tools/                    Network scanning and AD enumeration tools
    credential_access_tools/        Password attacks and credential extraction
    cracking_tools/                 Hashcat, John, wordlists
    acl_tools/                      AD ACL exploitation
    privesc_tools/                  Privilege escalation tools
    lateral_movement_tools/         Remote access and pass-the-hash
    coercion_tools/                 NTLM poisoning and relay
    aws_ssm_agent/                  AWS Systems Manager agent
    aws_cloudwatch_agent/           CloudWatch metrics + logs
    fluent_bit/                     Log forwarding to OpenSearch
    alloy/                          Grafana Alloy (observability)
    mythic/                         Mythic C2 framework
    dc_audit_sacl/                  Domain controller audit SACLs
  plugins/modules/
    vnc_pw.py                       VNC password management
    getent_passwd.py                Cross-platform user enumeration
    merge_list_dicts_into_list.py   Data transformation utility

warpgate-templates/                 Container image build templates
  ares-base/                        Base: Kali + Ansible base role + security tools
  ares-orchestrator/                Orchestrator: Rust binary + Redis client
  ares-worker/                      Generic worker (inherits ares-base)
  ares-{recon,credential-access,cracker,acl,privesc,lateral-movement,coercion}-agent/
  ares-cracker-{agent-gpu,base-gpu}/
  ares-blue-{agent,triage-agent,threat-hunter-agent,lateral-analyst-agent}/
  ares-golden-image/                All-in-one red team EC2 AMI (all tools)
```

## Building Container Images

### Prerequisites

- [Warpgate](https://github.com/cowdogmoo/warpgate) CLI
- Docker (or Podman)
- `GITHUB_TOKEN` environment variable (for cloning ares source into images)

### Build Chain

```text
kalilinux/kali-rolling
  └── ares-base (apt + Ansible base role + Rust binaries)
        ├── ares-recon-agent         (+recon_tools)
        ├── ares-credential-access-agent (+credential_access_tools)
        ├── ares-cracker-agent       (+cracking_tools)
        ├── ares-acl-agent           (+acl_tools)
        ├── ares-privesc-agent       (+privesc_tools)
        ├── ares-lateral-movement-agent (+lateral_movement_tools)
        ├── ares-coercion-agent      (+coercion_tools)
        ├── ares-blue-*              (blue team agents)
        └── ares-worker              (generic worker, no extra tools)

nvidia/cuda:12.6.0-runtime-ubuntu24.04
  └── ares-cracker-base-gpu (hashcat compiled from source with CUDA)
        └── ares-cracker-agent-gpu (+john, wordlists)

debian:bookworm-slim
  └── ares-orchestrator (Rust binary, no Ansible)

kalilinux/kali-rolling (AMI)
  └── ares-golden-image (all red team tools in one EC2 AMI)
```

### Building

```bash
# Set PROVISION_REPO_PATH to the ansible/ directory
export PROVISION_REPO_PATH=./ansible
export GITHUB_TOKEN=ghp_...

# Build base first (all agents depend on it)
warpgate build warpgate-templates/ares-base

# Build individual agent
warpgate build warpgate-templates/ares-recon-agent

# Build all agent images
for t in warpgate-templates/ares-*/; do
  warpgate build "$t"
done
```

### Building the Golden Image (EC2 AMI)

The `ares-golden-image` template builds a Kali-based EC2 AMI with every red
team tool pre-installed (recon, credential access, privesc, cracking, lateral
movement, ACL abuse, coercion) plus the Ares framework and Alloy telemetry.
Unlike the container templates, this produces an AMI in `us-west-1`.

```bash
# Build the golden image AMI
GITHUB_TOKEN=$(gh auth token); warpgate build \
  --template ares-golden-image \
  --arch amd64 \
  --verbose \
  --stream-logs \
  --show-ec2-status
```

The `GITHUB_TOKEN` is required because the build clones private repos
(`dreadnode/ansible-collection-nimbus_range` and `dreadnode/ares`) into the
image. The resulting AMI is tagged `ares-golden-image-<timestamp>` and can be
used to launch attack boxes for GOAD lab engagements.

Each template's `warpgate.yaml` references:

- `${PROVISION_REPO_PATH}/playbooks/ares/<role>.yml` -- the Ansible playbook
- `${PROVISION_REPO_PATH}/requirements.yml` -- collection dependencies
- `${sources.ares}` -- the ares Rust binaries (built from source or downloaded)

### Multi-Architecture Support

All container templates build for `linux/amd64` and `linux/arm64`, except
GPU templates (`ares-cracker-agent-gpu`, `ares-cracker-base-gpu`) which are
`amd64` only.

### Playbook-to-Template Mapping

| Playbook | Template | Ansible Role | Key Tools |
| --- | --- | --- | --- |
| `base.yml` | `ares-base` | `base` | Rust binaries, security tool deps, /ares workspace |
| `recon.yml` | `ares-recon-agent` | `recon_tools` | nmap, netexec, bloodhound, certipy, impacket |
| `credential_access.yml` | `ares-credential-access-agent` | `credential_access_tools` | sprayhound, lsassy, gMSADumper, impacket |
| `cracker.yml` | `ares-cracker-agent` | `cracking_tools` | hashcat, john, rockyou, seclists |
| `acl_abuse.yml` | `ares-acl-agent` | `acl_tools` | bloodyAD, pywhisker, dacledit |
| `privesc.yml` | `ares-privesc-agent` | `privesc_tools` | certipy, krbrelayx, nopac, potato, SharpGPOAbuse |
| `lateral_movement.yml` | `ares-lateral-movement-agent` | `lateral_movement_tools` | evil-winrm, xfreerdp, pth-*, impacket |
| `coercion.yml` | `ares-coercion-agent` | `coercion_tools` | responder, mitm6, coercer, ntlmrelayx |
| `goad_attack_box.yml` | `ares-golden-image` | all roles | All red team tools (AMI, not container) |

The `tools.yaml` file at the repo root is the single source of truth for
which binaries are expected per role. The build scripts
(`ares-worker/build.rs`, `ares-core/build.rs`) validate against it.

## Ansible Collection Details

### Installing Dependencies

```bash
cd ansible
ansible-galaxy collection install -r requirements.yml
```

### Collection Dependencies

- `amazon.aws` 11.2.0
- `ansible.windows` 3.5.0
- `community.windows` 3.1.0
- `community.docker` 5.0.6
- `community.general` 12.4.0
- `grafana.grafana` 6.0.6
- `cowdogmoo.workstation` (git, main)
- `l50.arsenal` (git, main)

### Running Playbooks Standalone

Playbooks can run outside of Warpgate for provisioning existing hosts:

```bash
# Provision a recon agent on a remote host
ansible-playbook ansible/playbooks/ares/recon.yml \
  -i inventory.yml \
  -e target_hosts=recon-host

# Provision inside a container (used by Warpgate)
ansible-playbook ansible/playbooks/ares/recon.yml \
  -e container_build=true \
  -e target_hosts=localhost \
  -c local
```

### Observability Roles

Three roles provide the telemetry layer for deployed infrastructure:

- **aws_ssm_agent** -- Secure remote management, session logging
- **aws_cloudwatch_agent** -- System metrics (CPU, disk, memory, network)
- **fluent_bit** -- Log forwarding to OpenSearch (system logs, SSM sessions,
  command history, Windows Event Logs)

These are used by `playbooks/linux/attacker_setup.yml` and
`playbooks/windows/target_setup.yml` for range host telemetry.

## Deployment Examples

### Kubernetes

Deploy the orchestrator and workers in a namespace:

```bash
# Orchestrator pod (interactive)
kubectl run ares-orchestrator \
  --image=ghcr.io/dreadnode/ares-orchestrator:latest \
  -it --rm \
  --env="REDIS_URL=redis://redis:6379" \
  --env="ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY"

# Worker deployment (long-running)
kubectl create deployment ares-recon \
  --image=ghcr.io/dreadnode/ares-recon-agent:latest
```

### Docker Compose

```yaml
services:
  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]

  orchestrator:
    image: ghcr.io/dreadnode/ares-orchestrator:latest
    environment:
      REDIS_URL: redis://redis:6379
      ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY}
    depends_on: [redis]

  recon-worker:
    image: ghcr.io/dreadnode/ares-recon-agent:latest
    environment:
      REDIS_URL: redis://redis:6379
    depends_on: [redis]
```
