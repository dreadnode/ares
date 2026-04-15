<!-- markdownlint-disable MD013 -->

# Infrastructure Reference

This document covers how to build agent container images, deploy AWS
infrastructure, and manage the provisioning pipeline.

## Overview

Ares agents run on two deployment targets:

1. **Kubernetes (EKS)** -- Multi-agent operations with orchestrator + 7
   specialized worker pods in the `attack-simulation` namespace.
2. **EC2 (Golden Image)** -- Single Kali instance with all tools, managed
   via AWS SSM.

Both targets use the same Ansible roles for tool installation, and Warpgate
for image building.

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
    base/                           Python + uv + workspace setup
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
  ares-base/                        Base: Kali + Python 3.13 + Ansible base role
  ares-orchestrator/                Orchestrator: python:3.13-slim + pip install ares
  ares-worker/                      Generic worker (inherits ares-base)
  ares-{recon,credential-access,cracker,acl,privesc,lateral-movement,coercion}-agent/
  ares-cracker-{agent-gpu,base-gpu}/
  ares-blue-{agent,triage-agent,threat-hunter-agent,lateral-analyst-agent}/

infra/                              Terragrunt deployment configs
  root.hcl                          Shared root (S3 remote state, AWS provider)
  ares-deployment/
    host-registry.yaml              Host metadata
    dev/
      env.hcl                       Argonaut dev env (account 897722667582, VPC 172.16.0.0/16)
      us-west-2/
        region.hcl
        ares-storage/               S3 bucket for agent artifacts
    staging/
      env.hcl                       Alpha-operator-range staging (account 381491903301, VPC 10.1.0.0/16)
      us-west-1/
        region.hcl
        kali-ares/                  Golden image EC2 instance

modules/                            Terraform modules
  terraform-aws-project-storage/    S3 bucket + versioning + lifecycle rules
  terraform-aws-instance-factory/   EC2 instance + IAM + SSM + security groups
```

## Building Container Images

### Prerequisites

- [Warpgate](https://github.com/cowdogmoo/warpgate) CLI
- Docker (or Podman)
- `GITHUB_TOKEN` environment variable (for cloning ares source into images)

### Build Chain

```text
kalilinux/kali-rolling
  └── ares-base (apt + Ansible base role + pip install ares)
        ├── ares-recon-agent         (+recon_tools)
        ├── ares-credential-access-agent (+credential_access_tools)
        ├── ares-cracker-agent       (+cracking_tools)
        ├── ares-acl-agent           (+acl_tools)
        ├── ares-privesc-agent       (+privesc_tools)
        ├── ares-lateral-movement-agent (+lateral_movement_tools)
        ├── ares-coercion-agent      (+coercion_tools)
        ├── ares-blue-*              (blue team agents)
        └── ares-worker              (generic worker, no extra tools)

python:3.13.7-slim
  └── ares-orchestrator (pip install ares[postgres], no Ansible)
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

Each template's `warpgate.yaml` references:

- `${PROVISION_REPO_PATH}/playbooks/ares/<role>.yml` -- the Ansible playbook
- `${PROVISION_REPO_PATH}/requirements.yml` -- collection dependencies
- `${sources.ares}` -- the ares Python package (cloned from GitHub)

### Multi-Architecture Support

All container templates build for `linux/amd64` and `linux/arm64`, except
GPU templates (`ares-cracker-agent-gpu`, `ares-cracker-base-gpu`) which are
`amd64` only.

### Playbook-to-Template Mapping

| Playbook | Template | Ansible Role | Key Tools |
| --- | --- | --- | --- |
| `base.yml` | `ares-base` | `base` | python3.13, uv, /ares workspace |
| `recon.yml` | `ares-recon-agent` | `recon_tools` | nmap, netexec, bloodhound, certipy, impacket |
| `credential_access.yml` | `ares-credential-access-agent` | `credential_access_tools` | sprayhound, lsassy, gMSADumper, impacket |
| `cracker.yml` | `ares-cracker-agent` | `cracking_tools` | hashcat, john, rockyou, seclists |
| `acl_abuse.yml` | `ares-acl-agent` | `acl_tools` | bloodyAD, pywhisker, dacledit |
| `privesc.yml` | `ares-privesc-agent` | `privesc_tools` | certipy, krbrelayx, nopac, potato, SharpGPOAbuse |
| `lateral_movement.yml` | `ares-lateral-movement-agent` | `lateral_movement_tools` | evil-winrm, xfreerdp, pth-*, impacket |
| `coercion.yml` | `ares-coercion-agent` | `coercion_tools` | responder, mitm6, coercer, ntlmrelayx |

The `tools.yaml` file at the repo root is the single source of truth for
which binaries are expected per role. The build scripts
(`ares-worker/build.rs`, `ares-core/build.rs`) validate against it.

## AWS Infrastructure

### S3 Artifact Storage

**Location:** `infra/ares-deployment/dev/us-west-2/ares-storage/`

- Bucket: `dev-argonaut-ares`
- Versioning enabled
- Lifecycle: 30d -> STANDARD_IA, 90d -> GLACIER, 365d expiration
- All agents have read/write access via IRSA

```bash
cd infra/ares-deployment/dev/us-west-2/ares-storage
terragrunt apply
```

### EKS / Kubernetes

The EKS cluster is shared infrastructure managed in the DreadOps repo:

- **Cluster config:** `DreadOps/dread-infra/argonaut/dev/us-west-2/eks/terragrunt.hcl`
- **Cluster:** `dev-argonaut`, K8s 1.34, us-west-2
- **Namespace:** `attack-simulation`

7 IRSA roles are defined in the EKS config for ares agents:

| Service Account | Agent | S3 Access |
| --- | --- | --- |
| `ares-enum-agent` | Recon | `dev-argonaut-ares` (rw) |
| `ares-cracker-agent` | Cracker | `dev-argonaut-ares` (rw) |
| `ares-acl-agent` | ACL | `dev-argonaut-ares` (rw) |
| `ares-privesc-agent` | Privesc | `dev-argonaut-ares` (rw) |
| `ares-lateral-movement-agent` | Lateral | `dev-argonaut-ares` (rw) |
| `ares-poisoning-agent` | Coercion | `dev-argonaut-ares` (rw) |
| `atomic-red-team` | Atomic Red Team | `dev-argonaut-ares` (rw) |

To modify IRSA roles, edit the `application_irsa_roles` block in the DreadOps
EKS terragrunt config and apply from that repo.

### EC2 Golden Image (kali-ares)

**Location:** `infra/ares-deployment/staging/us-west-1/kali-ares/`

- Instance: t3.xlarge, Kali Linux
- AMI: `ami-0632f108c12bf9dbd` (pre-built Ares golden image)
- Provisioned post-deploy via Ansible (`goad_attack_box.yml`)
- SSM-managed (no SSH keys, no open ports)
- Encrypted EBS gp3 100GB
- Workspace: `/ares`

```bash
cd infra/ares-deployment/staging/us-west-1/kali-ares
terragrunt apply
```

### Environments

| Environment | Account | Region | VPC CIDR | Purpose |
| --- | --- | --- | --- | --- |
| Argonaut dev | 897722667582 | us-west-2 | 172.16.0.0/16 | EKS + S3 storage |
| Alpha-operator-range staging | 381491903301 | us-west-1 | 10.1.0.0/16 | Golden images + GOAD range |

Cross-account VPC peering connects the two for agent-to-range communication.

## Terraform Modules

### terraform-aws-project-storage

Creates S3 buckets with:

- Versioning and lifecycle policies
- KMS or AES256 encryption
- Public access blocking
- Optional access logging and CORS

### terraform-aws-instance-factory

Creates EC2 instances with:

- IAM instance profiles (SSM + CloudWatch)
- Security groups (internal VPC only)
- Encrypted EBS volumes
- User data templates
- IMDSv2 enforcement
- Optional Ansible provisioning hooks

## Ansible Collection Details

### Installing Dependencies

```bash
cd ansible
ansible-galaxy collection install -r requirements.yml
ansible-galaxy role install -r requirements.yml
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
