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
  requirements.yml                  Collection dependencies
  ansible.cfg                       Ansible config (connection plugins, timeouts)
  playbooks/
    ares/                           Agent provisioning playbooks
      base.yml                      Base image (workspace /ares, ares binary)
      recon.yml                     Recon agent (nmap, netexec, bloodhound, certipy)
      credential_access.yml         Credential agent (sprayhound, lsassy, impacket)
      cracker.yml                   Cracker agent (hashcat, john, wordlists)
      acl_abuse.yml                 ACL agent (bloodyAD, pywhisker, dacledit)
      privesc.yml                   Privesc agent (certipy, krbrelayx, potato, nopac)
      lateral_movement.yml          Lateral agent (evil-winrm, xfreerdp, pth-*)
      coercion.yml                  Coercion agent (responder, mitm6, ntlmrelayx)
      goad_attack_box.yml           All-in-one attack workstation
      goad_attack_box_configure.yml Post-build configuration for the attack box
      runtime_nats.yml              NATS runtime provisioning
      logrotate.yml                 Log rotation for /var/log/ares
    linux/
      attacker_setup.yml            Linux attacker box (SSM + CloudWatch + log shipping)
      sliver.yml                    Sliver C2 server setup
      mythic.yml                    Mythic C2 server setup
    windows/
      target_setup.yml              Windows target telemetry setup
  roles/                            Only infrastructure roles live here
    base/                           System deps + workspace setup
    fluent_bit/                     Log forwarding
    vector/                         Log/metric pipeline
    nats/                           NATS JetStream server
    redis/                          Redis server
  plugins/modules/
    vnc_pw.py                       VNC password management
    getent_passwd.py                Cross-platform user enumeration
    merge_list_dicts_into_list.py   Data transformation utility

warpgate-templates/templates/       Container image build templates
  ares-base/                        Base: Kali + Ansible base role + security tools
  ares-orchestrator/                Orchestrator: unified Ares binary + Redis & NATS clients
  ares-cli/                         CLI-only image
  ares-worker/                      Generic worker (inherits ares-base)
  ares-{recon,credential-access,cracker,acl,privesc,lateral-movement,coercion}-agent/
  ares-cracker-{agent-gpu,base-gpu}/
  ares-blue-{agent,triage-agent,threat-hunter-agent,lateral-analyst-agent}/
  ares-golden-image/                All-in-one red team EC2 AMI (all tools)
  ares-golden-azure/                Azure variant of the golden image
  ares-attack-box-proxmox/          Proxmox attack box
  ares-replay-stack/                Benchmark replay observability stack AMI
```

**The pentesting tool roles are not in this repo.** `recon_tools`,
`credential_access_tools`, `cracking_tools`, `acl_tools`, `privesc_tools`,
`lateral_movement_tools` and `coercion_tools` live in the external
`l50.arsenal` collection, which `ansible/requirements.yml` tracks at `main`.
Only `base` is local (`dreadnode.nimbus_range.base`). Editing a tool list means
editing arsenal, not this tree.

## State & Transport Layer

Ares splits transport from state, and state itself has two tiers: a durable
NATS JetStream event log (the source of truth) and a Redis materialized
view (a fast, indexed cache).

### NATS JetStream

Everything queue-, RPC-, pub/sub-, or event-log-shaped runs on NATS. The
canonical taxonomy lives in the module header of `ares-core/src/nats.rs`.

| Purpose                       | Subject                                   | Stream            | Notes                                     |
| ----------------------------- | ----------------------------------------- | ----------------- | ----------------------------------------- |
| Red task queue per role       | `ares.tasks.{role}`                       | `ARES_TASKS`      | Pull consumer, explicit ack               |
| Urgent task queue per role    | `ares.tasks.urgent.{role}`                | `ARES_TASKS`      | Priority ≤ 2                              |
| Task results                  | `ares.tasks.results.{task_id}`            | `ARES_TASKS`      | Survives orchestrator restart             |
| Tool dispatch RPC             | `ares.tools.exec.{role}`                  | Core (no stream)  | Request/reply, inbox subject per call     |
| Blue task queue per role      | `ares.blue.tasks.{role}`                  | `ARES_BLUE_TASKS` | Pull consumer, explicit ack               |
| Blue task results             | `ares.blue.tasks.results.{task_id}`       | `ARES_BLUE_TASKS` |                                           |
| Blue investigation requests   | `ares.blue.investigations`                | Core (no stream)  |                                           |
| Deferred / delayed dispatch   | `ares.deferred.{op}.{type}`               | `ARES_DEFERRED`   | Per-orchestrator delayed re-dispatch      |
| State-change notifications    | `ares.state.updates.{op}`                 | Core (no stream)  | Fire-and-forget wake for subscribers      |
| Real-time discoveries         | `ares.discoveries.{op}`                   | `ARES_DISCOVERIES`|                                           |
| **Op-state event log**        | `ares.ops.{op_id}.{entity}.{action}`      | `ARES_OPSTATE`    | **Source of truth for live op state**     |

`ARES_OPSTATE` is the durable event log that Redis is rehydrated from on
orchestrator restart (`orchestrator/state/replay.rs`). Work-queue streams
auto-delete acked messages; `ARES_OPSTATE` retains ~30 days.

### Redis

Redis holds a materialized view of op state, keyed by
`ares:op:{op_id}:{suffix}`. Full layout in `ares-core/src/state/mod.rs`.

| Suffix                      | Type   | Contents                              |
| --------------------------- | ------ | ------------------------------------- |
| `credentials`               | HASH   | `dedup_key -> Credential JSON`        |
| `hashes`                    | HASH   | `dedup_key -> Hash JSON`              |
| `hosts`                     | LIST   | `Host JSON per entry`                 |
| `users`                     | LIST   | `User JSON per entry`                 |
| `shares`                    | HASH   | `dedup_key -> Share JSON`             |
| `vulns`                     | HASH   | `vuln_id -> Vuln JSON`                |
| `domains`                   | SET    | Discovered domain names               |
| `exploited`                 | SET    | Exploited targets                     |
| `meta`                      | HASH   | Operation metadata                    |
| `dc_map`, `netbios_map`     | HASH   | Host → DC / NetBIOS resolution        |
| `timeline`                  | LIST   | Attack step timeline                  |
| `techniques`                | SET    | MITRE ATT&CK techniques observed      |
| `dedup:{set_name}`          | SET    | Dedup guards for expensive tasks      |
| `dominated_domains`         | SET    | Domains where DA has been achieved    |
| `trusted_domains`           | SET    | Cross-domain / cross-forest trusts    |

Locks live at `ares:lock:{op_id}`; task status at
`ares:task_status:{task_id}`.

### Retention Tiers

| Layer                   | Retention                                                                 |
| ----------------------- | ------------------------------------------------------------------------- |
| Loki logs (Alloy → S3)  | ~4 days                                                                   |
| Redis                   | Live-op only; wiped by `k8s:reset` / re-provision                         |
| `ARES_TASKS` / `ARES_BLUE_TASKS` | WorkQueue — acked messages auto-delete                           |
| `ARES_DEFERRED`         | WorkQueue — acked messages auto-delete                                    |
| `ARES_OPSTATE`          | 30-day age, floored at stream creation date on this deployment (~Jun 29)  |
| Postgres persistent_store | Not deployed on kali-ares (no `ARES_DATABASE_URL`)                      |

Anything older than the stream-creation floor on `ARES_OPSTATE` (e.g.
`op-20260612`) is gone everywhere — Redis has been wiped, Loki has aged
out, and the event log doesn't reach that far back.

## Building Container Images

### Prerequisites

- [Warpgate](https://github.com/cowdogmoo/warpgate) CLI
- Docker (or Podman)
- `GITHUB_TOKEN` environment variable (for cloning ares source into images)

### Build Chain

```text
kalilinux/kali-rolling
  └── ares-base (apt + Ansible base role + Rust binaries)
        ├── ares-recon-agent              (+recon_tools)
        ├── ares-credential-access-agent  (+credential_access_tools)
        ├── ares-cracker-agent            (+cracking_tools)
        ├── ares-acl-agent                (+acl_tools)
        ├── ares-privesc-agent            (+privesc_tools)
        ├── ares-lateral-movement-agent   (+lateral_movement_tools)
        ├── ares-coercion-agent           (+coercion_tools)
        ├── ares-blue-*                   (blue team agents)
        └── ares-worker                   (generic worker, no extra tools)

nvidia/cuda:12.6.0-runtime-ubuntu24.04
  └── ares-cracker-base-gpu (hashcat compiled from source with CUDA)
        └── ares-cracker-agent-gpu (+john, wordlists)

debian:bookworm-slim
  └── ares-orchestrator (unified `ares` binary, no Ansible)

kalilinux/kali-rolling (AMI)
  └── ares-golden-image (all red team tools in one EC2 AMI)
```

### Building

```bash
# Set PROVISION_REPO_PATH to the ansible/ directory
export PROVISION_REPO_PATH=./ansible
export GITHUB_TOKEN=ghp_...

# Build base first (all agents depend on it)
warpgate build warpgate-templates/templates/ares-base

# Build individual agent
warpgate build warpgate-templates/templates/ares-recon-agent

# Build all agent images
for t in warpgate-templates/templates/ares-*/; do
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
used to launch attack boxes for lab engagements.

Each template's `warpgate.yaml` references:

- `${PROVISION_REPO_PATH}/playbooks/ares/<role>.yml` -- the Ansible playbook
- `${PROVISION_REPO_PATH}/requirements.yml` -- collection dependencies
- `${sources.ares}` -- the ares Rust binaries (built from source or downloaded)

### Multi-Architecture Support

All container templates build for `linux/amd64` and `linux/arm64`, except
GPU templates (`ares-python-cracker-agent-gpu`, `ares-python-cracker-base-gpu`) which are
`amd64` only.

### Playbook-to-Template Mapping

| Playbook | Template | Ansible Role | Key Tools |
| --- | --- | --- | --- |
| `base.yml` | `ares-base` | `dreadnode.nimbus_range.base` | Rust binaries, security tool deps, /ares workspace |
| `recon.yml` | `ares-recon-agent` | `l50.arsenal.recon_tools` | nmap, netexec, bloodhound, certipy, impacket |
| `credential_access.yml` | `ares-credential-access-agent` | `l50.arsenal.credential_access_tools` | sprayhound, lsassy, gMSADumper, impacket |
| `cracker.yml` | `ares-cracker-agent` | `l50.arsenal.cracking_tools` | hashcat, john, rockyou, seclists |
| `acl_abuse.yml` | `ares-acl-agent` | `l50.arsenal.acl_tools` | bloodyAD, pywhisker, dacledit |
| `privesc.yml` | `ares-privesc-agent` | `l50.arsenal.privesc_tools` | certipy, krbrelayx, nopac, potato, SharpGPOAbuse |
| `lateral_movement.yml` | `ares-lateral-movement-agent` | `l50.arsenal.lateral_movement_tools` | evil-winrm, xfreerdp, pth-*, impacket |
| `coercion.yml` | `ares-coercion-agent` | `l50.arsenal.coercion_tools` | responder, mitm6, coercer, ntlmrelayx |
| `goad_attack_box.yml` | `ares-golden-image` | all roles | All red team tools (AMI, not container) |

The `tools.yaml` file at the repo root is the single source of truth for
which binaries are expected per role. The build scripts
(`ares-cli/build.rs`, `ares-core/build.rs`) validate against it.

## Ansible Collection Details

### Installing Dependencies

```bash
cd ansible
ansible-galaxy collection install -r requirements.yml
```

### Collection Dependencies

Pinned in `ansible/requirements.yml`; the git-sourced collections track `main`
rather than a tag, so a rebuild can pick up upstream changes.

- `amazon.aws` 11.4.0
- `community.aws` 11.1.0
- `ansible.windows` 3.7.0
- `community.windows` 3.3.0
- `community.docker` 5.2.1
- `ansible.posix` 2.2.2
- `community.general` 13.2.0
- `grafana.grafana` 6.1.0
- `cowdogmoo.workstation` (git, main)
- `l50.arsenal` (git, main) — all pentesting tool roles
- `l50.bulwark` (git, main)

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

Two local roles ship the telemetry layer:

- **fluent_bit** -- Log forwarding (system logs, SSM sessions, command history,
  Windows Event Logs)
- **vector** -- Log and metric pipeline

Both are used by `playbooks/linux/attacker_setup.yml` and
`playbooks/windows/target_setup.yml` for range host telemetry. SSM and
CloudWatch agent installation comes from the external collections, not from
roles in this repo.

## Deployment Examples

### Kubernetes

Deploy the orchestrator and workers in a namespace:

```bash
# Orchestrator pod (interactive)
kubectl run ares-orchestrator \
  --image=ghcr.io/l50/ares-orchestrator:latest \
  -it --rm \
  --env="REDIS_URL=redis://redis:6379" \
  --env="NATS_URL=nats://nats:4222" \
  --env="ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY" \
  -- ares orchestrator

# Worker deployment (long-running)
kubectl create deployment ares-recon \
  --image=ghcr.io/l50/ares-recon-agent:latest
```

### Docker Compose

```yaml
services:
  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]

  nats:
    image: nats:2.10-alpine
    command: ["-js"]   # enable JetStream
    ports: ["4222:4222"]

  orchestrator:
    image: ghcr.io/l50/ares-orchestrator:latest
    command: ["ares", "orchestrator"]
    environment:
      REDIS_URL: redis://redis:6379
      NATS_URL: nats://nats:4222
      ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY}
    depends_on: [redis, nats]

  recon-worker:
    image: ghcr.io/l50/ares-recon-agent:latest
    command: ["ares", "worker"]
    environment:
      REDIS_URL: redis://redis:6379
      NATS_URL: nats://nats:4222
      ARES_WORKER_ROLE: recon
    depends_on: [redis, nats]
```
