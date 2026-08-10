# Ares Replay Stack Warp Gate Template

This template builds the **Ares Replay Stack** AMI using Warp Gate. It produces
an Amazon Linux 2023 image pre-loaded with Docker, docker-compose, and all six
replay-stack observability images pre-pulled: Grafana, Loki, Prometheus, Tempo,
Mimir, and Alertmanager.

The AMI is what `task benchmark:replay:provision` prefers when it launches
the replay stack box — replacing the multi-minute install-Docker-then-`compose
pull` step that runs on a stock AL2023 fallback. The provision task looks it up
by the `ares:component=benchmark-replay-stack` tag applied here; end-to-end
operator flow is documented in [`docs/benchmark-replay.md`](../../../docs/benchmark-replay.md).

---

## Requirements

- [Warp Gate](https://github.com/cowdogmoo/warpgate) >= v4.7.0
- AWS credentials configured (for building AMIs)
- Required Packer plugins (installed automatically via `warpgate init`):
  - `amazon`

---

## Configuration

The template configuration is managed in `warpgate.yaml`. Key settings:

- `name`: Template name (`ares-replay-stack`)
- `base.ami_filters`: Finds the latest Amazon Linux 2023 x86_64 AMI
- `provisioners`: Installs Docker + compose, pre-pulls the six replay-stack images
- `targets`: Publishes an AMI in `us-west-1` tagged `ares:component=benchmark-replay-stack`

---

## Building the AMI

This builds an **Ares Replay Stack** AMI in `us-west-1` on a `t3.medium`
instance with a 20 GB volume.

**One-time lab-account prerequisites:**

- IAM role + instance profile `warpgate-imagebuilder` with the AWS-managed
  `EC2InstanceProfileForImageBuilder` policy (grants SSM + S3 read on the
  staging bucket).
- An S3 bucket for warpgate's file-provisioner staging. The lab account
  already has `ec2imagebuilder-warpgate-<account-id>-us-west-1`.

Point the global warpgate config at them (once):

```bash
warpgate config set aws.ami.instance_profile_name warpgate-imagebuilder
warpgate config set aws.ami.file_staging_bucket   ec2imagebuilder-warpgate-<account-id>-us-west-1
```

**Build the AMI:**

```bash
aws sso login --profile lab

AWS_REGION=us-west-1 AWS_PROFILE=lab \
  warpgate build \
    --target ami \
    --stream-logs \
    --show-ec2-status \
    warpgate-templates/templates/ares-replay-stack/warpgate.yaml
```

After the build, the AMI is available in `us-west-1` with the name
`ares-replay-stack-<timestamp>` and tag `ares:component=benchmark-replay-stack`.
`task benchmark:replay:provision` in the same region + account picks it up
automatically.

---

## Validating the Template

```bash
warpgate validate ares-replay-stack
```

---

## Version-drift caveats

Two version lists must stay in sync with this template:

1. **`benchmarks/replay-stack/docker-compose.yml`** — source of truth for the
   six image tags. If you change an image version there, mirror the change in
   `warpgate.yaml`'s `docker pull` list or the bake will cache the wrong tag
   and the replay box will re-pull at runtime.
2. **`.taskfiles/benchmark/Taskfile.yaml`** — the `docker-compose` plugin
   version installed in the stock-AL2023 fallback path (search for
   `docker/compose/releases/download/v`) must match the version installed here.

---

## Notes

- **AMI build:**
  - Architecture: `x86_64` (amd64)
  - Region: `us-west-1`
  - Instance type: `t3.medium`
  - Volume size: 20 GB
  - Base: Amazon Linux 2023 (latest snapshot)
- **Pre-pulled images:**
  - `grafana/loki:3.6.7`
  - `prom/prometheus:v3.11.3`
  - `grafana/grafana:12.3.1`
  - `grafana/tempo:2.9.0`
  - `grafana/mimir:3.0.4`
  - `prom/alertmanager:v0.28.1`
