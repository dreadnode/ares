# Ares Operator

Use this workflow when the task is to operate the distributed Ares red/blue team system: deploy code, run operations, monitor progress, debug stuck operations, inspect loot, generate reports, or manage infrastructure across K8s and EC2.

## Architecture

```text
Local (this machine)              Remote (K8s or EC2)
────────────────────              ───────────────────
ares --k8s / --ec2        →      ares orchestrator (LLM coordination loop)
  or `task` commands              ares worker x7 (recon, credential_access,
                                    cracker, acl, privesc, lateral, coercion)
                                  NATS JetStream (task/RPC broker)
                                  Redis (durable state store)
```

The orchestrator and workers are autonomous LLM agents. You do not control them directly. Submit operations, monitor state, inject data when stuck, and debug failures.

## Deployment Targets

**K8s**: Use `ares --k8s <namespace>` or `task red:multi:*`. Auto-detects deployment name (`ares-orchestrator` for red, `ares-blue-orchestrator` for blue).

**EC2**: Use `ares --ec2 <name-tag>` or `task ec2:*`. Resolves the instance by Name tag and executes via AWS SSM.

## Global CLI Flags

```bash
# Transport
--k8s <namespace>          # Run on K8s pod (namespace usually 'attack-simulation')
--ec2 <name-tag>           # Run on EC2 instance (SSM)
--k8s-deploy <name>        # Override auto-detected deployment
--ec2-profile <profile>    # AWS profile for EC2/SSM (default: lab)

# Secrets and environment
--secrets-from 1password   # Fetch API keys/secrets from 1Password CLI (op)
--env-file <path>          # Load environment variables from a specific file
--redis-url <url>          # Override the default Redis connection
# NATS connection comes from $NATS_URL (e.g. nats://nats:4222)
```

## Development Workflow

```bash
# Build locally
task rust:build
task rust:release
task rust:test
task rust:check

# Deploy to K8s
task remote:rust:deploy
task remote:rust:deploy:quick
task remote:check
task remote:rust:deploy:config

# Deploy to EC2 (requires S3_BUCKET env var for binary staging)
task ec2:deploy
task ec2:deploy:config

# EC2 full clean test cycle (mirrors K8s `k8s:reset && k8s:deploy && red:multi`):
ulimit -n 65536                      # zig linker chokes on huge fd limits
export S3_BUCKET=your-deploy-bucket

EC2_NAME=kali-ares
TARGET=dreadgoad
BLUE_ENABLED=1

task ec2:stop       EC2_NAME=$EC2_NAME
task ec2:stop-op    EC2_NAME=$EC2_NAME LATEST=true
task -y ec2:deploy  EC2_NAME=$EC2_NAME
task ec2:exec       EC2_NAME=$EC2_NAME CMD="redis-cli FLUSHALL"
task ec2:start      EC2_NAME=$EC2_NAME
task -y red:ec2:multi TARGET=$TARGET EC2_NAME=$EC2_NAME BLUE_ENABLED=$BLUE_ENABLED
```

After code changes, always deploy before testing remote behavior. Use `task remote:check` to verify sync.

## Red Team Operations

### Start an operation

```bash
# Taskfile wrapper
task red:multi TARGET=dreadgoad DOMAIN=contoso.local

# Direct CLI
ares ops submit dreadgoad contoso.local \
  --username administrator --password P@ssw0rd \
  --model gpt-5.2 --max-steps 200 --follow

# EC2
task ec2:launch DOMAIN=contoso.local TARGETS=192.168.58.10
```

### Monitor

```bash
ares --k8s ares-red ops status --latest
ares --k8s ares-red ops loot --latest --watch 10 --diff
ares --k8s ares-red ops tasks --latest --status failed
ares --k8s ares-red ops queue
ares --k8s ares-red ops list

task red:multi:status LATEST=true
task red:multi:loot LATEST=true WATCH=10
task red:multi:tasks:list LATEST=true STATUS=failed
```

### State injection

Use injection to unblock stalled operations.

```bash
ares --k8s ares-red ops inject-credential op-xxx administrator P@ssw0rd --domain contoso.local
ares --k8s ares-red ops inject-hash op-xxx krbtgt "hash..." --domain contoso.local --aes-key "..."
ares --k8s ares-red ops inject-host op-xxx 192.168.58.20 dc01.fabrikam.local
ares --k8s ares-red ops inject-domain-sid op-xxx --domain fabrikam.local --sid "S-1-5-..."
ares --k8s ares-red ops inject-vulnerability op-xxx constrained_delegation 192.168.58.20 \
  --account-name svc_sql --domain fabrikam.local
```

### Reports and maintenance

```bash
ares --k8s ares-red ops report --latest --regenerate
ares --k8s ares-red ops export-detection --latest
ares --k8s ares-red ops offload-cost --latest

ares --k8s ares-red ops backfill-domains op-xxx
ares --k8s ares-red ops kill --all
ares --k8s ares-red ops cleanup --max-age-hours 24
```

## Blue Team Operations

### Submit investigations

```bash
ares --k8s ares-blue blue from-operation --latest
ares --k8s ares-blue blue submit '{"alert_title":"LSASS Read"}' --model gpt-5.2
ares --k8s ares-blue blue watch --poll-interval 30
```

### Monitor and report

```bash
ares --k8s ares-blue blue status --latest
ares --k8s ares-blue blue evidence --latest --json
ares --k8s ares-blue blue triage-status --latest
ares --k8s ares-blue blue operation-status --latest --watch 5
ares --k8s ares-blue blue report --latest
ares --k8s ares-blue blue report --investigation-id inv-xxx
```

## Historical Data

These commands require Postgres.

```bash
ares history list --domain contoso.local --has-da true
ares history search-creds --username admin --admin
ares history search-hashes --hash-type kerberoast --cracked
ares history mitre-coverage --since-days 30
ares history cost --since-days 7
```

## Configuration

The source of truth is `./config/ares.yaml`.

```bash
ares config show --models
ares config set-model orchestrator gpt-5.2
ares config set-model --all gpt-5.2
ares config validate

task config:models
task config:set-model -- orchestrator gpt-5.2
```

## Health Checks and Debugging

```bash
task ares:config:check
task remote:status
task remote:check
task remote:logs ROLE=orchestrator
```

When an operation is stuck:

1. Check Grafana (URL from `GRAFANA_URL` env var) for token use and Loki errors.
2. Check failed tasks with `ares --k8s ares-red ops tasks --latest --status failed`.
3. Verify binary sync with `task remote:check`.
4. Inject known state if the model is blocked on a discovery step.
5. Restart with `ares --k8s ares-red ops kill --all`, then resubmit.

## Lab Reference

- Primary: `contoso.local` (`dc01`, `192.168.58.10`)
- Foreign: `fabrikam.local` (`dc02`, `192.168.58.20`)
- Trust: Bidirectional forest trust

## Operating Rules

- Prefer `ares --k8s` for status, loot, reports, and direct operational queries.
- Prefer `task` for deployments, launches, and multi-step workflows.
- If using `--secrets-from 1password`, ensure `op signin` is already valid.
- The system is sensitive to local/remote binary mismatches. After code changes, run `task remote:rust:deploy:quick` and then `task remote:check`.
