# Ares Operator

Use this workflow when the task is to operate the distributed Ares red/blue team system: deploy code, run operations, monitor progress, debug stuck operations, inspect loot, generate reports, or manage infrastructure across K8s and EC2.

## Architecture

```text
Local (this machine)              Remote (K8s or EC2)
────────────────────              ───────────────────
ares-cli --k8s / --ec2    →      ares-orchestrator (LLM coordination loop)
  or `task` commands              ares-worker x7 (recon, credential_access,
                                    cracker, acl, privesc, lateral, coercion)
                                  Redis (state store + message broker)
```

The orchestrator and workers are autonomous LLM agents. You do not control them directly. Submit operations, monitor state, inject data when stuck, and debug failures.

## Deployment Targets

**K8s**: Use `ares-cli --k8s <namespace>` or `task red:multi:*`. Auto-detects deployment name (`ares-orchestrator` for red, `ares-blue-orchestrator` for blue).

**EC2**: Use `ares-cli --ec2 <name-tag>` or `task ec2:*`. Resolves the instance by Name tag and executes via AWS SSM.

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

# Deploy to EC2
task ec2:deploy
task ec2:deploy:config
```

After code changes, always deploy before testing remote behavior. Use `task remote:check` to verify sync.

## Red Team Operations

### Start an operation

```bash
# Taskfile wrapper
task red:multi TARGET=dreadgoad DOMAIN=sevenkingdoms.local

# Direct CLI
ares-cli ops submit dreadgoad contoso.local \
  --username administrator --password P@ssw0rd \
  --model gpt-5.2 --max-steps 200 --follow

# EC2
task ec2:launch DOMAIN=sevenkingdoms.local TARGETS=192.168.58.10
```

### Monitor

```bash
ares-cli --k8s ares-red ops status --latest
ares-cli --k8s ares-red ops loot --latest --watch 10 --diff
ares-cli --k8s ares-red ops tasks --latest --status failed
ares-cli --k8s ares-red ops queue
ares-cli --k8s ares-red ops list

task red:multi:status LATEST=true
task red:multi:loot LATEST=true WATCH=10
task red:multi:tasks:list LATEST=true STATUS=failed
```

### State injection

Use injection to unblock stalled operations.

```bash
ares-cli --k8s ares-red ops inject-credential op-xxx administrator P@ssw0rd --domain contoso.local
ares-cli --k8s ares-red ops inject-hash op-xxx krbtgt "hash..." --domain contoso.local --aes-key "..."
ares-cli --k8s ares-red ops inject-host op-xxx 192.168.58.20 dc01.fabrikam.local
ares-cli --k8s ares-red ops inject-domain-sid op-xxx --domain fabrikam.local --sid "S-1-5-..."
ares-cli --k8s ares-red ops inject-vulnerability op-xxx constrained_delegation 192.168.58.20 \
  --account-name svc_sql --domain fabrikam.local
```

### Reports and maintenance

```bash
ares-cli --k8s ares-red ops report --latest --regenerate
ares-cli --k8s ares-red ops export-detection --latest
ares-cli --k8s ares-red ops offload-cost --latest

ares-cli --k8s ares-red ops backfill-domains op-xxx
ares-cli --k8s ares-red ops kill --all
ares-cli --k8s ares-red ops cleanup --max-age-hours 24
```

## Blue Team Operations

### Submit investigations

```bash
ares-cli --k8s ares-blue blue from-operation --latest
ares-cli --k8s ares-blue blue submit '{"alert_title":"LSASS Read"}' --model gpt-5.2
ares-cli --k8s ares-blue blue watch --poll-interval 30
```

### Monitor and report

```bash
ares-cli --k8s ares-blue blue status --latest
ares-cli --k8s ares-blue blue evidence --latest --json
ares-cli --k8s ares-blue blue triage-status --latest
ares-cli --k8s ares-blue blue operation-status --latest --watch 5
ares-cli --k8s ares-blue blue report --latest
ares-cli --k8s ares-blue blue report --investigation-id inv-xxx
```

## Historical Data

These commands require Postgres.

```bash
ares-cli history list --domain contoso.local --has-da true
ares-cli history search-creds --username admin --admin
ares-cli history search-hashes --hash-type kerberoast --cracked
ares-cli history mitre-coverage --since-days 30
ares-cli history cost --since-days 7
```

## Configuration

The source of truth is `./config/ares.yaml`.

```bash
ares-cli config show --models
ares-cli config set-model orchestrator gpt-5.2
ares-cli config set-model --all gpt-5.2
ares-cli config validate

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

1. Check Grafana (`grafana.dev.plundr.ai`) for token use and Loki errors.
2. Check failed tasks with `ares-cli --k8s ares-red ops tasks --latest --status failed`.
3. Verify binary sync with `task remote:check`.
4. Inject known state if the model is blocked on a discovery step.
5. Restart with `ares-cli --k8s ares-red ops kill --all`, then resubmit.

## GOAD Lab Reference

- Primary: `contoso.local` (`dc01`, `192.168.58.10`)
- Foreign: `fabrikam.local` (`dc02`, `192.168.58.20`)
- Trust: Bidirectional forest trust

## Operating Rules

- Prefer `ares-cli --k8s` for status, loot, reports, and direct operational queries.
- Prefer `task` for deployments, launches, and multi-step workflows.
- If using `--secrets-from 1password`, ensure `op signin` is already valid.
- The system is sensitive to local/remote binary mismatches. After code changes, run `task remote:rust:deploy:quick` and then `task remote:check`.
