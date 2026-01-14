# Remote Development Workflow

Sync local code directly to running Kubernetes pods for testing without
rebuilding images.

## Quick Start

```bash
# Start watching for changes - syncs automatically on save
task remote:hot
```

That's it. Edit files, save, they sync to all pods instantly via `kubectl cp`.

## Available Tasks

| Task                       | Description                              |
| -------------------------- | ---------------------------------------- |
| `remote:hot`               | Watch for changes and auto-sync to pods  |
| `remote:sync`              | One-time sync of files to pods           |
| `remote:rollout`           | Restart pods (for structural changes)    |
| `remote:status`            | Check pod and deployment status          |
| `remote:logs`              | Tail logs from agent pods                |
| `remote:logs:orchestrator` | Tail orchestrator logs                   |
| `remote:exec`              | Execute commands in pods                 |
| `remote:verify`            | Verify synced code in pod                |

## How It Works

1. `fswatch` monitors `src/ares/**/*.py` for changes
2. On file save, `kubectl cp` copies the file directly into each running pod
3. Changes are live immediately (no restart needed for most changes)

For structural changes (new files, new imports), run `task remote:rollout`.

## Configuration

| Variable           | Default              | Description             |
| ------------------ | -------------------- | ----------------------- |
| `NAMESPACE`        | `attack-simulation`  | Kubernetes namespace    |
| `WORKER_CONTAINER` | `ares-worker`        | Container name in pods  |
| `FILES`            | `src/ares/core/*.py` | Files to sync           |

## Examples

### Sync specific files

```bash
task remote:sync FILES="src/ares/core/worker.py"
```

### Check logs while developing

```bash
task remote:logs ROLE=enum
```

### Verify code was synced

```bash
task remote:verify ROLE=enum FILE=core/worker.py
```

### Shell into a pod

```bash
task remote:exec ROLE=enum CMD=bash
```

## Troubleshooting

### fswatch not installed

```bash
brew install fswatch
```

### No pods found

```bash
kubectl get pods -n attack-simulation
```

### Changes not showing up

Run `task remote:rollout` to restart pods.
