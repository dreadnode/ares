# Remote Development Workflow

Sync local code to running Kubernetes pods for testing without rebuilding
images.

## Quick Start

```bash
# 1. Sync code to ConfigMap
task remote:sync

# 2. Patch deployments to mount the ConfigMap (first time only)
task remote:patch

# 3. Restart pods to pick up changes
task remote:rollout

# 4. Verify code is in place
task remote:verify ROLE=enum FILE=worker.py
```

## Hot Reload (Recommended)

For active development, use the hot reload watcher:

```bash
# Watch for changes and auto-sync
task remote:hot
```

This watches `src/ares/` for changes and automatically updates the ConfigMap.
After editing, run `task remote:rollout` to restart pods with the new code.

## Available Tasks

| Task                       | Description                              |
| -------------------------- | ---------------------------------------- |
| `remote:hot`               | Watch for changes and auto-sync to pods  |
| `remote:sync`              | Sync local code to ConfigMap             |
| `remote:patch`             | Patch deployments to mount ConfigMap     |
| `remote:rollout`           | Restart pods to pick up changes          |
| `remote:status`            | Check pod and deployment status          |
| `remote:logs`              | Tail logs from agent pods                |
| `remote:logs:orchestrator` | Tail orchestrator logs                   |
| `remote:exec`              | Execute commands in pods                 |
| `remote:verify`            | Verify hotfixed code is in place         |
| `remote:cleanup`           | Remove hotfix ConfigMaps                 |

## Configuration

Override defaults with environment variables or task arguments:

| Variable           | Default              | Description             |
| ------------------ | -------------------- | ----------------------- |
| `NAMESPACE`        | `attack-simulation`  | Kubernetes namespace    |
| `CONFIGMAP_NAME`   | `ares-code-hotfix`   | Name for the ConfigMap  |
| `WORKER_CONTAINER` | `ares-worker`        | Container name in pods  |
| `FILES`            | `src/ares/core/*.py` | Files to sync           |

Example:

```bash
task remote:sync NAMESPACE=ares FILES="src/ares/core/worker.py"
```

## Workflow Examples

### Testing a bug fix

```bash
# Edit the file
vim src/ares/core/worker.py

# Sync and restart
task remote:sync && task remote:rollout

# Check logs
task remote:logs ROLE=enum FOLLOW=true
```

### Sync specific files only

```bash
task remote:sync FILES="src/ares/core/worker.py src/ares/core/task_queue.py"
task remote:rollout
```

### Debug in a pod

```bash
# Get a shell in the enum agent
task remote:exec ROLE=enum CMD=bash

# Run Python interactively
task remote:exec ROLE=enum CMD="python -c 'print(1)'"
```

### Check what's deployed

```bash
# See all pods
task remote:status

# Verify specific file content
task remote:verify ROLE=cracker FILE=dispatcher.py
```

## How It Works

1. **ConfigMap**: Local Python files are stored in a Kubernetes ConfigMap
2. **Volume Mount**: The ConfigMap is mounted over the installed package
   files in the container
3. **Restart**: Pods restart to pick up the mounted files

This approach:

- Requires no image rebuilds
- Works with any running deployment
- Preserves original image behavior when ConfigMap is removed
- Supports syncing multiple files

## Cleanup

To restore original image behavior:

```bash
# Remove the ConfigMap
task remote:cleanup

# Redeploy from manifests (or remove volume mounts manually)
```

## Troubleshooting

### No pods found

Check the namespace and labels:

```bash
kubectl get pods -n attack-simulation \
  -l ares.dreadnode.io/component=red-team
```

### Changes not taking effect

1. Verify the ConfigMap was updated:

   ```bash
   kubectl get configmap ares-code-hotfix -n attack-simulation -o yaml
   ```

2. Check if volume is mounted:

   ```bash
   kubectl describe pod -n attack-simulation \
     -l ares.dreadnode.io/role=enum | grep -A5 Mounts
   ```

3. Verify the file in the pod:

   ```bash
   task remote:verify ROLE=enum FILE=worker.py
   ```

### fswatch not installed

```bash
brew install fswatch
```
