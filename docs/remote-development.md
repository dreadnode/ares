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
| `remote:sync:full`         | Sync full src/ares tree to pods          |
| `remote:sync:branch`       | Sync only files changed on current branch|
| `remote:rollout`           | Restart pods (for structural changes)    |
| `remote:pvc:clear`         | Delete dev PVCs for a fresh deploy       |
| `remote:status`            | Check pod and deployment status          |
| `remote:logs`              | Tail logs from agent pods                |
| `remote:logs:orchestrator` | Tail orchestrator logs                   |
| `remote:exec`              | Execute commands in pods                 |
| `remote:verify`            | Verify synced code in pod                |

## How It Works

1. `fswatch` monitors `src/ares/**/*.py` for changes
2. On file save, `kubectl cp` copies the file directly into each running pod
   at `/ares/src/ares/`
3. Files are verified with SHA256 hash comparison (PVC verification enabled by
   default)
4. Orchestrator pods receive a graceful Python restart (SIGTERM) after sync

For structural changes (new files, new imports), run `task remote:rollout`.

### Parallel Execution

The sync tasks use **go-task native parallelism** with `for` loops and
parallel `deps`:

- Multiple pods sync concurrently for speed
- Output is grouped per-pod (copy + verify together)
- Each pod's output appears sequentially, but pod order may vary between runs
- This is faster than sequential execution while maintaining readable output

## Configuration

| Variable           | Default              | Description                          |
| ------------------ | -------------------- | ------------------------------------ |
| `NAMESPACE`        | `attack-simulation`  | Kubernetes namespace                 |
| `WORKER_CONTAINER` | *(auto)*             | Container name in pods               |
| `FILES`            | `src/ares/core/*.py` | Files to sync                        |
| `VERIFY_PVC_DIFF`  | `true`               | Verify synced files with SHA256 hash |

**PVC Verification:**

- Enabled by default to catch sync failures automatically
- Compares local and remote file hashes after each sync
- Reports: `(pvc verified)`, `(pvc differs)`, or `(pvc missing)`
- Disable with: `task remote:sync:branch VERIFY_PVC_DIFF=false`

## Examples

### Sync specific files

```bash
task remote:sync FILES="src/ares/core/worker.py"
```

### Full tree sync (faster for many changes)

```bash
task remote:sync:full
```

### Sync only branch changes

```bash
task remote:sync:branch
```

### Clear dev PVC code (fresh deploy)

```bash
task remote:pvc:clear CONFIRM=true
```

**Output example:**

```text
[INFO] Finding files changed on branch vs main...
[SUCCESS] Found 2 changed file(s)

[INFO] core/orchestrator.py
[SUCCESS]   -> ares-acl-agent-799cd6c474-59q6d
[SUCCESS]   -> ares-acl-agent-799cd6c474-59q6d (pvc verified)
[SUCCESS]   -> ares-enum-agent-67dc44c9-4tx2t
[SUCCESS]   -> ares-enum-agent-67dc44c9-4tx2t (pvc verified)
[SUCCESS]   -> ares-orchestrator-76f467578c-6lwzf
[SUCCESS]   -> ares-orchestrator-76f467578c-6lwzf (pvc verified)
...

[SUCCESS] Branch sync complete (2 files)
```

Note: Pod order may vary between runs due to parallel execution, but each
pod's sync+verify output stays grouped together.

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
