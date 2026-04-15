# Ares Orchestrator Warp Gate Template

This template builds **Ares Orchestrator** images using Warp Gate. The
orchestrator coordinates multi-agent red team operations, dispatching tasks to
specialized worker agents via Redis.

---

## Requirements

- [Warp Gate](https://github.com/cowdogmoo/warpgate) installed and configured
- Docker (for building Docker images)
- Ares source code repository cloned at `../../../ares` (relative to this template)
- Required Packer plugins (installed automatically via `warpgate init`):
  - `docker`

---

## Configuration

The template configuration is managed in `warpgate.yaml`. Key settings include:

- `name`: Template name (`ares-orchestrator`)
- `base.image`: Base Docker image (Python 3.13.7 slim)
- `provisioners`: File and shell provisioners for setup
- `targets`: Defines build targets (container images)

---

## Building Docker Images

This builds **Ares Orchestrator** Docker images for `amd64` and `arm64`
architectures, installs the ares framework from source, and configures it
for interactive multi-agent operations.

**Initialize the template:**

```bash
warpgate init ares-orchestrator
```

**Build Docker images:**

```bash
warpgate build ares-orchestrator --only 'docker.*'
```

**Build for specific architecture:**

```bash
warpgate build ares-orchestrator --arch amd64 --only 'docker.*'
```

After the build, Ares Orchestrator Docker images will be available
locally as `ares-orchestrator:latest`.

---

## Pushing Docker Images to GitHub Container Registry

After building the Docker image, you can push it to GHCR:

```bash
# Tag the image
docker tag ares-orchestrator:latest ghcr.io/dreadnode/ares-orchestrator:latest

# Authenticate with GHCR
echo $GITHUB_TOKEN | docker login ghcr.io -u YOUR_USERNAME --password-stdin

# Push the image
docker push ghcr.io/dreadnode/ares-orchestrator:latest
```

---

## Local Testing

After building the image, you can test it locally:

**Run the orchestrator container interactively:**

```bash
# Run with Redis and API key for testing
docker run -it --rm \
  -e REDIS_URL="redis://localhost:6379" \
  -e ANTHROPIC_API_KEY="your-api-key" \
  ares-orchestrator:latest
```

**Verify the orchestrator is installed correctly:**

```bash
# Check ares CLI is available
docker run --rm ares-orchestrator:latest python -m ares --version

# Check that curl and jq are installed (for debugging)
docker run --rm ares-orchestrator:latest bash -c "curl --version && jq --version"
```

**Test with local Redis:**

```bash
# Start Redis in Docker
docker run -d --name redis -p 6379:6379 redis:7-alpine

# Run the orchestrator connected to local Redis
docker run -it --rm \
  --network host \
  -e REDIS_URL="redis://localhost:6379" \
  -e ANTHROPIC_API_KEY="your-api-key" \
  -e ARES_NAMESPACE="default" \
  ares-orchestrator:latest

# Inside the container, run a multi-agent operation
# ares multi-agent sevenkingdoms.local "192.168.56.10"
```

**Run orchestrator commands directly:**

```bash
# Execute ares commands without entering the container
docker run -it --rm \
  --network host \
  -e REDIS_URL="redis://localhost:6379" \
  -e ANTHROPIC_API_KEY="your-api-key" \
  ares-orchestrator:latest \
  python -m ares multi-agent --help
```

---

## Validating the Template

To validate the template configuration before building:

```bash
warpgate validate ares-orchestrator
```

---

## Usage in Kubernetes

The orchestrator is designed to run as a long-lived pod in Kubernetes. Deploy
using the manifests in the argonaut repository:

```bash
kubectl apply -k environments/dev/platforms/attack-simulation/ares-orchestrator
```

Then exec into the pod to run operations:

```bash
# Get a shell in the orchestrator pod
kubectl exec -it -n attack-simulation deploy/ares-orchestrator -- bash

# Run a multi-agent operation
ares multi-agent sevenkingdoms.local "192.168.56.10,192.168.56.11"
```

The pod has the following environment variables pre-configured:

- `REDIS_URL`: Redis connection string with authentication
- `ANTHROPIC_API_KEY`: API key for Claude models
- `ARES_NAMESPACE`: Kubernetes namespace for agent discovery

---

## Notes

- **Docker build:**
  - Multi-arch (`amd64` + `arm64`) support
  - Default user: `root`
  - Working directory: `/root`
  - Entrypoint: `/bin/bash` (interactive shell)
- **Installed Components:**
  - Python 3.13.7
  - uv package manager
  - Ares framework (installed from local source)
  - All Ares dependencies (rigging, dreadnode, litellm, kubernetes client, etc.)
  - curl and jq for debugging
- **Directory Structure:**
  - `/root/` - Default working directory
  - Python packages installed system-wide
- The build copies the Ares source from `../../../ares` relative to this template directory.
- The orchestrator requires Redis, an Anthropic API key, and access to worker agents to function.

---

## Differences from ares-worker

| Component | ares-worker | ares-orchestrator |
| ----------- | ------------- | ------------------- |
| Entrypoint | `python -m ares worker` | `/bin/bash` |
| Purpose | Polls Redis for tasks | Coordinates operations |
| CLI Command | `ares worker <role> <op-id>` | `ares multi-agent <domain> <ips>` |
| Lifecycle | Long-running daemon | Interactive or scripted |
| Extra Tools | procps (for health probes) | curl, jq (for debugging) |

---

## Customization

To customize the build, edit the `warpgate.yaml` file:

- Modify `base.image` to use a different Python version
- Add or remove provisioning steps in the `provisioners` section
- Adjust `targets` to change build platforms

For more information on Warp Gate template configuration, see the
[Warp Gate documentation](https://github.com/cowdogmoo/warpgate).
