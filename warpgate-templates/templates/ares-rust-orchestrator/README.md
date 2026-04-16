# Ares Rust Orchestrator Warp Gate Template

This template builds **Ares Rust Orchestrator** images using Warp Gate. The
orchestrator coordinates multi-agent red team operations, dispatching tasks to
specialized worker agents via Redis, using a compiled Rust binary with embedded
Python for LLM agent steps.

---

## Requirements

- [Warp Gate](https://github.com/cowdogmoo/warpgate) installed and configured
- Docker (for building Docker images)
- `GITHUB_TOKEN` environment variable set (for cloning the ares repository)
- Required Packer plugins (installed automatically via `warpgate init`):
  - `docker`

---

## Configuration

The template configuration is managed in `warpgate.yaml`. Key settings include:

- `name`: Template name (`ares-rust-orchestrator`)
- `base.image`: Base Docker image (Python 3.13.7 slim)
- `sources`: Clones the ares repository for Rust compilation
- `provisioners`: File and shell provisioners for setup
- `targets`: Defines build targets (container images)

---

## Building Docker Images

This builds **Ares Rust Orchestrator** Docker images for `amd64` and `arm64`
architectures, compiles the Rust orchestrator binary with Python bindings,
and configures it for multi-agent operations.

**Initialize the template:**

```bash
warpgate init ares-rust-orchestrator
```

**Build Docker images:**

```bash
warpgate build ares-rust-orchestrator --only 'docker.*'
```

**Build for specific architecture:**

```bash
warpgate build ares-rust-orchestrator --arch amd64 --only 'docker.*'
```

After the build, Ares Rust Orchestrator Docker images will be available
locally as `ares-rust-orchestrator:latest`.

---

## Pushing Docker Images to GitHub Container Registry

After building the Docker image, you can push it to GHCR:

```bash
# Tag the image
docker tag ares-rust-orchestrator:latest ghcr.io/dreadnode/ares-rust-orchestrator:latest

# Authenticate with GHCR
echo $GITHUB_TOKEN | docker login ghcr.io -u YOUR_USERNAME --password-stdin

# Push the image
docker push ghcr.io/dreadnode/ares-rust-orchestrator:latest
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
  --entrypoint /bin/bash \
  ares-rust-orchestrator:latest
```

**Verify the orchestrator is installed correctly:**

```bash
# Check the Rust binary is available
docker run --rm --entrypoint ares-orchestrator ares-rust-orchestrator:latest --version

# Check that curl and jq are installed (for debugging)
docker run --rm --entrypoint bash ares-rust-orchestrator:latest -c "curl --version && jq --version"
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
  ares-rust-orchestrator:latest
```

---

## Validating the Template

To validate the template configuration before building:

```bash
warpgate validate ares-rust-orchestrator
```

---

## Usage in Kubernetes

The orchestrator is designed to run as a long-lived pod in Kubernetes. Deploy
using the manifests in the argonaut repository:

```bash
kubectl apply -k environments/dev/platforms/attack-simulation/ares-rust-orchestrator
```

Then exec into the pod to run operations:

```bash
# Get a shell in the orchestrator pod
kubectl exec -it -n attack-simulation deploy/ares-rust-orchestrator -- bash

# Run a multi-agent operation
ares-orchestrator multi-agent sevenkingdoms.local "192.168.56.10,192.168.56.11"
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
  - Entrypoint: `ares-orchestrator` (compiled Rust binary)
- **Installed Components:**
  - Python 3.13.7
  - uv package manager
  - Ares framework (installed from source via pip)
  - Rust-compiled `ares-orchestrator` binary with PyO3 Python bindings
  - curl and jq for debugging
- **Build Process:**
  - Clones ares repository from `feature/rust-cli` branch
  - Installs Rust toolchain, compiles binary with `--features python`
  - Installs binary to `/usr/local/bin/ares-orchestrator`
  - Cleans up Rust toolchain, build artifacts, and build-only dependencies
- **Directory Structure:**
  - `/root/` - Default working directory
  - `/usr/local/bin/ares-orchestrator` - Compiled orchestrator binary
  - Python packages installed system-wide
- The orchestrator requires Redis, an Anthropic API key, and access to worker agents to function.

---

## Differences from ares-orchestrator (Python)

| Component | ares-orchestrator (Python) | ares-rust-orchestrator |
| ----------- | ---------------------------- | ------------------------ |
| Entrypoint | `/bin/bash` | `ares-orchestrator` (binary) |
| Runtime | Python interpreter | Compiled Rust + embedded Python |
| Build | pip install only | Rust compilation with PyO3 |
| Performance | Standard Python | Native Rust with Python FFI |
| Extra Tools | curl, jq | curl, jq |

---

## Customization

To customize the build, edit the `warpgate.yaml` file:

- Modify `base.image` to use a different Python version
- Add or remove provisioning steps in the `provisioners` section
- Adjust `targets` to change build platforms

For more information on Warp Gate template configuration, see the
[Warp Gate documentation](https://github.com/cowdogmoo/warpgate).
