# Ares Rust Worker Warp Gate Template

This template builds **Ares Rust Worker** images using Warp Gate. It supports
building **Docker images** (for `amd64` and `arm64`). The worker agent polls
Redis for tasks and orchestrates tool execution across the Ares framework,
using a compiled Rust binary with embedded Python for LLM agent steps.

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

- `name`: Template name (`ares-rust-worker`)
- `base.image`: Base Docker image (`ares-base`)
- `sources`: Clones the ares repository for Rust compilation
- `targets`: Defines build targets (container images)

---

## Building Docker Images

This builds **Ares Rust Worker** Docker images for `amd64` and `arm64`
architectures, compiles the Rust worker binary with Python bindings,
and configures it as a long-running worker daemon.

**Initialize the template:**

```bash
warpgate init ares-rust-worker
```

**Build Docker images:**

```bash
warpgate build ares-rust-worker --only 'docker.*'
```

**Build for specific architecture:**

```bash
warpgate build ares-rust-worker --arch amd64 --only 'docker.*'
```

After the build, Ares Rust Worker Docker images will be available
locally as `ares-rust-worker:latest`.

---

## Pushing Docker Images to GitHub Container Registry

After building the Docker image, you can push it to GHCR:

```bash
# Tag the image
docker tag ares-rust-worker:latest ghcr.io/dreadnode/ares-rust-worker:latest

# Authenticate with GHCR
echo $GITHUB_TOKEN | docker login ghcr.io -u YOUR_USERNAME --password-stdin

# Push the image
docker push ghcr.io/dreadnode/ares-rust-worker:latest
```

---

## Local Testing

After building the image, you can test it locally:

**Run the worker container interactively:**

```bash
# Run with Redis connection for testing
docker run -it --rm \
  -e REDIS_URL="redis://localhost:6379" \
  -e ANTHROPIC_API_KEY="your-api-key" \
  ares-rust-worker:latest
```

**Verify the worker is installed correctly:**

```bash
# Check the Rust binary is available
docker run --rm ares-rust-worker:latest ares-worker --version
```

**Test with local Redis:**

```bash
# Start Redis in Docker
docker run -d --name redis -p 6379:6379 redis:7-alpine

# Run the worker connected to local Redis
docker run -it --rm \
  --network host \
  -e REDIS_URL="redis://localhost:6379" \
  -e ANTHROPIC_API_KEY="your-api-key" \
  ares-rust-worker:latest
```

**Verify health check commands work:**

```bash
# Test that pgrep is available (for Kubernetes probes)
docker run --rm ares-rust-worker:latest pgrep -V
```

---

## Validating the Template

To validate the template configuration before building:

```bash
warpgate validate ares-rust-worker
```

---

## Notes

- **Docker build:**
  - Multi-arch (`amd64` + `arm64`) support
  - Default user: `root`
  - Working directory: `/root`
  - Entrypoint: `ares-worker` (compiled Rust binary)
- **Installed Components:**
  - Provided by `ares-base` (Python 3.13.x, uv, Ares framework, dependencies, procps)
  - Rust-compiled `ares-worker` binary with PyO3 Python bindings
- **Build Process:**
  - Clones ares repository from `feature/rust-cli` branch
  - Compiles Rust binary with `--features python` for Python interop
  - Installs binary to `/usr/local/bin/ares-worker`
  - Cleans up build artifacts (source, compiler symlinks)
- **Directory Structure:**
  - `/root/` - Default working directory
  - `/usr/local/bin/ares-worker` - Compiled worker binary
  - Python packages installed system-wide
- The worker requires Redis and an Anthropic API key to function.

---

## Usage in Kubernetes

The worker is designed to run as a Deployment in Kubernetes with liveness and
readiness probes:

```yaml
livenessProbe:
  exec:
    command:
      - /bin/sh
      - -c
      - pgrep -f 'ares-worker'
  initialDelaySeconds: 30
  periodSeconds: 10
```

Deploy using the manifests in the argonaut repository:

```bash
kubectl apply -k environments/dev/platforms/attack-simulation/ares-rust-worker
```

---

## Differences from ares-worker (Python)

| Component | ares-worker (Python) | ares-rust-worker |
| ----------- | ---------------------- | ------------------ |
| Entrypoint | `python -m ares worker` | `ares-worker` (binary) |
| Runtime | Python interpreter | Compiled Rust + embedded Python |
| Build | No compilation needed | Rust compilation with PyO3 |
| Performance | Standard Python | Native Rust with Python FFI |

---

## Customization

To customize the build, edit the `warpgate.yaml` file:

- Modify `base.image` to use a different base image
- Adjust the entrypoint or environment in the `base` section
- Adjust `targets` to change build platforms

For more information on Warp Gate template configuration, see the [Warp Gate documentation](https://github.com/cowdogmoo/warpgate).
