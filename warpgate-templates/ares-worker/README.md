# Ares Worker Warp Gate Template

This template builds **Ares Worker** images using Warp Gate. It supports
building **Docker images** (for `amd64` and `arm64`). The worker agent polls
Redis for tasks and orchestrates tool execution across the Ares framework.

---

## Requirements

- [Warp Gate](https://github.com/cowdogmoo/warpgate) installed and configured
- Docker (for building Docker images)
- Required Packer plugins (installed automatically via `warpgate init`):
  - `docker`

---

## Configuration

The template configuration is managed in `warpgate.yaml`. Key settings include:

- `name`: Template name (`ares-worker`)
- `base.image`: Base Docker image (`ares-base`)
- `targets`: Defines build targets (container images)

---

## Building Docker Images

This builds **Ares Worker** Docker images for `amd64` and `arm64`
architectures, uses the shared base image, and configures it
as a long-running worker daemon.

**Initialize the template:**

```bash
warpgate init ares-worker
```

**Build Docker images:**

```bash
warpgate build ares-worker --only 'docker.*'
```

**Build for specific architecture:**

```bash
warpgate build ares-worker --arch amd64 --only 'docker.*'
```

After the build, Ares Worker Docker images will be available
locally as `ares-worker:latest`.

---

## Pushing Docker Images to GitHub Container Registry

After building the Docker image, you can push it to GHCR:

```bash
# Tag the image
docker tag ares-worker:latest ghcr.io/dreadnode/ares-worker:latest

# Authenticate with GHCR
echo $GITHUB_TOKEN | docker login ghcr.io -u YOUR_USERNAME --password-stdin

# Push the image
docker push ghcr.io/dreadnode/ares-worker:latest
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
  ares-worker:latest
```

**Verify the worker is installed correctly:**

```bash
# Check ares CLI is available
docker run --rm ares-worker:latest python -m ares --version

# Test with a specific role (requires Redis)
docker run -it --rm \
  -e REDIS_URL="redis://localhost:6379" \
  -e ANTHROPIC_API_KEY="your-api-key" \
  ares-worker:latest enumeration test-operation-id
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
  ares-worker:latest enumeration test-op
```

**Verify health check commands work:**

```bash
# Test that pgrep is available (for Kubernetes probes)
docker run --rm ares-worker:latest pgrep -V
```

---

## Validating the Template

To validate the template configuration before building:

```bash
warpgate validate ares-worker
```

---

## Notes

- **Docker build:**
  - Multi-arch (`amd64` + `arm64`) support
  - Default user: `root`
  - Working directory: `/root`
  - Entrypoint: `python -m ares worker`
- **Installed Components:**
  - Provided by `ares-base` (Python 3.13.x, uv, Ares framework, dependencies, procps)
- **Directory Structure:**
  - `/root/` - Default working directory
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
      - pgrep -f 'ares worker'
  initialDelaySeconds: 30
  periodSeconds: 10
```

Deploy using the manifests in the argonaut repository:

```bash
kubectl apply -k environments/dev/platforms/attack-simulation/ares-worker
```

---

## Customization

To customize the build, edit the `warpgate.yaml` file:

- Modify `base.image` to use a different Python version
- Adjust the entrypoint or environment in the `base` section
- Adjust `targets` to change build platforms

For more information on Warp Gate template configuration, see the [Warp Gate documentation](https://github.com/cowdogmoo/warpgate).
