# Ares CLI Warp Gate Template

This template builds **Ares CLI** images using Warp Gate. It supports
building **Docker images** (for `amd64` and `arm64`). This is a pure Rust CLI
for the Ares red team orchestration system with no Python dependencies.

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

- `name`: Template name (`ares-cli`)
- `base.image`: Base Docker image (`debian:trixie-slim`)
- `sources`: Clones the ares repository for Rust compilation
- `targets`: Defines build targets (container images)

---

## Building Docker Images

This builds **Ares CLI** Docker images for `amd64` and `arm64`
architectures, compiles the pure Rust CLI binary, and produces a minimal
container image.

**Initialize the template:**

```bash
warpgate init ares-cli
```

**Build Docker images:**

```bash
warpgate build ares-cli --only 'docker.*'
```

**Build for specific architecture:**

```bash
warpgate build ares-cli --arch amd64 --only 'docker.*'
```

After the build, Ares CLI Docker images will be available
locally as `ares-cli:latest`.

---

## Pushing Docker Images to GitHub Container Registry

After building the Docker image, you can push it to GHCR:

```bash
# Tag the image
docker tag ares-cli:latest ghcr.io/dreadnode/ares-cli:latest

# Authenticate with GHCR
echo $GITHUB_TOKEN | docker login ghcr.io -u YOUR_USERNAME --password-stdin

# Push the image
docker push ghcr.io/dreadnode/ares-cli:latest
```

---

## Local Testing

After building the image, you can test it locally:

**Run the CLI:**

```bash
docker run --rm ares-cli:latest --help
```

**Verify the binary is installed correctly:**

```bash
docker run --rm ares-cli:latest --version
```

---

## Validating the Template

To validate the template configuration before building:

```bash
warpgate validate ares-cli
```

---

## Notes

- **Docker build:**
  - Multi-arch (`amd64` + `arm64`) support
  - Lightweight base image (`debian:trixie-slim`)
  - Default user: `root`
  - Working directory: `/root`
  - Entrypoint: `ares` (compiled Rust binary)
- **Installed Components:**
  - Pure Rust `ares` binary (no Python dependencies)
- **Build Process:**
  - Clones ares repository from `feature/rust-cli` branch
  - Installs Rust toolchain and build dependencies
  - Compiles binary with `cargo build --release --bin ares`
  - Installs binary to `/usr/local/bin/ares`
  - Cleans up Rust toolchain, build artifacts, and build-only dependencies
- **Directory Structure:**
  - `/root/` - Default working directory
  - `/usr/local/bin/ares` - Compiled Ares binary

---

## Customization

To customize the build, edit the `warpgate.yaml` file:

- Modify `base.image` to use a different base image
- Adjust the entrypoint or environment in the `base` section
- Adjust `targets` to change build platforms

For more information on Warp Gate template configuration, see the [Warp Gate documentation](https://github.com/cowdogmoo/warpgate).
