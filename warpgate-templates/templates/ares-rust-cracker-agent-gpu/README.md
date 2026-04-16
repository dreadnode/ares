# Ares Rust Cracker Agent GPU Warp Gate Template

This template builds **Ares Rust Cracker Agent GPU** images using Warp Gate. It provides
GPU-accelerated password cracking using hashcat with CUDA/OpenCL support for NVIDIA GPUs,
using a compiled Rust binary with embedded Python.

---

## Requirements

- [Warp Gate](https://github.com/cowdogmoo/warpgate) installed and configured
- Docker (for building Docker images)
- `GITHUB_TOKEN` environment variable set (for cloning the ares repository)
- NVIDIA GPU with CUDA support (for runtime)
- Required Packer plugins (installed automatically via `warpgate init`):
  - `docker`

---

## GPU Support

This image is built on the NVIDIA CUDA runtime image and supports:

- **CUDA**: Full NVIDIA CUDA compute support for hashcat
- **OpenCL**: OpenCL runtime for additional GPU backends
- **Multi-GPU**: Supports multiple GPUs via `NVIDIA_VISIBLE_DEVICES`

### Runtime Requirements

To run the container with GPU access:

```bash
docker run --gpus all -it ghcr.io/dreadnode/ares-rust-cracker-agent-gpu:latest
```

Or with specific GPUs:

```bash
docker run --gpus '"device=0,1"' -it ghcr.io/dreadnode/ares-rust-cracker-agent-gpu:latest
```

### Verifying GPU Access

Inside the container, verify GPU detection:

```bash
# Check NVIDIA driver/GPU visibility
nvidia-smi

# Check OpenCL devices
clinfo

# Check hashcat GPU detection
hashcat -I

# Verify the Rust binary
ares-worker --version
```

---

## Configuration

The template configuration is managed in `warpgate.yaml`. Key settings include:

- `name`: Template name (`ares-rust-cracker-agent-gpu`)
- `base.image`: Base Docker image (`ares-cracker-base-gpu`)
- `sources`: Clones the ares repository for Rust compilation
- `targets`: Defines build targets (container images)

---

## Building Docker Images

This builds GPU-accelerated Ares Rust Cracker Agent Docker images for `amd64` architecture.

**Initialize the template:**

```bash
warpgate init ares-rust-cracker-agent-gpu
```

**Build Docker images:**

```bash
warpgate build ares-rust-cracker-agent-gpu --only 'docker.*'
```

**Build with registry push:**

```bash
cd /path/to/warpgate-templates

export GITHUB_TOKEN="your-github-token"

warpgate build --template ares-rust-cracker-agent-gpu \
  --arch amd64 \
  --registry ghcr.io/dreadnode \
  --tag latest \
  --push \
  --cache-from type=registry,ref=ghcr.io/dreadnode/ares-rust-cracker-agent-gpu:buildcache-amd64 \
  --cache-to type=registry,ref=ghcr.io/dreadnode/ares-rust-cracker-agent-gpu:buildcache-amd64,mode=max
```

After the build, Ares Rust Cracker Agent GPU Docker images will be available
locally as `ares-rust-cracker-agent-gpu:latest`.

---

## Installed Tools

- **hashcat** - GPU-accelerated password recovery tool compiled from source with CUDA support
- **John the Ripper** - Classic password cracker
- **rockyou.txt** - Famous password wordlist
- **SecLists passwords** - Common password lists
- **ares-worker** - Rust-compiled binary with PyO3 Python bindings
- **Ares Python framework** - Agent orchestration and tool execution

---

## CPU vs GPU Comparison

| Image                          | GPU Support      | Use Case                          |
|--------------------------------|------------------|-----------------------------------|
| `ares-rust-cracker-agent`      | CPU only (PoCL)  | CI/CD, testing, ARM support       |
| `ares-rust-cracker-agent-gpu`  | CUDA/OpenCL      | Production cracking, NVIDIA GPUs  |

---

## Notes

- **Docker build:**
  - `amd64` only (NVIDIA CUDA does not support ARM64)
  - Privileged mode with cgroup mounts
  - Default user: `root`
  - Working directory: `/root`
  - Entrypoint: configurable via `${ENTRYPOINT}`
- **GPU Configuration:**
  - `NVIDIA_VISIBLE_DEVICES=all`
  - `NVIDIA_DRIVER_CAPABILITIES=compute,utility`
  - CUDA and OpenCL runtime support
- **Installed Components:**
  - Provided by `ares-cracker-base-gpu` (hashcat, john, wordlists, CUDA runtime)
  - Rust-compiled `ares-worker` binary with PyO3 Python bindings
  - Ares Python framework
- **Build Process:**
  - Clones ares repository from `feature/rust-cli` branch
  - Installs Rust toolchain, compiles binary with `--features python`
  - Installs binary to `/usr/local/bin/ares-worker`
  - Cleans up Rust toolchain, build artifacts, and build-only dependencies
- **Directory Structure:**
  - `/root/` - Default working directory
  - `/usr/local/bin/ares-worker` - Compiled worker binary
  - `/usr/share/wordlists/` - Wordlist collection
  - `/usr/share/hashcat/rules/` - Hashcat rules
- **Architecture**: Only `amd64` is supported (NVIDIA CUDA not available for ARM)
- **Memory**: GPU cracking may require significant VRAM for large wordlists
- **Kubernetes**: Use NVIDIA device plugin for GPU scheduling

For CPU-only cracking, use the `ares-rust-cracker-agent` template instead.

---

## Customization

To customize the build, edit the `warpgate.yaml` file:

- Modify `base.image` to use a different GPU base image
- Adjust the entrypoint or environment in the `base` section
- Update NVIDIA environment variables for different GPU configurations

For more information on Warp Gate template configuration, see the [Warp Gate documentation](https://github.com/cowdogmoo/warpgate).
