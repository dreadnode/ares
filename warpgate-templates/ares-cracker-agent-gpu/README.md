# Ares Cracker Agent GPU Warp Gate Template

This template builds **Ares Cracker Agent GPU** images using Warp Gate. It provides
GPU-accelerated password cracking using hashcat with CUDA/OpenCL support for NVIDIA GPUs.

---

## Requirements

- [Warp Gate](https://github.com/cowdogmoo/warpgate) installed and configured
- Docker with BuildKit support
- NVIDIA GPU with CUDA support (for runtime)
- NVIDIA Container Toolkit installed on the host
- Access to `ansible-collection-nimbus_range` repository

---

## GPU Support

This image is built on the NVIDIA CUDA runtime image and supports:

- **CUDA**: Full NVIDIA CUDA compute support for hashcat
- **OpenCL**: OpenCL runtime for additional GPU backends
- **Multi-GPU**: Supports multiple GPUs via `NVIDIA_VISIBLE_DEVICES`

### Runtime Requirements

To run the container with GPU access:

```bash
docker run --gpus all -it ghcr.io/dreadnode/ares-cracker-agent-gpu:latest
```

Or with specific GPUs:

```bash
docker run --gpus '"device=0,1"' -it ghcr.io/dreadnode/ares-cracker-agent-gpu:latest
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
```

---

## Configuration

The template uses the standard warpgate provisioner pattern with ansible playbooks from
`ansible-collection-nimbus_range`. Key GPU-specific settings:

- `cracking_tools_gpu_support: true` - Installs OpenCL packages
- `cracking_tools_hashcat_from_source: true` - Builds hashcat from source for CUDA support
- `cracking_tools_nvidia_opencl_icd: true` - Registers NVIDIA OpenCL ICD

---

## Building Docker Images

This builds GPU-accelerated Ares Cracker Agent Docker images for `amd64` architecture.

**Build with registry push:**

```bash
cd /path/to/warpgate-templates

export PROVISION_REPO_PATH="$HOME/path/to/ansible-collection-nimbus_range"
export GITHUB_TOKEN="your-github-token"

warpgate build --template ares-cracker-agent-gpu \
  --arch amd64 \
  --registry ghcr.io/dreadnode \
  --tag latest \
  --push \
  --cache-from type=registry,ref=ghcr.io/dreadnode/ares-cracker-agent-gpu:buildcache-amd64 \
  --cache-to type=registry,ref=ghcr.io/dreadnode/ares-cracker-agent-gpu:buildcache-amd64,mode=max
```

---

## Installed Tools

- **hashcat** - GPU-accelerated password recovery tool compiled from source with CUDA support
- **John the Ripper** - Classic password cracker
- **rockyou.txt** - Famous password wordlist
- **SecLists passwords** - Common password lists

---

## CPU vs GPU Comparison

| Image                     | GPU Support      | Use Case                          |
|---------------------------|------------------|-----------------------------------|
| `ares-cracker-agent`      | CPU only (PoCL)  | CI/CD, testing, ARM support       |
| `ares-cracker-agent-gpu`  | CUDA/OpenCL      | Production cracking, NVIDIA GPUs  |

---

## Notes

- **Architecture**: Only `amd64` is supported (NVIDIA CUDA not available for ARM)
- **Base Image**: `nvidia/cuda:12.2.2-runtime-ubuntu22.04`
- **hashcat**: Compiled from source for optimal CUDA performance
- **Memory**: GPU cracking may require significant VRAM for large wordlists
- **Kubernetes**: Use NVIDIA device plugin for GPU scheduling

For more information on Warp Gate template configuration, see the [Warp Gate documentation](https://github.com/cowdogmoo/warpgate).
