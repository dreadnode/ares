# Ares Cracker Base GPU Warp Gate Template

This template builds the **Ares Cracker Base GPU** image using Warp Gate. It
provides a pre-compiled hashcat binary with CUDA support on an NVIDIA runtime
base. This is an intermediate build layer -- `ares-cracker-agent-gpu` extends
it with wordlists and additional tools.

---

## Requirements

- [Warp Gate](https://github.com/cowdogmoo/warpgate) installed and configured
- Docker with BuildKit support
- NVIDIA Container Toolkit on the build host
- Provisioning repository with the `PROVISION_REPO_PATH` environment variable set

---

## GPU Support

Built on `nvidia/cuda:12.6.0-runtime-ubuntu24.04` with:

- **CUDA**: Full NVIDIA compute support for hashcat
- **OpenCL**: NVIDIA OpenCL ICD registered
- **hashcat**: Compiled from source for optimal CUDA performance

---

## Configuration

The template uses the `cracking_tools` Ansible role with GPU-specific overrides:

- `cracking_tools_gpu_support: true` -- Installs OpenCL packages
- `cracking_tools_hashcat_from_source: true` -- Compiles hashcat with CUDA
- `cracking_tools_nvidia_opencl_icd: true` -- Registers NVIDIA OpenCL ICD

---

## Building Docker Images

```bash
export PROVISION_REPO_PATH="./ansible"

warpgate build ares-cracker-base-gpu --only 'docker.*'
```

---

## Notes

- **Architecture**: `amd64` only (NVIDIA CUDA not available for ARM)
- **Base Image**: `nvidia/cuda:12.6.0-runtime-ubuntu24.04`
- **Python**: 3.13 via deadsnakes PPA
- **Purpose**: Intermediate layer to cache the expensive hashcat CUDA
  compilation. Downstream images (`ares-cracker-agent-gpu`) add wordlists
  and runtime tooling on top.
- **Privileged build**: Required for cgroup access during provisioning

## Build Chain

```text
nvidia/cuda:12.6.0-runtime-ubuntu24.04
  └── ares-cracker-base-gpu (this template)
        └── ares-cracker-agent-gpu (+john, rockyou, seclists)
```

For more information on Warp Gate template configuration, see the
[Warp Gate documentation](https://github.com/cowdogmoo/warpgate).
