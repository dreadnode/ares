# Ares Rust Lateral Movement Agent Warp Gate Template

This template builds **Ares Rust Lateral Movement Agent** images using Warp Gate. It supports
building **Docker images** (for `amd64` and `arm64`). The build provisions
lateral movement and credential extraction tools using Ansible roles from the nimbus_range
collection, plus a compiled Rust worker binary with embedded Python.

---

## Requirements

- [Warp Gate](https://github.com/cowdogmoo/warpgate) installed and configured
- Docker (for building Docker images)
- `GITHUB_TOKEN` environment variable set (for cloning the ares repository)
- Provisioning repository (ansible-collection-nimbus_range) with the
  `PROVISION_REPO_PATH` environment variable set
- Required Packer plugins (installed automatically via `warpgate init`):
  - `docker`
  - `ansible`

---

## Configuration

The template configuration is managed in `warpgate.yaml`. Key settings include:

- `name`: Template name (`ares-rust-lateral-movement-agent`)
- `base.image`: Base Docker image (ares-base)
- `sources`: Clones the ares repository for Rust compilation
- `provisioners`: Shell, Ansible, and file provisioners for setup
- `targets`: Defines build targets (container images)

Environment variables required:

- `PROVISION_REPO_PATH`: Path to your ansible-collection-nimbus_range repository
- `GITHUB_TOKEN`: GitHub token for cloning the ares repository

---

## Building Docker Images

This builds **Ares Rust Lateral Movement Agent** Docker images for `amd64` and `arm64`
architectures, installs prerequisites, provisions using Ansible roles, and
compiles the Rust worker binary.

**Initialize the template:**

```bash
warpgate init ares-rust-lateral-movement-agent
```

**Build Docker images:**

```bash
export PROVISION_REPO_PATH="${HOME}/ansible-collection-nimbus_range"
warpgate build ares-rust-lateral-movement-agent --only 'docker.*'
```

After the build, multi-arch Ares Rust Lateral Movement Agent Docker images will be available
locally as `ares-rust-lateral-movement-agent:latest`.

---

## Pushing Docker Images to GitHub Container Registry

After building the Docker image, you can push it to GHCR:

```bash
# Tag the image
docker tag ares-rust-lateral-movement-agent:latest ghcr.io/dreadnode/ares-rust-lateral-movement-agent:latest

# Authenticate with GHCR
echo $GITHUB_TOKEN | docker login ghcr.io -u YOUR_USERNAME --password-stdin

# Push the image
docker push ghcr.io/dreadnode/ares-rust-lateral-movement-agent:latest
```

---

## Validating the Template

To validate the template configuration before building:

```bash
warpgate validate ares-rust-lateral-movement-agent
```

---

## Notes

- The build uses **shell, Ansible, and file provisioners**. Ensure your
  provisioning playbooks and requirement files are available at the path
  specified by `PROVISION_REPO_PATH`.
- **Docker build:**
  - Multi-arch (`amd64` + `arm64`) and privileged for full testbed support.
  - Images are suitable for CI, local testing, or deployment in a Kubernetes cluster.
  - Default user: `root`
  - Working directory: `/root`
- **Ansible Roles:** Uses `dreadnode.nimbus_range` roles:
  - `ares_base` - Python 3.13.7, uv, core dependencies
  - `ares_lateral_movement_tools` - evil-winrm, lsassy, xfreerdp, sshpass
- **Rust Binary:**
  - Compiled from `feature/rust-cli` branch with PyO3 Python bindings
  - Installed to `/usr/local/bin/ares-worker`
- **Installed Tools:**
  - **evil-winrm** - WinRM shell with pass-the-hash support
  - **lsassy** - Remote LSASS credential extraction
  - **xfreerdp** - RDP client with pass-the-hash support
  - **sshpass** - SSH with password automation
- **Directory Structure:**
  - `/ares/` - Main Ares workspace directory
  - `/ares/.venv/` - Python virtual environment
  - `/usr/local/bin/ares-worker` - Compiled worker binary
- The build includes cleanup steps to remove temporary files, Ansible artifacts, and Rust build artifacts.

---

## Use Cases

This agent is specialized for:

- **WinRM Access** - Interactive shell access with pass-the-hash
- **Credential Extraction** - Remote LSASS dumping via lsassy
- **RDP Pass-the-Hash** - GUI access using NTLM hashes
- **SSH Automation** - Scripted SSH access with passwords

---

## Customization

To customize the build, edit the `warpgate.yaml` file:

- Modify `base.image` to use a different base image
- Add or remove provisioning steps in the `provisioners` section
- Adjust `targets` to change build platforms
- Update environment variables in provisioners to change Ansible behavior

For more information on Warp Gate template configuration, see the [Warp Gate documentation](https://github.com/cowdogmoo/warpgate).
