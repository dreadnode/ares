# Ares Base Warp Gate Template

This template builds **Ares Base** images using Warp Gate. It supports
building **Docker images** (for `amd64` and `arm64`). The build provisions
Python 3.13.7, uv package manager, the Ares framework package, and core
dependencies using Ansible roles from the nimbus_range collection.

---

## Requirements

- [Warp Gate](https://github.com/cowdogmoo/warpgate) installed and configured
- Docker (for building Docker images)
- Provisioning repository (ansible-collection-nimbus_range) with the
  `PROVISION_REPO_PATH` environment variable set
- Required Packer plugins (installed automatically via `warpgate init`):
  - `docker`
  - `ansible`

---

## Configuration

The template configuration is managed in `warpgate.yaml`. Key settings include:

- `name`: Template name (`ares-base`)
- `base.image`: Base Docker image (Kali rolling)
- `provisioners`: Shell and Ansible provisioners for setup
- `targets`: Defines build targets (container images)

Environment variables required:

- `PROVISION_REPO_PATH`: Path to your ansible-collection-nimbus_range repository

---

## Building Docker Images

This builds **Ares Base** Docker images for `amd64` and `arm64`
architectures, installs prerequisites, and provisions using Ansible roles.

**Initialize the template:**

```bash
warpgate init ares-base
```

**Build Docker images:**

```bash
export PROVISION_REPO_PATH="${HOME}/ansible-collection-nimbus_range"
warpgate build ares-base --only 'docker.*'
```

After the build, multi-arch Ares Base Docker images will be available
locally as `ares-base:latest`.

---

## Pushing Docker Images to GitHub Container Registry

After building the Docker image, you can push it to GHCR:

```bash
# Tag the image
docker tag ares-base:latest ghcr.io/dreadnode/ares-base:latest

# Authenticate with GHCR
echo $GITHUB_TOKEN | docker login ghcr.io -u YOUR_USERNAME --password-stdin

# Push the image
docker push ghcr.io/dreadnode/ares-base:latest
```

---

## Validating the Template

To validate the template configuration before building:

```bash
warpgate validate ares-base
```

---

## Notes

- The build uses both **shell and Ansible provisioners**. Ensure your
  provisioning playbooks and requirement files are available at the path
  specified by `PROVISION_REPO_PATH`.
- **Docker build:**
  - Multi-arch (`amd64` + `arm64`) and privileged for full testbed support.
  - Images are suitable for CI, local testing, or deployment in a Kubernetes cluster.
  - Default user: `root`
  - Working directory: `/root`
- **Ansible Role:** Uses `dreadnode.nimbus_range.ares_base` role which installs:
  - Python 3.13.7 with development packages
  - uv package manager (fast Python package installer)
  - Core Ares Python dependencies (python-dotenv, dreadnode, rigging, pydantic)
  - Base system tools (build essentials, SSL libraries, git, curl)
- **Ares Framework:** Installed from source to enable the worker entrypoint in derived images.
- **Directory Structure:**
  - `/ares/` - Main Ares workspace directory
  - `/ares/.venv/` - Python virtual environment
  - `/ares/agents/` - Agent storage directory
  - `/ares/data/` - Data storage directory
- The build includes cleanup steps to remove temporary files and Ansible artifacts.

---

## Customization

To customize the build, edit the `warpgate.yaml` file:

- Modify `base.image` to use a different base image
- Add or remove provisioning steps in the `provisioners` section
- Adjust `targets` to change build platforms
- Update environment variables in provisioners to change Ansible behavior

For more information on Warp Gate template configuration, see the [Warp Gate documentation](https://github.com/cowdogmoo/warpgate).
