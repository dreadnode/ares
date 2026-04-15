# Ares Recon Agent Warp Gate Template

This template builds **Ares Recon Agent** images using Warp Gate. It supports
building **Docker images** (for `amd64` and `arm64`). The build provisions
comprehensive network reconnaissance and Active Directory enumeration tools
using Ansible roles from the nimbus_range collection.

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

- `name`: Template name (`ares-recon-agent`)
- `base.image`: Base Docker image (ares-base)
- `provisioners`: Shell and Ansible provisioners for setup
- `targets`: Defines build targets (container images)

Environment variables required:

- `PROVISION_REPO_PATH`: Path to your ansible-collection-nimbus_range repository

---

## Building Docker Images

This builds **Ares Recon Agent** Docker images for `amd64` and `arm64`
architectures, installs prerequisites, and provisions using Ansible roles.

**Initialize the template:**

```bash
warpgate init ares-recon-agent
```

**Build Docker images:**

```bash
export PROVISION_REPO_PATH="${HOME}/ansible-collection-nimbus_range"
warpgate build ares-recon-agent --only 'docker.*'
```

After the build, multi-arch Ares Recon Agent Docker images will be available
locally as `ares-recon-agent:latest`.

---

## Pushing Docker Images to GitHub Container Registry

After building the Docker image, you can push it to GHCR:

```bash
# Tag the image
docker tag ares-recon-agent:latest ghcr.io/dreadnode/ares-recon-agent:latest

# Authenticate with GHCR
echo $GITHUB_TOKEN | docker login ghcr.io -u YOUR_USERNAME --password-stdin

# Push the image
docker push ghcr.io/dreadnode/ares-recon-agent:latest
```

---

## Validating the Template

To validate the template configuration before building:

```bash
warpgate validate ares-recon-agent
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
- **Ansible Roles:** Uses `dreadnode.nimbus_range` roles:
  - `ares_base` - Python 3.13.7, uv, core dependencies
  - `ares_recon_tools` - nmap, netexec, impacket, bloodhound, certipy, rpcclient
- **Installed Tools:**
  - **Network:** nmap, smbclient, ldap-utils, dnsutils, netcat
  - **AD Recon:** netexec, impacket, bloodhound-python, certipy
- **Directory Structure:**
  - `/ares/` - Main Ares workspace directory
  - `/ares/.venv/` - Python virtual environment
  - `/ares/agents/` - Agent storage directory
  - `/ares/data/` - Data storage directory
- The build includes cleanup steps to remove temporary files and Ansible artifacts.

---

## Use Cases

This agent is specialized for:

- **Network Discovery** - Port scanning, service enumeration with nmap
- **AD Enumeration** - LDAP queries, BloodHound data collection
- **SMB Enumeration** - Share discovery, user enumeration with netexec
- **Certificate Services** - ADCS enumeration with certipy

---

## Customization

To customize the build, edit the `warpgate.yaml` file:

- Modify `base.image` to use a different base image
- Add or remove provisioning steps in the `provisioners` section
- Adjust `targets` to change build platforms
- Update environment variables in provisioners to change Ansible behavior

For more information on Warp Gate template configuration, see the [Warp Gate documentation](https://github.com/cowdogmoo/warpgate).
