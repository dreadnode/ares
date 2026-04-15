# Ares PrivEsc Agent Warp Gate Template

This template builds **Ares PrivEsc Agent** images using Warp Gate. It supports
building **Docker images** (for `amd64` and `arm64`). The build provisions
privilege escalation tools for Windows and Linux targets using Ansible roles
from the nimbus_range collection.

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

- `name`: Template name (`ares-privesc-agent`)
- `base.image`: Base Docker image (ares-base)
- `provisioners`: Shell and Ansible provisioners for setup
- `targets`: Defines build targets (container images)

Environment variables required:

- `PROVISION_REPO_PATH`: Path to your ansible-collection-nimbus_range repository

---

## Building Docker Images

This builds **Ares PrivEsc Agent** Docker images for `amd64` and `arm64`
architectures, installs prerequisites, and provisions using Ansible roles.

**Initialize the template:**

```bash
warpgate init ares-privesc-agent
```

**Build Docker images:**

```bash
export PROVISION_REPO_PATH="${HOME}/ansible-collection-nimbus_range"
warpgate build ares-privesc-agent --only 'docker.*'
```

After the build, multi-arch Ares PrivEsc Agent Docker images will be available
locally as `ares-privesc-agent:latest`.

---

## Pushing Docker Images to GitHub Container Registry

After building the Docker image, you can push it to GHCR:

```bash
# Tag the image
docker tag ares-privesc-agent:latest ghcr.io/dreadnode/ares-privesc-agent:latest

# Authenticate with GHCR
echo $GITHUB_TOKEN | docker login ghcr.io -u YOUR_USERNAME --password-stdin

# Push the image
docker push ghcr.io/dreadnode/ares-privesc-agent:latest
```

---

## Validating the Template

To validate the template configuration before building:

```bash
warpgate validate ares-privesc-agent
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
  - `ares_privesc_tools` - Comprehensive privilege escalation toolkit
- **Installed Tools:**

  **Potato Exploits (SeImpersonatePrivilege):**
  - **PrintSpoofer** - Named pipe impersonation
  - **SweetPotato** - Alternative potato exploit
  - **GodPotato** - Modern potato exploit

  **Kerberos/AD PrivEsc:**
  - **KrbRelayUp** - Kerberos relay local privilege escalation
  - **SharpGPOAbuse** - GPO-based privilege escalation
  - **noPac** - CVE-2021-42287/CVE-2021-42278 exploitation

  **Enumeration Tools:**
  - **Seatbelt** - Windows security enumeration
  - **SharpUp** - Privilege escalation checks
  - **PowerUp** - PowerShell privesc enumeration
  - **WinPEAS** - Windows privilege escalation enumeration
  - **LinPEAS** - Linux privilege escalation enumeration

  **Other Tools:**
  - **RunasCs** - Run commands as another user
  - **PrintNightmare** - CVE-2021-1675 exploitation

- **Directory Structure:**
  - `/ares/` - Main Ares workspace directory
  - `/ares/.venv/` - Python virtual environment
  - `/opt/privesc/` - All privilege escalation tools
    - `/opt/privesc/PrintSpoofer/`
    - `/opt/privesc/SweetPotato/`
    - `/opt/privesc/GodPotato/`
    - `/opt/privesc/KrbRelayUp/`
    - `/opt/privesc/SharpGPOAbuse/`
    - `/opt/privesc/Seatbelt/`
    - `/opt/privesc/SharpUp/`
    - `/opt/privesc/PowerUp/`
    - `/opt/privesc/WinPEAS/`
    - `/opt/privesc/LinPEAS/`
    - `/opt/privesc/RunasCs/`
    - `/opt/privesc/noPac/`
    - `/opt/privesc/PrintNightmare/`
- The build includes cleanup steps to remove temporary files and Ansible artifacts.

---

## Use Cases

This agent is specialized for:

- **Token Impersonation** - Potato exploits for SeImpersonatePrivilege abuse
- **Local Privilege Escalation** - Multiple techniques for elevating privileges
- **Enumeration** - Identifying privilege escalation vectors
- **CVE Exploitation** - noPac, PrintNightmare

### Common Attack Scenarios

1. **Service Account with SeImpersonatePrivilege** - Use PrintSpoofer/GodPotato
2. **Misconfigured GPO** - Use SharpGPOAbuse
3. **CVE-2021-42287** - Use noPac for domain user to domain admin
4. **General Enumeration** - Run WinPEAS/LinPEAS to identify vectors

---

## Customization

To customize the build, edit the `warpgate.yaml` file:

- Modify `base.image` to use a different base image
- Add or remove provisioning steps in the `provisioners` section
- Adjust `targets` to change build platforms
- Update environment variables in provisioners to change Ansible behavior

For more information on Warp Gate template configuration, see the [Warp Gate documentation](https://github.com/cowdogmoo/warpgate).
