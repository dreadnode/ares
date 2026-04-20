# Ares Golden Image Warp Gate Template

This template builds the **Ares Golden Image** AMI using Warp Gate. It produces
a Kali-based Amazon Machine Image pre-loaded with all Ares red team tools
-- recon, credential access, privilege escalation, password cracking, lateral
movement, ACL abuse, and coercion -- plus Alloy telemetry.

---

## Requirements

- [Warp Gate](https://github.com/cowdogmoo/warpgate) installed and configured
- AWS credentials configured (for building AMIs)
- `GITHUB_TOKEN` environment variable set (for cloning private repositories)
- Required Packer plugins (installed automatically via `warpgate init`):
  - `amazon`

---

## Configuration

The template configuration is managed in `warpgate.yaml`. Key settings include:

- `name`: Template name (`ares-golden-image`)
- `base.image`: Base Docker image (`kalilinux/kali-rolling:latest`)
- `base.ami_filters`: Finds the latest Kali AMI for `x86_64`
- `provisioners`: Shell steps that install tools via Ansible and the Ares framework
- `targets`: Defines the AMI build target

---

## Building the AMI

This builds an **Ares Golden Image** AMI in `us-west-1` on a `t3.large`
instance with a 100 GB volume.

**Initialize the template:**

```bash
warpgate init ares-golden-image
```

**Build the AMI:**

```bash
warpgate build ares-golden-image --only 'ami.*'
```

After the build, the AMI will be available in `us-west-1` with the name
`ares-golden-image-<timestamp>`.

---

## Validating the Template

To validate the template configuration before building:

```bash
warpgate validate ares-golden-image
```

---

## Notes

- **AMI build:**
  - Architecture: `x86_64` (amd64)
  - Region: `us-west-1`
  - Instance type: `t3.large`
  - Volume size: 100 GB
  - Base: Kali Linux (latest Debian Kali snapshot)
- **Build Process:**
  1. Installs base packages (pipx, Ansible, git, Python tooling)
  2. Clones the `nimbus_range` Ansible collection and installs its dependencies
  3. Runs the `goad_attack_box` playbook to install all red team tools and Alloy telemetry
  4. Clones and installs the Ares framework via `pipx`
  5. Cleans up build artifacts
- **Installed Components:**
  - All attack box tools (via Ansible)
  - Alloy telemetry agent
  - Ares framework (installed via pipx)
  - Python 3, uv, pipx
- **AMI Tags:**
  - `Project`: ares
  - `Role`: RedTeamAttackBox
  - `ManagedBy`: warpgate
  - `Tools`: recon, credential-access, privesc, cracker, lateral-movement, acl-abuse, coercion

---

## Customization

To customize the build, edit the `warpgate.yaml` file:

- Modify `base.ami_filters` to use a different base AMI
- Adjust `targets` to change region, instance type, or volume size
- Add or remove provisioner steps to customize installed tools

For more information on Warp Gate template configuration, see the [Warp Gate documentation](https://github.com/cowdogmoo/warpgate).
