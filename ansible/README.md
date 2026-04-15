# Dreadnode Nimbus Range Ansible Collection

Ansible collection for provisioning Ares security operations agents. Includes
roles for reconnaissance, credential access, privilege escalation, lateral
movement, coercion, hash cracking, and observability tooling.

**Namespace:** `dreadnode.nimbus_range`
**Version:** 1.5.0

## Requirements

- Ansible >= 2.15.0
- Python 3.13+

## Installation

Install collection dependencies:

```bash
cd ansible
ansible-galaxy collection install -r requirements.yml
```

## Roles

### Agent Roles

| Role | Description |
| --- | --- |
| `base` | Python 3.13, uv, `/ares` workspace setup |
| `recon_tools` | nmap, netexec, bloodhound-python, certipy, impacket, rpcclient |
| `credential_access_tools` | sprayhound, lsassy, gMSADumper, kerberoasting, secretsdump |
| `cracking_tools` | hashcat, John the Ripper, rockyou.txt, SecLists (optional GPU/CUDA) |
| `acl_tools` | bloodyAD, pywhisker, dacledit |
| `privesc_tools` | certipy, krbrelayx, nopac, potato exploits, SharpGPOAbuse, WinPEAS, LinPEAS |
| `lateral_movement_tools` | evil-winrm, xfreerdp, lsassy, sshpass, pth-toolkit, impacket |
| `coercion_tools` | Responder, mitm6, Coercer, PetitPotam, ntlmrelayx |

### Infrastructure Roles

| Role | Description |
| --- | --- |
| `aws_ssm_agent` | AWS Systems Manager agent for remote management |
| `aws_cloudwatch_agent` | CloudWatch metrics and log collection |
| `fluent_bit` | Log forwarding to OpenSearch/Loki |
| `alloy` | Grafana Alloy observability agent |
| `mythic` | Mythic C2 framework deployment |
| `dc_audit_sacl` | Domain controller audit SACL configuration |

## Playbooks

### Agent Provisioning (`playbooks/ares/`)

Each playbook provisions a specialized agent container or host:

| Playbook | Purpose |
| --- | --- |
| `base.yml` | Base image with Python, uv, and core dependencies |
| `recon.yml` | Network reconnaissance and AD enumeration |
| `credential_access.yml` | Credential harvesting and Kerberos attacks |
| `cracker.yml` | Password cracking (CPU or GPU) |
| `acl_abuse.yml` | AD ACL/DACL exploitation |
| `privesc.yml` | Privilege escalation |
| `lateral_movement.yml` | Lateral movement and remote access |
| `coercion.yml` | NTLM relay and authentication coercion |
| `goad_attack_box.yml` | All-in-one attack workstation with all tools |

### Infrastructure (`playbooks/linux/`, `playbooks/windows/`)

| Playbook | Purpose |
| --- | --- |
| `linux/attacker_setup.yml` | Linux attacker box with SSM, CloudWatch, Fluent Bit |
| `linux/sliver.yml` | Sliver C2 server |
| `windows/target_setup.yml` | Windows target telemetry |

## Usage

### Container Builds (via Warpgate)

Playbooks are invoked automatically by Warpgate templates during image builds:

```bash
export PROVISION_REPO_PATH=./ansible
warpgate build warpgate-templates/ares-recon-agent
```

### Standalone Provisioning

Playbooks can provision existing hosts directly:

```bash
# Provision a recon agent on a remote host
ansible-playbook ansible/playbooks/ares/recon.yml \
  -i inventory.yml \
  -e target_hosts=recon-host

# Provision inside a container
ansible-playbook ansible/playbooks/ares/recon.yml \
  -e container_build=true \
  -e target_hosts=localhost \
  -c local
```

## Custom Modules

| Module | Description |
| --- | --- |
| `vnc_pw` | VNC password management |
| `getent_passwd` | Cross-platform user enumeration |
| `merge_list_dicts_into_list` | Data transformation utility |

## Collection Dependencies

| Collection | Version |
| --- | --- |
| `amazon.aws` | 11.2.0 |
| `ansible.windows` | 3.5.0 |
| `community.windows` | 3.1.0 |
| `community.docker` | 5.0.6 |
| `community.general` | 12.4.0 |
| `grafana.grafana` | 6.0.6 |
| `cowdogmoo.workstation` | main (git) |
| `l50.arsenal` | main (git) |

## License

MIT
