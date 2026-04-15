<!-- DOCSIBLE START -->
# credential_access_tools

## Description

Install and configure credential access tooling for Ares agents

## Requirements

- Ansible >= 2.18.4

## Dependencies


- dreadnode.nimbus_range.base

## Role Variables

### Default Variables (main.yml)

| Variable | Type | Default | Description |
| -------- | ---- | ------- | ----------- |
| `credential_access_tools_kali_packages` | list | <code>&#91;&#93;</code> | No description |
| `credential_access_tools_kali_packages.0` | str | <code>git</code> | No description |
| `credential_access_tools_kali_packages.1` | str | <code>python3-dev</code> | No description |
| `credential_access_tools_kali_packages.2` | str | <code>build-essential</code> | No description |
| `credential_access_tools_kali_packages.3` | str | <code>samba-common-bin</code> | No description |
| `credential_access_tools_kali_packages.4` | str | <code>smbclient</code> | No description |
| `credential_access_tools_ubuntu_packages` | list | <code>&#91;&#93;</code> | No description |
| `credential_access_tools_ubuntu_packages.0` | str | <code>git</code> | No description |
| `credential_access_tools_ubuntu_packages.1` | str | <code>python3</code> | No description |
| `credential_access_tools_ubuntu_packages.2` | str | <code>python3-pip</code> | No description |
| `credential_access_tools_ubuntu_packages.3` | str | <code>python3-dev</code> | No description |
| `credential_access_tools_ubuntu_packages.4` | str | <code>python3-venv</code> | No description |
| `credential_access_tools_ubuntu_packages.5` | str | <code>build-essential</code> | No description |
| `credential_access_tools_ubuntu_packages.6` | str | <code>samba-common-bin</code> | No description |
| `credential_access_tools_ubuntu_packages.7` | str | <code>smbclient</code> | No description |
| `credential_access_tools_install_impacket` | bool | <code>True</code> | No description |
| `credential_access_tools_impacket_from_source` | bool | <code>True</code> | No description |
| `credential_access_tools_impacket_repo` | str | <code>https://github.com/fortra/impacket.git</code> | No description |
| `credential_access_tools_impacket_version` | str | <code>impacket_0_13_0</code> | No description |
| `credential_access_tools_impacket_install_dir` | str | <code>/opt/impacket</code> | No description |
| `credential_access_tools_install_lsassy` | bool | <code>True</code> | No description |
| `credential_access_tools_install_sprayhound` | bool | <code>True</code> | No description |
| `credential_access_tools_sprayhound_package` | str | <code>sprayhound</code> | No description |
| `credential_access_tools_install_targetedkerberoast` | bool | <code>True</code> | No description |
| `credential_access_tools_targetedkerberoast_repo` | str | <code>https://github.com/ShutdownRepo/targetedKerberoast.git</code> | No description |
| `credential_access_tools_targetedkerberoast_install_dir` | str | <code>/opt/targetedKerberoast</code> | No description |
| `credential_access_tools_targetedkerberoast_version` | str | <code>main</code> | No description |
| `credential_access_tools_install_gmsadumper` | bool | <code>True</code> | No description |
| `credential_access_tools_gmsadumper_repo` | str | <code>https://github.com/micahvandeusen/gMSADumper.git</code> | No description |
| `credential_access_tools_gmsadumper_install_dir` | str | <code>/opt/gMSADumper</code> | No description |
| `credential_access_tools_gmsadumper_version` | str | <code>main</code> | No description |
| `credential_access_tools_update_cache` | bool | <code>True</code> | No description |
| `credential_access_tools_binaries` | dict | <code>{}</code> | No description |
| `credential_access_tools_binaries.impacket_getnpusers` | str | <code>/usr/local/bin/impacket-GetNPUsers</code> | No description |
| `credential_access_tools_binaries.impacket_secretsdump` | str | <code>/usr/local/bin/impacket-secretsdump</code> | No description |
| `credential_access_tools_binaries.lsassy` | str | <code>/usr/local/bin/lsassy</code> | No description |
| `credential_access_tools_binaries.sprayhound` | str | <code>/usr/bin/sprayhound</code> | No description |
| `credential_access_tools_binaries.targetedkerberoast` | str | <code>/usr/local/bin/targetedKerberoast</code> | No description |
| `credential_access_tools_binaries.gmsadumper` | str | <code>/usr/local/bin/gMSADumper</code> | No description |
| `credential_access_tools_binaries.smbclient` | str | <code>/usr/bin/smbclient</code> | No description |

## Tasks

### gmsadumper.yml


- **Clone gMSADumper from GitHub** (ansible.builtin.git) - Conditional
- **Create virtual environment for gMSADumper** (ansible.builtin.command) - Conditional
- **Install gMSADumper dependencies in venv** (ansible.builtin.pip) - Conditional
- **Create wrapper script for gMSADumper** (ansible.builtin.copy) - Conditional

### impacket_source.yml


- **Install git for cloning impacket** (ansible.builtin.apt) - Conditional
- **Remove conflicting apt impacket packages (Ubuntu only - Kali netexec depends on them)** (ansible.builtin.apt) - Conditional
- **Check if impacket is installed from source** (ansible.builtin.stat)
- **Check if impacket repo already exists** (ansible.builtin.stat)
- **Clone impacket repository from GitHub (initial clone)** (ansible.builtin.git) - Conditional
- **Set impacket venv path** (ansible.builtin.set_fact)
- **Check if impacket venv exists** (ansible.builtin.stat)
- **Check if we need to install or reinstall impacket** (ansible.builtin.set_fact)
- **Create impacket virtual environment** (ansible.builtin.command) - Conditional
- **Install impacket from source** (ansible.builtin.pip) - Conditional
- **Check if impacket is correctly installed in venv** (ansible.builtin.command)
- **Make impacket example scripts executable** (ansible.builtin.shell)
- **Check if \_\_init\_\_.py exists in impacket/examples** (ansible.builtin.stat)
- **Create \_\_init\_\_.py in impacket/examples to make it a proper Python package** (ansible.builtin.copy) - Conditional
- **Create symlinks for impacket scripts (impacket-* style for Kali compatibility)** (ansible.builtin.shell)
- **Verify impacket regsecrets module is available** (ansible.builtin.command)
- **Report impacket installation status** (ansible.builtin.debug)

### linux.yml


- **Set DEBIAN_FRONTEND to noninteractive** (ansible.builtin.lineinfile) - Conditional
- **Update apt cache** (ansible.builtin.apt) - Conditional
- **Install Kali-specific credential access tools** (ansible.builtin.apt) - Conditional
- **Install Ubuntu-compatible credential access tools** (ansible.builtin.apt) - Conditional
- **Set pip break-system-packages args (when supported)** (ansible.builtin.set_fact) - Conditional
- **Install Impacket from source** (ansible.builtin.include_tasks) - Conditional
- **Install lsassy via pipx** (ansible.builtin.include_tasks) - Conditional
- **Install sprayhound via apt (Kali)** (ansible.builtin.apt) - Conditional
- **Install sprayhound via pip** (ansible.builtin.pip) - Conditional
- **Find sprayhound binary location** (ansible.builtin.command) - Conditional
- **Create symlink for sprayhound in /usr/bin** (ansible.builtin.file) - Conditional
- **Clone targetedKerberoast from GitHub** (ansible.builtin.git) - Conditional
- **Create virtual environment for targetedKerberoast** (ansible.builtin.command) - Conditional
- **Install targetedKerberoast dependencies in venv** (ansible.builtin.pip) - Conditional
- **Create wrapper script for targetedKerberoast** (ansible.builtin.copy) - Conditional
- **Create .py symlink for targetedKerberoast** (ansible.builtin.file) - Conditional
- **Install gMSADumper** (ansible.builtin.include_tasks) - Conditional

### lsassy_pipx.yml


- **Check if lsassy is already installed via pipx** (ansible.builtin.command)
- **Install lsassy via pipx** (ansible.builtin.command) - Conditional
- **Create symlink for lsassy in /usr/local/bin** (ansible.builtin.file)

### main.yml


- **Include Linux tasks** (ansible.builtin.include_tasks) - Conditional

## Example Playbook

```yaml
- hosts: servers
  roles:
    - credential_access_tools
```

## Author Information

- **Author**: Dreadnode
- **Company**: dreadnode
- **License**: MIT

## Platforms


- Ubuntu: all
- Debian: all
- Kali: all
<!-- DOCSIBLE END -->
