<!-- DOCSIBLE START -->
# acl_tools

## Description

Install and configure Active Directory ACL exploitation tools for Ares agents

## Requirements

- Ansible >= 2.18.4

## Dependencies


- dreadnode.nimbus_range.base

## Role Variables

### Default Variables (main.yml)

| Variable | Type | Default | Description |
| -------- | ---- | ------- | ----------- |
| `acl_tools_ubuntu_packages` | list | <code>&#91;&#93;</code> | No description |
| `acl_tools_ubuntu_packages.0` | str | <code>git</code> | No description |
| `acl_tools_ubuntu_packages.1` | str | <code>python3</code> | No description |
| `acl_tools_ubuntu_packages.2` | str | <code>python3-pip</code> | No description |
| `acl_tools_ubuntu_packages.3` | str | <code>python3-dev</code> | No description |
| `acl_tools_ubuntu_packages.4` | str | <code>python3-venv</code> | No description |
| `acl_tools_ubuntu_packages.5` | str | <code>build-essential</code> | No description |
| `acl_tools_ubuntu_packages.6` | str | <code>smbclient</code> | No description |
| `acl_tools_ubuntu_packages.7` | str | <code>samba-common-bin</code> | No description |
| `acl_tools_install_bloodyad` | bool | <code>True</code> | No description |
| `acl_tools_bloodyad_package` | str | <code>bloodyAD</code> | No description |
| `acl_tools_bloodyad_apt_package` | str | <code>bloodyad</code> | No description |
| `acl_tools_install_pywhisker` | bool | <code>True</code> | No description |
| `acl_tools_pywhisker_package` | str | <code>pywhisker</code> | No description |
| `acl_tools_install_dacledit` | bool | <code>True</code> | No description |
| `acl_tools_impacket_from_source` | bool | <code>True</code> | No description |
| `acl_tools_impacket_repo` | str | <code>https://github.com/fortra/impacket.git</code> | No description |
| `acl_tools_impacket_version` | str | <code>impacket_0_13_0</code> | No description |
| `acl_tools_impacket_install_dir` | str | <code>/opt/impacket</code> | No description |
| `acl_tools_install_targetedkerberoast` | bool | <code>True</code> | No description |
| `acl_tools_targetedkerberoast_repo` | str | <code>https://github.com/ShutdownRepo/targetedKerberoast.git</code> | No description |
| `acl_tools_targetedkerberoast_install_dir` | str | <code>/opt/targetedKerberoast</code> | No description |
| `acl_tools_targetedkerberoast_version` | str | <code>main</code> | No description |
| `acl_tools_update_cache` | bool | <code>True</code> | No description |
| `acl_tools_binaries` | dict | <code>{}</code> | No description |
| `acl_tools_binaries.bloodyad` | str | <code>/usr/local/bin/bloodyAD</code> | No description |
| `acl_tools_binaries.pywhisker` | str | <code>/usr/local/bin/pywhisker</code> | No description |
| `acl_tools_binaries.dacledit` | str | <code>/usr/local/bin/impacket-dacledit</code> | No description |
| `acl_tools_binaries.targetedkerberoast` | str | <code>/usr/local/bin/targetedKerberoast</code> | No description |
| `acl_tools_binaries.rpcclient` | str | <code>/usr/bin/rpcclient</code> | No description |

## Tasks

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
- **Install Ubuntu-compatible dependencies** (ansible.builtin.apt) - Conditional
- **Check rpcclient availability** (ansible.builtin.command) - Conditional
- **Install smbclient when rpcclient is missing** (ansible.builtin.apt) - Conditional
- **Recheck rpcclient availability after smbclient install** (ansible.builtin.command) - Conditional
- **Check if samba-common-bin package is available** (ansible.builtin.command) - Conditional
- **Install samba-common-bin when rpcclient is still missing** (ansible.builtin.apt) - Conditional
- **Install Impacket from source for dacledit** (ansible.builtin.include_tasks) - Conditional
- **Install bloodyAD via apt (Kali)** (ansible.builtin.apt) - Conditional
- **Check if bloodyAD is already installed** (ansible.builtin.command) - Conditional
- **Install bloodyAD via pip** (ansible.builtin.pip) - Conditional
- **Check if pywhisker is already installed** (ansible.builtin.command) - Conditional
- **Install pywhisker via pip** (ansible.builtin.pip) - Conditional
- **Clone targetedKerberoast from GitHub** (ansible.builtin.git) - Conditional
- **Create virtual environment for targetedKerberoast** (ansible.builtin.command) - Conditional
- **Install targetedKerberoast dependencies in venv** (ansible.builtin.pip) - Conditional
- **Create wrapper script for targetedKerberoast** (ansible.builtin.copy) - Conditional
- **Create .py symlink for targetedKerberoast** (ansible.builtin.file) - Conditional

### main.yml


- **Include Linux tasks** (ansible.builtin.include_tasks) - Conditional

## Example Playbook

```yaml
- hosts: servers
  roles:
    - acl_tools
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
