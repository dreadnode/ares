<!-- DOCSIBLE START -->
# lateral_movement_tools

## Description

Install and configure lateral movement and credential extraction tools for Ares agents

## Requirements

- Ansible >= 2.18.4

## Dependencies


- dreadnode.nimbus_range.base

## Role Variables

### Default Variables (main.yml)

| Variable | Type | Default | Description |
| -------- | ---- | ------- | ----------- |
| `lateral_movement_tools_kali_packages` | list | <code>&#91;&#93;</code> | No description |
| `lateral_movement_tools_kali_packages.0` | str | <code>evil-winrm</code> | No description |
| `lateral_movement_tools_kali_packages.1` | str | <code>ruby</code> | No description |
| `lateral_movement_tools_kali_packages.2` | str | <code>freerdp3-x11</code> | No description |
| `lateral_movement_tools_kali_packages.3` | str | <code>smbclient</code> | No description |
| `lateral_movement_tools_kali_packages.4` | str | <code>sshpass</code> | No description |
| `lateral_movement_tools_kali_packages.5` | str | <code>proxychains4</code> | No description |
| `lateral_movement_tools_ubuntu_packages` | list | <code>&#91;&#93;</code> | No description |
| `lateral_movement_tools_ubuntu_packages.0` | str | <code>git</code> | No description |
| `lateral_movement_tools_ubuntu_packages.1` | str | <code>python3</code> | No description |
| `lateral_movement_tools_ubuntu_packages.2` | str | <code>python3-pip</code> | No description |
| `lateral_movement_tools_ubuntu_packages.3` | str | <code>python3-dev</code> | No description |
| `lateral_movement_tools_ubuntu_packages.4` | str | <code>python3-venv</code> | No description |
| `lateral_movement_tools_ubuntu_packages.5` | str | <code>build-essential</code> | No description |
| `lateral_movement_tools_ubuntu_packages.6` | str | <code>ruby</code> | No description |
| `lateral_movement_tools_ubuntu_packages.7` | str | <code>ruby-dev</code> | No description |
| `lateral_movement_tools_ubuntu_packages.8` | str | <code>rubygems</code> | No description |
| `lateral_movement_tools_ubuntu_packages.9` | str | <code>libffi-dev</code> | No description |
| `lateral_movement_tools_ubuntu_packages.10` | str | <code>clang</code> | No description |
| `lateral_movement_tools_ubuntu_packages.11` | str | <code>freerdp2-x11</code> | No description |
| `lateral_movement_tools_ubuntu_packages.12` | str | <code>smbclient</code> | No description |
| `lateral_movement_tools_ubuntu_packages.13` | str | <code>sshpass</code> | No description |
| `lateral_movement_tools_ubuntu_packages.14` | str | <code>proxychains4</code> | No description |
| `lateral_movement_tools_install_evil_winrm` | bool | <code>True</code> | No description |
| `lateral_movement_tools_evil_winrm_gem` | str | <code>evil-winrm</code> | No description |
| `lateral_movement_tools_install_xfreerdp` | bool | <code>True</code> | No description |
| `lateral_movement_tools_install_sshpass` | bool | <code>True</code> | No description |
| `lateral_movement_tools_install_proxychains` | bool | <code>True</code> | No description |
| `lateral_movement_tools_install_pth_toolkit` | bool | <code>True</code> | No description |
| `lateral_movement_tools_pth_toolkit_package` | str | <code>passing-the-hash</code> | No description |
| `lateral_movement_tools_install_impacket` | bool | <code>True</code> | No description |
| `lateral_movement_tools_impacket_from_source` | bool | <code>True</code> | No description |
| `lateral_movement_tools_impacket_repo` | str | <code>https://github.com/fortra/impacket.git</code> | No description |
| `lateral_movement_tools_impacket_version` | str | <code>impacket_0_13_0</code> | No description |
| `lateral_movement_tools_impacket_install_dir` | str | <code>/opt/impacket</code> | No description |
| `lateral_movement_tools_update_cache` | bool | <code>True</code> | No description |
| `lateral_movement_tools_binaries` | dict | <code>{}</code> | No description |
| `lateral_movement_tools_binaries.evil-winrm` | str | <code>/usr/local/bin/evil-winrm</code> | No description |
| `lateral_movement_tools_binaries.xfreerdp` | str | <code>/usr/bin/xfreerdp</code> | No description |
| `lateral_movement_tools_binaries.sshpass` | str | <code>/usr/bin/sshpass</code> | No description |
| `lateral_movement_tools_binaries.proxychains` | str | <code>/usr/bin/proxychains4</code> | No description |
| `lateral_movement_tools_binaries.impacket_psexec` | str | <code>/usr/local/bin/impacket-psexec</code> | No description |
| `lateral_movement_tools_binaries.impacket_wmiexec` | str | <code>/usr/local/bin/impacket-wmiexec</code> | No description |
| `lateral_movement_tools_binaries.impacket_smbexec` | str | <code>/usr/local/bin/impacket-smbexec</code> | No description |
| `lateral_movement_tools_binaries.impacket_secretsdump` | str | <code>/usr/local/bin/impacket-secretsdump</code> | No description |
| `lateral_movement_tools_binaries.smbclient` | str | <code>/usr/bin/smbclient</code> | No description |

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


- **Wait for apt locks to be released** (ansible.builtin.shell) - Conditional
- **Set DEBIAN_FRONTEND to noninteractive** (ansible.builtin.lineinfile) - Conditional
- **Update apt cache** (ansible.builtin.apt) - Conditional
- **Install Kali-specific lateral movement tools (includes evil-winrm from apt)** (ansible.builtin.apt) - Conditional
- **Install Ubuntu-compatible dependencies** (ansible.builtin.apt) - Conditional
- **Check xfreerdp and xfreerdp3 availability** (ansible.builtin.stat) - Conditional
- **Create xfreerdp symlink to xfreerdp3 when needed** (ansible.builtin.file) - Conditional
- **Verify gcc is available for native gem extensions** (ansible.builtin.command) - Conditional
- **Verify libffi-dev is installed** (ansible.builtin.command) - Conditional
- **Verify ruby-dev is installed** (ansible.builtin.command) - Conditional
- **Check ffi.h header file exists** (ansible.builtin.stat) - Conditional
- **Check alternate ffi.h location** (ansible.builtin.shell) - Conditional
- **Check pkg-config for libffi** (ansible.builtin.command) - Conditional
- **Display build environment for debugging** (ansible.builtin.debug) - Conditional
- **Force reinstall gcc packages to restore missing libgcc files** (ansible.builtin.shell) - Conditional
- **Test gcc can compile a simple program** (ansible.builtin.shell) - Conditional
- **Create symlink for ffi.h in standard include path** (ansible.builtin.file) - Conditional
- **Create symlink for ffitarget.h in standard include path** (ansible.builtin.file) - Conditional
- **Install rubyzip gem for evil-winrm dependency** (community.general.gem) - Conditional
- **Install evil-winrm gem (Ubuntu only, Kali uses apt)** (community.general.gem) - Conditional
- **Install pth-toolkit (Kali only - may not be available in all repos)** (ansible.builtin.apt) - Conditional
- **Warn if pth-toolkit installation failed** (ansible.builtin.debug) - Conditional
- **Install Impacket from source for lateral movement tools** (ansible.builtin.include_tasks) - Conditional

### main.yml


- **Include Linux tasks** (ansible.builtin.include_tasks) - Conditional

## Example Playbook

```yaml
- hosts: servers
  roles:
    - lateral_movement_tools
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
