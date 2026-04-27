<!-- DOCSIBLE START -->
<!-- DOCSIBLE START -->
# recon_tools

## Description

Install and configure network reconnaissance tools for Ares agents

## Requirements

- Ansible >= 2.18.4

## Dependencies


- dreadnode.nimbus_range.base

## Role Variables

### Default Variables (main.yml)

| Variable | Type | Default | Description |
| -------- | ---- | ------- | ----------- |
| `recon_tools_kali_packages` | list | <code>&#91;&#93;</code> | No description |
| `recon_tools_kali_packages.0` | str | <code>nmap</code> | No description |
| `recon_tools_kali_packages.1` | str | <code>ldap-utils</code> | No description |
| `recon_tools_kali_packages.2` | str | <code>enum4linux</code> | No description |
| `recon_tools_kali_packages.3` | str | <code>enum4linux-ng</code> | No description |
| `recon_tools_kali_packages.4` | str | <code>dnsutils</code> | No description |
| `recon_tools_kali_packages.5` | str | <code>whois</code> | No description |
| `recon_tools_kali_packages.6` | str | <code>samba-common-bin</code> | No description |
| `recon_tools_kali_packages.7` | str | <code>smbclient</code> | No description |
| `recon_tools_ubuntu_packages` | list | <code>&#91;&#93;</code> | No description |
| `recon_tools_ubuntu_packages.0` | str | <code>nmap</code> | No description |
| `recon_tools_ubuntu_packages.1` | str | <code>ldap-utils</code> | No description |
| `recon_tools_ubuntu_packages.2` | str | <code>enum4linux</code> | No description |
| `recon_tools_ubuntu_packages.3` | str | <code>dnsutils</code> | No description |
| `recon_tools_ubuntu_packages.4` | str | <code>whois</code> | No description |
| `recon_tools_ubuntu_packages.5` | str | <code>samba-common-bin</code> | No description |
| `recon_tools_ubuntu_packages.6` | str | <code>smbclient</code> | No description |
| `recon_tools_install_enum4linuxng` | bool | <code>True</code> | No description |
| `recon_tools_enum4linuxng_install_source` | str | <code>git+https://github.com/cddmp/enum4linux-ng.git</code> | No description |
| `recon_tools_enum4linuxng_use_pipx` | bool | <code>True</code> | No description |
| `recon_tools_enum4linux_repo` | str | <code>https://github.com/CiscoCXSecurity/enum4linux.git</code> | No description |
| `recon_tools_enum4linux_version` | str | <code>master</code> | No description |
| `recon_tools_enum4linux_install_dir` | str | <code>/opt/enum4linux</code> | No description |
| `recon_tools_impacket_from_source` | bool | <code>True</code> | No description |
| `recon_tools_impacket_repo` | str | <code>https://github.com/fortra/impacket.git</code> | No description |
| `recon_tools_impacket_version` | str | <code>impacket_0_13_0</code> | No description |
| `recon_tools_impacket_install_dir` | str | <code>/opt/impacket</code> | No description |
| `recon_tools_install_netexec` | bool | <code>True</code> | No description |
| `recon_tools_netexec_repo` | str | <code>https://github.com/Pennyw0rth/NetExec.git</code> | No description |
| `recon_tools_netexec_version` | str | <code>v1.4.0</code> | No description |
| `recon_tools_netexec_package` | str | <code>netexec</code> | No description |
| `recon_tools_netexec_use_pipx` | bool | <code>True</code> | No description |
| `recon_tools_install_bloodhound` | bool | <code>True</code> | No description |
| `recon_tools_bloodhound_package` | str | <code>bloodhound</code> | No description |
| `recon_tools_install_certipy` | bool | <code>True</code> | No description |
| `recon_tools_certipy_package` | str | <code>certipy-ad</code> | No description |
| `recon_tools_install_adidnsdump` | bool | <code>True</code> | No description |
| `recon_tools_adidnsdump_package` | str | <code>adidnsdump</code> | No description |
| `recon_tools_adidnsdump_install_source` | str | <code>git+https://github.com/dirkjanm/adidnsdump#egg=adidnsdump</code> | No description |
| `recon_tools_adidnsdump_use_pipx` | bool | <code>True</code> | No description |
| `recon_tools_update_cache` | bool | <code>True</code> | No description |
| `recon_tools_binary_search_paths` | list | <code>&#91;&#93;</code> | No description |
| `recon_tools_binary_search_paths.0` | str | <code>/usr/local/bin</code> | No description |
| `recon_tools_binary_search_paths.1` | str | <code>/usr/bin</code> | No description |
| `recon_tools_binary_search_paths.2` | str | <code>/root/.local/bin</code> | No description |
| `recon_tools_binary_search_paths.3` | str | <code>/opt/impacket/examples</code> | No description |

## Tasks

### bloodhound_pipx.yml


- **Check if bloodhound-python is already installed via pipx** (ansible.builtin.command)
- **Install bloodhound-python via pipx** (ansible.builtin.command) - Conditional
- **Create symlink for bloodhound-python in /usr/bin** (ansible.builtin.file)

### certipy_pipx.yml


- **Check if certipy-ad is already installed via pipx** (ansible.builtin.command)
- **Install certipy-ad via pipx** (ansible.builtin.command) - Conditional
- **Create symlink for certipy in /usr/bin** (ansible.builtin.file)

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
- **Check system impacket version (Kali)** (ansible.builtin.command) - Conditional
- **Install source impacket into system Python (Kali apt netexec needs it system-wide)** (ansible.builtin.pip) - Conditional
- **Create symlinks for impacket scripts (impacket-* style for Kali compatibility)** (ansible.builtin.shell)
- **Verify impacket regsecrets module is available** (ansible.builtin.command)
- **Report impacket installation status** (ansible.builtin.debug)
- **Fail if regsecrets module is not available** (ansible.builtin.fail) - Conditional

### linux.yml


- **Set DEBIAN_FRONTEND to noninteractive** (ansible.builtin.lineinfile) - Conditional
- **Update apt cache** (ansible.builtin.apt) - Conditional
- **Install Kali-specific network tools** (ansible.builtin.apt) - Conditional
- **Install NetExec via apt (Kali)** (ansible.builtin.apt) - Conditional
- **Install Ubuntu-compatible network tools** (ansible.builtin.apt) - Conditional
- **Check if enum4linux package is available (non-Kali)** (ansible.builtin.command) - Conditional
- **Install enum4linux via apt when available (non-Kali)** (ansible.builtin.apt) - Conditional
- **Clone enum4linux from GitHub when apt is unavailable (non-Kali)** (ansible.builtin.git) - Conditional
- **Ensure enum4linux script is executable (non-Kali, GitHub fallback)** (ansible.builtin.file) - Conditional
- **Create enum4linux symlink in /usr/local/bin (non-Kali, GitHub fallback)** (ansible.builtin.file) - Conditional
- **Install enum4linux-ng via pipx (non-Kali)** (block) - Conditional
- **Check if pipx is available** (ansible.builtin.command)
- **Fail if pipx is not available** (ansible.builtin.fail) - Conditional
- **Check if enum4linux-ng is already installed via pipx** (ansible.builtin.command)
- **Install enum4linux-ng via pipx** (ansible.builtin.command) - Conditional
- **Find enum4linux-ng binary location** (ansible.builtin.command) - Conditional
- **Create symlink for enum4linux-ng in /usr/bin** (ansible.builtin.file) - Conditional
- **Set pip break-system-packages args (when supported)** (ansible.builtin.set_fact) - Conditional
- **Install impacket from source (required for NetExec compatibility)** (ansible.builtin.include_tasks) - Conditional
- **Install NetExec via pipx from GitHub** (ansible.builtin.include_tasks) - Conditional
- **Install BloodHound Python via pipx** (ansible.builtin.include_tasks) - Conditional
- **Install Certipy via pipx** (ansible.builtin.include_tasks) - Conditional
- **Install adidnsdump via pipx** (block) - Conditional
- **Check if pipx is available** (ansible.builtin.command)
- **Fail if pipx is not available** (ansible.builtin.fail) - Conditional
- **Check if adidnsdump is already installed via pipx** (ansible.builtin.command)
- **Install adidnsdump via pipx** (ansible.builtin.command) - Conditional
- **Find adidnsdump binary location** (ansible.builtin.command) - Conditional
- **Create symlink for adidnsdump in /usr/bin** (ansible.builtin.file) - Conditional

### main.yml


- **Include Linux tasks** (ansible.builtin.include_tasks) - Conditional

### netexec_pip.yml


- **Check pip version** (ansible.builtin.command)
- **Set fact for pip supports break-system-packages** (ansible.builtin.set_fact)
- **Install netexec from pip** (ansible.builtin.pip)
- **Warn if netexec installation failed** (ansible.builtin.debug) - Conditional

### netexec_pipx.yml


- **Check if Rust is available** (ansible.builtin.command)
- **Warn if Rust is not available** (ansible.builtin.debug) - Conditional
- **Check if pipx is available** (ansible.builtin.command)
- **Reinstall pipx if not available (may have been broken by package removal)** (ansible.builtin.apt) - Conditional
- **Verify pipx is now available** (ansible.builtin.command) - Conditional
- **Fail if pipx is still not available** (ansible.builtin.fail) - Conditional
- **Check if NetExec is already installed via pipx** (ansible.builtin.command)
- **Install NetExec via pipx from GitHub** (ansible.builtin.command) - Conditional
- **Upgrade NetExec if already installed** (ansible.builtin.command) - Conditional
- **Report NetExec installation result** (ansible.builtin.debug)
- **Discover pipx venvs directory** (ansible.builtin.shell) - Conditional
- **Inject source impacket into NetExec pipx venv** (ansible.builtin.command) - Conditional
- **Verify regsecrets is importable from NetExec pipx venv** (ansible.builtin.command) - Conditional
- **Install impacket from source into NetExec venv (fallback for pipx inject)** (ansible.builtin.shell) - Conditional
- **Re-verify regsecrets after examples copy** (ansible.builtin.command) - Conditional
- **Fail if regsecrets not available in NetExec venv** (ansible.builtin.fail) - Conditional
- **Find nxc binary location** (ansible.builtin.shell)
- **Create symlink for nxc in /usr/local/bin** (ansible.builtin.file) - Conditional
- **Find netexec binary location** (ansible.builtin.shell)
- **Create symlink for netexec in /usr/local/bin** (ansible.builtin.file) - Conditional
- **Find nxcdb binary location** (ansible.builtin.shell)
- **Create symlink for nxcdb in /usr/local/bin** (ansible.builtin.file) - Conditional

## Example Playbook

```yaml
- hosts: servers
  roles:
    - recon_tools
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
<!-- DOCSIBLE END -->
