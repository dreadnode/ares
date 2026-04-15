<!-- DOCSIBLE START -->
# privesc_tools

## Description

Install and configure privilege escalation tools for Ares agents

## Requirements

- Ansible >= 2.18.4

## Dependencies


- dreadnode.nimbus_range.base

## Role Variables

### Default Variables (main.yml)

| Variable | Type | Default | Description |
| -------- | ---- | ------- | ----------- |
| `privesc_tools_kali_packages` | list | <code>&#91;&#93;</code> | No description |
| `privesc_tools_kali_packages.0` | str | <code>git</code> | No description |
| `privesc_tools_kali_packages.1` | str | <code>python3-dev</code> | No description |
| `privesc_tools_kali_packages.2` | str | <code>build-essential</code> | No description |
| `privesc_tools_ubuntu_packages` | list | <code>&#91;&#93;</code> | No description |
| `privesc_tools_ubuntu_packages.0` | str | <code>git</code> | No description |
| `privesc_tools_ubuntu_packages.1` | str | <code>python3</code> | No description |
| `privesc_tools_ubuntu_packages.2` | str | <code>python3-pip</code> | No description |
| `privesc_tools_ubuntu_packages.3` | str | <code>python3-dev</code> | No description |
| `privesc_tools_ubuntu_packages.4` | str | <code>python3-venv</code> | No description |
| `privesc_tools_ubuntu_packages.5` | str | <code>build-essential</code> | No description |
| `privesc_tools_install_printspoofer` | bool | <code>True</code> | No description |
| `privesc_tools_printspoofer_url` | str | <code>https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe</code> | No description |
| `privesc_tools_printspoofer_install_dir` | str | <code>/opt/privesc/PrintSpoofer</code> | No description |
| `privesc_tools_install_sweetpotato` | bool | <code>True</code> | No description |
| `privesc_tools_sweetpotato_repo` | str | <code>https://github.com/CCob/SweetPotato.git</code> | No description |
| `privesc_tools_sweetpotato_install_dir` | str | <code>/opt/privesc/SweetPotato</code> | No description |
| `privesc_tools_sweetpotato_version` | str | <code>master</code> | No description |
| `privesc_tools_install_godpotato` | bool | <code>True</code> | No description |
| `privesc_tools_godpotato_url` | str | <code>https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe</code> | No description |
| `privesc_tools_godpotato_install_dir` | str | <code>/opt/privesc/GodPotato</code> | No description |
| `privesc_tools_install_krbrelayup` | bool | <code>True</code> | No description |
| `privesc_tools_krbrelayup_repo` | str | <code>https://github.com/Dec0ne/KrbRelayUp.git</code> | No description |
| `privesc_tools_krbrelayup_install_dir` | str | <code>/opt/privesc/KrbRelayUp</code> | No description |
| `privesc_tools_krbrelayup_version` | str | <code>main</code> | No description |
| `privesc_tools_install_sharpgpoabuse` | bool | <code>True</code> | No description |
| `privesc_tools_sharpgpoabuse_repo` | str | <code>https://github.com/byronkg/SharpGPOAbuse.git</code> | No description |
| `privesc_tools_sharpgpoabuse_install_dir` | str | <code>/opt/privesc/SharpGPOAbuse</code> | No description |
| `privesc_tools_sharpgpoabuse_version` | str | <code>main</code> | No description |
| `privesc_tools_install_seatbelt` | bool | <code>True</code> | No description |
| `privesc_tools_seatbelt_url` | str | <code>https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe</code> | No description |
| `privesc_tools_seatbelt_install_dir` | str | <code>/opt/privesc/Seatbelt</code> | No description |
| `privesc_tools_install_sharpup` | bool | <code>True</code> | No description |
| `privesc_tools_sharpup_url` | str | <code>https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpUp.exe</code> | No description |
| `privesc_tools_sharpup_install_dir` | str | <code>/opt/privesc/SharpUp</code> | No description |
| `privesc_tools_install_powerup` | bool | <code>True</code> | No description |
| `privesc_tools_powerup_url` | str | <code>https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1</code> | No description |
| `privesc_tools_powerup_install_dir` | str | <code>/opt/privesc/PowerUp</code> | No description |
| `privesc_tools_install_powerupsql` | bool | <code>True</code> | No description |
| `privesc_tools_powerupsql_url` | str | <code>https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1</code> | No description |
| `privesc_tools_powerupsql_install_dir` | str | <code>/opt/privesc/PowerUpSQL</code> | No description |
| `privesc_tools_install_impacket` | bool | <code>True</code> | No description |
| `privesc_tools_impacket_from_source` | bool | <code>True</code> | No description |
| `privesc_tools_impacket_repo` | str | <code>https://github.com/fortra/impacket.git</code> | No description |
| `privesc_tools_impacket_version` | str | <code>impacket_0_13_0</code> | No description |
| `privesc_tools_impacket_install_dir` | str | <code>/opt/impacket</code> | No description |
| `privesc_tools_install_certipy` | bool | <code>True</code> | No description |
| `privesc_tools_certipy_package` | str | <code>certipy-ad</code> | No description |
| `privesc_tools_install_winpeas` | bool | <code>True</code> | No description |
| `privesc_tools_winpeas_url` | str | <code>https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany_ofs.exe</code> | No description |
| `privesc_tools_winpeas_install_dir` | str | <code>/opt/privesc/WinPEAS</code> | No description |
| `privesc_tools_install_linpeas` | bool | <code>True</code> | No description |
| `privesc_tools_linpeas_url` | str | <code>https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh</code> | No description |
| `privesc_tools_linpeas_install_dir` | str | <code>/opt/privesc/LinPEAS</code> | No description |
| `privesc_tools_install_runascs` | bool | <code>True</code> | No description |
| `privesc_tools_runascs_url` | str | <code>https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip</code> | No description |
| `privesc_tools_runascs_install_dir` | str | <code>/opt/privesc/RunasCs</code> | No description |
| `privesc_tools_install_scmuacbypass` | bool | <code>True</code> | No description |
| `privesc_tools_scmuacbypass_repo` | str | <code>https://github.com/rasta-mouse/SCMUACBypass.git</code> | No description |
| `privesc_tools_scmuacbypass_version` | str | <code>main</code> | No description |
| `privesc_tools_scmuacbypass_install_dir` | str | <code>/opt/privesc/SCMUACBypass</code> | No description |
| `privesc_tools_install_nopac` | bool | <code>True</code> | No description |
| `privesc_tools_nopac_repo` | str | <code>https://github.com/Ridter/noPac.git</code> | No description |
| `privesc_tools_nopac_install_dir` | str | <code>/opt/privesc/noPac</code> | No description |
| `privesc_tools_nopac_version` | str | <code>main</code> | No description |
| `privesc_tools_install_printnightmare` | bool | <code>True</code> | No description |
| `privesc_tools_printnightmare_repo` | str | <code>https://github.com/cube0x0/CVE-2021-1675.git</code> | No description |
| `privesc_tools_printnightmare_install_dir` | str | <code>/opt/privesc/PrintNightmare</code> | No description |
| `privesc_tools_printnightmare_version` | str | <code>main</code> | No description |
| `privesc_tools_install_krbrelayx` | bool | <code>True</code> | No description |
| `privesc_tools_krbrelayx_repo` | str | <code>https://github.com/dirkjanm/krbrelayx.git</code> | No description |
| `privesc_tools_krbrelayx_install_dir` | str | <code>/opt/krbrelayx</code> | No description |
| `privesc_tools_krbrelayx_version` | str | <code>master</code> | No description |
| `privesc_tools_install_lsassy` | bool | <code>True</code> | No description |
| `privesc_tools_install_zerologon` | bool | <code>True</code> | No description |
| `privesc_tools_zerologon_repo` | str | <code>https://github.com/dirkjanm/CVE-2020-1472.git</code> | No description |
| `privesc_tools_zerologon_install_dir` | str | <code>/opt/privesc/zerologon</code> | No description |
| `privesc_tools_zerologon_version` | str | <code>master</code> | No description |
| `privesc_tools_install_pygpoabuse` | bool | <code>True</code> | No description |
| `privesc_tools_pygpoabuse_repo` | str | <code>https://github.com/Hackndo/pyGPOAbuse.git</code> | No description |
| `privesc_tools_base_dir` | str | <code>/opt/privesc</code> | No description |
| `privesc_tools_update_cache` | bool | <code>True</code> | No description |
| `privesc_tools_binaries` | dict | <code>{}</code> | No description |
| `privesc_tools_binaries.printspoofer` | str | <code>/opt/privesc/PrintSpoofer/PrintSpoofer64.exe</code> | No description |
| `privesc_tools_binaries.godpotato` | str | <code>/opt/privesc/GodPotato/GodPotato-NET4.exe</code> | No description |
| `privesc_tools_binaries.winpeas` | str | <code>/opt/privesc/WinPEAS/winPEASany_ofs.exe</code> | No description |
| `privesc_tools_binaries.linpeas` | str | <code>/opt/privesc/LinPEAS/linpeas.sh</code> | No description |
| `privesc_tools_binaries.powerup` | str | <code>/opt/privesc/PowerUp/PowerUp.ps1</code> | No description |
| `privesc_tools_binaries.powerupsql` | str | <code>/opt/privesc/PowerUpSQL/PowerUpSQL.ps1</code> | No description |
| `privesc_tools_binaries.nopac` | str | <code>/opt/privesc/noPac/noPac.py</code> | No description |
| `privesc_tools_binaries.printnightmare` | str | <code>/opt/privesc/PrintNightmare/CVE-2021-1675.py</code> | No description |
| `privesc_tools_binaries.zerologon` | str | <code>/usr/local/bin/zerologon</code> | No description |
| `privesc_tools_binaries.pygpoabuse` | str | <code>/usr/local/bin/pygpoabuse</code> | No description |
| `privesc_tools_binaries.certipy` | str | <code>/usr/bin/certipy</code> | No description |
| `privesc_tools_binaries.impacket_getst` | str | <code>/usr/local/bin/impacket-getST</code> | No description |
| `privesc_tools_binaries.impacket_gettgt` | str | <code>/usr/local/bin/impacket-getTGT</code> | No description |
| `privesc_tools_binaries.impacket_rbcd` | str | <code>/usr/local/bin/impacket-rbcd</code> | No description |
| `privesc_tools_binaries.impacket_mssqlclient` | str | <code>/usr/local/bin/impacket-mssqlclient</code> | No description |
| `privesc_tools_binaries.impacket_raisechild` | str | <code>/usr/local/bin/impacket-raiseChild</code> | No description |
| `privesc_tools_binaries.krbrelayx` | str | <code>/usr/local/bin/krbrelayx</code> | No description |
| `privesc_tools_binaries.printerbug` | str | <code>/usr/local/bin/printerbug</code> | No description |

## Tasks

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
- **Create symlinks for impacket scripts (impacket-* style for Kali compatibility)** (ansible.builtin.shell)
- **Verify impacket regsecrets module is available** (ansible.builtin.command)
- **Report impacket installation status** (ansible.builtin.debug)

### linux.yml


- **Wait for apt locks to be released** (ansible.builtin.shell) - Conditional
- **Set DEBIAN_FRONTEND to noninteractive** (ansible.builtin.lineinfile) - Conditional
- **Update apt cache** (ansible.builtin.apt) - Conditional
- **Install Kali-specific privesc dependencies** (ansible.builtin.apt) - Conditional
- **Install Ubuntu-compatible privesc dependencies** (ansible.builtin.apt) - Conditional
- **Install unzip for extracting archives** (ansible.builtin.apt) - Conditional
- **Create base privesc tools directory** (ansible.builtin.file)
- **Install Impacket from source** (ansible.builtin.include_tasks) - Conditional
- **Install Certipy via pipx** (ansible.builtin.include_tasks) - Conditional
- **Install lsassy via pipx** (ansible.builtin.include_tasks) - Conditional
- **Create PrintSpoofer directory** (ansible.builtin.file) - Conditional
- **Download PrintSpoofer** (ansible.builtin.get_url) - Conditional
- **Create GodPotato directory** (ansible.builtin.file) - Conditional
- **Download GodPotato** (ansible.builtin.get_url) - Conditional
- **Clone SweetPotato from GitHub** (ansible.builtin.git) - Conditional
- **Clone KrbRelayUp from GitHub** (ansible.builtin.git) - Conditional
- **Clone SharpGPOAbuse from GitHub** (ansible.builtin.git) - Conditional
- **Create Seatbelt directory** (ansible.builtin.file) - Conditional
- **Download Seatbelt** (ansible.builtin.get_url) - Conditional
- **Create SharpUp directory** (ansible.builtin.file) - Conditional
- **Download SharpUp** (ansible.builtin.get_url) - Conditional
- **Create PowerUp directory** (ansible.builtin.file) - Conditional
- **Download PowerUp.ps1** (ansible.builtin.get_url) - Conditional
- **Create PowerUpSQL directory** (ansible.builtin.file) - Conditional
- **Download PowerUpSQL.ps1** (ansible.builtin.get_url) - Conditional
- **Create WinPEAS directory** (ansible.builtin.file) - Conditional
- **Download WinPEAS** (ansible.builtin.get_url) - Conditional
- **Create LinPEAS directory** (ansible.builtin.file) - Conditional
- **Download LinPEAS** (ansible.builtin.get_url) - Conditional
- **Create RunasCs directory** (ansible.builtin.file) - Conditional
- **Download RunasCs zip** (ansible.builtin.get_url) - Conditional
- **Extract RunasCs** (ansible.builtin.unarchive) - Conditional
- **Clone SCMUACBypass from GitHub** (ansible.builtin.git) - Conditional
- **Clone noPac from GitHub** (ansible.builtin.git) - Conditional
- **Create virtual environment for noPac** (ansible.builtin.command) - Conditional
- **Install noPac dependencies in venv** (ansible.builtin.pip) - Conditional
- **Create wrapper script for noPac** (ansible.builtin.copy) - Conditional
- **Clone PrintNightmare from GitHub** (ansible.builtin.git) - Conditional
- **Make PrintNightmare script executable** (ansible.builtin.file) - Conditional
- **Create symlink for PrintNightmare** (ansible.builtin.file) - Conditional
- **Clone krbrelayx from GitHub** (ansible.builtin.git) - Conditional
- **Configure git to ignore filemode changes in krbrelayx repo** (ansible.builtin.command) - Conditional
- **Create virtual environment for krbrelayx** (ansible.builtin.command) - Conditional
- **Install krbrelayx dependencies in venv** (ansible.builtin.pip) - Conditional
- **Create wrapper scripts for krbrelayx tools** (ansible.builtin.copy) - Conditional
- **Install zerologon (CVE-2020-1472)** (ansible.builtin.include_tasks) - Conditional
- **Install pygpoabuse via pipx** (ansible.builtin.include_tasks) - Conditional

### lsassy_pipx.yml


- **Check if lsassy is already installed via pipx** (ansible.builtin.command)
- **Install lsassy via pipx** (ansible.builtin.command) - Conditional
- **Create symlink for lsassy in /usr/local/bin** (ansible.builtin.file)

### main.yml


- **Include Linux tasks** (ansible.builtin.include_tasks) - Conditional

### pygpoabuse_pipx.yml


- **Check if pygpoabuse is already installed via pipx** (ansible.builtin.command)
- **Install pygpoabuse via pipx** (ansible.builtin.command) - Conditional
- **Create symlink for pygpoabuse.py in /usr/local/bin** (ansible.builtin.file)
- **Create pygpoabuse symlink (without .py extension)** (ansible.builtin.file)

### zerologon.yml


- **Clone zerologon from GitHub** (ansible.builtin.git) - Conditional
- **Create virtual environment for zerologon** (ansible.builtin.command) - Conditional
- **Install zerologon dependencies in venv** (ansible.builtin.pip) - Conditional
- **Create wrapper script for zerologon (cve-2020-1472-exploit)** (ansible.builtin.copy) - Conditional
- **Create wrapper script for zerologon restore password** (ansible.builtin.copy) - Conditional

## Example Playbook

```yaml
- hosts: servers
  roles:
    - privesc_tools
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
