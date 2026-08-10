<!-- DOCSIBLE START -->
# base

## Description

Base requirements for Ares AI agents

## Requirements

- Ansible >= 2.18.4

## Role Variables

### Default Variables (main.yml)

| Variable | Type | Default | Description |
| -------- | ---- | ------- | ----------- |
| `base_python_version` | str | <code>3.13.7</code> | No description |
| `base_python_packages` | list | <code>&#91;&#93;</code> | No description |
| `base_python_packages.0` | str | <code>python3</code> | No description |
| `base_python_packages.1` | str | <code>python3-pip</code> | No description |
| `base_python_packages.2` | str | <code>python3-dev</code> | No description |
| `base_python_packages_ubuntu` | list | <code>&#91;&#93;</code> | No description |
| `base_python_packages_ubuntu.0` | str | <code>python3-venv</code> | No description |
| `base_install_uv` | bool | <code>True</code> | No description |
| `base_uv_version` | str | <code>latest</code> | No description |
| `base_uv_install_script` | str | <code>https://astral.sh/uv/install.sh</code> | No description |
| `base_install_awscli` | bool | <code>True</code> | No description |
| `base_install_rust` | bool | <code>True</code> | No description |
| `base_rust_install_script` | str | <code>https://sh.rustup.rs</code> | No description |
| `base_install_pipx` | bool | <code>True</code> | No description |
| `base_pip_packages` | list | <code>&#91;&#93;</code> | No description |
| `base_pip_packages.0` | str | <code>python-dotenv</code> | No description |
| `base_pip_packages.1` | str | <code>rigging>=3.0</code> | No description |
| `base_pip_packages.2` | str | <code>pydantic</code> | No description |
| `base_pip_packages.3` | str | <code>aiohttp>=3.13.4</code> | No description |
| `base_pip_packages.4` | str | <code>cryptography>=44.0.1</code> | No description |
| `base_pip_packages.5` | str | <code>requests>=2.33.0</code> | No description |
| `base_pip_externally_managed` | bool | <code>False</code> | No description |
| `base_pip_break_required` | bool | <code>False</code> | No description |
| `base_system_packages` | list | <code>&#91;&#93;</code> | No description |
| `base_system_packages.0` | str | <code>curl</code> | No description |
| `base_system_packages.1` | str | <code>wget</code> | No description |
| `base_system_packages.2` | str | <code>git</code> | No description |
| `base_system_packages.3` | str | <code>build-essential</code> | No description |
| `base_system_packages.4` | str | <code>cargo</code> | No description |
| `base_system_packages.5` | str | <code>libffi-dev</code> | No description |
| `base_system_packages.6` | str | <code>libssl-dev</code> | No description |
| `base_system_packages.7` | str | <code>netcat-traditional</code> | No description |
| `base_system_packages.8` | str | <code>procps</code> | No description |
| `base_system_packages.9` | str | <code>strace</code> | No description |
| `base_system_packages.10` | str | <code>lsof</code> | No description |
| `base_system_packages.11` | str | <code>tcpdump</code> | No description |
| `base_system_packages.12` | str | <code>net-tools</code> | No description |
| `base_system_packages.13` | str | <code>iproute2</code> | No description |
| `base_system_packages.14` | str | <code>telnet</code> | No description |
| `base_system_packages.15` | str | <code>vim</code> | No description |
| `base_system_packages.16` | str | <code>jq</code> | No description |
| `base_system_packages.17` | str | <code>htop</code> | No description |
| `base_system_packages.18` | str | <code>tmux</code> | No description |
| `base_system_packages.19` | str | <code>acl</code> | No description |
| `base_system_packages_ubuntu` | list | <code>&#91;&#93;</code> | No description |
| `base_system_packages_ubuntu.0` | str | <code>dnsutils</code> | No description |
| `base_system_packages_kali` | list | <code>&#91;&#93;</code> | No description |
| `base_system_packages_kali.0` | str | <code>bind9-dnsutils</code> | No description |
| `base_workspace_dir` | str | <code>/opt/ares</code> | No description |
| `base_create_workspace` | bool | <code>True</code> | No description |
| `base_workspace_owner` | str | <code>root</code> | No description |
| `base_workspace_group` | str | <code>root</code> | No description |
| `base_workspace_mode` | str | <code>0755</code> | No description |
| `base_pip_break_system_packages` | bool | <code>True</code> | No description |
| `base_pip_executable` | str | <code>pip3</code> | No description |
| `base_configure_swap` | bool | <code>False</code> | No description |
| `base_swap_file` | str | <code>/swapfile</code> | No description |
| `base_swap_size_mb` | int | <code>4096</code> | No description |
| `base_oom_tuning` | bool | <code>False</code> | No description |
| `base_vm_swappiness` | int | <code>10</code> | No description |
| `base_vm_oom_kill_allocating_task` | int | <code>1</code> | No description |

## Tasks

### install_awscli.yml


- **Check if AWS CLI is already installed** (ansible.builtin.command)
- **Install AWS CLI v2** (block) - Conditional
- **Download AWS CLI v2 installer** (ansible.builtin.get_url)
- **Install unzip** (ansible.builtin.apt)
- **Unzip AWS CLI installer** (ansible.builtin.unarchive)
- **Run AWS CLI installer** (ansible.builtin.command)
- **Clean up AWS CLI installer** (ansible.builtin.file)
- **Verify AWS CLI installation** (ansible.builtin.command) - Conditional
- **Display AWS CLI version** (ansible.builtin.debug) - Conditional

### install_pipx.yml


- **Install pipx via apt (Debian/Ubuntu)** (block) - Conditional
- **Refresh apt cache before pipx install** (ansible.builtin.apt)
- **Install pipx via apt** (ansible.builtin.apt)
- **Check pipx version after apt install** (ansible.builtin.command)
- **Check whether pip supports --break-system-packages** (ansible.builtin.command) - Conditional
- **Upgrade pipx to a version supporting --global (>= 1.5.0)** (ansible.builtin.pip) - Conditional
- **Add pipx bin to system PATH via profile.d** (ansible.builtin.copy)
- **Verify pipx installation** (ansible.builtin.command)
- **Display pipx version** (ansible.builtin.debug)

### install_rust.yml


- **Check if Rust is already installed** (ansible.builtin.command)
- **Check if Cargo is already installed** (ansible.builtin.command)
- **Install Rust via rustup (non-interactive)** (ansible.builtin.shell) - Conditional
- **Add Rust to system PATH via profile.d** (ansible.builtin.copy)
- **Check root shell profiles for rustup env sourcing** (ansible.builtin.stat)
- **Guard rustup env sourcing to avoid missing file errors** (ansible.builtin.replace)
- **Verify Rust installation** (ansible.builtin.command)
- **Display Rust version** (ansible.builtin.debug) - Conditional

### install_uv.yml


- **Check if uv is already installed** (ansible.builtin.command)
- **Download uv installer** (ansible.builtin.get_url) - Conditional
- **Install uv** (ansible.builtin.command) - Conditional
- **Clean up uv installer** (ansible.builtin.file) - Conditional
- **Verify uv installation** (ansible.builtin.command)

### linux.yml


- **Check if sudoers.d is present (sudo installed)** (ansible.builtin.stat) - Conditional
- **Ensure sudo secure_path includes /usr/local** (ansible.builtin.copy) - Conditional
- **Set DEBIAN_FRONTEND to noninteractive** (ansible.builtin.lineinfile) - Conditional
- **Update apt cache** (ansible.builtin.apt) - Conditional
- **Install Python packages** (ansible.builtin.apt) - Conditional
- **Install Ubuntu-specific Python packages** (ansible.builtin.apt) - Conditional
- **Install system utilities** (ansible.builtin.apt) - Conditional
- **Install Ubuntu-specific system packages** (ansible.builtin.apt) - Conditional
- **Install Kali-specific system packages** (ansible.builtin.apt) - Conditional
- **Remove kali-motd to suppress MOTD spam** (ansible.builtin.file) - Conditional
- **Install AWS CLI v2** (ansible.builtin.include_tasks) - Conditional
- **Install uv package manager** (ansible.builtin.include_tasks) - Conditional
- **Install Rust toolchain** (ansible.builtin.include_tasks) - Conditional
- **Install pipx** (ansible.builtin.include_tasks) - Conditional
- **Set base tool paths for dependent roles** (ansible.builtin.set_fact)
- **Check pip version** (ansible.builtin.command)
- **Set fact for pip supports break-system-packages** (ansible.builtin.set_fact)
- **Check for externally managed Python** (ansible.builtin.shell)
- **Set fact for pip externally managed** (ansible.builtin.set_fact)
- **Fail when break-system-packages is required but disabled** (ansible.builtin.fail) - Conditional
- **Fail when break-system-packages is required but unsupported by pip** (ansible.builtin.fail) - Conditional
- **Upgrade pip to latest (CVE fixes)** (ansible.builtin.command)
- **Install Ares Python dependencies (with full log)** (ansible.builtin.shell)
- **Show pip install log tail on failure** (ansible.builtin.command) - Conditional
- **Print pip install tail** (ansible.builtin.debug) - Conditional
- **Fail if pip install failed** (ansible.builtin.fail) - Conditional
- **Create Ares workspace directory** (ansible.builtin.file) - Conditional
- **Apply host tuning for the Ares worker fleet** (ansible.builtin.include_tasks) - Conditional

### main.yml


- **Include Linux tasks** (ansible.builtin.include_tasks) - Conditional

### tuning.yml


- **Detect container environment (swap/sysctl are not settable there)** (ansible.builtin.set_fact)
- **Configure swap file (OOM cushion)** (block) - Conditional
- **Stat swap file** (ansible.builtin.stat)
- **Create or resize swap file** (block) - Conditional
- **Disable existing (undersized) swap file** (ansible.builtin.command) - Conditional
- **Allocate swap file (fallocate, dd fallback)** (ansible.builtin.shell)
- **Secure swap file permissions** (ansible.builtin.file)
- **Initialize swap area** (ansible.builtin.command)
- **Enable swap** (ansible.builtin.command)
- **Ensure swap file is registered in fstab** (ansible.posix.mount)
- **Tune OOM behavior via sysctl** (ansible.posix.sysctl) - Conditional

## Example Playbook

```yaml
- hosts: servers
  roles:
    - base
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
