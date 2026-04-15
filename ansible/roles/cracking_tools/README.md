<!-- DOCSIBLE START -->
# cracking_tools

## Description

Install and configure password cracking tools for Ares agents

## Requirements

- Ansible >= 2.18.4

## Dependencies


- dreadnode.nimbus_range.base

## Role Variables

### Default Variables (main.yml)

| Variable | Type | Default | Description |
| -------- | ---- | ------- | ----------- |
| `cracking_tools_install_hashcat` | bool | <code>True</code> | No description |
| `cracking_tools_install_john` | bool | <code>True</code> | No description |
| `cracking_tools_install_crackmapexec` | bool | <code>False</code> | No description |
| `cracking_tools_hashcat_package` | str | <code>hashcat</code> | No description |
| `cracking_tools_hashcat_from_source` | bool | <code>False</code> | No description |
| `cracking_tools_hashcat_repo` | str | <code>https://github.com/hashcat/hashcat.git</code> | No description |
| `cracking_tools_hashcat_version` | str | <code>master</code> | No description |
| `cracking_tools_libgcc_package_primary` | str | <code>libgcc-s1</code> | No description |
| `cracking_tools_libgcc_package_fallback` | str | <code>libgcc1</code> | No description |
| `cracking_tools_gcc_package_primary` | str | <code>gcc</code> | No description |
| `cracking_tools_gcc_package_fallback` | str | <code>gcc-15</code> | No description |
| `cracking_tools_john_package` | str | <code>john</code> | No description |
| `cracking_tools_john_from_source` | bool | <code>False</code> | No description |
| `cracking_tools_john_repo` | str | <code>https://github.com/openwall/john.git</code> | No description |
| `cracking_tools_john_version` | str | <code>bleeding-jumbo</code> | No description |
| `cracking_tools_install_wordlists` | bool | <code>True</code> | No description |
| `cracking_tools_wordlists` | list | <code>&#91;&#93;</code> | No description |
| `cracking_tools_wordlists.0` | str | <code>rockyou</code> | No description |
| `cracking_tools_wordlists.1` | str | <code>seclists_passwords</code> | No description |
| `cracking_tools_rockyou_path` | str | <code>/usr/share/wordlists/rockyou.txt</code> | No description |
| `cracking_tools_rockyou_gz_path` | str | <code>/usr/share/wordlists/rockyou.txt.gz</code> | No description |
| `cracking_tools_extract_rockyou` | bool | <code>True</code> | No description |
| `cracking_tools_install_seclists` | bool | <code>True</code> | No description |
| `cracking_tools_seclists_repo` | str | <code>https://github.com/danielmiessler/SecLists.git</code> | No description |
| `cracking_tools_seclists_path` | str | <code>/usr/share/wordlists/seclists</code> | No description |
| `cracking_tools_wordlist_dir` | str | <code>/usr/share/wordlists</code> | No description |
| `cracking_tools_gpu_support` | bool | <code>False</code> | No description |
| `cracking_tools_opencl_packages` | list | <code>&#91;&#93;</code> | No description |
| `cracking_tools_opencl_packages.0` | str | <code>ocl-icd-libopencl1</code> | No description |
| `cracking_tools_opencl_packages.1` | str | <code>opencl-headers</code> | No description |
| `cracking_tools_opencl_packages.2` | str | <code>clinfo</code> | No description |
| `cracking_tools_nvidia_opencl_icd` | bool | <code>False</code> | No description |
| `cracking_tools_update_cache` | bool | <code>True</code> | No description |

## Tasks

### hashcat.yml


- **Install hashcat from package** (ansible.builtin.apt) - Conditional
- **Install hashcat from source** (block) - Conditional
- **Install build dependencies for hashcat** (ansible.builtin.apt)
- **Install hashcat build dependencies from repository** (ansible.builtin.apt)
- **Clone hashcat repository** (ansible.builtin.git)
- **Check if Rust is already installed** (ansible.builtin.stat)
- **Install Rust via rustup (for edition 2024 support)** (block) - Conditional
- **Download rustup installer** (ansible.builtin.get_url)
- **Run rustup installer** (ansible.builtin.shell)
- **Remove rustup installer** (ansible.builtin.file)
- **Build hashcat** (ansible.builtin.shell)
- **Install hashcat binary** (ansible.builtin.copy)
- **Create hashcat share directory** (ansible.builtin.file)
- **Symlink hashcat OpenCL kernels** (ansible.builtin.file)
- **Symlink hashcat modules** (ansible.builtin.file)

### john.yml


- **Install John the Ripper from package** (ansible.builtin.apt) - Conditional
- **Install John the Ripper from source** (block) - Conditional
- **Install build dependencies for John** (ansible.builtin.apt)
- **Clone John repository** (ansible.builtin.git)
- **Configure John** (ansible.builtin.command)
- **Build John** (ansible.builtin.command)
- **Create symlink for john** (ansible.builtin.file)

### linux.yml


- **Set DEBIAN_FRONTEND to noninteractive** (ansible.builtin.lineinfile) - Conditional
- **Update apt cache** (ansible.builtin.apt) - Conditional
- **Create wordlist directory** (ansible.builtin.file)
- **Install GPU support packages** (ansible.builtin.apt) - Conditional
- **Create OpenCL vendors directory** (ansible.builtin.file) - Conditional
- **Register NVIDIA OpenCL ICD** (ansible.builtin.copy) - Conditional
- **Ensure libgcc runtime is present for hashcat** (block) - Conditional
- **Install primary libgcc package** (ansible.builtin.apt)
- **Ensure libgcc static archive is present for hashcat** (block) - Conditional
- **Install primary gcc package** (ansible.builtin.apt)
- **Install hashcat** (ansible.builtin.include_tasks) - Conditional
- **Install John the Ripper** (ansible.builtin.include_tasks) - Conditional
- **Install wordlists** (ansible.builtin.include_tasks) - Conditional

### main.yml


- **Include Linux tasks** (ansible.builtin.include_tasks) - Conditional

### wordlists.yml


- **Check if rockyou.txt.gz exists** (ansible.builtin.stat)
- **Extract rockyou.txt** (ansible.builtin.command) - Conditional
- **Download rockyou.txt if not present** (block) - Conditional
- **Check if rockyou.txt exists** (ansible.builtin.stat)
- **Download rockyou wordlist** (ansible.builtin.get_url) - Conditional
- **Clone SecLists repository** (ansible.builtin.git) - Conditional
- **Display installed wordlists** (ansible.builtin.find)
- **Show wordlist summary** (ansible.builtin.debug)

## Example Playbook

```yaml
- hosts: servers
  roles:
    - cracking_tools
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
