<!-- DOCSIBLE START -->
# fluent_bit

## Description

Install and configure Fluent Bit for log management

## Requirements

- Ansible >= 2.18.4

## Role Variables

### Default Variables (main.yml)

| Variable | Type | Default | Description |
| -------- | ---- | ------- | ----------- |
| `fluent_bit_linux_config_dir` | str | <code>/etc/fluent-bit</code> | No description |
| `fluent_bit_linux_state_dir` | str | <code>/var/lib/fluent-bit</code> | No description |
| `fluent_bit_linux_log_dir` | str | <code>/var/log/fluent-bit</code> | No description |
| `fluent_bit_force_reread_user_data` | bool | <code>True</code> | No description |
| `fluent_bit_inputs` | list | <code>&#91;&#93;</code> | No description |
| `fluent_bit_inputs.0` | dict | <code>{}</code> | No description |
| `fluent_bit_inputs.1` | dict | <code>{}</code> | No description |
| `fluent_bit_inputs.2` | dict | <code>{}</code> | No description |
| `fluent_bit_windows_url` | str | <code>https://fluentbit.io/releases/latest/fluent-bit-latest-win64.zip</code> | No description |
| `fluent_bit_windows_temp_dir` | str | <code>C:\Windows\Temp</code> | No description |
| `fluent_bit_windows_installer` | str | <code>fluent-bit-latest-win64.zip</code> | No description |
| `fluent_bit_windows_install_dir` | str | <code>C:\Program Files\fluent-bit</code> | No description |
| `fluent_bit_windows_config_dir` | str | <code>C:\Program Files\fluent-bit\conf</code> | No description |
| `fluent_bit_windows_state_dir` | str | <code>C:\ProgramData\fluent-bit</code> | No description |
| `fluent_bit_windows_log_dir` | str | <code>C:\ProgramData\fluent-bit\logs</code> | No description |
| `fluent_bit_opensearch_host` | str | <code>localhost</code> | No description |
| `fluent_bit_opensearch_port` | int | <code>9200</code> | No description |
| `fluent_bit_opensearch_index` | str | <code>fluent-bit</code> | No description |
| `fluent_bit_opensearch_type` | str | <code>_doc</code> | No description |
| `fluent_bit_opensearch_http_user` | str | <code></code> | No description |
| `fluent_bit_opensearch_http_passwd` | str | <code></code> | No description |
| `fluent_bit_opensearch_tls` | str | <code>false</code> | No description |
| `fluent_bit_opensearch_tls_verify` | str | <code>false</code> | No description |
| `fluent_bit_opensearch_custom_domain` | str | <code>localhost</code> | No description |
| `fluent_bit_opensearch_username` | str | <code></code> | No description |
| `fluent_bit_opensearch_password` | str | <code></code> | No description |
| `fluent_bit_env` | str | <code>dev</code> | No description |
| `fluent_bit_deployment_name` | str | <code>default</code> | No description |
| `fluent_bit_parsers` | list | <code>&#91;&#93;</code> | No description |
| `fluent_bit_parsers.0` | dict | <code>{}</code> | No description |
| `fluent_bit_parsers.1` | dict | <code>{}</code> | No description |

### Role Variables (main.yml)

| Variable | Type | Value | Description |
| -------- | ---- | ----- | ----------- |
| `fluent_bit_common_install_packages` | list | `[]` | No description |
| `fluent_bit_common_install_packages.0` | str | `ca-certificates` | No description |
| `fluent_bit_debian_specific_packages` | list | `[]` | No description |
| `fluent_bit_debian_specific_packages.0` | str | `gpg` | No description |
| `fluent_bit_debian_specific_packages.1` | str | `fluent-bit` | No description |
| `fluent_bit_install_script_url` | str | `https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh` | No description |
| `fluent_bit_repo_key_url` | str | `https://packages.fluentbit.io/fluentbit.key` | No description |
| `fluent_bit_repo_url` | str | `{% if ansible_facts['distribution'] == 'Ubuntu' %}https://packages.fluentbit.io/ubuntu/{{ ansible_facts['distribution_release'] }}{% elif ansible_facts['distribution'] == 'Kali' %}https://packages.fluentbit.io/debian/bookworm{% else %}https://packages.fluentbit.io/debian/{{ 'bookworm' if ansible_facts['distribution_release'] == 'kali-rolling' else ansible_facts['distribution_release'] }}{% endif %}` | No description |
| `fluent_bit_linux_config_dir` | str | `/etc/fluent-bit` | No description |
| `fluent_bit_linux_state_dir` | str | `/var/lib/fluent-bit` | No description |
| `fluent_bit_force_reread_user_data` | bool | `False` | No description |
| `fluent_bit_version` | str | `4.0.1` | No description |
| `fluent_bit_windows_url` | str | `https://packages.fluentbit.io/windows/fluent-bit-{{ fluent_bit_version }}-win64.zip` | No description |
| `fluent_bit_windows_temp_dir` | str | `C:\Windows\Temp` | No description |
| `fluent_bit_windows_installer` | str | `fluent-bit-{{ fluent_bit_version }}-win64.zip` | No description |
| `fluent_bit_windows_install_dir` | str | `C:\Program Files\fluent-bit` | No description |

## Tasks

### linux.yml


- **Set DEBIAN_FRONTEND to noninteractive** (ansible.builtin.lineinfile) - Conditional
- **Install required packages for Fluent Bit** (ansible.builtin.include_role) - Conditional
- **Add Fluent Bit repository key** (ansible.builtin.uri) - Conditional
- **Convert key to GPG format** (ansible.builtin.shell) - Conditional
- **Add Fluent Bit repository to sources list** (ansible.builtin.lineinfile) - Conditional
- **Install Fluent Bit package** (ansible.builtin.include_role) - Conditional
- **Create scripts directory for Fluent Bit** (ansible.builtin.file)
- **Copy cmd_output_parser.lua script to Fluent Bit** (ansible.builtin.copy)
- **Create directory for Fluent Bit state files** (ansible.builtin.file)
- **Check if default Fluent Bit config exists** (ansible.builtin.stat)
- **Backup default Fluent Bit config if exists** (ansible.builtin.copy) - Conditional
- **Create Fluent Bit configuration for OpenSearch** (ansible.builtin.template)
- **Create Fluent Bit parsers configuration** (ansible.builtin.template)
- **Pause to ensure services have fully started** (ansible.builtin.pause)
- **Enable and start Fluent Bit service** (ansible.builtin.systemd)
- **Wait for Fluent Bit to initialize** (ansible.builtin.pause)
- **Stop Fluent Bit for DB cleanup (if fluent_bit_force_reread_user_data is enabled)** (ansible.builtin.systemd) - Conditional
- **Remove user-data.db to force re-read (if fluent_bit_force_reread_user_data is enabled)** (ansible.builtin.file) - Conditional
- **Start Fluent Bit after DB cleanup (if fluent_bit_force_reread_user_data is enabled)** (ansible.builtin.systemd) - Conditional
- **Check Fluent Bit service status** (ansible.builtin.systemd)

### main.yml


- **Include Linux tasks** (ansible.builtin.include_tasks) - Conditional
- **Include Windows tasks** (ansible.builtin.include_tasks) - Conditional

### windows.yml


- **Create temporary directory for Fluent Bit installation (Windows)** (ansible.windows.win_file)
- **Set installer filename and URL based on version choice (Windows)** (ansible.builtin.set_fact)
- **Download Fluent Bit installer (Windows)** (ansible.windows.win_get_url)
- **Check if Fluent Bit service exists (Windows)** (ansible.windows.win_service)
- **Stop Fluent Bit service if exists (Windows)** (ansible.windows.win_service) - Conditional
- **Remove existing Fluent Bit service if exists (Windows)** (ansible.windows.win_service) - Conditional
- **Create Fluent Bit installation directory (Windows)** (ansible.windows.win_file)
- **Extract Fluent Bit ZIP archive (Windows)** (community.windows.win_unzip)
- **Find Fluent Bit executable (Windows)** (ansible.windows.win_find)
- **Set executable path and directory (Windows)** (ansible.builtin.set_fact) - Conditional
- **Create Fluent Bit configuration directory (Windows)** (ansible.windows.win_file)
- **Create Fluent Bit state directory (Windows)** (ansible.windows.win_file)
- **Create Fluent Bit log directory (Windows)** (ansible.windows.win_file)
- **Check if Sysmon is installed (Windows)** (ansible.windows.win_shell)
- **Set sysmon_installed fact (Windows)** (ansible.builtin.set_fact)
- **Create Fluent Bit configuration (Windows)** (ansible.windows.win_template)
- **Install Fluent Bit as a service** (ansible.windows.win_service)
- **Verify Fluent Bit configuration and paths (Windows)** (ansible.windows.win_shell)
- **Remove Windows state DB files to force re-read (Windows)** (ansible.windows.win_file) - Conditional
- **Start Fluent Bit after DB cleanup (Windows)** (ansible.windows.win_service) - Conditional
- **Clean up temporary files (Windows)** (ansible.windows.win_file)

## Example Playbook

```yaml
- hosts: servers
  roles:
    - fluent_bit
```

## Author Information

- **Author**: Jayson Grace
- **Company**: dreadnode
- **License**: MIT

## Platforms


- Ubuntu: all
- Debian: all
- Windows: all
<!-- DOCSIBLE END -->
