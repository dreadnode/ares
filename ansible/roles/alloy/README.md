<!-- DOCSIBLE START -->
# alloy

## Description

Install and configure Grafana Alloy for Windows hosts

## Requirements

- Ansible >= 2.13

## Role Variables

### Default Variables (main.yml)

| Variable | Type | Default | Description |
| -------- | ---- | ------- | ----------- |
| `alloy_version` | str | <code>1.10.1</code> | No description |
| `alloy_env` | str | <code>dev</code> | No description |
| `alloy_deployment_name` | str | <code></code> | No description |
| `alloy_instance_id` | str | <code></code> | No description |
| `alloy_loki_endpoint` | str | <code>https://loki.dev.plundr.ai/loki/api/v1/push</code> | No description |
| `alloy_windows_installer_url` | str | <code>https://github.com/grafana/alloy/releases/download/v{{ alloy_version }}/alloy-installer-windows-amd64.exe.zip</code> | No description |
| `alloy_windows_temp_dir` | str | <code>C:\Windows\Temp</code> | No description |
| `alloy_windows_install_dir` | str | <code>C:\Program Files\GrafanaLabs\Alloy</code> | No description |
| `alloy_windows_config_path` | str | <code>C:\Program Files\GrafanaLabs\Alloy\config.alloy</code> | No description |
| `alloy_windows_data_path` | str | <code>C:\ProgramData\GrafanaLabs\Alloy\data</code> | No description |
| `alloy_disable_reporting` | bool | <code>True</code> | No description |
| `alloy_disable_profiling` | bool | <code>True</code> | No description |
| `alloy_service_name` | str | <code>Alloy</code> | No description |
| `alloy_service_user` | str | <code>NT AUTHORITY\LocalSystem</code> | No description |
| `alloy_runtime_priority` | str | <code>normal</code> | No description |
| `alloy_stability` | str | <code>generally-available</code> | No description |
| `alloy_log_sources` | list | <code>&#91;&#93;</code> | No description |
| `alloy_log_sources.0` | dict | <code>{}</code> | No description |
| `alloy_log_sources.1` | dict | <code>{}</code> | No description |
| `alloy_log_sources.2` | dict | <code>{}</code> | No description |

## Tasks

### main.yml


- **Include OS-specific tasks** (ansible.builtin.include_tasks)

### windows.yml


- **Check if Alloy is already installed** (ansible.windows.win_service)
- **Download Alloy installer** (ansible.windows.win_get_url) - Conditional
- **Extract Alloy installer** (community.windows.win_unzip) - Conditional
- **Install Alloy silently** (ansible.windows.win_command) - Conditional
- **Wait for Alloy service to be created** (ansible.windows.win_service) - Conditional
- **Create Alloy configuration file** (ansible.windows.win_template)
- **Ensure Alloy service is running** (ansible.windows.win_service)
- **Clean up installer files** (ansible.windows.win_file)

## Example Playbook

```yaml
- hosts: servers
  roles:
    - alloy
```

## Author Information

- **Author**: Dreadnode
- **Company**: Dreadnode
- **License**: MIT

## Platforms


- Windows: all
<!-- DOCSIBLE END -->
