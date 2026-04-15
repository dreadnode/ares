<!-- DOCSIBLE START -->
# aws_cloudwatch_agent

## Description

Install and configure AWS CloudWatch Agent

## Requirements

- Ansible >= 2.18.4

## Role Variables

### Default Variables (main.yml)

| Variable | Type | Default | Description |
| -------- | ---- | ------- | ----------- |
| `aws_cloudwatch_agent_temp_dir` | str | <code>/tmp/cloudwatch_install</code> | No description |
| `aws_cloudwatch_agent_linux_config_dir` | str | <code>/opt/aws/amazon-cloudwatch-agent/etc</code> | No description |
| `aws_cloudwatch_agent_linux_log_dir` | str | <code>/var/log/amazon/amazon-cloudwatch-agent</code> | No description |
| `aws_cloudwatch_agent_windows_temp_dir` | str | <code>C:\Windows\Temp</code> | No description |
| `aws_cloudwatch_agent_windows_installer` | str | <code>amazon-cloudwatch-agent.msi</code> | No description |
| `aws_cloudwatch_agent_windows_config_dir` | str | <code>C:\ProgramData\Amazon\AmazonCloudWatchAgent</code> | No description |
| `aws_cloudwatch_agent_windows_log_dir` | str | <code>C:\ProgramData\Amazon\AmazonCloudWatchAgent\Logs</code> | No description |
| `aws_cloudwatch_agent_config` | dict | <code>{}</code> | No description |
| `aws_cloudwatch_agent_config.agent` | dict | <code>{}</code> | No description |
| `aws_cloudwatch_agent_config.metrics` | dict | <code>{}</code> | No description |

### Role Variables (main.yml)

| Variable | Type | Value | Description |
| -------- | ---- | ----- | ----------- |
| `aws_cloudwatch_agent_deb_url` | str | `https://s3.amazonaws.com/amazoncloudwatch-agent/debian/amd64/latest/amazon-cloudwatch-agent.deb` | No description |
| `aws_cloudwatch_agent_win_url` | str | `https://s3.amazonaws.com/amazoncloudwatch-agent/windows/amd64/latest/amazon-cloudwatch-agent.msi` | No description |

## Tasks

### linux.yml


- **Set DEBIAN_FRONTEND to noninteractive** (ansible.builtin.lineinfile) - Conditional
- **Create temporary directory for CloudWatch installation** (ansible.builtin.file)
- **Download CloudWatch agent (Debian/Ubuntu)** (ansible.builtin.get_url) - Conditional
- **Install CloudWatch agent (Debian/Ubuntu)** (ansible.builtin.apt) - Conditional
- **Ensure CloudWatch Agent config directory exists** (ansible.builtin.file)
- **Create CloudWatch Agent configuration** (ansible.builtin.template)
- **Start CloudWatch Agent** (ansible.builtin.shell)
- **Reload systemd** (ansible.builtin.systemd)
- **Enable and start CloudWatch agent** (ansible.builtin.systemd)
- **Clean up temporary files** (ansible.builtin.file)

### main.yml


- **Include Linux tasks** (ansible.builtin.include_tasks) - Conditional
- **Include Windows tasks** (ansible.builtin.include_tasks) - Conditional

### windows.yml


- **Download CloudWatch agent installer (Windows)** (ansible.windows.win_get_url)
- **Install CloudWatch agent (Windows)** (ansible.windows.win_package)
- **Ensure CloudWatch Agent config directory exists** (ansible.windows.win_file)
- **Create CloudWatch Agent configuration (Windows)** (ansible.windows.win_template)
- **Start CloudWatch Agent (Windows)** (ansible.windows.win_shell)
- **Make sure CloudWatch agent service is running (Windows)** (ansible.windows.win_service)
- **Clean up temporary files (Windows)** (ansible.windows.win_file)

## Example Playbook

```yaml
- hosts: servers
  roles:
    - aws_cloudwatch_agent
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
