<!-- DOCSIBLE START -->
# aws_ssm_agent

## Description

Install and configure AWS SSM Agent

## Requirements

- Ansible >= 2.18.4

## Role Variables

### Default Variables (main.yml)

| Variable | Type | Default | Description |
| -------- | ---- | ------- | ----------- |
| `aws_ssm_agent_temp_dir` | str | <code>/tmp/ssm_install</code> | No description |
| `aws_ssm_agent_aws_region` | str | <code>us-east-1</code> | No description |

### Role Variables (main.yml)

| Variable | Type | Value | Description |
| -------- | ---- | ----- | ----------- |
| `aws_ssm_agent_linux_install_url` | str | `https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/debian_amd64/amazon-ssm-agent.deb` | No description |
| `aws_ssm_agent_install_packages` | list | `[]` | No description |
| `aws_ssm_agent_install_packages.0` | str | `systemd` | No description |
| `aws_ssm_agent_windows_install_url` | str | `https://amazon-ssm-{{ aws_ssm_agent_aws_region | default('us-east-1') }}.s3.amazonaws.com/latest/windows_amd64/AmazonSSMAgentSetup.exe` | No description |
| `aws_ssm_agent_windows_temp_dir` | str | `C:\Windows\Temp` | No description |
| `aws_ssm_agent_windows_installer` | str | `SSMAgent_latest.exe` | No description |

## Tasks

### linux.yml


- **Set DEBIAN_FRONTEND to noninteractive** (ansible.builtin.lineinfile) - Conditional
- **Install packages** (ansible.builtin.package) - Conditional
- **Create temporary directory for SSM installation** (ansible.builtin.file)
- **Download SSM agent** (ansible.builtin.get_url)
- **Install SSM agent (Debian/Ubuntu)** (ansible.builtin.apt) - Conditional
- **Reload systemd** (ansible.builtin.systemd)
- **Enable and start SSM agent** (ansible.builtin.systemd)
- **Clean up temporary files** (ansible.builtin.file)

### main.yml


- **Include Linux tasks** (ansible.builtin.include_tasks) - Conditional
- **Include Windows tasks** (ansible.builtin.include_tasks) - Conditional

### windows.yml


- **Download SSM agent installer (Windows)** (ansible.windows.win_get_url)
- **Install SSM agent (Windows)** (ansible.windows.win_package)
- **Make sure SSM agent service is running (Windows)** (ansible.windows.win_service)
- **Clean up temporary files (Windows)** (ansible.windows.win_file)

## Example Playbook

```yaml
- hosts: servers
  roles:
    - aws_ssm_agent
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
