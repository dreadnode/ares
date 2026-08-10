<!-- DOCSIBLE START -->
# vector

## Description

Vector log shipper — file/syslog sources to an S3 store-and-forward sink for off-LAN ares boxes

## Requirements

- Ansible >= 2.18.4

## Role Variables

### Default Variables (main.yml)

| Variable | Type | Default | Description |
| -------- | ---- | ------- | ----------- |
| `vector_version` | str | <code>0.56.0</code> | No description |
| `vector_download_base` | str | <code>https://github.com/vectordotdev/vector/releases/download</code> | No description |
| `vector_install_dir` | str | <code>/usr/local/bin</code> | No description |
| `vector_config_dir` | str | <code>/etc/vector</code> | No description |
| `vector_data_dir` | str | <code>/var/lib/vector</code> | No description |
| `vector_s3_bucket` | str | <code></code> | No description |
| `vector_s3_region` | str | <code>us-east-1</code> | No description |
| `vector_s3_key_prefix` | str | <code>logs</code> | No description |
| `vector_deployment_name` | str | <code>alpha-operator-range</code> | No description |
| `vector_environment` | str | <code>prod</code> | No description |
| `vector_log_includes` | list | <code>&#91;&#93;</code> | No description |
| `vector_log_includes.0` | str | <code>/var/log/ares/*.log</code> | No description |
| `vector_log_includes.1` | str | <code>/var/log/syslog</code> | No description |
| `vector_log_includes.2` | str | <code>/var/log/auth.log</code> | No description |
| `vector_log_includes.3` | str | <code>/var/log/user-data.log</code> | No description |
| `vector_s3_batch_timeout_secs` | int | <code>300</code> | No description |
| `vector_s3_batch_max_bytes` | int | <code>10485760</code> | No description |
| `vector_verify_install` | bool | <code>False</code> | No description |

## Tasks

### linux.yml


- **Fail when no S3 bucket is configured** (ansible.builtin.fail) - Conditional
- **Map kernel arch to Vector release arch** (ansible.builtin.set_fact)
- **Create Vector directories** (ansible.builtin.file)
- **Check installed Vector version** (ansible.builtin.command)
- **Download Vector release** (ansible.builtin.unarchive) - Conditional
- **Install Vector binary** (ansible.builtin.copy) - Conditional
- **Clean up Vector release directory** (ansible.builtin.file) - Conditional
- **Render Vector config** (ansible.builtin.template)
- **Validate Vector config** (ansible.builtin.command) - Conditional
- **Install Vector systemd unit** (ansible.builtin.template)
- **Enable and start Vector** (ansible.builtin.systemd)

### main.yml


- **Include Linux tasks** (ansible.builtin.include_tasks) - Conditional

## Example Playbook

```yaml
- hosts: servers
  roles:
    - vector
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
