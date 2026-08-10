<!-- DOCSIBLE START -->
# nats

## Description

NATS JetStream server for Ares task and RPC broker

## Requirements

- Ansible >= 2.18.4

## Role Variables

### Default Variables (main.yml)

| Variable | Type | Default | Description |
| -------- | ---- | ------- | ----------- |
| `nats_version` | str | <code>2.10.22</code> | No description |
| `nats_install_dir` | str | <code>/usr/local/bin</code> | No description |
| `nats_user` | str | <code>nats</code> | No description |
| `nats_group` | str | <code>nats</code> | No description |
| `nats_bind_address` | str | <code>127.0.0.1</code> | No description |
| `nats_port` | int | <code>4222</code> | No description |
| `nats_http_port` | int | <code>8222</code> | No description |
| `nats_jetstream_enabled` | bool | <code>True</code> | No description |
| `nats_jetstream_store_dir` | str | <code>/var/lib/nats/jetstream</code> | No description |
| `nats_jetstream_max_memory` | str | <code>512M</code> | No description |
| `nats_jetstream_max_file` | str | <code>4G</code> | No description |
| `nats_log_dir` | str | <code>/var/log/nats</code> | No description |
| `nats_log_file` | str | <code>/var/log/nats/nats-server.log</code> | No description |
| `nats_debug` | bool | <code>False</code> | No description |
| `nats_verify_install` | bool | <code>False</code> | No description |

## Tasks

### linux.yml


- **Map kernel arch to NATS release arch** (ansible.builtin.set_fact)
- **Create NATS group** (ansible.builtin.group)
- **Create NATS user** (ansible.builtin.user)
- **Create NATS directories** (ansible.builtin.file)
- **Check installed NATS version** (ansible.builtin.command)
- **Download NATS server release** (ansible.builtin.unarchive) - Conditional
- **Install NATS server binary** (ansible.builtin.copy) - Conditional
- **Clean up NATS release tarball directory** (ansible.builtin.file) - Conditional
- **Render NATS server config** (ansible.builtin.template)
- **Install NATS systemd unit** (ansible.builtin.template)
- **Enable and start NATS** (ansible.builtin.systemd)
- **Verify NATS is responding** (ansible.builtin.uri) - Conditional
- **Display NATS verification** (ansible.builtin.debug) - Conditional

### main.yml


- **Include Linux tasks** (ansible.builtin.include_tasks) - Conditional

## Example Playbook

```yaml
- hosts: servers
  roles:
    - nats
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
