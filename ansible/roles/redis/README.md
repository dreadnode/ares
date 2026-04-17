<!-- DOCSIBLE START -->
<!-- DOCSIBLE START -->
# redis

## Description

Redis server for Ares worker message broker

## Requirements

- Ansible >= 2.18.4

## Role Variables

### Default Variables (main.yml)

| Variable | Type | Default | Description |
| -------- | ---- | ------- | ----------- |
| `redis_bind_address` | str | <code>127.0.0.1</code> | No description |
| `redis_port` | int | <code>6379</code> | No description |
| `redis_maxmemory` | str | <code>256mb</code> | No description |
| `redis_maxmemory_policy` | str | <code>allkeys-lru</code> | No description |
| `redis_install_ares_worker_unit` | bool | <code>True</code> | No description |
| `redis_ares_worker_binary` | str | <code>/usr/local/bin/ares</code> | No description |
| `redis_ares_log_dir` | str | <code>/var/log/ares</code> | No description |
| `redis_ares_config_dir` | str | <code>/etc/ares</code> | No description |
| `redis_verify_install` | bool | <code>False</code> | No description |

## Tasks

### linux.yml


- **Install Redis server** (ansible.builtin.apt)
- **Configure Redis bind address** (ansible.builtin.lineinfile)
- **Configure Redis port** (ansible.builtin.lineinfile)
- **Configure Redis maxmemory** (ansible.builtin.lineinfile)
- **Configure Redis maxmemory-policy** (ansible.builtin.lineinfile)
- **Enable and start Redis** (ansible.builtin.systemd)
- **Create Ares directories** (ansible.builtin.file)
- **Install Ares worker systemd template unit** (ansible.builtin.template) - Conditional
- **Verify Redis is responding** (ansible.builtin.command) - Conditional
- **Display Redis verification** (ansible.builtin.debug) - Conditional

### main.yml


- **Include Linux tasks** (ansible.builtin.include_tasks) - Conditional

## Example Playbook

```yaml
- hosts: servers
  roles:
    - redis
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
