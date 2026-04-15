<!-- DOCSIBLE START -->
# dc_audit_sacl

## Description

Configure SACL auditing on Domain Controllers for attack detection

## Requirements

- Ansible >= 2.14

## Role Variables

### Default Variables (main.yml)

| Variable | Type | Default | Description |
| -------- | ---- | ------- | ----------- |
| `dc_audit_sacl_replication_guids` | list | <code>&#91;&#93;</code> | No description |
| `dc_audit_sacl_replication_guids.0` | dict | <code>{}</code> | No description |
| `dc_audit_sacl_replication_guids.1` | dict | <code>{}</code> | No description |
| `dc_audit_sacl_replication_guids.2` | dict | <code>{}</code> | No description |
| `dc_audit_sacl_principal` | str | <code>S-1-1-0</code> | No description |
| `dc_audit_sacl_flags` | str | <code>Success</code> | No description |
| `dc_audit_sacl_ensure_auditpol` | bool | <code>True</code> | No description |
| `dc_audit_sacl_subcategories` | list | <code>&#91;&#93;</code> | No description |
| `dc_audit_sacl_subcategories.0` | str | <code>Directory Service Access</code> | No description |
| `dc_audit_sacl_subcategories.1` | str | <code>Directory Service Changes</code> | No description |

## Tasks

### main.yml


- **Check if host is a Domain Controller** (ansible.windows.win_feature_info)
- **Skip if not a Domain Controller** (ansible.builtin.debug) - Conditional
- **Configure SACL auditing on Domain Controller** (block) - Conditional
- **Configure auditpol for Directory Service Access** (ansible.windows.win_shell) - Conditional
- **Get current domain DN** (ansible.windows.win_shell)
- **Configure SACL for replication GUIDs (DCSync detection)** (ansible.windows.win_shell)
- **Verify SACL configuration** (ansible.windows.win_shell)
- **Display verification result** (ansible.builtin.debug)

## Example Playbook

```yaml
- hosts: servers
  roles:
    - dc_audit_sacl
```

## Author Information

- **Author**: Dreadnode
- **Company**: Dreadnode
- **License**: proprietary

## Platforms


- Windows: 2019, 2022
<!-- DOCSIBLE END -->
