<!-- DOCSIBLE START -->
# mythic

## Description

Install and configure Mythic C2 framework

## Requirements

- Ansible >= 2.13

## Role Variables

### Default Variables (main.yml)

| Variable | Type | Default | Description |
| -------- | ---- | ------- | ----------- |
| `mythic_user` | str | <code>mythic</code> | No description |
| `mythic_home` | str | <code>/home/{{ mythic_user }}</code> | No description |
| `mythic_repo` | str | <code>https://github.com/its-a-feature/Mythic.git</code> | No description |
| `mythic_install_dir` | str | <code>{{ mythic_home }}/Mythic</code> | No description |
| `mythic_go_version` | str | <code>1.21</code> | No description |
| `mythic_install_dev_tools` | bool | <code>True</code> | No description |
| `mythic_setup_systemd` | bool | <code>True</code> | No description |
| `mythic_admin_user` | str | <code>mythic_admin</code> | No description |
| `mythic_credentials_path` | str | <code>{{ lookup('env', 'HOME') }}/.ansible/credentials/mythic</code> | No description |
| `mythic_admin_password` | str | <code>{{ lookup('ansible.builtin.password', mythic_credentials_path + '/admin_password length=32 chars=ascii_letters,digits') }}</code> | No description |
| `mythic_hasura_secret` | str | <code>{{ lookup('ansible.builtin.password', mythic_credentials_path + '/hasura_secret length=32 chars=ascii_letters,digits') }}</code> | No description |
| `mythic_jwt_secret` | str | <code>{{ lookup('ansible.builtin.password', mythic_credentials_path + '/jwt_secret length=32 chars=ascii_letters,digits') }}</code> | No description |
| `mythic_postgres_password` | str | <code>{{ lookup('ansible.builtin.password', mythic_credentials_path + '/postgres_password length=32 chars=ascii_letters,digits') }}</code> | No description |
| `mythic_rabbitmq_password` | str | <code>{{ lookup('ansible.builtin.password', mythic_credentials_path + '/rabbitmq_password length=32 chars=ascii_letters,digits') }}</code> | No description |
| `mythic_postgres_user` | str | <code>mythic_user</code> | No description |
| `mythic_postgres_db` | str | <code>mythic_db</code> | No description |
| `mythic_rabbitmq_user` | str | <code>mythic_user</code> | No description |
| `mythic_rabbitmq_vhost` | str | <code>mythic_vhost</code> | No description |
| `mythic_bind_all_interfaces` | bool | <code>True</code> | No description |
| `mythic_nginx_port` | int | <code>7443</code> | No description |
| `mythic_server_port` | int | <code>17443</code> | No description |
| `mythic_server_grpc_port` | int | <code>17444</code> | No description |
| `mythic_dynamic_ports` | str | <code>7000-7010,1080</code> | No description |
| `mythic_initial_pull_timeout` | int | <code>600</code> | No description |
| `mythic_jupyter_timeout` | int | <code>300</code> | No description |
| `mythic_service_timeout` | int | <code>180</code> | No description |
| `mythic_retry_delay` | int | <code>10</code> | No description |
| `mythic_max_retries` | int | <code>30</code> | No description |
| `mythic_service_description` | str | <code>Mythic C2 Framework Service</code> | No description |
| `mythic_service_start_command` | str | <code>./mythic-cli start</code> | No description |
| `mythic_service_stop_command` | str | <code>./mythic-cli stop</code> | No description |
| `mythic_service_restart_sec` | int | <code>100</code> | No description |
| `mythic_service_timeout_start_sec` | int | <code>300</code> | No description |

## Tasks

### agents.yml


- **Ensure proper permissions for Mythic installation** (block)
- **Set ownership of Mythic directory** (ansible.builtin.file)
- **Ensure docker-compose.yml is writable** (ansible.builtin.file)
- **Install HTTP C2 profile** (block)
- **Start HTTP C2 installation** (ansible.builtin.command)
- **Wait for HTTP container** (ansible.builtin.shell)
- **Install Apollo agent** (block)
- **Start Apollo installation** (ansible.builtin.command)
- **Wait for Apollo container** (ansible.builtin.shell)
- **Install Poseidon agent** (block)
- **Start Poseidon installation** (ansible.builtin.command)
- **Wait for Poseidon container** (ansible.builtin.shell)
- **Install Mythic Forge** (block)
- **Start Mythic Forge installation** (ansible.builtin.command)
- **Wait for Forge container** (ansible.builtin.shell)
- **Install Bloodhound agent** (block)
- **Start Bloodhound installation** (ansible.builtin.command)
- **Wait for Bloodhound container** (ansible.builtin.shell)

### docker.yml


- **Show Ubuntu version** (ansible.builtin.debug)
- **Install prerequisites** (ansible.builtin.apt)
- **Create directory for Docker GPG key** (ansible.builtin.file)
- **Download Docker GPG key** (ansible.builtin.get_url)
- **Dearmor Docker GPG key** (ansible.builtin.command)
- **Clean up temporary GPG key** (ansible.builtin.file)
- **Add Docker repository** (ansible.builtin.apt_repository)
- **Update apt cache after adding Docker repository** (ansible.builtin.apt)
- **Check available Docker versions** (ansible.builtin.command)
- **Show available Docker versions** (ansible.builtin.debug)
- **Install Docker packages** (ansible.builtin.apt)
- **Add user to docker group** (ansible.builtin.user)
- **Start and enable Docker service** (ansible.builtin.systemd)
- **Wait for Docker socket to be available** (ansible.builtin.wait_for)

### main.yml


- **Include user setup tasks** (ansible.builtin.import_tasks)
- **Include package installation tasks** (ansible.builtin.import_tasks)
- **Include Docker installation tasks** (ansible.builtin.import_tasks)
- **Include Mythic installation tasks** (ansible.builtin.import_tasks)
- **Include Mythic agents tasks** (ansible.builtin.import_tasks)
- **Include Mythic service tasks** (ansible.builtin.import_tasks) - Conditional

### mythic.yml


- **Ensure mythic home directory exists with proper permissions** (ansible.builtin.file)
- **Ensure Mythic installation directory exists with proper permissions** (ansible.builtin.file)
- **Clone Mythic repository** (ansible.builtin.git)
- **Build Mythic** (ansible.builtin.command)
- **Template Mythic environment file** (ansible.builtin.template)
- **Start Mythic services** (ansible.builtin.command)
- **Wait for Docker images to be pulled and initial startup** (block)
- **Get container status** (ansible.builtin.shell)
- **Set container facts** (ansible.builtin.set_fact)
- **Show current status** (ansible.builtin.debug)
- **Verify all containers are healthy** (ansible.builtin.assert)
- **Mark setup as complete** (ansible.builtin.debug)

### packages.yml


- **Update apt cache** (ansible.builtin.apt)
- **Install essential packages** (ansible.builtin.apt)
- **Install development tools** (ansible.builtin.apt) - Conditional

### service.yml


- **Configure systemd service for Mythic** (ansible.builtin.template)
- **Reload systemd daemon** (ansible.builtin.systemd)
- **Enable and restart Mythic service** (ansible.builtin.systemd)

### user.yml


- **Create mythic user** (ansible.builtin.user)
- **Add mythic user to sudoers with NOPASSWD** (ansible.builtin.lineinfile)

## Example Playbook

```yaml
- hosts: servers
  roles:
    - mythic
```

## Author Information

- **Author**: Dreadnode
- **Company**: Dreadnode
- **License**: MIT

## Platforms


- Ubuntu: all
- Debian: all
<!-- DOCSIBLE END -->
