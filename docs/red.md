# Red Team Multi-Agent Architecture

This document describes the design and operation of the Ares red team
multi-agent system.

## Overview

The red team system uses a **coordinator/worker architecture** where a central
orchestrator delegates tasks to specialized worker agents. Each agent runs in
its own Kubernetes pod with role-specific tools installed.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                     Orchestrator Service Pod                           │
│                    (ares-orchestrator-*)                               │
│                                                                         │
│  Responsibilities:                                                      │
│  - LLM-powered strategic coordination                                   │
│  - Attack path identification and planning                              │
│  - Task dispatch to all worker agents                                   │
│  - Progress monitoring and state aggregation                            │
│  - Operation completion decision                                        │
│  - Does NOT execute exploitation tools directly                         │
└──────────────────────────────┬─────────────────────────────────────────┘
                               │ Redis pub/sub + task queues
       ┌───────────────────────┼─────────────┬─────────────┬─────────────┬─────────────┐
       ▼             ▼         ▼             ▼             ▼             ▼             ▼
┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐
│   RECON   │ │ CREDENTIAL│ │  CRACKER  │ │    ACL    │ │  PRIVESC  │ │  LATERAL  │ │ COERCION  │
│           │ │  ACCESS   │ │           │ │           │ │           │ │           │ │           │
└───────────┘ └───────────┘ └───────────┘ └───────────┘ └───────────┘ └───────────┘ └───────────┘
        │             │             │             │             │             │             │
        ▼             ▼             ▼             ▼             ▼             ▼             ▼
   nmap        secretsdump    hashcat      bloodyAD      certipy      psexec      PetitPotam
   enum4linux  kerberoast     john         pywhisker     mssqlclient  evil-winrm  Coercer
   bloodhound  asrep_roast                 dacledit      rbcd         wmiexec     ntlmrelayx
               password_spray                            delegation   smbexec     Responder
```

## Design Principles

### 1. Orchestrator Coordinates, Workers Execute

The orchestrator **never executes exploitation tools directly**. It:

- Uses LLM-powered strategic decision making
- Identifies attack opportunities from shared state
- Dispatches tasks to appropriate worker agents (including RECON)
- Monitors progress and aggregates results
- Makes completion decisions

### 2. Workers Are Specialists

Each worker agent has:

- A specific set of tools for its domain
- No knowledge of other workers' activities (except via shared state)
- Responsibility to report results back to the orchestrator

### 3. Shared State via Redis

All agents share state through Redis:

- Discovered credentials are automatically broadcast
- Hashes are tracked for cracking status
- Hosts and vulnerabilities are cataloged
- Task status is visible to all agents

## Agent Roles and Responsibilities

### Orchestrator Service

**Purpose**: Central LLM-powered coordinator with the "big picture" view.

**Pod**: `ares-orchestrator-*` (separate from worker agents)

**Tools Available**:

- `OrchestratorTools` - Dispatch functions for all worker types
- `RedTeamReportingTools` - Status reporting, operation control

**Does NOT Have**:

- Network enumeration tools (nmap, enum4linux) - dispatches to RECON
- Credential harvesting tools (secretsdump, kerberoast) - dispatches to CREDENTIAL_ACCESS
- Exploitation tools (certipy, mssqlclient) - dispatches to PRIVESC
- Lateral movement tools (psexec, evil-winrm) - dispatches to LATERAL
- Cracking tools (hashcat, john) - dispatches to CRACKER

**Dispatch Functions**:

- `dispatch_recon` - RECON, network scanning, user/share enumeration, BloodHound
- `dispatch_credential_access` - CREDENTIAL_ACCESS, password attacks, hash extraction
- `dispatch_crack_hash` - CRACKER, hash cracking
- `dispatch_acl_analysis` - ACL, ACL abuse paths
- `dispatch_lateral_movement` - LATERAL, host compromise
- `dispatch_privesc_exploit` - PRIVESC, direct exploitation
- `queue_vulnerability_for_exploitation` - PRIVESC, queue vuln for exploitation
- `start_coercion` - COERCION, NTLM coercion/relay

### RECON

**Purpose**: Network reconnaissance and asset discovery.

**Pods**: `ares-recon-agent-*` (2 replicas)

**Tools Available**:

- `NetworkEnumerationTools` - nmap, user/share enumeration, domain info
- `BloodHoundTools` - AD relationship mapping, attack path analysis

**Workflow**:

1. Receive reconnaissance task from orchestrator (e.g., "scan subnet")
2. Execute network scanning and enumeration
3. Report discovered hosts, users, shares, services
4. Mark task complete

### CREDENTIAL_ACCESS

**Purpose**: Extract credentials and hashes from the environment.

**Tools Available**:

- `NetworkEnumerationTools` - target discovery, service enumeration for
  credential attacks
- `CredentialDiscoveryTools` - password spray, username=password, LDAP
  descriptions
- `CredentialHarvestingTools` - secretsdump, kerberoast, asrep_roast
- `SharePilferingTools` - GPP passwords, SYSVOL scripts, share spidering

**Workflow**:

1. Receive task from orchestrator (e.g., "run secretsdump on DC")
2. Execute the requested tool
3. Parse results for credentials/hashes
4. Report findings back (auto-broadcast to all agents)
5. Mark task complete

### CRACKER

**Purpose**: Crack password hashes offline.

**Tools Available**:

- `CrackingTools` - hashcat (GPU), john (CPU)

**Workflow**:

1. Receive hash with priority level
2. Attempt cracking with appropriate wordlists/rules
3. Report cracked passwords (auto-broadcast)
4. Mark task complete

### ACL

**Purpose**: Exploit Active Directory ACL misconfigurations.

**Tools Available**:

- `ACLExploitTools` - bloodyAD, pywhisker, dacledit, targeted kerberoast

**Workflow**:

1. Receive ACL abuse target from orchestrator
2. Execute appropriate ACL attack (shadow credentials, password change, etc.)
3. Report new credentials/access
4. Mark task complete

### PRIVESC

**Purpose**: Exploit privilege escalation vulnerabilities.

**Tools Available**:

- `CertipyTools` - ADCS exploitation (ESC1-ESC8)
- `DelegationTools` - Constrained/unconstrained delegation
- `MSSQLTools` - SQL Server attacks, linked server pivoting
- `CVEExploitTools` - Known vulnerability exploits
- `GoldenTicketTools` - Kerberos ticket forging
- `TrustAttackTools` - Domain/forest trust attacks

**Workflow**:

1. Receive vulnerability from queue (prioritized)
2. Attempt exploitation
3. Report success/failure with any new credentials
4. Mark task complete

### LATERAL

**Purpose**: Move to new hosts and extract credentials.

**Tools Available**:

- `LateralMovementTools` - psexec, evil-winrm, wmiexec, smbexec
- `CredentialHarvestingTools` - secretsdump on compromised hosts
- `SharePilferingTools` - Search shares for credentials
- `PostureValidationTools` - Verify access levels

**Workflow**:

1. Receive lateral movement target
2. Attempt access with available credentials
3. Run secretsdump on successful compromise
4. Report new credentials/hashes
5. Mark task complete

### COERCION

**Purpose**: Force NTLM authentication for relay attacks.

**Tools Available**:

- `CoercionTools` - PetitPotam, Coercer, PrinterBug
- `CoercionNetworkTools` - Responder, ntlmrelayx

**Workflow**:

1. Start listener (Responder/ntlmrelayx)
2. Trigger coercion against target
3. Capture/relay authentication
4. Report captured hashes or relayed access

## Operation Lifecycle

### Phase 1: Initial Reconnaissance

The orchestrator dispatches reconnaissance tasks to RECON workers:

```text
# Network discovery
dispatch_recon(task_type="network_scan", targets="10.0.0.0/24")
→ RECON executes: nmap_scan - Discover live hosts and services

# User enumeration (unauthenticated)
dispatch_recon(task_type="user_enumeration", targets="DC_IP", domain="corp.local")
→ RECON executes: enumerate_users - Get domain user list

# Share enumeration
dispatch_recon(task_type="share_enumeration", targets="DC_IP", domain="corp.local")
→ RECON executes: enumerate_shares - Find accessible shares

# Domain information
dispatch_recon(task_type="domain_info", targets="DC_IP", domain="corp.local")
→ RECON executes: get_domain_info - Domain controllers, trusts, etc.
```

### Phase 2: Low-Hanging Fruit (Dispatched)

Orchestrator dispatches credential discovery to CREDENTIAL_ACCESS:

```text
dispatch_credential_access(task_type="low_hanging_fruit", ...)

CREDENTIAL_ACCESS executes:
- username_as_password - Test username=password combos
- password_spray - Common passwords (Password1, Welcome1)
- ldap_search_descriptions - Passwords in user descriptions
- gpp_password_finder - GPP passwords (MS14-025)
- sysvol_script_search - Hardcoded passwords in scripts
```

### Phase 3: Credential Expansion Loop

**Every time a credential is found**, orchestrator dispatches:

```text
1. dispatch_recon(task_type="bloodhound", domain="corp.local", username="user", password="pass")  # pragma: allowlist secret
   → Run BloodHound collection for attack path analysis

2. dispatch_credential_access(task="secretsdump", targets="ALL_DCs")
   → Extracts NTLM hashes, looks for krbtgt/Administrator

3. dispatch_credential_access(task="kerberoast", ...)
   → Finds service accounts with SPNs

4. dispatch_credential_access(task="asrep_roast", ...)
   → Finds accounts without pre-auth

5. dispatch_crack_hash for any new hashes
   → Attempts offline cracking

6. REPEAT with any newly cracked credentials
```

This loop continues until:

- Domain Admin is achieved (krbtgt or Administrator hash found)
- No new credentials are discovered

### Phase 4: Vulnerability Exploitation

As vulnerabilities are discovered, orchestrator queues them:

```python
# ADCS vulnerabilities
queue_vulnerability_for_exploitation(
    vuln_type="ADCS_ESC1",
    target="CA-NAME",
    details='{"template": "VulnTemplate", "ca": "domain\\CA"}'
)

# Delegation attacks
queue_vulnerability_for_exploitation(
    vuln_type="constrained_delegation",
    target="SERVER-NAME",
    details='{"allowed_to": "TARGET-SPN"}'
)

# MSSQL exploitation
queue_vulnerability_for_exploitation(
    vuln_type="mssql_linked_server",
    target="SQL-SERVER-IP",
    details='{"username": "sql_user", "domain": "DOMAIN.COM"}'
)
```

PRIVESC agent processes the queue by priority.

### Phase 5: Lateral Movement

When credentials with admin access are found:

```text
dispatch_lateral_movement(
    target="HOST-IP",
    username="admin",
    credential="hash_or_password",
    method="auto"  # tries psexec, wmiexec, evil-winrm
)
```

LATERAL agent:

1. Establishes access
2. Runs secretsdump
3. Reports new credentials
4. Triggers credential expansion loop

### Phase 6: Domain Admin Achievement

When krbtgt or Administrator hash is found:

```text
1. Orchestrator calls announce_domain_admin()
2. Optionally generates golden ticket for persistence
3. Runs final secretsdump on all DCs
4. Calls complete_operation() with summary
```

## Vulnerability Priority Queue

Vulnerabilities are processed in priority order:

| Priority | Vulnerability Type | Reason |
| --- | --- | --- |
| 1 | ADCS_ESC1 | Direct DA path |
| 2 | ADCS_ESC4 | Direct DA path |
| 3 | ADCS_ESC8 | Direct DA path |
| 4 | krbtgt_hash | Golden ticket |
| 5 | domain_admin_hash | Immediate DA |
| 6 | acl_abuse | Path to DA |
| 7 | unconstrained_delegation | Token capture |
| 8 | constrained_delegation | Impersonation |
| 9 | rbcd | Impersonation |
| 10 | mssql_impersonation | SQL privesc |
| 11 | mssql_linked_server | Cross-domain pivot |
| 12 | mssql_xp_cmdshell | Code execution |

## State Management

### Shared State Objects

All agents access shared state via Redis:

```python
SharedRedTeamState:
    operation_id: str
    credentials: list[Credential]  # Auto-broadcast on discovery
    hashes: list[Hash]             # Tracked for cracking status
    users: list[User]              # Enumerated users
    hosts: list[Host]              # Discovered hosts
    shares: list[Share]            # Accessible shares
    vulnerabilities: list[VulnerabilityInfo]
    domains: set[str]              # Discovered domains
```

### Automatic Broadcasting

When any agent discovers a credential:

1. Credential is added to shared state
2. Redis pub/sub broadcasts to all agents
3. All agents can use the credential immediately

## Task Flow Example

```text
┌─────────────┐    dispatch_credential_access     ┌─────────────────┐
│ Orchestrator│ ─────────────────────────────────▶│ CREDENTIAL_ACCESS│
│             │                                    │                  │
│ "Found user │    task: secretsdump              │ Runs secretsdump │
│  with creds"│    target: 10.0.0.1               │ on DC            │
└─────────────┘                                    └────────┬─────────┘
                                                           │
                    ◀──────────────────────────────────────┘
                    Results: Administrator:500:aad3b...:31d6c...

┌─────────────┐    dispatch_crack_hash            ┌─────────────────┐
│ Orchestrator│ ─────────────────────────────────▶│    CRACKER      │
│             │                                    │                  │
│ "Got admin  │    hash: 31d6c...                 │ Runs hashcat    │
│  hash"      │    priority: 2                    │                  │
└─────────────┘                                    └────────┬─────────┘
                                                           │
                    ◀──────────────────────────────────────┘
                    Results: Administrator:P@ssw0rd!

┌─────────────┐    dispatch_lateral_movement      ┌─────────────────┐
│ Orchestrator│ ─────────────────────────────────▶│    LATERAL      │
│             │                                    │                  │
│ "Test DA    │    targets: all hosts             │ psexec to hosts │
│  access"    │    credential: P@ssw0rd!          │ secretsdump     │
└─────────────┘                                    └────────┬─────────┘
                                                           │
                    ◀──────────────────────────────────────┘
                    Results: Pwn3d! on 5/5 hosts

┌─────────────┐
│ Orchestrator│
│             │
│ announce_domain_admin()
│ complete_operation()
└─────────────┘
```

## Anti-Patterns to Avoid

### Orchestrator Should NOT

1. **Execute reconnaissance tools directly**
   - Wrong: Orchestrator calls `nmap_scan`, `enumerate_users`
   - Right: Orchestrator dispatches to RECON

2. **Execute credential attacks directly**
   - Wrong: Orchestrator calls `secretsdump`, `kerberoast`
   - Right: Orchestrator dispatches to CREDENTIAL_ACCESS

3. **Run exploitation tools**
   - Wrong: Orchestrator calls `certipy_req_esc1`, `mssql_exec_linked`
   - Right: Orchestrator queues vulnerability for PRIVESC

4. **Perform lateral movement**
   - Wrong: Orchestrator calls `psexec`, `evil_winrm`
   - Right: Orchestrator dispatches to LATERAL

5. **Crack hashes**
   - Wrong: Orchestrator calls `hashcat`, `john`
   - Right: Orchestrator dispatches to CRACKER

### Workers Should NOT

1. **Make strategic decisions**
   - Workers execute assigned tasks, not decide what to attack next

2. **Dispatch to other workers**
   - Only the orchestrator coordinates between agents

3. **Hold onto results**
   - Results should be reported immediately for broadcast

## Debugging and Manual Testing

### Manually Running Tools on Agent Pods

For debugging or testing specific tools, you can exec into a worker pod and run
tools directly without going through the orchestrator dispatch system.

#### Method 1: Direct Python Tool Invocation

Exec into the appropriate agent pod and call the tool class directly:

```bash
# Run SYSVOL script search on credential-access agent
kubectl -n attack-simulation exec -it ares-credential-access-agent-0 -- python -c "
from ares.tools.red import SharePilferingTools
tools = SharePilferingTools()
result = tools.sysvol_script_search(
    target='10.1.2.240',
    username='samwell.tarly',
    password='Heartsbane',  # pragma: allowlist secret
    domain='north.sevenkingdoms.local'
)
print(result)
"

# Run secretsdump on credential-access agent
kubectl -n attack-simulation exec -it ares-credential-access-agent-0 -- python -c "
from ares.tools.red import CredentialHarvestingTools
tools = CredentialHarvestingTools()
result = tools.secretsdump(
    target='10.1.2.240',
    username='administrator',
    password='AdminPass123',  # pragma: allowlist secret
    domain='north.sevenkingdoms.local'
)
print(result)
"

# Run nmap scan on recon agent
kubectl -n attack-simulation exec -it ares-recon-agent-0 -- python -c "
from ares.tools.red import NetworkEnumerationTools
tools = NetworkEnumerationTools()
result = tools.nmap_scan(target='10.1.2.0/24', scan_type='quick')
print(result)
"
```

#### Method 2: Direct Shell Command

Run the underlying tool binaries directly:

```bash
# Run smbclient directly
kubectl -n attack-simulation exec -it ares-credential-access-agent-0 -- \
    smbclient '//10.1.2.240/SYSVOL' -U 'DOMAIN/user%password' -c 'ls'

# Run netexec directly
kubectl -n attack-simulation exec -it ares-credential-access-agent-0 -- \
    netexec smb 10.1.2.240 -u 'user' -p 'password' -d 'DOMAIN' --shares

# Run secretsdump directly
kubectl -n attack-simulation exec -it ares-credential-access-agent-0 -- \
    secretsdump.py 'DOMAIN/user:password@10.1.2.240'
```

#### Available Tool Classes by Agent

| Agent Pod | Tool Classes |
| --------- | ------------ |
| `ares-recon-agent-*` | `NetworkEnumerationTools`, `BloodHoundTools` |
| `ares-credential-access-agent-*` | `CredentialDiscoveryTools`, `CredentialHarvestingTools`, `SharePilferingTools` |
| `ares-cracker-agent-*` | `CrackingTools` |
| `ares-acl-agent-*` | `ACLExploitTools` |
| `ares-privesc-agent-*` | `CertipyTools`, `DelegationTools`, `MSSQLTools`, `CVEExploitTools` |
| `ares-lateral-movement-agent-*` | `LateralMovementTools`, `CredentialHarvestingTools` |
| `ares-coercion-agent-*` | `CoercionTools`, `CoercionNetworkTools` |

#### Importing Tool Classes

All red team tools can be imported from `ares.tools.red`:

```python
from ares.tools.red import (
    NetworkEnumerationTools,
    BloodHoundTools,
    CredentialDiscoveryTools,
    CredentialHarvestingTools,
    SharePilferingTools,
    CrackingTools,
    ACLExploitTools,
    CertipyTools,
    DelegationTools,
    MSSQLTools,
    LateralMovementTools,
    CoercionTools,
)
```

#### Testing with State

To test tools that need shared state (for credential resolution or result
reporting):

```python
kubectl -n attack-simulation exec -it ares-credential-access-agent-0 -- python -c "
from ares.core.models import SharedRedTeamState, Target
from ares.tools.red import SharePilferingTools

# Create minimal state
state = SharedRedTeamState(operation_id='test-op')
state.target = Target(ip='10.1.2.240', hostname='winterfell', domain='north.sevenkingdoms.local')

# Initialize tools with state
tools = SharePilferingTools()
tools.set_state(state)

# Run tool - credentials found will be added to state
result = tools.sysvol_script_search(
    target='10.1.2.240',
    username='samwell.tarly',
    password='Heartsbane',  # pragma: allowlist secret
    domain='north.sevenkingdoms.local'
)
print(result)

# Check if any credentials were extracted
print(f'Credentials found: {len(state.all_credentials)}')
for cred in state.all_credentials:
    print(f'  {cred.domain}\\\\{cred.username}: {cred.password}')
"
```

## File Reference

- `src/ares/core/orchestrator.py` - Main orchestrator coordination engine
- `src/ares/core/orchestrator_service.py` - Orchestrator service (K8s pod)
- `src/ares/core/orchestrator_client.py` - Client for submitting operations
- `src/ares/core/dispatcher.py` - Task routing and state management
- `src/ares/core/factories/red_agents.py` - Agent creation and toolset assignment
- `src/ares/templates/redteam/agents/recon.md.jinja` - RECON agent instructions
- `src/ares/templates/redteam/agents/credential_access.md.jinja` - CRED_ACCESS
- `src/ares/templates/redteam/agents/privesc.md.jinja` - PRIVESC instructions
- `src/ares/templates/redteam/agents/lateral.md.jinja` - LATERAL instructions
- `src/ares/templates/redteam/agents/acl.md.jinja` - ACL instructions
- `src/ares/templates/redteam/agents/cracker.md.jinja` - CRACKER instructions
- `src/ares/templates/redteam/agents/coercion.md.jinja` - COERCION instructions
- `src/ares/tools/red/` - Tool implementations

## Installed Tools by Agent Role

Each agent pod has role-specific pentesting tools installed via Ansible. Tool
availability can vary by distro and role flags.

### Base Tools (All Agents)

All agents inherit these foundational tools:

- **Runtime**: python3, pip3, uv, rust/cargo (via rustup), pipx
- **Utilities**: git, curl, wget, netcat-traditional
- **Build**: build-essential, libffi-dev, libssl-dev
- **Python packages**: python-dotenv, dreadnode, rigging, pydantic, asyncio

### Orchestrator Service Pod

- **Python runtime**: python3, pip3, dreadnode SDK
- **Redis client**: For dispatcher and state management
- **Kubernetes client**: For pod discovery and health monitoring
- **No pentesting tools**: Orchestrator only coordinates, never executes tools directly

### RECON Agent

- **Network scanning**: nmap
- **LDAP**: ldap-utils (ldapsearch)
- **SMB enumeration**: enum4linux, enum4linux-ng, samba-common-bin (rpcclient)
- **DNS**: dnsutils (dig, nslookup), whois, adidnsdump
- **AD tools**: NetExec (netexec, nxc, nxcdb), bloodhound-python
- **Impacket suite**: GetNPUsers, GetUserSPNs

### CREDENTIAL_ACCESS Agent

- **LDAP**: ldap-utils (ldapsearch)
- **SMB**: smbclient, samba-common-bin (rpcclient)
- **AD tools**: NetExec (netexec, nxc, nxcdb), sprayhound,
  targetedKerberoast, lsassy
- **Impacket suite**: GetNPUsers, secretsdump

### CRACKER Agent

- **Cracking**: hashcat, John the Ripper (john)
- **Wordlists**: rockyou, SecLists (password lists)
- **GPU support** (when enabled): ocl-icd-libopencl1, opencl-headers, clinfo

### ACL Agent

- **ACL abuse**: bloodyAD, pywhisker, targetedKerberoast
- **SMB**: samba-common-bin (rpcclient)
- **Impacket**: dacledit (impacket-dacledit)

### PRIVESC Agent

- **ADCS**: certipy-ad (certipy)
- **Kerberos**: noPac
- **Impacket suite**: getST, getTGT, rbcd, mssqlclient, raiseChild
- **Windows privesc binaries**: PrintSpoofer, GodPotato, SweetPotato,
  KrbRelayUp, SharpGPOAbuse, Seatbelt, SharpUp, RunasCs
- **Privesc scripts**: PowerUp, PowerUpSQL, WinPEAS, LinPEAS
- **Exploits**: PrintNightmare, SCMUACBypass (optional)

### LATERAL Agent

- **Remote access**: evil-winrm, xfreerdp (freerdp2/3), sshpass
- **SMB**: smbclient
- **Impacket suite**: psexec, wmiexec, smbexec, secretsdump

### COERCION Agent

- **Coercion tools**: Coercer, PetitPotam, dfscoerce
- **Relay tools**: krbrelayx (addspn, dnstool, krbrelayx tools)
- **Impacket**: ntlmrelayx (impacket-ntlmrelayx)
