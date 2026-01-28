# Red Team Multi-Agent Architecture

This document describes the design and operation of the Ares red team
multi-agent system.

## Overview

The red team system uses a **coordinator/worker architecture** where a central
orchestrator delegates tasks to specialized worker agents. Each agent runs in
its own Kubernetes pod with role-specific tools installed.

```text
┌─────────────────────────────────────────────────────────────────┐
│                        Orchestrator                              │
│                    (RECON Agent Pod)                             │
│                                                                  │
│  Responsibilities:                                               │
│  - Initial network reconnaissance                                │
│  - Asset discovery and enumeration                               │
│  - Attack path identification                                    │
│  - Task dispatch to specialized workers                          │
│  - Progress monitoring and coordination                          │
│  - Operation completion decision                                 │
└─────────────────────┬───────────────────────────────────────────┘
                      │ Redis pub/sub + task queues
        ┌─────────────┼─────────────┬─────────────┬─────────────┐
        ▼             ▼             ▼             ▼             ▼
┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐
│ CREDENTIAL│ │  CRACKER  │ │    ACL    │ │  PRIVESC  │ │  LATERAL  │
│  ACCESS   │ │           │ │           │ │           │ │           │
└───────────┘ └───────────┘ └───────────┘ └───────────┘ └───────────┘
        │             │             │             │             │
        ▼             ▼             ▼             ▼             ▼
   secretsdump    hashcat      bloodyAD      certipy      psexec
   kerberoast     john         pywhisker     mssqlclient  evil-winrm
   asrep_roast                 dacledit      rbcd         wmiexec
   password_spray                            delegation   smbexec
```

## Design Principles

### 1. Orchestrator Coordinates, Workers Execute

The orchestrator (RECON agent) **never executes exploitation tools directly**.
It:

- Gathers information through passive enumeration
- Identifies attack opportunities
- Dispatches tasks to appropriate worker agents
- Monitors progress and makes strategic decisions

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

### Orchestrator (RECON)

**Purpose**: Central coordinator with the "big picture" view.

**Tools Available**:

- `NetworkEnumerationTools` - nmap, user/share enumeration, domain info
- `BloodHoundTools` - AD relationship mapping
- `RedTeamReportingTools` - status reporting, operation control

**Does NOT Have**:

- Credential harvesting tools (secretsdump, kerberoast)
- Exploitation tools (certipy, mssqlclient)
- Lateral movement tools (psexec, evil-winrm)
- Cracking tools (hashcat, john)

**Dispatch Tools**:

- `dispatch_credential_access` - CREDENTIAL_ACCESS, password attacks, hash
  extraction
- `dispatch_crack_hash` - CRACKER, hash cracking
- `dispatch_acl_analysis` - ACL, ACL abuse paths
- `dispatch_lateral_movement` - LATERAL, host compromise
- `queue_vulnerability_for_exploitation` - PRIVESC, ADCS, delegation, MSSQL
- `start_coercion` - COERCION, NTLM coercion/relay

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

The orchestrator performs passive enumeration:

```text
1. nmap_scan - Discover live hosts and services
2. enumerate_users - Get domain user list
3. enumerate_shares - Find accessible shares
4. get_domain_info - Domain controllers, trusts, etc.
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
1. dispatch_credential_access(task="secretsdump", targets="ALL_DCs")
   → Extracts NTLM hashes, looks for krbtgt/Administrator

2. dispatch_credential_access(task="kerberoast", ...)
   → Finds service accounts with SPNs

3. dispatch_credential_access(task="asrep_roast", ...)
   → Finds accounts without pre-auth

4. dispatch_crack_hash for any new hashes
   → Attempts offline cracking

5. REPEAT with any newly cracked credentials
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

1. **Execute credential attacks directly**
   - Wrong: Orchestrator calls `secretsdump`, `kerberoast`
   - Right: Orchestrator dispatches to CREDENTIAL_ACCESS

2. **Run exploitation tools**
   - Wrong: Orchestrator calls `certipy_req_esc1`, `mssql_exec_linked`
   - Right: Orchestrator queues vulnerability for PRIVESC

3. **Perform lateral movement**
   - Wrong: Orchestrator calls `psexec`, `evil_winrm`
   - Right: Orchestrator dispatches to LATERAL

4. **Crack hashes**
   - Wrong: Orchestrator calls `hashcat`, `john`
   - Right: Orchestrator dispatches to CRACKER

### Workers Should NOT

1. **Make strategic decisions**
   - Workers execute assigned tasks, not decide what to attack next

2. **Dispatch to other workers**
   - Only the orchestrator coordinates between agents

3. **Hold onto results**
   - Results should be reported immediately for broadcast

## File Reference

- `src/ares/core/factories/red_agents.py` - Agent creation and toolset
  assignment
- `src/ares/core/dispatcher.py` - Task routing and state management
- `src/ares/templates/redteam/agents/recon.md.jinja` - Orchestrator
  instructions
- `src/ares/templates/redteam/agents/credential_access.md.jinja` -
  CREDENTIAL_ACCESS instructions
- `src/ares/templates/redteam/agents/privesc.md.jinja` - PRIVESC instructions
- `src/ares/templates/redteam/agents/lateral.md.jinja` - LATERAL instructions
- `src/ares/templates/redteam/agents/acl.md.jinja` - ACL instructions
- `src/ares/templates/redteam/agents/cracker.md.jinja` - CRACKER instructions
- `src/ares/templates/redteam/agents/coercion.md.jinja` - COERCION
  instructions
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

### Orchestrator / RECON Agent

- **Network scanning**: nmap
- **LDAP**: ldap-utils (ldapsearch)
- **SMB enumeration**: enum4linux, enum4linux-ng, samba-common-bin
  (rpcclient)
- **DNS**: dnsutils (dig, nslookup), whois, adidnsdump
- **AD tools**: NetExec (netexec, nxc, nxcdb), bloodhound-python, certipy-ad
- **Impacket suite**: GetNPUsers, GetUserSPNs, secretsdump, regsecrets,
  ntlmrelayx, psexec, wmiexec, smbexec, rbcd, getST, getTGT, mssqlclient,
  raiseChild, ticketer

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
