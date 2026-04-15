<!-- markdownlint-disable MD013 MD060 -->

# Red Team Multi-Agent Architecture

This document describes the design and operation of the Ares red team
multi-agent system.

## Overview

The red team system uses a **coordinator/worker architecture** where a central
orchestrator delegates tasks to specialized worker agents. Each agent runs in
its own container (Kubernetes pod or EC2 instance) with role-specific tools
installed.

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

## Agent Quick Reference

Quick reference table for all red team agents with their key configuration and
tool assignments. For detailed responsibilities, see sections below.

| Agent | Purpose | Pod Selector | Max Steps | Tool Classes |
|-------|---------|--------------|-----------|--------------|
| **ORCHESTRATOR** | Central coordinator (dispatches, never executes) | `app.kubernetes.io/name=ares-orchestrator` | 200 | `OrchestratorTools`, `RedTeamReportingTools` |
| **RECON** | Network scanning, enumeration, BloodHound | `ares.dreadnode.io/role=recon` | 100 | `NetworkEnumerationTools`, `BloodHoundTools`, `RedTeamReportingTools` |
| **CREDENTIAL_ACCESS** | Password attacks, hash extraction | `ares.dreadnode.io/role=credential_access` | 100 | `CredentialDiscoveryTools`, `CredentialHarvestingTools`, `SharePilferingTools`, `GMSATools` |
| **CRACKER** | Offline hash cracking | `ares.dreadnode.io/role=cracker` | 150 | `CrackingTools`, `CrackerCallbackTools` |
| **ACL** | AD ACL abuse attacks | `ares.dreadnode.io/role=acl` | 150 | `ACLExploitTools` |
| **PRIVESC** | Privilege escalation exploitation | `ares.dreadnode.io/role=privesc` | 100 | `CertipyTools`, `DelegationTools`, `MSSQLTools`, `CVEExploitTools`, `GoldenTicketTools`, `TrustAttackTools`, `LateralMovementTools`, `CredentialHarvestingTools` |
| **LATERAL** | Host compromise, credential harvesting | `ares.dreadnode.io/role=lateral` | 300 | `LateralMovementTools`, `CredentialHarvestingTools`, `SharePilferingTools`, `PostureValidationTools`, `LateralCallbackTools` |
| **COERCION** | NTLM coercion and relay attacks | `ares.dreadnode.io/role=coercion` | 30 | `CoercionTools`, `CoercionNetworkTools` |

### Configuration Sources

- **Pod selectors**: `config/ares.yaml`
- **Tool assignments**: `config/ares.yaml` → per-agent `capabilities`
- **Max steps defaults**: `config/ares.yaml` → per-agent `max_steps`
- **Agent instructions**: `ares-orchestrator/src/` prompt templates

### Model Selection

Models can be configured via environment variables (in order of precedence):

| Variable | Scope |
|----------|-------|
| `ARES_AGENT_<ROLE>_MODEL` | Role-specific (e.g., `ARES_AGENT_PRIVESC_MODEL`) |
| `ARES_ORCHESTRATOR_MODEL` | Orchestrator only |
| `ARES_WORKER_MODEL` | All workers |
| `ARES_MODEL` | Global default |

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

- `CredentialDiscoveryTools` - password spray, username=password, LDAP
  descriptions
- `CredentialHarvestingTools` - secretsdump, kerberoast, asrep_roast
- `SharePilferingTools` - GPP passwords, SYSVOL scripts, share spidering
- `GMSATools` - gMSA password extraction

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
- `LateralMovementTools` - psexec for S4U→DA chain completion
- `CredentialHarvestingTools` - secretsdump for S4U→DA chain completion

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

```text
# ADCS vulnerabilities
queue_vulnerability_for_exploitation(
    vuln_type="ADCS_ESC1",
    target="CA-NAME",
    details={"template": "VulnTemplate", "ca": "domain\\CA"}
)

# Delegation attacks
queue_vulnerability_for_exploitation(
    vuln_type="constrained_delegation",
    target="SERVER-NAME",
    details={"allowed_to": "TARGET-SPN"}
)

# MSSQL exploitation
queue_vulnerability_for_exploitation(
    vuln_type="mssql_linked_server",
    target="SQL-SERVER-IP",
    details={"username": "sql_user", "domain": "DOMAIN.COM"}
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

## Task Throttling and Phase-Aware Dispatch

The dispatcher uses intelligent throttling to prevent LLM API rate limit storms
while ensuring all worker agents stay productive.
See [Phase Priority Guide](phase-priority.md) for detailed analysis.

### Throttling Behavior

1. **LLM Task Limit**: Only LLM-using tasks count against `max_concurrent_tasks`
   - Non-LLM tasks (`crack`, `command`) always allowed
2. **Per-Role Minimum Slots**: Each role gets at least `min_slots_per_role` tasks
   - Prevents worker starvation - no agent sits completely idle
3. **Phase-Aware Priority**: Tasks are boosted or lowered based on operation phase
   - Early phase: RECON and COERCION boosted (network discovery, Responder)
   - Mid phase: LATERAL and CREDENTIAL_ACCESS boosted (credential expansion)
   - Late phase: EXPLOIT boosted (final push to DA)

### Operation Phases

The dispatcher automatically detects the current engagement phase:

| Phase                 | Detection Criteria              | High-Priority Agents             |
| --------------------- | ------------------------------- | -------------------------------- |
| `initial_access`      | No credentials yet              | RECON, COERCION                  |
| `enumeration`         | Have first valid creds          | CREDENTIAL_ACCESS, RECON         |
| `privilege_escalation`| Vulns found OR admin creds      | PRIVESC, ACL, CREDENTIAL_ACCESS  |
| `lateral_movement`    | 3+ admin creds OR 5+ owned      | LATERAL, CREDENTIAL_ACCESS       |
| `domain_dominance`    | DA achieved OR krbtgt hash      | PRIVESC, LATERAL                 |

### Configuration

Phase detection thresholds in `config/ares.yaml`:

```yaml
phase_detection:
  lateral_movement_admin_creds: 3  # >= this many admin credentials
  lateral_movement_owned_hosts: 5  # >= this many owned hosts
  min_slots_per_role: 1            # minimum task slots per worker
```

### Phase Transition Logging

The dispatcher logs phase transitions for observability:

```text
INFO | Operation phase transition: initial_access → enumeration
INFO | Operation phase transition: enumeration → privilege_escalation
```

## State Management

### Pattern: Write-Through Cache

Redis is the **durable store**. In-memory dicts are **write-through caches**.

#### Pattern

- **Write**: Persist to Redis (immediately or via background task), update memory
- **Read**: Read from memory (assumes write-through keeps it in sync)
- **Recovery**: Hydrate all state from Redis before any decisions

#### Assumptions

1. Single orchestrator instance per operation
2. No external mutations to Redis during operation
3. Recovery path (`recover_operation()`) always runs before resuming

#### Known Gaps

- `SharedRedTeamState.add_*()` methods are memory-first with async persist
- If Redis write fails, state diverges (logged, checkpoint is safety net)

### Shared State Objects

All agents access shared state via Redis:

```text
SharedRedTeamState:
    operation_id: String
    credentials: Vec<Credential>          // Auto-broadcast on discovery
    hashes: Vec<Hash>                     // Tracked for cracking status
    users: Vec<User>                      // Enumerated users
    hosts: Vec<Host>                      // Discovered hosts
    shares: Vec<Share>                    // Accessible shares
    vulnerabilities: Vec<VulnerabilityInfo>
    domains: HashSet<String>              // Discovered domains
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

#### Direct Shell Commands

Run the underlying tool binaries directly on the appropriate agent pod:

```bash
# Run smbclient directly
kubectl -n attack-simulation exec -it ares-credential-access-agent-0 -- \
    smbclient '//10.1.2.240/SYSVOL' -U 'DOMAIN/user%password' -c 'ls'

# Run netexec directly (on recon agent - netexec is only installed there)
kubectl -n attack-simulation exec -it ares-recon-agent-0 -- \
    netexec smb 10.1.2.240 -u 'user' -p 'password' -d 'DOMAIN' --shares

# Run secretsdump directly
kubectl -n attack-simulation exec -it ares-credential-access-agent-0 -- \
    secretsdump.py 'DOMAIN/user:password@10.1.2.240'

# Run nmap directly
kubectl -n attack-simulation exec -it ares-recon-agent-0 -- \
    nmap -sV --top-ports 1000 10.1.2.0/24
```

#### Available Tools by Agent Pod

| Agent Pod | Installed Tools |
| --------- | --------------- |
| `ares-recon-agent-*` | nmap, netexec, enum4linux, bloodhound-python, certipy, ldapsearch, adidnsdump |
| `ares-credential-access-agent-*` | secretsdump, sprayhound, lsassy, gMSADumper, targetedKerberoast, smbclient |
| `ares-cracker-agent-*` | hashcat, john, wordlists (rockyou, seclists) |
| `ares-acl-agent-*` | bloodyAD, pywhisker, dacledit, targetedKerberoast |
| `ares-privesc-agent-*` | certipy, krbrelayx, nopac, impacket-findDelegation, impacket-mssqlclient |
| `ares-lateral-movement-agent-*` | evil-winrm, xfreerdp, pth-winexe, impacket-psexec, impacket-wmiexec, impacket-smbexec |
| `ares-coercion-agent-*` | responder, ntlmrelayx, coercer, petitpotam, mitm6 |

## File Reference

**Core Components**:

- `ares-orchestrator/src/` - Main orchestrator coordination loop, task dispatch, LLM runner
- `ares-orchestrator/src/dispatcher/` - Task routing, throttling, and state management
- `ares-orchestrator/src/state/` - Operation state management
- `ares-orchestrator/src/config.rs` - Orchestrator configuration
- `ares-worker/src/` - Worker agent task loop, tool execution
- `ares-core/src/` - Shared models, state, Redis schema, telemetry

**CLI**:

- `ares-cli/src/cli.rs` - CLI command definitions
- `ares-cli/src/ops/` - Red team operation commands
- `ares-cli/src/blue/` - Blue team investigation commands
- `ares-cli/src/transport.rs` - K8s/EC2 transport layer

**Configuration**:

- `config/ares.yaml` - Production config (models, thresholds, timeouts, capabilities)

## Installed Tools by Agent Role

Each agent pod has role-specific pentesting tools installed via Ansible. Tool
availability can vary by distro and role flags.

### Base Tools (All Agents)

All agents inherit these foundational tools:

- **Runtime**: Rust binaries (ares-worker), python3, pip3
- **Utilities**: git, curl, wget, netcat-traditional, vim, jq, tmux, htop
- **Network diagnostics**: dnsutils (dig, nslookup), net-tools, iproute2, tcpdump, telnet
- **Debugging**: procps (ps, top), strace, lsof
- **Build**: build-essential, libffi-dev, libssl-dev

### Orchestrator Service Pod

- **Runtime**: Rust binary (ares-orchestrator)
- **Redis client**: For dispatcher and state management
- **No pentesting tools**: Orchestrator only coordinates, never executes tools directly

### RECON Agent

Provisioned by: `ansible/playbooks/ares/recon.yml` → `dreadnode.nimbus_range.recon_tools`

- **Network scanning**: nmap
- **LDAP**: ldapsearch (from ldap-utils)
- **SMB enumeration**: enum4linux, enum4linux-ng, rpcclient
- **DNS**: dig, nslookup, whois, adidnsdump
- **AD tools**: netexec, bloodhound-python, certipy
- **Impacket**: impacket-GetNPUsers, impacket-GetUserSPNs

### CREDENTIAL_ACCESS Agent

Provisioned by: `ansible/playbooks/ares/credential_access.yml` → `dreadnode.nimbus_range.credential_access_tools`

- **SMB**: smbclient, rpcclient
- **Password spraying**: sprayhound
- **Kerberoasting**: targetedKerberoast
- **Credential extraction**: lsassy, gMSADumper
- **Impacket**: impacket-GetNPUsers, impacket-GetUserSPNs, impacket-secretsdump

> **Note**: netexec is NOT installed on this agent (only on RECON).

### CRACKER Agent

Provisioned by: `ansible/playbooks/ares/cracker.yml` → `dreadnode.nimbus_range.cracking_tools`

- **Cracking**: hashcat, john
- **Wordlists**: rockyou (`/usr/share/wordlists/rockyou.txt`), seclists (`/usr/share/wordlists/seclists/`)
- **GPU support** (when enabled): ocl-icd-libopencl1, opencl-headers, clinfo

### ACL Agent

Provisioned by: `ansible/playbooks/ares/acl_abuse.yml` → `dreadnode.nimbus_range.acl_tools`

- **ACL abuse**: bloodyAD, pywhisker
- **Kerberoasting**: targetedKerberoast
- **SMB**: rpcclient
- **Impacket**: impacket-dacledit

### PRIVESC Agent

Provisioned by: `ansible/playbooks/ares/privesc.yml` → `dreadnode.nimbus_range.privesc_tools`

- **ADCS**: certipy
- **Credential extraction**: lsassy
- **CVE exploits**: nopac, printnightmare, zerologon
- **Kerberos relay**: krbrelayx, printerbug, addspn, dnstool
- **Impacket**: impacket-findDelegation, impacket-getST, impacket-getTGT, impacket-rbcd,
  impacket-addcomputer, impacket-lookupsid, impacket-mssqlclient, impacket-raiseChild,
  impacket-ticketer, impacket-secretsdump, impacket-psexec
- **Windows potato exploits**: PrintSpoofer, GodPotato, SweetPotato
- **Kerberos privesc**: KrbRelayUp
- **GPO abuse**: SharpGPOAbuse, pygpoabuse
- **Windows enumeration**: Seatbelt, SharpUp
- **User impersonation**: RunasCs
- **PowerShell scripts**: PowerUp, PowerUpSQL
- **PEAS enumeration**: winPEAS, linPEAS
- **UAC bypass**: SCMUACBypass

### LATERAL Agent

Provisioned by: `ansible/playbooks/ares/lateral_movement.yml` → `dreadnode.nimbus_range.lateral_movement_tools`

- **WinRM**: evil-winrm
- **RDP**: xfreerdp (pass-the-hash capable)
- **SSH**: sshpass
- **SMB**: smbclient
- **Pivoting**: proxychains4
- **Pass-the-Hash**: pth-winexe, pth-smbclient, pth-rpcclient, pth-net, pth-wmic (from passing-the-hash package)
- **Impacket**: impacket-psexec, impacket-wmiexec, impacket-smbexec, impacket-secretsdump

### COERCION Agent

Provisioned by: `ansible/playbooks/ares/coercion.yml` → `dreadnode.nimbus_range.coercion_tools`

- **Poisoning**: responder, mitm6
- **Coercion**: coercer, petitpotam, dfscoerce
- **Kerberos relay**: krbrelayx, printerbug, addspn, dnstool
- **NTLM relay**: impacket-ntlmrelayx
