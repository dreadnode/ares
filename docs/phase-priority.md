<!-- markdownlint-disable MD013 MD040 MD060 -->
<!-- Line length, fenced code language, and table style rules disabled for ASCII art and complex tables -->

# Ares Agent Utility by Engagement Phase

## Visual Phase Map

```
                          ENGAGEMENT PROGRESSION →
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                                                                 │
│  Phase 1         Phase 2          Phase 3         Phase 4        Phase 5       │
│  INITIAL         ENUMERATION      PRIVILEGE       LATERAL        DOMAIN        │
│  ACCESS          (Authed)         ESCALATION      MOVEMENT       DOMINANCE     │
│                                                                                 │
│  ════════════════════════════════════════════════════════════════════════════  │
│                                                                                 │
│  RECON       ████████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  │
│              ▲ Critical        ▲ Still useful   ▲ Diminishing   ▲ Minimal      │
│              Scanning          BloodHound       New targets     Done           │
│                                                                                 │
│  COERCION    ████████████████████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░  │
│              ▲ Responder       ▲ Relay attacks  ▲ ESC8/DC coerce ▲ Rare        │
│              LLMNR poison      LDAP relay       Kerberos relay                 │
│                                                                                 │
│  CRED_ACCESS ░░░░████████████████████████████████████████████████████████████  │
│              ▲ Spray only      ▲ Kerberoast     ▲ secretsdump   ▲ DC dump      │
│              Need usernames    AS-REP roast     Each host       Final loot     │
│                                                                                 │
│  CRACKER     ░░░░░░░░████████████████████████████████████████░░░░░░░░░░░░░░░░  │
│              ▲ Waiting         ▲ Peak utility   ▲ Steady        ▲ Done         │
│              No hashes yet     TGS/AS-REP       NTLM hashes     Have DA        │
│                                                                                 │
│  ACL         ░░░░░░░░░░░░░░░░██████████████████████████████░░░░░░░░░░░░░░░░░░  │
│              ▲ No creds        ▲ Map paths      ▲ Exploit       ▲ Minimal      │
│              Can't enumerate   BloodHound data  WriteDACL etc   Already DA     │
│                                                                                 │
│  PRIVESC     ░░░░░░░░░░░░░░░░░░░░██████████████████████████████████████████░░  │
│              ▲ No foothold     ▲ ADCS scan      ▲ Primary       ▲ Golden Tkt   │
│              Need access       Delegation enum  S4U, ESC1-8     DCSync         │
│                                                                                 │
│  LATERAL     ░░░░░░░░░░░░░░░░░░░░░░░░░░░░████████████████████████████████████  │
│              ▲ No creds        ▲ Limited        ▲ Building      ▲ DC access    │
│              Can't move        Few valid creds  Credential web  Final push     │
│                                                                                 │
│  ════════════════════════════════════════════════════════════════════════════  │
│                                                                                 │
│  Legend:  ████ High utility   ░░░░ Low/No utility                              │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Detailed Phase-by-Phase Breakdown

### Phase 1: Initial Access (No Credentials)

| Agent | Utility | What It Does | Limitations |
|-------|---------|--------------|-------------|
| **RECON** | Critical | Nmap scanning, SMB signing checks, enumerate anonymous shares, DNS recon | Can't do authenticated enum |
| **COERCION** | Critical | Responder for LLMNR/NBT-NS poisoning, capture NTLMv2 hashes | Need to wait for victim traffic |
| **CREDENTIAL_ACCESS** | Limited | Password spraying (if usernames found), username=password | No Kerberoast without valid auth |
| **CRACKER** | Idle | Waiting for hashes | No input yet |
| **ACL** | Useless | Requires authenticated LDAP access | Can't enumerate ACLs |
| **PRIVESC** | Useless | No foothold to escalate from | Needs initial access |
| **LATERAL** | Useless | No credentials to move with | Needs creds |

**Orchestrator Focus**: Dispatch RECON heavily, start COERCION listeners, queue spray attacks as usernames discovered.

---

### Phase 2: Authenticated Enumeration (First Valid Creds)

| Agent | Utility | What It Does | Limitations |
|-------|---------|--------------|-------------|
| **RECON** | Critical | BloodHound collection, authenticated LDAP enum, Certipy find | Most valuable phase |
| **CREDENTIAL_ACCESS** | Critical | Kerberoast all SPNs, AS-REP roast, LDAP description hunting, GPP passwords | Gold mine phase |
| **CRACKER** | High | Crack TGS-REP (Kerberoast), AS-REP hashes | Throughput-limited by GPU |
| **COERCION** | High | NTLM relay to LDAP (RBCD), relay to ADCS if found | Need relay targets |
| **ACL** | Growing | Analyze BloodHound paths, identify abusable ACLs | Need paths identified first |
| **PRIVESC** | Growing | Scan for ADCS misconfigs, enumerate delegation | Need vulns identified |
| **LATERAL** | Limited | Test initial creds on hosts | Often low-priv creds |

**Orchestrator Focus**: Heavy RECON for BloodHound, CREDENTIAL_ACCESS for Kerberoast, start queueing ACL paths.

---

### Phase 3: Privilege Escalation (Multiple Creds, Identified Paths)

| Agent | Utility | What It Does | Limitations |
|-------|---------|--------------|-------------|
| **PRIVESC** | Critical | S4U attacks (constrained delegation), ESC1/ESC4/ESC8, MSSQL impersonation, noPac | Primary escalation engine |
| **ACL** | Critical | Shadow credentials, password resets, WriteDACL abuse, targeted Kerberoast | Exploiting identified paths |
| **CREDENTIAL_ACCESS** | High | secretsdump on owned hosts, lsassy for live creds | Harvesting from compromises |
| **CRACKER** | High | Crack new NTLM hashes from secretsdump | Steady stream of hashes |
| **COERCION** | Situational | ESC8 relay to ADCS, DC coercion for delegation attacks | Specific scenarios |
| **RECON** | Diminishing | Scan new networks, enumerate new trusts | Most discovery done |
| **LATERAL** | Growing | Test new creds across hosts, expand footprint | Building credential web |

**Orchestrator Focus**: Prioritize vulnerability queue (ESC1 > delegation > ACL), PRIVESC and ACL are workhorses.

---

### Phase 4: Lateral Movement (Expanding Footprint)

| Agent | Utility | What It Does | Limitations |
|-------|---------|--------------|-------------|
| **LATERAL** | Critical | PSExec/WMI/WinRM to new hosts, validate admin access, secretsdump everywhere | Primary movement engine |
| **CREDENTIAL_ACCESS** | Critical | secretsdump each new host, hunt for DA sessions | Snowballing creds |
| **CRACKER** | High | Crack NTLM hashes from secretsdump | High volume of hashes |
| **PRIVESC** | Situational | Exploit new delegation paths, MSSQL linked servers | When new paths found |
| **ACL** | Situational | New ACL paths from expanded access | Usually paths exhausted |
| **COERCION** | Low | Specific relay scenarios | Mostly done |
| **RECON** | Minimal | Occasional new network discovery | Environment well-mapped |

**Orchestrator Focus**: LATERAL movement loop: access host → secretsdump → test new creds → repeat.

---

### Phase 5: Domain Dominance (Path to DA / Post-DA)

| Agent | Utility | What It Does | Limitations |
|-------|---------|--------------|-------------|
| **PRIVESC** | Critical | Golden Ticket, DCSync, krbtgt extraction, child→parent escalation | Final escalation |
| **LATERAL** | High | Access DC with obtained creds, validate DA | Execute final access |
| **CREDENTIAL_ACCESS** | High | secretsdump on DC (NTDS.dit), full domain dump | Final credential harvest |
| **CRACKER** | Low | Usually have what we need | DA achieved |
| **ACL** | Minimal | Already have DA | No longer needed |
| **COERCION** | Minimal | Already have DA | No longer needed |
| **RECON** | Minimal | Already have DA | No longer needed |

**Orchestrator Focus**: DCSync → Golden Ticket → announce_domain_admin → complete_operation.

---

## Agent Workload Distribution Over Time

```
Activity Level
     ▲
100% │                    ╭──╮
     │   ╭────╮          ╱    ╲         LATERAL
     │  ╱      ╲        ╱      ╲       ╭────────────╮
 75% │ ╱        ╲      ╱        ╲     ╱              ╲
     │╱  RECON   ╲    ╱ PRIVESC  ╲   ╱                ╲
     │            ╲  ╱            ╲ ╱                  ╲
 50% │             ╲╱              ╳                    ╲
     │         CREDENTIAL_ACCESS ╱ ╲                    ╲
     │         ───────────────────────                   ╲
 25% │    COERCION                                        ╲
     │    ─────────────╲
     │        ACL       ╲      CRACKER
     │        ────────────────────────
  0% └────────────────────────────────────────────────────▶
         Phase 1    Phase 2    Phase 3    Phase 4    Phase 5
```

---

## Critical Handoff Points

### 1. COERCION → CRACKER → CREDENTIAL_ACCESS

```
Responder captures NTLMv2 → CRACKER cracks → CREDENTIAL_ACCESS uses for Kerberoast
```

### 2. RECON → ACL/PRIVESC

```
BloodHound finds paths → ACL exploits WriteDACL → PRIVESC exploits delegation
```

### 3. CREDENTIAL_ACCESS → LATERAL → CREDENTIAL_ACCESS

```
Kerberoast gets SVC creds → LATERAL moves to host → secretsdump gets more creds
                    ↑_______________________________________|
```

### 4. PRIVESC → LATERAL → PRIVESC

```
S4U gets Admin ticket → LATERAL accesses DC → PRIVESC does DCSync
```

---

## Gaps & Recommendations

| Gap | Current State | Recommendation |
|-----|---------------|----------------|
| **No initial spray agent** | CREDENTIAL_ACCESS handles spray but needs usernames | Add username harvesting to RECON (LinkedIn scraping, email format guessing) |
| **COERCION underutilized mid-game** | Mostly used for initial foothold | Integrate with PRIVESC for ESC8 relay, printer bug coercion |
| **ACL peaks then drops** | Heavy in Phase 3, then idle | Could assist with persistence (AdminSDHolder modification) |
| **No dedicated persistence agent** | PRIVESC handles Golden Ticket | Consider post-DA persistence tasks (DSRM, custom SSP) |
| **RECON idle late-game** | Done after Phase 2 | Could do continuous monitoring for new assets/sessions |

---

## Suggested Orchestrator Dispatch Weights by Phase

```python
PHASE_WEIGHTS = {
    "initial_access": {
        "recon": 0.40,
        "coercion": 0.35,
        "credential_access": 0.20,
        "cracker": 0.05,
        "acl": 0.00,
        "privesc": 0.00,
        "lateral": 0.00,
    },
    "enumeration": {
        "recon": 0.30,
        "credential_access": 0.35,
        "cracker": 0.15,
        "coercion": 0.10,
        "acl": 0.05,
        "privesc": 0.05,
        "lateral": 0.00,
    },
    "privilege_escalation": {
        "privesc": 0.35,
        "acl": 0.25,
        "credential_access": 0.15,
        "cracker": 0.10,
        "lateral": 0.10,
        "coercion": 0.05,
        "recon": 0.00,
    },
    "lateral_movement": {
        "lateral": 0.40,
        "credential_access": 0.30,
        "cracker": 0.15,
        "privesc": 0.10,
        "acl": 0.05,
        "coercion": 0.00,
        "recon": 0.00,
    },
    "domain_dominance": {
        "privesc": 0.40,
        "lateral": 0.30,
        "credential_access": 0.25,
        "cracker": 0.05,
        "acl": 0.00,
        "coercion": 0.00,
        "recon": 0.00,
    },
}
```

---

## Phase Detection Heuristics

The orchestrator can detect which phase the engagement is in based on state:

```python
def detect_phase(state: SharedRedTeamState) -> str:
    """Determine current engagement phase from state."""

    # Phase 5: Domain Dominance
    if state.has_domain_admin or state.has_golden_ticket:
        return "domain_dominance"

    # Check for krbtgt or Administrator hash
    for h in state.all_hashes:
        if h.username.lower() in ("krbtgt", "administrator"):
            return "domain_dominance"

    # Phase 4: Lateral Movement (multiple admin creds, expanding footprint)
    admin_creds = [c for c in state.all_credentials if c.is_admin]
    owned_hosts = len([h for h in state.all_hosts if h.owned])
    if len(admin_creds) >= 3 or owned_hosts >= 5:
        return "lateral_movement"

    # Phase 3: Privilege Escalation (vulns identified, paths available)
    if state.discovered_vulnerabilities or admin_creds:
        return "privilege_escalation"

    # Phase 2: Enumeration (have valid creds)
    if state.all_credentials:
        return "enumeration"

    # Phase 1: Initial Access (no creds yet)
    return "initial_access"
```

---

## Attack Chain Examples by Phase

### Phase 1 → 2: Initial Foothold

```
COERCION: Responder captures jsmith NTLMv2 hash
    ↓
CRACKER: Cracks hash → "Summer2024!"
    ↓
CREDENTIAL_ACCESS: Validates cred, adds to state
    ↓
→ Transition to Phase 2
```

### Phase 2 → 3: Finding Attack Paths

```
RECON: BloodHound collection with jsmith creds
    ↓
RECON: Identifies SVC_SQL has constrained delegation to DC
    ↓
CREDENTIAL_ACCESS: Kerberoasts SVC_SQL
    ↓
CRACKER: Cracks TGS → "SqlServer123!"
    ↓
→ Transition to Phase 3 (delegation vuln + creds)
```

### Phase 3 → 4: Privilege Escalation

```
PRIVESC: S4U attack with SVC_SQL → Administrator ticket for DC
    ↓
LATERAL: PSExec to DC with Kerberos ticket
    ↓
CREDENTIAL_ACCESS: secretsdump on DC
    ↓
→ Transition to Phase 4/5 (DA access achieved)
```

### Phase 5: Domain Dominance

```
CREDENTIAL_ACCESS: Extract krbtgt hash via DCSync
    ↓
PRIVESC: Forge Golden Ticket
    ↓
ORCHESTRATOR: announce_domain_admin()
    ↓
ORCHESTRATOR: complete_operation()
```
