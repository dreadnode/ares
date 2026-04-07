# Redis Schema Contract for Ares Rust CLI Migration

This document is the definitive reference for all Redis keys,
data structures, serialization formats, and CLI operations used
by Ares. The Rust implementation MUST match this contract exactly
for backward compatibility.

---

## Table of Contents

1. [Key Naming Convention](#1-key-naming-convention)
2. [TTLs and Constants](#2-ttls-and-constants)
3. [Operation State Keys](#3-operation-state-keys-aresopop_id)
4. [Task Queue Keys](#4-task-queue-keys)
5. [Heartbeat Keys](#5-heartbeat-keys)
6. [Lock and Lifecycle Keys](#6-lock-and-lifecycle-keys)
7. [Pub/Sub Channels](#7-pubsub-channels)
8. [Data Models and Serialization](#8-data-models-and-serialization)
9. [Deduplication Strategies](#9-deduplication-strategies)
10. [CLI Commands Reference](#10-cli-commands-reference)
11. [Operation ID Generation](#11-operation-id-generation)
12. [Edge Cases and Legacy Formats](#12-edge-cases-and-legacy-formats)

---

## 1. Key Naming Convention

All keys follow a hierarchical colon-separated convention:

```text
ares:{namespace}:{identifier}:{suffix}
```

Examples:

- `ares:op:multiagent-abc12345:credentials` -- operation state
- `ares:tasks:cracker` -- task queue for cracker role
- `ares:heartbeat:ares-enum` -- agent heartbeat
- `ares:lock:multiagent-abc12345` -- operation lock

---

## 2. TTLs and Constants

| Constant | Value | Used By |
| --- | --- | --- |
| `DEFAULT_TTL` | 86400 (24h) | All `ares:op:*` state keys |
| `RESULT_TTL` | 86400 (24h) | `ares:results:{task_id}` |
| `HEARTBEAT_TTL` | 60s base, `max(60, t*2)` | `ares:heartbeat:{agent}` |
| `TASK_STATUS_TTL` | 86400 (24h) | `ares:task_status:{task_id}` |
| `DISCOVERY_TTL` | 3600 (1h) | `ares:discoveries:{op_id}` |
| `ENV_VARS_TTL` | 3600 (1h) | `ares:op:{op_id}:env_vars` |
| Lock TTL | 7200 (2h) | `ares:lock:{op_id}` |

TTL is refreshed on every write via `EXPIRE` after each mutation.

---

## 3. Operation State Keys (`ares:op:{op_id}:*`)

The key prefix is built as: `ares:op:{operation_id}`

### 3.1 Credentials -- HASH

**Key:** `ares:op:{op_id}:credentials`
**Type:** Redis HASH
**Dedup:** HSETNX (atomic -- returns 0 if field already exists)

**Hash Field (dedup key) format:**

```text
cred:{domain_lower}:{username_lower}:{md5(password)[:16]}
```

- domain: `.strip().lower()`
- username: `.strip().lower()`
- password hashed with MD5 (NOT for security, just dedup),
  first 16 hex chars

**Hash Value (JSON, compact `separators=(",",":")`):**

```json
{"id":"uuid","username":"svc_sql","password":"P@ssw0rd!","domain":"contoso.local","source":"kerberoast","parent_id":null,"attack_step":0}
```

Fields stored:

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| id | string | uuid4 | Unique chain tracking ID |
| username | string | "" | |
| password | string | "" | |
| domain | string | "" | |
| source | string | "" | Discovery method |
| parent_id | string/null | null | ID of cred/hash that enabled discovery |
| attack_step | int | 0 | Position in attack chain |

**Note:** `discovered_at` and `is_admin` are NOT serialized
to Redis.

**Legacy fallback:** If key type is LIST (pre-migration), items
are migrated to HASH on first read by `get_credentials()`.
The migration reads all LIST items, deletes the key, and
rewrites as HASH.

### 3.2 Hashes -- HASH

**Key:** `ares:op:{op_id}:hashes`
**Type:** Redis HASH
**Dedup:** HSETNX

**Hash Field (dedup key) format varies by hash type:**

**AS-REP** (`as-rep`, `asrep`, `krb5asrep`, or value
starts with `$krb5asrep$`):
`asrep:{domain}:{username}`

**Kerberoast** (`kerberoast`, `krb5tgs`, `tgs-rep`,
`tgs`, or value starts with `$krb5tgs$`):
`krb:{domain}:{username}:{etype}:{spn}` (extracted)
or `krb:{domain}:{username}:{hash_value[:32]}`
(fallback)

**NTLM/other**:
`ntlm:{domain}:{username}:{hash_value[:32]}`

Kerberoast SPN extraction from
`$krb5tgs$ETYPE$*user$realm$spn*$checksum$encrypted`:

- Split on `$` to get etype at index 2
- Split on `*` to get inner at index 1
- Split inner on `$` to get spn at index 2
- Result: `{etype}:{spn}`

**Hash Value (JSON):**

```json
{"id":"uuid","username":"svc_sql","hash_type":"NTLM","hash_value":"aad3b435...","domain":"contoso.local","source":"secretsdump","cracked_password":"","discovered_at":"2026-04-06T12:00:00+00:00","parent_id":null,"attack_step":0}
```

Fields stored:

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| id | string | uuid4 | |
| username | string | "" | |
| hash_type | string | "NTLM" | |
| hash_value | string | "" | Full hash value |
| domain | string | "" | |
| source | string | "" | |
| cracked_password | string | "" | null becomes "" |
| discovered_at | string/null | ISO 8601 datetime | |
| parent_id | string/null | null | |
| attack_step | int | 0 | |

### 3.3 Hosts -- LIST

**Key:** `ares:op:{op_id}:hosts`
**Type:** Redis LIST (RPUSH to append)

**Element (JSON):**

```json
{
  "ip": "192.168.58.10",
  "hostname": "dc01.contoso.local",
  "os": "Windows Server 2019",
  "roles": ["Domain Controller"],
  "services": ["88/tcp kerberos", "389/tcp ldap"],
  "is_dc": true
}
```

Fields:

| Field | Type | Default |
| --- | --- | --- |
| ip | string | "" |
| hostname | string | "" |
| os | string | "" |
| roles | string[] | [] |
| services | string[] | [] |
| is_dc | bool | false |

**Note:** `owned` field exists on the model but is NOT
serialized.

**Update:** Host updates do a full rewrite: read all, find by
IP, replace, delete+rpush atomically via pipeline.

### 3.4 Users -- LIST

**Key:** `ares:op:{op_id}:users`
**Type:** Redis LIST (RPUSH)

**Element (JSON):**

```json
{"username":"svc_sql","domain":"contoso.local","source":"netexec_user_enum"}
```

Fields:

| Field | Type | Default |
| --- | --- | --- |
| username | string | "" |
| domain | string | "" |
| source | string | "" |

**Note:** `description`, `is_admin` are on the model but NOT
serialized.

### 3.5 Shares -- HASH

**Key:** `ares:op:{op_id}:shares`
**Type:** Redis HASH
(HSET, not HSETNX -- overwrites are fine)

**Hash Field:** `{host_lower}:{name_lower}`

**Hash Value (JSON):**

```json
{
  "host": "192.168.58.10",
  "name": "SYSVOL",
  "permissions": "READ",
  "comment": "Logon server share"
}
```

Fields:

| Field | Type | Default |
| --- | --- | --- |
| host | string | "" |
| name | string | "" |
| permissions | string | "" |
| comment | string | "" |

### 3.6 Weaknesses -- HASH

**Key:** `ares:op:{op_id}:weaknesses`
**Type:** Redis HASH
**Dedup:** HSETNX

**Hash Field:** Normalized dedup key
(computed by caller, e.g., `unconstrained_delegation:dc01$`)
**Hash Value:** Full weakness description block
(markdown text, NOT JSON)

**Legacy fallback:** If key type is SET, migrates to HASH on
read. Legacy migration uses
`weakness[:64].replace("\n", " ").strip()` as the hash field
key.

### 3.7 Domains -- SET

**Key:** `ares:op:{op_id}:domains`
**Type:** Redis SET (SADD)

**Members:** Lowercase domain FQDNs
(e.g., `contoso.local`, `fabrikam.local`)

### 3.8 Vulnerabilities -- HASH

**Key:** `ares:op:{op_id}:vulns`
**Type:** Redis HASH
**Dedup:** HSETNX (by vuln_id)

**Hash Field:**
`{vuln_id}` (e.g.,
`constrained_delegation_192.168.58.240_svc_sql`)
**Hash Value (JSON):**

```json
{
  "vuln_id": "constrained_delegation_192.168.58.240_svc_sql",
  "vuln_type": "constrained_delegation",
  "target": "192.168.58.240",
  "discovered_by": "recon",
  "discovered_at": "2026-04-06T12:00:00+00:00",
  "details": {
    "target_ip": "192.168.58.240",
    "account_name": "svc_sql",
    "domain": "contoso.local"
  },
  "recommended_agent": "privesc",
  "priority": 5
}
```

Fields:

| Field | Type | Default |
| --- | --- | --- |
| vuln_id | string | "" |
| vuln_type | string | "" |
| target | string | "" |
| discovered_by | string | "" |
| discovered_at | string/null | ISO 8601 |
| details | object | {} |
| recommended_agent | string | "" |
| priority | int | 5 |

### 3.9 Exploited Vulnerabilities -- SET

**Key:** `ares:op:{op_id}:exploited`
**Type:** Redis SET (SADD)

**Members:** vuln_id strings

### 3.10 MITRE Techniques -- SET

**Key:** `ares:op:{op_id}:techniques`
**Type:** Redis SET (SADD)

**Members:** MITRE ATT&CK technique IDs
(e.g., `T1003.006`, `T1558.003`)

### 3.11 Meta (Scalars) -- HASH

**Key:** `ares:op:{op_id}:meta`
**Type:** Redis HASH

All values are JSON-serialized via
`json.dumps(value, default=str)`.

Known fields:

| Field | JSON Type | Description |
| --- | --- | --- |
| `has_domain_admin` | bool | DA achieved flag |
| `has_golden_ticket` | bool | Golden ticket forged flag |
| `domain_admin_path` | string | Attack path description |
| `da_hash_id` | string | ID of krbtgt hash for DA |
| `completed` | bool | Operation complete flag |
| `completed_at` | string | ISO 8601 timestamp |
| `started_at` | string | ISO 8601 timestamp |
| `target_ip` | string | Primary target IP |
| `target_domain` | string | Primary target domain |
| `target_ips` | string | Comma-separated IPs |
| `golden_ticket_capable_creds` | object | See below |

`golden_ticket_capable_creds` format:
`{"domain:username": [{domain, reason, dc_host, dc_ip}]}`

### 3.12 Domain Controller Map -- HASH

**Key:** `ares:op:{op_id}:dc_map`
**Type:** Redis HASH

**Hash Field:** `{domain_fqdn_lower}`
(e.g., `contoso.local`)
**Hash Value:** DC IP address string
(e.g., `192.168.58.10`)

### 3.13 NetBIOS Map -- HASH

**Key:** `ares:op:{op_id}:netbios_map`
**Type:** Redis HASH

**Hash Field:** `{netbios_lower}` (e.g., `contoso`)
**Hash Value:** FQDN string (e.g., `contoso.local`)

### 3.14 Artifacts -- HASH

**Key:** `ares:op:{op_id}:artifacts`
**Type:** Redis HASH

**Hash Field:** `{category/filename}`
(e.g., `sysvol/login.bat`)
**Hash Value:** Base64-encoded file content

### 3.15 Timeline -- LIST

**Key:** `ares:op:{op_id}:timeline`
**Type:** Redis LIST (RPUSH)

**Element (JSON):**

```json
{
  "id": "evt-uuid",
  "timestamp": "2026-04-06T12:00:00+00:00",
  "description": "Discovered credential via kerberoast",
  "evidence_ids": [],
  "mitre_techniques": ["T1558.003"],
  "confidence": 0.9,
  "source": "investigation"
}
```

### 3.16 Golden Tickets -- LIST

**Key:** `ares:op:{op_id}:golden_tickets`
**Type:** Redis LIST (RPUSH)

**Element (JSON):**

```json
{"domain":"contoso.local","ticket_path":"/tmp/golden.ccache","status":"success","created_at":"2026-04-06T12:00:00","krbtgt_hash":"aad3b435..."}
```

### 3.17 AdminSD Backdoors -- LIST

**Key:** `ares:op:{op_id}:adminsd_backdoors`
**Type:** Redis LIST (RPUSH)

**Element:** Plain string (backdoor identifier)

### 3.18 ACL Chains -- LIST

**Key:** `ares:op:{op_id}:acl_chains`
**Type:** Redis LIST (RPUSH)

**Element (JSON):**

```json
{"chain_id":"acl-uuid","steps":[...],"goal":"DA","domain":"contoso.local","is_complete":false,"progress":2}
```

**Update:** Full rewrite via pipeline
(read all, find by chain_id, replace, delete+rpush).

### 3.19 gMSA Accounts -- LIST

**Key:** `ares:op:{op_id}:gmsa_accounts`
**Type:** Redis LIST (RPUSH)

**Element (JSON):**

```json
{"account":"gmsa_svc$","domain":"contoso.local","principals_allowed":["Domain Computers"],"discovered_by":"ldap_search"}
```

### 3.20 Report -- STRING

**Key:** `ares:op:{op_id}:report`
**Type:** Redis STRING (SET with EX)

**Value:** Full markdown report content

### 3.21 Dedup Sets -- SET (multiple)

**Key pattern:** `ares:op:{op_id}:dedup:{set_name}`
**Type:** Redis SET (SADD)

Known set names (from `_PROCESSED_SET_MAP`):

| In-Memory Attribute | Redis Set Name |
| --- | --- |
| `processed_cred_expansion` | `cred_expansion` |
| `processed_hash_lateral` | `hash_lateral` |
| `processed_crack_requests` | `crack_requests` |
| `processed_asrep_domains` | `asrep_domains` |
| `processed_username_spray` | `username_spray` |
| `processed_password_spray` | `password_spray` |
| `processed_secretsdump` | `secretsdump` |
| `processed_esc8_servers` | `esc8_servers` |
| `processed_coerced_dcs` | `coerced_dcs` |
| `processed_writable_shares` | `writable_shares` |
| `processed_delegation_creds` | `delegation_creds` |
| `processed_adcs_servers` | `adcs_servers` |
| `processed_bloodhound_domains` | `bloodhound_domains` |
| `processed_spidered_shares` | `spidered_shares` |
| `processed_expansion_creds` | `expansion_creds` |
| `dispatched_acl_steps` | `acl_steps` |
| `scanned_targets` | `scanned_targets` |

**Members:** Vary by set type:

- `cred_expansion`: `"domain:username:password_hash"`
- `hash_lateral`: `"domain:username:hash"`
- `crack_requests`: hash submission identifiers
- `secretsdump`: `"host:user:domain"`
- `acl_steps`: `"chain:step"`
- `coerced_dcs`: DC IP addresses
- `scanned_targets`: IP/subnet strings

### 3.22 Pending Tasks -- HASH

**Key:** `ares:op:{op_id}:pending_tasks`
**Type:** Redis HASH

**Hash Field:** `{task_id}`
**Hash Value (JSON):** Serialized TaskInfo dict:

```json
{"task_id":"exploit_abc123","task_type":"exploit","assigned_agent":"privesc","status":"in_progress","created_at":"...","started_at":"...","completed_at":null,"last_activity_at":"...","params":{},"result":null,"error":null,"retry_count":0,"max_retries":3}
```

### 3.23 Completed Tasks -- HASH

**Key:** `ares:op:{op_id}:completed_tasks`
**Type:** Redis HASH

**Hash Field:** `{task_id}`
**Hash Value (JSON):** Serialized TaskResult dict:

```json
{"task_id":"exploit_abc123","success":true,"result":null,"error":null,"completed_at":"..."}
```

### 3.24 Vulnerability Type Failures -- HASH

**Key:** `ares:op:{op_id}:vuln_type_failures`
**Type:** Redis HASH

**Hash Field:** `{vuln_type}`
(e.g., `mssql_impersonation`)
**Hash Value:** Integer count string (via HINCRBY)

### 3.25 MSSQL Enum Dispatched -- SET

**Key:** `ares:op:{op_id}:mssql_enum_dispatched`
**Type:** Redis SET (SADD)

**Members:** Dispatch keys like
`mssql_enum:{ip}:{domain}\{username}`

### 3.26 Operation Status -- STRING

**Key:** `ares:op:{op_id}:status`
**Type:** Redis STRING (SET)

**Value (JSON):**

```json
{"status":"running","updated_at":"...","completed_at":"...","failed_at":"...","error":"..."}
```

Status values: `"submitted"`, `"running"`, `"completed"`,
`"failed"`

### 3.27 Environment Variables -- STRING

**Key:** `ares:op:{op_id}:env_vars`
**Type:** Redis STRING (SET with TTL 1h)

**Value:** JSON object of env var name -> value

```json
{"OPENAI_API_KEY":"sk-xxx","ARES_MODEL":"gpt-4.1"}
```

Orchestrator reads and deletes this key during processing.

---

## 4. Task Queue Keys

### 4.1 Task Queues -- LIST

**Key pattern:** `ares:tasks:{role}`
**Type:** Redis LIST

**Roles:** `cracker`, `lateral`, `acl`, `privesc`,
`coercion`, `recon`, `credential_access`

**Priority-based insertion:**

- Priority <= 2 (urgent): `RPUSH`
  (front of queue, processed first by BRPOP)
- Priority > 2 (normal): `LPUSH`
  (back of queue, FIFO)

Workers consume via `BRPOP` from the right side.

**Element (JSON via Pydantic `model_dump_json`):**

```json
{
  "task_id": "exploit_abc123def456",
  "task_type": "exploit",
  "source_agent": "orchestrator",
  "target_agent": "privesc",
  "payload": {
    "vuln_id": "...",
    "target_ip": "192.168.58.10"
  },
  "priority": 5,
  "created_at": "2026-04-06T12:00:00+00:00",
  "callback_queue": "ares:results:exploit_abc123def456"
}
```

TaskMessage fields:

| Field | Type | Default |
| --- | --- | --- |
| task_id | string | `{task_type}_{uuid.hex[:12]}` |
| task_type | string | required |
| source_agent | string | required |
| target_agent | string | required |
| payload | object | required |
| priority | int | 5 |
| created_at | datetime/null | now(utc) |
| callback_queue | string/null | auto-built |

### 4.2 Result Queues -- LIST

**Key pattern:** `ares:results:{task_id}`
**Type:** Redis LIST (LPUSH to add, BRPOP/RPOP to consume)
**TTL:** 86400 (24h)

**Element (JSON via Pydantic `model_dump_json`):**

```json
{
  "task_id": "exploit_abc123def456",
  "success": true,
  "result": {"credentials": [], "hashes": []},
  "error": null,
  "completed_at": "2026-04-06T12:30:00+00:00",
  "worker_pod": "ares-worker-privesc-0",
  "agent_name": "ares-privesc"
}
```

### 4.3 Task Status -- STRING

**Key pattern:** `ares:task_status:{task_id}`
**Type:** Redis STRING (SET with TTL 24h)

**Value (JSON):**

```json
{
  "status": "running",
  "updated_at": "2026-04-06T12:00:00+00:00",
  "operation_id": "multiagent-abc12345",
  "role": "privesc",
  "task_type": "exploit",
  "started_at": "...",
  "ended_at": "...",
  "pod_name": "ares-worker-privesc-0",
  "error": null,
  "payload": {}
}
```

### 4.4 Operations Queue -- LIST

**Key:** `ares:operations`
**Type:** Redis LIST (RPUSH to submit)

**Element (JSON):**

```json
{
  "operation_id": "multiagent-abc12345",
  "target_domain": "contoso.local",
  "target_ips": ["192.168.58.10"],
  "target_environment": "dev",
  "initial_credential": {
    "username": "user",
    "password": "pass",
    "domain": "contoso.local"
  },
  "resume_from_checkpoint": false,
  "model": "gpt-4.1",
  "max_steps": 200,
  "checkpoint_interval": 60,
  "report_dir": null,
  "submitted_at": "2026-04-06T12:00:00+00:00"
}
```

Note: `env_vars` is stored separately in
`ares:op:{op_id}:env_vars` and removed from this payload.

---

## 5. Heartbeat Keys

**Key pattern:** `ares:heartbeat:{agent_name}`
**Type:** Redis STRING (SET with EX)
**TTL:** `max(60, heartbeat_timeout * 2)` seconds

**Value (JSON):**

```json
{
  "status": "busy",
  "current_task": "exploit_abc123",
  "pod_name": "ares-worker-privesc-0",
  "role": "privesc",
  "operation_id": "multiagent-abc12345",
  "timestamp": "2026-04-06T12:00:00+00:00"
}
```

Status values: `"idle"`, `"busy"`, `"offline"`

---

## 6. Lock and Lifecycle Keys

### 6.1 Operation Lock

**Key:** `ares:lock:{operation_id}`
**Type:** Redis STRING
**Value:** `"locked"`
**TTL:** 7200s (2h), extended periodically

**Acquire:** `SET key "locked" NX EX 7200` (SETNX-style)
**Force acquire:** `DEL key` then
`SET key "locked" EX 7200`
**Release:** `DEL key`, then also clears `ares:op:active`
if it points to this op
**Extend:** `EXPIRE key 7200`

### 6.2 Active Operation Pointer

**Key:** `ares:op:active`
**Type:** Redis STRING
**Value:** operation_id string

Cleared when lock is released if it matches the current
operation.

---

## 7. Pub/Sub Channels

### 7.1 State Update Notifications

**Channel:** `ares:state:updates:{operation_id}`

**Message (JSON):**

```json
{
  "type": "state_update",
  "operation_id": "multiagent-abc12345",
  "ts": "2026-04-06T12:00:00+00:00"
}
```

Workers subscribe and refresh state from Redis when they
receive this.

### 7.2 Discovery Queue (NOT pub/sub -- LIST)

**Key:** `ares:discoveries:{operation_id}`
**Type:** Redis LIST (LPUSH to add, RPOP to consume)
**TTL:** 3600 (1h)

**Element (JSON):**

```json
{
  "type": "credential",
  "data": {
    "username": "svc_sql",
    "password": "P@ss",
    "domain": "contoso.local"
  },
  "source_agent": "ares-cred-access",
  "task_id": "credential_access_abc123",
  "ts": "2026-04-06T12:00:00+00:00"
}
```

Discovery types: `credential`, `hash`, `vulnerability`,
`delegation`, etc.

---

## 8. Data Models and Serialization

### 8.1 Enums

**AgentRole:**

```text
orchestrator, recon, credential_access, cracker,
acl, privesc, lateral, coercion
```

**TaskStatus:**

```text
pending, in_progress, completed, failed,
cancelled, retrying
```

### 8.2 Credential Model

```python
class Credential(Model):
    id: str           # uuid4, default factory
    username: str      # required
    password: str      # required
    domain: str = ""
    source: str = ""
    discovered_at: datetime  # NOT serialized
    is_admin: bool = False   # NOT serialized
    parent_id: str | None = None
    attack_step: int = 0
```

### 8.3 Hash Model

```python
class Hash(Model):
    id: str              # uuid4
    username: str        # required
    hash_value: str      # required
    hash_type: str = "NTLM"
    domain: str = ""
    cracked_password: str = ""
    source: str = ""
    discovered_at: datetime  # IS serialized
    parent_id: str | None = None
    attack_step: int = 0
```

### 8.4 Host Model

```python
class Host(Model):
    ip: str              # required
    hostname: str = ""
    os: str = ""
    roles: list[str] = []
    services: list[str] = []
    is_dc: bool = False
    owned: bool = False  # NOT serialized
```

### 8.5 User Model

```python
class User(Model):
    username: str        # required
    domain: str = ""
    description: str = ""  # NOT serialized
    is_admin: bool = False  # NOT serialized
    source: str = ""
```

### 8.6 Share Model

```python
class Share(Model):
    host: str            # required
    name: str            # required
    permissions: str = ""
    comment: str = ""
```

### 8.7 VulnerabilityInfo (dataclass)

```python
@dataclass
class VulnerabilityInfo:
    vuln_id: str
    vuln_type: str
    target: str
    discovered_by: str
    discovered_at: datetime = now(utc)
    details: dict[str, Any] = {}
    recommended_agent: str = ""
    priority: int = 5    # 1=highest, 10=lowest
```

### 8.8 TaskInfo (dataclass, in-memory + pending_tasks HASH)

```python
@dataclass
class TaskInfo:
    task_id: str
    task_type: str
    assigned_agent: str
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = now(utc)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    last_activity_at: datetime = now(utc)
    params: dict[str, Any] = {}
    result: Any = None
    error: str | None = None
    retry_count: int = 0
    max_retries: int = 3  # from config
```

### 8.9 Serialization Notes

- All JSON uses compact separators:
  `separators=(",",":")`
- Datetimes serialized via `.isoformat()` or
  `json.dumps(value, default=str)`
- Deserialization uses `or ""` pattern to handle JSON
  `null` values:

  ```python
  # handles both missing key AND null
  username = d.get("username") or ""
  ```

- Meta values are double-JSON-encoded:
  `json.dumps(value, default=str)` stored as HASH field
  value, then `json.loads()` to retrieve

---

## 9. Deduplication Strategies

### 9.1 Credentials

- **Redis-level:** HSETNX on
  `cred:{domain}:{username}:{md5(password)[:16]}`
- **In-memory (CLI dedup for display):**
  `(domain.lower(), username.lower(), password)` tuple set

### 9.2 Hashes

- **Redis-level:** HSETNX on type-specific dedup key
  (see section 3.2)
- **In-memory (CLI dedup for display):**
  `(domain.lower(), username.lower(),
  hash_type.lower(), hash_value.lower())` tuple set

### 9.3 Users

- **In-memory (CLI dedup for display):**
  `(domain.lower(), username.lower())` tuple set
- **Redis-level:** No dedup -- LIST RPUSH
  (caller handles)

### 9.4 Shares

- **Redis-level:** HSET (overwrites allowed) on
  `{host_lower}:{name_lower}`

### 9.5 Weaknesses

- **Redis-level:** HSETNX on normalized dedup key
  (provided by caller)

### 9.6 Vulnerabilities

- **Redis-level:** HSETNX on `{vuln_id}`

### 9.7 Domains

- **Redis-level:** SADD (SET provides natural dedup)

### 9.8 Processed Sets

- **Redis-level:** SADD (SET provides natural dedup)

---

## 10. CLI Commands Reference

All commands are async, use cyclopts, and follow the pattern
of resolving redis_url from config if not provided.

### 10.1 `submit`

Submit a new operation to the orchestrator.

| Arg | Type | Default | Description |
| --- | --- | --- | --- |
| target | str | required | Target name |
| domain | str | required | Target domain |
| --ips | list[str] | None | Target IPs |
| --operation-id | str | auto-gen | `multiagent-{uuid.hex[:8]}` |
| --username | str | None | Initial credential |
| --password | str | None | Initial credential |
| --ntlm-hash | str | None | Initial credential |
| --resume | bool | false | Resume from checkpoint |
| --wait | bool | false | Wait for completion |
| --model | str | from env | LLM model |
| --max-steps | int | 200 | Max agent steps |

**Redis ops:** RPUSH to `ares:operations`,
SET `ares:op:{op_id}:env_vars`

### 10.2 `status`

**Redis ops:** GET `ares:op:{op_id}:status`

### 10.3 `wait-for`

**Redis ops:** Poll GET `ares:op:{op_id}:status` until
completed/failed

### 10.4 `loot`

Dump discovered credentials, hashes, hosts, users, shares,
weaknesses.

| Arg | Type | Default |
| --- | --- | --- |
| operation_id | str | None |
| --latest | bool | false |
| --json | bool | false |
| --watch | int | 0 (off) |
| --diff | bool | false |

**Redis ops:** HGETALL/LRANGE on all state keys,
KEYS `ares:op:*:meta` for --latest

### 10.5 `list`

List all operations.

**Redis ops:** KEYS `ares:op:*:meta`,
KEYS `ares:lock:*`, HGETALL meta per op

### 10.6 `report`

Generate markdown report.

**Redis ops:** GET `ares:op:{op_id}:report` (cached),
or read all state

### 10.7 `tasks`

List tasks for an operation.

**Redis ops:** KEYS `ares:task_status:*`, GET each,
filter by operation_id

### 10.8 `runtime`

Show operation runtime and metrics.

**Redis ops:** Read state + EXISTS `ares:lock:{op_id}`

### 10.9 `queue`

Show queue state for all operations.

### 10.10 `cleanup`

Delete old operation checkpoints.

### 10.11 `delete`

Delete operation and all associated keys.

**Redis ops:** KEYS `ares:op:{op_id}:*`, DEL each,
also `ares:lock:{op_id}`, `ares:op:active`,
task_status keys

### 10.12 `backfill-domains`

Extract domains from state and add to domains SET.

**Redis ops:** Read state, SADD to domains,
PUBLISH state update

### 10.13 `inject-credential`

Inject a credential into shared state.

**Redis ops:** HSETNX on credentials HASH,
PUBLISH state update

### 10.14 `inject-vulnerability`

Inject a vulnerability into shared state.

**Redis ops:** HSETNX on vulns HASH,
PUBLISH state update

### 10.15 `loot-users`

User-centric view of credentials and hashes with
attack chains.

### 10.16 `export-detection`

Export detection playbook for blue team.

### 10.17 `watch`

Watch for completed operations, auto-fetch reports.

---

## 11. Operation ID Generation

Format: `multiagent-{uuid.hex[:8]}`

Example: `multiagent-a1b2c3d4`

The CLI generates this if `--operation-id` is not provided.
The uuid is generated via `uuid.uuid4().hex[:8]`.

---

## 12. Edge Cases and Legacy Formats

### 12.1 Credential LIST-to-HASH Migration

When `get_credentials()` encounters a key of type LIST
instead of HASH:

1. Read all items via LRANGE
2. Deserialize each as Credential
3. Pipeline: DELETE key, then HSET each with dedup key,
   then EXPIRE
4. Return the deserialized list

### 12.2 Weakness SET-to-HASH Migration

When `get_weaknesses()` encounters a key of type SET
instead of HASH:

1. Read all members via SMEMBERS
2. Pipeline: DELETE key, then HSET each with
   `weakness[:64].replace("\n", " ").strip()` as key
3. EXPIRE, return list

### 12.3 JSON null Handling

Deserialization uses `d.get("field") or ""` to handle both
missing keys AND JSON null. This means `null` in JSON
becomes `""` (empty string) for string fields, or `0` for
int fields.

### 12.4 Bytes vs String Handling

Redis client may return bytes or strings depending on
`decode_responses` setting. All deserialization handles
both:

```python
if isinstance(data, bytes):
    data = data.decode()
```

For HASH keys/values, TYPE checks:

```python
key_type = await redis.type(key)
if (
    key_type == "list"
    or (
        isinstance(key_type, bytes)
        and key_type == b"list"
    )
):
```

### 12.5 Circuit Breaker and Retry

All write operations use tenacity retry with:

- Max 3 attempts
- Exponential backoff: base=1s, cap=10s
- Retry on: ConnectionError, TimeoutError, OSError

Circuit breaker pattern:

- Shared singleton across all backend instances
- Fail-fast when Redis is unavailable
- Half-open state allows test requests through

### 12.6 Well-Known Accounts

Accounts in `WELL_KNOWN_ACCOUNTS` (krbtgt, administrator,
guest, defaultaccount) exist in every AD domain.
Domain normalization MUST NOT change domains for these
accounts.

### 12.7 Resolving Latest Operation

The `--latest` flag resolution algorithm:

1. KEYS `ares:lock:*` to find running operations
2. KEYS `ares:op:*:meta` to find all operations
3. For each op, read `started_at` from meta HASH
4. Prefer running operations
5. Within running (or all), pick latest by
   `started_at` datetime
6. If no timestamps, sort by operation_id string
   descending

### 12.8 Key Deletion Pattern

`delete_all_keys()` uses `SCAN_ITER` with pattern
`{prefix}:*` and deletes each key individually.
The `delete` CLI command also removes:

- `ares:lock:{op_id}`
- `ares:op:active` (if it matches)
- All `ares:task_status:*` keys where `operation_id`
  matches (requires reading each)
