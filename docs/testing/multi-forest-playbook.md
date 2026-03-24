# Multi-Forest Mode Testing Playbook

Fast iteration guide for testing multi-forest escalation scenarios.

## Quick Reference

### Start Fresh Operation

```bash
# Sync + clear + rollout (full reset)
task -y red:multi:sync:align && task -y red:multi TARGET=dreadgoad
```

### Monitor Running Operation

```bash
# Watch loot in real-time (refreshes every 5s)
task red:multi:loot LATEST=true WATCH=5

# Check runtime and status
task red:multi:runtime LATEST=true
task red:multi:status LATEST=true

# View running tasks
task red:multi:tasks:list LATEST=true STATUS=running
```

---

## Fast-Path Testing Scenarios

### Scenario 1: Test Trust Key Extraction Trigger

Inject state to simulate DA achievement, verify trust extraction task is dispatched.

```bash
# 1. Start minimal operation
task red:multi:sync:align
task -y red:multi TARGET=dreadgoad

# 2. Get operation ID
OP_ID=$(task red:multi:list 2>/dev/null | grep '\[running\]' | awk '{print $1}')
echo "Operation: $OP_ID"

# 3. Inject DA credentials + krbtgt hash
task red:multi:inject-credential OPERATION_ID=$OP_ID \
  USERNAME=Administrator PASSWORD=P@ssw0rd! DOMAIN=sevenkingdoms.local IS_ADMIN=true

task red:multi:inject-hash OPERATION_ID=$OP_ID \
  USERNAME=krbtgt DOMAIN=sevenkingdoms.local \
  HASH="aad3b435b51404eeaad3b435b51404ee:313b6f423a71d74c0a1b8a2f43b22d4c"

# 4. Inject trusted domain host (makes fabrikam.local a "discovered" forest)
task red:multi:inject-host OPERATION_ID=$OP_ID \
  IP=192.168.58.20 HOSTNAME=dc01.essos.local

# 5. Watch for trust_extraction task dispatch
task red:multi:tasks:list OPERATION_ID=$OP_ID STATUS=all | grep -i trust
```

### Scenario 2: Test Golden Ticket with ExtraSid

Verify child domain DA can escalate to parent forest root.

```bash
OP_ID=$(task red:multi:list 2>/dev/null | grep '\[running\]' | awk '{print $1}')

# Inject child domain krbtgt (3+ FQDN parts = child domain)
task red:multi:inject-hash OPERATION_ID=$OP_ID \
  USERNAME=krbtgt DOMAIN=north.sevenkingdoms.local \
  HASH="aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890"

# Inject parent domain host (so parent DC can be resolved)
task red:multi:inject-host OPERATION_ID=$OP_ID \
  IP=192.168.58.10 HOSTNAME=dc01.sevenkingdoms.local

# Watch logs for ExtraSid golden ticket generation
task remote:logs ROLE=orchestrator | grep -E "ExtraSid|golden.?ticket|Enterprise"
```

### Scenario 3: Test Vulnerability Dispatch After DA

Verify vulns targeting foreign domains are still exploited after DA.

```bash
OP_ID=$(task red:multi:list 2>/dev/null | grep '\[running\]' | awk '{print $1}')

# 1. Inject DA state
task red:multi:inject-hash OPERATION_ID=$OP_ID \
  USERNAME=krbtgt DOMAIN=sevenkingdoms.local \
  HASH="aad3b435b51404eeaad3b435b51404ee:313b6f423a71d74c0a1b8a2f43b22d4c"

# 2. Inject vulnerability targeting foreign domain
task red:multi:inject-vulnerability OPERATION_ID=$OP_ID \
  VULN_TYPE=constrained_delegation TARGET_IP=192.168.58.20 \
  TARGET_HOSTNAME=srv01.essos.local \
  TARGET_SPN="cifs/srv01.essos.local" \
  ACCOUNT_NAME=svc_sql DOMAIN=essos.local

# 3. Verify vuln is dispatched (not skipped due to DA)
task red:multi:tasks:list OPERATION_ID=$OP_ID STATUS=all | grep -i constrained
```

---

## State Injection Reference

### Credentials

```bash
task red:multi:inject-credential OPERATION_ID=op-xxx \
  USERNAME=testuser PASSWORD=P@ssw0rd! DOMAIN=contoso.local \
  [IS_ADMIN=true] [SOURCE=manual-inject]
```

### Hashes (NEW - requires CLI update)

```bash
task red:multi:inject-hash OPERATION_ID=op-xxx \
  USERNAME=krbtgt DOMAIN=contoso.local \
  HASH="aad3b435b51404eeaad3b435b51404ee:313b6f423a71d74c0a1b8a2f43b22d4c" \
  [HASH_TYPE=NTLM]
```

### Hosts (NEW - requires CLI update)

```bash
task red:multi:inject-host OPERATION_ID=op-xxx \
  IP=192.168.58.20 HOSTNAME=dc01.fabrikam.local
```

### Vulnerabilities

```bash
task red:multi:inject-vulnerability OPERATION_ID=op-xxx \
  VULN_TYPE=constrained_delegation TARGET_IP=192.168.58.240 \
  TARGET_HOSTNAME=srv01.contoso.local \
  TARGET_SPN="cifs/srv01.contoso.local" \
  ACCOUNT_NAME=svc_sql DOMAIN=contoso.local
```

**VULN_TYPEs:** `constrained_delegation`, `unconstrained_delegation`, `rbcd`,
`adcs_esc1`, `adcs_esc4`, `adcs_esc8`, `mssql_impersonation`, `mssql_linked`,
`gpo_abuse`, `laps_abuse`, `dcsync`, `shadow_credentials`

---

## Multi-Forest State Conditions

The orchestrator checks these conditions to determine behavior:

| State | Condition | Behavior |
| ----- | --------- | -------- |
| DA not achieved | `has_domain_admin = false` | Normal exploitation |
| DA on single forest | `has_domain_admin = true`, `multi_forest_mode = false` | Stop or continue per config |
| DA on multi-forest | `has_domain_admin = true`, `all_forests_dominated() = false` | Continue, dispatch trust extraction |
| All forests dominated | `all_forests_dominated() = true` | Stop operation |

### Key Functions to Trace

```python
# Check multi-forest continuation logic
src/ares/core/dispatcher/vulnerability.py:get_next_vulnerability()

# Trust key extraction dispatch
src/ares/core/dispatcher/publishing.py:_auto_dispatch_trust_key_extraction_threaded()
src/ares/core/dispatcher/announcements.py:_auto_dispatch_trust_key_extraction()

# Golden ticket with ExtraSid
src/ares/core/orchestrator/_orchestrator.py:_auto_golden_ticket()

# Forest domination check
src/ares/core/models.py:SharedRedTeamState.all_forests_dominated()
src/ares/core/models.py:SharedRedTeamState.get_undominated_forests()
```

---

## Debugging Commands

### Check Redis State Directly

```bash
# Port-forward to Redis
kubectl port-forward -n attack-simulation svc/redis 16379:6379 &

# Get Redis password
REDIS_PASS=$(kubectl get secret redis-secret -n attack-simulation -o jsonpath='{.data.password}' | base64 -d)

# Check DA status
redis-cli -p 16379 -a "$REDIS_PASS" hget ares:op:$OP_ID:meta has_domain_admin
redis-cli -p 16379 -a "$REDIS_PASS" hget ares:op:$OP_ID:meta domain_admin_domains

# List all hashes
redis-cli -p 16379 -a "$REDIS_PASS" hgetall ares:op:$OP_ID:hashes

# List trusted domains discovered
redis-cli -p 16379 -a "$REDIS_PASS" smembers ares:op:$OP_ID:trusted_domains

# Check pending tasks
redis-cli -p 16379 -a "$REDIS_PASS" hgetall ares:op:$OP_ID:pending_tasks
```

### Trace Logs

```bash
# Trust extraction dispatch
task remote:logs ROLE=orchestrator | grep -E "trust.*extraction|🌲"

# Golden ticket generation
task remote:logs ROLE=orchestrator | grep -E "golden.?ticket|ExtraSid|ticketer"

# Vulnerability dispatch after DA
task remote:logs ROLE=orchestrator | grep -E "get_next_vulnerability|multi.?forest|undominated"
```

---

## Unit Test Coverage

Run existing multi-forest tests:

```bash
# All multi-forest tests
uv run pytest tests/core/dispatcher/test_multi_forest.py -v

# Specific scenarios
uv run pytest tests/core/dispatcher/test_multi_forest.py::TestTrustKeyExtractionTaskFormat -v
uv run pytest tests/core/dispatcher/test_multi_forest.py::TestGetNextVulnerabilityMultiForest -v
uv run pytest tests/core/dispatcher/test_multi_forest.py::TestWorkflowMultiForestFallthrough -v
```

---

## Config Toggle

Multi-forest mode is controlled in `config/multi-agent-production.yaml`:

```yaml
operation:
  # These are mutually exclusive:
  # stop_on_domain_admin: true   # Stop immediately on DA
  # stop_on_golden_ticket: true  # Stop after golden ticket
  multi_forest_mode: true        # Continue until ALL forests dominated
```

To test single-forest behavior, comment out `multi_forest_mode` and uncomment `stop_on_domain_admin`.
