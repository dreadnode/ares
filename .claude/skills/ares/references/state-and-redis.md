# State model + Redis keys

All operation state is Redis-native. There is no database. The orchestrator keeps an in-memory
`SharedState` mirror (`ares-cli/src/orchestrator/state/`), but Redis is authoritative across
restarts and is the only thing you can inspect from outside the process.

Canonical key constants: `ares-core/src/state/keys.rs`. Key builders `build_key`, `build_lock_key`,
`build_blue_key`, `build_blue_lock_key`: `ares-core/src/state/mod.rs:84-109`.

## Read this before you touch redis-cli

**1. Wrong verb is loud; wrong key name is silent.** `SCARD` on a HASH returns `WRONGTYPE Operation
against a key holding the wrong kind of value` — on **stdout**, with **exit code 0**. `$(...)`
captures that error string verbatim and `set -e` never trips, so a mistyped verb prints the error
inline and diagnoses itself. The dangerous case is the inverse: a mistyped *key name* (`creds` for
`credentials`, `vuln_queue` under the wrong op id) returns a clean `0` from any verb, and *that* is
what you misread as a wedge. Verified on redis-cli 8.8.0, non-TTY. The keys operators get wrong
most often:

| Key | Actual TYPE | Correct | Wrong verb you'll reach for |
|---|---|---|---|
| `ares:op:{op}:credentials` | HASH | `HLEN` | `SCARD`, `LLEN` |
| `ares:op:{op}:hashes` | HASH | `HLEN` | `SCARD`, `LLEN` |
| `ares:op:{op}:vulns` | HASH | `HLEN` | `SCARD` |
| `ares:op:{op}:completed_tasks` | HASH | `HLEN` | `SCARD` |
| `ares:op:{op}:hosts` | LIST | `LLEN` | `SCARD`, `HLEN` |
| `ares:op:{op}:users` | LIST | `LLEN` | `HLEN` |
| `ares:op:{op}:exploited` | SET | `SCARD` | `LLEN` |
| `ares:op:{op}:vuln_queue` | ZSET | `ZCARD` | `LLEN` |

Verified against the `redis-rs` call, not a doc comment: `reader.rs:56` credentials HGETALL, `:69`
hashes HGETALL, `:130` vulns HGETALL, `:82` hosts LRANGE, `:95` users LRANGE, `:147` exploited
SMEMBERS; `publishing/entities.rs:370` completed_tasks HSET; `publishing/entities.rs:230`
vuln_queue ZADD. When unsure: `redis-cli type <key>` first, always.

**2. Doc comments in `keys.rs` and the `mod.rs` header lie about TYPE and direction.** They
disagree with each other and with the code. Confirmed wrong at HEAD:

| Constant | Comment claims | Truth |
|---|---|---|
| `KEY_ACL_CHAINS` (`keys.rs:59`) | "Redis SET" | LIST — both readers `LRANGE` (`persistence.rs:152`, `:368`) |
| `KEY_DC_MAP` (`keys.rs:47`) | "IP → DC hostname" | **domain (lowercase FQDN) → DC IP** (`publishing/hosts.rs:452`, `orchestrator/mod.rs:337`) |
| `KEY_NETBIOS_MAP` (`keys.rs:49`) | "IP → NetBIOS name" | **NetBIOS name → FQDN** (`publishing/entities.rs:405`) |
| `mod.rs:17-24` | artifacts HASH; golden_tickets/adminsd_backdoors/acl_chains/gmsa_accounts LIST | `keys.rs:52-62` calls all five SET; four of them have no writer at all |

Trust the `redis-rs` call site. Nothing else.

**3. Four key constants have no writer anywhere in the tree.** `KEY_ARTIFACTS`,
`KEY_GOLDEN_TICKETS`, `KEY_ADMINSD_BACKDOORS`, `KEY_GMSA_ACCOUNTS` appear only in `keys.rs` — those
Redis keys never exist regardless of what the op did. Golden-ticket state lives in
`meta.has_golden_ticket`. `acl_chains` has readers but no writer, so it is always empty
(`state.acl_chains` is rebuilt in memory every tick by `acl_graph::refresh_acl_chains`,
`automation/acl.rs:278`). `ares:op:{op}:loot` likewise has one reader
(`ares-tools/src/blue/learning/playbook.rs:441`) and no writer.

**4. Meta values are JSON-encoded — strings come back quoted.** `set_meta_field` does
`serde_json::to_string(value)` before HSET (`reader.rs:442-453`). `HGET ares:op:$OP:meta
target_domain` returns `"contoso.local"` *with the quotes*; `has_domain_admin` returns bare `true`.
Any `[ "$x" = "contoso.local" ]` test silently always fails. Strip with `sed -E 's/^"(.*)"$/\1/'` —
exactly what the shipped `.taskfiles/ec2/scripts/list-ops.sh:21` does.

**5. `SCARD exploited` overcounts.** `mark_exploited` SADDs the primary vuln *and every superseded
vuln id* into `exploited`, mirroring the latter into `superseded`
(`orchestrator/state/dedup.rs:78-88`). Genuinely-proven count = `SCARD exploited − SCARD
superseded`.

**6. An empty HGETALL means expired, not "never ran" — and the 24h clock starts at the last write,
not at finalize.** Nearly every per-op key arms its own rolling 24h TTL on every write
(`OP_TTL_SECS`, `ares-core/src/state/reader.rs:18`, re-applied at 17 sites there plus the
`publishing/*` writers). `finalize_operation` additionally SCANs `ares:op:{id}:*` and applies
`OP_RETENTION_TTL_SECS = 86400` to every remaining key (`operations.rs:249-255`, `keys.rs:19`). Two
consequences: an op that crashed and never finalized still loses its state 24h after its **last
write**, and a key that went quiet early can expire while the op is still running. The finalize
sweep is a backfill for the minority written with no TTL of their own — `dc_map`, `token_usage`,
`path_record`, `coverage`, `mutation_journal`, `force_forge_requests`, `teardown_claimed`.

## Per-operation keys — `ares:op:{op_id}:{suffix}`

`op_id` format is `op-YYYYMMDD-HHMMSS`. Every row below re-arms a 24h TTL on write except the seven
called out in trap 6, which get one only at finalize. **Both citation columns point at the
`redis-rs` call line, never at the `pub async fn` signature** — the same contract as trap 1.

| Suffix | TYPE | Read with | Writer |
|---|---|---|---|
| `meta` | HASH (JSON-encoded values) | `HGETALL` / `HMGET` | `bootstrap.rs:315-357`, `reader.rs:450` `hset` (in `set_meta_field`, `:442`), `completion.rs:809-827`, `operations.rs:217-232` |
| `status` | STRING (JSON) | `GET` | `operations.rs:107` `SET EX 86400` |
| `model` | STRING | `GET` | `bootstrap.rs:365-374` `SET EX 86400`; only when `ARES_LLM_MODEL` is set |
| `stop_requested` | STRING `"1"`, **TTL 120s** | `EXISTS` | `operations.rs:433` |
| `report` | STRING (rendered markdown) | `GET` | `ops/report.rs:64-73` SET + `EXPIRE 86400` |
| `env_vars` | STRING (JSON map), TTL 3600 | `GET` | `ops/submit.rs:207-210` |
| `credentials` | HASH `cred:{domain}:{user}:{md5_16} → Credential JSON` | `HLEN` / `HVALS` | `reader.rs:273` `hset_nx` |
| `hashes` | HASH `dedup_key → Hash JSON` | `HLEN` / `HVALS` | `reader.rs:414` `hset_nx` insert; `:432` plain `hset` on the AES-key upgrade path |
| `shares` | HASH `host:name → Share JSON` | `HLEN` | `reader.rs:558` `hset_nx` |
| `vulns` | HASH `vuln_id → VulnerabilityInfo JSON` | `HLEN` / `HKEYS` | `reader.rs:289` `hset_nx` |
| `candidate_domains` | HASH `fqdn → CandidateDomain JSON` | `HGETALL` | `publishing/domains.rs:291` HSET + `EXPIRE 86400` on the record path; the probe-update path (`:237`) HSETs without re-arming the TTL |
| `dc_map` | HASH **domain → DC IP**, no TTL | `HGETALL` | `publishing/hosts.rs:452`, `orchestrator/mod.rs:337`, `ops/inject.rs:288` (inject path) |
| `netbios_map` | HASH **NetBIOS → FQDN** | `HGETALL` | `publishing/entities.rs:405` |
| `domain_sids` | HASH `domain → SID` (**raw string**, not JSON) | `HGETALL` | `reader.rs:463` `hset` |
| `admin_names` | HASH `fqdn → RID-500 name` (**raw**) | `HGETALL` | `reader.rs:497` `hset` |
| `trusted_domains` | HASH `fqdn → TrustInfo JSON` | `HGETALL` | `reader.rs:691` `hset_nx` |
| `kerberos_tickets` | HASH `{src}:{tgt}:{user} → KerberosTicket JSON` | `HGETALL` | `reader.rs:525` `hset` (overwrites) |
| `pending_tasks` | HASH `task_id → TaskInfo JSON` | `HLEN` / `HGETALL` | `publishing/entities.rs:336`, `:364` |
| `completed_tasks` | HASH `task_id → TaskResult JSON` | `HLEN` | `publishing/entities.rs:370` |
| `vuln_type_failures` | HASH `vuln_type → int` | `HGETALL` | `reader.rs:637` `hincr` |
| `token_usage` | HASH of counters | `HGETALL` | `token_usage.rs:257` → HINCRBY pipe `:304-334` |
| `hosts` | LIST of Host JSON | `LLEN` / `LRANGE 0 -1` | `reader.rs:322` `rpush` after a full dup scan; merges via `LSET` (`publishing/hosts.rs:275`) |
| `users` | LIST of User JSON | `LLEN` / `LRANGE 0 -1` | `reader.rs:350` `rpush` after dup scan on `user@domain` |
| `timeline` | LIST of event JSON, oldest first | `LLEN` / `LRANGE 0 -1` | `reader.rs:573` `rpush` |
| `path_record` | LIST of `PathStep` JSON | `LRANGE 0 -1` | `diversity.rs:178` RPUSH (only when `emit_path_records`) |
| `force_forge_requests` | LIST of forge-request JSON | `LLEN` / `LRANGE 0 -1` | `ops/inject.rs:113` RPUSH; drained by `automation/trust.rs:2803` |
| `acl_chains` | LIST | `LRANGE 0 -1` | **none** — read-only at `persistence.rs:152`, `:368` |
| `domains` | SET (lowercased FQDNs) | `SCARD` / `SMEMBERS` | `reader.rs:362` `sadd`, `publishing/domains.rs:180` |
| `exploited` | SET of vuln_id (includes superseded) | `SCARD` / `SMEMBERS` | `state/dedup.rs:78` SADD |
| `superseded` | SET ⊆ `exploited`, never actually proven | `SCARD` / `SMEMBERS` | `state/dedup.rs:84` SADD |
| `techniques` | SET of MITRE ATT&CK IDs | `SMEMBERS` | `reader.rs:585` `sadd` |
| `dominated_domains` | SET of FQDNs with krbtgt owned | `SCARD` / `SMEMBERS` | `publishing/credentials.rs:386` SADD |
| `mssql_enum_dispatched` | SET of IPs | `SMEMBERS` | `state/dedup.rs:196` SADD + `EXPIRE 86400` |
| `coverage` | SET of `{technique}:{target}` step keys | `SCARD` / `SMEMBERS` | `diversity.rs:183` SADD |
| `dedup:{set_name}` | SET | `SCARD` / `SMEMBERS` | `state/dedup.rs:151` SADD + `EXPIRE 86400` |
| `vuln_queue` | ZSET `vuln JSON → priority` (lower = more urgent) | `ZCARD` / `ZRANGE 0 -1 WITHSCORES` | `publishing/entities.rs:230` ZADD |
| `mutation_journal` | LIST of mutation records | `LRANGE 0 -1` | `cleanup/journal.rs:230` RPUSH; teardown plan source |
| `teardown_claimed` | STRING `"1"`, no TTL of its own | `EXISTS` | `cleanup/mod.rs:54` `SETNX`. Gates only the **automatic** pass (`run_teardown_once`) so the completion monitor and the shutdown fallback can't both fire. Not deleted on use, but it picks up the 24h retention TTL at finalize and dies with `ares ops delete`. `ares ops teardown` calls `run_teardown` directly and ignores the claim (`cleanup/mod.rs:46-47`, `ops/teardown.rs:35`) — you can always re-run teardown by hand |

## The meta HASH — completion and termination

Parsed into `OperationMeta` (`ares-core/src/models/operation.rs:13-25`). Every value is
JSON-encoded (trap 4).

| Field | Meaning | Written by |
|---|---|---|
| `started_at` | RFC3339. **HSETNX** — set once so restarts don't reset runtime math | `bootstrap.rs:332` |
| `initialized` | Literal `true` (not JSON-quoted) once bootstrap ran | `bootstrap.rs:336` |
| `target_domain` | Primary target domain | `bootstrap.rs:339` |
| `target_ip` | First of `target_ips` | `bootstrap.rs:343` |
| `target_ips` | **Comma-joined string**, JSON-quoted — not a JSON array (the parser also accepts an array, `operation.rs:51-54`) | `bootstrap.rs:348` |
| `has_domain_admin` | DA achieved | `publishing/milestones.rs:157` (in `set_domain_admin`, `:146`) |
| `has_golden_ticket` | Golden ticket forged | `publishing/milestones.rs:40` (in `set_golden_ticket`, `:22`) |
| `domain_admin_path` | Human-readable path that produced DA | `publishing/milestones.rs:165` |
| `red_completed_at` | **Red loop ended** — set the moment the completion condition fires | `completion.rs:810-814` |
| `red_completion_reason` | Why red stopped | `completion.rs:815-819` |
| `red_blocked_on_blue` | Red done, op holding open for blue to drain | `completion.rs:820-824`; forced `false` by `finalize_operation` (`operations.rs:227-231`) |
| `completed` | Whole operation finalized | `operations.rs:223` |
| `completed_at` | RFC3339 finalization time | `operations.rs:225` |

**`red_completed_at` set while op `status` is still `running` is NORMAL, not a wedge.** Red freezes
dispatch and the operation holds open until blue investigations drain.

**Status is derived from the lock, not the status key.** `list_running_operations` SCANs
`ares:lock:*` (`operations.rs:298-329`). The shipped derivation
(`.taskfiles/ec2/scripts/list-ops.sh:23-29`): lock exists → `running`; else `meta.completed_at`
present → `completed`; else → `stopped` (crashed / killed / never finalized). **The lock is a 300s
lease, so `running` survives a hard orchestrator death for up to five minutes** — cross-check
`updated_at` on the status key before trusting it.

`ares:op:{op}:status` carries liveness separately: `updated_at` moves on every heartbeat,
`status_changed_at` only on a real status change (`operations.rs:64-74`). A `running` record is
`is_stale` after `heartbeat_interval_secs × 3` (`OP_HEARTBEAT_STALE_INTERVALS`, `operations.rs:54`;
default interval 30s, `:58`). Terminal records are never stale, and `heartbeat_operation_status`
refuses to write when the record is absent or already terminal (`operations.rs:139-143`) — a
heartbeat cannot flip `completed` back to `running`.

**`resolve_latest_operation` ignores running status on purpose.** It SCANs `ares:op:*:meta`,
HGETALLs each, and picks the newest `started_at` (op_id descending as fallback)
(`operations.rs:332-389`), so a wedged running op cannot shadow a newer one.

### `finalize_operation` sequence

`operations.rs:212-259`, in order: meta `completed` / `completed_at` / `red_blocked_on_blue=false`
→ write `status` key → `DEL ares:lock:{op}` → `DEL ares:op:active` if it points here → SCAN
`ares:op:{op}:*` and `EXPIRE` every key to 86400s. Most per-op keys already carry a rolling 24h TTL
re-armed on every write (trap 6), so this sweep only backfills the handful written without one.

## Timeline events

`ares:op:{op}:timeline` is a LIST, RPUSHed one JSON object per event (`reader.rs:566-576`). Events
are `serde_json::Value`, not a typed struct — the fields are a convention
(`result_processing/timeline.rs:76-81`):

```json
{
  "id": "evt-cred-a1b2c3d4",
  "timestamp": "2026-07-30T12:00:00+00:00",
  "source": "secretsdump",
  "description": "Credential discovered: contoso.local\\alice via secretsdump",
  "mitre_techniques": ["T1003.006"]
}
```

`persist_timeline_event` also SADDs every `mitre_techniques` entry into `ares:op:{op}:techniques`
(`publishing/entities.rs:301-305`) — that SET plus the timeline `mitre_techniques` arrays form the
denominator of the red/blue scorecard. `id` prefixes identify the emitter: `evt-cred-`,
`evt-hash-`, `evt-admin-`, `evt-exploit-`, `evt-exploit-fail-`, `evt-lateral-`, `evt-da-`,
`evt-gt-`, `evt-adcs-`, `evt-trust-`.

**Timeline `evt-exploit-fail-*` descriptions are the failing LLM agent's own explanation, not a bug
report** — see the `ares-debug` skill before acting on one.

## Queues: what is Redis and what moved to NATS

| Key / subject | TYPE | Purpose |
|---|---|---|
| `ares:operations` | Redis LIST | Operation submission queue. RPUSH by `ares ops submit` (`ops/submit.rs:214`), BRPOP by `ares ops claim-next` (`ops/queue.rs:48-52`) |
| `ares:op:{op}:vuln_queue` | Redis ZSET | Exploitation queue. `ZPOPMIN` when diversity knobs are off; peek-`CANDIDATE_LIMIT`-then-softmax when `selection_temperature > 0` or novelty is on (`exploitation.rs:318-330`, `diversity.rs:34`) |
| `ares:deferred:{op}:{task_type}` | Redis ZSET | Deferred tasks. Score = `priority × 1e9 + enqueue_millis` (`deferred.rs:107-110`), so priority buckets dominate and FIFO applies only within a bucket |
| `ares:deferred:{op}:{task_type}:sigs` | Redis SET | Producer-side signature dedup, kept in lockstep with the ZSET via Lua (`deferred.rs:232-238`). **Not queued work** |
| `ares:deferred:{op}:__total` | Redis STRING (int) | Cached cardinality; `reconcile_total()` rebuilds it by ZCARDing every `ares:deferred:{op}:*` while skipping `__total` and `:sigs` (`deferred.rs:504-521`) |
| `ares:discoveries:{op}` | Redis LIST | Real-time worker discoveries. **LPUSH** (`tool_dispatcher/mod.rs:390`), drained LRANGE-then-DEL every 5s (`discovery_polling.rs:37-43`). Deliberately NOT under `ares:op:` (`orchestrator/state/mod.rs:126` — *not* `ares-core`'s `state/mod.rs`, whose line 126 is test code) |
| `ares.tasks.{role}` / `ares.tasks.urgent.{role}` | **NATS JetStream** | Worker task dispatch |
| `ares.tasks.results.{task_id}` | **NATS JetStream** | Result mailbox |
| `ares.tools.exec.{role}` | **NATS core** | Direct tool dispatch |
| `ares.state.updates.{op}` | **NATS core** | State-change notification, fire-and-forget (`operations.rs:29-32`) |

**`LLEN ares:tasks:recon` always returns 0 and proves nothing.** Work queues live in NATS
(`task_queue.rs:1-18`, `ares-core/src/nats.rs:7-14`); no Rust constant for `ares:tasks:*` or
`ares:results:*` exists outside doc comments. Concluding "the queue is empty, workers are starved"
from that is a false diagnosis. Same for `SUBSCRIBE ares:state:updates` — the constant
`STATE_UPDATE_CHANNEL_PREFIX` still sits at `keys.rs:96` but nothing publishes to it.

## Dedup sets

`ares:op:{op}:dedup:{set_name}` — SET, `SADD` + `EXPIRE 86400` (`state/dedup.rs:151-153`). The 64
`set_name` values are the `DEDUP_*` constants in `ares-cli/src/orchestrator/state/mod.rs:27-121`.
Membership is a "we already tried this" gate; `SREM` (or `unpersist_dedup`, `state/dedup.rs:157`)
re-arms the automation.

**An orchestrator restarted inside 24h inherits every prior dedup decision**, so many automations
appear to never fire again. The one deliberate exception: `dedup:trust_follow` is DELETED on every
state load (`persistence.rs:47-63`) so the trust/forge path re-runs against current code.

```bash
redis-cli --scan --pattern "ares:op:$OP:dedup:*" | while read -r k; do
  printf '%s\t%s\n' "$(redis-cli scard "$k")" "$k"
done | sort -rn | head -20
```

## Novelty, path records, coverage

Key builders `ares-cli/src/orchestrator/diversity.rs:50-68`. Canonical step key is
`{lowercased_vuln_type}:{target}` (`diversity.rs:51-53`).

| Key | TYPE | Gate | Note |
|---|---|---|---|
| `ares:novelty:{scope}:steps` | SET | `operation.novelty.enabled` | **Not under `ares:op:` — no TTL, survives `delete_operation` and the retention sweep.** Default scope `per-campaign` (`ares-core/src/config/defaults.rs:69-71`, repo-root `config/ares.yaml:110`), so every op on the box shares one bias set |
| `ares:op:{op}:path_record` | LIST of `PathStep` JSON | `operation.emit_path_records` | Ordered steps walked |
| `ares:op:{op}:coverage` | SET of step keys | `operation.emit_path_records` | Distinct steps walked |

Shipped defaults in `config/ares.yaml:104-116`: `selection_temperature: 0.7`, `novelty.enabled:
true`, `scope: per-campaign`, `randomize_entry_foothold: true`, `emit_path_records: true`. Penalty
for an already-walked step is `NOVELTY_PENALTY = 4.0` (`diversity.rs:30`).

Reset cross-run bias. Default scope only:

```bash
redis-cli del "ares:novelty:per-campaign:steps"
```

All scopes at once is what `task benchmark:diversity-sweep N=… TARGET=… RESET=true` does on the box
before it loops (`.taskfiles/benchmark/Taskfile.yaml:643-646`):

```bash
redis-cli --scan --pattern "ares:novelty:*:steps" | xargs -r redis-cli del
```

**`RESET` defaults to `false`** (`.taskfiles/benchmark/Taskfile.yaml:558`), so an ordinary sweep
inherits every prior run's bias — and a sweep run *with* `RESET=true` silently wipes every scope,
not just `per-campaign`.

For running and reading a diversity sweep, route to the `attack-path-diversity-sweep` skill.

## Locks and liveness

| Key | TYPE | Detail |
|---|---|---|
| `ares:lock:{op}` | STRING = holder id, **TTL 300s** | `SET NX EX <ttl>` (`task_queue.rs:592-605`) where ttl = `ARES_LOCK_TTL_SECS`, default **300** (`orchestrator/config.rs:196`, passed at `orchestrator/mod.rs:156`), renewed by the lock keeper (`monitoring.rs:152`). **It is a lease, not a liveness proof** — a hard-dead orchestrator keeps the lock, and every `running` derivation below, for up to 5 minutes. Holder prefers `POD_NAME`, then `HOSTNAME`, then a UUID persisted at `$XDG_STATE_HOME/ares/host_id` (`task_queue.rs:52-70`). Same holder re-acquiring is crash recovery; `ARES_LOCK_TAKEOVER=1` steals from a different holder (`task_queue.rs:41-44`) |
| `ares:heartbeat:{agent}` | STRING (JSON), TTL from caller | `{status,current_task,pod_name,role,operation_id,timestamp}` (`worker/heartbeat.rs:135-151`, SET EX at `:120`). Absent == dead worker |
| `ares:task_status:{task_id}` | STRING (JSON), TTL 86400 | `task_queue.rs:772`, `:805`; `TASK_STATUS_TTL_SECS` at `:116` |
| `ares:tools:{agent_name}` | STRING (JSON array), TTL 3600 | Worker tool inventory (`worker/tool_check.rs:70-86`). Orchestrator reads `ares:tools:ares-{role with _ → -}-agent` (`monitoring.rs:492`) |
| `ares:blue:lock:{inv}` | STRING (RFC3339) | `SETNX` + `EXPIRE 3600` (`blue_writer.rs:331-344`, TTL from `blue/investigation.rs:133`) |

**Two "active operation" pointers exist and neither resolves an op.** `ares:op:active` is SET by
the orchestrator (`bootstrap.rs:360`) and DEL'd by `finalize_operation` (`operations.rs:244-247`).
`ares:operation:active` is SET by `ares ops submit --pin-active` (`ops/submit.rs:202`) and nothing
in Rust ever deletes or reads it. `resolve_latest_operation` scans meta by `started_at` instead —
setting either pointer changes nothing about which op the CLI targets.

**`ares:op:{op}:stop_requested` has a 120-second TTL, not 24h** (`operations.rs:437`), and the
orchestrator DELETEs it at startup (`orchestrator/mod.rs:888-892`). Two consequences: a stop issued
before the orchestrator boots is silently lost, and if the orchestrator is blocked for two minutes
the signal evaporates with no trace. The main loop polls it every 5s (`orchestrator/mod.rs:957`,
`:990-996`).

Three writers, all via `request_stop_operation` (`operations.rs:433`), so the 120s trap applies to
all of them: `ares ops stop` (`ops/stop.rs:32`), `ares ops kill` (`ops/kill.rs:66`, which then
`delete_operation`s), and the orchestrator's own completion path (`completion.rs:769`).

## Blue keys — `ares:blue:inv:{inv_id}:{suffix}`

Prefix `ares:blue:inv` (`keys.rs:100`). Investigation ids look like `inv-YYYYMMDD-HHMMSS`.

| Suffix | TYPE | Read with | Note |
|---|---|---|---|
| `status` | STRING (JSON), TTL 86400 | `GET` | `{status, started_at[, completed_at, error]}` (`blue_writer.rs:370-409`). `completed_at` only for `completed`/`escalated`/`failed` |
| `meta` | HASH, TTL 86400 | `HGETALL` | `blue_writer.rs:286-326` |
| `queue_meta` | HASH, TTL 86400 | `HGETALL` | `alert`, `model`, `registered_at` (`blue_task_queue.rs:447-461`) |
| `env_vars` | STRING (JSON), **TTL 3600** | `GET` | Grafana + LLM creds (`blue/submit.rs:83-86`, `completion.rs:979-982`, `orchestrator/blue/auto_submit.rs:309` — the only `auto_submit.rs` in the tree; there is none under `ares-cli/src/blue/`) |
| `evidence` | HASH — **HSETNX** | `HLEN` / `HGETALL` | `blue_writer.rs:35-46`. HLEN is a unique-evidence count |
| `technique_names` | HASH `id → name` | `HGETALL` | `blue_writer.rs:95` |
| `tasks:pending` / `tasks:completed` | HASH (colon is inside the suffix) | `HLEN` / `HGETALL` | `blue_writer.rs:255-273` |
| `token_usage` | HASH | `HGETALL` | `token_usage.rs:196` |
| `timeline` / `queries` / `lateral` / `pivot_queue` / `chain_queue` / `recommendations` / `triage:records` | LIST | `LRANGE 0 -1` | RPUSH at `blue_writer.rs:58, 144, 157, 169, 181, 219, 244` — in that order |
| `techniques` / `tactics` / `hosts` / `users` / `query_types` | SET | `SCARD` / `SMEMBERS` | `blue_writer.rs:70,82,107,119,131` |
| `triage:decision` | STRING (JSON), TTL 86400 | `GET` | `blue_writer.rs:232` |
| `supersede` | STRING `"1"`, TTL 86400 | `EXISTS` | `blue_writer.rs:426-433`; advisory abort flag |

**`hosts` and `users` are lowercased on SADD** (`blue_writer.rs:107`, `:119`). `SISMEMBER
ares:blue:inv:$INV:hosts DC01.CONTOSO.LOCAL` returns 0 for a host blue definitely saw.

Blue globals:

| Key | TYPE | Detail |
|---|---|---|
| `ares:blue:active_investigations` | SET, TTL 86400 | `blue_task_queue.rs:443`, `completion.rs:990-994`; SREM'd on finish |
| `ares:blue:op:{op}:investigations` | SET, TTL 7 days | `blue/submit.rs:250-252`, `completion.rs:997`; the set completion drains and supersedes |
| `ares:blue:heartbeat:{agent}` | STRING (JSON), **TTL 60s** | `SET EX 60` (`blue_task_queue.rs:402-411`). Absent == no write in the last 60s, i.e. dead worker |

Blue work queues are **NATS, not Redis**: `ares.blue.investigations`, `ares.blue.tasks.{role}`,
`ares.blue.tasks.results.{task_id}` (`blue_task_queue.rs:6-14`, `ares-core/src/nats.rs:52`).
`BLUE_TASK_QUEUE_PREFIX`, `BLUE_RESULT_QUEUE_PREFIX` and `BLUE_INVESTIGATION_QUEUE`
(`keys.rs:172-184`) are dead constants — do not look for `ares:blue:tasks:*` Redis keys.

**`ares blue delete` clears Redis only.** It DELs `ares:blue:inv:{id}:*` and SREMs from the active
set (`blue/delete.rs:27-46`). The lock `ares:blue:lock:{id}` does not match that glob and survives,
and the queued JetStream request survives too — a "deleted" investigation resurrects on the next
poll. `ares blue cleanup --all` is the one path that also purges the NATS stream
(`blue/delete.rs:175-186`), but it scans only `ares:blue:inv:*` and `ares:blue:op:*`
(`blue/delete.rs:126-128`) — `ares:blue:lock:*` (`keys.rs:104`) and `ares:blue:heartbeat:*`
(`keys.rs:178`) match neither pattern and survive that too.

## Token usage

`ares:op:{op}:token_usage` HASH (`token_usage.rs:190-192`), all fields HINCRBY'd in one atomic pipe
(`:304-334`):

| Field | Meaning |
|---|---|
| `input_tokens` | Aggregate uncached prompt tokens |
| `cache_read_input_tokens` | Aggregate cached prompt tokens |
| `output_tokens` | Aggregate completion tokens |
| `model` | Last model that wrote — last-writer-wins, informational only |
| `model:{base64url(name)}:{input_tokens\|cache_read_input_tokens\|output_tokens}` | Per-model breakdown; URL-safe base64 so model names can't inject `:` into a field name (`token_usage.rs:229-236`) |

Blue equivalent: `ares:blue:inv:{inv}:token_usage`.

## Snapshot for a wedge diff

The wedge signature is *objective state frozen while tokens climb*. Take two snapshots ≥60s apart
and diff them. Types are correct here — copy this, don't retype it.

```bash
# $1 = op id. Run on the box (see "Reaching Redis" below).
OP="$1"
printf '=== %s @ %s ===\n' "$OP" "$(date -u +%FT%TZ)"
redis-cli hmget "ares:op:$OP:meta" \
  has_domain_admin has_golden_ticket domain_admin_path \
  red_completed_at red_completion_reason red_blocked_on_blue completed completed_at
for k in credentials hashes shares vulns pending_tasks completed_tasks trusted_domains kerberos_tickets; do
  printf '%-22s HLEN  %s\n' "$k" "$(redis-cli hlen "ares:op:$OP:$k")"
done
for k in hosts users timeline path_record force_forge_requests mutation_journal; do
  printf '%-22s LLEN  %s\n' "$k" "$(redis-cli llen "ares:op:$OP:$k")"
done
for k in domains exploited superseded techniques dominated_domains coverage; do
  printf '%-22s SCARD %s\n' "$k" "$(redis-cli scard "ares:op:$OP:$k")"
done
printf '%-22s ZCARD %s\n' vuln_queue     "$(redis-cli zcard "ares:op:$OP:vuln_queue")"
printf '%-22s %s\n'       deferred_total "$(redis-cli get   "ares:deferred:$OP:__total")"
printf '%-22s %s\n'       lock           "$(redis-cli exists "ares:lock:$OP")"
redis-cli get "ares:op:$OP:status"   # read updated_at — lock=1 alone does not prove liveness
redis-cli hgetall "ares:op:$OP:token_usage" | paste - -
```

Read the diff this way. `lock` = 1 is necessary but not sufficient for `running`: always pair it
with the `status` record's `updated_at`, because the lock is a 300s lease.

| Observation | Verdict |
|---|---|
| `token_usage` climbing, every count identical | Wedge. Escalate — see the `ares-debug` skill |
| Any count advancing | Healthy, however slow it looks |
| `red_completed_at` set, `lock` = 1 | Red done, holding for blue drain. Not a wedge |
| `lock` = 0 and `completed_at` empty | Orchestrator died without finalizing → derived status `stopped` |
| `lock` = 1 but the `status` record's `updated_at` is older than `heartbeat_interval_secs × 3` | Orchestrator is dead; the lock is a 300s lease that has not expired yet. Derived status `running` is a lie for up to 5 minutes (`is_stale`, `operations.rs:88-101`) |
| `vuln_queue` ZCARD large and static while `exploited` static | Exploitation not popping — read `vuln_type_failures` |
| `exploited` climbing at the same rate as `superseded` | No new techniques proven; the credit is supersede cascade |
| `deferred_total` climbing without bound | Producer dedup not catching duplicates; compare ZSET ZCARD vs `:sigs` SCARD |
| Every HGETALL empty on an op you know ran | 24h TTL expired — measured from the **last write**, not from finalize (trap 6). Not "never ran" |

Deferred backlog per type, excluding the two keys that are not queued work:

```bash
redis-cli get "ares:deferred:$OP:__total"
redis-cli --scan --pattern "ares:deferred:$OP:*" \
  | grep -v -e ':sigs$' -e '__total$' \
  | while read -r k; do printf '%s\t%s\n' "$(redis-cli zcard "$k")" "$k"; done | sort -rn
```

## Reaching Redis without a local server

The CLI connects to `ARES_REDIS_URL` → `REDIS_URL` → `redis://localhost:6379`
(`ares-cli/src/redis_conn.rs:9-13`). From an agent host with no `redis-server` a bare
`ares ops list` exits `Failed to connect to Redis: Connection refused`. Three ways around it:

**A. `--ec2` re-execs the whole command on the box over SSM.** `maybe_exec_ec2` prescans argv
before clap, resolves the instance by Name tag, and runs `RUST_LOG=error ares <args>` remotely
(`ares-cli/src/main.rs:34-40`, `ares-cli/src/transport.rs:397-440`). The Redis connection is
therefore the *box's*, not yours. Defaults: `--ec2-profile lab`, `--ec2-region us-west-1`
(`ares-cli/src/cli/mod.rs:53-62`).

```bash
ares --ec2 kali-ares ops list
ares --ec2 kali-ares ops runtime --latest
```

> The `ares-debug` skill states this flag reads local Redis. That is wrong at HEAD — verify with
> `transport.rs:397`. A `Connection refused` from `ares --ec2 ...` means the local binary predates
> the transport module or the instance did not resolve; it is not evidence about the box's Redis.

Option A needs the local `./target/release/ares`, which **no ec2 task ever builds** (`BUILD_TOOL=remote`, the deploy default, builds only on the box) — `task ec2:loot` / `runtime` / `ops` / `watch` then exit **201** with "build it first" while the box is perfectly healthy. Either `cargo build --release -p ares-cli`, or use B.

**B. Run the box's own binary and `redis-cli` over SSM** — no local binary needed:

```bash
task ec2:exec EC2_NAME=kali-ares CMD='redis-cli ping'
task ec2:exec EC2_NAME=kali-ares CMD='redis-cli info keyspace'
task ec2:exec EC2_NAME=kali-ares CMD='redis-cli --scan --pattern "ares:op:*:meta"'
task ec2:ops:ids EC2_NAME=kali-ares    # all ops + started_at + derived status

# the CLI-backed reads, without the CLI gate
task ec2:exec EC2_NAME=kali-ares CMD='ares ops loot --latest --json'
task ec2:exec EC2_NAME=kali-ares CMD='ares ops runtime --latest'
task ec2:exec EC2_NAME=kali-ares CMD='ares ops inspect-vulns --latest --json'
```

Bounded by `ec2:exec`'s hardcoded 60 s SSM budget (`.taskfiles/ec2/Taskfile.yaml:1488`) and SSM's
~24 KB stdout cap — prefer `--json` and a narrow query over dumping a whole op.

`task ec2:exec` runs `CMD` through go-task's template engine and then `run_ssm_cmd ... 60`
(`.taskfiles/ec2/Taskfile.yaml:1472-1489`) — keep the outer quotes single, avoid `{{`, and keep the
payload short enough to finish inside the 60s SSM window. `ec2:ops:ids` ships a whole script
(`.taskfiles/ec2/scripts/list-ops.sh`) precisely because inline quoting is fragile.

**C. Port-forward, then point the CLI at it** — needed for typed output when you want it local:

```bash
task ec2:redis:forward EC2_NAME=kali-ares      # blocks in foreground; local port is 16379
ARES_REDIS_URL=redis://localhost:16379 ares ops list
```

The forwarded port is **16379**, not 6379 (`.taskfiles/ec2/Taskfile.yaml:779-804`). Do not run
`ec2:redis:forward` from an agent — it never returns.

In k8s, Redis is a pod in namespace `attack-simulation` behind `app=redis` and may require
`REDISCLI_AUTH` from the `redis-secret` secret (`.taskfiles/k8s/Taskfile.yaml:184-190`).

Prefer `--scan` over `KEYS` everywhere — every code path in the repo uses cursor iteration
deliberately (`operations.rs:265-296`, `:449-458`).

## What "cleared" actually clears

| Command | Clears | Leaves behind |
|---|---|---|
| `ares ops delete <op> --force` | `ares:op:<op>:*`, `ares:lock:<op>`, every `ares:task_status:*` whose JSON `operation_id` matches (`operations.rs:388-424`) | novelty, deferred, discoveries, heartbeats, tools, both active pointers, and `ares:blue:op:<op>:investigations` — the pattern is `ares:op:{op}:*`, so blue's tracking set outlives the "deleted" red op |
| `ares ops cleanup --max-age-hours N` | `delete_operation` for each non-running op older than N (`ops/delete.rs:41-70`) | same as above; refuses to touch a lock-held op |
| `ares blue delete <inv> --force` | `ares:blue:inv:<inv>:*` + SREM from the active set (`blue/delete.rs:27-46`) | `ares:blue:lock:<inv>`, the JetStream request |
| `ares blue delete-operation <op> --force` | resolves `ares:blue:op:<op>:investigations` and deletes each investigation's keys (`cli/blue.rs:95`, `blue/delete.rs:50`) | same as `blue delete`, per investigation |
| `ares blue cleanup --all --force` | `ares:blue:inv:*`, `ares:blue:op:*`, `ares:blue:active_investigations` + purges the NATS `BLUE_TASKS_STREAM` (`blue/delete.rs:126-186`) | `ares:blue:lock:*`, `ares:blue:heartbeat:*` |
| `task k8s:redis:clear` (invoked by `k8s:reset`) | `ares:op:*`, `ares:lock:*`, `ares:operations`, `ares:operation:active` — plus a dead `ares:tool_exec:*` pass (`.taskfiles/k8s/Taskfile.yaml:154-172`) | **`ares:blue:*`, `ares:novelty:*`, `ares:deferred:*`, `ares:discoveries:*`, `ares:task_status:*`, `ares:heartbeat:*`, `ares:tools:*`** |

**Four of those five commands block on an interactive `[y/N]` stdin prompt without `--force`** —
`ops delete` (`ops/delete.rs:25-33`), `blue delete` (`blue/delete.rs:17-25`), `blue delete-operation`
(`blue/delete.rs:73-79`), `blue cleanup --all` (`blue/delete.rs:152-155`). From an agent that hangs;
over SSM the 60s window expires with no output. `ares ops cleanup` has no prompt and no `--force`
flag (`ops/delete.rs:41-77`).

**Five** of the six SCAN patterns in `k8s:redis:clear`'s first loop (`.taskfiles/k8s/Taskfile.yaml:155`)
match keys nothing writes: `ares:operation:*:state`, `ares:operation:*:checkpoint_time`,
`ares:operations:*:status`, `ares:tasks:*`, `ares:results:*`. `ares:lock:*` is the only live one.
The later `ares:tool_exec:*` pass (`:167`) is dead too — tool dispatch moved to the NATS subject
`ares.tools.exec.{role}` (`worker/tool_executor.rs:174`, `nats.rs:103`) and the Redis key survives
only in a log line (`orchestrator/mod.rs:576`) and doc comments. Likewise `task k8s:redis:list`
scans `ares:operations:*:status`
(`.taskfiles/k8s/Taskfile.yaml:201`) — the real key is `ares:op:{id}:status` — so its "operation
status keys" section always prints `(none)`.

**A "cleared" Redis still carries a queued blue investigation, `ares:blue:lock:*`, and cross-run
novelty bias into the next op.** Clear those by hand for a genuinely cold start. Never `FLUSHALL`
on a box with a live op — `ops cleanup` refuses lock-held ops for a reason.

## Test-data rule

Allowed values only — see `references/tools-and-gates.md#test-conventions`.

## Route elsewhere

Routing map: `SKILL.md`. Nearest neighbours only:

| Question | Go to |
|---|---|
| "This op is stuck / slow / broken" | skill `ares-debug` (probe ladder, wedge signatures, tool-pruning cascade). Its Step-0 TYPE table (`SKILL.md:112-123`) agrees with this one; the only difference is scope — it covers 8 keys, this doc covers all of them |
| Which key a knob writes and how precedence resolves | `references/config-and-env.md` |
| Reading loot / runtime / inspect-vulns without a local binary | `references/deployment.md`, "Binary-free equivalents" |
| The mistakes this assistant actually makes on this repo | `references/hard-won-lessons.md` — read it first |
