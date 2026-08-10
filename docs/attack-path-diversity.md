# Attack Path Diversity

Getting from "launch 100 runs, walk ~1 path" to "launch 100 runs, walk 80–100
distinct paths." This is a *diversity* objective, not a *success* objective, so
the levers are different from the ones that make a single run finish faster.

## Why runs converge

Selection is deterministic greedy. The deferred queue scores each vuln
`priority * 1e9 + enqueue_time * 1000` (`orchestrator/deferred.rs`) and
`pop_best` takes the global minimum. With no randomization and no novelty term
in the drain loop, identical state drains in an identical order and every run
walks the same path. Strategy weights only affect which follow-up vulns the
automations *create*, not which one the queue picks next — so they change the
path's shape, not its variety. Absent the knobs below, the only diversity comes
from accident: recon host-discovery order, LLM sampling, tool-timeout noise.

The lab is not the limiter. Provisioning supports roughly 29 distinct
primitives and ~133 foothold×technique permutations to domain compromise (see
`domain-compromise-paths.md` in the DreadGOAD repo). The gap between "133
available" and "1 walked per run" lives in `ares-cli/src/orchestrator/`.

### Define "unique" before measuring

The target number is meaningless without this, and the two readings differ by
an order of magnitude:

| View | Ceiling | "Unique path" means |
|---|---|---|
| Distinct primitive | 29 | a different provisioned primitive / minimal chain to DA |
| Permutation | ~133 | a different (foothold × technique) traversal |

Target the **permutation view**: a path is the ordered sequence of
(foothold credential, technique class, target) tuples, and two runs are the
same path iff those sequences match. 80–100 unique under that view needs no lab
changes. Under the distinct-primitive view it would be above the 29 ceiling and
would require adding lab principals instead.

## The knobs

All four live under `operation:` in `config/ares.yaml` and **default to off**,
so a stock run reproduces the deterministic behaviour above. They ship enabled
nowhere — an operator has to turn them on and push the config to the box before
any of this takes effect.

| Key | Effect |
|---|---|
| `selection_temperature` | Softmax-samples the queue instead of taking the argmin, in `pop_next_vuln` (`exploitation.rs`) and `pop_best` (`deferred.rs`). `0.0` = exact argmin. |
| `novelty.enabled` / `novelty.scope` | Penalises `(technique, target)` steps already walked in prior runs, via a scoped Redis set (`ares:novelty:{scope}:steps`). This is what maximises *unique* paths rather than relying on sampling luck — without it, softmax keeps rediscovering the popular paths and the tail stays uncovered. |
| `emit_path_records` | Emits a per-run path record (`ares:op:{id}:path_record`) and coverage set (`ares:op:{id}:coverage`) on exploit success. |
| `randomize_entry_foothold` | Shuffles the entry recon targets in `bootstrap.rs`, pushing run N off run N−1's opening. |

Field definitions are in `ares-core/src/config/sections.rs`; the selection logic
is in `orchestrator/diversity.rs`.

## Operator workflow

```bash
# Run the sweep: preflight the deployed config, optionally wipe novelty memory,
# loop N ops sequentially, and write reports/diversity/<campaign>/coverage.csv
task benchmark:diversity-sweep N=10 TARGET=dreadgoad RESET=true

# Compare against a baseline: technique set-diff, (technique, target) pair
# coverage delta, path-length distribution, ranked top techniques
task benchmark:diversity-diff BEFORE=reports/red AFTER=reports/diversity/<campaign>
```

Both tasks live in `.taskfiles/benchmark/Taskfile.yaml`. The sweep runs ops
**sequentially on purpose** — novelty memory needs prior prefixes, so
parallelizing defeats it.

`.claude/skills/attack-path-diversity-sweep/SKILL.md` carries the end-to-end
playbook: config activation, reading the diff, a symptom→fix table for bad
sweeps, and temperature iteration guidance.

> A header-only `coverage.csv` means the sweep fired all N ops concurrently and
> marked every submit "completed" without waiting. Check that before concluding
> the knobs did nothing.

## Recon→queue coverage audit

The original premise — "whole families are dark, never enumerated" — turned out
to be **false**. MSSQL impersonation and linked-server, delegation
(constrained/unconstrained/RBCD), and ADCS (ESC 1–15) are all enumerated,
parsed, registered, queued and exploited by existing modules. The real gaps were
routing, parsing and provisioning correctness bugs. Each was confirmed by
reading code and has since been fixed:

| # | Family | Gap | Fix |
|---|---|---|---|
| 1 | ADCS | ESC9 & ESC10 categorically failed — routed to `privesc`, but the only UPN-write tool was `acl`-only and that container lacks `certipy`. | Added `certipy_account_update` (certipy *is* on privesc, so the chain runs on one worker) and repointed the ESC9/ESC10 instructions to it. |
| 2 | Delegation | Kerberos-only constrained parsed identically to protocol-transition → wrong S4U payload, always failed S4U2Self. | Parser sets a `protocol_transition` flag (`w/o` ⇒ false); `build_s4u_payload` surfaces it with S4U2Proxy-only guidance. |
| 3 | MSSQL | Impersonation target hardcoded to `"sa"` → grantee→non-sa logins never fired. | `impersonate_target` captured per grant and threaded into the probe. |
| 4 | MSSQL | `vuln_id = mssql_impersonation_{host}` collapsed multiple grants via `HSETNX`. | vuln_id is now per `(scope, grantee, target)`. |
| 5 | MSSQL | DB-level `EXECUTE AS USER` never enumerated (server view only). | Enum query resolves principal names and queries `master`/`msdb` `sys.database_permissions`; parser emits a vuln per grant. |
| 6 | MSSQL | Objectives steered the LLM to unparsed `mssql_command` → linked-server / impersonation vulns never registered. | Objectives now call the parsed `mssql_enum_impersonation` / `mssql_enum_linked_servers` tools. |
| 7 | ADCS | ESC4 picked the first same-domain cred instead of the GenericAll holder. | certipy parser captures the write-holder principal into `account_name`; `find_adcs_credential` prefers it. |
| 8 | Delegation | RBCD rows from findDelegation misclassified as constrained. | Parser checks `resource`/`rbcd` before `constrained` and emits the bare `rbcd` type the automation watches. |

Alongside these, the queue was rebalanced in `config/ares.yaml`: `acl_abuse` was
priority 1, so the high-volume ACL graph drained first every run and starved the
MSSQL families at 10/11. ACL is now 3 and MSSQL impersonation/linked are lifted
to 3. That rebalance reached nothing until the `acl_abuse`/`dacl_abuse` key
mismatch was fixed — `auto_dacl_abuse` looked up `dacl_abuse` and fell through
to the default weight of 5. Both spellings now resolve to the same weight.

## Still outstanding

Selection diversity is necessary but not sufficient. Raising the
distinct-primitive ceiling past 29 means adding **principals**, not new vuln
classes — the certificate-template any-user grant scales path count with the
number of forest accounts (+7 paths per added account). Adding cold-start creds
or duplicate primitives is pure redundancy.

Two open risks worth tracking:

- **Exploration vs. completion.** Softmax and novelty trade single-run
  efficiency for fleet diversity; some runs take longer or take worse paths.
  Keep the deterministic mode for "best path" ops.
- **Dedup interaction.** Dedup is artifact-level (`ares-cli/src/dedup/`), not
  path-level. Confirm it isn't suppressing the re-exploration diversity depends
  on.
