# Attack Path Diversity — Plan

How to get from "launch 100 runs, see ~1 path" to "launch 100 runs, get 80–100
unique attack paths." This is a *diversity* objective, not a *success* objective —
the levers are different.

## Implementation status

Landed (this change): the orchestrator-side levers and instrumentation —
Phase 0 (path records + coverage) and Phase 1 (softmax selection, cross-run
novelty memory, randomized entry foothold). All gated by `operation:` config
keys in `config/ares.yaml` and **off by default**, so deterministic behaviour is
unchanged until an operator opts in.

- `selection_temperature` → softmax sampling in `pop_next_vuln`
  (`exploitation.rs`) and `pop_best` (`deferred.rs`); 0.0 = exact argmin.
- `novelty.enabled` / `novelty.scope` → cross-run prefix avoidance via a scoped
  Redis set (`ares:novelty:{scope}:steps`), penalising already-walked
  `(technique, target)` steps.
- `emit_path_records` → per-run path record (`ares:op:{id}:path_record`) and
  coverage set (`ares:op:{id}:coverage`) emitted on exploit success.
- `randomize_entry_foothold` → shuffles the entry recon targets in `bootstrap.rs`.

Still outstanding: **Phase 2** (recon→vuln enumeration of the dark families —
MSSQL impersonation/linked-server, delegation, advanced ADCS) and **Phase 3**
(lab principals). Selection diversity is necessary but not sufficient for 80–100
unique paths until the dark families actually enter the queue.

## Operator workflow

Turning the knobs on and measuring the result is driven by two Taskfile tasks
and a Claude skill:

- **`task benchmark:diversity-sweep N=10 TARGET=dreadgoad RESET=true`** —
  preflight-checks the deployed config, optionally wipes novelty memory, loops
  N `red:ec2:multi` ops sequentially (novelty needs prior prefixes; do not
  parallelize), pulls `ares:op:<op>:path_record` back through SSM, and writes
  `reports/diversity/<campaign>/coverage.csv` with `(op_id, step_index,
  technique, target)` rows. This is the Phase 0 measurement loop.
- **`task benchmark:diversity-diff BEFORE=reports/red AFTER=reports/diversity/<campaign>`** —
  auto-detects CSV vs `reports/red`-style markdown, then prints technique
  set-diff, `(technique, target)` pair coverage delta, path length
  distribution, and a top-technique ranked table. Use it to answer "did the
  sweep unlock techniques the baseline never exploited?"
- **`.claude/skills/attack-path-diversity-sweep/SKILL.md`** — end-to-end
  playbook covering config activation, running the sweep, reading the diff, a
  symptom→fix troubleshooting table for bad sweeps, and temperature iteration
  guidance.

Both tasks live in `.taskfiles/benchmark/Taskfile.yaml`.

## Phase 2 audit findings (recon→queue coverage)

The original premise — "whole families are dark / never enumerated" — turned out
to be **false** for the current codebase. MSSQL impersonation + linked-server,
delegation (constrained/unconstrained/RBCD), and ADCS (ESC 1–15) are all
enumerated → parsed → registered → queued → exploited by existing modules. The
real gaps are **routing/parsing/provisioning correctness bugs**, not missing
enumeration. Audited against the lab spec
(`../DreadOps/apps/DreadGOAD/docs/domain-compromise-paths.md`); each item below is
confirmed by reading code, with file:line.

Fixed in this change:

- **Queue rebalance** (`config/ares.yaml`). `acl_abuse` was priority 1 (top), so
  the high-volume ACL graph drained first every run and starved the MSSQL
  families (which fell back to 10/11). ACL de-dominated to 3; MSSQL
  impersonation/linked lifted to 3. This is the "rebalance the ACL flood" lever.
  Correction: until the `acl_abuse`/`dacl_abuse` key mismatch was fixed, this
  lever reached no ACL driver at all — `auto_dacl_abuse` looked up `dacl_abuse`
  and fell through to the default weight of 5. Both spellings now resolve to the
  same weight, so the rebalance above takes effect for the first time.

| # | Family | Gap | Fix |
|---|---|---|---|
| 1 | ADCS | ESC9 & ESC10 categorically failed — routed to `privesc`, but the only UPN-write tool was `acl`-only and that container lacks `certipy`. | Added a `certipy_account_update` tool (certipy *is* on privesc, so the whole chain runs on one worker) and repointed the ESC9/ESC10 instructions to it. |
| 2 | Delegation | Kerberos-only constrained (N6) parsed identically to protocol-transition (N4) → wrong S4U payload, always failed S4U2Self. | Parser sets a `protocol_transition` flag (`w/o` ⇒ false); `build_s4u_payload` surfaces it with explicit S4U2Proxy-only guidance for kerberos-only accounts. |
| 3 | MSSQL | Impersonation target hardcoded to `"sa"` → grantee→non-sa logins never fired. | `impersonate_target` captured per grant and threaded into the probe (falls back to `sa`). |
| 4 | MSSQL | `vuln_id = mssql_impersonation_{host}` collapsed multiple grants via `HSETNX`. | vuln_id is now per `(scope, grantee, target)`. |
| 5 | MSSQL | DB-level `EXECUTE AS USER` never enumerated (server view only). | Enum query resolves principal names and also queries `master`/`msdb` `sys.database_permissions`; parser emits a vuln per grant. |
| 6 | MSSQL | Objectives steered the LLM to unparsed `mssql_command` → linked-server / impersonation vulns never registered. | Objectives #4/#5 now call the parsed `mssql_enum_impersonation` / `mssql_enum_linked_servers` tools. |
| 7 | ADCS | ESC4 picked the first same-domain cred instead of the GenericAll holder. | certipy parser captures the write-holder principal into `account_name` for ESC4/7/9/10; `find_adcs_credential` prefers it and still falls back. |
| 8 | Delegation | RBCD rows from findDelegation misclassified as constrained (latent). | Parser checks `resource`/`rbcd` before `constrained` and emits the bare `rbcd` type the automation watches. |

## TL;DR

The lab is not the limiter. The orchestrator is. Provisioning already supports
**29 distinct paths / ~133 foothold×technique permutations** to domain compromise
(see `../DreadOps/apps/DreadGOAD/docs/domain-compromise-paths.md`). The
exploitation queue defaults to deterministic greedy, so identical state drains in
an identical order and every run walks the *same* path. The gap between "133
available" and "1 walked per run" is the entire deficit, and it lives in
`ares-cli/src/orchestrator/`.

**Status:** the selection levers described below are implemented and shipped —
`orchestrator/diversity.rs`, wired at `exploitation.rs:313-387` and
`deferred.rs:386`, gated behind `selection_temperature`, `novelty.enabled` and
`randomize_entry_foothold` in `config/ares.yaml`. All three default to off, so a
stock run still reproduces the deterministic behaviour analysed here.

Lever ranking: **add exploration to selection** (free, decisive) > **fix
recon→vuln-state coverage** (free, unlocks dark families) > **add lab principals**
(only to push past the 29 distinct-primitive ceiling). Adding new vuln *classes*
is unnecessary — they already exist.

## Step 0: pin down what "unique" means

Pick one before measuring; the target number is meaningless without it.

| View | Ceiling | "Unique path" = |
|---|---|---|
| Distinct primitive | **29** | a different provisioned primitive / minimal chain to DA |
| Permutation | **~133** | a different (foothold × technique) traversal; ADCS is open-ended |

- **80–100 unique under the permutation view → no lab changes needed.** The ~133
  already exist; the job is purely to make the orchestrator traverse different
  ones. This is the realistic reading of the goal.
- **80–100 unique under the distinct-primitive view → above the 29 ceiling.**
  Requires lab expansion (Phase 3). Demanding 80–100 *distinct primitives* is
  asking for a different lab; 29 distinct technique classes across 100 runs is
  already a strong result.

Recommendation: target the **permutation view**. Define a path canonically as the
ordered sequence of (foothold credential, technique class, target) tuples, and
two runs are "the same path" iff their canonical sequences match.

## Diagnosis

Two facts, both verified in code/spec:

1. **Selection is deterministic greedy — 100 runs ≈ 1 path.** The deferred queue
   scores each vuln `priority * 1e9 + enqueue_time * 1000`
   (`ares-cli/src/orchestrator/.../deferred.rs:80-83`) and `pop_best` always takes
   the global minimum (`deferred.rs:179-238`). No randomization, no temperature,
   no novelty term anywhere in the drain loop (`exploitation.rs:112-137`). Strategy
   weights (`strategy.rs:238-244`) only affect *automation-created* follow-up
   vulns, not the queue selection that picks the actual path. Accidental variance
   (recon host-discovery order, LLM temperature, tool-timeout noise) is the only
   thing producing any diversity today.

   Resolved: `pop_best` now branches to softmax selection when
   `selection_temperature > 0` or `novelty_enabled` (`exploitation.rs:323`,
   `:370`, `:387`). With both knobs at their defaults the deterministic path
   above is still exactly what runs.

2. **Recon→vuln-state mapping leaves whole families dark.** Per the lab spec,
   MSSQL impersonation / linked-server is **13 paths**, delegation is 3, and the
   advanced certificate-template ESCs add several more — all provisioned, all
   reachable, none reliably enumerated into actionable queue state. Meanwhile the
   ACL graph *floods* the queue. So the queue is simultaneously starved (dark
   families never enter) and noisy (ACL edges dominate).

## The work

### Phase 0 — Instrument & baseline (do first, cheap)

You cannot tune diversity you cannot measure.

- Emit a structured **path record** per run: the canonical (foothold, technique,
  target) sequence defined in Step 0, plus first-DA timestamp and domain reached.
- Add a **coverage metric**: unique canonical paths / runs, and which of the ~133
  permutations were touched. Map observed paths back to the spec's path IDs
  (N1–N6, S1–S7, E1–E12, C1–C4).
- Run 10 baseline ops. Expectation: coverage collapses to a small handful. This
  confirms the deficit is selection, not the lab, and gives you a number to beat.

Acceptance: a dashboard/report answering "of the 133, how many did N runs hit?"

### Phase 1 — Exploration in selection (the decisive lever)

Convert latent paths into observed ones. Two mechanisms, layered:

- **Softmax-sample the queue** instead of argmin. Add a temperature knob to
  `pop_best`: sample from the priority distribution rather than taking the
  minimum, so equal/near-equal-priority vulns get chosen in different orders
  across runs. Temperature 0 = current behavior (keep as a flag for reproducible
  runs).
- **Cross-run novelty memory.** Persist walked path prefixes; bias each run *away*
  from prefixes already seen in prior runs (penalty added to score, or
  epsilon-greedy override of `pop_best`). This is what deliberately maximizes
  *unique* paths rather than relying on sampling luck. Without it, softmax
  rediscovers the popular paths repeatedly and the tail goes uncovered.
- Optional: **randomize the entry foothold** per run (and/or a "forbidden first
  move") so run N is pushed off run N−1's opening. Cheapest possible diversity
  source; useful even before the queue rework lands.

Acceptance: coverage from Phase 0 baseline rises substantially across the same
run count; the tail (rarely-chosen paths) starts getting hit.

### Phase 2 — Recon→vuln coverage (unlock the dark families)

Make the present-but-dark primitives enter the queue as actionable state:

- **MSSQL impersonation / linked-server (13 paths).** Highest leverage — this is
  the largest dark family and the documented bottleneck. Enumerate impersonation
  edges and cross-link sysadmin reach into vuln state the strategy can act on.
- **Delegation (3).** Constrained (protocol-transition and kerberos-only) and
  unconstrained+coercion. Each is a clean DA finisher independent of relay timing.
- **Advanced certificate-template ESCs.** The any-user templates and the
  write-holder ESCs that are rarely fired.
- While here, **rebalance the ACL flood** so it doesn't crowd out newly-enumerated
  families (this pairs naturally with Phase 1's selection rework).

Acceptance: MSSQL and delegation path IDs appear in coverage reports; they were
absent at baseline.

### Phase 3 — Raise the distinct-primitive ceiling (optional, only if needed)

Only relevant if you insist on the distinct-primitive view (>29). Do *not* add
new vuln classes — add principals, because the certificate-template any-user
grant scales path count with the number of forest accounts (+7 paths per added
account, per the spec). This is the one cheap, open-ended lab lever, and it's
closer to "change user perms" than "change which vulns." Adding cold-start creds
or duplicate primitives is pure redundancy.

## Success criteria

- A single canonical definition of "unique path" (Step 0), used consistently.
- A coverage metric and baseline (Phase 0).
- Phase 1 + Phase 2 land and coverage approaches the permutation ceiling across
  100 runs. If targeting the permutation view, **this is sufficient for 80–100 —
  no lab changes.**
- Reproducibility preserved: temperature 0 / novelty-off reproduces deterministic
  runs for debugging.

## Key references

| What | Where |
|---|---|
| Queue score formula | `ares-cli/src/orchestrator/.../deferred.rs:80-83` |
| Greedy `pop_best` (no exploration) | `deferred.rs:179-238` |
| Exploitation drain loop | `ares-cli/src/orchestrator/.../exploitation.rs:112-137` |
| Strategy weights (automation-only) | `ares-cli/src/orchestrator/strategy.rs:238-244` |
| Artifact-level dedup (not path-level) | `ares-cli/src/dedup/mod.rs` |
| Lab path inventory (29 / ~133) | `../DreadOps/apps/DreadGOAD/docs/domain-compromise-paths.md` |

## Risks / open questions

- **Novelty memory storage.** Cross-run state needs a home (Redis keyspace?) and a
  reset/scope policy so unrelated operations don't poison each other's novelty
  bias.
- **Exploration vs. completion.** Softmax/novelty trades single-run efficiency for
  fleet diversity; some runs will take longer or take worse paths. Acceptable for
  a diversity objective, but keep the deterministic mode for "best path" ops.
- **Dedup interaction.** Dedup is artifact-level today; confirm it doesn't
  silently suppress re-exploration that diversity depends on.
- **Counting drift.** The ~133 is sub-rule-sensitive (91 / 128 / 133). Lock the
  counting rule in Step 0 or the target number moves under you.
