---
name: attack-path-diversity-sweep
description: Run a fleet of red-team ops with the attack-path diversity knobs on and produce a coverage CSV + comparison against a baseline. Use whenever the ask is to "get more attack variety", "capture varied ops for replay", "unlock techniques that never show up", "sweep to see which paths the LLM will explore under exploration", or "compare a sweep against reports/red baseline". The feature (softmax queue selection, cross-run novelty memory, entry-foothold shuffle, path records) is fully merged on main but SHIPS DISABLED — the knobs must be turned on in `config/ares.yaml` and pushed to the box before any of it takes effect. Also covers the sequel: how to read the resulting CSV, what a good sweep looks like vs a bad one, and how to iterate on temperature.
---

# Attack-path diversity sweep

Turn a single-path fleet into a many-path fleet. Four knobs make it happen; two tasks (`benchmark:diversity-sweep`, `benchmark:diversity-diff`) drive the workflow. Design doc: `docs/attack-path-diversity.md`. Feature code: `ares-cli/src/orchestrator/diversity.rs`.

## What "diversity off" looks like

Baseline (all 27 ops in `reports/red/`, July 3–6 2026) converges on one signature:

```
autologon_registry → workstation admin hash → dc_secretsdump → golden_ticket
                   → child_to_parent (ExtraSid) → mssql_access
                   → mssql_linked_server → seimpersonate → far-forest DA
```

22 of 26 successful ops execute exactly that. `constrained_delegation`, `unconstrained_delegation`, `rbcd`, `adcs_esc4`, `adcs_esc9/10`, and `genericall` are **found** every run and **exploited zero times**. That's the diversity deficit the knobs address.

## Step 1 — Turn the knobs on

Edit `config/ares.yaml` in the `operation:` block. Uncomment:

```yaml
selection_temperature: 0.7      # 0 = deterministic argmin; higher = softmax spread
novelty:
  enabled: true
  scope: per-campaign           # keys novelty memory to campaign name
randomize_entry_foothold: true  # shuffles entry IP order per op
emit_path_records: true         # writes ares:op:<op>:path_record to Redis
```

**All four default to off.** If the sweep task runs against a box where the knobs are commented out, it aborts in preflight — that's intentional, don't work around it.

Push to the box:

```bash
task ec2:deploy
```

## Step 2 — Run the sweep

```bash
task benchmark:diversity-sweep N=10 TARGET=dreadgoad RESET=true
```

**What the task does, in order:**

1. **Preflight** — SSMs the EC2 instance, greps `/etc/ares/config.yaml`, refuses to proceed if `selection_temperature` is `0` or missing. Prevents accidentally running a "diversity sweep" against a deterministic config.
2. **Novelty reset** (`RESET=true` only) — wipes `ares:novelty:*:steps` in Redis so the campaign starts fresh. Skip if you want a follow-up sweep to inherit the prior sweep's novelty memory.
3. **Sequential loop** — launches N ops through `red:ec2:multi`, one at a time. **Do not parallelize.** Novelty memory needs prior runs' prefixes to bias against; parallel runs see empty memory and converge just like determinism does.
4. **CSV emission** — for every successful op, pulls `ares:op:<op>:path_record` (a Redis list of `PathStep` JSON) and writes rows to `reports/diversity/<campaign>/coverage.csv` with columns `op_id,step_index,technique,target`. Also writes `ops.txt` (manifest with FAILED markers) and the full per-op reports under `red/`.

Args:

| Var | Default | Notes |
|---|---|---|
| `N` | required | Op count. 5 is a smoke test; 10+ before drawing conclusions. |
| `TARGET` | required | Lab name — `dreadgoad` for the default lab. |
| `CAMPAIGN` | timestamped | Also becomes the novelty-memory scope. Pin when running variants back-to-back. |
| `RESET` | `false` | `true` wipes novelty memory across ALL scopes before starting. |
| `EC2_NAME` | `kali-ares` | Instance Name tag substring. |
| `OUTPUT_DIR` | `./reports/diversity` | Root for `<campaign>/` subdir. |

## Step 3 — Read the results

```bash
task benchmark:diversity-diff BEFORE=reports/red AFTER=reports/diversity/<campaign>
```

Both args are directories. The task auto-detects format:

- If the dir has `coverage.csv`, it uses the full path_record (every step, ordered).
- Otherwise it greps `*.md` for `#### <name>` + `- **Status**: EXPLOITED` (coarser — exploited-only).

Comparing a sweep against `reports/red` uses the second mode for the baseline and the first for the sweep. That's fine; both normalize to `(op, technique, target)` triples.

The output has four sections:

1. **Technique classes** — set diff. The `AFTER only` line is the payoff — if empty, the knobs unlocked nothing.
2. **(technique, target) pair coverage** — set counts and overlap. The `AFTER-only pairs (novel)` number is your coverage delta.
3. **Techniques per op (median/mean/max)** — path-length distribution. Sweeps should have longer paths (LLM exploring more before locking in).
4. **Top techniques (op count)** — a two-column table with per-technique op counts. Watch which of the "dark family" techniques (`constrained_delegation`, `rbcd`, `adcs_esc4`, `adcs_esc9`, `genericall`) show up in the AFTER column that were 0 in BEFORE.

## What a good sweep looks like

- **`AFTER only` non-empty** with at least one of: `constrained_delegation`, `unconstrained_delegation`, `rbcd`, `adcs_esc4`, `adcs_esc9`, `adcs_esc10`, `genericall`.
- **`AFTER-only pairs (novel)` ≥ 30%** of the AFTER pair count.
- **DA success rate ≥ 70%** across the sweep (check `ops.txt` for FAILED markers). Sweeps trade single-run efficiency for fleet coverage; some ops will time out or take suboptimal paths. That's fine as long as the majority still reach DA.

## What a bad sweep looks like, and how to fix it

| Symptom | Cause | Fix |
|---|---|---|
| `AFTER only` empty, `AFTER-only pairs = 0` | Temperature too low OR novelty not actually on | Bump `selection_temperature` to `1.0`; verify `novelty.enabled: true` in `/etc/ares/config.yaml` on the box |
| All ops FAILED | Temperature too high (LLM chasing low-value paths) | Drop to `0.3–0.5` |
| Same "novel" alt path picked every run | Novelty memory got stuck / not scoped right | `redis-cli DEL ares:novelty:per-campaign:steps` and re-run, or bump temperature |
| Preflight fails with "selection_temperature is 0 or missing" | Config never actually deployed | Confirm `config/ares.yaml` was edited (not `ares.yaml.example`), then `task ec2:deploy` and check `mtime` of `/etc/ares/config.yaml` on the box |
| CSV empty despite ops succeeding | `emit_path_records: false` OR wrong Redis key | Verify the knob is uncommented; check `redis-cli KEYS 'ares:op:*:path_record'` on the box |

## What the knobs actually do (code-level)

For debugging when the sweep behaves weirdly:

- **`selection_temperature`** (`diversity.rs::softmax_select_index`) — replaces the argmin in `pop_best` and `pop_next_vuln` with softmax sampling by inverse priority. At 0 it degrades to exact argmin (previous behavior).
- **`novelty.enabled` / `novelty.scope`** — before dequeue, top-K candidates get scored against `ares:novelty:{scope}:steps` (a Redis set of `technique:target` strings from prior runs). Already-walked steps take a penalty. Same-campaign runs share memory; cross-campaign runs don't.
- **`randomize_entry_foothold`** (`bootstrap.rs::dispatch_initial_recon`) — shuffles the entry IP list before initial recon. Cheapest possible diversity source — pushes op N off op N-1's opening move even if the queue is deterministic. Also reduces detection signature (the standing `autologon_registry → workstation admin` opener is the loudest primitive in current runs).
- **`emit_path_records`** (`diversity.rs::record_step`) — appends `PathStep {technique, target}` to `ares:op:<op>:path_record` on every successful exploit. This is the data the sweep task reads back.

Rebalanced technique weights (already active on main, not gated by any knob):

```yaml
technique_weights:
  esc1: 1
  esc4: 1
  constrained_delegation: 2
  unconstrained_delegation: 2
  rbcd: 2
  acl_abuse: 3          # demoted from 1
  mssql_access: 3
  mssql_impersonation: 3
  mssql_linked: 3
```

`acl_abuse` was priority 1, which is why the ACL graph drained the queue first every run and starved MSSQL/delegation families. Demotion to 3 is what makes the softmax-sampled queue actually surface those families.

## Iterating temperature

Start at 0.7. If the sweep unlocks nothing new after 10 ops, bump to 1.0 and rerun (with a new CAMPAIGN name so novelty memory doesn't cross-contaminate). If ops start failing, drop to 0.5. Don't go above 1.5 — the LLM starts picking demonstrably worse paths.

For "less noisy" runs (the sequel goal — lower blue detection score), `randomize_entry_foothold: true` alone helps most; combined with softmax at 0.3 (mild spread, not aggressive) you get some path diversity without the LLM chasing exotic techniques that generate loud traffic.

## Reference

| What | Where |
|---|---|
| Design doc (phases, ceiling analysis) | `docs/attack-path-diversity.md` |
| Feature code | `ares-cli/src/orchestrator/diversity.rs` |
| Config knobs | `config/ares.yaml` around line 74 |
| Sweep task | `.taskfiles/benchmark/Taskfile.yaml` (`diversity-sweep`, `diversity-diff`) |
| Baseline (deterministic) reports | `reports/red/*.md` |
| Redis keys | `ares:op:<op>:path_record` (list), `ares:op:<op>:coverage` (set), `ares:novelty:<scope>:steps` (set) |
