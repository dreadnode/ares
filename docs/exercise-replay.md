<!-- markdownlint-disable MD013 -->

# Exercises — replayable, packaged engagements

Design doc. Complements `benchmark-replay.md` (operational),
`benchmark-replay-strategy.md` (blue-eval strategy), and
`benchmark-replay-timeline-spec.md` (clock/unfolding contract).

## What we mean by "exercise"

An **exercise** is a fully-serialized adversarial engagement, packaged as a
versioned artifact that anyone can replay to reproduce the same engagement.

Today's `ares benchmark capture` produces something close to this — a snapshot
directory with red state, Loki logs, alerts, dashboards, annotations. But it is
positioned narrowly as *input to blue-team evaluation*. The "exercise" framing
promotes the same artifact to first class and unlocks four more uses:

1. **Demo playback** (this talk, and every future talk) — deterministic, no
   agent runtime, no lab needed.
2. **Blue-agent eval** (what benchmark:replay already does) — telemetry
   replays, blue investigates live.
3. **Red-agent eval** (new) — start conditions replay, a fresh red agent runs
   against the same initial world.
4. **Head-to-head replay** (new) — both agents restart from a checkpoint,
   race again.
5. **CI regression** (partial today via `benchmark:replay:loop`) — any prompt
   or config change replays N exercises, score regression is a hard gate.
6. **Public reproducibility** (new) — exercises published as versioned
   artifacts, community can validate our numbers by re-running them.

Reframing snapshots as exercises is 30% new engineering, 70% naming +
distribution + a few missing pieces.

## Anatomy of an exercise

```text
exercise-<id>/
├── manifest.yaml                  # metadata + schema version
├── README.md                      # narrative — what happened, difficulty, tags
├── red-state.json                 # starting conditions + full red execution trace
├── ground-truth.json              # IOCs, techniques, timeline, DA path
├── loki/                          # per-stream JSONL.gz — Windows/Sysmon/PS
├── tempo/                         # trace bundle (NEW — see gap below)
├── alerts/                        # rule firings with timestamps
├── metrics/                       # Prometheus series over the window
├── dashboards/                    # Grafana JSON at capture time (versioning)
├── annotations/                   # Grafana annotations
├── checkpoints/                   # (NEW) mid-run world snapshots for fork replay
│   ├── t+00-30.json               # world state at 30s in
│   ├── t+02-00.json
│   └── ...
└── signatures/                    # (NEW) cosign-style attestations for public dist
```

### Manifest — the identity of an exercise

```yaml
schema_version: 2
exercise_id: dreadgoad-cross-forest-esc5
title: "Cross-forest DA via ESC5 Golden Certificate"
version: 1.3.0
captured_at: 2026-07-05T10:11:28Z
captured_by: kali-ares
capture_config:                    # what was on when this ran
  diversity_temperature: 0.0
  novelty_enabled: false
  random_entry_foothold: false
llm:                               # provenance, not required for replay
  model: anthropic/claude-opus-4-8
  temperature: 0.7
target:
  lab: dreadgoad
  topology: 2-forest-3-domain
difficulty: hard                   # informal — signal to consumers
tags: [cross-forest, adcs, esc5, golden-cert, kerberos]
red_summary:
  first_da_at: 6m40s               # from op start
  first_da_domain: child.contoso.local
  domains_dominated: 3
  techniques: [T1590.001, T1078.002, T1550.003, T1649, T1558.001]
  final_outcome: full-domain-dominance
blue_baseline:                     # what a reference blue run scored
  score: 0.71
  ioc_detection: 6/9
  ttps_covered: 18/24
  time_to_first_alert_seconds: 11.4
integrity:
  content_hash: sha256:abc123...
  signer: dreadnode/keys/ares-release@v1
```

Schema version is load-bearing. Anyone who publishes an exercise commits to
loading it back in five years. Everything downstream reads through
`ares-cli/src/benchmark/versions.rs`.

## Replay modes

Six modes, one artifact.

| Mode | Red | Blue | World | Use case |
|---|---|---|---|---|
| **visual** | replayed (trace playback) | replayed (trace playback) | replayed (Loki + Tempo + alerts stream) | Demos. No agents run. Deterministic. This talk. |
| **blue-eval** (existing) | replayed | live agent | replayed (Loki + alerts) | Blue benchmark. What `ares benchmark run` does today. |
| **red-eval** (new) | live agent | absent | starting state only | Red benchmark — can a fresh red reach DA from the same foothold? |
| **head-to-head** (new) | live agent | live agent | live lab | Full engagement. Requires a warm lab. |
| **checkpoint-fork** (new) | live from checkpoint | live from checkpoint | replayed up to checkpoint, then live | "What if blue caught this 30s earlier?" Explore counterfactuals. |
| **counterfactual** (new) | replayed with edits | live agent | replayed with edits | "What if this alert never fired?" Removes signals from the telemetry stream. |

`visual` is the demo primary path. `blue-eval` is the existing evaluation
harness. The other four are new and worth building only if they unblock
research or product use cases.

## Distribution

Once exercises are versioned artifacts, they need a home.

Three options in decreasing order of engineering weight:

1. **OCI registry** (recommended). Push exercises as OCI artifacts (like Helm
   charts / ORAS-compatible bundles). Content-addressed, signed with cosign,
   pull with `ares exercise pull ghcr.io/dreadnode/exercises/dreadgoad-cross-forest-esc5:1.3.0`.
   Aligns with how DreadGOAD range images already ship.
2. **GitHub Releases** on `dreadnode/ares-exercises`. Zero infra, human-browseable.
   Fine for the first 10 exercises; friction grows with the catalog.
3. **S3 bucket with an index.** What we do now, minus the "exercise" framing.
   Cheapest, no signing story, no public distribution.

For Black Hat launch: option 2 (GH Releases) with a hand-curated set of 5–10
exercises. Migrate to option 1 in the following quarter if adoption warrants.

## What's built today, what's missing

Confirmed against `ares-cli/src/benchmark/{capture,manifest,replay}.rs` and
`docs/benchmark-replay.md`:

| Capability | Built | Gap |
|---|---|---|
| Red-state serialization | ✅ | Full execution trace lives in `red-state.json` |
| Loki telemetry capture | ✅ | `--wait-for-flush` handles ingester latency |
| Grafana alert capture | ✅ | Annotations + fired-alerts JSON |
| Prometheus metrics capture | ✅ | Windowed series |
| Grafana dashboard capture | ✅ | JSON at capture time (for schema drift) |
| Ground-truth generation | ✅ | `ares-core/src/eval/ground_truth/transform.rs` |
| Manifest w/ schema versioning | ✅ | `MANIFEST_VERSION = 1` today; bump to 2 for exercises |
| S3 upload | ✅ | Snapshot-level today |
| Blue-eval replay (`benchmark:replay`) | ✅ | Full harness with seeded replicates |
| `wallclock` / `step` / `static` unfolding | ✅ | Clock state machine in `ares-core/src/replay_clock.rs` |
| Deterministic scoring | ✅ | Seed + temperature + K-of-N replicates |
| **Tempo trace capture** | ❌ | Blocking for `visual` mode and for the demo attack-graph panel |
| **Tempo trace replay** | ❌ | Push captured spans into ephemeral Tempo during replay |
| **Exercise manifest schema v2** | ❌ | Title, version, difficulty, tags, blue baseline, capture config, signatures |
| **README.md generator** | ❌ | Narrative summary from red state + ground truth |
| **Signing / attestation** | ❌ | Cosign integration for public artifacts |
| **`ares exercise` CLI verb** | ❌ | `capture --exercise-id`, `pull`, `run --mode visual|blue-eval|red-eval|...`,`list`,`verify` |
| **Checkpoint capture** | ❌ | World state at N intervals during a live run |
| **Public catalog** | ❌ | Repo + index + versioning conventions |

## Roadmap: from snapshot to exercise

Phases are independent of each other; each ships value.

### Phase 1 — Tempo capture + replay (BLOCKING FOR DEMO)

Add trace capture to `ares benchmark capture` and replay into ephemeral Tempo.

- Extend `SnapshotManifest` with `tempo_traces_captured: usize`.
- `capture.rs` → pull traces for the operation window from Tempo (TraceQL by
  `attack_operation_id`), gzip to `tempo/traces.jsonl.gz`.
- `replay.rs` → after ephemeral Tempo boots, push captured spans in via the
  OTLP HTTP endpoint. Clock advance already handles time re-anchoring.
- Preserves the demo dashboard's attack-graph panel working against a
  captured op, not just live.

**Owner:** Jayson. **ETA:** 2–3 days. **Precondition:** must land before
demo dashboard work depends on it.

### Phase 2 — Exercise manifest v2 + `ares exercise` CLI

Reframe existing bundles as exercises. Additive; snapshot v1 still readable.

- Bump `MANIFEST_VERSION` to 2. Migrate loader in `versions.rs`.
- New fields: `exercise_id`, `title`, `version`, `difficulty`, `tags`,
  `blue_baseline`, `capture_config`.
- New verb: `ares exercise capture --from-op <op-id> --title "..." --tag ...`.
  Wraps `benchmark capture` and writes the extended manifest.
- New verb: `ares exercise list [--local | --catalog]`.
- New verb: `ares exercise verify` (schema + content hash).
- README auto-generation from red-state + ground-truth (small Tera template).

**Owner:** Jayson + Shane. **ETA:** 1 week. **Not blocking for demo but
blocks public catalog.**

### Phase 3 — Visual replay mode

`ares exercise run <id> --mode visual` — no agents run, no LLM calls, no lab.
The command streams captured telemetry into ephemeral Loki + Tempo + alert
receivers at wall-clock timings. Everything the audience sees on the demo
dashboard renders identically to a live op, deterministically.

Implementation is small once Phase 1 lands: it's `benchmark:replay` minus the
blue orchestrator, plus a Tempo push. `wallclock` clock mode already exists;
this mode just skips agent startup.

**Owner:** Jayson. **ETA:** 2 days. **Blocks:** none — makes demo primary
path official; before this, the demo runs a slightly awkward
`benchmark:replay` with the blue orch running-but-idle.

### Phase 4 — Distribution + signing

- Publish first exercise set via GitHub Releases on
  `dreadnode/ares-exercises`.
- Cosign integration for signed artifacts. `ares exercise verify` checks
  signatures on pull.
- Index file at repo root lists all exercises with metadata.

**Owner:** Jayson. **ETA:** 1 week. **Precondition:** Phase 2.

### Phase 5 — New replay modes (post-Black Hat)

- **red-eval:** initial-state replay + live red. Requires a warm lab (or
  ephemeral DreadGOAD range spun up per run). Score against blue baseline
  from the manifest.
- **head-to-head:** initial-state replay + live red + live blue. Requires
  warm lab. Most expensive, most compelling for the "adversarial evaluation"
  thesis.
- **checkpoint-fork:** capture world state periodically during a live run
  (Redis dump + AD snapshot + Loki cursor). Replay to checkpoint N, then run
  live from there. Enables counterfactual research.
- **counterfactual:** telemetry replay with edits — remove/inject alerts to
  test blue behavior under altered signal conditions.

**Owner:** TBD. **ETA:** post-August; scope depends on research agenda.

## Demo relevance (what has to happen by Aug 6)

Only Phase 1 and Phase 3 are on the critical path for the talk.

- **Phase 1 (Tempo capture + replay)** unblocks the attack-graph panel
  working from a captured op. Without it, the demo either runs live (fragile)
  or the panel is empty (bad).
- **Phase 3 (`--mode visual`)** is the demo primary path; it removes blue
  agent startup latency and LLM cost from the show-floor loop.

Phase 2 (manifest v2 + CLI) is a nice-to-have for Black Hat — if it lands
in time, the hero snapshot ships as a signed public exercise the same day
the talk airs. If it doesn't, the exercise concept goes in the deck as
"here's what we're building next" and Phases 2+4 land in the following
month.

## Open decisions

1. **Distribution choice at launch** (GH Releases vs OCI registry). Recommend
   GH Releases for launch, migrate later. Ask: what's the first 100 users'
   friction budget?
2. **Signing story.** Cosign is idiomatic and free. But signing is only
   valuable if consumers verify. Do we want `ares exercise pull` to enforce
   signature verification by default, with `--allow-unsigned` opt-out?
   Recommend yes.
3. **LLM output re-recording for `visual` mode.** The audience sees action
   spans, not LLM completions. But if we ever want to demo *how the agent
   thought*, we need to capture and replay LLM I/O too — that's a separate
   privacy question (prompts may contain lab context worth scrubbing).
   Recommend defer; ship visual mode without LLM I/O until a use case
   demands it.
4. **Public exercise curation.** Who decides what enters the catalog? What
   is the quality bar (min replicability rate over N runs)? Draft a curation
   policy before we ship the first 10.
5. **Backward compatibility promise.** If we publish an exercise today, we
   commit to loading it in future ares versions. Formalize this in
   `versions.rs` and in a `docs/exercise-compatibility.md` — every schema
   version has an EOL date and a migration path.

## Relationship to the demo plan

The demo (see `DEMO-PLAN.md`) is one instance of `visual` mode against a
single hero exercise. The demo plan handles operational logistics; this doc
handles the artifact class and the machinery. If you're planning the Black
Hat demo, read the demo plan. If you're building the machinery it sits on,
this is the design.
