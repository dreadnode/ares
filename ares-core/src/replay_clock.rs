//! Virtual replay clock for deterministic benchmark replay.
//!
//! During a benchmark replay the captured logs/alerts are historical, but the
//! blue-team agent must reason in *attack time* and, in the unfolding modes,
//! must not be able to see its own future. [`replay_now`] returns the current
//! instant on the replay clock; [`replay_clamp_end`] returns the ceiling that
//! the query tools cap every `end_time` at (so a query for the future comes
//! back empty — faithful to a live analyst).
//!
//! Modes (env `ARES_REPLAY_CLOCK_MODE`):
//! - unset / other → **frozen**: `replay_now = ARES_REPLAY_CLOCK_START` (legacy v1;
//!   no clamp), or `Utc::now()` when no anchor is set (a live investigation).
//! - `static` → `replay_now = ARES_REPLAY_CLOCK_END` (the whole concluded attack
//!   is visible; no clamp).
//! - `step` → advance from START→END proportional to `CURRENT_STEP / max_steps`
//!   (deterministic; the agent loop calls [`set_step`] each iteration). Clamped.
//! - `wallclock` → advance from START by real elapsed time, capped at END. Clamped.
//!
//! Env config (read fresh every call — no cache to go stale):
//! - `ARES_REPLAY_CLOCK_START` — anchor (trigger alert `fired_at`), RFC3339
//! - `ARES_REPLAY_CLOCK_END`   — attack end (`completed_at`), RFC3339
//! - `ARES_REPLAY_CLOCK_MODE`  — `static` | `step` | `wallclock`
//! - `ARES_REPLAY_MAX_STEPS`   — step budget for `step` mode (default 50)
//!
//! Lives in `ares-core` so `ares-tools` (query tools), `ares-llm` (prompt builder
//! and agent loop), and `ares-cli` (benchmark runner) share one clock source.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use chrono::{DateTime, Duration, Utc};

/// Env var carrying the replay-clock anchor (attack entry) as RFC3339.
pub const REPLAY_CLOCK_ENV: &str = "ARES_REPLAY_CLOCK_START";
/// Env var carrying the attack-end timestamp as RFC3339.
pub const REPLAY_CLOCK_END_ENV: &str = "ARES_REPLAY_CLOCK_END";
/// Env var selecting the advance mode: `static` | `step` | `wallclock`.
pub const REPLAY_CLOCK_MODE_ENV: &str = "ARES_REPLAY_CLOCK_MODE";
/// Env var carrying the step budget for `step` mode.
pub const REPLAY_MAX_STEPS_ENV: &str = "ARES_REPLAY_MAX_STEPS";

/// Sentinel for "no value set".
const UNSET: i64 = i64::MIN;

/// Optional programmatic anchor override (tests / replay drivers). While `UNSET`
/// the anchor is resolved from [`REPLAY_CLOCK_ENV`] instead.
static OVERRIDE_NANOS: AtomicI64 = AtomicI64::new(UNSET);
/// Current investigation step, updated by the agent loop via [`set_step`]. Only
/// consulted in `step` mode.
static CURRENT_STEP: AtomicU64 = AtomicU64::new(0);
/// Wall-clock instant of the first `replay_now()` call in `wallclock` mode,
/// captured lazily so elapsed time is measured from the investigation's start.
static WALL_START_NANOS: AtomicI64 = AtomicI64::new(UNSET);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    /// Legacy v1: `replay_now = anchor`, no clamp.
    Frozen,
    /// `replay_now = attack_end`; whole concluded attack visible, no clamp.
    Static,
    /// Advance by investigation step; clamped.
    Step,
    /// Advance by real elapsed time, capped at attack_end; clamped.
    WallClock,
}

fn nanos_to_dt(ns: i64) -> DateTime<Utc> {
    let secs = ns.div_euclid(1_000_000_000);
    let sub = ns.rem_euclid(1_000_000_000) as u32;
    DateTime::from_timestamp(secs, sub).unwrap_or_else(Utc::now)
}

fn parse_env_dt(key: &str) -> Option<DateTime<Utc>> {
    let raw = std::env::var(key).ok()?;
    DateTime::parse_from_rfc3339(raw.trim())
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// Resolve the replay anchor (attack entry). Programmatic override wins; else the
/// env var, read fresh. `None` for a live investigation.
fn anchor() -> Option<DateTime<Utc>> {
    let ov = OVERRIDE_NANOS.load(Ordering::Relaxed);
    if ov != UNSET {
        return Some(nanos_to_dt(ov));
    }
    parse_env_dt(REPLAY_CLOCK_ENV)
}

/// Attack end from env; falls back to the anchor (→ frozen) when unset.
fn attack_end() -> Option<DateTime<Utc>> {
    parse_env_dt(REPLAY_CLOCK_END_ENV)
}

fn mode() -> Mode {
    match std::env::var(REPLAY_CLOCK_MODE_ENV).ok().as_deref() {
        Some("static") => Mode::Static,
        Some("step") => Mode::Step,
        Some("wallclock") => Mode::WallClock,
        _ => Mode::Frozen,
    }
}

fn max_steps() -> u64 {
    std::env::var(REPLAY_MAX_STEPS_ENV)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(50)
}

/// Set the current investigation step absolutely (used by tests). Prefer
/// [`advance_step`] at runtime.
pub fn set_step(step: u64) {
    CURRENT_STEP.store(step, Ordering::Relaxed);
}

/// Monotonically advance the investigation step by one — called once per agent
/// loop turn. The blue investigation runs several agents, each with its own local
/// step counter that resets to 0; a global monotonic counter keeps the replay
/// clock moving strictly forward across those hand-offs (and is safe under
/// concurrency). No-op outside `step` mode.
pub fn advance_step() {
    CURRENT_STEP.fetch_add(1, Ordering::Relaxed);
}

/// Lazily capture (once) and return the wall-clock instant used as the
/// `wallclock`-mode origin.
fn wall_origin() -> DateTime<Utc> {
    let existing = WALL_START_NANOS.load(Ordering::Relaxed);
    if existing != UNSET {
        return nanos_to_dt(existing);
    }
    let now_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);
    // First writer wins; re-read to get the agreed origin.
    let _ = WALL_START_NANOS.compare_exchange(UNSET, now_ns, Ordering::Relaxed, Ordering::Relaxed);
    nanos_to_dt(WALL_START_NANOS.load(Ordering::Relaxed))
}

/// The current instant on the replay clock. Wall-clock [`Utc::now`] for a live
/// investigation; otherwise resolved per [`Mode`], always within `[start, end]`.
pub fn replay_now() -> DateTime<Utc> {
    let Some(start) = anchor() else {
        return Utc::now();
    };
    let end = attack_end().unwrap_or(start);
    let raw = match mode() {
        Mode::Frozen => start,
        Mode::Static => end,
        Mode::Step => {
            let step = CURRENT_STEP.load(Ordering::Relaxed);
            let max = max_steps();
            let frac = (step as f64 / max as f64).clamp(0.0, 1.0);
            let span_ms = (end - start).num_milliseconds().max(0) as f64;
            start + Duration::milliseconds((span_ms * frac) as i64)
        }
        Mode::WallClock => start + (Utc::now() - wall_origin()),
    };
    // Keep within the captured window regardless of mode/skew.
    raw.clamp(start.min(end), start.max(end))
}

/// The ceiling that query tools cap `end_time` at, or `None` when no clamp
/// applies (live, `frozen` legacy, or `static` — all data visible). In the
/// unfolding modes this equals [`replay_now`].
pub fn replay_clamp_end() -> Option<DateTime<Utc>> {
    if !is_replay() {
        return None;
    }
    match mode() {
        Mode::Step | Mode::WallClock => Some(replay_now()),
        Mode::Frozen | Mode::Static => None,
    }
}

/// Whether a replay clock anchor is configured (i.e. this is a replay run).
pub fn is_replay() -> bool {
    anchor().is_some()
}

/// Explicitly set the replay anchor, overriding the env var (mainly for tests
/// and programmatic replay drivers). Pair with [`reset_replay_clock`].
pub fn set_replay_clock(anchor: DateTime<Utc>) {
    if let Some(ns) = anchor.timestamp_nanos_opt() {
        OVERRIDE_NANOS.store(ns, Ordering::Relaxed);
    }
}

/// Clear a programmatic override and the transient step / wall-origin state,
/// restoring env-var-driven behavior. Idempotent.
pub fn reset_replay_clock() {
    OVERRIDE_NANOS.store(UNSET, Ordering::Relaxed);
    WALL_START_NANOS.store(UNSET, Ordering::Relaxed);
    CURRENT_STEP.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // The clock reads process-global env + `static` items, so these tests would race
    // each other under cargo's parallel runner. Serialize on one lock (recovering
    // from a poisoned lock so one failure doesn't cascade) and fully reset state
    // at each test's start and end.
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn clear() {
        reset_replay_clock();
        std::env::remove_var(REPLAY_CLOCK_ENV);
        std::env::remove_var(REPLAY_CLOCK_END_ENV);
        std::env::remove_var(REPLAY_CLOCK_MODE_ENV);
        std::env::remove_var(REPLAY_MAX_STEPS_ENV);
    }
    fn dt(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn frozen_roundtrips_to_anchor() {
        let _g = lock();
        clear();
        let anchor = dt("2026-06-30T22:20:23Z");
        set_replay_clock(anchor);
        assert!(is_replay());
        assert_eq!(replay_now(), anchor); // frozen = anchor
        assert!(replay_clamp_end().is_none()); // frozen → no clamp (legacy v1)
        clear();
    }

    #[test]
    fn static_returns_end_no_clamp() {
        let _g = lock();
        clear();
        let start = dt("2026-07-07T08:33:00Z");
        let end = dt("2026-07-07T10:00:00Z");
        set_replay_clock(start);
        std::env::set_var(REPLAY_CLOCK_END_ENV, end.to_rfc3339());
        std::env::set_var(REPLAY_CLOCK_MODE_ENV, "static");
        assert_eq!(replay_now(), end);
        assert!(replay_clamp_end().is_none()); // static → everything visible
        clear();
    }

    #[test]
    fn step_advances_and_clamps() {
        let _g = lock();
        clear();
        let start = dt("2026-07-07T08:00:00Z");
        let end = dt("2026-07-07T10:00:00Z"); // 120 min span
        set_replay_clock(start);
        std::env::set_var(REPLAY_CLOCK_END_ENV, end.to_rfc3339());
        std::env::set_var(REPLAY_CLOCK_MODE_ENV, "step");
        std::env::set_var(REPLAY_MAX_STEPS_ENV, "10");

        set_step(0);
        assert_eq!(replay_now(), start);
        set_step(5); // halfway → +60 min
        assert_eq!(replay_now(), dt("2026-07-07T09:00:00Z"));
        set_step(10); // full → end
        assert_eq!(replay_now(), end);
        set_step(999); // past budget → capped at end
        assert_eq!(replay_now(), end);
        assert_eq!(replay_clamp_end(), Some(end)); // step → clamps
        clear();
    }

    #[test]
    fn live_is_wall_clock_when_unset() {
        let _g = lock();
        clear();
        assert!(!is_replay());
        assert!(replay_clamp_end().is_none());
        // replay_now ≈ now (can't assert exact, just that it's recent)
        let delta = (Utc::now() - replay_now()).num_seconds().abs();
        assert!(delta < 5);
        clear();
    }
}
