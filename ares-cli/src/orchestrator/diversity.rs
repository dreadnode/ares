//! Attack-path diversity primitives.
//!
//! Three opt-in mechanisms, all gated by `Strategy` knobs (see
//! `docs/attack-path-diversity.md`):
//!
//! 1. **Softmax queue selection** — sample the exploitation/deferred queue by
//!    priority instead of taking the strict minimum, so equal/near-equal
//!    priority work is chosen in different orders across runs.
//! 2. **Cross-run novelty memory** — a scoped Redis set of walked path steps;
//!    candidates whose step was already walked in a prior run get a priority
//!    penalty, biasing the fleet onto the long tail of paths.
//! 3. **Path records + coverage** — a per-operation ordered record of the
//!    canonical `(foothold, technique, target)` steps actually walked, plus a
//!    coverage set, for measuring how many distinct paths N runs hit.
//!
//! With `selection_temperature == 0.0`, `novelty_enabled == false`, and
//! `emit_path_records == false` every helper here is inert and the orchestrator
//! reproduces its previous deterministic behaviour exactly.

use rand::{Rng, RngExt};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tracing::debug;

use ares_core::state::KEY_PREFIX;

/// Priority penalty added to a candidate whose canonical step was already
/// walked in a prior run within the same novelty scope. Large enough to push a
/// seen step well down the softmax distribution without making it unreachable.
pub const NOVELTY_PENALTY: f32 = 4.0;

/// Max queue members to peek when softmax-sampling. Bounds the work per pop
/// while still giving the sampler a meaningful spread to choose from.
pub const CANDIDATE_LIMIT: isize = 24;

/// One walked step in an attack path, persisted in the per-operation record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathStep {
    /// Foothold credential used (e.g. "svc_sql@contoso.local"), or "-" if none.
    pub foothold: String,
    /// Technique class (lowercased vuln_type).
    pub technique: String,
    /// Target the technique was applied against.
    pub target: String,
}

/// Canonical single step key: technique class against a target. Two runs are
/// "the same path" iff their ordered step-key sequences match.
pub fn step_key(vuln_type: &str, target: &str) -> String {
    format!("{}:{}", vuln_type.to_lowercase(), target)
}

/// Cross-run novelty set key, scoped so unrelated operations don't poison each
/// other's diversity bias. Deleting this key resets novelty for the scope.
pub fn novelty_key(scope: &str) -> String {
    format!("ares:novelty:{scope}:steps")
}

/// Per-operation ordered path record (Redis LIST of `PathStep` JSON).
pub fn path_record_key(operation_id: &str) -> String {
    format!("{KEY_PREFIX}:{operation_id}:path_record")
}

/// Per-operation coverage set (distinct step keys walked).
pub fn coverage_key(operation_id: &str) -> String {
    format!("{KEY_PREFIX}:{operation_id}:coverage")
}

/// Pick an index into `priorities` (lower value = more urgent) using softmax
/// sampling at `temperature`.
///
/// - `temperature <= 0.0` → deterministic argmin (lowest priority, first on
///   ties). This reproduces the previous greedy `ZPOPMIN`/`pop_best` behaviour.
/// - Higher temperature flattens the distribution, spreading selection across
///   near-equal-priority candidates. As `temperature → ∞` it approaches uniform.
///
/// Returns `None` only for an empty input.
pub fn softmax_select_index<R: Rng + ?Sized>(
    priorities: &[f32],
    temperature: f32,
    rng: &mut R,
) -> Option<usize> {
    if priorities.is_empty() {
        return None;
    }
    if temperature <= 0.0 {
        return argmin(priorities);
    }

    // Softmax over negative priority, shifted by the minimum so the largest
    // exponent is 0 (avoids overflow; lowest-priority candidate weighs most).
    let min_p = priorities.iter().copied().fold(f32::INFINITY, f32::min);
    let weights: Vec<f32> = priorities
        .iter()
        .map(|p| (-(p - min_p) / temperature).exp())
        .collect();
    let total: f32 = weights.iter().sum();
    if !total.is_finite() || total <= 0.0 {
        return argmin(priorities);
    }

    let mut r = rng.random::<f32>() * total;
    for (i, w) in weights.iter().enumerate() {
        r -= w;
        if r <= 0.0 {
            return Some(i);
        }
    }
    // Floating-point slack — fall through to the last candidate.
    Some(weights.len() - 1)
}

fn argmin(priorities: &[f32]) -> Option<usize> {
    priorities
        .iter()
        .enumerate()
        .min_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(i, _)| i)
}

/// For each step in `steps`, whether it is already in the scope's novelty set.
/// On any Redis error, returns all-false (fail open — never block selection).
pub async fn novelty_seen(
    conn: &mut ConnectionManager,
    scope: &str,
    steps: &[String],
) -> Vec<bool> {
    if steps.is_empty() {
        return Vec::new();
    }
    let key = novelty_key(scope);
    let mut cmd = redis::cmd("SMISMEMBER");
    cmd.arg(&key);
    for s in steps {
        cmd.arg(s);
    }
    let res: Vec<i64> = cmd
        .query_async(conn)
        .await
        .unwrap_or_else(|_| vec![0; steps.len()]);
    res.into_iter().map(|v| v != 0).collect()
}

/// Record a successfully-walked path step.
///
/// - `emit_path_records` → append the `PathStep` to the per-operation record
///   list and add its canonical step key to the coverage set.
/// - `novelty_enabled` → add the canonical step key to the cross-run novelty
///   set so future runs in this scope are biased away from it.
///
/// Best-effort: Redis errors are logged at debug and swallowed so a recording
/// failure never affects exploitation.
#[allow(clippy::too_many_arguments)]
pub async fn record_step(
    conn: &mut ConnectionManager,
    operation_id: &str,
    novelty_scope: &str,
    foothold: Option<&str>,
    vuln_type: &str,
    target: &str,
    emit_path_records: bool,
    novelty_enabled: bool,
) {
    if !emit_path_records && !novelty_enabled {
        return;
    }
    let skey = step_key(vuln_type, target);

    if emit_path_records {
        let step = PathStep {
            foothold: foothold.unwrap_or("-").to_string(),
            technique: vuln_type.to_lowercase(),
            target: target.to_string(),
        };
        if let Ok(json) = serde_json::to_string(&step) {
            let rkey = path_record_key(operation_id);
            if let Err(e) = conn.rpush::<_, _, ()>(&rkey, &json).await {
                debug!(err = %e, "path record rpush failed");
            }
        }
        let ckey = coverage_key(operation_id);
        if let Err(e) = conn.sadd::<_, _, ()>(&ckey, &skey).await {
            debug!(err = %e, "coverage sadd failed");
        }
    }

    if novelty_enabled {
        let nkey = novelty_key(novelty_scope);
        if let Err(e) = conn.sadd::<_, _, ()>(&nkey, &skey).await {
            debug!(err = %e, "novelty sadd failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn empty_input_returns_none() {
        let mut rng = StdRng::seed_from_u64(1);
        assert_eq!(softmax_select_index(&[], 1.0, &mut rng), None);
    }

    #[test]
    fn zero_temperature_is_argmin() {
        let mut rng = StdRng::seed_from_u64(1);
        // Lowest priority value wins, deterministically, regardless of rng.
        let p = [5.0, 2.0, 9.0, 2.0];
        for _ in 0..100 {
            assert_eq!(softmax_select_index(&p, 0.0, &mut rng), Some(1));
        }
    }

    #[test]
    fn negative_temperature_is_argmin() {
        let mut rng = StdRng::seed_from_u64(1);
        let p = [3.0, 1.0, 2.0];
        assert_eq!(softmax_select_index(&p, -1.0, &mut rng), Some(1));
    }

    #[test]
    fn single_candidate_always_selected() {
        let mut rng = StdRng::seed_from_u64(7);
        assert_eq!(softmax_select_index(&[42.0], 2.0, &mut rng), Some(0));
    }

    #[test]
    fn high_temperature_spreads_selection() {
        // With equal priorities and T>0, both indices should be picked over many
        // draws (i.e. it is not collapsing to argmin).
        let mut rng = StdRng::seed_from_u64(123);
        let p = [1.0, 1.0];
        let mut counts = [0usize; 2];
        for _ in 0..2000 {
            let i = softmax_select_index(&p, 1.0, &mut rng).unwrap();
            counts[i] += 1;
        }
        assert!(counts[0] > 200, "index 0 picked {} times", counts[0]);
        assert!(counts[1] > 200, "index 1 picked {} times", counts[1]);
    }

    #[test]
    fn lower_priority_favored_at_moderate_temperature() {
        // Priority 1 should be sampled far more often than priority 9 at T=1.
        let mut rng = StdRng::seed_from_u64(99);
        let p = [1.0, 9.0];
        let mut low = 0usize;
        for _ in 0..2000 {
            if softmax_select_index(&p, 1.0, &mut rng).unwrap() == 0 {
                low += 1;
            }
        }
        assert!(low > 1900, "low-priority chosen only {low}/2000 times");
    }

    #[test]
    fn step_key_lowercases_type() {
        assert_eq!(step_key("ADCS_ESC1", "10.0.0.1"), "adcs_esc1:10.0.0.1");
    }

    #[test]
    fn key_helpers_use_expected_prefixes() {
        assert_eq!(novelty_key("camp-a"), "ares:novelty:camp-a:steps");
        assert_eq!(path_record_key("op1"), "ares:op:op1:path_record");
        assert_eq!(coverage_key("op1"), "ares:op:op1:coverage");
    }

    #[test]
    fn path_step_roundtrip() {
        let s = PathStep {
            foothold: "svc@contoso.local".into(),
            technique: "esc1".into(),
            target: "10.0.0.5".into(),
        };
        let j = serde_json::to_string(&s).unwrap();
        let back: PathStep = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
