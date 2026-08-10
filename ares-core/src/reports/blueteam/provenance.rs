//! Evidence provenance — separates what the deterministic detection sweep
//! recorded from what the analyst loop produced.
//!
//! The sweep stamps every fired detection at pyramid level 6, so a report that
//! sums both sources reads "reached TTP level" the instant the sweep runs at
//! all, regardless of what the investigation found. Reports use this split to
//! attribute each level to whichever produced it.

use std::collections::HashMap;

use crate::models::Evidence;

/// Source prefix the deterministic detection sweep stamps on the state it records.
const SWEEP_SOURCE_PREFIX: &str = "detection_sweep";

/// Top of the Pyramid of Pain.
const TTP_LEVEL: i32 = 6;

/// Evidence tallies partitioned by what produced the evidence.
#[derive(Debug, Clone, Default)]
pub(super) struct EvidenceProvenance {
    pub(super) distribution: HashMap<i32, i32>,
    pub(super) analyst_distribution: HashMap<i32, i32>,
    pub(super) total_count: usize,
    pub(super) analyst_count: usize,
    pub(super) highest_level: i32,
    pub(super) highest_analyst_level: i32,
    pub(super) ttp_count: usize,
    pub(super) analyst_ttp_count: usize,
}

impl EvidenceProvenance {
    /// Partition evidence into sweep-produced and analyst-produced tallies.
    pub(super) fn from_evidence<'a>(evidence: impl IntoIterator<Item = &'a Evidence>) -> Self {
        let mut split = Self::default();

        for ev in evidence {
            *split.distribution.entry(ev.pyramid_level).or_insert(0) += 1;
            split.total_count += 1;
            split.highest_level = split.highest_level.max(ev.pyramid_level);
            if ev.pyramid_level == TTP_LEVEL {
                split.ttp_count += 1;
            }

            if is_sweep(&ev.source) {
                continue;
            }

            *split
                .analyst_distribution
                .entry(ev.pyramid_level)
                .or_insert(0) += 1;
            split.analyst_count += 1;
            split.highest_analyst_level = split.highest_analyst_level.max(ev.pyramid_level);
            if ev.pyramid_level == TTP_LEVEL {
                split.analyst_ttp_count += 1;
            }
        }

        split
    }

    /// Evidence items the deterministic sweep recorded.
    pub(super) fn sweep_count(&self) -> usize {
        self.total_count - self.analyst_count
    }

    /// TTP-level items the deterministic sweep recorded.
    pub(super) fn sweep_ttp_count(&self) -> usize {
        self.ttp_count - self.analyst_ttp_count
    }

    /// Items at or above `level`, from any source.
    pub(super) fn at_or_above(&self, level: i32) -> i32 {
        count_at_or_above(&self.distribution, level)
    }

    /// Items at or above `level` that the analyst loop produced.
    pub(super) fn analyst_at_or_above(&self, level: i32) -> i32 {
        count_at_or_above(&self.analyst_distribution, level)
    }

    /// Mean pyramid level across all evidence, as a fraction of the top level.
    pub(super) fn elevation_score(&self) -> f64 {
        elevation(&self.distribution, self.total_count)
    }

    /// Mean pyramid level across analyst evidence only.
    pub(super) fn analyst_elevation_score(&self) -> f64 {
        elevation(&self.analyst_distribution, self.analyst_count)
    }
}

fn is_sweep(source: &str) -> bool {
    source.starts_with(SWEEP_SOURCE_PREFIX)
}

fn count_at_or_above(distribution: &HashMap<i32, i32>, level: i32) -> i32 {
    distribution
        .iter()
        .filter(|(l, _)| **l >= level)
        .map(|(_, n)| *n)
        .sum()
}

fn elevation(distribution: &HashMap<i32, i32>, count: usize) -> f64 {
    if count == 0 {
        return 0.0;
    }
    let weighted: i32 = distribution.iter().map(|(level, n)| level * n).sum();
    f64::from(weighted) / (count as f64 * f64::from(TTP_LEVEL))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(level: i32, source: &str) -> Evidence {
        serde_json::from_value(serde_json::json!({
            "id": format!("ev-{level}-{source}"),
            "type": "log_entry",
            "value": "T1003",
            "source": source,
            "pyramid_level": level,
        }))
        .expect("evidence deserializes")
    }

    #[test]
    fn empty_evidence_scores_zero() {
        let split = EvidenceProvenance::from_evidence(&[]);

        assert_eq!(split.highest_level, 0);
        assert_eq!(split.highest_analyst_level, 0);
        assert_eq!(split.elevation_score(), 0.0);
        assert_eq!(split.analyst_elevation_score(), 0.0);
    }

    #[test]
    fn sweep_evidence_does_not_raise_the_analyst_level() {
        let items = vec![
            evidence(6, "detection_sweep:detect_dcsync"),
            evidence(6, "detection_sweep:detect_s4u_delegation"),
            evidence(2, "loki"),
        ];

        let split = EvidenceProvenance::from_evidence(&items);

        assert_eq!(split.highest_level, 6);
        assert_eq!(split.highest_analyst_level, 2);
        assert_eq!(split.ttp_count, 2);
        assert_eq!(split.analyst_ttp_count, 0);
        assert_eq!(split.sweep_count(), 2);
        assert_eq!(split.sweep_ttp_count(), 2);
    }

    #[test]
    fn analyst_evidence_raises_the_analyst_level() {
        let items = vec![
            evidence(6, "detection_sweep:detect_dcsync"),
            evidence(6, "grafana_loki_query"),
        ];

        let split = EvidenceProvenance::from_evidence(&items);

        assert_eq!(split.highest_analyst_level, 6);
        assert_eq!(split.analyst_ttp_count, 1);
        assert_eq!(split.sweep_ttp_count(), 1);
    }

    #[test]
    fn distributions_are_tallied_per_level() {
        let items = vec![
            evidence(6, "detection_sweep:detect_dcsync"),
            evidence(4, "loki"),
            evidence(4, "loki"),
        ];

        let split = EvidenceProvenance::from_evidence(&items);

        assert_eq!(split.distribution.get(&6), Some(&1));
        assert_eq!(split.distribution.get(&4), Some(&2));
        assert_eq!(split.analyst_distribution.get(&6), None);
        assert_eq!(split.analyst_distribution.get(&4), Some(&2));
        assert_eq!(split.at_or_above(5), 1);
        assert_eq!(split.analyst_at_or_above(5), 0);
    }

    #[test]
    fn elevation_separates_sweep_from_analyst() {
        let items = vec![
            evidence(6, "detection_sweep:detect_dcsync"),
            evidence(6, "detection_sweep:detect_kerberoast"),
            evidence(3, "loki"),
        ];

        let split = EvidenceProvenance::from_evidence(&items);

        assert!((split.elevation_score() - 15.0 / 18.0).abs() < 1e-9);
        assert!((split.analyst_elevation_score() - 0.5).abs() < 1e-9);
    }
}
