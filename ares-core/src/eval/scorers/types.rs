//! Snapshot types for scoring input.

use std::collections::HashSet;

use crate::models::SharedBlueTeamState;

/// Input for scoring functions: investigation evidence data extracted from state.
#[derive(Debug, Clone, Default)]
pub struct InvestigationSnapshot {
    /// Current stage: triage, causation, lateral, synthesis
    pub stage: Option<String>,
    /// Evidence values (lowercase).
    pub evidence_values: Vec<EvidenceItem>,
    /// Queried hosts (lowercase).
    pub queried_hosts: HashSet<String>,
    /// Queried users (lowercase).
    pub queried_users: HashSet<String>,
    /// Identified MITRE technique IDs.
    pub identified_techniques: HashSet<String>,
    /// Timeline event descriptions.
    pub timeline: Vec<TimelineEvent>,
    /// Highest pyramid level reached (1–6).
    pub highest_pyramid_level: u32,
}

impl InvestigationSnapshot {
    /// Build an `InvestigationSnapshot` from a loaded `SharedBlueTeamState`.
    ///
    /// This bridges the blue team's Redis-backed state into the scoring framework,
    /// enabling live post-investigation evaluation.
    pub fn from_blue_state(state: &SharedBlueTeamState) -> Self {
        let evidence_values: Vec<EvidenceItem> = state
            .evidence
            .iter()
            .map(|e| EvidenceItem {
                evidence_type: e.evidence_type.clone(),
                value: e.value.clone(),
                pyramid_level: e.pyramid_level.max(0) as u32,
                confidence: e.confidence,
                validated: e.validated,
            })
            .collect();

        let highest_pyramid_level = evidence_values
            .iter()
            .map(|e| e.pyramid_level)
            .max()
            .unwrap_or(0);

        let timeline: Vec<TimelineEvent> = state
            .timeline
            .iter()
            .map(|e| TimelineEvent {
                description: e.description.clone(),
                mitre_techniques: e.mitre_techniques.iter().cloned().collect(),
            })
            .collect();

        Self {
            stage: Some(state.stage.clone()),
            evidence_values,
            queried_hosts: state.queried_hosts.iter().cloned().collect(),
            queried_users: state.queried_users.iter().cloned().collect(),
            identified_techniques: state.identified_techniques.iter().cloned().collect(),
            timeline,
            highest_pyramid_level,
        }
    }
}

/// A piece of evidence from the investigation.
#[derive(Debug, Clone)]
pub struct EvidenceItem {
    pub evidence_type: String,
    pub value: String,
    pub pyramid_level: u32,
    pub confidence: f64,
    pub validated: bool,
}

/// A timeline event.
#[derive(Debug, Clone)]
pub struct TimelineEvent {
    pub description: String,
    pub mitre_techniques: HashSet<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Evidence, SharedBlueTeamState, TimelineEvent as BlueTimelineEvent};

    fn empty_blue_state() -> SharedBlueTeamState {
        SharedBlueTeamState::new("inv-1".into())
    }

    #[test]
    fn from_blue_state_empty() {
        let state = empty_blue_state();
        let snap = InvestigationSnapshot::from_blue_state(&state);
        assert_eq!(snap.stage, Some("triage".to_string()));
        assert!(snap.evidence_values.is_empty());
        assert!(snap.queried_hosts.is_empty());
        assert!(snap.queried_users.is_empty());
        assert!(snap.identified_techniques.is_empty());
        assert!(snap.timeline.is_empty());
        assert_eq!(snap.highest_pyramid_level, 0);
    }

    #[test]
    fn from_blue_state_evidence_mapping() {
        let mut state = empty_blue_state();
        state.evidence.push(Evidence {
            id: "e1".into(),
            evidence_type: "ip".into(),
            value: "192.168.58.1".into(),
            source: "loki".into(),
            timestamp: None,
            pyramid_level: 3,
            mitre_techniques: vec![],
            confidence: 0.85,
            metadata: Default::default(),
            validated: true,
            source_query_id: None,
        });
        let snap = InvestigationSnapshot::from_blue_state(&state);
        assert_eq!(snap.evidence_values.len(), 1);
        let e = &snap.evidence_values[0];
        assert_eq!(e.evidence_type, "ip");
        assert_eq!(e.value, "192.168.58.1");
        assert_eq!(e.pyramid_level, 3);
        assert!((e.confidence - 0.85).abs() < f64::EPSILON);
        assert!(e.validated);
    }

    #[test]
    fn from_blue_state_negative_pyramid_clamped() {
        let mut state = empty_blue_state();
        state.evidence.push(Evidence {
            id: "e2".into(),
            evidence_type: "hash".into(),
            value: "abc123".into(),
            source: "test".into(),
            timestamp: None,
            pyramid_level: -5,
            mitre_techniques: vec![],
            confidence: 0.5,
            metadata: Default::default(),
            validated: false,
            source_query_id: None,
        });
        let snap = InvestigationSnapshot::from_blue_state(&state);
        assert_eq!(snap.evidence_values[0].pyramid_level, 0);
    }

    #[test]
    fn from_blue_state_highest_pyramid() {
        let mut state = empty_blue_state();
        for (lvl, etype) in [(2, "ip"), (5, "ttp"), (3, "domain")] {
            state.evidence.push(Evidence {
                id: format!("e{lvl}"),
                evidence_type: etype.into(),
                value: "v".into(),
                source: "s".into(),
                timestamp: None,
                pyramid_level: lvl,
                mitre_techniques: vec![],
                confidence: 0.9,
                metadata: Default::default(),
                validated: true,
                source_query_id: None,
            });
        }
        let snap = InvestigationSnapshot::from_blue_state(&state);
        assert_eq!(snap.highest_pyramid_level, 5);
    }

    #[test]
    fn from_blue_state_timeline() {
        let mut state = empty_blue_state();
        state.timeline.push(BlueTimelineEvent {
            id: "t1".into(),
            timestamp: "2024-01-15T10:00:00Z".into(),
            description: "Lateral movement detected".into(),
            evidence_ids: vec![],
            mitre_techniques: vec!["T1021".into(), "T1003".into()],
            confidence: 0.9,
            source: "agent".into(),
            extra_data_json: None,
        });
        let snap = InvestigationSnapshot::from_blue_state(&state);
        assert_eq!(snap.timeline.len(), 1);
        assert_eq!(snap.timeline[0].description, "Lateral movement detected");
        assert!(snap.timeline[0].mitre_techniques.contains("T1021"));
        assert!(snap.timeline[0].mitre_techniques.contains("T1003"));
    }

    #[test]
    fn from_blue_state_hosts_and_users() {
        let mut state = empty_blue_state();
        state.queried_hosts = vec!["dc01".into(), "web01".into()];
        state.queried_users = vec!["admin".into(), "svc_sql".into()];
        let snap = InvestigationSnapshot::from_blue_state(&state);
        assert_eq!(snap.queried_hosts.len(), 2);
        assert!(snap.queried_hosts.contains("dc01"));
        assert_eq!(snap.queried_users.len(), 2);
        assert!(snap.queried_users.contains("svc_sql"));
    }

    #[test]
    fn from_blue_state_techniques() {
        let mut state = empty_blue_state();
        state.identified_techniques = vec!["T1003".into(), "T1021.002".into()];
        state.stage = "synthesis".into();
        let snap = InvestigationSnapshot::from_blue_state(&state);
        assert_eq!(snap.stage, Some("synthesis".to_string()));
        assert_eq!(snap.identified_techniques.len(), 2);
        assert!(snap.identified_techniques.contains("T1003"));
        assert!(snap.identified_techniques.contains("T1021.002"));
    }

    #[test]
    fn from_blue_state_deduplicates_sets() {
        let mut state = empty_blue_state();
        state.queried_hosts = vec!["dc01".into(), "dc01".into()];
        state.identified_techniques = vec!["T1003".into(), "T1003".into()];
        let snap = InvestigationSnapshot::from_blue_state(&state);
        assert_eq!(snap.queried_hosts.len(), 1);
        assert_eq!(snap.identified_techniques.len(), 1);
    }
}
