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
