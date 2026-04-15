//! PyramidClimber engine — generates Pyramid of Pain climbing questions from evidence.

use std::collections::HashMap;

use serde_json::Value;

use super::data::{climb_strategies, pyramid_level_name, pyramid_level_value};
use super::mitre::{make_question_id, InvestigativeQuestion};

// ---------------------------------------------------------------------------
// Evidence item
// ---------------------------------------------------------------------------

/// Evidence item for pyramid climbing.
pub struct EvidenceItem {
    pub value: String,
    pub pyramid_level: String,
}

// ---------------------------------------------------------------------------
// PyramidClimber engine
// ---------------------------------------------------------------------------

/// Generate pyramid-climbing questions from evidence.
pub fn generate_pyramid_questions(evidence: &[EvidenceItem]) -> Vec<InvestigativeQuestion> {
    let strategies = climb_strategies();
    let mut questions = Vec::new();

    for ev in evidence {
        if ev.pyramid_level == "ttps" {
            continue; // already at the top
        }

        if let Some(level_strategies) = strategies.get(&ev.pyramid_level) {
            for strategy in level_strategies {
                let question_text = strategy.template.replace("{value}", &ev.value);
                let elevation_score = strategy.elevation as f64 / 5.0;
                let priority = elevation_score * 3.0 + 0.5 * 2.0 + 0.5 * 2.0;

                questions.push(InvestigativeQuestion {
                    id: make_question_id("pyramid"),
                    question: question_text,
                    source: "pyramid",
                    rationale: format!(
                        "Climb from {} (level {}) to {} — {}",
                        pyramid_level_name(&ev.pyramid_level),
                        pyramid_level_value(&ev.pyramid_level),
                        pyramid_level_name(&strategy.target),
                        strategy.insight
                    ),
                    target_technique: None,
                    priority_score: priority,
                    pyramid_elevation_score: elevation_score,
                    confidence_impact_score: 0.5,
                });
            }
        }
    }

    questions.sort_by(|a, b| {
        b.priority_score
            .partial_cmp(&a.priority_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    questions
}

/// Assess current pyramid state from evidence distribution.
pub fn assess_pyramid(evidence: &[EvidenceItem]) -> Value {
    let mut distribution: HashMap<&str, u32> = HashMap::new();
    let mut weighted_sum: f64 = 0.0;

    for ev in evidence {
        let name = pyramid_level_name(&ev.pyramid_level);
        *distribution.entry(name).or_insert(0) += 1;
        weighted_sum += pyramid_level_value(&ev.pyramid_level) as f64;
    }

    let total = evidence.len() as f64;
    let elevation_score = if total > 0.0 {
        weighted_sum / (total * 6.0)
    } else {
        0.0
    };

    let hash_count = distribution.get("Hash Values").copied().unwrap_or(0);
    let tool_count = distribution.get("Tools").copied().unwrap_or(0);
    let ip_count = distribution.get("IP Addresses").copied().unwrap_or(0);
    let domain_count = distribution.get("Domain Names").copied().unwrap_or(0);
    let ttp_count = distribution.get("TTPs").copied().unwrap_or(0);

    let mut recommendations = Vec::new();
    if hash_count > tool_count + 2 {
        recommendations.push(
            "Many hash indicators but few tools identified. Try to attribute hashes to specific tools."
                .to_string(),
        );
    }
    if ip_count > domain_count + 2 {
        recommendations
            .push("More IPs than domains. Resolve IPs to domains for better coverage.".to_string());
    }
    if ttp_count == 0 {
        recommendations.push(
            "CRITICAL: No TTPs identified yet. Focus on mapping evidence to MITRE ATT&CK techniques."
                .to_string(),
        );
    }

    serde_json::json!({
        "distribution": distribution,
        "elevation_score": elevation_score,
        "total_evidence": evidence.len(),
        "recommendations": recommendations,
    })
}
