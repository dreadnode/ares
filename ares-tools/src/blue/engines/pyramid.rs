//! PyramidClimber engine — generates Pyramid of Pain climbing questions from evidence.

use std::collections::HashMap;

use serde_json::Value;

use super::data::{climb_strategies, pyramid_level_name, pyramid_level_value};
use super::mitre::{make_question_id, InvestigativeQuestion};

/// Evidence item for pyramid climbing.
pub struct EvidenceItem {
    pub value: String,
    pub pyramid_level: String,
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_pyramid_questions_empty_evidence() {
        let questions = generate_pyramid_questions(&[]);
        assert!(questions.is_empty());
    }

    #[test]
    fn generate_pyramid_questions_ttps_skipped() {
        let evidence = vec![EvidenceItem {
            value: "lateral movement".to_string(),
            pyramid_level: "ttps".to_string(),
        }];
        let questions = generate_pyramid_questions(&evidence);
        assert!(questions.is_empty());
    }

    #[test]
    fn generate_pyramid_questions_from_ip() {
        let evidence = vec![EvidenceItem {
            value: "192.168.58.10".to_string(),
            pyramid_level: "ip_addresses".to_string(),
        }];
        let questions = generate_pyramid_questions(&evidence);
        for q in &questions {
            assert_eq!(q.source, "pyramid");
            assert!(q.question.contains("192.168.58.10"));
        }
    }

    #[test]
    fn pyramid_questions_sorted_by_priority() {
        let evidence = vec![
            EvidenceItem {
                value: "192.168.58.1".to_string(),
                pyramid_level: "ip_addresses".to_string(),
            },
            EvidenceItem {
                value: "evil.exe".to_string(),
                pyramid_level: "tools".to_string(),
            },
        ];
        let questions = generate_pyramid_questions(&evidence);
        if questions.len() >= 2 {
            for pair in questions.windows(2) {
                assert!(pair[0].priority_score >= pair[1].priority_score);
            }
        }
    }

    #[test]
    fn assess_pyramid_empty_evidence() {
        let result = assess_pyramid(&[]);
        assert_eq!(result["total_evidence"], 0);
        assert_eq!(result["elevation_score"], 0.0);
        let recs = result["recommendations"].as_array().unwrap();
        assert!(recs.iter().any(|r| r.as_str().unwrap().contains("No TTPs")));
    }

    #[test]
    fn assess_pyramid_with_ttps() {
        let evidence = vec![EvidenceItem {
            value: "T1003".to_string(),
            pyramid_level: "ttps".to_string(),
        }];
        let result = assess_pyramid(&evidence);
        assert_eq!(result["total_evidence"], 1);
        // TTPs have level 6, so elevation_score = 6/(1*6) = 1.0
        assert!((result["elevation_score"].as_f64().unwrap() - 1.0).abs() < 0.01);
        let recs = result["recommendations"].as_array().unwrap();
        assert!(!recs.iter().any(|r| r.as_str().unwrap().contains("No TTPs")));
    }

    #[test]
    fn assess_pyramid_recommends_hash_to_tool() {
        let evidence: Vec<EvidenceItem> = (0..5)
            .map(|i| EvidenceItem {
                value: format!("hash{i}"),
                pyramid_level: "hash_values".to_string(),
            })
            .collect();
        let result = assess_pyramid(&evidence);
        let recs = result["recommendations"].as_array().unwrap();
        assert!(recs
            .iter()
            .any(|r| r.as_str().unwrap().contains("hash indicators")));
    }

    #[test]
    fn assess_pyramid_recommends_ip_to_domain() {
        let evidence: Vec<EvidenceItem> = (0..5)
            .map(|i| EvidenceItem {
                value: format!("192.168.58.{i}"),
                pyramid_level: "ip_addresses".to_string(),
            })
            .collect();
        let result = assess_pyramid(&evidence);
        let recs = result["recommendations"].as_array().unwrap();
        assert!(recs
            .iter()
            .any(|r| r.as_str().unwrap().contains("IPs than domains")));
    }
}
