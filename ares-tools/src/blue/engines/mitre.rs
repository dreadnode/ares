//! MITRENavigator engine — generates investigative questions from MITRE ATT&CK chains.

use std::collections::HashSet;

use serde_json::Value;

use super::data::{attack_chains, detection_recipes, technique_to_recipe};

// ---------------------------------------------------------------------------
// InvestigativeQuestion
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct InvestigativeQuestion {
    pub id: String,
    pub question: String,
    pub source: &'static str, // "mitre" or "pyramid"
    pub rationale: String,
    pub target_technique: Option<String>,
    pub priority_score: f64,
}

impl InvestigativeQuestion {
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "id": self.id,
            "question": self.question,
            "source": self.source,
            "rationale": self.rationale,
            "target_technique": self.target_technique,
            "priority_score": self.priority_score,
        })
    }
}

pub fn make_question_id(prefix: &str) -> String {
    format!("{}-{}", prefix, &uuid::Uuid::new_v4().to_string()[..8])
}

// ---------------------------------------------------------------------------
// MITRENavigator engine
// ---------------------------------------------------------------------------

/// Generate MITRE-based investigative questions from identified techniques.
pub fn generate_mitre_questions(
    identified_techniques: &HashSet<String>,
) -> Vec<InvestigativeQuestion> {
    let chains = attack_chains();
    let recipes = detection_recipes();
    let tech_recipe_map = technique_to_recipe();
    let mut questions = Vec::new();

    for tech_id in identified_techniques {
        // 1. Precursor questions (highest priority)
        if let Some(chain) = chains.get(tech_id.as_str()) {
            for precursor in &chain.precursors {
                if identified_techniques.contains(&precursor.technique) {
                    continue;
                }
                let pyramid_elevation = 0.8;
                let confidence_impact = 0.9;
                let priority =
                    pyramid_elevation * 3.0 + confidence_impact * 2.0 + precursor.relevance * 2.0;

                questions.push(InvestigativeQuestion {
                    id: make_question_id("precursor"),
                    question: format!(
                        "Investigate {} ({}) as a precursor to {} ({}). {}",
                        precursor.technique,
                        precursor.name,
                        tech_id,
                        chain.name,
                        precursor.rationale
                    ),
                    source: "mitre",
                    rationale: precursor.rationale.clone(),
                    target_technique: Some(precursor.technique.clone()),
                    priority_score: priority,
                });
            }

            // Investigation questions from chain data
            for q in &chain.investigation_questions {
                let priority = q.priority * 3.0 + 0.8 * 2.0 + 0.7 * 2.0;
                questions.push(InvestigativeQuestion {
                    id: make_question_id("chain-q"),
                    question: q.question.clone(),
                    source: "mitre",
                    rationale: format!("Follow-up question for {tech_id} investigation"),
                    target_technique: q.target_technique.clone(),
                    priority_score: priority,
                });
            }
        }

        // 2. Detection recipe questions
        if let Some(recipe_name) = tech_recipe_map.get(tech_id.as_str()) {
            if let Some(recipe) = recipes.get(*recipe_name) {
                // Indicator questions (max 3)
                if let Some(indicators) = recipe.get("indicators").and_then(|v| v.as_array()) {
                    for indicator in indicators.iter().take(3) {
                        if let Some(text) = indicator.as_str() {
                            questions.push(InvestigativeQuestion {
                                id: make_question_id("recipe"),
                                question: format!(
                                    "Check for: {} (detection recipe: {})",
                                    text, recipe_name
                                ),
                                source: "mitre",
                                rationale: format!("Detection indicator from {recipe_name} recipe"),
                                target_technique: Some(tech_id.clone()),
                                priority_score: 0.7 * 3.0 + 0.8 * 2.0 + 0.6 * 2.0,
                            });
                        }
                    }
                }

                // LogQL queries (max 2)
                if let Some(queries) = recipe.get("logql_queries").and_then(|v| v.as_array()) {
                    for query_obj in queries.iter().take(2) {
                        let name = query_obj
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unnamed");
                        let query = query_obj
                            .get("query")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        questions.push(InvestigativeQuestion {
                            id: make_question_id("recipe-q"),
                            question: format!(
                                "Execute detection query '{}': {}",
                                name,
                                query.trim()
                            ),
                            source: "mitre",
                            rationale: format!("LogQL query from {recipe_name} recipe"),
                            target_technique: Some(tech_id.clone()),
                            priority_score: 0.6 * 3.0 + 0.7 * 2.0 + 0.8 * 2.0,
                        });
                    }
                }

                // Investigation steps (max 3)
                if let Some(steps) = recipe.get("investigation_steps") {
                    let step_entries: Vec<(&str, &str)> = if let Some(obj) = steps.as_object() {
                        obj.iter()
                            .filter_map(|(k, v)| v.as_str().map(|s| (k.as_str(), s)))
                            .take(3)
                            .collect()
                    } else {
                        Vec::new()
                    };
                    for (_step_num, step_text) in step_entries {
                        questions.push(InvestigativeQuestion {
                            id: make_question_id("recipe-step"),
                            question: step_text.to_string(),
                            source: "mitre",
                            rationale: format!("Investigation step from {recipe_name} recipe"),
                            target_technique: Some(tech_id.clone()),
                            priority_score: 0.5 * 3.0 + 0.6 * 2.0 + 0.7 * 2.0,
                        });
                    }
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn question_to_json_has_all_fields() {
        let q = InvestigativeQuestion {
            id: "test-001".to_string(),
            question: "Is there evidence of lateral movement?".to_string(),
            source: "mitre",
            rationale: "Follow-up".to_string(),
            target_technique: Some("T1021".to_string()),
            priority_score: 5.0,
        };
        let json = q.to_json();
        assert_eq!(json["id"], "test-001");
        assert_eq!(json["source"], "mitre");
        assert_eq!(json["target_technique"], "T1021");
        assert_eq!(json["priority_score"], 5.0);
    }

    #[test]
    fn make_question_id_contains_prefix() {
        let id = make_question_id("test");
        assert!(id.starts_with("test-"));
        assert!(id.len() > 5);
    }

    #[test]
    fn make_question_id_unique() {
        let id1 = make_question_id("q");
        let id2 = make_question_id("q");
        assert_ne!(id1, id2);
    }

    #[test]
    fn generate_mitre_questions_empty_techniques() {
        let techs = HashSet::new();
        let questions = generate_mitre_questions(&techs);
        assert!(questions.is_empty());
    }

    #[test]
    fn generate_mitre_questions_known_technique() {
        let mut techs = HashSet::new();
        techs.insert("T1003".to_string());
        let questions = generate_mitre_questions(&techs);
        // Should produce at least some questions for credential dumping
        // (unless T1003 has no chain data, which is possible)
        // Either way, should not panic
        for q in &questions {
            assert!(!q.question.is_empty());
            assert!(q.priority_score > 0.0);
        }
    }

    #[test]
    fn generate_mitre_questions_with_recipe() {
        let mut techs = HashSet::new();
        techs.insert("T1003.006".to_string()); // DCSync — has a recipe mapping
        let questions = generate_mitre_questions(&techs);
        // Should generate recipe-based questions
        for q in &questions {
            assert_eq!(q.source, "mitre");
        }
    }

    #[test]
    fn questions_sorted_by_priority_desc() {
        let mut techs = HashSet::new();
        techs.insert("T1003.006".to_string());
        techs.insert("T1110".to_string());
        let questions = generate_mitre_questions(&techs);
        if questions.len() >= 2 {
            for pair in questions.windows(2) {
                assert!(pair[0].priority_score >= pair[1].priority_score);
            }
        }
    }
}
