//! Public tool functions: Redis evidence loader and all `*_tool()` entry points.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::args::{optional_i64, required_str};
use crate::ToolOutput;

use super::data::{attack_chains, detection_recipes, make_output};
use super::mitre::generate_mitre_questions;
use super::pyramid::{assess_pyramid, generate_pyramid_questions, EvidenceItem};

pub async fn load_investigation_evidence(
    investigation_id: &str,
) -> anyhow::Result<(HashSet<String>, Vec<EvidenceItem>)> {
    let url = std::env::var("ARES_REDIS_URL")
        .or_else(|_| std::env::var("REDIS_URL"))
        .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

    let client = redis::Client::open(url.as_str())?;
    let mut conn = client.get_multiplexed_async_connection().await?;

    // Load techniques
    let tech_key = format!("ares:blue:inv:{investigation_id}:techniques");
    let techniques: HashSet<String> = redis::AsyncCommands::smembers(&mut conn, &tech_key)
        .await
        .unwrap_or_default();

    // Load evidence
    let evidence_key = format!("ares:blue:inv:{investigation_id}:evidence");
    let evidence_map: HashMap<String, String> =
        redis::AsyncCommands::hgetall(&mut conn, &evidence_key)
            .await
            .unwrap_or_default();

    let mut evidence_items = Vec::new();
    for val in evidence_map.values() {
        if let Ok(obj) = serde_json::from_str::<Value>(val) {
            let value = obj
                .get("value")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let pyramid_level = obj
                .get("pyramid_level")
                .and_then(|v| v.as_str())
                .unwrap_or("ip_addresses")
                .to_string();
            if !value.is_empty() {
                evidence_items.push(EvidenceItem {
                    value,
                    pyramid_level,
                });
            }
        }
    }

    Ok((techniques, evidence_items))
}

/// Generate MITRE-based investigative questions from current investigation state.
pub async fn generate_mitre_questions_tool(args: &Value) -> anyhow::Result<ToolOutput> {
    let investigation_id = required_str(args, "investigation_id")?;
    let max_questions = optional_i64(args, "max_questions").unwrap_or(10) as usize;

    let (techniques, _evidence) = load_investigation_evidence(investigation_id).await?;

    if techniques.is_empty() {
        return Ok(make_output(
            "No techniques identified yet. Add techniques first to generate MITRE questions.",
        ));
    }

    let questions = generate_mitre_questions(&techniques);
    let capped: Vec<Value> = questions
        .iter()
        .take(max_questions)
        .map(|q| q.to_json())
        .collect();

    let output = serde_json::to_string_pretty(&capped).unwrap_or_default();
    Ok(make_output(&format!(
        "Generated {} MITRE questions (from {} techniques):\n\n{}",
        capped.len(),
        techniques.len(),
        output
    )))
}

/// Generate pyramid-climbing questions from current investigation evidence.
pub async fn generate_pyramid_questions_tool(args: &Value) -> anyhow::Result<ToolOutput> {
    let investigation_id = required_str(args, "investigation_id")?;
    let max_questions = optional_i64(args, "max_questions").unwrap_or(10) as usize;

    let (_techniques, evidence) = load_investigation_evidence(investigation_id).await?;

    if evidence.is_empty() {
        return Ok(make_output(
            "No evidence collected yet. Add evidence first to generate pyramid questions.",
        ));
    }

    let questions = generate_pyramid_questions(&evidence);
    let capped: Vec<Value> = questions
        .iter()
        .take(max_questions)
        .map(|q| q.to_json())
        .collect();

    let output = serde_json::to_string_pretty(&capped).unwrap_or_default();
    Ok(make_output(&format!(
        "Generated {} Pyramid of Pain questions (from {} evidence items):\n\n{}",
        capped.len(),
        evidence.len(),
        output
    )))
}

/// Assess current Pyramid of Pain state.
pub async fn assess_pyramid_state_tool(args: &Value) -> anyhow::Result<ToolOutput> {
    let investigation_id = required_str(args, "investigation_id")?;

    let (_techniques, evidence) = load_investigation_evidence(investigation_id).await?;

    let assessment = assess_pyramid(&evidence);
    let output = serde_json::to_string_pretty(&assessment).unwrap_or_default();

    Ok(make_output(&format!(
        "Pyramid of Pain Assessment:\n\n{output}"
    )))
}

/// Get combined questions from both MITRE and Pyramid engines, sorted by priority.
pub async fn get_combined_questions_tool(args: &Value) -> anyhow::Result<ToolOutput> {
    let investigation_id = required_str(args, "investigation_id")?;
    let max_questions = optional_i64(args, "max_questions").unwrap_or(10) as usize;

    let (techniques, evidence) = load_investigation_evidence(investigation_id).await?;

    let mut all_questions = Vec::new();

    if !techniques.is_empty() {
        all_questions.extend(generate_mitre_questions(&techniques));
    }
    if !evidence.is_empty() {
        all_questions.extend(generate_pyramid_questions(&evidence));
    }

    if all_questions.is_empty() {
        return Ok(make_output(
            "No questions to generate. Add techniques or evidence first.",
        ));
    }

    all_questions.sort_by(|a, b| {
        b.priority_score
            .partial_cmp(&a.priority_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let capped: Vec<Value> = all_questions
        .iter()
        .take(max_questions)
        .map(|q| q.to_json())
        .collect();

    let output = serde_json::to_string_pretty(&capped).unwrap_or_default();
    Ok(make_output(&format!(
        "Combined questions ({} total, showing top {}):\n\n{}",
        all_questions.len(),
        capped.len(),
        output
    )))
}

/// Get attack chain precursors for a technique.
pub fn get_attack_chain_precursors(args: &Value) -> anyhow::Result<ToolOutput> {
    let technique_id = required_str(args, "technique_id")?;

    let chains = attack_chains();
    let Some(chain) = chains.get(technique_id) else {
        let available: Vec<&str> = chains.keys().map(|k| k.as_str()).collect();
        return Ok(make_output(&format!(
            "No attack chain data for technique {}.\nAvailable techniques: {}",
            technique_id,
            available.join(", ")
        )));
    };

    let output = serde_json::json!({
        "technique": technique_id,
        "name": chain.name,
        "description": chain.description,
        "precursors": chain.precursors.iter().map(|p| serde_json::json!({
            "technique": p.technique,
            "name": p.name,
            "relationship": p.relationship,
            "relevance": p.relevance,
            "rationale": p.rationale,
        })).collect::<Vec<_>>(),
        "windows_events": chain.windows_events.iter().map(|e| serde_json::json!({
            "event_id": e.event_id,
            "name": e.name,
            "relevance": e.relevance,
            "description": e.description,
            "query_pattern": e.query_pattern,
        })).collect::<Vec<_>>(),
        "log_patterns": chain.log_patterns.iter().map(|p| serde_json::json!({
            "name": p.name,
            "pattern": p.pattern.trim(),
            "description": p.description,
        })).collect::<Vec<_>>(),
        "investigation_questions": chain.investigation_questions.iter().map(|q| serde_json::json!({
            "question": q.question,
            "priority": q.priority,
            "target_technique": q.target_technique,
        })).collect::<Vec<_>>(),
    });

    let formatted = serde_json::to_string_pretty(&output).unwrap_or_default();
    Ok(make_output(&formatted))
}

/// Get a detection recipe by name.
pub fn get_detection_recipe(args: &Value) -> anyhow::Result<ToolOutput> {
    let recipe_name = required_str(args, "recipe_name")?;

    let recipes = detection_recipes();
    let Some(recipe) = recipes.get(recipe_name) else {
        let available: Vec<&str> = recipes.keys().map(|k| k.as_str()).collect();
        return Ok(make_output(&format!(
            "No detection recipe '{}'.\nAvailable recipes: {}",
            recipe_name,
            available.join(", ")
        )));
    };

    // Extract fields with coalescing (mitre_technique or mitre_techniques)
    let mitre = recipe
        .get("mitre_technique")
        .or_else(|| recipe.get("mitre_techniques"))
        .cloned()
        .unwrap_or(Value::Null);

    let output = serde_json::json!({
        "name": recipe.get("name").and_then(|v| v.as_str()).unwrap_or(recipe_name),
        "description": recipe.get("description").and_then(|v| v.as_str()).unwrap_or(""),
        "mitre_technique": mitre,
        "indicators": recipe.get("indicators").unwrap_or(&Value::Null),
        "windows_events": recipe.get("windows_events").unwrap_or(&Value::Null),
        "logql_queries": recipe.get("logql_queries").unwrap_or(&Value::Null),
        "investigation_steps": recipe.get("investigation_steps").unwrap_or(&Value::Null),
        "detection_logic": recipe.get("detection_patterns").unwrap_or(&Value::Null),
    });

    let formatted = serde_json::to_string_pretty(&output).unwrap_or_default();
    Ok(make_output(&formatted))
}

/// List all available detection recipes.
pub fn list_detection_recipes(_args: &Value) -> anyhow::Result<ToolOutput> {
    let recipes = detection_recipes();

    let mut entries: Vec<Value> = Vec::new();
    for (key, val) in recipes {
        if !val.is_object() {
            continue;
        }
        let name = val
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(key.as_str());
        let mitre = val
            .get("mitre_technique")
            .or_else(|| val.get("mitre_techniques"))
            .cloned()
            .unwrap_or(Value::Null);
        let desc = val
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let short_desc = if desc.len() > 100 {
            format!("{}...", &desc[..100])
        } else {
            desc.to_string()
        };

        entries.push(serde_json::json!({
            "recipe_name": key,
            "name": name,
            "mitre_technique": mitre,
            "description": short_desc,
        }));
    }

    let output = serde_json::to_string_pretty(&entries).unwrap_or_default();
    Ok(make_output(&format!(
        "Available detection recipes ({}):\n\n{}",
        entries.len(),
        output
    )))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::blue::engines::data::{
        attack_chains, climb_strategies, detection_recipes, technique_to_recipe,
    };
    use crate::blue::engines::mitre::generate_mitre_questions;
    use crate::blue::engines::pyramid::{assess_pyramid, generate_pyramid_questions, EvidenceItem};

    #[test]
    fn attack_chains_load() {
        let chains = attack_chains();
        assert!(chains.contains_key("T1003.006"), "DCSync should be present");
        assert!(
            chains.contains_key("T1558.003"),
            "Kerberoasting should be present"
        );
        assert!(chains.len() >= 10, "Should have 10+ techniques");
    }

    #[test]
    fn detection_recipes_load() {
        let recipes = detection_recipes();
        assert!(
            recipes.contains_key("dcsync"),
            "DCSync recipe should be present"
        );
        assert!(
            recipes.contains_key("password_spray"),
            "Password spray recipe should be present"
        );
        // query_templates should be filtered out
        assert!(
            !recipes.contains_key("query_templates"),
            "query_templates should be filtered"
        );
    }

    #[test]
    fn climb_strategies_load() {
        let strategies = climb_strategies();
        assert!(
            strategies.contains_key("hash_values"),
            "hash_values should be present"
        );
        assert!(
            strategies.contains_key("ip_addresses"),
            "ip_addresses should be present"
        );
        assert!(strategies.contains_key("tools"), "tools should be present");
    }

    #[test]
    fn generates_mitre_questions() {
        let mut techniques = HashSet::new();
        techniques.insert("T1003.006".to_string());

        let questions = generate_mitre_questions(&techniques);
        assert!(
            !questions.is_empty(),
            "Should generate questions for DCSync"
        );

        // Should be sorted by priority (descending)
        for w in questions.windows(2) {
            assert!(
                w[0].priority_score >= w[1].priority_score,
                "Questions should be sorted by priority"
            );
        }
    }

    #[test]
    fn generates_pyramid_questions() {
        let evidence = vec![
            EvidenceItem {
                value: "192.168.58.10".to_string(),
                pyramid_level: "ip_addresses".to_string(),
            },
            EvidenceItem {
                value: "abc123".to_string(),
                pyramid_level: "hash_values".to_string(),
            },
        ];

        let questions = generate_pyramid_questions(&evidence);
        assert!(
            !questions.is_empty(),
            "Should generate pyramid questions for evidence"
        );
        assert!(
            questions.iter().all(|q| q.source == "pyramid"),
            "All should be pyramid source"
        );
    }

    #[test]
    fn pyramid_questions_skip_ttps() {
        let evidence = vec![EvidenceItem {
            value: "T1003".to_string(),
            pyramid_level: "ttps".to_string(),
        }];

        let questions = generate_pyramid_questions(&evidence);
        assert!(
            questions.is_empty(),
            "Should not generate questions for TTPs (already at top)"
        );
    }

    #[test]
    fn assesses_pyramid() {
        let evidence = vec![
            EvidenceItem {
                value: "192.168.58.10".to_string(),
                pyramid_level: "ip_addresses".to_string(),
            },
            EvidenceItem {
                value: "evil.com".to_string(),
                pyramid_level: "domain_names".to_string(),
            },
        ];

        let assessment = assess_pyramid(&evidence);
        let score = assessment
            .get("elevation_score")
            .and_then(|v| v.as_f64())
            .unwrap();
        assert!(
            score > 0.0 && score < 1.0,
            "Score should be between 0 and 1"
        );
        assert_eq!(
            assessment
                .get("total_evidence")
                .and_then(|v| v.as_u64())
                .unwrap(),
            2
        );
    }

    #[test]
    fn assess_pyramid_empty() {
        let assessment = assess_pyramid(&[]);
        assert_eq!(
            assessment
                .get("elevation_score")
                .and_then(|v| v.as_f64())
                .unwrap(),
            0.0
        );
    }

    #[test]
    fn gets_attack_chain_precursors() {
        let args = serde_json::json!({ "technique_id": "T1003.006" });
        let result = get_attack_chain_precursors(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("DCSync"));
        assert!(result.stdout.contains("precursors"));
    }

    #[test]
    fn get_attack_chain_unknown() {
        let args = serde_json::json!({ "technique_id": "T9999" });
        let result = get_attack_chain_precursors(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("No attack chain data"));
    }

    #[test]
    fn gets_detection_recipe() {
        let args = serde_json::json!({ "recipe_name": "dcsync" });
        let result = get_detection_recipe(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("DCSync"));
    }

    #[test]
    fn get_detection_recipe_unknown() {
        let args = serde_json::json!({ "recipe_name": "nonexistent" });
        let result = get_detection_recipe(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("No detection recipe"));
        assert!(result.stdout.contains("Available recipes"));
    }

    #[test]
    fn lists_detection_recipes() {
        let args = serde_json::json!({});
        let result = list_detection_recipes(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("dcsync") || result.stdout.contains("DCSync"));
    }

    #[test]
    fn technique_to_recipe_mapping() {
        let map = technique_to_recipe();
        assert_eq!(map.get("T1003.006"), Some(&"dcsync"));
        assert_eq!(map.get("T1110.003"), Some(&"password_spray"));
        assert_eq!(map.get("T1558.003"), Some(&"kerberos_attacks"));
    }
}
