//! Investigation question engines: MITRENavigator and PyramidClimber.
//!
//! Generates investigative questions based on identified techniques and evidence
//! to drive investigation depth — climbing the Pyramid of Pain and following
//! MITRE ATT&CK chains.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use serde::Deserialize;
use serde_json::Value;

use crate::args::{optional_i64, required_str};
use crate::ToolOutput;

// ---------------------------------------------------------------------------
// Embedded YAML data
// ---------------------------------------------------------------------------

const ATTACK_CHAINS_YAML: &str = include_str!("data/attack_chains.yaml");
const DETECTION_RECIPES_YAML: &str = include_str!("data/detection_recipes.yaml");
const CLIMB_STRATEGIES_YAML: &str = include_str!("data/climb_strategies.yaml");

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct AttackChainEntry {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub precursors: Vec<ChainPrecursor>,
    #[serde(default)]
    pub follow_on: Vec<ChainPrecursor>,
    #[serde(default)]
    pub windows_events: Vec<WindowsEvent>,
    #[serde(default)]
    pub log_patterns: Vec<LogPattern>,
    #[serde(default)]
    pub investigation_questions: Vec<ChainQuestion>,
    #[serde(default)]
    pub detection_patterns: HashMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainPrecursor {
    pub technique: String,
    pub name: String,
    #[serde(default)]
    pub relationship: String,
    #[serde(default)]
    pub relevance: f64,
    #[serde(default)]
    pub rationale: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WindowsEvent {
    pub event_id: u32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub relevance: f64,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub query_pattern: String,
    #[serde(default)]
    pub threshold: Option<String>,
    #[serde(default)]
    pub detection_logic: Option<String>,
    #[serde(default)]
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogPattern {
    pub name: String,
    pub pattern: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainQuestion {
    pub question: String,
    #[serde(default)]
    pub priority: f64,
    #[serde(default)]
    pub target_technique: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClimbStrategy {
    pub template: String,
    pub target: String,
    #[serde(default)]
    pub insight: String,
    #[serde(default)]
    pub elevation: u32,
}

// ---------------------------------------------------------------------------
// Lazy-loaded data caches
// ---------------------------------------------------------------------------

fn attack_chains() -> &'static HashMap<String, AttackChainEntry> {
    static CACHE: OnceLock<HashMap<String, AttackChainEntry>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let raw: HashMap<String, Value> =
            serde_yaml::from_str(ATTACK_CHAINS_YAML).unwrap_or_default();
        let mut chains = HashMap::new();
        for (key, val) in raw {
            if key.starts_with('T') {
                if let Ok(entry) = serde_json::from_value::<AttackChainEntry>(
                    serde_json::to_value(&val).unwrap_or_default(),
                ) {
                    chains.insert(key, entry);
                }
            }
        }
        chains
    })
}

fn detection_recipes() -> &'static HashMap<String, Value> {
    static CACHE: OnceLock<HashMap<String, Value>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let raw: HashMap<String, Value> =
            serde_yaml::from_str(DETECTION_RECIPES_YAML).unwrap_or_default();
        raw.into_iter()
            .filter(|(k, _)| !k.starts_with("query_"))
            .collect()
    })
}

fn climb_strategies() -> &'static HashMap<String, Vec<ClimbStrategy>> {
    static CACHE: OnceLock<HashMap<String, Vec<ClimbStrategy>>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let raw: HashMap<String, Vec<Value>> =
            serde_yaml::from_str(CLIMB_STRATEGIES_YAML).unwrap_or_default();
        let mut strategies = HashMap::new();
        for (level, vals) in raw {
            let parsed: Vec<ClimbStrategy> = vals
                .into_iter()
                .filter_map(|v| {
                    serde_json::from_value::<ClimbStrategy>(
                        serde_json::to_value(&v).unwrap_or_default(),
                    )
                    .ok()
                })
                .collect();
            if !parsed.is_empty() {
                strategies.insert(level, parsed);
            }
        }
        strategies
    })
}

// Pyramid level name mapping
fn pyramid_level_name(level: &str) -> &str {
    match level {
        "hash_values" => "Hash Values",
        "ip_addresses" => "IP Addresses",
        "domain_names" => "Domain Names",
        "network_host_artifacts" => "Network/Host Artifacts",
        "tools" => "Tools",
        "ttps" => "TTPs",
        _ => level,
    }
}

fn pyramid_level_value(level: &str) -> u32 {
    match level {
        "hash_values" => 1,
        "ip_addresses" => 2,
        "domain_names" => 3,
        "network_host_artifacts" => 4,
        "tools" => 5,
        "ttps" => 6,
        _ => 0,
    }
}

// Technique-to-recipe mapping (hardcoded like Python)
fn technique_to_recipe() -> &'static HashMap<&'static str, &'static str> {
    static MAP: OnceLock<HashMap<&str, &str>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert("T1003.006", "dcsync");
        m.insert("T1110", "password_spray");
        m.insert("T1110.003", "password_spray");
        m.insert("T1110.004", "credential_stuffing");
        m.insert("T1558.003", "kerberos_attacks");
        m.insert("T1558.004", "kerberos_attacks");
        m.insert("T1558.001", "kerberos_attacks");
        m.insert("T1550.002", "pass_the_hash");
        m.insert("T1135", "share_enumeration");
        m.insert("T1087.002", "ldap_enumeration");
        m.insert("T1046", "service_enumeration");
        m
    })
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

fn make_output(body: &str) -> ToolOutput {
    ToolOutput {
        stdout: body.to_string(),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    }
}

// ---------------------------------------------------------------------------
// InvestigativeQuestion
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct InvestigativeQuestion {
    id: String,
    question: String,
    source: &'static str, // "mitre" or "pyramid"
    rationale: String,
    target_technique: Option<String>,
    priority_score: f64,
    #[allow(dead_code)]
    pyramid_elevation_score: f64,
    #[allow(dead_code)]
    confidence_impact_score: f64,
}

impl InvestigativeQuestion {
    fn to_json(&self) -> Value {
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

fn make_question_id(prefix: &str) -> String {
    format!("{}-{}", prefix, &uuid::Uuid::new_v4().to_string()[..8])
}

// ---------------------------------------------------------------------------
// MITRENavigator engine
// ---------------------------------------------------------------------------

/// Generate MITRE-based investigative questions from identified techniques.
fn generate_mitre_questions(identified_techniques: &HashSet<String>) -> Vec<InvestigativeQuestion> {
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
                    pyramid_elevation_score: pyramid_elevation,
                    confidence_impact_score: confidence_impact,
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
                    pyramid_elevation_score: 0.7,
                    confidence_impact_score: 0.8,
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
                                pyramid_elevation_score: 0.7,
                                confidence_impact_score: 0.8,
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
                            pyramid_elevation_score: 0.6,
                            confidence_impact_score: 0.7,
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
                            pyramid_elevation_score: 0.5,
                            confidence_impact_score: 0.6,
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

// ---------------------------------------------------------------------------
// PyramidClimber engine
// ---------------------------------------------------------------------------

/// Evidence item for pyramid climbing.
struct EvidenceItem {
    value: String,
    pyramid_level: String,
}

/// Generate pyramid-climbing questions from evidence.
fn generate_pyramid_questions(evidence: &[EvidenceItem]) -> Vec<InvestigativeQuestion> {
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
fn assess_pyramid(evidence: &[EvidenceItem]) -> Value {
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

// ---------------------------------------------------------------------------
// Evidence extraction from Redis investigation state (for question generation)
// ---------------------------------------------------------------------------

async fn load_investigation_evidence(
    investigation_id: &str,
) -> anyhow::Result<(HashSet<String>, Vec<EvidenceItem>)> {
    let url = std::env::var("ARES_REDIS_URL")
        .or_else(|_| std::env::var("REDIS_URL"))
        .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

    let client = redis::Client::open(url.as_str())?;
    let mut conn = client.get_multiplexed_tokio_connection().await?;

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

// ---------------------------------------------------------------------------
// Tool methods
// ---------------------------------------------------------------------------

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
    let chain = match chains.get(technique_id) {
        Some(c) => c,
        None => {
            let available: Vec<&str> = chains.keys().map(|k| k.as_str()).collect();
            return Ok(make_output(&format!(
                "No attack chain data for technique {}.\nAvailable techniques: {}",
                technique_id,
                available.join(", ")
            )));
        }
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
    let recipe = match recipes.get(recipe_name) {
        Some(r) => r,
        None => {
            let available: Vec<&str> = recipes.keys().map(|k| k.as_str()).collect();
            return Ok(make_output(&format!(
                "No detection recipe '{}'.\nAvailable recipes: {}",
                recipe_name,
                available.join(", ")
            )));
        }
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attack_chains_load() {
        let chains = attack_chains();
        assert!(chains.contains_key("T1003.006"), "DCSync should be present");
        assert!(
            chains.contains_key("T1558.003"),
            "Kerberoasting should be present"
        );
        assert!(chains.len() >= 10, "Should have 10+ techniques");
    }

    #[test]
    fn test_detection_recipes_load() {
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
    fn test_climb_strategies_load() {
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
    fn test_generate_mitre_questions() {
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
    fn test_generate_pyramid_questions() {
        let evidence = vec![
            EvidenceItem {
                value: "192.168.1.1".to_string(),
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
    fn test_pyramid_questions_skip_ttps() {
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
    fn test_assess_pyramid() {
        let evidence = vec![
            EvidenceItem {
                value: "192.168.1.1".to_string(),
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
    fn test_assess_pyramid_empty() {
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
    fn test_get_attack_chain_precursors() {
        let args = serde_json::json!({ "technique_id": "T1003.006" });
        let result = get_attack_chain_precursors(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("DCSync"));
        assert!(result.stdout.contains("precursors"));
    }

    #[test]
    fn test_get_attack_chain_unknown() {
        let args = serde_json::json!({ "technique_id": "T9999" });
        let result = get_attack_chain_precursors(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("No attack chain data"));
    }

    #[test]
    fn test_get_detection_recipe() {
        let args = serde_json::json!({ "recipe_name": "dcsync" });
        let result = get_detection_recipe(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("DCSync"));
    }

    #[test]
    fn test_get_detection_recipe_unknown() {
        let args = serde_json::json!({ "recipe_name": "nonexistent" });
        let result = get_detection_recipe(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("No detection recipe"));
        assert!(result.stdout.contains("Available recipes"));
    }

    #[test]
    fn test_list_detection_recipes() {
        let args = serde_json::json!({});
        let result = list_detection_recipes(&args).unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("dcsync") || result.stdout.contains("DCSync"));
    }

    #[test]
    fn test_technique_to_recipe_mapping() {
        let map = technique_to_recipe();
        assert_eq!(map.get("T1003.006"), Some(&"dcsync"));
        assert_eq!(map.get("T1110.003"), Some(&"password_spray"));
        assert_eq!(map.get("T1558.003"), Some(&"kerberos_attacks"));
    }
}
