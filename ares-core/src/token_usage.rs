//! LLM token usage tracking and cost estimation.
//!
//! Provides Redis-backed atomic token counters that match the Python
//! `RedisTaskQueue.increment_token_usage()` / `get_token_usage()` protocol
//! exactly, ensuring interoperability between Rust and Python workers.
//!
//! ## Redis key format
//!
//! All counters live in a single HASH at `ares:op:{op_id}:token_usage`:
//!
//! | Field | Description |
//! |-------|-------------|
//! | `input_tokens` | Aggregate prompt tokens across all models |
//! | `output_tokens` | Aggregate completion tokens across all models |
//! | `model` | Last model name (last-writer-wins) |
//! | `model:{base64(name)}:input_tokens` | Per-model input tokens |
//! | `model:{base64(name)}:output_tokens` | Per-model output tokens |
//!
//! Model names are URL-safe base64-encoded to avoid `:` / `/` collisions in
//! Redis HASH field names, matching Python's `_token_usage_model_field()`.

use std::collections::HashMap;

use base64::engine::general_purpose::URL_SAFE;
use base64::Engine;
use redis::AsyncCommands;

/// Redis HASH field prefix for per-model counters.
const MODEL_PREFIX: &str = "model";

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Token usage counters for a single LLM call.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// Aggregated token usage for an operation, with per-model breakdown.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct OperationTokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Last model that wrote to the HASH (informational).
    pub model: String,
    /// Per-model breakdown: `model_name -> {input_tokens, output_tokens}`.
    pub models: HashMap<String, ModelTokenUsage>,
}

/// Per-model token counters.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ModelTokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

// ---------------------------------------------------------------------------
// Cost estimation — static pricing table (no litellm in Rust)
// ---------------------------------------------------------------------------

/// Per-model pricing: (input_cost_per_million, output_cost_per_million) in USD.
///
/// Kept in sync with common LLM provider pricing. Models not in the table
/// are reported as "unpriced" in the breakdown.
const MODEL_COSTS: &[(&str, f64, f64)] = &[
    // Anthropic Claude
    ("claude-sonnet-4-20250514", 3.0, 15.0),
    ("claude-opus-4-20250514", 15.0, 75.0),
    ("claude-haiku-3-5-20241022", 0.80, 4.0),
    ("anthropic/claude-sonnet-4-20250514", 3.0, 15.0),
    ("anthropic/claude-opus-4-20250514", 15.0, 75.0),
    // OpenAI GPT-4.1
    ("gpt-4.1", 2.0, 8.0),
    ("gpt-4.1-mini", 0.40, 1.60),
    ("gpt-4.1-nano", 0.10, 0.40),
    ("openai/gpt-4.1", 2.0, 8.0),
    ("openai/gpt-4.1-mini", 0.40, 1.60),
    ("openai/gpt-4.1-nano", 0.10, 0.40),
    // OpenAI GPT-4o/4-turbo
    ("gpt-4o", 2.50, 10.0),
    ("gpt-4o-mini", 0.15, 0.60),
    ("gpt-4-turbo", 10.0, 30.0),
    ("openai/gpt-4o", 2.50, 10.0),
    ("openai/gpt-4o-mini", 0.15, 0.60),
    ("openai/gpt-4-turbo", 10.0, 30.0),
    // OpenAI GPT-5
    ("gpt-5", 1.25, 10.0),
    ("gpt-5.2", 1.75, 14.0),
    ("gpt-5-mini", 0.25, 2.0),
    ("openai/gpt-5", 1.25, 10.0),
    ("openai/gpt-5.2", 1.75, 14.0),
    ("openai/gpt-5-mini", 0.25, 2.0),
    // Google Gemini
    ("gemini/gemini-2.5-pro", 1.25, 10.0),
    ("gemini/gemini-2.5-flash", 0.15, 0.60),
];

/// Cost breakdown for a single model.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ModelCostBreakdown {
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub cost: f64,
}

/// Estimate the total cost for an operation's token usage.
///
/// Returns `(total_cost, priced_breakdown, unpriced_models)`.
/// If no models could be priced, `total_cost` is `None`.
pub fn estimate_usage_cost(
    usage: &OperationTokenUsage,
) -> (Option<f64>, Vec<ModelCostBreakdown>, Vec<String>) {
    if usage.models.is_empty() {
        return (None, vec![], vec![]);
    }

    let mut total_cost = 0.0f64;
    let mut breakdown = Vec::new();
    let mut unpriced = Vec::new();

    let mut models: Vec<_> = usage.models.iter().collect();
    models.sort_by_key(|(name, _)| name.to_lowercase());

    for (model_name, model_usage) in models {
        if let Some((input_rate, output_rate)) = lookup_model_cost(model_name) {
            let cost = (model_usage.input_tokens as f64 * input_rate
                + model_usage.output_tokens as f64 * output_rate)
                / 1_000_000.0;
            total_cost += cost;
            breakdown.push(ModelCostBreakdown {
                model: model_name.clone(),
                input_tokens: model_usage.input_tokens,
                output_tokens: model_usage.output_tokens,
                total_tokens: model_usage.input_tokens + model_usage.output_tokens,
                cost,
            });
        } else {
            unpriced.push(model_name.clone());
        }
    }

    if breakdown.is_empty() {
        (None, breakdown, unpriced)
    } else {
        (Some(total_cost), breakdown, unpriced)
    }
}

/// Look up per-token pricing for a model.
fn lookup_model_cost(model: &str) -> Option<(f64, f64)> {
    let model_lower = model.to_lowercase();
    for &(name, input, output) in MODEL_COSTS {
        if name == model_lower {
            return Some((input, output));
        }
    }
    // Fuzzy fallback: check if model contains a known name as substring
    for &(name, input, output) in MODEL_COSTS {
        if model_lower.contains(name) || name.contains(&model_lower) {
            return Some((input, output));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Redis operations — Python-compatible
// ---------------------------------------------------------------------------

/// Build the Redis key for an operation's token usage HASH.
pub fn token_usage_key(operation_id: &str) -> String {
    format!("ares:op:{operation_id}:token_usage")
}

/// Build the Redis key for a blue team investigation's token usage HASH.
pub fn blue_token_usage_key(investigation_id: &str) -> String {
    format!("ares:blue:inv:{investigation_id}:token_usage")
}

/// Atomically increment token usage counters for a blue team investigation.
pub async fn increment_blue_token_usage(
    conn: &mut impl AsyncCommands,
    investigation_id: &str,
    input_tokens: u64,
    output_tokens: u64,
    model: &str,
) -> Result<(), redis::RedisError> {
    let key = blue_token_usage_key(investigation_id);

    let input_i64 = i64::try_from(input_tokens).map_err(|_| {
        redis::RedisError::from((
            redis::ErrorKind::InvalidClientConfig,
            "input_tokens overflows i64",
        ))
    })?;
    let output_i64 = i64::try_from(output_tokens).map_err(|_| {
        redis::RedisError::from((
            redis::ErrorKind::InvalidClientConfig,
            "output_tokens overflows i64",
        ))
    })?;

    let mut pipe = redis::pipe();
    pipe.atomic();
    pipe.cmd("HINCRBY")
        .arg(&key)
        .arg("input_tokens")
        .arg(input_i64);
    pipe.cmd("HINCRBY")
        .arg(&key)
        .arg("output_tokens")
        .arg(output_i64);

    if !model.is_empty() {
        pipe.cmd("HSET").arg(&key).arg("model").arg(model);
        pipe.cmd("HINCRBY")
            .arg(&key)
            .arg(model_field(model, "input_tokens"))
            .arg(input_i64);
        pipe.cmd("HINCRBY")
            .arg(&key)
            .arg(model_field(model, "output_tokens"))
            .arg(output_i64);
    }

    pipe.query_async::<()>(conn).await?;
    Ok(())
}

/// Read aggregated token usage for a blue team investigation.
///
/// Returns `None` if the key does not exist.
pub async fn get_blue_token_usage(
    conn: &mut impl AsyncCommands,
    investigation_id: &str,
) -> Result<Option<OperationTokenUsage>, redis::RedisError> {
    let key = blue_token_usage_key(investigation_id);
    let data: HashMap<String, String> = conn.hgetall(&key).await?;
    if data.is_empty() {
        return Ok(None);
    }

    let input_tokens = data
        .get("input_tokens")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let output_tokens = data
        .get("output_tokens")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let model = data.get("model").cloned().unwrap_or_default();

    let mut models: HashMap<String, ModelTokenUsage> = HashMap::new();
    for (field, value) in &data {
        if let Some((model_name, token_type)) = parse_model_field(field) {
            let entry = models.entry(model_name).or_default();
            let count = value.parse::<u64>().unwrap_or(0);
            match token_type.as_str() {
                "input_tokens" => entry.input_tokens = count,
                "output_tokens" => entry.output_tokens = count,
                _ => {}
            }
        }
    }

    Ok(Some(OperationTokenUsage {
        input_tokens,
        output_tokens,
        model,
        models,
    }))
}

/// Encode a per-model HASH field name matching Python's `_token_usage_model_field`.
///
/// Format: `model:{url_safe_base64(model_name)}:{token_type}`
fn model_field(model: &str, token_type: &str) -> String {
    let encoded = URL_SAFE.encode(model.as_bytes());
    format!("{MODEL_PREFIX}:{encoded}:{token_type}")
}

/// Decode a per-model HASH field back to `(model_name, token_type)`.
///
/// Returns `None` for non-model fields (e.g. `input_tokens`, `model`).
fn parse_model_field(field: &str) -> Option<(String, String)> {
    let rest = field
        .strip_prefix(MODEL_PREFIX)
        .and_then(|s| s.strip_prefix(':'))?;
    let colon_pos = rest.rfind(':')?;
    let encoded = &rest[..colon_pos];
    let token_type = &rest[colon_pos + 1..];
    let decoded = URL_SAFE.decode(encoded).ok()?;
    let model_name = String::from_utf8(decoded).ok()?;
    Some((model_name, token_type.to_string()))
}

/// Atomically increment token usage counters for an operation.
///
/// Uses Redis HINCRBY for lock-free, crash-safe accumulation across workers.
/// Matches Python's `RedisTaskQueue.increment_token_usage()`.
pub async fn increment_token_usage(
    conn: &mut impl AsyncCommands,
    operation_id: &str,
    input_tokens: u64,
    output_tokens: u64,
    model: &str,
) -> Result<(), redis::RedisError> {
    let key = token_usage_key(operation_id);

    let input_i64 = i64::try_from(input_tokens).map_err(|_| {
        redis::RedisError::from((
            redis::ErrorKind::InvalidClientConfig,
            "input_tokens overflows i64",
        ))
    })?;
    let output_i64 = i64::try_from(output_tokens).map_err(|_| {
        redis::RedisError::from((
            redis::ErrorKind::InvalidClientConfig,
            "output_tokens overflows i64",
        ))
    })?;

    let mut pipe = redis::pipe();
    pipe.atomic();
    pipe.cmd("HINCRBY")
        .arg(&key)
        .arg("input_tokens")
        .arg(input_i64);
    pipe.cmd("HINCRBY")
        .arg(&key)
        .arg("output_tokens")
        .arg(output_i64);

    if !model.is_empty() {
        pipe.cmd("HSET").arg(&key).arg("model").arg(model);
        pipe.cmd("HINCRBY")
            .arg(&key)
            .arg(model_field(model, "input_tokens"))
            .arg(input_i64);
        pipe.cmd("HINCRBY")
            .arg(&key)
            .arg(model_field(model, "output_tokens"))
            .arg(output_i64);
    }

    pipe.query_async::<()>(conn).await?;
    Ok(())
}

/// Read aggregated token usage for an operation.
///
/// Returns `None` if the key does not exist.
/// Matches Python's `RedisTaskQueue.get_token_usage()`.
pub async fn get_token_usage(
    conn: &mut impl AsyncCommands,
    operation_id: &str,
) -> Result<Option<OperationTokenUsage>, redis::RedisError> {
    let key = token_usage_key(operation_id);
    let data: HashMap<String, String> = conn.hgetall(&key).await?;
    if data.is_empty() {
        return Ok(None);
    }

    let input_tokens = data
        .get("input_tokens")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let output_tokens = data
        .get("output_tokens")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let model = data.get("model").cloned().unwrap_or_default();

    let mut models: HashMap<String, ModelTokenUsage> = HashMap::new();
    for (field, value) in &data {
        if let Some((model_name, token_type)) = parse_model_field(field) {
            let entry = models.entry(model_name).or_default();
            let count = value.parse::<u64>().unwrap_or(0);
            match token_type.as_str() {
                "input_tokens" => entry.input_tokens = count,
                "output_tokens" => entry.output_tokens = count,
                _ => {}
            }
        }
    }

    Ok(Some(OperationTokenUsage {
        input_tokens,
        output_tokens,
        model,
        models,
    }))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_field_roundtrip() {
        let field = model_field("openai/gpt-4.1-mini", "input_tokens");
        assert!(field.starts_with("model:"));
        assert!(field.ends_with(":input_tokens"));

        let (model, token_type) = parse_model_field(&field).unwrap();
        assert_eq!(model, "openai/gpt-4.1-mini");
        assert_eq!(token_type, "input_tokens");
    }

    #[test]
    fn test_model_field_with_slashes_and_dots() {
        // Ensure models with special chars survive encoding
        let names = [
            "anthropic/claude-sonnet-4-20250514",
            "openai/gpt-4.1",
            "gemini/gemini-2.5-pro",
        ];
        for name in names {
            let field = model_field(name, "output_tokens");
            let (decoded, tt) = parse_model_field(&field).unwrap();
            assert_eq!(decoded, name);
            assert_eq!(tt, "output_tokens");
        }
    }

    #[test]
    fn test_parse_non_model_fields() {
        assert!(parse_model_field("input_tokens").is_none());
        assert!(parse_model_field("output_tokens").is_none());
        assert!(parse_model_field("model").is_none());
    }

    #[test]
    fn test_estimate_usage_cost_single_model() {
        let usage = OperationTokenUsage {
            input_tokens: 1_000_000,
            output_tokens: 500_000,
            model: "openai/gpt-4.1-mini".to_string(),
            models: HashMap::from([(
                "openai/gpt-4.1-mini".to_string(),
                ModelTokenUsage {
                    input_tokens: 1_000_000,
                    output_tokens: 500_000,
                },
            )]),
        };

        let (total, breakdown, unpriced) = estimate_usage_cost(&usage);
        assert!(total.is_some());
        assert_eq!(breakdown.len(), 1);
        assert!(unpriced.is_empty());
        // gpt-4.1-mini: $0.40/M input + $1.60/M output
        // cost = 1M * 0.40/1M + 0.5M * 1.60/1M = 0.40 + 0.80 = 1.20
        let cost = total.unwrap();
        assert!((cost - 1.20).abs() < 0.001, "expected ~1.20, got {cost}");
    }

    #[test]
    fn test_estimate_usage_cost_multi_model() {
        let usage = OperationTokenUsage {
            input_tokens: 2_000_000,
            output_tokens: 1_000_000,
            model: "openai/gpt-4.1".to_string(),
            models: HashMap::from([
                (
                    "openai/gpt-4.1-mini".to_string(),
                    ModelTokenUsage {
                        input_tokens: 1_000_000,
                        output_tokens: 500_000,
                    },
                ),
                (
                    "openai/gpt-4.1".to_string(),
                    ModelTokenUsage {
                        input_tokens: 1_000_000,
                        output_tokens: 500_000,
                    },
                ),
            ]),
        };

        let (total, breakdown, _) = estimate_usage_cost(&usage);
        assert!(total.is_some());
        assert_eq!(breakdown.len(), 2);
        // gpt-4.1-mini: 1M * 0.40 + 0.5M * 1.60 = 0.40 + 0.80 = 1.20
        // gpt-4.1:      1M * 2.00 + 0.5M * 8.00 = 2.00 + 4.00 = 6.00
        // total = 7.20
        let cost = total.unwrap();
        assert!((cost - 7.20).abs() < 0.001, "expected ~7.20, got {cost}");
    }

    #[test]
    fn test_estimate_usage_cost_unknown_model() {
        let usage = OperationTokenUsage {
            input_tokens: 100,
            output_tokens: 50,
            model: "unknown-model-v99".to_string(),
            models: HashMap::from([(
                "unknown-model-v99".to_string(),
                ModelTokenUsage {
                    input_tokens: 100,
                    output_tokens: 50,
                },
            )]),
        };

        let (total, breakdown, unpriced) = estimate_usage_cost(&usage);
        assert!(total.is_none());
        assert!(breakdown.is_empty());
        assert_eq!(unpriced, vec!["unknown-model-v99"]);
    }

    #[test]
    fn test_estimate_usage_cost_empty() {
        let usage = OperationTokenUsage::default();
        let (total, breakdown, unpriced) = estimate_usage_cost(&usage);
        assert!(total.is_none());
        assert!(breakdown.is_empty());
        assert!(unpriced.is_empty());
    }

    #[test]
    fn test_token_usage_key() {
        assert_eq!(
            token_usage_key("op-abc-123"),
            "ares:op:op-abc-123:token_usage"
        );
    }
}
