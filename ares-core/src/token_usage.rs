//! LLM token usage tracking and cost estimation.
//!
//! Redis-backed atomic token counters.
//!
//! ## Redis key format
//!
//! All counters live in a single HASH at `ares:op:{op_id}:token_usage`:
//!
//! | Field | Description |
//! |-------|-------------|
//! | `input_tokens` | Aggregate uncached prompt tokens across all models |
//! | `cache_read_input_tokens` | Aggregate cached prompt tokens (billed at cached rate) |
//! | `output_tokens` | Aggregate completion tokens across all models |
//! | `model` | Last model name (last-writer-wins) |
//! | `model:{base64(name)}:input_tokens` | Per-model uncached input tokens |
//! | `model:{base64(name)}:cache_read_input_tokens` | Per-model cached input tokens |
//! | `model:{base64(name)}:output_tokens` | Per-model output tokens |
//! | `role:{role}:input_tokens` | Per-role uncached input tokens |
//! | `role:{role}:cache_read_input_tokens` | Per-role cached input tokens |
//! | `role:{role}:output_tokens` | Per-role output tokens |
//! | `role:{role}:model` | Model that role ran on (last-writer-wins) |
//!
//! Model names are URL-safe base64-encoded to avoid `:` / `/` collisions in
//! Redis HASH field names. Role names are fixed identifiers, so they are
//! stored verbatim to keep `HGETALL` output readable.
//!
//! Role fields are additive: operations that predate them read back with an
//! empty `roles` map rather than a table of zeros.

use std::collections::HashMap;

use base64::engine::general_purpose::URL_SAFE;
use base64::Engine;
use redis::AsyncCommands;

/// Redis HASH field prefix for per-model counters.
const MODEL_PREFIX: &str = "model";

/// Redis HASH field prefix for per-role counters.
const ROLE_PREFIX: &str = "role";

/// Token usage counters for a single LLM call.
///
/// `input_tokens` is the uncached portion of the prompt; tokens billed at the
/// provider's cached-input rate are tracked separately in
/// `cache_read_input_tokens`. The OpenAI provider splits the API's reported
/// `prompt_tokens` into these two counters; the Anthropic provider populates
/// `cache_read_input_tokens` from `cache_read_input_tokens` directly.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    #[serde(default)]
    pub cache_read_input_tokens: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// Aggregated token usage for an operation, with per-model breakdown.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct OperationTokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_input_tokens: u64,
    /// Last model that wrote to the HASH (informational).
    pub model: String,
    /// Per-model breakdown.
    pub models: HashMap<String, ModelTokenUsage>,
    /// Per-role breakdown. Empty for operations that predate role tracking.
    pub roles: HashMap<String, RoleTokenUsage>,
}

/// Per-model token counters.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ModelTokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_input_tokens: u64,
}

/// Per-role token counters, with the model that role ran on.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct RoleTokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_input_tokens: u64,
    /// Last model this role wrote under; empty if never recorded.
    pub model: String,
}

/// Per-model pricing in USD per million tokens:
/// `(name, input_cost, cached_input_cost, output_cost)`.
///
/// Cached-input rate applies to tokens billed at the provider's prompt-cache
/// rate (OpenAI auto-cache reads, Anthropic cache reads). For providers that
/// don't expose a cached rate, set `cached_input_cost` equal to `input_cost`.
///
/// Kept in sync with common LLM provider pricing. Models not in the table
/// are reported as "unpriced" in the breakdown.
const MODEL_COSTS: &[(&str, f64, f64, f64)] = &[
    // Anthropic Claude — cache reads are 10% of input.
    ("claude-sonnet-4-6", 3.0, 0.30, 15.0),
    ("claude-opus-4-20250514", 15.0, 1.50, 75.0),
    ("claude-haiku-3-5-20241022", 0.80, 0.08, 4.0),
    ("anthropic/claude-sonnet-4-6", 3.0, 0.30, 15.0),
    ("anthropic/claude-opus-4-20250514", 15.0, 1.50, 75.0),
    // OpenAI GPT-4.1 — auto-cache reads are 25% of input.
    ("gpt-4.1", 2.0, 0.50, 8.0),
    ("gpt-4.1-mini", 0.40, 0.10, 1.60),
    ("gpt-4.1-nano", 0.10, 0.025, 0.40),
    ("openai/gpt-4.1", 2.0, 0.50, 8.0),
    ("openai/gpt-4.1-mini", 0.40, 0.10, 1.60),
    ("openai/gpt-4.1-nano", 0.10, 0.025, 0.40),
    // OpenAI GPT-4o/4-turbo — 4o auto-cache reads are 50% of input;
    // 4-turbo has no cache rate, charge full input.
    ("gpt-4o", 2.50, 1.25, 10.0),
    ("gpt-4o-mini", 0.15, 0.075, 0.60),
    ("gpt-4-turbo", 10.0, 10.0, 30.0),
    ("openai/gpt-4o", 2.50, 1.25, 10.0),
    ("openai/gpt-4o-mini", 0.15, 0.075, 0.60),
    ("openai/gpt-4-turbo", 10.0, 10.0, 30.0),
    // OpenAI GPT-5 — auto-cache reads are 10% of input.
    ("gpt-5", 1.25, 0.125, 10.0),
    ("gpt-5.2", 1.75, 0.175, 14.0),
    ("gpt-5-mini", 0.25, 0.025, 2.0),
    ("openai/gpt-5", 1.25, 0.125, 10.0),
    ("openai/gpt-5.2", 1.75, 0.175, 14.0),
    ("openai/gpt-5-mini", 0.25, 0.025, 2.0),
    // Google Gemini — cache reads ~25% of input.
    ("gemini/gemini-2.5-pro", 1.25, 0.3125, 10.0),
    ("gemini/gemini-2.5-flash", 0.15, 0.0375, 0.60),
];

/// Cost breakdown for a single model.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ModelCostBreakdown {
    pub model: String,
    pub input_tokens: u64,
    pub cache_read_input_tokens: u64,
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
        if let Some((input_rate, cached_rate, output_rate)) = lookup_model_cost(model_name) {
            let cost = (model_usage.input_tokens as f64 * input_rate
                + model_usage.cache_read_input_tokens as f64 * cached_rate
                + model_usage.output_tokens as f64 * output_rate)
                / 1_000_000.0;
            total_cost += cost;
            breakdown.push(ModelCostBreakdown {
                model: model_name.clone(),
                input_tokens: model_usage.input_tokens,
                cache_read_input_tokens: model_usage.cache_read_input_tokens,
                output_tokens: model_usage.output_tokens,
                total_tokens: model_usage.input_tokens
                    + model_usage.cache_read_input_tokens
                    + model_usage.output_tokens,
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

/// Cost breakdown for a single role.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RoleCostBreakdown {
    pub role: String,
    pub model: String,
    pub input_tokens: u64,
    pub cache_read_input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    /// `None` when the role's model is unknown or unpriced.
    pub cost: Option<f64>,
}

/// Estimate per-role cost, sorted by descending spend then role name.
///
/// Roles with an unrecorded or unpriced model report `cost: None` and keep
/// their token counts.
pub fn estimate_role_costs(usage: &OperationTokenUsage) -> Vec<RoleCostBreakdown> {
    let mut out: Vec<RoleCostBreakdown> = usage
        .roles
        .iter()
        .map(|(role, u)| {
            let cost = lookup_model_cost(&u.model).map(|(input, cached, output)| {
                (u.input_tokens as f64 * input
                    + u.cache_read_input_tokens as f64 * cached
                    + u.output_tokens as f64 * output)
                    / 1_000_000.0
            });
            RoleCostBreakdown {
                role: role.clone(),
                model: u.model.clone(),
                input_tokens: u.input_tokens,
                cache_read_input_tokens: u.cache_read_input_tokens,
                output_tokens: u.output_tokens,
                total_tokens: u.input_tokens + u.cache_read_input_tokens + u.output_tokens,
                cost,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        b.cost
            .unwrap_or(0.0)
            .total_cmp(&a.cost.unwrap_or(0.0))
            .then_with(|| a.role.cmp(&b.role))
    });
    out
}

/// Look up per-token pricing for a model.
///
/// Returns `(input_rate, cached_input_rate, output_rate)` per million tokens.
fn lookup_model_cost(model: &str) -> Option<(f64, f64, f64)> {
    let model_lower = model.trim().to_lowercase();
    if model_lower.is_empty() {
        return None;
    }
    for &(name, input, cached, output) in MODEL_COSTS {
        if name == model_lower {
            return Some((input, cached, output));
        }
    }
    // Fuzzy fallback: check if model contains a known name as substring
    for &(name, input, cached, output) in MODEL_COSTS {
        if model_lower.contains(name) || name.contains(&model_lower) {
            return Some((input, cached, output));
        }
    }
    None
}

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
    cache_read_input_tokens: u64,
    output_tokens: u64,
    model: &str,
    role: &str,
) -> Result<(), redis::RedisError> {
    let key = blue_token_usage_key(investigation_id);
    increment_usage_hash(
        conn,
        &key,
        input_tokens,
        cache_read_input_tokens,
        output_tokens,
        model,
        role,
    )
    .await
}

/// Read aggregated token usage for a blue team investigation.
///
/// Returns `None` if the key does not exist.
pub async fn get_blue_token_usage(
    conn: &mut impl AsyncCommands,
    investigation_id: &str,
) -> Result<Option<OperationTokenUsage>, redis::RedisError> {
    let key = blue_token_usage_key(investigation_id);
    read_usage_hash(conn, &key).await
}

/// Encode a per-model HASH field name.
///
/// Format: `model:{url_safe_base64(model_name)}:{token_type}`
fn model_field(model: &str, token_type: &str) -> String {
    let encoded = URL_SAFE.encode(model.as_bytes());
    format!("{MODEL_PREFIX}:{encoded}:{token_type}")
}

/// Encode a per-role HASH field name: `role:{role_name}:{token_type}`.
fn role_field(role: &str, token_type: &str) -> String {
    format!("{ROLE_PREFIX}:{role}:{token_type}")
}

/// Decode a per-role HASH field back to `(role_name, token_type)`.
fn parse_role_field(field: &str) -> Option<(String, String)> {
    let rest = field
        .strip_prefix(ROLE_PREFIX)
        .and_then(|s| s.strip_prefix(':'))?;
    let colon_pos = rest.rfind(':')?;
    let role_name = &rest[..colon_pos];
    let token_type = &rest[colon_pos + 1..];
    if role_name.is_empty() {
        return None;
    }
    Some((role_name.to_string(), token_type.to_string()))
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
pub async fn increment_token_usage(
    conn: &mut impl AsyncCommands,
    operation_id: &str,
    input_tokens: u64,
    cache_read_input_tokens: u64,
    output_tokens: u64,
    model: &str,
    role: &str,
) -> Result<(), redis::RedisError> {
    let key = token_usage_key(operation_id);
    increment_usage_hash(
        conn,
        &key,
        input_tokens,
        cache_read_input_tokens,
        output_tokens,
        model,
        role,
    )
    .await
}

async fn increment_usage_hash(
    conn: &mut impl AsyncCommands,
    key: &str,
    input_tokens: u64,
    cache_read_input_tokens: u64,
    output_tokens: u64,
    model: &str,
    role: &str,
) -> Result<(), redis::RedisError> {
    let input_i64 = i64::try_from(input_tokens).map_err(|_| {
        redis::RedisError::from((
            redis::ErrorKind::InvalidClientConfig,
            "input_tokens overflows i64",
        ))
    })?;
    let cached_i64 = i64::try_from(cache_read_input_tokens).map_err(|_| {
        redis::RedisError::from((
            redis::ErrorKind::InvalidClientConfig,
            "cache_read_input_tokens overflows i64",
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
        .arg(key)
        .arg("input_tokens")
        .arg(input_i64);
    pipe.cmd("HINCRBY")
        .arg(key)
        .arg("cache_read_input_tokens")
        .arg(cached_i64);
    pipe.cmd("HINCRBY")
        .arg(key)
        .arg("output_tokens")
        .arg(output_i64);

    if !model.is_empty() {
        pipe.cmd("HSET").arg(key).arg("model").arg(model);
        pipe.cmd("HINCRBY")
            .arg(key)
            .arg(model_field(model, "input_tokens"))
            .arg(input_i64);
        pipe.cmd("HINCRBY")
            .arg(key)
            .arg(model_field(model, "cache_read_input_tokens"))
            .arg(cached_i64);
        pipe.cmd("HINCRBY")
            .arg(key)
            .arg(model_field(model, "output_tokens"))
            .arg(output_i64);
    }

    if !role.is_empty() {
        pipe.cmd("HINCRBY")
            .arg(key)
            .arg(role_field(role, "input_tokens"))
            .arg(input_i64);
        pipe.cmd("HINCRBY")
            .arg(key)
            .arg(role_field(role, "cache_read_input_tokens"))
            .arg(cached_i64);
        pipe.cmd("HINCRBY")
            .arg(key)
            .arg(role_field(role, "output_tokens"))
            .arg(output_i64);
        if !model.is_empty() {
            pipe.cmd("HSET")
                .arg(key)
                .arg(role_field(role, "model"))
                .arg(model);
        }
    }

    pipe.query_async::<()>(conn).await?;
    Ok(())
}

/// Read aggregated token usage for an operation. Returns `None` if absent.
pub async fn get_token_usage(
    conn: &mut impl AsyncCommands,
    operation_id: &str,
) -> Result<Option<OperationTokenUsage>, redis::RedisError> {
    let key = token_usage_key(operation_id);
    read_usage_hash(conn, &key).await
}

async fn read_usage_hash(
    conn: &mut impl AsyncCommands,
    key: &str,
) -> Result<Option<OperationTokenUsage>, redis::RedisError> {
    let data: HashMap<String, String> = conn.hgetall(key).await?;
    if data.is_empty() {
        return Ok(None);
    }

    let parse_u64 = |field: &str| -> u64 {
        data.get(field)
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
    };

    let input_tokens = parse_u64("input_tokens");
    let cache_read_input_tokens = parse_u64("cache_read_input_tokens");
    let output_tokens = parse_u64("output_tokens");
    let model = data.get("model").cloned().unwrap_or_default();

    let mut models: HashMap<String, ModelTokenUsage> = HashMap::new();
    for (field, value) in &data {
        if let Some((model_name, token_type)) = parse_model_field(field) {
            let entry = models.entry(model_name).or_default();
            let count = value.parse::<u64>().unwrap_or(0);
            match token_type.as_str() {
                "input_tokens" => entry.input_tokens = count,
                "cache_read_input_tokens" => entry.cache_read_input_tokens = count,
                "output_tokens" => entry.output_tokens = count,
                _ => {}
            }
        }
    }

    let mut roles: HashMap<String, RoleTokenUsage> = HashMap::new();
    for (field, value) in &data {
        if let Some((role_name, token_type)) = parse_role_field(field) {
            let entry = roles.entry(role_name).or_default();
            match token_type.as_str() {
                "model" => entry.model = value.clone(),
                "input_tokens" => entry.input_tokens = value.parse().unwrap_or(0),
                "cache_read_input_tokens" => {
                    entry.cache_read_input_tokens = value.parse().unwrap_or(0)
                }
                "output_tokens" => entry.output_tokens = value.parse().unwrap_or(0),
                _ => {}
            }
        }
    }

    Ok(Some(OperationTokenUsage {
        input_tokens,
        cache_read_input_tokens,
        output_tokens,
        model,
        models,
        roles,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage_with_roles(roles: &[(&str, &str, u64, u64, u64)]) -> OperationTokenUsage {
        let mut usage = OperationTokenUsage::default();
        for (role, model, input, cached, output) in roles {
            usage.roles.insert(
                (*role).to_string(),
                RoleTokenUsage {
                    input_tokens: *input,
                    cache_read_input_tokens: *cached,
                    output_tokens: *output,
                    model: (*model).to_string(),
                },
            );
        }
        usage
    }

    #[test]
    fn an_empty_model_name_is_never_priced() {
        assert!(
            lookup_model_cost("").is_none(),
            "the substring fallback matches every entry on an empty name, \
             which would price unrecorded models as the first table row"
        );
        assert!(lookup_model_cost("   ").is_none());
    }

    #[test]
    fn role_field_roundtrip() {
        let field = role_field("credential_access", "input_tokens");
        assert_eq!(field, "role:credential_access:input_tokens");
        let (role, token_type) = parse_role_field(&field).unwrap();
        assert_eq!(role, "credential_access");
        assert_eq!(token_type, "input_tokens");
    }

    #[test]
    fn role_and_model_fields_do_not_capture_each_other() {
        let model = model_field("gpt-5.2", "output_tokens");
        assert!(parse_role_field(&model).is_none());

        let role = role_field("acl", "output_tokens");
        assert!(parse_model_field(&role).is_none());

        for plain in ["input_tokens", "output_tokens", "model"] {
            assert!(parse_role_field(plain).is_none(), "{plain}");
        }
    }

    #[test]
    fn roles_sharing_one_model_are_costed_apart() {
        let usage = usage_with_roles(&[
            ("acl", "gpt-5.2", 50_000, 2_000_000, 30_000),
            ("privesc", "gpt-5.2", 11_000, 508_240, 2_977),
        ]);
        let costs = estimate_role_costs(&usage);

        assert_eq!(costs.len(), 2, "both roles must survive sharing a model");
        assert_eq!(costs[0].role, "acl", "highest spender leads");
        assert_eq!(costs[1].role, "privesc");

        let acl = costs[0].cost.unwrap();
        let privesc = costs[1].cost.unwrap();
        assert!(acl > privesc, "acl {acl} should exceed privesc {privesc}");
        assert_eq!(costs[0].total_tokens, 2_080_000);
    }

    #[test]
    fn a_role_with_an_unknown_model_keeps_its_tokens() {
        let costs = estimate_role_costs(&usage_with_roles(&[("acl", "not-a-real-model", 1, 2, 3)]));
        assert_eq!(costs.len(), 1);
        assert!(costs[0].cost.is_none(), "unpriced model must not fabricate");
        assert_eq!(costs[0].total_tokens, 6, "tokens still reported");
    }

    #[test]
    fn a_role_with_no_recorded_model_is_still_listed() {
        let costs = estimate_role_costs(&usage_with_roles(&[("acl", "", 10, 20, 30)]));
        assert_eq!(costs.len(), 1);
        assert!(costs[0].cost.is_none());
        assert_eq!(costs[0].total_tokens, 60);
    }

    #[test]
    fn operations_predating_role_tracking_report_no_roles() {
        let costs = estimate_role_costs(&OperationTokenUsage::default());
        assert!(
            costs.is_empty(),
            "absent role fields must not render as a table of zeros"
        );
    }

    #[test]
    fn model_field_roundtrip() {
        let field = model_field("openai/gpt-4.1-mini", "input_tokens");
        assert!(field.starts_with("model:"));
        assert!(field.ends_with(":input_tokens"));

        let (model, token_type) = parse_model_field(&field).unwrap();
        assert_eq!(model, "openai/gpt-4.1-mini");
        assert_eq!(token_type, "input_tokens");
    }

    #[test]
    fn model_field_with_slashes_and_dots() {
        // Ensure models with special chars survive encoding
        let names = [
            "anthropic/claude-sonnet-4-6",
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
    fn parse_non_model_fields() {
        assert!(parse_model_field("input_tokens").is_none());
        assert!(parse_model_field("output_tokens").is_none());
        assert!(parse_model_field("model").is_none());
    }

    #[test]
    fn estimate_usage_cost_single_model() {
        let usage = OperationTokenUsage {
            input_tokens: 1_000_000,
            cache_read_input_tokens: 0,
            output_tokens: 500_000,
            model: "openai/gpt-4.1-mini".to_string(),
            models: HashMap::from([(
                "openai/gpt-4.1-mini".to_string(),
                ModelTokenUsage {
                    input_tokens: 1_000_000,
                    cache_read_input_tokens: 0,
                    output_tokens: 500_000,
                },
            )]),
            roles: HashMap::new(),
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
    fn estimate_usage_cost_multi_model() {
        let usage = OperationTokenUsage {
            input_tokens: 2_000_000,
            cache_read_input_tokens: 0,
            output_tokens: 1_000_000,
            model: "openai/gpt-4.1".to_string(),
            models: HashMap::from([
                (
                    "openai/gpt-4.1-mini".to_string(),
                    ModelTokenUsage {
                        input_tokens: 1_000_000,
                        cache_read_input_tokens: 0,
                        output_tokens: 500_000,
                    },
                ),
                (
                    "openai/gpt-4.1".to_string(),
                    ModelTokenUsage {
                        input_tokens: 1_000_000,
                        cache_read_input_tokens: 0,
                        output_tokens: 500_000,
                    },
                ),
            ]),
            roles: HashMap::new(),
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
    fn estimate_usage_cost_unknown_model() {
        let usage = OperationTokenUsage {
            input_tokens: 100,
            cache_read_input_tokens: 0,
            output_tokens: 50,
            model: "unknown-model-v99".to_string(),
            models: HashMap::from([(
                "unknown-model-v99".to_string(),
                ModelTokenUsage {
                    input_tokens: 100,
                    cache_read_input_tokens: 0,
                    output_tokens: 50,
                },
            )]),
            roles: HashMap::new(),
        };

        let (total, breakdown, unpriced) = estimate_usage_cost(&usage);
        assert!(total.is_none());
        assert!(breakdown.is_empty());
        assert_eq!(unpriced, vec!["unknown-model-v99"]);
    }

    #[test]
    fn estimate_usage_cost_empty() {
        let usage = OperationTokenUsage::default();
        let (total, breakdown, unpriced) = estimate_usage_cost(&usage);
        assert!(total.is_none());
        assert!(breakdown.is_empty());
        assert!(unpriced.is_empty());
    }

    #[test]
    fn token_usage_key_basic() {
        assert_eq!(
            super::token_usage_key("op-abc-123"),
            "ares:op:op-abc-123:token_usage"
        );
    }

    #[test]
    fn blue_token_usage_key_format() {
        assert_eq!(
            blue_token_usage_key("inv-xyz-456"),
            "ares:blue:inv:inv-xyz-456:token_usage"
        );
    }

    #[test]
    fn lookup_model_cost_exact_match() {
        let result = lookup_model_cost("gpt-4o");
        let (input, _cached, output) = result.expect("gpt-4o should have known cost");
        assert!((input - 2.50).abs() < 0.001);
        assert!((output - 10.0).abs() < 0.001);
    }

    #[test]
    fn lookup_model_cost_case_insensitive() {
        // Model names are lowercased before lookup
        let result = lookup_model_cost("GPT-4O");
        assert!(result.is_some());
    }

    #[test]
    fn lookup_model_cost_unknown_returns_none() {
        let result = lookup_model_cost("totally-unknown-model-xyz");
        assert!(result.is_none());
    }

    #[test]
    fn model_field_roundtrip_simple() {
        let field = model_field("gpt-4o", "input_tokens");
        let (model, token_type) = parse_model_field(&field).unwrap();
        assert_eq!(model, "gpt-4o");
        assert_eq!(token_type, "input_tokens");
    }

    #[test]
    fn parse_model_field_invalid_prefix() {
        assert!(parse_model_field("something_else").is_none());
        assert!(parse_model_field("").is_none());
    }

    #[test]
    fn estimate_usage_cost_breakdown_total_tokens() {
        let usage = OperationTokenUsage {
            input_tokens: 500_000,
            cache_read_input_tokens: 0,
            output_tokens: 500_000,
            model: "gpt-4o".to_string(),
            models: HashMap::from([(
                "gpt-4o".to_string(),
                ModelTokenUsage {
                    input_tokens: 500_000,
                    cache_read_input_tokens: 0,
                    output_tokens: 500_000,
                },
            )]),
            roles: HashMap::new(),
        };
        let (_, breakdown, _) = estimate_usage_cost(&usage);
        assert_eq!(breakdown[0].total_tokens, 1_000_000);
        assert_eq!(breakdown[0].input_tokens, 500_000);
        assert_eq!(breakdown[0].output_tokens, 500_000);
    }

    #[test]
    fn token_usage_default() {
        let t = TokenUsage::default();
        assert_eq!(t.input_tokens, 0);
        assert_eq!(t.output_tokens, 0);
        assert_eq!(t.total_tokens, 0);
        assert!(t.model.is_none());
    }

    #[test]
    fn token_usage_serde_roundtrip() {
        let t = TokenUsage {
            input_tokens: 100,
            output_tokens: 50,
            total_tokens: 150,
            cache_read_input_tokens: 0,
            model: Some("gpt-4.1".to_string()),
        };
        let json = serde_json::to_string(&t).unwrap();
        let deserialized: TokenUsage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.input_tokens, 100);
        assert_eq!(deserialized.output_tokens, 50);
        assert_eq!(deserialized.total_tokens, 150);
        assert_eq!(deserialized.model, Some("gpt-4.1".to_string()));
    }

    #[test]
    fn token_usage_serde_skips_none_model() {
        let t = TokenUsage {
            input_tokens: 10,
            output_tokens: 5,
            total_tokens: 15,
            cache_read_input_tokens: 0,
            model: None,
        };
        let json = serde_json::to_string(&t).unwrap();
        assert!(!json.contains("model"));
    }

    #[test]
    fn token_usage_deserialize_missing_model() {
        let json = r#"{"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}"#;
        let t: TokenUsage = serde_json::from_str(json).unwrap();
        assert!(t.model.is_none());
    }

    #[test]
    fn operation_token_usage_default() {
        let o = OperationTokenUsage::default();
        assert_eq!(o.input_tokens, 0);
        assert_eq!(o.output_tokens, 0);
        assert!(o.model.is_empty());
        assert!(o.models.is_empty());
    }

    #[test]
    fn model_token_usage_default() {
        let m = ModelTokenUsage::default();
        assert_eq!(m.input_tokens, 0);
        assert_eq!(m.output_tokens, 0);
    }

    #[test]
    fn lookup_model_cost_all_known_models() {
        // Verify every model in the pricing table can be looked up
        let known_models = [
            "gpt-4.1",
            "gpt-4.1-mini",
            "gpt-4.1-nano",
            "gpt-4o",
            "gpt-4o-mini",
            "gpt-4-turbo",
            "gpt-5",
            "gpt-5.2",
            "gpt-5-mini",
            "openai/gpt-4.1",
            "openai/gpt-4.1-mini",
            "openai/gpt-4o",
            "gemini/gemini-2.5-pro",
            "gemini/gemini-2.5-flash",
        ];
        for model in known_models {
            assert!(
                lookup_model_cost(model).is_some(),
                "Expected pricing for {model}"
            );
        }
    }

    #[test]
    fn lookup_model_cost_fuzzy_substring_match() {
        // A model name that contains a known name as substring
        let result = lookup_model_cost("azure/gpt-4o-2024-deployment");
        assert!(
            result.is_some(),
            "Expected fuzzy match for gpt-4o substring"
        );
    }

    #[test]
    fn lookup_model_cost_returns_correct_rates() {
        // gpt-4.1: $2.00/M input, $8.00/M output
        let (input, _cached, output) = lookup_model_cost("gpt-4.1").unwrap();
        assert!((input - 2.0).abs() < 0.001);
        assert!((output - 8.0).abs() < 0.001);

        // gpt-4.1-nano: $0.10/M input, $0.40/M output
        let (input, _cached, output) = lookup_model_cost("gpt-4.1-nano").unwrap();
        assert!((input - 0.10).abs() < 0.001);
        assert!((output - 0.40).abs() < 0.001);
    }

    #[test]
    fn model_field_empty_model_name() {
        let field = model_field("", "input_tokens");
        let (model, tt) = parse_model_field(&field).unwrap();
        assert!(model.is_empty());
        assert_eq!(tt, "input_tokens");
    }

    #[test]
    fn model_field_with_colons_in_name() {
        // Model names with colons should survive base64 encoding
        let name = "provider:model:variant";
        let field = model_field(name, "output_tokens");
        let (decoded, tt) = parse_model_field(&field).unwrap();
        assert_eq!(decoded, name);
        assert_eq!(tt, "output_tokens");
    }

    #[test]
    fn parse_model_field_malformed_base64() {
        // Valid prefix but invalid base64 content
        let result = parse_model_field("model:!!!invalid!!!:input_tokens");
        assert!(result.is_none());
    }

    #[test]
    fn estimate_usage_cost_mixed_models() {
        let usage = OperationTokenUsage {
            input_tokens: 2_000_000,
            cache_read_input_tokens: 0,
            output_tokens: 1_000_000,
            model: "gpt-4o".to_string(),
            models: HashMap::from([
                (
                    "gpt-4o".to_string(),
                    ModelTokenUsage {
                        input_tokens: 1_000_000,
                        cache_read_input_tokens: 0,
                        output_tokens: 500_000,
                    },
                ),
                (
                    "my-custom-model-v1".to_string(),
                    ModelTokenUsage {
                        input_tokens: 1_000_000,
                        cache_read_input_tokens: 0,
                        output_tokens: 500_000,
                    },
                ),
            ]),
            roles: HashMap::new(),
        };
        let (total, breakdown, unpriced) = estimate_usage_cost(&usage);
        assert!(total.is_some());
        assert_eq!(breakdown.len(), 1); // Only gpt-4o is priced
        assert_eq!(unpriced.len(), 1);
        assert_eq!(unpriced[0], "my-custom-model-v1");
    }

    #[test]
    fn estimate_usage_cost_breakdown_sorted_by_name() {
        let usage = OperationTokenUsage {
            input_tokens: 2_000_000,
            cache_read_input_tokens: 0,
            output_tokens: 1_000_000,
            model: "gpt-4o".to_string(),
            models: HashMap::from([
                (
                    "gpt-4o".to_string(),
                    ModelTokenUsage {
                        input_tokens: 500_000,
                        cache_read_input_tokens: 0,
                        output_tokens: 250_000,
                    },
                ),
                (
                    "gpt-4.1-mini".to_string(),
                    ModelTokenUsage {
                        input_tokens: 500_000,
                        cache_read_input_tokens: 0,
                        output_tokens: 250_000,
                    },
                ),
            ]),
            roles: HashMap::new(),
        };
        let (_, breakdown, _) = estimate_usage_cost(&usage);
        assert_eq!(breakdown.len(), 2);
        // Sorted alphabetically: gpt-4.1-mini before gpt-4o
        assert_eq!(breakdown[0].model, "gpt-4.1-mini");
        assert_eq!(breakdown[1].model, "gpt-4o");
    }

    #[test]
    fn token_usage_key_format_various() {
        assert_eq!(token_usage_key("op-123"), "ares:op:op-123:token_usage");
        assert_eq!(token_usage_key(""), "ares:op::token_usage");
    }

    #[test]
    fn blue_token_usage_key_format_various() {
        assert_eq!(
            blue_token_usage_key("inv-abc"),
            "ares:blue:inv:inv-abc:token_usage"
        );
        assert_eq!(blue_token_usage_key(""), "ares:blue:inv::token_usage");
    }

    #[test]
    fn model_cost_breakdown_serialize() {
        let b = ModelCostBreakdown {
            model: "gpt-4.1".to_string(),
            input_tokens: 1000,
            cache_read_input_tokens: 0,
            output_tokens: 500,
            total_tokens: 1500,
            cost: 0.006,
        };
        let json = serde_json::to_value(&b).unwrap();
        assert_eq!(json["model"], "gpt-4.1");
        assert_eq!(json["total_tokens"], 1500);
        assert!((json["cost"].as_f64().unwrap() - 0.006).abs() < 0.0001);
    }

    #[test]
    fn operation_token_usage_serialize() {
        let usage = OperationTokenUsage {
            input_tokens: 10000,
            cache_read_input_tokens: 0,
            output_tokens: 5000,
            model: "gpt-4o".to_string(),
            models: HashMap::from([(
                "gpt-4o".to_string(),
                ModelTokenUsage {
                    input_tokens: 10000,
                    cache_read_input_tokens: 0,
                    output_tokens: 5000,
                },
            )]),
            roles: HashMap::new(),
        };
        let json = serde_json::to_value(&usage).unwrap();
        assert_eq!(json["input_tokens"], 10000);
        assert_eq!(json["output_tokens"], 5000);
        assert_eq!(json["model"], "gpt-4o");
        assert!(json["models"]["gpt-4o"].is_object());
    }

    #[test]
    fn estimate_usage_cost_zero_tokens_known_model() {
        let usage = OperationTokenUsage {
            input_tokens: 0,
            cache_read_input_tokens: 0,
            output_tokens: 0,
            model: "gpt-4o".to_string(),
            models: HashMap::from([(
                "gpt-4o".to_string(),
                ModelTokenUsage {
                    input_tokens: 0,
                    cache_read_input_tokens: 0,
                    output_tokens: 0,
                },
            )]),
            roles: HashMap::new(),
        };
        let (total, breakdown, unpriced) = estimate_usage_cost(&usage);
        assert_eq!(total.expect("total should be set"), 0.0);
        assert_eq!(breakdown.len(), 1);
        assert!(unpriced.is_empty());
    }

    #[test]
    fn blue_token_usage_key_with_dashes() {
        assert_eq!(
            blue_token_usage_key("inv-123"),
            "ares:blue:inv:inv-123:token_usage"
        );
    }

    #[test]
    fn estimate_usage_cost_empty_models() {
        let usage = OperationTokenUsage {
            input_tokens: 100,
            cache_read_input_tokens: 0,
            output_tokens: 50,
            model: "gpt-4o".to_string(),
            models: HashMap::new(),
            roles: HashMap::new(),
        };
        let (total, breakdown, unpriced) = estimate_usage_cost(&usage);
        assert!(total.is_none());
        assert!(breakdown.is_empty());
        assert!(unpriced.is_empty());
    }

    #[test]
    fn estimate_usage_cost_all_unpriced() {
        let usage = OperationTokenUsage {
            input_tokens: 1000,
            cache_read_input_tokens: 0,
            output_tokens: 500,
            model: "unknown".to_string(),
            models: HashMap::from([(
                "unknown-model".to_string(),
                ModelTokenUsage {
                    input_tokens: 1000,
                    cache_read_input_tokens: 0,
                    output_tokens: 500,
                },
            )]),
            roles: HashMap::new(),
        };
        let (total, breakdown, unpriced) = estimate_usage_cost(&usage);
        assert!(total.is_none());
        assert!(breakdown.is_empty());
        assert_eq!(unpriced.len(), 1);
    }

    #[test]
    fn estimate_usage_cost_single_priced_model() {
        let usage = OperationTokenUsage {
            input_tokens: 1_000_000,
            cache_read_input_tokens: 0,
            output_tokens: 500_000,
            model: "gpt-4o".to_string(),
            models: HashMap::from([(
                "gpt-4o".to_string(),
                ModelTokenUsage {
                    input_tokens: 1_000_000,
                    cache_read_input_tokens: 0,
                    output_tokens: 500_000,
                },
            )]),
            roles: HashMap::new(),
        };
        let (total, breakdown, unpriced) = estimate_usage_cost(&usage);
        let cost = total.expect("total should be set");
        // gpt-4o: 2.50/M input + 10.0/M output
        // 1M * 2.50/1M + 0.5M * 10.0/1M = 2.50 + 5.0 = 7.50
        assert!((cost - 7.50).abs() < 0.01);
        assert_eq!(breakdown.len(), 1);
        assert!(unpriced.is_empty());
    }

    #[test]
    fn lookup_model_cost_prefixed_openai() {
        let result = lookup_model_cost("openai/gpt-4o-mini");
        let (input, _cached, output) = result.expect("gpt-4o-mini should have known cost");
        assert!((input - 0.15).abs() < 0.001);
        assert!((output - 0.60).abs() < 0.001);
    }

    #[test]
    fn lookup_model_cost_claude_opus() {
        let result = lookup_model_cost("claude-opus-4-20250514");
        let (input, _cached, output) = result.expect("claude-opus should have known cost");
        assert!((input - 15.0).abs() < 0.001);
        assert!((output - 75.0).abs() < 0.001);
    }

    #[test]
    fn lookup_model_cost_haiku() {
        let result = lookup_model_cost("claude-haiku-3-5-20241022");
        let (input, _cached, output) = result.expect("claude-haiku should have known cost");
        assert!((input - 0.80).abs() < 0.001);
        assert!((output - 4.0).abs() < 0.001);
    }
}
