//! Model cost estimation for LLM token usage.

use std::collections::HashMap;

/// Model cost rates per million tokens.
#[derive(Debug, Clone)]
pub struct ModelCost {
    pub input_per_million: f64,
    pub output_per_million: f64,
}

/// Estimate cost in USD for token usage.
pub fn estimate_cost(model: &str, prompt_tokens: u64, completion_tokens: u64) -> f64 {
    static MODEL_COSTS: std::sync::LazyLock<HashMap<&'static str, ModelCost>> =
        std::sync::LazyLock::new(|| {
            HashMap::from([
                (
                    "claude-sonnet-4-6",
                    ModelCost {
                        input_per_million: 3.0,
                        output_per_million: 15.0,
                    },
                ),
                (
                    "claude-opus-4-20250514",
                    ModelCost {
                        input_per_million: 15.0,
                        output_per_million: 75.0,
                    },
                ),
                (
                    "gpt-4o",
                    ModelCost {
                        input_per_million: 2.5,
                        output_per_million: 10.0,
                    },
                ),
                (
                    "gpt-4-turbo",
                    ModelCost {
                        input_per_million: 10.0,
                        output_per_million: 30.0,
                    },
                ),
            ])
        });

    let default_cost = ModelCost {
        input_per_million: 5.0,
        output_per_million: 15.0,
    };
    let costs = MODEL_COSTS.get(model).unwrap_or(&default_cost);

    (prompt_tokens as f64 * costs.input_per_million
        + completion_tokens as f64 * costs.output_per_million)
        / 1_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_cost_known_model_claude_sonnet() {
        let cost = estimate_cost("claude-sonnet-4-6", 1_000_000, 0);
        assert!((cost - 3.0).abs() < 1e-9);
    }

    #[test]
    fn estimate_cost_known_model_output_tokens() {
        let cost = estimate_cost("claude-sonnet-4-6", 0, 1_000_000);
        assert!((cost - 15.0).abs() < 1e-9);
    }

    #[test]
    fn estimate_cost_known_model_mixed() {
        let cost = estimate_cost("gpt-4o", 500_000, 200_000);
        let expected = (500_000.0 * 2.5 + 200_000.0 * 10.0) / 1_000_000.0;
        assert!((cost - expected).abs() < 1e-9);
    }

    #[test]
    fn estimate_cost_unknown_model_uses_default() {
        let cost = estimate_cost("unknown-model-xyz", 1_000_000, 0);
        assert!((cost - 5.0).abs() < 1e-9);
    }

    #[test]
    fn estimate_cost_zero_tokens() {
        let cost = estimate_cost("gpt-4o", 0, 0);
        assert_eq!(cost, 0.0);
    }

    #[test]
    fn estimate_cost_claude_opus() {
        let cost = estimate_cost("claude-opus-4-20250514", 1_000_000, 1_000_000);
        assert!((cost - 90.0).abs() < 1e-9);
    }

    #[test]
    fn estimate_cost_gpt4_turbo() {
        let cost = estimate_cost("gpt-4-turbo", 100_000, 50_000);
        let expected = (100_000.0 * 10.0 + 50_000.0 * 30.0) / 1_000_000.0;
        assert!((cost - expected).abs() < 1e-9);
    }
}
