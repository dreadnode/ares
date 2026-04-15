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
                    "claude-sonnet-4-20250514",
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
