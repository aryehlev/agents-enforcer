//! Per-model token pricing.
//!
//! Pricing changes often; this module centralizes the table so
//! updates are a single-file concern. Values are **USD per 1 million
//! tokens** to match every major provider's public price list and
//! so the math is obvious — dividing `tokens * price / 1_000_000`
//! gives you dollars.
//!
//! When a model isn't in the table the proxy returns 402 Payment
//! Required rather than silently letting a priceless call through:
//! an un-priced model would bypass the daily budget.
//!
//! Update this table by hand when provider pricing moves. A full
//! dynamic pricing feed (ConfigMap, remote JSON) is tracked as a
//! follow-up; hardcoding keeps the proxy deterministic and makes
//! tests stable.

/// Price of one model's input and output tokens in USD per million.
#[derive(Debug, Clone, Copy)]
pub struct Pricing {
    pub input_per_million: f64,
    pub output_per_million: f64,
}

impl Pricing {
    /// Dollars for a given token count on the input side.
    pub fn input_cost(&self, tokens: u64) -> f64 {
        (tokens as f64) * self.input_per_million / 1_000_000.0
    }

    /// Dollars for a given token count on the output side.
    pub fn output_cost(&self, tokens: u64) -> f64 {
        (tokens as f64) * self.output_per_million / 1_000_000.0
    }
}

/// Look up pricing by model name. Matching is case-insensitive;
/// returns `None` for unknown models.
pub fn price_for(model: &str) -> Option<Pricing> {
    let needle = model.trim().to_ascii_lowercase();
    for (k, v) in TABLE {
        if *k == needle {
            return Some(*v);
        }
    }
    None
}

// Prefix-match is deliberately not supported. Providers have shipped
// tokenizer / pricing changes under the same short name before, and
// we'd rather refuse to enforce than enforce the wrong price.
const TABLE: &[(&str, Pricing)] = &[
    // Anthropic, April 2026 public pricing (per 1M tokens).
    (
        "claude-opus-4.7",
        Pricing {
            input_per_million: 15.0,
            output_per_million: 75.0,
        },
    ),
    (
        "claude-sonnet-4.6",
        Pricing {
            input_per_million: 3.0,
            output_per_million: 15.0,
        },
    ),
    (
        "claude-haiku-4.5",
        Pricing {
            input_per_million: 0.8,
            output_per_million: 4.0,
        },
    ),
    // OpenAI — ball-park April 2026 for reproducibility; operators
    // who care about penny-accurate cost should pin the actual
    // numbers for their contract.
    (
        "gpt-4o",
        Pricing {
            input_per_million: 2.5,
            output_per_million: 10.0,
        },
    ),
    (
        "gpt-4o-mini",
        Pricing {
            input_per_million: 0.15,
            output_per_million: 0.6,
        },
    ),
    (
        "gpt-4-turbo",
        Pricing {
            input_per_million: 10.0,
            output_per_million: 30.0,
        },
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_insensitive_lookup() {
        assert!(price_for("GPT-4o").is_some());
        assert!(price_for("gpt-4o").is_some());
        assert!(price_for("GpT-4O").is_some());
    }

    #[test]
    fn unknown_model_returns_none() {
        assert!(price_for("made-up").is_none());
    }

    #[test]
    fn cost_math_is_linear_in_tokens() {
        let p = price_for("gpt-4o-mini").unwrap();
        assert!((p.input_cost(1_000_000) - p.input_per_million).abs() < 1e-9);
        assert!((p.output_cost(500_000) - p.output_per_million / 2.0).abs() < 1e-9);
    }

    #[test]
    fn input_and_output_cost_can_differ() {
        let p = price_for("claude-sonnet-4.6").unwrap();
        assert!(p.output_per_million > p.input_per_million);
    }
}
