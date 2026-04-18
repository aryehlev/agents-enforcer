//! Per-model token pricing, loaded from a YAML file at runtime.
//!
//! Pricing drifts all the time — providers push a new model every
//! few weeks, a tier every few months, an entirely new pricing axis
//! occasionally (input caching, batch discounts, image tokens).
//! Baking that into the binary turns every price change into a
//! release; this module hot-loads a YAML file shipped separately
//! (typically a Kubernetes ConfigMap) and supports SIGHUP reloads
//! without dropping in-flight requests.
//!
//! The YAML shape is deliberately flat: one entry per model, with
//! USD-per-million-tokens for input and output. It's a straight
//! superset of what the hardcoded table used to be, so any committed
//! history comparing both sides round-trips.
//!
//! ```yaml
//! # pricing.yaml
//! models:
//!   - name: gpt-4o
//!     inputPerMillion: 2.5
//!     outputPerMillion: 10.0
//!   - name: claude-sonnet-4.6
//!     inputPerMillion: 3.0
//!     outputPerMillion: 15.0
//! ```
//!
//! Unknown models continue to be rejected with 400 so that operators
//! can't silently bypass the budget by mistyping a model name.

use std::collections::HashMap;
use std::path::Path;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// USD per million tokens — the canonical unit providers publish.
/// Multiplying `tokens * per_million / 1_000_000` yields dollars;
/// kept in f64 because the numbers involved are small and exact
/// dollar arithmetic isn't a goal (cost displays, not billing).
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Pricing {
    pub input_per_million: f64,
    pub output_per_million: f64,
}

impl Pricing {
    /// Dollars for `tokens` on the input side.
    pub fn input_cost(&self, tokens: u64) -> f64 {
        (tokens as f64) * self.input_per_million / 1_000_000.0
    }
    /// Dollars for `tokens` on the output side.
    pub fn output_cost(&self, tokens: u64) -> f64 {
        (tokens as f64) * self.output_per_million / 1_000_000.0
    }
}

/// File-on-disk schema. One source of truth the whole fleet shares.
#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct PricingFile {
    models: Vec<ModelEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ModelEntry {
    name: String,
    input_per_million: f64,
    output_per_million: f64,
}

/// Thread-safe pricing lookup. Cheap to clone (it's an Arc'd RwLock
/// of a hashmap). Lookups are case-insensitive.
#[derive(Debug, Default)]
pub struct PricingTable {
    // The RwLock is outside the HashMap so `reload` swaps the whole
    // map in a single pointer assignment — lookups can never see a
    // half-applied update.
    inner: RwLock<HashMap<String, Pricing>>,
}

impl PricingTable {
    /// Build an empty table. Use `from_yaml_str` / `load_from_file`
    /// / `reload_from_file` to populate.
    pub fn new() -> Self {
        Self::default()
    }

    /// Deserialize a YAML blob in the shape documented at the top
    /// of this module.
    pub fn from_yaml_str(yaml: &str) -> anyhow::Result<Self> {
        let table = Self::new();
        table.replace_from_yaml_str(yaml)?;
        Ok(table)
    }

    /// Load from a file path. Errors only on I/O or parse — unknown
    /// fields are currently tolerated by serde_yaml by default so
    /// future pricing axes (cached input, image tokens) can ship in
    /// the file before the proxy knows what to do with them.
    pub fn load_from_file(path: &Path) -> anyhow::Result<Self> {
        let table = Self::new();
        table.reload_from_file(path)?;
        Ok(table)
    }

    /// Replace the table's contents from a YAML file on disk. Safe
    /// to call while the proxy is serving — readers take no lock
    /// beyond a RwLock read. SIGHUP reloads go through this.
    pub fn reload_from_file(&self, path: &Path) -> anyhow::Result<()> {
        let yaml = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read {}: {}", path.display(), e))?;
        self.replace_from_yaml_str(&yaml)
    }

    /// Replace the table's contents from a YAML blob.
    pub fn replace_from_yaml_str(&self, yaml: &str) -> anyhow::Result<()> {
        let parsed: PricingFile = serde_yaml::from_str(yaml)
            .map_err(|e| anyhow::anyhow!("parse pricing yaml: {}", e))?;
        let mut map = HashMap::with_capacity(parsed.models.len());
        for m in parsed.models {
            if !m.input_per_million.is_finite() || !m.output_per_million.is_finite() {
                anyhow::bail!("model '{}': non-finite price", m.name);
            }
            if m.input_per_million < 0.0 || m.output_per_million < 0.0 {
                anyhow::bail!("model '{}': negative price", m.name);
            }
            // Collisions overwrite — later entries win. Lets
            // operators override a shipped default by appending.
            map.insert(
                m.name.trim().to_ascii_lowercase(),
                Pricing {
                    input_per_million: m.input_per_million,
                    output_per_million: m.output_per_million,
                },
            );
        }
        *self.inner.write() = map;
        Ok(())
    }

    /// Case-insensitive lookup. `None` means "model unknown, refuse
    /// to forward without cost accounting" — the handler turns this
    /// into a 400 rather than silently passing.
    pub fn price_for(&self, model: &str) -> Option<Pricing> {
        let needle = model.trim().to_ascii_lowercase();
        self.inner.read().get(&needle).copied()
    }

    /// How many models are loaded. Useful for a `/readyz` probe.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Whether any pricing is configured. Proxy should refuse to
    /// start with cost enforcement on and zero prices loaded — the
    /// handler delegates that to the AppState wiring.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
models:
  - name: gpt-4o
    inputPerMillion: 2.5
    outputPerMillion: 10.0
  - name: claude-sonnet-4.6
    inputPerMillion: 3.0
    outputPerMillion: 15.0
"#;

    #[test]
    fn loads_from_yaml() {
        let t = PricingTable::from_yaml_str(SAMPLE).unwrap();
        assert_eq!(t.len(), 2);
        assert_eq!(t.price_for("gpt-4o").unwrap().input_per_million, 2.5);
    }

    #[test]
    fn case_insensitive_lookup() {
        let t = PricingTable::from_yaml_str(SAMPLE).unwrap();
        assert!(t.price_for("GPT-4o").is_some());
        assert!(t.price_for("gpt-4O").is_some());
    }

    #[test]
    fn unknown_model_returns_none() {
        let t = PricingTable::from_yaml_str(SAMPLE).unwrap();
        assert!(t.price_for("made-up").is_none());
    }

    #[test]
    fn reload_replaces_contents_atomically() {
        let t = PricingTable::from_yaml_str(SAMPLE).unwrap();
        assert!(t.price_for("gpt-4o").is_some());
        // Reload with a narrower set: old model disappears.
        t.replace_from_yaml_str(
            r#"
models:
  - { name: other-model, inputPerMillion: 1.0, outputPerMillion: 2.0 }
"#,
        )
        .unwrap();
        assert!(t.price_for("gpt-4o").is_none());
        assert!(t.price_for("other-model").is_some());
    }

    #[test]
    fn rejects_negative_prices() {
        let err = PricingTable::from_yaml_str(
            r#"
models:
  - { name: gpt-4o, inputPerMillion: -1.0, outputPerMillion: 1.0 }
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("negative"));
    }

    #[test]
    fn rejects_non_finite_prices() {
        // NaN serialized as a string fails YAML typing, so use Inf
        // which does round-trip.
        let err = PricingTable::from_yaml_str(
            r#"
models:
  - { name: gpt-4o, inputPerMillion: .inf, outputPerMillion: 1.0 }
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("non-finite"));
    }

    #[test]
    fn cost_math_is_linear_in_tokens() {
        let t = PricingTable::from_yaml_str(SAMPLE).unwrap();
        let p = t.price_for("gpt-4o").unwrap();
        assert!((p.input_cost(1_000_000) - 2.5).abs() < 1e-9);
        assert!((p.output_cost(500_000) - 5.0).abs() < 1e-9);
    }

    #[test]
    fn duplicate_entries_keep_last_value() {
        // Operators stack a base YAML with an override YAML via
        // multiple mounts; document the win-last semantic here.
        let t = PricingTable::from_yaml_str(
            r#"
models:
  - { name: gpt-4o, inputPerMillion: 1.0, outputPerMillion: 2.0 }
  - { name: gpt-4o, inputPerMillion: 9.9, outputPerMillion: 9.9 }
"#,
        )
        .unwrap();
        assert_eq!(t.price_for("gpt-4o").unwrap().input_per_million, 9.9);
    }

    #[test]
    fn load_from_file_reads_yaml() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("pricing.yaml");
        std::fs::write(&path, SAMPLE).unwrap();
        let t = PricingTable::load_from_file(&path).unwrap();
        assert_eq!(t.len(), 2);
    }
}
