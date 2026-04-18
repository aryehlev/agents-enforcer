//! Compile `AgentCapability` CRs into the flat `CapabilityBundle` the
//! LLM proxy consumes. Pure — no kube client, no I/O; drops into the
//! same reconciler pattern as `compile_policy`.
//!
//! The CR is user-facing and forgiving; the bundle is the tight
//! machine-readable shape. Bundle shape is deliberately simple
//! because the proxy re-evaluates on every request — a few dozen
//! string comparisons is not a hot path worth optimizing.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crds::AgentCapabilitySpec;

/// Content-hashed bundle the LLM proxy enforces. Fields mirror
/// `AgentCapabilitySpec` 1:1; the compiler's job is normalization
/// (lowercase model names, dedupe + sort) so two semantically
/// identical CRs produce byte-identical bundles and dashboards
/// don't thrash on hash churn.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct CapabilityBundle {
    /// SHA-256 of the bundle body with hash=""; see `hash_bundle`.
    pub hash: String,
    /// Lowercased, sorted, deduplicated model names.
    pub allowed_models: Vec<String>,
    /// Sorted, deduplicated tool / function names (case preserved —
    /// OpenAI + Anthropic both match tool names exactly).
    pub allowed_tools: Vec<String>,
    /// Daily USD ceiling.
    pub max_daily_spend_usd: f64,
    /// Per-response output-token cap, if configured.
    pub max_output_tokens: Option<u32>,
}

/// Compilation errors surfaced to the user via the webhook or the
/// controller's status message.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum CapabilityCompileError {
    /// Spend ceiling is negative. `0.0` is allowed (disables cost
    /// enforcement); a negative value is almost certainly a typo
    /// that would silently open the budget.
    #[error("maxDailySpendUsd must be >= 0 (got {0})")]
    NegativeSpend(f64),
    /// NaN / ±Inf. Serde accepts them; we refuse to.
    #[error("maxDailySpendUsd is not a finite number")]
    NonFiniteSpend,
}

/// Compile a `AgentCapabilitySpec` into a [`CapabilityBundle`].
pub fn compile_capability(
    cap: &AgentCapabilitySpec,
) -> Result<CapabilityBundle, CapabilityCompileError> {
    if !cap.max_daily_spend_usd.is_finite() {
        return Err(CapabilityCompileError::NonFiniteSpend);
    }
    if cap.max_daily_spend_usd < 0.0 {
        return Err(CapabilityCompileError::NegativeSpend(cap.max_daily_spend_usd));
    }

    // Normalize models: lowercase + sort + dedupe. Model names like
    // "gpt-4o" / "GPT-4O" land in the same bucket on the wire.
    let mut models: Vec<String> = cap
        .allowed_models
        .iter()
        .map(|m| m.trim().to_ascii_lowercase())
        .filter(|m| !m.is_empty())
        .collect();
    models.sort();
    models.dedup();

    let mut tools: Vec<String> = cap
        .allowed_tools
        .iter()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    tools.sort();
    tools.dedup();

    let mut bundle = CapabilityBundle {
        hash: String::new(),
        allowed_models: models,
        allowed_tools: tools,
        max_daily_spend_usd: cap.max_daily_spend_usd,
        max_output_tokens: cap.max_output_tokens,
    };
    bundle.hash = hash_bundle(&bundle);
    Ok(bundle)
}

fn hash_bundle(b: &CapabilityBundle) -> String {
    let mut canon = b.clone();
    canon.hash = String::new();
    let bytes = serde_json::to_vec(&canon).expect("serialize");
    hex::encode(Sha256::digest(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty() -> AgentCapabilitySpec {
        AgentCapabilitySpec {
            pod_selector: crate::crds::LabelSelector::default(),
            allowed_models: vec![],
            allowed_tools: vec![],
            max_daily_spend_usd: 0.0,
            max_output_tokens: None,
        }
    }

    #[test]
    fn empty_compiles_but_denies_everything() {
        let b = compile_capability(&empty()).unwrap();
        assert!(b.allowed_models.is_empty());
        assert!(b.allowed_tools.is_empty());
        assert_eq!(b.max_daily_spend_usd, 0.0);
        assert!(!b.hash.is_empty(), "hash always populated");
    }

    #[test]
    fn models_are_lowercased_sorted_and_deduped() {
        let mut cap = empty();
        cap.allowed_models = vec!["GPT-4o".into(), "gpt-4o".into(), "claude-sonnet-4.6".into()];
        let b = compile_capability(&cap).unwrap();
        assert_eq!(
            b.allowed_models,
            vec!["claude-sonnet-4.6".to_string(), "gpt-4o".to_string()]
        );
    }

    #[test]
    fn tools_are_sorted_deduped_but_case_preserved() {
        let mut cap = empty();
        cap.allowed_tools = vec!["send_email".into(), "read_file".into(), "send_email".into()];
        let b = compile_capability(&cap).unwrap();
        assert_eq!(
            b.allowed_tools,
            vec!["read_file".to_string(), "send_email".to_string()]
        );
    }

    #[test]
    fn hash_is_deterministic() {
        let mut a = empty();
        a.allowed_models = vec!["a".into()];
        let mut b = empty();
        b.allowed_models = vec!["A".into()];
        let ba = compile_capability(&a).unwrap();
        let bb = compile_capability(&b).unwrap();
        assert_eq!(ba.hash, bb.hash, "case normalization must flow through hash");
    }

    #[test]
    fn negative_spend_is_rejected() {
        let mut cap = empty();
        cap.max_daily_spend_usd = -1.0;
        assert!(matches!(
            compile_capability(&cap),
            Err(CapabilityCompileError::NegativeSpend(_))
        ));
    }

    #[test]
    fn nan_spend_is_rejected() {
        let mut cap = empty();
        cap.max_daily_spend_usd = f64::NAN;
        assert!(matches!(
            compile_capability(&cap),
            Err(CapabilityCompileError::NonFiniteSpend)
        ));
    }
}
