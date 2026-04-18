//! Pure enforcement core. Given an incoming request's shape, a
//! capability bundle, and the daily spend accumulated so far, decide
//! whether to forward upstream or reject with a specific reason.
//!
//! Pure so every rule is table-tested; the HTTP handler is a thin
//! wrapper that extracts these inputs from `axum` types and pushes
//! the decision back out as a status code + JSON error body.

use agent_gateway_enforcer_controller::CapabilityBundle;

use crate::pricing::price_for;

/// Reason the proxy rejected a request. Maps 1:1 to
/// `enforcer_llm_rejections_total{reason=...}` labels — keep stable.
#[derive(Debug, Clone, PartialEq)]
pub enum RejectReason {
    /// No capability matched the request's caller identity.
    NoCapability,
    /// `model` not in the capability's allowedModels.
    ModelNotAllowed { model: String },
    /// The request carries tool definitions at all and the
    /// capability's allowedTools is empty.
    ToolsDisabled,
    /// The request carries a tool the capability doesn't list.
    ToolNotAllowed { tool: String },
    /// Model isn't in our pricing table; we can't cost-account it.
    UnknownModel { model: String },
    /// Daily budget reached.
    BudgetExceeded { spent: f64, budget: f64 },
    /// max_output_tokens override > bundle's cap.
    OutputTokenCapExceeded { requested: u32, cap: u32 },
}

impl RejectReason {
    /// Short stable label used in metrics.
    pub fn metric_label(&self) -> &'static str {
        match self {
            Self::NoCapability => "no_capability",
            Self::ModelNotAllowed { .. } => "model_not_allowed",
            Self::ToolsDisabled => "tools_disabled",
            Self::ToolNotAllowed { .. } => "tool_not_allowed",
            Self::UnknownModel { .. } => "unknown_model",
            Self::BudgetExceeded { .. } => "budget_exceeded",
            Self::OutputTokenCapExceeded { .. } => "output_cap",
        }
    }

    /// HTTP status code the handler should return. 403 for policy
    /// rejects, 402 for money, 400 for malformed.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::NoCapability
            | Self::ModelNotAllowed { .. }
            | Self::ToolsDisabled
            | Self::ToolNotAllowed { .. }
            | Self::OutputTokenCapExceeded { .. } => 403,
            Self::UnknownModel { .. } => 400,
            Self::BudgetExceeded { .. } => 402,
        }
    }

    /// Human-readable message for the rejection's HTTP body.
    pub fn user_message(&self) -> String {
        match self {
            Self::NoCapability => "no AgentCapability matched this caller".into(),
            Self::ModelNotAllowed { model } => {
                format!("model '{}' is not in this agent's allowedModels", model)
            }
            Self::ToolsDisabled => {
                "this agent is not permitted to use tools / function-calling".into()
            }
            Self::ToolNotAllowed { tool } => {
                format!("tool '{}' is not in this agent's allowedTools", tool)
            }
            Self::UnknownModel { model } => format!(
                "model '{}' has no pricing configured; refusing to forward without cost accounting",
                model
            ),
            Self::BudgetExceeded { spent, budget } => format!(
                "daily budget exhausted: spent ${:.4}, cap ${:.2}",
                spent, budget
            ),
            Self::OutputTokenCapExceeded { requested, cap } => format!(
                "max_output_tokens {} exceeds the capability cap {}",
                requested, cap
            ),
        }
    }
}

/// Minimal view of an inbound request the enforcement logic needs.
/// Extracted from the JSON body by the handler so this module has
/// no JSON dependency.
#[derive(Debug)]
pub struct RequestFacts<'a> {
    pub model: &'a str,
    /// Tool / function names present in the request. Empty slice
    /// means no tool use.
    pub tool_names: Vec<String>,
    /// The request's `max_tokens` / `max_output_tokens` override, if
    /// set.
    pub requested_max_output: Option<u32>,
    /// Estimated input tokens. The handler derives this; cheap
    /// approximations (byte count / 4) are fine — the enforcement
    /// math just needs a lower bound to decide whether the daily
    /// budget is already gone.
    pub estimated_input_tokens: u64,
}

/// Decide whether to forward. `spent_today` is the running daily
/// total *before* this request; the caller will add the actual cost
/// once upstream responds.
pub fn check(
    bundle: &CapabilityBundle,
    req: &RequestFacts<'_>,
    spent_today: f64,
) -> Result<(), RejectReason> {
    // Model allowlist — empty list means allow nothing.
    let model_lc = req.model.trim().to_ascii_lowercase();
    if !bundle.allowed_models.iter().any(|m| m == &model_lc) {
        return Err(RejectReason::ModelNotAllowed {
            model: req.model.to_string(),
        });
    }

    // Tool use — zero tools listed on the capability = tools off.
    if !req.tool_names.is_empty() {
        if bundle.allowed_tools.is_empty() {
            return Err(RejectReason::ToolsDisabled);
        }
        for t in &req.tool_names {
            if !bundle.allowed_tools.iter().any(|a| a == t) {
                return Err(RejectReason::ToolNotAllowed { tool: t.clone() });
            }
        }
    }

    // Output cap — reject rather than silently clamping. A silent
    // clamp mutates what the caller asked for; a 403 forces the
    // caller to adjust.
    if let (Some(cap), Some(req_cap)) = (bundle.max_output_tokens, req.requested_max_output) {
        if req_cap > cap {
            return Err(RejectReason::OutputTokenCapExceeded {
                requested: req_cap,
                cap,
            });
        }
    }

    // Cost accounting. `max_daily_spend_usd == 0.0` is the documented
    // "disable cost enforcement" escape hatch; see the CR docs.
    if bundle.max_daily_spend_usd > 0.0 {
        let price = price_for(req.model).ok_or_else(|| RejectReason::UnknownModel {
            model: req.model.to_string(),
        })?;
        // Use the input estimate as a *lower bound* on what this
        // request costs. Output is unknown until upstream responds.
        let estimated_input = price.input_cost(req.estimated_input_tokens);
        if spent_today + estimated_input >= bundle.max_daily_spend_usd {
            return Err(RejectReason::BudgetExceeded {
                spent: spent_today,
                budget: bundle.max_daily_spend_usd,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle_with(models: &[&str], tools: &[&str], spend: f64) -> CapabilityBundle {
        CapabilityBundle {
            hash: "h".into(),
            allowed_models: models.iter().map(|s| s.to_ascii_lowercase()).collect(),
            allowed_tools: tools.iter().map(|s| s.to_string()).collect(),
            max_daily_spend_usd: spend,
            max_output_tokens: None,
        }
    }

    fn req<'a>(model: &'a str, tools: Vec<String>, input_tokens: u64) -> RequestFacts<'a> {
        RequestFacts {
            model,
            tool_names: tools,
            requested_max_output: None,
            estimated_input_tokens: input_tokens,
        }
    }

    #[test]
    fn happy_path_passes() {
        let b = bundle_with(&["gpt-4o"], &[], 100.0);
        check(&b, &req("gpt-4o", vec![], 1000), 0.0).unwrap();
    }

    #[test]
    fn model_not_in_list_rejected() {
        let b = bundle_with(&["gpt-4o"], &[], 100.0);
        let e = check(&b, &req("claude-opus-4.7", vec![], 1000), 0.0).unwrap_err();
        assert!(matches!(e, RejectReason::ModelNotAllowed { .. }));
    }

    #[test]
    fn model_match_is_case_insensitive() {
        let b = bundle_with(&["GPT-4o"], &[], 100.0);
        check(&b, &req("gpt-4o", vec![], 0), 0.0).unwrap();
    }

    #[test]
    fn tools_with_empty_allowlist_disables_tools() {
        let b = bundle_with(&["gpt-4o"], &[], 100.0);
        let e = check(&b, &req("gpt-4o", vec!["search".into()], 0), 0.0).unwrap_err();
        assert_eq!(e, RejectReason::ToolsDisabled);
    }

    #[test]
    fn unlisted_tool_rejected() {
        let b = bundle_with(&["gpt-4o"], &["read_file"], 100.0);
        let e = check(
            &b,
            &req("gpt-4o", vec!["send_email".into()], 0),
            0.0,
        )
        .unwrap_err();
        assert!(matches!(e, RejectReason::ToolNotAllowed { .. }));
    }

    #[test]
    fn unknown_model_rejected_when_cost_enforcement_on() {
        let b = bundle_with(&["made-up"], &[], 100.0);
        let e = check(&b, &req("made-up", vec![], 100), 0.0).unwrap_err();
        assert!(matches!(e, RejectReason::UnknownModel { .. }));
    }

    #[test]
    fn unknown_model_passes_when_cost_enforcement_off() {
        // max_daily_spend_usd == 0.0 → cost check is skipped
        // entirely, see docs on the field.
        let b = bundle_with(&["made-up"], &[], 0.0);
        check(&b, &req("made-up", vec![], 100), 0.0).unwrap();
    }

    #[test]
    fn budget_exceeded_rejects() {
        let b = bundle_with(&["gpt-4o"], &[], 0.01);
        // 10M input tokens on gpt-4o ~ $25, way over a penny.
        let e = check(&b, &req("gpt-4o", vec![], 10_000_000), 0.0).unwrap_err();
        assert!(matches!(e, RejectReason::BudgetExceeded { .. }));
    }

    #[test]
    fn budget_already_spent_rejects_even_for_tiny_request() {
        let b = bundle_with(&["gpt-4o"], &[], 1.0);
        let e = check(&b, &req("gpt-4o", vec![], 0), 1.0).unwrap_err();
        assert!(matches!(e, RejectReason::BudgetExceeded { .. }));
    }

    #[test]
    fn output_cap_rejects_higher_request() {
        let mut b = bundle_with(&["gpt-4o"], &[], 100.0);
        b.max_output_tokens = Some(512);
        let mut r = req("gpt-4o", vec![], 0);
        r.requested_max_output = Some(1024);
        let e = check(&b, &r, 0.0).unwrap_err();
        assert!(matches!(e, RejectReason::OutputTokenCapExceeded { .. }));
    }

    #[test]
    fn reject_reasons_all_have_metric_labels() {
        let reasons = [
            RejectReason::NoCapability,
            RejectReason::ModelNotAllowed { model: "x".into() },
            RejectReason::ToolsDisabled,
            RejectReason::ToolNotAllowed { tool: "x".into() },
            RejectReason::UnknownModel { model: "x".into() },
            RejectReason::BudgetExceeded {
                spent: 0.0,
                budget: 0.0,
            },
            RejectReason::OutputTokenCapExceeded {
                requested: 0,
                cap: 0,
            },
        ];
        for r in reasons {
            assert!(!r.metric_label().is_empty());
            assert!(r.http_status() >= 400 && r.http_status() < 500);
            assert!(!r.user_message().is_empty());
        }
    }
}
