//! Pure decision: given parsed [`LlmRequestFacts`] and the pod's
//! [`LlmCapability`], decide allow/deny + reason. Mirrors the LLM
//! proxy's `enforce::check` for parity, minus the cost-budget check
//! (eBPF-only mode doesn't see the response token usage today;
//! Phase E.3 adds an SSL_read aggregation that closes that gap).

use super::capability::LlmCapability;
use super::decoder::LlmRequestFacts;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LlmVerdict {
    Allow,
    Deny(DenyReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// Pod has no capability bundle. Conservatively deny — without
    /// a bundle we can't tell what's allowed. Operators wanting
    /// agent enrollment to be opt-in flip a flag at the consumer
    /// level, not here.
    NoCapability,
    /// Requested model is not in `allowed_models`.
    ModelNotAllowed { requested: String },
    /// At least one tool name in the request isn't in `allowed_tools`.
    ToolNotAllowed { tool: String },
    /// Requested `max_output_tokens` exceeds capability cap.
    MaxTokensExceeded { requested: u32, cap: u32 },
}

impl DenyReason {
    /// Short stable label suitable for metrics + the `detail` field
    /// of an `AgentViolation`. Matches the LLM proxy's labels so
    /// dashboards work across modes.
    pub fn label(&self) -> &'static str {
        match self {
            DenyReason::NoCapability => "no_capability",
            DenyReason::ModelNotAllowed { .. } => "model_not_allowed",
            DenyReason::ToolNotAllowed { .. } => "tool_not_allowed",
            DenyReason::MaxTokensExceeded { .. } => "max_tokens_exceeded",
        }
    }

    /// Human-readable detail for the `AgentViolation.spec.detail`.
    pub fn detail(&self, facts: &LlmRequestFacts) -> String {
        match self {
            DenyReason::NoCapability => format!("model={}", facts.model),
            DenyReason::ModelNotAllowed { requested } => {
                format!("model={}", requested)
            }
            DenyReason::ToolNotAllowed { tool } => format!("tool={}", tool),
            DenyReason::MaxTokensExceeded { requested, cap } => {
                format!("max_output_tokens={} cap={}", requested, cap)
            }
        }
    }
}

/// Decide whether `facts` is allowed under `capability`.
///
/// Order matches the proxy's: capability presence → model → tools
/// → max-tokens. First failure short-circuits so an event carries
/// one reason, not a list — operators triaging a denied request
/// want a single root cause.
pub fn decide(facts: &LlmRequestFacts, capability: Option<&LlmCapability>) -> LlmVerdict {
    let Some(cap) = capability else {
        return LlmVerdict::Deny(DenyReason::NoCapability);
    };

    // `model` is already lowercased by the decoder; capability
    // models are lowercased+sorted at load.
    if !cap.allowed_models.iter().any(|m| m == &facts.model) {
        return LlmVerdict::Deny(DenyReason::ModelNotAllowed {
            requested: facts.model.clone(),
        });
    }

    for t in &facts.tool_names {
        if !cap.allowed_tools.iter().any(|allowed| allowed == t) {
            return LlmVerdict::Deny(DenyReason::ToolNotAllowed { tool: t.clone() });
        }
    }

    if let (Some(req), Some(cap_max)) = (facts.requested_max_output, cap.max_output_tokens) {
        if req > cap_max {
            return LlmVerdict::Deny(DenyReason::MaxTokensExceeded {
                requested: req,
                cap: cap_max,
            });
        }
    }

    LlmVerdict::Allow
}

#[cfg(test)]
mod tests {
    use super::super::decoder::ProviderHint;
    use super::*;

    fn facts(model: &str) -> LlmRequestFacts {
        LlmRequestFacts {
            model: model.into(),
            tool_names: vec![],
            requested_max_output: None,
            provider: ProviderHint::OpenAi,
        }
    }

    fn cap(models: &[&str]) -> LlmCapability {
        LlmCapability {
            allowed_models: models.iter().map(|s| s.to_string()).collect(),
            allowed_tools: vec![],
            max_output_tokens: None,
        }
    }

    #[test]
    fn no_capability_denies_with_no_capability_reason() {
        // The "no bundle = deny" default is the conservative choice;
        // explicit test pins it so a future refactor can't quietly
        // flip to allow.
        let v = decide(&facts("gpt-4o"), None);
        assert_eq!(v, LlmVerdict::Deny(DenyReason::NoCapability));
    }

    #[test]
    fn allowed_model_passes() {
        let cap = cap(&["gpt-4o"]);
        assert_eq!(decide(&facts("gpt-4o"), Some(&cap)), LlmVerdict::Allow);
    }

    #[test]
    fn disallowed_model_denies_with_model_reason() {
        let cap = cap(&["claude-sonnet-4.6"]);
        let v = decide(&facts("gpt-4o"), Some(&cap));
        assert_eq!(
            v,
            LlmVerdict::Deny(DenyReason::ModelNotAllowed {
                requested: "gpt-4o".into()
            })
        );
    }

    #[test]
    fn first_disallowed_tool_short_circuits() {
        // If two tools are bad, only the first one shows up in the
        // event — operators want one root cause, not a checklist.
        let mut f = facts("gpt-4o");
        f.tool_names = vec!["allowed".into(), "bad-1".into(), "bad-2".into()];
        let mut c = cap(&["gpt-4o"]);
        c.allowed_tools = vec!["allowed".into()];
        let v = decide(&f, Some(&c));
        assert_eq!(
            v,
            LlmVerdict::Deny(DenyReason::ToolNotAllowed { tool: "bad-1".into() })
        );
    }

    #[test]
    fn all_tools_allowed_passes() {
        let mut f = facts("gpt-4o");
        f.tool_names = vec!["search".into(), "db".into()];
        let mut c = cap(&["gpt-4o"]);
        c.allowed_tools = vec!["db".into(), "search".into()];
        assert_eq!(decide(&f, Some(&c)), LlmVerdict::Allow);
    }

    #[test]
    fn max_tokens_under_cap_passes() {
        let mut f = facts("gpt-4o");
        f.requested_max_output = Some(512);
        let mut c = cap(&["gpt-4o"]);
        c.max_output_tokens = Some(1024);
        assert_eq!(decide(&f, Some(&c)), LlmVerdict::Allow);
    }

    #[test]
    fn max_tokens_at_cap_passes() {
        // Boundary check — `>` not `>=`, mirrors the proxy.
        let mut f = facts("gpt-4o");
        f.requested_max_output = Some(1024);
        let mut c = cap(&["gpt-4o"]);
        c.max_output_tokens = Some(1024);
        assert_eq!(decide(&f, Some(&c)), LlmVerdict::Allow);
    }

    #[test]
    fn max_tokens_over_cap_denies() {
        let mut f = facts("gpt-4o");
        f.requested_max_output = Some(2048);
        let mut c = cap(&["gpt-4o"]);
        c.max_output_tokens = Some(1024);
        let v = decide(&f, Some(&c));
        assert_eq!(
            v,
            LlmVerdict::Deny(DenyReason::MaxTokensExceeded {
                requested: 2048,
                cap: 1024,
            })
        );
    }

    #[test]
    fn no_max_tokens_cap_means_no_check() {
        // Capability with no `max_output_tokens` should let any
        // value through — the proxy's behavior; this pins parity.
        let mut f = facts("gpt-4o");
        f.requested_max_output = Some(1_000_000);
        let cap = cap(&["gpt-4o"]); // max_output_tokens: None
        assert_eq!(decide(&f, Some(&cap)), LlmVerdict::Allow);
    }

    #[test]
    fn deny_reason_labels_match_proxy() {
        // Trip-wire for label drift between the two enforcement
        // modes; dashboards group by these labels.
        assert_eq!(DenyReason::NoCapability.label(), "no_capability");
        assert_eq!(
            DenyReason::ModelNotAllowed { requested: "x".into() }.label(),
            "model_not_allowed"
        );
        assert_eq!(
            DenyReason::ToolNotAllowed { tool: "x".into() }.label(),
            "tool_not_allowed"
        );
        assert_eq!(
            DenyReason::MaxTokensExceeded { requested: 1, cap: 0 }.label(),
            "max_tokens_exceeded"
        );
    }
}
