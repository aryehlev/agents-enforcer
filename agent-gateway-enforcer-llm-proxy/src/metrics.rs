//! Prometheus metrics exposed by the LLM proxy. Names carry the
//! `enforcer_llm_*` prefix — kept narrow so `enforcer_*` dashboards
//! slice cleanly.
//!
//! Scrape endpoint lives in `metrics_server.rs`.

use once_cell::sync::Lazy;
use prometheus::{CounterVec, IntCounterVec, IntGaugeVec, Opts, Registry};

/// Process-wide registry. Prefix becomes `enforcer_*` to match the
/// plan's §5.2 namespace.
pub static REGISTRY: Lazy<Registry> =
    Lazy::new(|| Registry::new_custom(Some("enforcer".to_string()), None).expect("registry"));

fn counter_vec(name: &str, help: &str, labels: &[&str]) -> CounterVec {
    let c = CounterVec::new(Opts::new(name, help), labels).expect("counter");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
}

fn int_counter_vec(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    let c = IntCounterVec::new(Opts::new(name, help), labels).expect("int counter");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
}

fn gauge_vec(name: &str, help: &str, labels: &[&str]) -> IntGaugeVec {
    let g = IntGaugeVec::new(Opts::new(name, help), labels).expect("gauge");
    REGISTRY.register(Box::new(g.clone())).expect("register");
    g
}

/// `enforcer_llm_requests_total{agent, model, outcome}`. `outcome` is
/// `forwarded` or `rejected`.
pub static LLM_REQUESTS: Lazy<IntCounterVec> = Lazy::new(|| {
    int_counter_vec(
        "llm_requests_total",
        "LLM proxy requests bucketed by agent, model, and outcome.",
        &["agent", "model", "outcome"],
    )
});

/// `enforcer_llm_tokens_total{agent, model, direction}`. `direction`
/// is `input` or `output`.
pub static LLM_TOKENS: Lazy<IntCounterVec> = Lazy::new(|| {
    int_counter_vec(
        "llm_tokens_total",
        "Token count flowing through the LLM proxy.",
        &["agent", "model", "direction"],
    )
});

/// `enforcer_llm_spend_usd_total{agent, model}` — float counter.
pub static LLM_SPEND: Lazy<CounterVec> = Lazy::new(|| {
    counter_vec(
        "llm_spend_usd_total",
        "Running USD spend attributed to (agent, model).",
        &["agent", "model"],
    )
});

/// `enforcer_llm_rejections_total{agent, reason}` — see
/// `enforce::RejectReason::metric_label`.
pub static LLM_REJECTIONS: Lazy<IntCounterVec> = Lazy::new(|| {
    int_counter_vec(
        "llm_rejections_total",
        "Requests rejected by the proxy, bucketed by reason.",
        &["agent", "reason"],
    )
});

/// `enforcer_llm_budget_spent_usd{agent}` — instantaneous gauge of
/// the current day's running spend. Backed by `BudgetStore`.
pub static LLM_BUDGET_SPENT: Lazy<IntGaugeVec> = Lazy::new(|| {
    // IntGauge stores cents — Prometheus gauges are f64 under the
    // hood, but IntGaugeVec is enough for a budget display.
    gauge_vec(
        "llm_budget_spent_cents",
        "Cents spent today per agent. Divide by 100 for dollars.",
        &["agent"],
    )
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_metric_is_registered_with_enforcer_prefix() {
        LLM_REQUESTS
            .with_label_values(&["a", "m", "forwarded"])
            .inc();
        LLM_TOKENS
            .with_label_values(&["a", "m", "input"])
            .inc_by(10);
        LLM_SPEND.with_label_values(&["a", "m"]).inc_by(0.01);
        LLM_REJECTIONS
            .with_label_values(&["a", "budget_exceeded"])
            .inc();
        LLM_BUDGET_SPENT.with_label_values(&["a"]).set(100);

        let names: Vec<String> = REGISTRY
            .gather()
            .into_iter()
            .map(|f| f.get_name().to_string())
            .collect();
        for n in [
            "enforcer_llm_requests_total",
            "enforcer_llm_tokens_total",
            "enforcer_llm_spend_usd_total",
            "enforcer_llm_rejections_total",
            "enforcer_llm_budget_spent_cents",
        ] {
            assert!(
                names.iter().any(|x| x == n),
                "expected {} in gathered metrics; got {:?}",
                n,
                names
            );
        }
    }
}
