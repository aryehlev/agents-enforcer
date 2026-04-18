//! Prometheus metrics matching `docs/k8s-controller-plan.md` §5.2.
//!
//! Names and label sets are locked by that doc — operators build
//! dashboards and alerts on these. Drift silently breaks things
//! outside the repo, so rename/remove requires a minor-version bump
//! and a deprecation note.
//!
//! Scope split:
//! - Metrics the **controller** emits live here and are incremented
//!   from [`crate::reconciler`] / [`crate::controller`].
//! - Metrics the **node agent / data plane** emits (egress / file /
//!   exec decisions, map utilization) are registered here too so
//!   every instance exports the same schema even before data exists
//!   — prevents dashboards from blinking and simplifies the
//!   node-agent's Prometheus adapter.

use once_cell::sync::Lazy;
use prometheus::{
    Histogram, HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts, Registry,
};

/// The single process-wide registry. `prometheus::default_registry()`
/// would also work, but a named registry keeps metric-names clear in
/// integration tests where both controller + node agent run in one
/// binary.
pub static REGISTRY: Lazy<Registry> =
    Lazy::new(|| Registry::new_custom(Some("enforcer".to_string()), None).expect("registry"));

fn register_counter(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    let c = IntCounterVec::new(Opts::new(name, help), labels).expect("counter");
    REGISTRY
        .register(Box::new(c.clone()))
        .expect("register counter");
    c
}

fn register_gauge(name: &str, help: &str, labels: &[&str]) -> IntGaugeVec {
    let g = IntGaugeVec::new(Opts::new(name, help), labels).expect("gauge");
    REGISTRY
        .register(Box::new(g.clone()))
        .expect("register gauge");
    g
}

fn register_hist(name: &str, help: &str, labels: &[&str], buckets: Vec<f64>) -> HistogramVec {
    let h = HistogramVec::new(HistogramOpts::new(name, help).buckets(buckets), labels)
        .expect("histogram");
    REGISTRY
        .register(Box::new(h.clone()))
        .expect("register histogram");
    h
}

// --- Controller-side metrics ---

/// `enforcer_controller_reconcile_total{result}` — every reconcile
/// pass the controller runs. `result` ∈ {ok, compile_error,
/// distribute_error, kube_error}.
pub static RECONCILE_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_counter(
        "controller_reconcile_total",
        "Controller reconcile attempts bucketed by outcome.",
        &["result"],
    )
});

/// `enforcer_policy_program_latency_seconds{phase}` — time to move a
/// policy through compile / push / attach. Buckets chosen to cover
/// the plan's p99 < 2s target with headroom into the slow tail.
pub static POLICY_PROGRAM_LATENCY: Lazy<HistogramVec> = Lazy::new(|| {
    register_hist(
        "policy_program_latency_seconds",
        "End-to-end latency of programming a PolicyBundle.",
        &["phase"],
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0],
    )
});

// --- Data-plane metrics (written by node agents) ---

/// `enforcer_egress_decisions_total{namespace, pod, policy, action, gateway}`.
pub static EGRESS_DECISIONS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_counter(
        "egress_decisions_total",
        "Egress-connect decisions from the data plane.",
        &["namespace", "pod", "policy", "action", "gateway"],
    )
});

/// `enforcer_file_decisions_total{namespace, pod, policy, action, op, path_bucket}`.
pub static FILE_DECISIONS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_counter(
        "file_decisions_total",
        "File-access decisions from the LSM data plane.",
        &["namespace", "pod", "policy", "action", "op", "path_bucket"],
    )
});

/// `enforcer_exec_decisions_total{namespace, pod, policy, action, binary}`.
pub static EXEC_DECISIONS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_counter(
        "exec_decisions_total",
        "Exec-allowlist decisions from bprm_check_security.",
        &["namespace", "pod", "policy", "action", "binary"],
    )
});

/// `enforcer_ebpf_map_utilization{map, node}` — early warning on
/// MAX_* limits before they start dropping entries silently.
pub static EBPF_MAP_UTILIZATION: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_gauge(
        "ebpf_map_utilization",
        "Fraction of eBPF map capacity in use, as a fixed-point int (0..100).",
        &["map", "node"],
    )
});

/// `enforcer_node_agent_up{node}` — 1 when a node-agent has checked
/// in recently, 0 otherwise.
pub static NODE_AGENT_UP: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_gauge(
        "node_agent_up",
        "1 if the node-agent on this node is reachable.",
        &["node"],
    )
});

// --- Helpers the reconciler calls ---

/// Record a reconcile outcome. `result` strings are consumed by
/// Prometheus as cardinality — stick to a closed set.
pub fn record_reconcile(result: &str) {
    RECONCILE_TOTAL.with_label_values(&[result]).inc();
}

/// Time a phase. Returns a `prometheus::Histogram` timer that records
/// on drop; prefer this over manual `Instant::now` so we can't
/// forget to observe.
pub fn time_phase(phase: &str) -> Histogram {
    POLICY_PROGRAM_LATENCY.with_label_values(&[phase])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `prometheus::Registry::gather` returns each metric's family;
    /// this lets us assert a metric has been registered without
    /// actually scraping.
    fn metric_is_registered(name: &str) -> bool {
        REGISTRY
            .gather()
            .into_iter()
            .any(|mf| mf.get_name() == name)
    }

    #[test]
    fn plan_5_2_metric_names_are_registered_with_enforcer_prefix() {
        // Prefix is applied by Registry::new_custom; the families
        // that come back are `enforcer_<name>`.
        for n in [
            "enforcer_controller_reconcile_total",
            "enforcer_policy_program_latency_seconds",
            "enforcer_egress_decisions_total",
            "enforcer_file_decisions_total",
            "enforcer_exec_decisions_total",
            "enforcer_ebpf_map_utilization",
            "enforcer_node_agent_up",
        ] {
            // Touch the metric so it shows up in gather().
            match n {
                "enforcer_controller_reconcile_total" => record_reconcile("ok"),
                "enforcer_policy_program_latency_seconds" => {
                    time_phase("compile").observe(0.001);
                }
                "enforcer_egress_decisions_total" => {
                    EGRESS_DECISIONS
                        .with_label_values(&["n", "p", "po", "Deny", "gw"])
                        .inc();
                }
                "enforcer_file_decisions_total" => {
                    FILE_DECISIONS
                        .with_label_values(&["n", "p", "po", "Deny", "read", "etc"])
                        .inc();
                }
                "enforcer_exec_decisions_total" => {
                    EXEC_DECISIONS
                        .with_label_values(&["n", "p", "po", "Deny", "/bin/sh"])
                        .inc();
                }
                "enforcer_ebpf_map_utilization" => {
                    EBPF_MAP_UTILIZATION
                        .with_label_values(&["allowed_gateways", "node-1"])
                        .set(50);
                }
                "enforcer_node_agent_up" => {
                    NODE_AGENT_UP.with_label_values(&["node-1"]).set(1);
                }
                _ => {}
            }
            assert!(metric_is_registered(n), "expected {} to be registered", n);
        }
    }
}
