//! Node-agent side of the `enforcer_*` Prometheus metrics.
//!
//! Node-agents own the data-plane counters (egress / file / exec
//! decisions, map utilization, agent-up). The registry is process-
//! local to avoid cross-crate static coupling — the controller-side
//! registry in `agent-gateway-enforcer-controller::metrics` is an
//! independent instance, and each binary exposes its own /metrics.

use once_cell::sync::Lazy;
use prometheus::{IntCounterVec, IntGaugeVec, Opts, Registry};

/// Process-wide registry. Prefix becomes `enforcer_` to match the
/// schema in `docs/k8s-controller-plan.md` §5.2.
pub static REGISTRY: Lazy<Registry> =
    Lazy::new(|| Registry::new_custom(Some("enforcer".to_string()), None).expect("registry"));

fn counter(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    let c = IntCounterVec::new(Opts::new(name, help), labels).expect("counter");
    REGISTRY.register(Box::new(c.clone())).expect("register");
    c
}

fn gauge(name: &str, help: &str, labels: &[&str]) -> IntGaugeVec {
    let g = IntGaugeVec::new(Opts::new(name, help), labels).expect("gauge");
    REGISTRY.register(Box::new(g.clone())).expect("register");
    g
}

/// `enforcer_egress_decisions_total{namespace, pod, policy, action, gateway}`.
pub static EGRESS_DECISIONS: Lazy<IntCounterVec> = Lazy::new(|| {
    counter(
        "egress_decisions_total",
        "Egress-connect decisions from the data plane.",
        &["namespace", "pod", "policy", "action", "gateway"],
    )
});

/// `enforcer_file_decisions_total{...}`.
pub static FILE_DECISIONS: Lazy<IntCounterVec> = Lazy::new(|| {
    counter(
        "file_decisions_total",
        "File-access decisions from the LSM data plane.",
        &["namespace", "pod", "policy", "action", "op", "path_bucket"],
    )
});

/// `enforcer_exec_decisions_total{...}`.
pub static EXEC_DECISIONS: Lazy<IntCounterVec> = Lazy::new(|| {
    counter(
        "exec_decisions_total",
        "Exec-allowlist decisions from bprm_check_security.",
        &["namespace", "pod", "policy", "action", "binary"],
    )
});

/// `enforcer_ebpf_map_utilization{map, node}` — percent (0..100).
pub static EBPF_MAP_UTILIZATION: Lazy<IntGaugeVec> = Lazy::new(|| {
    gauge(
        "ebpf_map_utilization",
        "Fraction of eBPF map capacity in use, scaled 0..100.",
        &["map", "node"],
    )
});

/// `enforcer_node_agent_up{node}` — toggled to 1 at startup, stays
/// at 1 while the process is alive. The controller's scrape
/// discovery infers 0 when a target disappears.
pub static NODE_AGENT_UP: Lazy<IntGaugeVec> = Lazy::new(|| {
    gauge(
        "node_agent_up",
        "1 if the node-agent on this node is serving.",
        &["node"],
    )
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_families_carry_enforcer_prefix() {
        // Touch at least one metric so `gather()` yields a family.
        NODE_AGENT_UP.with_label_values(&["n1"]).set(1);
        let names: Vec<String> = REGISTRY
            .gather()
            .into_iter()
            .map(|f| f.get_name().to_string())
            .collect();
        assert!(
            names.iter().any(|n| n == "enforcer_node_agent_up"),
            "expected enforcer_node_agent_up; got {:?}",
            names
        );
    }
}
