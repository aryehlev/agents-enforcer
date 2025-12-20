//! Metrics definitions for agent gateway enforcer

use prometheus::{IntCounterVec, IntGauge, Opts, Registry};

/// Metrics collector for the enforcer
pub struct Metrics {
    /// Registry for Prometheus metrics
    pub registry: Registry,
    /// Total network connections blocked
    pub network_blocked: IntCounterVec,
    /// Total network connections allowed
    pub network_allowed: IntCounterVec,
    /// Total file accesses blocked
    pub file_blocked: IntCounterVec,
    /// Total file accesses allowed
    pub file_allowed: IntCounterVec,
    /// Backend status (0 = stopped, 1 = running)
    pub backend_status: IntGauge,
}

impl Metrics {
    /// Create a new metrics collector
    pub fn new() -> crate::Result<Self> {
        let registry = Registry::new();
        
        let network_blocked = IntCounterVec::new(
            Opts::new("agent_gateway_network_blocked_total", "Total network connections blocked"),
            &["dst_ip", "dst_port", "protocol"],
        )?;
        registry.register(Box::new(network_blocked.clone()))?;
        
        let network_allowed = IntCounterVec::new(
            Opts::new("agent_gateway_network_allowed_total", "Total network connections allowed"),
            &["dst_ip", "dst_port", "protocol"],
        )?;
        registry.register(Box::new(network_allowed.clone()))?;
        
        let file_blocked = IntCounterVec::new(
            Opts::new("agent_gateway_file_blocked_total", "Total file accesses blocked"),
            &["path", "access_type"],
        )?;
        registry.register(Box::new(file_blocked.clone()))?;
        
        let file_allowed = IntCounterVec::new(
            Opts::new("agent_gateway_file_allowed_total", "Total file accesses allowed"),
            &["path", "access_type"],
        )?;
        registry.register(Box::new(file_allowed.clone()))?;
        
        let backend_status = IntGauge::new(
            "agent_gateway_backend_status",
            "Backend status (0 = stopped, 1 = running)",
        )?;
        registry.register(Box::new(backend_status.clone()))?;
        
        Ok(Self {
            registry,
            network_blocked,
            network_allowed,
            file_blocked,
            file_allowed,
            backend_status,
        })
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new().expect("Failed to create metrics")
    }
}
