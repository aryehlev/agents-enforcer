//! Unified metrics collection framework for agent gateway enforcer

pub mod collector;
pub mod exporter;
pub mod registry;
pub mod types;

use prometheus::{
    Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramVec, IntCounter, IntCounterVec,
    IntGauge, IntGaugeVec, Opts, Registry,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};

pub use collector::MetricsCollector;
pub use exporter::MetricsExporter;
pub use registry::MetricsRegistry;
pub use types::*;

/// Unified metrics system
#[derive(Debug)]
pub struct UnifiedMetrics {
    /// Prometheus registry
    pub registry: Registry,
    /// Event metrics
    pub events: EventMetrics,
    /// Network metrics
    pub network: NetworkMetrics,
    /// File metrics
    pub files: FileMetrics,
    /// System metrics
    pub system: SystemMetrics,
    /// Performance metrics
    pub performance: PerformanceMetrics,
    /// Backend metrics
    pub backends: BackendMetrics,
    /// Security metrics
    pub security: SecurityMetrics,
}

/// Event metrics
#[derive(Debug)]
pub struct EventMetrics {
    /// Total events processed
    pub events_total: IntCounterVec,
    /// Events by type
    pub events_by_type: IntCounterVec,
    /// Events by source
    pub events_by_source: IntCounterVec,
    /// Events by severity
    pub events_by_severity: IntCounterVec,
    /// Event processing duration
    pub event_processing_duration: HistogramVec,
    /// Event queue size
    pub event_queue_size: IntGaugeVec,
}

/// Network metrics
#[derive(Debug)]
pub struct NetworkMetrics {
    /// Total network connections blocked
    pub network_blocked_total: IntCounterVec,
    /// Total network connections allowed
    pub network_allowed_total: IntCounterVec,
    /// Total network connections rate limited
    pub network_rate_limited_total: IntCounter,
    /// Network connection duration
    pub network_connection_duration: HistogramVec,
    /// Network bytes transferred
    pub network_bytes_transferred: CounterVec,
    /// Active network connections
    pub network_active_connections: IntGauge,
    /// Network errors
    pub network_errors_total: IntCounterVec,
}

/// File metrics
#[derive(Debug)]
pub struct FileMetrics {
    /// Total file accesses blocked
    pub file_blocked_total: IntCounterVec,
    /// Total file accesses allowed
    pub file_allowed_total: IntCounterVec,
    /// Total file accesses quarantined
    pub file_quarantined_total: IntCounter,
    /// File access duration
    pub file_access_duration: HistogramVec,
    /// File bytes accessed
    pub file_bytes_accessed: CounterVec,
    /// Active file operations
    pub file_active_operations: IntGauge,
    /// File system errors
    pub file_system_errors_total: IntCounterVec,
}

/// System metrics
#[derive(Debug)]
pub struct SystemMetrics {
    /// System uptime
    pub system_uptime: Gauge,
    /// System load average
    pub system_load_average: GaugeVec,
    /// Memory usage
    pub memory_usage_bytes: GaugeVec,
    /// CPU usage percentage
    pub cpu_usage_percentage: Gauge,
    /// Disk usage bytes
    pub disk_usage_bytes: GaugeVec,
    /// Network interface bytes
    pub network_interface_bytes: CounterVec,
    /// Process count
    pub process_count: IntGauge,
    /// Thread count
    pub thread_count: IntGauge,
}

/// Performance metrics
#[derive(Debug)]
pub struct PerformanceMetrics {
    /// Request duration
    pub request_duration: HistogramVec,
    /// Request rate
    pub request_rate: GaugeVec,
    /// Error rate
    pub error_rate: GaugeVec,
    /// Throughput
    pub throughput: GaugeVec,
    /// Latency percentiles
    pub latency_percentiles: HistogramVec,
    /// Resource utilization
    pub resource_utilization: GaugeVec,
}

/// Backend metrics
#[derive(Debug)]
pub struct BackendMetrics {
    /// Backend status
    pub backend_status: IntGaugeVec,
    /// Backend health check duration
    pub backend_health_check_duration: HistogramVec,
    /// Backend operations total
    pub backend_operations_total: IntCounterVec,
    /// Backend errors total
    pub backend_errors_total: IntCounterVec,
    /// Backend active connections
    pub backend_active_connections: IntGaugeVec,
    /// Backend queue size
    pub backend_queue_size: IntGaugeVec,
}

/// Security metrics
#[derive(Debug)]
pub struct SecurityMetrics {
    /// Security events total
    pub security_events_total: IntCounterVec,
    /// Threats detected total
    pub threats_detected_total: IntCounterVec,
    /// Security violations total
    pub security_violations_total: IntCounterVec,
    /// Blocked attempts total
    pub blocked_attempts_total: IntCounterVec,
    /// Security score
    pub security_score: Gauge,
    /// Active threats
    pub active_threats: IntGauge,
}

impl UnifiedMetrics {
    /// Create a new unified metrics system
    pub fn new() -> crate::Result<Self> {
        let registry = Registry::new();

        // Initialize event metrics
        let events = EventMetrics::new(&registry)?;

        // Initialize network metrics
        let network = NetworkMetrics::new(&registry)?;

        // Initialize file metrics
        let files = FileMetrics::new(&registry)?;

        // Initialize system metrics
        let system = SystemMetrics::new(&registry)?;

        // Initialize performance metrics
        let performance = PerformanceMetrics::new(&registry)?;

        // Initialize backend metrics
        let backends = BackendMetrics::new(&registry)?;

        // Initialize security metrics
        let security = SecurityMetrics::new(&registry)?;

        Ok(Self {
            registry,
            events,
            network,
            files,
            system,
            performance,
            backends,
            security,
        })
    }

    /// Get metrics summary
    pub fn get_summary(&self) -> MetricsSummary {
        MetricsSummary {
            total_events: self.events.events_total.get(),
            network_blocked: self.network.network_blocked_total.get(),
            network_allowed: self.network.network_allowed_total.get(),
            file_blocked: self.files.file_blocked_total.get(),
            file_allowed: self.files.file_allowed_total.get(),
            security_events: self.security.security_events_total.get(),
            uptime_seconds: self.system.system_uptime.get(),
        }
    }

    /// Reset all metrics
    pub fn reset(&self) -> crate::Result<()> {
        // This would require custom implementation as prometheus doesn't have a built-in reset
        // For now, we'll just log that reset was called
        tracing::info!("Metrics reset requested (not implemented)");
        Ok(())
    }

    /// Export metrics in Prometheus format
    pub fn export_prometheus(&self) -> crate::Result<String> {
        use prometheus::Encoder;
        
        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        
        encoder.encode(&metric_families, &mut buffer)
            .map_err(|e| anyhow::anyhow!(format!("Failed to encode metrics: {}", e)))?;
        
        String::from_utf8(buffer)
            .map_err(|e| anyhow::anyhow!(format!("Failed to convert metrics to string: {}", e)))
    }
}

impl Default for UnifiedMetrics {
    fn default() -> Self {
        Self::new().expect("Failed to create unified metrics")
    }
}

impl EventMetrics {
    fn new(registry: &Registry) -> crate::Result<Self> {
        let events_total = IntCounterVec::new(
            Opts::new("agent_gateway_events_total", "Total number of events processed"),
            &["component"],
        )?;
        registry.register(Box::new(events_total.clone()))?;

        let events_by_type = IntCounterVec::new(
            Opts::new("agent_gateway_events_by_type_total", "Total events by type"),
            &["event_type"],
        )?;
        registry.register(Box::new(events_by_type.clone()))?;

        let events_by_source = IntCounterVec::new(
            Opts::new("agent_gateway_events_by_source_total", "Total events by source"),
            &["source"],
        )?;
        registry.register(Box::new(events_by_source.clone()))?;

        let events_by_severity = IntCounterVec::new(
            Opts::new("agent_gateway_events_by_severity_total", "Total events by severity"),
            &["severity"],
        )?;
        registry.register(Box::new(events_by_severity.clone()))?;

        let event_processing_duration = HistogramVec::new(
            Opts::new("agent_gateway_event_processing_duration_seconds", "Event processing duration in seconds"),
            &["event_type", "component"],
            vec![0.001, 0.01, 0.1, 1.0, 10.0], // Buckets from 1ms to 10s
        )?;
        registry.register(Box::new(event_processing_duration.clone()))?;

        let event_queue_size = IntGaugeVec::new(
            Opts::new("agent_gateway_event_queue_size", "Current event queue size"),
            &["queue_name"],
        )?;
        registry.register(Box::new(event_queue_size.clone()))?;

        Ok(Self {
            events_total,
            events_by_type,
            events_by_source,
            events_by_severity,
            event_processing_duration,
            event_queue_size,
        })
    }
}

impl NetworkMetrics {
    fn new(registry: &Registry) -> crate::Result<Self> {
        let network_blocked_total = IntCounterVec::new(
            Opts::new("agent_gateway_network_blocked_total", "Total network connections blocked"),
            &["protocol", "dst_port", "src_ip"],
        )?;
        registry.register(Box::new(network_blocked_total.clone()))?;

        let network_allowed_total = IntCounterVec::new(
            Opts::new("agent_gateway_network_allowed_total", "Total network connections allowed"),
            &["protocol", "dst_port", "src_ip"],
        )?;
        registry.register(Box::new(network_allowed_total.clone()))?;

        let network_rate_limited_total = IntCounter::new(
            Opts::new("agent_gateway_network_rate_limited_total", "Total network connections rate limited"),
        )?;
        registry.register(Box::new(network_rate_limited_total.clone()))?;

        let network_connection_duration = HistogramVec::new(
            Opts::new("agent_gateway_network_connection_duration_seconds", "Network connection duration in seconds"),
            &["protocol", "dst_port"],
            vec![0.1, 1.0, 10.0, 60.0, 300.0], // Buckets from 100ms to 5 minutes
        )?;
        registry.register(Box::new(network_connection_duration.clone()))?;

        let network_bytes_transferred = CounterVec::new(
            Opts::new("agent_gateway_network_bytes_transferred_total", "Total network bytes transferred"),
            &["direction", "protocol"],
        )?;
        registry.register(Box::new(network_bytes_transferred.clone()))?;

        let network_active_connections = IntGauge::new(
            Opts::new("agent_gateway_network_active_connections", "Current number of active network connections"),
        )?;
        registry.register(Box::new(network_active_connections.clone()))?;

        let network_errors_total = IntCounterVec::new(
            Opts::new("agent_gateway_network_errors_total", "Total network errors"),
            &["error_type", "protocol"],
        )?;
        registry.register(Box::new(network_errors_total.clone()))?;

        Ok(Self {
            network_blocked_total,
            network_allowed_total,
            network_rate_limited_total,
            network_connection_duration,
            network_bytes_transferred,
            network_active_connections,
            network_errors_total,
        })
    }
}

impl FileMetrics {
    fn new(registry: &Registry) -> crate::Result<Self> {
        let file_blocked_total = IntCounterVec::new(
            Opts::new("agent_gateway_file_blocked_total", "Total file accesses blocked"),
            &["access_type", "file_extension"],
        )?;
        registry.register(Box::new(file_blocked_total.clone()))?;

        let file_allowed_total = IntCounterVec::new(
            Opts::new("agent_gateway_file_allowed_total", "Total file accesses allowed"),
            &["access_type", "file_extension"],
        )?;
        registry.register(Box::new(file_allowed_total.clone()))?;

        let file_quarantined_total = IntCounter::new(
            Opts::new("agent_gateway_file_quarantined_total", "Total files quarantined"),
        )?;
        registry.register(Box::new(file_quarantined_total.clone()))?;

        let file_access_duration = HistogramVec::new(
            Opts::new("agent_gateway_file_access_duration_seconds", "File access duration in seconds"),
            &["access_type"],
            vec![0.001, 0.01, 0.1, 1.0, 10.0], // Buckets from 1ms to 10s
        )?;
        registry.register(Box::new(file_access_duration.clone()))?;

        let file_bytes_accessed = CounterVec::new(
            Opts::new("agent_gateway_file_bytes_accessed_total", "Total file bytes accessed"),
            &["access_type", "direction"],
        )?;
        registry.register(Box::new(file_bytes_accessed.clone()))?;

        let file_active_operations = IntGauge::new(
            Opts::new("agent_gateway_file_active_operations", "Current number of active file operations"),
        )?;
        registry.register(Box::new(file_active_operations.clone()))?;

        let file_system_errors_total = IntCounterVec::new(
            Opts::new("agent_gateway_file_system_errors_total", "Total file system errors"),
            &["error_type", "operation"],
        )?;
        registry.register(Box::new(file_system_errors_total.clone()))?;

        Ok(Self {
            file_blocked_total,
            file_allowed_total,
            file_quarantined_total,
            file_access_duration,
            file_bytes_accessed,
            file_active_operations,
            file_system_errors_total,
        })
    }
}

impl SystemMetrics {
    fn new(registry: &Registry) -> crate::Result<Self> {
        let system_uptime = Gauge::new(
            Opts::new("agent_gateway_system_uptime_seconds", "System uptime in seconds"),
        )?;
        registry.register(Box::new(system_uptime.clone()))?;

        let system_load_average = GaugeVec::new(
            Opts::new("agent_gateway_system_load_average", "System load average"),
            &["period"], // 1m, 5m, 15m
        )?;
        registry.register(Box::new(system_load_average.clone()))?;

        let memory_usage_bytes = GaugeVec::new(
            Opts::new("agent_gateway_memory_usage_bytes", "Memory usage in bytes"),
            &["type"], // total, used, free, available
        )?;
        registry.register(Box::new(memory_usage_bytes.clone()))?;

        let cpu_usage_percentage = Gauge::new(
            Opts::new("agent_gateway_cpu_usage_percentage", "CPU usage percentage"),
        )?;
        registry.register(Box::new(cpu_usage_percentage.clone()))?;

        let disk_usage_bytes = GaugeVec::new(
            Opts::new("agent_gateway_disk_usage_bytes", "Disk usage in bytes"),
            &["mount_point", "type"], // total, used, free
        )?;
        registry.register(Box::new(disk_usage_bytes.clone()))?;

        let network_interface_bytes = CounterVec::new(
            Opts::new("agent_gateway_network_interface_bytes_total", "Network interface bytes total"),
            &["interface", "direction"], // tx, rx
        )?;
        registry.register(Box::new(network_interface_bytes.clone()))?;

        let process_count = IntGauge::new(
            Opts::new("agent_gateway_process_count", "Number of processes"),
        )?;
        registry.register(Box::new(process_count.clone()))?;

        let thread_count = IntGauge::new(
            Opts::new("agent_gateway_thread_count", "Number of threads"),
        )?;
        registry.register(Box::new(thread_count.clone()))?;

        Ok(Self {
            system_uptime,
            system_load_average,
            memory_usage_bytes,
            cpu_usage_percentage,
            disk_usage_bytes,
            network_interface_bytes,
            process_count,
            thread_count,
        })
    }
}

impl PerformanceMetrics {
    fn new(registry: &Registry) -> crate::Result<Self> {
        let request_duration = HistogramVec::new(
            Opts::new("agent_gateway_request_duration_seconds", "Request duration in seconds"),
            &["endpoint", "method"],
            vec![0.001, 0.01, 0.1, 1.0, 10.0], // Buckets from 1ms to 10s
        )?;
        registry.register(Box::new(request_duration.clone()))?;

        let request_rate = GaugeVec::new(
            Opts::new("agent_gateway_request_rate", "Request rate per second"),
            &["endpoint", "method"],
        )?;
        registry.register(Box::new(request_rate.clone()))?;

        let error_rate = GaugeVec::new(
            Opts::new("agent_gateway_error_rate", "Error rate percentage"),
            &["endpoint", "method"],
        )?;
        registry.register(Box::new(error_rate.clone()))?;

        let throughput = GaugeVec::new(
            Opts::new("agent_gateway_throughput", "Throughput per second"),
            &["component"],
        )?;
        registry.register(Box::new(throughput.clone()))?;

        let latency_percentiles = HistogramVec::new(
            Opts::new("agent_gateway_latency_seconds", "Request latency in seconds"),
            &["operation"],
            vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
        )?;
        registry.register(Box::new(latency_percentiles.clone()))?;

        let resource_utilization = GaugeVec::new(
            Opts::new("agent_gateway_resource_utilization_percentage", "Resource utilization percentage"),
            &["resource"], // cpu, memory, disk, network
        )?;
        registry.register(Box::new(resource_utilization.clone()))?;

        Ok(Self {
            request_duration,
            request_rate,
            error_rate,
            throughput,
            latency_percentiles,
            resource_utilization,
        })
    }
}

impl BackendMetrics {
    fn new(registry: &Registry) -> crate::Result<Self> {
        let backend_status = IntGaugeVec::new(
            Opts::new("agent_gateway_backend_status", "Backend status (0=stopped, 1=running, 2=error)"),
            &["backend_name", "backend_type"],
        )?;
        registry.register(Box::new(backend_status.clone()))?;

        let backend_health_check_duration = HistogramVec::new(
            Opts::new("agent_gateway_backend_health_check_duration_seconds", "Backend health check duration in seconds"),
            &["backend_name"],
            vec![0.01, 0.1, 1.0, 5.0, 10.0], // Buckets from 10ms to 10s
        )?;
        registry.register(Box::new(backend_health_check_duration.clone()))?;

        let backend_operations_total = IntCounterVec::new(
            Opts::new("agent_gateway_backend_operations_total", "Total backend operations"),
            &["backend_name", "operation_type"],
        )?;
        registry.register(Box::new(backend_operations_total.clone()))?;

        let backend_errors_total = IntCounterVec::new(
            Opts::new("agent_gateway_backend_errors_total", "Total backend errors"),
            &["backend_name", "error_type"],
        )?;
        registry.register(Box::new(backend_errors_total.clone()))?;

        let backend_active_connections = IntGaugeVec::new(
            Opts::new("agent_gateway_backend_active_connections", "Active backend connections"),
            &["backend_name"],
        )?;
        registry.register(Box::new(backend_active_connections.clone()))?;

        let backend_queue_size = IntGaugeVec::new(
            Opts::new("agent_gateway_backend_queue_size", "Backend queue size"),
            &["backend_name", "queue_type"],
        )?;
        registry.register(Box::new(backend_queue_size.clone()))?;

        Ok(Self {
            backend_status,
            backend_health_check_duration,
            backend_operations_total,
            backend_errors_total,
            backend_active_connections,
            backend_queue_size,
        })
    }
}

impl SecurityMetrics {
    fn new(registry: &Registry) -> crate::Result<Self> {
        let security_events_total = IntCounterVec::new(
            Opts::new("agent_gateway_security_events_total", "Total security events"),
            &["event_type", "severity"],
        )?;
        registry.register(Box::new(security_events_total.clone()))?;

        let threats_detected_total = IntCounterVec::new(
            Opts::new("agent_gateway_threats_detected_total", "Total threats detected"),
            &["threat_type", "severity"],
        )?;
        registry.register(Box::new(threats_detected_total.clone()))?;

        let security_violations_total = IntCounterVec::new(
            Opts::new("agent_gateway_security_violations_total", "Total security violations"),
            &["violation_type"],
        )?;
        registry.register(Box::new(security_violations_total.clone()))?;

        let blocked_attempts_total = IntCounterVec::new(
            Opts::new("agent_gateway_blocked_attempts_total", "Total blocked attempts"),
            &["attempt_type", "source"],
        )?;
        registry.register(Box::new(blocked_attempts_total.clone()))?;

        let security_score = Gauge::new(
            Opts::new("agent_gateway_security_score", "Overall security score (0-100)"),
        )?;
        registry.register(Box::new(security_score.clone()))?;

        let active_threats = IntGauge::new(
            Opts::new("agent_gateway_active_threats", "Number of active threats"),
        )?;
        registry.register(Box::new(active_threats.clone()))?;

        Ok(Self {
            security_events_total,
            threats_detected_total,
            security_violations_total,
            blocked_attempts_total,
            security_score,
            active_threats,
        })
    }
}

/// Metrics summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSummary {
    /// Total events processed
    pub total_events: u64,
    /// Network connections blocked
    pub network_blocked: u64,
    /// Network connections allowed
    pub network_allowed: u64,
    /// File accesses blocked
    pub file_blocked: u64,
    /// File accesses allowed
    pub file_allowed: u64,
    /// Security events
    pub security_events: u64,
    /// System uptime in seconds
    pub uptime_seconds: f64,
}

/// Legacy metrics for backward compatibility
#[derive(Debug)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_metrics_creation() {
        let metrics = UnifiedMetrics::new().unwrap();
        
        // Test that all metric types are created
        assert!(!metrics.events.events_total.get().is_empty());
        assert!(!metrics.network.network_blocked_total.get().is_empty());
        assert!(!metrics.files.file_blocked_total.get().is_empty());
    }

    #[test]
    fn test_metrics_summary() {
        let metrics = UnifiedMetrics::new().unwrap();
        let summary = metrics.get_summary();
        
        // Test summary structure
        assert_eq!(summary.total_events, 0);
        assert_eq!(summary.network_blocked, 0);
        assert_eq!(summary.network_allowed, 0);
    }

    #[test]
    fn test_prometheus_export() {
        let metrics = UnifiedMetrics::new().unwrap();
        let exported = metrics.export_prometheus().unwrap();
        
        // Test that export contains metric names
        assert!(exported.contains("agent_gateway_events_total"));
        assert!(exported.contains("agent_gateway_network_blocked_total"));
        assert!(exported.contains("agent_gateway_file_blocked_total"));
    }

    #[test]
    fn test_legacy_metrics() {
        let metrics = Metrics::new().unwrap();
        
        // Test legacy metrics structure
        assert!(!metrics.network_blocked.get().is_empty());
        assert!(!metrics.network_allowed.get().is_empty());
        assert!(!metrics.file_blocked.get().is_empty());
        assert!(!metrics.file_allowed.get().is_empty());
    }
}