//! Integration tests for metrics system
//!
//! These tests verify metric collection, export, and registry functionality.

use agent_gateway_enforcer_core::metrics::*;
use prometheus::Encoder;

#[test]
fn test_unified_metrics_creation() {
    let metrics = UnifiedMetrics::new().unwrap();

    // Verify all metric groups are initialized
    assert!(metrics.events.events_total.get().is_empty());
    assert!(metrics.network.network_blocked_total.get().is_empty());
    assert!(metrics.files.file_blocked_total.get().is_empty());
}

#[test]
fn test_event_metrics() {
    let metrics = UnifiedMetrics::new().unwrap();

    // Increment event counters
    metrics
        .events
        .events_total
        .with_label_values(&["test"])
        .inc();

    metrics
        .events
        .events_by_type
        .with_label_values(&["network"])
        .inc();

    metrics
        .events
        .events_by_source
        .with_label_values(&["core"])
        .inc();

    metrics
        .events
        .events_by_severity
        .with_label_values(&["info"])
        .inc();

    // Verify metrics were recorded
    let families = metrics.registry.gather();
    assert!(!families.is_empty());

    let event_total = families
        .iter()
        .find(|f| f.get_name() == "agent_gateway_events_total");
    assert!(event_total.is_some());
}

#[test]
fn test_network_metrics() {
    let metrics = UnifiedMetrics::new().unwrap();

    // Record network metrics
    metrics
        .network
        .network_blocked_total
        .with_label_values(&["tcp", "443", "192.168.1.1"])
        .inc();

    metrics
        .network
        .network_allowed_total
        .with_label_values(&["tcp", "80", "10.0.0.1"])
        .inc();

    metrics.network.network_rate_limited_total.inc();

    metrics.network.network_active_connections.set(5);

    // Verify metrics
    let families = metrics.registry.gather();
    let blocked = families
        .iter()
        .find(|f| f.get_name() == "agent_gateway_network_blocked_total");
    assert!(blocked.is_some());

    let allowed = families
        .iter()
        .find(|f| f.get_name() == "agent_gateway_network_allowed_total");
    assert!(allowed.is_some());
}

#[test]
fn test_file_metrics() {
    let metrics = UnifiedMetrics::new().unwrap();

    // Record file access metrics
    metrics
        .files
        .file_blocked_total
        .with_label_values(&["read", "txt"])
        .inc();

    metrics
        .files
        .file_allowed_total
        .with_label_values(&["write", "log"])
        .inc();

    metrics.files.file_quarantined_total.inc();

    metrics.files.file_active_operations.set(3);

    // Verify metrics
    let families = metrics.registry.gather();
    let blocked = families
        .iter()
        .find(|f| f.get_name() == "agent_gateway_file_blocked_total");
    assert!(blocked.is_some());
}

#[test]
fn test_system_metrics() {
    let metrics = UnifiedMetrics::new().unwrap();

    // Record system metrics
    metrics.system.system_uptime.set(12345.67);

    metrics
        .system
        .system_load_average
        .with_label_values(&["1m"])
        .set(1.5);

    metrics
        .system
        .memory_usage_bytes
        .with_label_values(&["used"])
        .set(8_589_934_592.0); // 8 GB

    metrics.system.cpu_usage_percentage.set(45.2);

    metrics.system.process_count.set(150);

    metrics.system.thread_count.set(800);

    // Verify metrics
    let families = metrics.registry.gather();
    let uptime = families
        .iter()
        .find(|f| f.get_name() == "agent_gateway_system_uptime_seconds");
    assert!(uptime.is_some());

    assert_eq!(metrics.system.system_uptime.get(), 12345.67);
}

#[test]
fn test_performance_metrics() {
    let metrics = UnifiedMetrics::new().unwrap();

    // Record performance metrics
    metrics
        .performance
        .request_rate
        .with_label_values(&["/api/status", "GET"])
        .set(100.5);

    metrics
        .performance
        .error_rate
        .with_label_values(&["/api/config", "POST"])
        .set(0.02);

    metrics
        .performance
        .throughput
        .with_label_values(&["event_bus"])
        .set(1000.0);

    metrics
        .performance
        .resource_utilization
        .with_label_values(&["cpu"])
        .set(75.5);

    // Verify metrics
    let families = metrics.registry.gather();
    let request_rate = families
        .iter()
        .find(|f| f.get_name() == "agent_gateway_request_rate");
    assert!(request_rate.is_some());
}

#[test]
fn test_backend_metrics() {
    let metrics = UnifiedMetrics::new().unwrap();

    // Record backend metrics
    metrics
        .backends
        .backend_status
        .with_label_values(&["ebpf", "linux"])
        .set(1); // Running

    metrics
        .backends
        .backend_operations_total
        .with_label_values(&["ebpf", "initialize"])
        .inc();

    metrics
        .backends
        .backend_errors_total
        .with_label_values(&["ebpf", "network_error"])
        .inc();

    metrics
        .backends
        .backend_active_connections
        .with_label_values(&["ebpf"])
        .set(10);

    metrics
        .backends
        .backend_queue_size
        .with_label_values(&["ebpf", "events"])
        .set(50);

    // Verify metrics
    let families = metrics.registry.gather();
    let status = families
        .iter()
        .find(|f| f.get_name() == "agent_gateway_backend_status");
    assert!(status.is_some());
}

#[test]
fn test_security_metrics() {
    let metrics = UnifiedMetrics::new().unwrap();

    // Record security metrics
    metrics
        .security
        .security_events_total
        .with_label_values(&["malware", "high"])
        .inc();

    metrics
        .security
        .threats_detected_total
        .with_label_values(&["malware", "high"])
        .inc();

    metrics
        .security
        .security_violations_total
        .with_label_values(&["unauthorized_access"])
        .inc();

    metrics
        .security
        .blocked_attempts_total
        .with_label_values(&["file_access", "external"])
        .inc();

    metrics.security.security_score.set(85.5);

    metrics.security.active_threats.set(2);

    // Verify metrics
    let families = metrics.registry.gather();
    let events = families
        .iter()
        .find(|f| f.get_name() == "agent_gateway_security_events_total");
    assert!(events.is_some());
}

#[test]
fn test_histogram_metrics() {
    let metrics = UnifiedMetrics::new().unwrap();

    // Record histogram observations
    metrics
        .events
        .event_processing_duration
        .with_label_values(&["network", "ebpf"])
        .observe(0.015); // 15ms

    metrics
        .network
        .network_connection_duration
        .with_label_values(&["tcp", "443"])
        .observe(2.5); // 2.5 seconds

    metrics
        .files
        .file_access_duration
        .with_label_values(&["read"])
        .observe(0.001); // 1ms

    // Verify histograms were created
    let families = metrics.registry.gather();
    let duration = families
        .iter()
        .find(|f| f.get_name() == "agent_gateway_event_processing_duration_seconds");
    assert!(duration.is_some());
}

#[test]
fn test_prometheus_export() {
    let metrics = UnifiedMetrics::new().unwrap();

    // Add some test data
    metrics
        .events
        .events_total
        .with_label_values(&["test"])
        .inc();
    metrics
        .network
        .network_blocked_total
        .with_label_values(&["tcp", "443", "0.0.0.0"])
        .inc();

    // Export metrics
    let exported = metrics.export_prometheus().unwrap();

    // Verify export format
    assert!(exported.contains("agent_gateway_events_total"));
    assert!(exported.contains("agent_gateway_network_blocked_total"));
    assert!(exported.contains("# HELP"));
    assert!(exported.contains("# TYPE"));
}

#[test]
fn test_metrics_summary() {
    let metrics = UnifiedMetrics::new().unwrap();

    // Set some metrics
    metrics.system.system_uptime.set(1234.5);

    // Get summary
    let summary = metrics.get_summary();

    assert_eq!(summary.uptime_seconds, 1234.5);
    // Note: Other fields are placeholders in current implementation
}

#[test]
fn test_legacy_metrics_compatibility() {
    let metrics = Metrics::new().unwrap();

    // Test legacy metric structure
    metrics
        .network_blocked
        .with_label_values(&["10.0.0.1", "443", "tcp"])
        .inc();

    metrics
        .network_allowed
        .with_label_values(&["10.0.0.2", "80", "tcp"])
        .inc();

    metrics
        .file_blocked
        .with_label_values(&["/etc/shadow", "read"])
        .inc();

    metrics
        .file_allowed
        .with_label_values(&["/tmp/test.txt", "write"])
        .inc();

    metrics.backend_status.set(1);

    // Verify metrics exist
    let families = metrics.registry.gather();
    assert!(!families.is_empty());
}

#[test]
fn test_counter_increment() {
    let metrics = UnifiedMetrics::new().unwrap();

    let counter = &metrics.events.events_total;

    // Increment multiple times
    for _ in 0..10 {
        counter.with_label_values(&["test"]).inc();
    }

    // Verify count (we can't directly read the value, but we can export and check)
    let exported = metrics.export_prometheus().unwrap();
    assert!(exported.contains("agent_gateway_events_total"));
}

#[test]
fn test_gauge_set_and_inc() {
    let metrics = UnifiedMetrics::new().unwrap();

    let gauge = &metrics.network.network_active_connections;

    // Set initial value
    gauge.set(5);
    assert_eq!(gauge.get(), 5);

    // Increment
    gauge.inc();
    assert_eq!(gauge.get(), 6);

    // Decrement
    gauge.dec();
    assert_eq!(gauge.get(), 5);

    // Add specific amount
    gauge.add(10);
    assert_eq!(gauge.get(), 15);

    // Subtract specific amount
    gauge.sub(5);
    assert_eq!(gauge.get(), 10);
}

#[test]
fn test_metric_labels() {
    let metrics = UnifiedMetrics::new().unwrap();

    // Test metrics with different label combinations
    metrics
        .events
        .events_by_type
        .with_label_values(&["network"])
        .inc();
    metrics
        .events
        .events_by_type
        .with_label_values(&["file_access"])
        .inc();
    metrics
        .events
        .events_by_type
        .with_label_values(&["system"])
        .inc();

    // Export and verify all labels are present
    let exported = metrics.export_prometheus().unwrap();
    assert!(exported.contains(r#"event_type="network""#));
    assert!(exported.contains(r#"event_type="file_access""#));
    assert!(exported.contains(r#"event_type="system""#));
}

#[test]
fn test_multiple_metric_registries() {
    // Create multiple independent metric systems
    let metrics1 = UnifiedMetrics::new().unwrap();
    let metrics2 = UnifiedMetrics::new().unwrap();

    // Modify metrics1
    metrics1
        .events
        .events_total
        .with_label_values(&["m1"])
        .inc();

    // Modify metrics2
    metrics2
        .events
        .events_total
        .with_label_values(&["m2"])
        .inc();

    // Verify they're independent
    let export1 = metrics1.export_prometheus().unwrap();
    let export2 = metrics2.export_prometheus().unwrap();

    assert!(export1.contains(r#"component="m1""#));
    assert!(export2.contains(r#"component="m2""#));
}

#[test]
fn test_metric_help_and_type_annotations() {
    let metrics = UnifiedMetrics::new().unwrap();

    metrics
        .events
        .events_total
        .with_label_values(&["test"])
        .inc();

    let exported = metrics.export_prometheus().unwrap();

    // Verify HELP and TYPE annotations
    assert!(exported.contains("# HELP agent_gateway_events_total"));
    assert!(exported.contains("# TYPE agent_gateway_events_total counter"));
}
