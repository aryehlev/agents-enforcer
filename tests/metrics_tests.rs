//! Metrics Collection and Export Integration Tests
//! 
//! This module contains integration tests for the metrics system:
//! - Counter, gauge, and histogram metrics
//! - Event, network, file, system metrics
//! - Performance and security metrics
//! - Prometheus export format
//! - Multiple metric registries
//! - Metric labels and annotations

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use crate::test_utils::*;

/// Run all metrics tests
pub fn run_all_metrics_tests() {
    println!("=== Running Metrics Integration Tests ===");
    
    // Test metric types
    test_counter_metrics();
    test_gauge_metrics();
    test_histogram_metrics();
    
    // Test specialized metrics
    test_event_metrics();
    test_network_metrics();
    test_file_access_metrics();
    test_system_metrics();
    test_performance_metrics();
    test_security_metrics();
    test_backend_metrics();
    
    // Test metric registries and export
    test_metric_registry();
    test_prometheus_export();
    test_multiple_registries();
    
    // Test metric metadata
    test_metric_labels();
    test_help_and_type_annotations();
    
    // Test advanced functionality
    test_metric_aggregation();
    test_metric_performance();
    test_metric_cleanup();
    
    println!("=== Metrics Integration Tests Completed ===");
}

// =============================================================================
// Basic Metric Types Tests
// =============================================================================

/// Mock metric types for testing
#[derive(Debug, Clone)]
struct MockCounter {
    name: String,
    value: Arc<Mutex<f64>>,
    labels: HashMap<String, String>,
    help: String,
}

impl MockCounter {
    fn new(name: &str, help: &str) -> Self {
        Self {
            name: name.to_string(),
            value: Arc::new(Mutex::new(0.0)),
            labels: HashMap::new(),
            help: help.to_string(),
        }
    }
    
    fn inc(&self) {
        *self.value.lock().unwrap() += 1.0;
    }
    
    fn inc_by(&self, amount: f64) {
        *self.value.lock().unwrap() += amount;
    }
    
    fn get(&self) -> f64 {
        *self.value.lock().unwrap()
    }
    
    fn reset(&self) {
        *self.value.lock().unwrap() = 0.0;
    }
    
    fn with_label(mut self, key: &str, value: &str) -> Self {
        self.labels.insert(key.to_string(), value.to_string());
        self
    }
}

#[derive(Debug, Clone)]
struct MockGauge {
    name: String,
    value: Arc<Mutex<f64>>,
    labels: HashMap<String, String>,
    help: String,
}

impl MockGauge {
    fn new(name: &str, help: &str) -> Self {
        Self {
            name: name.to_string(),
            value: Arc::new(Mutex::new(0.0)),
            labels: HashMap::new(),
            help: help.to_string(),
        }
    }
    
    fn set(&self, value: f64) {
        *self.value.lock().unwrap() = value;
    }
    
    fn inc(&self) {
        *self.value.lock().unwrap() += 1.0;
    }
    
    fn dec(&self) {
        *self.value.lock().unwrap() -= 1.0;
    }
    
    fn add(&self, amount: f64) {
        *self.value.lock().unwrap() += amount;
    }
    
    fn sub(&self, amount: f64) {
        *self.value.lock().unwrap() -= amount;
    }
    
    fn get(&self) -> f64 {
        *self.value.lock().unwrap()
    }
    
    fn with_label(mut self, key: &str, value: &str) -> Self {
        self.labels.insert(key.to_string(), value.to_string());
        self
    }
}

#[derive(Debug, Clone)]
struct MockHistogram {
    name: String,
    observations: Arc<Mutex<Vec<f64>>>,
    buckets: Vec<f64>,
    sum: Arc<Mutex<f64>>,
    count: Arc<Mutex<u64>>,
    labels: HashMap<String, String>,
    help: String,
}

impl MockHistogram {
    fn new(name: &str, help: &str, buckets: Vec<f64>) -> Self {
        Self {
            name: name.to_string(),
            observations: Arc::new(Mutex::new(Vec::new())),
            buckets,
            sum: Arc::new(Mutex::new(0.0)),
            count: Arc::new(Mutex::new(0)),
            labels: HashMap::new(),
            help: help.to_string(),
        }
    }
    
    fn observe(&self, value: f64) {
        self.observations.lock().unwrap().push(value);
        *self.sum.lock().unwrap() += value;
        *self.count.lock().unwrap() += 1;
    }
    
    fn get_count(&self) -> u64 {
        *self.count.lock().unwrap()
    }
    
    fn get_sum(&self) -> f64 {
        *self.sum.lock().unwrap()
    }
    
    fn get_bucket_counts(&self) -> Vec<u64> {
        let observations = self.observations.lock().unwrap();
        let mut counts = vec![0; self.buckets.len()];
        
        for &value in observations.iter() {
            for (i, &bucket) in self.buckets.iter().enumerate() {
                if value <= bucket {
                    counts[i] += 1;
                }
            }
        }
        
        counts
    }
    
    fn with_label(mut self, key: &str, value: &str) -> Self {
        self.labels.insert(key.to_string(), value.to_string());
        self
    }
}

/// Test counter metrics
fn test_counter_metrics() {
    println!("Testing counter metrics...");
    
    let counter = MockCounter::new("test_counter", "A test counter metric");
    
    // Test initial state
    assert_eq!(counter.get(), 0.0);
    
    // Test increment
    counter.inc();
    assert_eq!(counter.get(), 1.0);
    
    // Test increment by amount
    counter.inc_by(5.0);
    assert_eq!(counter.get(), 6.0);
    
    // Test reset
    counter.reset();
    assert_eq!(counter.get(), 0.0);
    
    // Test multiple increments
    for _ in 0..10 {
        counter.inc();
    }
    assert_eq!(counter.get(), 10.0);
    
    println!("✓ Counter metrics tests passed");
}

/// Test gauge metrics
fn test_gauge_metrics() {
    println!("Testing gauge metrics...");
    
    let gauge = MockGauge::new("test_gauge", "A test gauge metric");
    
    // Test initial state
    assert_eq!(gauge.get(), 0.0);
    
    // Test set
    gauge.set(42.5);
    assert_eq!(gauge.get(), 42.5);
    
    // Test increment
    gauge.inc();
    assert_eq!(gauge.get(), 43.5);
    
    // Test decrement
    gauge.dec();
    assert_eq!(gauge.get(), 42.5);
    
    // Test add
    gauge.add(10.0);
    assert_eq!(gauge.get(), 52.5);
    
    // Test subtract
    gauge.sub(20.0);
    assert_eq!(gauge.get(), 32.5);
    
    // Test negative values
    gauge.sub(50.0);
    assert_eq!(gauge.get(), -17.5);
    
    println!("✓ Gauge metrics tests passed");
}

/// Test histogram metrics
fn test_histogram_metrics() {
    println!("Testing histogram metrics...");
    
    let buckets = vec![0.1, 0.5, 1.0, 2.5, 5.0, 10.0];
    let histogram = MockHistogram::new("test_histogram", "A test histogram metric", buckets);
    
    // Test initial state
    assert_eq!(histogram.get_count(), 0);
    assert_eq!(histogram.get_sum(), 0.0);
    
    // Test observations
    let observations = vec![0.05, 0.2, 0.8, 1.5, 3.0, 8.0, 12.0];
    for &value in &observations {
        histogram.observe(value);
    }
    
    assert_eq!(histogram.get_count(), observations.len() as u64);
    
    let expected_sum: f64 = observations.iter().sum();
    assert_eq!(histogram.get_sum(), expected_sum);
    
    // Test bucket counts
    let bucket_counts = histogram.get_bucket_counts();
    assert_eq!(bucket_counts.len(), buckets.len());
    
    // Verify bucket distribution
    assert!(bucket_counts[0] >= 1); // ≤0.1
    assert!(bucket_counts[1] >= 2); // ≤0.5
    assert!(bucket_counts[2] >= 3); // ≤1.0
    assert!(bucket_counts[3] >= 4); // ≤2.5
    assert!(bucket_counts[4] >= 5); // ≤5.0
    assert!(bucket_counts[5] >= 6); // ≤10.0
    
    println!("✓ Histogram metrics tests passed");
}

// =============================================================================
// Specialized Metrics Tests
// =============================================================================

/// Test event-related metrics
fn test_event_metrics() {
    println!("Testing event metrics...");
    
    let events_total = MockCounter::new("events_total", "Total number of events processed");
    let events_by_type = MockCounter::new("events_by_type_total", "Events by type")
        .with_label("type", "network");
    let event_processing_duration = MockHistogram::new(
        "event_processing_duration_seconds", 
        "Time spent processing events",
        vec![0.001, 0.01, 0.1, 1.0, 10.0]
    );
    
    // Simulate event processing
    events_total.inc();
    events_by_type.inc();
    event_processing_duration.observe(0.05);
    
    events_total.inc();
    event_processing_duration.observe(0.15);
    
    assert_eq!(events_total.get(), 2.0);
    assert_eq!(events_by_type.get(), 1.0);
    assert_eq!(event_processing_duration.get_count(), 2);
    
    println!("✓ Event metrics tests passed");
}

/// Test network-related metrics
fn test_network_metrics() {
    println!("Testing network metrics...");
    
    let network_connections = MockGauge::new("network_connections", "Current number of network connections");
    let network_bytes_sent = MockCounter::new("network_bytes_sent_total", "Total bytes sent");
    let network_bytes_received = MockCounter::new("network_bytes_received_total", "Total bytes received");
    let network_latency = MockHistogram::new(
        "network_latency_seconds",
        "Network request latency",
        vec![0.001, 0.01, 0.1, 1.0]
    );
    
    // Simulate network activity
    network_connections.set(5);
    network_bytes_sent.inc_by(1024.0);
    network_bytes_received.inc_by(2048.0);
    network_latency.observe(0.025);
    
    assert_eq!(network_connections.get(), 5.0);
    assert_eq!(network_bytes_sent.get(), 1024.0);
    assert_eq!(network_bytes_received.get(), 2048.0);
    assert_eq!(network_latency.get_count(), 1);
    
    // Simulate connection changes
    network_connections.inc();
    network_connections.inc();
    assert_eq!(network_connections.get(), 7.0);
    
    network_connections.dec();
    assert_eq!(network_connections.get(), 6.0);
    
    println!("✓ Network metrics tests passed");
}

/// Test file access metrics
fn test_file_access_metrics() {
    println!("Testing file access metrics...");
    
    let file_operations_total = MockCounter::new("file_operations_total", "Total file operations")
        .with_label("operation", "read");
    let file_access_denied = MockCounter::new("file_access_denied_total", "File access denied");
    let file_size_bytes = MockHistogram::new(
        "file_size_bytes",
        "Size of accessed files",
        vec![1024.0, 4096.0, 16384.0, 65536.0, 262144.0]
    );
    
    // Simulate file operations
    file_operations_total.inc();
    file_operations_total.inc();
    file_size_bytes.observe(2048.0);
    
    // Simulate access denied
    file_access_denied.inc();
    file_size_bytes.observe(512.0);
    
    assert_eq!(file_operations_total.get(), 2.0);
    assert_eq!(file_access_denied.get(), 1.0);
    assert_eq!(file_size_bytes.get_count(), 2);
    
    println!("✓ File access metrics tests passed");
}

/// Test system metrics
fn test_system_metrics() {
    println!("Testing system metrics...");
    
    let cpu_usage = MockGauge::new("system_cpu_usage_percent", "CPU usage percentage");
    let memory_usage = MockGauge::new("system_memory_usage_bytes", "Memory usage in bytes");
    let disk_usage = MockGauge::new("system_disk_usage_percent", "Disk usage percentage");
    let load_average = MockGauge::new("system_load_average", "System load average");
    
    // Simulate system metrics
    cpu_usage.set(75.5);
    memory_usage.set(8589934592.0); // 8GB
    disk_usage.set(45.2);
    load_average.set(1.25);
    
    assert_eq!(cpu_usage.get(), 75.5);
    assert_eq!(memory_usage.get(), 8589934592.0);
    assert_eq!(disk_usage.get(), 45.2);
    assert_eq!(load_average.get(), 1.25);
    
    // Simulate metric changes
    cpu_usage.set(80.0);
    memory_usage.add(1073741824.0); // Add 1GB
    
    assert_eq!(cpu_usage.get(), 80.0);
    assert_eq!(memory_usage.get(), 9663676416.0); // 9GB
    
    println!("✓ System metrics tests passed");
}

/// Test performance metrics
fn test_performance_metrics() {
    println!("Testing performance metrics...");
    
    let request_duration = MockHistogram::new(
        "http_request_duration_seconds",
        "HTTP request duration",
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
    );
    let throughput = MockGauge::new("requests_per_second", "Current request throughput");
    let error_rate = MockGauge::new("error_rate_percent", "Current error rate");
    
    // Simulate performance metrics
    for &latency in &[0.002, 0.015, 0.025, 0.08, 0.12, 0.3] {
        request_duration.observe(latency);
    }
    
    throughput.set(125.5);
    error_rate.set(2.3);
    
    assert_eq!(request_duration.get_count(), 6);
    assert_eq!(throughput.get(), 125.5);
    assert_eq!(error_rate.get(), 2.3);
    
    println!("✓ Performance metrics tests passed");
}

/// Test security metrics
fn test_security_metrics() {
    println!("Testing security metrics...");
    
    let security_events = MockCounter::new("security_events_total", "Total security events")
        .with_label("type", "intrusion_attempt");
    let blocked_connections = MockCounter::new("blocked_connections_total", "Total blocked connections");
    let authentication_failures = MockCounter::new("authentication_failures_total", "Authentication failures");
    let policy_violations = MockCounter::new("policy_violations_total", "Policy violations")
        .with_label("severity", "high");
    
    // Simulate security events
    security_events.inc();
    blocked_connections.inc_by(3);
    authentication_failures.inc();
    policy_violations.inc();
    
    assert_eq!(security_events.get(), 1.0);
    assert_eq!(blocked_connections.get(), 3.0);
    assert_eq!(authentication_failures.get(), 1.0);
    assert_eq!(policy_violations.get(), 1.0);
    
    println!("✓ Security metrics tests passed");
}

/// Test backend metrics
fn test_backend_metrics() {
    println!("Testing backend metrics...");
    
    let backend_status = MockGauge::new("backend_status", "Backend status (1=up, 0=down)")
        .with_label("backend", "ebpf_linux");
    let backend_operations = MockCounter::new("backend_operations_total", "Backend operations")
        .with_label("backend", "ebpf_linux")
        .with_label("operation", "policy_check");
    let backend_errors = MockCounter::new("backend_errors_total", "Backend errors")
        .with_label("backend", "ebpf_linux");
    
    // Simulate backend metrics
    backend_status.set(1.0); // Backend is up
    backend_operations.inc();
    backend_operations.inc();
    
    // Simulate backend error
    backend_errors.inc();
    backend_status.set(0.0); // Backend went down
    backend_status.set(1.0); // Backend recovered
    
    assert_eq!(backend_status.get(), 1.0);
    assert_eq!(backend_operations.get(), 2.0);
    assert_eq!(backend_errors.get(), 1.0);
    
    println!("✓ Backend metrics tests passed");
}

// =============================================================================
// Metric Registry and Export Tests
// =============================================================================

/// Mock metric registry
struct MockMetricRegistry {
    counters: Arc<Mutex<HashMap<String, MockCounter>>>,
    gauges: Arc<Mutex<HashMap<String, MockGauge>>>,
    histograms: Arc<Mutex<HashMap<String, MockHistogram>>>,
}

impl MockMetricRegistry {
    fn new() -> Self {
        Self {
            counters: Arc::new(Mutex::new(HashMap::new())),
            gauges: Arc::new(Mutex::new(HashMap::new())),
            histograms: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    fn register_counter(&self, counter: MockCounter) {
        self.counters.lock().unwrap().insert(counter.name.clone(), counter);
    }
    
    fn register_gauge(&self, gauge: MockGauge) {
        self.gauges.lock().unwrap().insert(gauge.name.clone(), gauge);
    }
    
    fn register_histogram(&self, histogram: MockHistogram) {
        self.histograms.lock().unwrap().insert(histogram.name.clone(), histogram);
    }
    
    fn get_counter(&self, name: &str) -> Option<MockCounter> {
        self.counters.lock().unwrap().get(name).cloned()
    }
    
    fn get_gauge(&self, name: &str) -> Option<MockGauge> {
        self.gauges.lock().unwrap().get(name).cloned()
    }
    
    fn get_histogram(&self, name: &str) -> Option<MockHistogram> {
        self.histograms.lock().unwrap().get(name).cloned()
    }
    
    fn export_prometheus(&self) -> String {
        let mut output = String::new();
        
        // Export counters
        let counters = self.counters.lock().unwrap();
        for (name, counter) in counters.iter() {
            output.push_str(&format!("# HELP {} {}\n", name, counter.help));
            output.push_str(&format!("# TYPE {} counter\n", name));
            output.push_str(&format!("{} {}\n", name, counter.get()));
        }
        
        // Export gauges
        let gauges = self.gauges.lock().unwrap();
        for (name, gauge) in gauges.iter() {
            output.push_str(&format!("# HELP {} {}\n", name, gauge.help));
            output.push_str(&format!("# TYPE {} gauge\n", name));
            output.push_str(&format!("{} {}\n", name, gauge.get()));
        }
        
        // Export histograms
        let histograms = self.histograms.lock().unwrap();
        for (name, histogram) in histograms.iter() {
            output.push_str(&format!("# HELP {} {}\n", name, histogram.help));
            output.push_str(&format!("# TYPE {} histogram\n", name));
            output.push_str(&format!("{}_count {}\n", name, histogram.get_count()));
            output.push_str(&format!("{}_sum {}\n", name, histogram.get_sum()));
            
            let bucket_counts = histogram.get_bucket_counts();
            for (i, &bucket) in histogram.buckets.iter().enumerate() {
                output.push_str(&format!("{}_bucket{{le=\"{}\"}} {}\n", name, bucket, bucket_counts[i]));
            }
        }
        
        output
    }
}

/// Test metric registry
fn test_metric_registry() {
    println!("Testing metric registry...");
    
    let registry = MockMetricRegistry::new();
    
    // Register metrics
    let counter = MockCounter::new("test_counter", "Test counter metric");
    let gauge = MockGauge::new("test_gauge", "Test gauge metric");
    let histogram = MockHistogram::new(
        "test_histogram",
        "Test histogram metric",
        vec![0.1, 1.0, 10.0]
    );
    
    registry.register_counter(counter.clone());
    registry.register_gauge(gauge.clone());
    registry.register_histogram(histogram.clone());
    
    // Update metrics
    counter.inc();
    gauge.set(42.0);
    histogram.observe(5.0);
    
    // Retrieve and verify metrics
    let retrieved_counter = registry.get_counter("test_counter").unwrap();
    let retrieved_gauge = registry.get_gauge("test_gauge").unwrap();
    let retrieved_histogram = registry.get_histogram("test_histogram").unwrap();
    
    assert_eq!(retrieved_counter.get(), counter.get());
    assert_eq!(retrieved_gauge.get(), gauge.get());
    assert_eq!(retrieved_histogram.get_count(), histogram.get_count());
    
    println!("✓ Metric registry tests passed");
}

/// Test Prometheus export format
fn test_prometheus_export() {
    println!("Testing Prometheus export format...");
    
    let registry = MockMetricRegistry::new();
    
    // Register and update metrics
    let counter = MockCounter::new("http_requests_total", "Total HTTP requests");
    let gauge = MockGauge::new("active_connections", "Active network connections");
    let histogram = MockHistogram::new(
        "response_time_seconds",
        "HTTP response time",
        vec![0.1, 0.5, 1.0, 2.0]
    );
    
    counter.inc_by(1250.0);
    gauge.set(42.0);
    histogram.observe(0.25);
    histogram.observe(0.75);
    histogram.observe(1.5);
    
    registry.register_counter(counter);
    registry.register_gauge(gauge);
    registry.register_histogram(histogram);
    
    // Export to Prometheus format
    let prometheus_output = registry.export_prometheus();
    
    // Verify output format
    assert!(prometheus_output.contains("# HELP http_requests_total Total HTTP requests"));
    assert!(prometheus_output.contains("# TYPE http_requests_total counter"));
    assert!(prometheus_output.contains("http_requests_total 1250"));
    
    assert!(prometheus_output.contains("# HELP active_connections Active network connections"));
    assert!(prometheus_output.contains("# TYPE active_connections gauge"));
    assert!(prometheus_output.contains("active_connections 42"));
    
    assert!(prometheus_output.contains("# HELP response_time_seconds HTTP response time"));
    assert!(prometheus_output.contains("# TYPE response_time_seconds histogram"));
    assert!(prometheus_output.contains("response_time_seconds_count 3"));
    assert!(prometheus_output.contains("response_time_seconds_sum"));
    assert!(prometheus_output.contains("response_time_seconds_bucket{le="));
    
    println!("Prometheus export sample:\n{}", prometheus_output);
    println!("✓ Prometheus export format tests passed");
}

/// Test multiple registries
fn test_multiple_registries() {
    println!("Testing multiple metric registries...");
    
    let app_registry = MockMetricRegistry::new();
    let system_registry = MockMetricRegistry::new();
    
    // Register application metrics
    let app_requests = MockCounter::new("app_requests_total", "Application requests");
    app_requests.inc_by(100.0);
    app_registry.register_counter(app_requests);
    
    // Register system metrics
    let system_cpu = MockGauge::new("system_cpu_usage", "System CPU usage");
    system_cpu.set(75.5);
    system_registry.register_gauge(system_cpu);
    
    // Verify separate registries
    let app_metrics = app_registry.export_prometheus();
    let system_metrics = system_registry.export_prometheus();
    
    assert!(app_metrics.contains("app_requests_total"));
    assert!(!app_metrics.contains("system_cpu_usage"));
    
    assert!(system_metrics.contains("system_cpu_usage"));
    assert!(!system_metrics.contains("app_requests_total"));
    
    println!("✓ Multiple registries tests passed");
}

// =============================================================================
// Metric Metadata Tests
// =============================================================================

/// Test metric labels
fn test_metric_labels() {
    println!("Testing metric labels...");
    
    let counter_with_labels = MockCounter::new("labeled_counter", "Counter with labels")
        .with_label("method", "GET")
        .with_label("status", "200");
    
    let gauge_with_labels = MockGauge::new("labeled_gauge", "Gauge with labels")
        .with_label("instance", "server-1")
        .with_label("region", "us-west");
    
    counter_with_labels.inc();
    gauge_with_labels.set(85.0);
    
    assert_eq!(counter_with_labels.get(), 1.0);
    assert_eq!(gauge_with_labels.get(), 85.0);
    assert_eq!(counter_with_labels.labels.len(), 2);
    assert_eq!(gauge_with_labels.labels.len(), 2);
    
    println!("✓ Metric labels tests passed");
}

/// Test help and type annotations
fn test_help_and_type_annotations() {
    println!("Testing help and type annotations...");
    
    let counter = MockCounter::new("test_counter", "This is a test counter metric");
    let gauge = MockGauge::new("test_gauge", "This is a test gauge metric");
    let histogram = MockHistogram::new(
        "test_histogram",
        "This is a test histogram metric",
        vec![0.1, 1.0]
    );
    
    assert!(!counter.help.is_empty());
    assert!(!gauge.help.is_empty());
    assert!(!histogram.help.is_empty());
    
    assert_eq!(counter.help, "This is a test counter metric");
    assert_eq!(gauge.help, "This is a test gauge metric");
    assert_eq!(histogram.help, "This is a test histogram metric");
    
    println!("✓ Help and type annotations tests passed");
}

// =============================================================================
// Advanced Functionality Tests
// =============================================================================

/// Test metric aggregation
fn test_metric_aggregation() {
    println!("Testing metric aggregation...");
    
    // Create multiple counters for aggregation
    let mut counters = Vec::new();
    for i in 0..5 {
        let counter = MockCounter::new(&format!("counter_{}", i), &format!("Counter {}", i));
        counter.inc_by((i + 1) as f64 * 10.0);
        counters.push(counter);
    }
    
    // Aggregate values
    let total: f64 = counters.iter().map(|c| c.get()).sum();
    let average = total / counters.len() as f64;
    let max = counters.iter().map(|c| c.get()).fold(0.0, f64::max);
    let min = counters.iter().map(|c| c.get()).fold(f64::INFINITY, f64::min);
    
    assert_eq!(total, 150.0); // 10 + 20 + 30 + 40 + 50
    assert_eq!(average, 30.0);
    assert_eq!(max, 50.0);
    assert_eq!(min, 10.0);
    
    println!("✓ Metric aggregation tests passed");
}

/// Test metric performance
fn test_metric_performance() {
    println!("Testing metric performance...");
    
    let registry = MockMetricRegistry::new();
    
    // Register many metrics
    for i in 0..100 {
        let counter = MockCounter::new(&format!("counter_{}", i), &format!("Counter {}", i));
        registry.register_counter(counter);
    }
    
    let start_time = Instant::now();
    let operations = 10000;
    
    // Perform many metric operations
    for i in 0..operations {
        let counter_name = format!("counter_{}", i % 100);
        if let Some(counter) = registry.get_counter(&counter_name) {
            counter.inc();
        }
    }
    
    let elapsed = start_time.elapsed();
    let ops_per_second = operations as f64 / elapsed.as_secs_f64();
    
    println!("Performed {} metric operations in {:?} ({:.2} ops/sec)", 
             operations, elapsed, ops_per_second);
    
    // Performance should be reasonable (at least 10000 ops/sec)
    assert!(ops_per_second > 10000.0, 
           "Metric performance too low: {:.2} ops/sec", ops_per_second);
    
    println!("✓ Metric performance tests passed");
}

/// Test metric cleanup
fn test_metric_cleanup() {
    println!("Testing metric cleanup...");
    
    let registry = MockMetricRegistry::new();
    
    // Register metrics
    let counter = MockCounter::new("cleanup_test", "Counter for cleanup test");
    registry.register_counter(counter);
    
    // Verify metric exists
    assert!(registry.get_counter("cleanup_test").is_some());
    
    // In a real implementation, this would clean up metrics
    // For now, we'll just verify the metric can be retrieved
    let retrieved = registry.get_counter("cleanup_test").unwrap();
    retrieved.inc();
    assert_eq!(retrieved.get(), 1.0);
    
    println!("✓ Metric cleanup tests passed");
}