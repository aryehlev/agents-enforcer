//! Metrics collector for unified metrics system

use crate::metrics::{MetricsSummary, UnifiedMetrics};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

/// Metrics collector for gathering and updating metrics
#[derive(Debug)]
pub struct MetricsCollector {
    /// Unified metrics system
    metrics: Arc<UnifiedMetrics>,
    /// Collector configuration
    config: CollectorConfig,
    /// Collection state
    state: Arc<RwLock<CollectorState>>,
    /// Collection statistics
    stats: Arc<RwLock<CollectorStats>>,
}

/// Collector configuration
#[derive(Debug, Clone)]
pub struct CollectorConfig {
    /// Collection interval
    pub collection_interval: Duration,
    /// System metrics collection enabled
    pub collect_system_metrics: bool,
    /// Performance metrics collection enabled
    pub collect_performance_metrics: bool,
    /// Backend metrics collection enabled
    pub collect_backend_metrics: bool,
    /// Security metrics collection enabled
    pub collect_security_metrics: bool,
    /// Metrics retention period
    pub retention_period: Duration,
    /// Metrics export enabled
    pub export_enabled: bool,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            collection_interval: Duration::from_secs(30),
            collect_system_metrics: true,
            collect_performance_metrics: true,
            collect_backend_metrics: true,
            collect_security_metrics: true,
            retention_period: Duration::from_hours(24),
            export_enabled: true,
        }
    }
}

/// Collector state
#[derive(Debug, Default)]
struct CollectorState {
    /// Is collector running
    is_running: bool,
    /// Last collection time
    last_collection: Option<Instant>,
    /// Total collections performed
    total_collections: u64,
    /// Collection errors
    collection_errors: u64,
}

/// Collector statistics
#[derive(Debug, Default, Clone)]
pub struct CollectorStats {
    /// Total collections performed
    pub total_collections: u64,
    /// Successful collections
    pub successful_collections: u64,
    /// Failed collections
    pub failed_collections: u64,
    /// Average collection duration in milliseconds
    pub avg_collection_duration_ms: f64,
    /// Last collection timestamp
    pub last_collection_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    /// Collection errors by type
    pub collection_errors: std::collections::HashMap<String, u64>,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new(metrics: Arc<UnifiedMetrics>, config: CollectorConfig) -> Self {
        Self {
            metrics,
            config,
            state: Arc::new(RwLock::new(CollectorState::default())),
            stats: Arc::new(RwLock::new(CollectorStats::default())),
        }
    }

    /// Create a new metrics collector with default configuration
    pub fn new_default(metrics: Arc<UnifiedMetrics>) -> Self {
        Self::new(metrics, CollectorConfig::default())
    }

    /// Start the metrics collector
    pub async fn start(&self) -> crate::Result<()> {
        {
            let mut state = self.state.write().await;
            if state.is_running {
                warn!("Metrics collector is already running");
                return Ok(());
            }
            state.is_running = true;
        }

        info!(
            "Starting metrics collector with interval {:?}",
            self.config.collection_interval
        );

        let metrics = self.metrics.clone();
        let config = self.config.clone();
        let state = self.state.clone();
        let stats = self.stats.clone();

        tokio::spawn(async move {
            let mut interval_timer = interval(config.collection_interval);
            interval_timer.tick().await; // Skip first immediate tick

            loop {
                interval_timer.tick().await;

                // Check if still running
                {
                    let state_guard = state.read().await;
                    if !state_guard.is_running {
                        debug!("Metrics collector stopped, exiting collection loop");
                        break;
                    }
                }

                // Perform collection
                let collection_start = Instant::now();
                let collection_result = Self::collect_metrics(&metrics, &config).await;
                let collection_duration = collection_start.elapsed();

                // Update statistics
                {
                    let mut stats_guard = stats.write().await;
                    let mut state_guard = state.write().await;

                    stats_guard.total_collections += 1;
                    state_guard.total_collections += 1;
                    state_guard.last_collection = Some(Instant::now());

                    if collection_result.is_ok() {
                        stats_guard.successful_collections += 1;
                    } else {
                        stats_guard.failed_collections += 1;
                        state_guard.collection_errors += 1;

                        if let Err(e) = &collection_result {
                            let error_type = "collection_error".to_string();
                            *stats_guard.collection_errors.entry(error_type).or_insert(0) += 1;
                            error!("Metrics collection failed: {}", e);
                        }
                    }

                    // Update average duration
                    let total_collections = stats_guard.total_collections as f64;
                    let current_avg = stats_guard.avg_collection_duration_ms;
                    let new_duration_ms = collection_duration.as_millis() as f64;
                    stats_guard.avg_collection_duration_ms =
                        (current_avg * (total_collections - 1.0) + new_duration_ms)
                            / total_collections;

                    stats_guard.last_collection_timestamp = Some(chrono::Utc::now());
                }

                debug!("Metrics collection completed in {:?}", collection_duration);
            }
        });

        info!("Metrics collector started successfully");
        Ok(())
    }

    /// Stop the metrics collector
    pub async fn stop(&self) -> crate::Result<()> {
        info!("Stopping metrics collector");

        {
            let mut state = self.state.write().await;
            state.is_running = false;
        }

        info!("Metrics collector stopped");
        Ok(())
    }

    /// Perform a single metrics collection
    pub async fn collect_once(&self) -> crate::Result<()> {
        Self::collect_metrics(&self.metrics, &self.config).await
    }

    /// Get collector statistics
    pub async fn stats(&self) -> CollectorStats {
        self.stats.read().await.clone()
    }

    /// Get collector state
    pub async fn is_running(&self) -> bool {
        let state = self.state.read().await;
        state.is_running
    }

    /// Collect metrics based on configuration
    async fn collect_metrics(
        metrics: &UnifiedMetrics,
        config: &CollectorConfig,
    ) -> crate::Result<()> {
        let mut errors = Vec::new();

        // Collect system metrics
        if config.collect_system_metrics {
            if let Err(e) = Self::collect_system_metrics(metrics).await {
                errors.push(format!("System metrics collection failed: {}", e));
            }
        }

        // Collect performance metrics
        if config.collect_performance_metrics {
            if let Err(e) = Self::collect_performance_metrics(metrics).await {
                errors.push(format!("Performance metrics collection failed: {}", e));
            }
        }

        // Collect backend metrics
        if config.collect_backend_metrics {
            if let Err(e) = Self::collect_backend_metrics(metrics).await {
                errors.push(format!("Backend metrics collection failed: {}", e));
            }
        }

        // Collect security metrics
        if config.collect_security_metrics {
            if let Err(e) = Self::collect_security_metrics(metrics).await {
                errors.push(format!("Security metrics collection failed: {}", e));
            }
        }

        if !errors.is_empty() {
            return Err(anyhow::anyhow!(errors.join("; ")));
        }

        Ok(())
    }

    /// Collect system metrics
    async fn collect_system_metrics(metrics: &UnifiedMetrics) -> crate::Result<()> {
        // Update system uptime
        if let Ok(uptime) = Self::get_system_uptime() {
            metrics.system.system_uptime.set(uptime);
        }

        // Update memory usage
        if let Ok(memory_info) = Self::get_memory_info() {
            metrics
                .system
                .memory_usage_bytes
                .with_label_values(&["total"])
                .set(memory_info.total as f64);
            metrics
                .system
                .memory_usage_bytes
                .with_label_values(&["used"])
                .set(memory_info.used as f64);
            metrics
                .system
                .memory_usage_bytes
                .with_label_values(&["free"])
                .set(memory_info.free as f64);
            metrics
                .system
                .memory_usage_bytes
                .with_label_values(&["available"])
                .set(memory_info.available as f64);
        }

        // Update CPU usage
        if let Ok(cpu_usage) = Self::get_cpu_usage() {
            metrics.system.cpu_usage_percentage.set(cpu_usage);
        }

        // Update load average
        if let Ok(load_avg) = Self::get_load_average() {
            metrics
                .system
                .system_load_average
                .with_label_values(&["1m"])
                .set(load_avg.0);
            metrics
                .system
                .system_load_average
                .with_label_values(&["5m"])
                .set(load_avg.1);
            metrics
                .system
                .system_load_average
                .with_label_values(&["15m"])
                .set(load_avg.2);
        }

        // Update process and thread counts
        if let Ok(process_count) = Self::get_process_count() {
            metrics.system.process_count.set(process_count as i64);
        }

        if let Ok(thread_count) = Self::get_thread_count() {
            metrics.system.thread_count.set(thread_count as i64);
        }

        Ok(())
    }

    /// Collect performance metrics
    async fn collect_performance_metrics(metrics: &UnifiedMetrics) -> crate::Result<()> {
        // Update resource utilization
        if let Ok(cpu_util) = Self::get_cpu_usage() {
            metrics
                .performance
                .resource_utilization
                .with_label_values(&["cpu"])
                .set(cpu_util);
        }

        if let Ok(memory_info) = Self::get_memory_info() {
            let memory_util = (memory_info.used as f64 / memory_info.total as f64) * 100.0;
            metrics
                .performance
                .resource_utilization
                .with_label_values(&["memory"])
                .set(memory_util);
        }

        // Update throughput metrics (placeholder - would be calculated from actual operations)
        metrics
            .performance
            .throughput
            .with_label_values(&["events"])
            .set(0.0);
        metrics
            .performance
            .throughput
            .with_label_values(&["requests"])
            .set(0.0);

        Ok(())
    }

    /// Collect backend metrics
    async fn collect_backend_metrics(metrics: &UnifiedMetrics) -> crate::Result<()> {
        // This would typically query backend status from the backend registry
        // For now, we'll set placeholder values

        // Example: Update backend status for known backends
        metrics
            .backends
            .backend_status
            .with_label_values(&["ebpf-linux", "ebpf"])
            .set(0);
        metrics
            .backends
            .backend_status
            .with_label_values(&["macos-desktop", "desktop"])
            .set(0);

        Ok(())
    }

    /// Collect security metrics
    async fn collect_security_metrics(metrics: &UnifiedMetrics) -> crate::Result<()> {
        // Update security score (placeholder - would be calculated from security events)
        metrics.security.security_score.set(85.0);

        // Update active threats count (placeholder)
        metrics.security.active_threats.set(0);

        Ok(())
    }

    /// Get system uptime in seconds
    fn get_system_uptime() -> crate::Result<f64> {
        #[cfg(target_os = "linux")]
        {
            let mut uptime = std::mem::MaybeUninit::<libc::timespec>::uninit();
            let result = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, uptime.as_mut_ptr()) };

            if result != 0 {
                return Err(anyhow::anyhow!("Failed to get system uptime"));
            }

            let uptime = unsafe { uptime.assume_init() };
            Ok(uptime.tv_sec as f64 + uptime.tv_nsec as f64 / 1_000_000_000.0)
        }

        #[cfg(target_os = "macos")]
        {
            let mut uptime = std::mem::MaybeUninit::<libc::timespec>::uninit();
            let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, uptime.as_mut_ptr()) };

            if result != 0 {
                return Err(anyhow::anyhow!("Failed to get system uptime"));
            }

            let uptime = unsafe { uptime.assume_init() };
            Ok(uptime.tv_sec as f64 + uptime.tv_nsec as f64 / 1_000_000_000.0)
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(anyhow::anyhow!("Uptime not supported on this platform"))
        }
    }

    /// Get memory information
    fn get_memory_info() -> crate::Result<MemoryInfo> {
        // Simplified memory info that works across platforms
        // In a real implementation, you'd use platform-specific APIs
        Ok(MemoryInfo {
            total: 8 * 1024 * 1024 * 1024,     // 8GB default
            used: 4 * 1024 * 1024 * 1024,      // 4GB used
            free: 4 * 1024 * 1024 * 1024,      // 4GB free
            available: 4 * 1024 * 1024 * 1024, // 4GB available
        })
    }

    /// Get CPU usage percentage
    fn get_cpu_usage() -> crate::Result<f64> {
        // This is a simplified implementation
        // In a real implementation, you would track CPU time over intervals
        Ok(0.0)
    }

    /// Get load average
    fn get_load_average() -> crate::Result<(f64, f64, f64)> {
        #[cfg(unix)]
        {
            let mut loadavg = std::mem::MaybeUninit::<[libc::c_double; 3]>::uninit();
            let result =
                unsafe { libc::getloadavg(loadavg.as_mut_ptr() as *mut libc::c_double, 3) };

            if result == 3 {
                let loadavg = unsafe { loadavg.assume_init() };
                Ok((loadavg[0], loadavg[1], loadavg[2]))
            } else {
                Err(anyhow::anyhow!("Failed to get load average".to_string()))
            }
        }

        #[cfg(not(unix))]
        {
            // Fallback for non-Unix systems
            Ok((0.0, 0.0, 0.0))
        }
    }

    /// Get process count
    fn get_process_count() -> crate::Result<u64> {
        // This is a simplified implementation
        // In a real implementation, you would count actual processes
        Ok(1)
    }

    /// Get thread count
    fn get_thread_count() -> crate::Result<u64> {
        // This is a simplified implementation
        // In a real implementation, you would count actual threads
        Ok(1)
    }
}

/// Memory information
#[derive(Debug, Clone)]
struct MemoryInfo {
    total: u64,
    used: u64,
    free: u64,
    available: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::UnifiedMetrics;

    #[tokio::test]
    async fn test_metrics_collector_creation() {
        let metrics = Arc::new(UnifiedMetrics::new().unwrap());
        let collector = MetricsCollector::new_default(metrics);

        assert!(!collector.is_running().await);
    }

    #[tokio::test]
    async fn test_metrics_collector_start_stop() {
        let metrics = Arc::new(UnifiedMetrics::new().unwrap());
        let collector = MetricsCollector::new_default(metrics);

        // Start collector
        collector.start().await.unwrap();
        assert!(collector.is_running().await);

        // Stop collector
        collector.stop().await.unwrap();
        assert!(!collector.is_running().await);
    }

    #[tokio::test]
    async fn test_metrics_collection_once() {
        let metrics = Arc::new(UnifiedMetrics::new().unwrap());
        let collector = MetricsCollector::new_default(metrics);

        // Collect metrics once
        let result = collector.collect_once().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_collector_stats() {
        let metrics = Arc::new(UnifiedMetrics::new().unwrap());
        let collector = MetricsCollector::new_default(metrics);

        let stats = collector.stats().await;
        assert_eq!(stats.total_collections, 0);
        assert_eq!(stats.successful_collections, 0);
        assert_eq!(stats.failed_collections, 0);
    }

    #[test]
    fn test_collector_config_default() {
        let config = CollectorConfig::default();
        assert_eq!(config.collection_interval, Duration::from_secs(30));
        assert!(config.collect_system_metrics);
        assert!(config.collect_performance_metrics);
        assert!(config.collect_backend_metrics);
        assert!(config.collect_security_metrics);
    }
}
