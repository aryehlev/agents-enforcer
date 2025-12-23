//! Metrics exporter for unified metrics system

use crate::metrics::{UnifiedMetrics, MetricsSummary};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use tracing::{debug, info, warn, error};

/// Metrics exporter for exporting metrics to various destinations
#[derive(Debug)]
pub struct MetricsExporter {
    /// Unified metrics system
    metrics: Arc<UnifiedMetrics>,
    /// Export configurations
    export_configs: Arc<RwLock<HashMap<String, ExportConfig>>>,
    /// Export destinations
    destinations: Arc<RwLock<HashMap<String, Box<dyn MetricsExportDestination + Send + Sync>>>>,
    /// Export statistics
    stats: Arc<RwLock<ExportStats>>,
}

/// Export configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportConfig {
    /// Export ID
    pub id: String,
    /// Export name
    pub name: String,
    /// Export format
    pub format: ExportFormat,
    /// Destination type
    pub destination: DestinationType,
    /// Export schedule
    pub schedule: Option<ExportSchedule>,
    /// Export options
    pub options: ExportOptions,
    /// Export is enabled
    pub enabled: bool,
}

/// Export format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportFormat {
    /// Prometheus text format
    Prometheus,
    /// JSON format
    Json,
    /// InfluxDB line protocol
    InfluxDB,
    /// Graphite plaintext format
    Graphite,
    /// StatsD format
    StatsD,
    /// Custom format
    Custom(String),
}

/// Destination type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DestinationType {
    /// HTTP endpoint
    Http(HttpDestination),
    /// File destination
    File(FileDestination),
    /// Pushgateway (Prometheus)
    Pushgateway(PushgatewayDestination),
    /// InfluxDB
    InfluxDB(InfluxDBDestination),
    /// Graphite
    Graphite(GraphiteDestination),
    /// StatsD
    StatsD(StatsDDestination),
    /// Custom destination
    Custom(HashMap<String, serde_json::Value>),
}

/// HTTP destination configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpDestination {
    /// URL
    pub url: String,
    /// HTTP method
    pub method: HttpMethod,
    /// Headers
    pub headers: HashMap<String, String>,
    /// Authentication
    pub auth: Option<HttpAuth>,
    /// Timeout in seconds
    pub timeout: Option<u64>,
    /// Retry policy
    pub retry: Option<RetryPolicy>,
}

/// HTTP method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
}

/// HTTP authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HttpAuth {
    /// Bearer token
    Bearer(String),
    /// Basic authentication
    Basic { username: String, password: String },
    /// API key
    ApiKey { key: String, value: String, header: Option<String> },
}

/// Retry policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Maximum number of retries
    pub max_retries: u32,
    /// Initial delay in milliseconds
    pub initial_delay_ms: u64,
    /// Backoff multiplier
    pub backoff_multiplier: f64,
    /// Maximum delay in milliseconds
    pub max_delay_ms: u64,
}

/// File destination configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDestination {
    /// File path
    pub path: String,
    /// Rotation policy
    pub rotation: Option<FileRotation>,
    /// Compression
    pub compression: Option<CompressionType>,
}

/// File rotation policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileRotation {
    /// Rotate by size
    Size(u64),
    /// Rotate by time
    Time(chrono::Duration),
    /// Rotate daily
    Daily,
    /// Rotate hourly
    Hourly,
}

/// Compression type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompressionType {
    /// Gzip compression
    Gzip,
    /// Zip compression
    Zip,
    /// No compression
    None,
}

/// Pushgateway destination configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushgatewayDestination {
    /// Pushgateway URL
    pub url: String,
    /// Job name
    pub job: String,
    /// Instance name
    pub instance: Option<String>,
    /// Grouping labels
    pub grouping_labels: HashMap<String, String>,
}

/// InfluxDB destination configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfluxDBDestination {
    /// Database URL
    pub url: String,
    /// Database name
    pub database: String,
    /// Username
    pub username: Option<String>,
    /// Password
    pub password: Option<String>,
    /// Retention policy
    pub retention_policy: Option<String>,
}

/// Graphite destination configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphiteDestination {
    /// Graphite server address
    pub address: String,
    /// Graphite server port
    pub port: u16,
    /// Prefix for metrics
    pub prefix: Option<String>,
}

/// StatsD destination configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsDDestination {
    /// StatsD server address
    pub address: String,
    /// StatsD server port
    pub port: u16,
    /// Prefix for metrics
    pub prefix: Option<String>,
}

/// Export schedule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportSchedule {
    /// Schedule type
    pub schedule_type: ScheduleType,
    /// Interval (for interval schedules)
    pub interval: Option<chrono::Duration>,
    /// Cron expression (for cron schedules)
    pub cron_expression: Option<String>,
}

/// Schedule type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScheduleType {
    /// Export on interval
    Interval,
    /// Export on cron schedule
    Cron,
    /// Export immediately
    Immediate,
}

/// Export options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportOptions {
    /// Include timestamp
    pub include_timestamp: bool,
    /// Include help text (for Prometheus)
    pub include_help: bool,
    /// Include type information (for Prometheus)
    pub include_type: bool,
    /// Metric name prefix
    pub prefix: Option<String>,
    /// Metric name suffix
    pub suffix: Option<String>,
    /// Custom labels
    pub custom_labels: HashMap<String, String>,
}

/// Export statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExportStats {
    /// Total exports attempted
    pub total_exports: u64,
    /// Successful exports
    pub successful_exports: u64,
    /// Failed exports
    pub failed_exports: u64,
    /// Total metrics exported
    pub total_metrics_exported: u64,
    /// Last export timestamp
    pub last_export_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    /// Export errors by type
    pub export_errors: HashMap<String, u64>,
    /// Export duration statistics
    pub export_duration_ms: ExportDurationStats,
}

/// Export duration statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExportDurationStats {
    /// Minimum duration in milliseconds
    pub min_ms: f64,
    /// Maximum duration in milliseconds
    pub max_ms: f64,
    /// Average duration in milliseconds
    pub avg_ms: f64,
    /// Total exports for duration calculation
    pub count: u64,
}

/// Metrics export destination trait
#[async_trait::async_trait]
pub trait MetricsExportDestination: Send + Sync {
    /// Export metrics to the destination
    async fn export(&self, metrics: &str, format: ExportFormat, options: &ExportOptions) -> crate::Result<()>;
    
    /// Check if destination is healthy
    async fn health_check(&self) -> crate::Result<bool>;
    
    /// Get destination name
    fn name(&self) -> &str;
}

impl MetricsExporter {
    /// Create a new metrics exporter
    pub fn new(metrics: Arc<UnifiedMetrics>) -> Self {
        Self {
            metrics,
            export_configs: Arc::new(RwLock::new(HashMap::new())),
            destinations: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ExportStats::default())),
        }
    }

    /// Add an export configuration
    pub async fn add_export_config(&self, config: ExportConfig) -> crate::Result<()> {
        // Create destination based on type
        let destination: Box<dyn MetricsExportDestination + Send + Sync> = match &config.destination {
            DestinationType::Http(http_config) => {
                Box::new(HttpMetricsDestination::new(http_config.clone()))
            }
            DestinationType::File(file_config) => {
                Box::new(FileMetricsDestination::new(file_config.clone()))
            }
            DestinationType::Pushgateway(pg_config) => {
                Box::new(PushgatewayMetricsDestination::new(pg_config.clone()))
            }
            DestinationType::InfluxDB(influx_config) => {
                Box::new(InfluxDBMetricsDestination::new(influx_config.clone()))
            }
            DestinationType::Graphite(graphite_config) => {
                Box::new(GraphiteMetricsDestination::new(graphite_config.clone()))
            }
            DestinationType::StatsD(statsd_config) => {
                Box::new(StatsDMetricsDestination::new(statsd_config.clone()))
            }
            DestinationType::Custom(_) => {
                return Err(anyhow::anyhow!("Custom destinations not yet implemented".to_string()));
            }
        };

        {
            let mut configs = self.export_configs.write().await;
            configs.insert(config.id.clone(), config);
        }

        {
            let mut destinations = self.destinations.write().await;
            destinations.insert(config.id.clone(), destination);
        }

        Ok(())
    }

    /// Remove an export configuration
    pub async fn remove_export_config(&self, export_id: &str) -> bool {
        let removed_config = {
            let mut configs = self.export_configs.write().await;
            configs.remove(export_id).is_some()
        };

        let removed_destination = {
            let mut destinations = self.destinations.write().await;
            destinations.remove(export_id).is_some()
        };

        removed_config && removed_destination
    }

    /// List export configurations
    pub async fn list_export_configs(&self) -> Vec<ExportConfig> {
        let configs = self.export_configs.read().await;
        configs.values().cloned().collect()
    }

    /// Export metrics to all configured destinations
    pub async fn export_metrics(&self) -> crate::Result<HashMap<String, crate::Result<()>>> {
        let mut results = HashMap::new();
        let configs = self.export_configs.read().await;
        let destinations = self.destinations.read().await;

        for (export_id, config) in configs.iter() {
            if !config.enabled {
                continue;
            }

            // Export to destination
            if let Some(destination) = destinations.get(export_id) {
                let export_start = Instant::now();
                
                // Get metrics in the specified format
                let metrics_data = match config.format {
                    ExportFormat::Prometheus => self.metrics.export_prometheus()?,
                    ExportFormat::Json => self.export_json(&config.options)?,
                    ExportFormat::InfluxDB => self.export_influxdb(&config.options)?,
                    ExportFormat::Graphite => self.export_graphite(&config.options)?,
                    ExportFormat::StatsD => self.export_statsd(&config.options)?,
                    ExportFormat::Custom(_) => {
                        results.insert(export_id.clone(), Err(anyhow::anyhow!("Custom export format not implemented".to_string())));
                        continue;
                    }
                };

                let result = destination.export(&metrics_data, config.format, &config.options).await;
                let export_duration = export_start.elapsed();

                results.insert(export_id.clone(), result);

                // Update statistics
                {
                    let mut stats = self.stats.write().await;
                    stats.total_exports += 1;
                    
                    let duration_ms = export_duration.as_millis() as f64;
                    stats.export_duration_ms.min_ms = stats.export_duration_ms.min_ms.min(duration_ms);
                    stats.export_duration_ms.max_ms = stats.export_duration_ms.max_ms.max(duration_ms);
                    stats.export_duration_ms.count += 1;
                    stats.export_duration_ms.avg_ms = 
                        (stats.export_duration_ms.avg_ms * (stats.export_duration_ms.count - 1) as f64 + duration_ms) 
                        / stats.export_duration_ms.count as f64;

                    if result.is_ok() {
                        stats.successful_exports += 1;
                        stats.last_export_timestamp = Some(chrono::Utc::now());
                    } else {
                        stats.failed_exports += 1;
                        let error_type = "export_failed".to_string();
                        *stats.export_errors.entry(error_type).or_insert(0) += 1;
                    }
                }
            }
        }

        Ok(results)
    }

    /// Export metrics in JSON format
    fn export_json(&self, options: &ExportOptions) -> crate::Result<String> {
        let summary = self.metrics.get_summary();
        let json_data = serde_json::json!({
            "timestamp": chrono::Utc::now(),
            "summary": summary,
            "custom_labels": options.custom_labels
        });

        serde_json::to_string_pretty(&json_data)
            .map_err(|e| anyhow::anyhow!(format!("Failed to serialize metrics to JSON: {}", e)))
    }

    /// Export metrics in InfluxDB line protocol format
    fn export_influxdb(&self, options: &ExportOptions) -> crate::Result<String> {
        let summary = self.metrics.get_summary();
        let timestamp = chrono::Utc::now().timestamp_nanos_opt();
        
        let mut lines = Vec::new();
        
        // Summary metrics
        let measurement = options.prefix.as_deref().unwrap_or("agent_gateway");
        lines.push(format!(
            "{}_summary total_events={},network_blocked={},network_allowed={},file_blocked={},file_allowed={},security_events={},uptime_seconds={} {}",
            measurement,
            summary.total_events,
            summary.network_blocked,
            summary.network_allowed,
            summary.file_blocked,
            summary.file_allowed,
            summary.security_events,
            summary.uptime_seconds,
            timestamp.unwrap_or(0)
        ));

        Ok(lines.join("\n"))
    }

    /// Export metrics in Graphite plaintext format
    fn export_graphite(&self, options: &ExportOptions) -> crate::Result<String> {
        let summary = self.metrics.get_summary();
        let timestamp = chrono::Utc::now().timestamp();
        let prefix = options.prefix.as_deref().unwrap_or("agent_gateway");
        
        let mut lines = Vec::new();
        
        lines.push(format!(
            "{}.total_events {} {}",
            prefix,
            summary.total_events,
            timestamp
        ));
        
        lines.push(format!(
            "{}.network.network_blocked {} {}",
            prefix,
            summary.network_blocked,
            timestamp
        ));
        
        lines.push(format!(
            "{}.network.network_allowed {} {}",
            prefix,
            summary.network_allowed,
            timestamp
        ));
        
        lines.push(format!(
            "{}.file.file_blocked {} {}",
            prefix,
            summary.file_blocked,
            timestamp
        ));
        
        lines.push(format!(
            "{}.file.file_allowed {} {}",
            prefix,
            summary.file_allowed,
            timestamp
        ));
        
        lines.push(format!(
            "{}.security.security_events {} {}",
            prefix,
            summary.security_events,
            timestamp
        ));
        
        lines.push(format!(
            "{}.system.uptime_seconds {} {}",
            prefix,
            summary.uptime_seconds,
            timestamp
        ));

        Ok(lines.join("\n"))
    }

    /// Export metrics in StatsD format
    fn export_statsd(&self, options: &ExportOptions) -> crate::Result<String> {
        let summary = self.metrics.get_summary();
        let prefix = options.prefix.as_deref().unwrap_or("agent_gateway");
        
        let mut lines = Vec::new();
        
        lines.push(format!(
            "{}.total_events:{}|c",
            prefix,
            summary.total_events
        ));
        
        lines.push(format!(
            "{}.network.network_blocked:{}|c",
            prefix,
            summary.network_blocked
        ));
        
        lines.push(format!(
            "{}.network.network_allowed:{}|c",
            prefix,
            summary.network_allowed
        ));
        
        lines.push(format!(
            "{}.file.file_blocked:{}|c",
            prefix,
            summary.file_blocked
        ));
        
        lines.push(format!(
            "{}.file.file_allowed:{}|c",
            prefix,
            summary.file_allowed
        ));
        
        lines.push(format!(
            "{}.security.security_events:{}|c",
            prefix,
            summary.security_events
        ));
        
        lines.push(format!(
            "{}.system.uptime_seconds:{}|g",
            prefix,
            summary.uptime_seconds as u64
        ));

        Ok(lines.join("\n"))
    }

    /// Get export statistics
    pub async fn stats(&self) -> ExportStats {
        self.stats.read().await.clone()
    }
}

// Placeholder implementations for destination types
#[derive(Debug)]
pub struct HttpMetricsDestination {
    config: HttpDestination,
}

impl HttpMetricsDestination {
    pub fn new(config: HttpDestination) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl MetricsExportDestination for HttpMetricsDestination {
    async fn export(&self, _metrics: &str, _format: ExportFormat, _options: &ExportOptions) -> crate::Result<()> {
        Err(anyhow::anyhow!("HTTP metrics export not yet implemented".to_string()))
    }

    async fn health_check(&self) -> crate::Result<bool> {
        Ok(true) // Placeholder
    }

    fn name(&self) -> &str {
        "http"
    }
}

#[derive(Debug)]
pub struct FileMetricsDestination {
    config: FileDestination,
}

impl FileMetricsDestination {
    pub fn new(config: FileDestination) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl MetricsExportDestination for FileMetricsDestination {
    async fn export(&self, metrics: &str, _format: ExportFormat, _options: &ExportOptions) -> crate::Result<()> {
        tokio::fs::write(&self.config.path, metrics).await
            .map_err(|e| anyhow::anyhow!(format!("Failed to write metrics to file: {}", e)))?;
        Ok(())
    }

    async fn health_check(&self) -> crate::Result<bool> {
        // Check if we can write to the file path
        let test_content = "health_check";
        match tokio::fs::write(&self.config.path, test_content).await {
            Ok(_) => {
                let _ = tokio::fs::remove_file(&self.config.path).await;
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    fn name(&self) -> &str {
        "file"
    }
}

#[derive(Debug)]
pub struct PushgatewayMetricsDestination {
    config: PushgatewayDestination,
}

impl PushgatewayMetricsDestination {
    pub fn new(config: PushgatewayDestination) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl MetricsExportDestination for PushgatewayMetricsDestination {
    async fn export(&self, _metrics: &str, _format: ExportFormat, _options: &ExportOptions) -> crate::Result<()> {
        Err(anyhow::anyhow!("Pushgateway metrics export not yet implemented".to_string()))
    }

    async fn health_check(&self) -> crate::Result<bool> {
        Ok(true) // Placeholder
    }

    fn name(&self) -> &str {
        "pushgateway"
    }
}

#[derive(Debug)]
pub struct InfluxDBMetricsDestination {
    config: InfluxDBDestination,
}

impl InfluxDBMetricsDestination {
    pub fn new(config: InfluxDBDestination) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl MetricsExportDestination for InfluxDBMetricsDestination {
    async fn export(&self, _metrics: &str, _format: ExportFormat, _options: &ExportOptions) -> crate::Result<()> {
        Err(anyhow::anyhow!("InfluxDB metrics export not yet implemented".to_string()))
    }

    async fn health_check(&self) -> crate::Result<bool> {
        Ok(true) // Placeholder
    }

    fn name(&self) -> &str {
        "influxdb"
    }
}

#[derive(Debug)]
pub struct GraphiteMetricsDestination {
    config: GraphiteDestination,
}

impl GraphiteMetricsDestination {
    pub fn new(config: GraphiteDestination) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl MetricsExportDestination for GraphiteMetricsDestination {
    async fn export(&self, _metrics: &str, _format: ExportFormat, _options: &ExportOptions) -> crate::Result<()> {
        Err(anyhow::anyhow!("Graphite metrics export not yet implemented".to_string()))
    }

    async fn health_check(&self) -> crate::Result<bool> {
        Ok(true) // Placeholder
    }

    fn name(&self) -> &str {
        "graphite"
    }
}

#[derive(Debug)]
pub struct StatsDMetricsDestination {
    config: StatsDDestination,
}

impl StatsDMetricsDestination {
    pub fn new(config: StatsDDestination) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl MetricsExportDestination for StatsDMetricsDestination {
    async fn export(&self, _metrics: &str, _format: ExportFormat, _options: &ExportOptions) -> crate::Result<()> {
        Err(anyhow::anyhow!("StatsD metrics export not yet implemented".to_string()))
    }

    async fn health_check(&self) -> crate::Result<bool> {
        Ok(true) // Placeholder
    }

    fn name(&self) -> &str {
        "statsd"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::UnifiedMetrics;

    #[tokio::test]
    async fn test_metrics_exporter_creation() {
        let metrics = Arc::new(UnifiedMetrics::new().unwrap());
        let exporter = MetricsExporter::new(metrics);
        
        let stats = exporter.stats().await;
        assert_eq!(stats.total_exports, 0);
        assert_eq!(stats.successful_exports, 0);
        assert_eq!(stats.failed_exports, 0);
    }

    #[tokio::test]
    async fn test_file_export_config() {
        let metrics = Arc::new(UnifiedMetrics::new().unwrap());
        let exporter = MetricsExporter::new(metrics);

        let export_config = ExportConfig {
            id: "test_file".to_string(),
            name: "Test File Export".to_string(),
            format: ExportFormat::Prometheus,
            destination: DestinationType::File(FileDestination {
                path: "/tmp/test_metrics.prom".to_string(),
                rotation: None,
                compression: None,
            }),
            schedule: None,
            options: ExportOptions {
                include_timestamp: true,
                include_help: true,
                include_type: true,
                prefix: None,
                suffix: None,
                custom_labels: HashMap::new(),
            },
            enabled: true,
        };

        exporter.add_export_config(export_config).await.unwrap();

        let configs = exporter.list_export_configs().await;
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].id, "test_file");
    }

    #[tokio::test]
    async fn test_export_formats() {
        let metrics = Arc::new(UnifiedMetrics::new().unwrap());
        let exporter = MetricsExporter::new(metrics);

        let options = ExportOptions {
            include_timestamp: true,
            include_help: true,
            include_type: true,
            prefix: Some("test".to_string()),
            suffix: None,
            custom_labels: HashMap::new(),
        };

        // Test JSON export
        let json_result = exporter.export_json(&options);
        assert!(json_result.is_ok());

        // Test InfluxDB export
        let influx_result = exporter.export_influxdb(&options);
        assert!(influx_result.is_ok());

        // Test Graphite export
        let graphite_result = exporter.export_graphite(&options);
        assert!(graphite_result.is_ok());

        // Test StatsD export
        let statsd_result = exporter.export_statsd(&options);
        assert!(statsd_result.is_ok());
    }
}