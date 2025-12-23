//! Common types for unified metrics system

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Metric value types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricValue {
    /// Counter value
    Counter(u64),
    /// Gauge value
    Gauge(f64),
    /// Histogram value
    Histogram(HistogramValue),
    /// Summary value
    Summary(SummaryValue),
    /// Untyped value
    Untyped(f64),
}

/// Histogram value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramValue {
    /// Sample count
    pub sample_count: u64,
    /// Sample sum
    pub sample_sum: f64,
    /// Buckets
    pub buckets: Vec<HistogramBucket>,
}

/// Histogram bucket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramBucket {
    /// Upper bound (inclusive)
    pub upper_bound: f64,
    /// Cumulative count
    pub cumulative_count: u64,
}

/// Summary value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummaryValue {
    /// Sample count
    pub sample_count: u64,
    /// Sample sum
    pub sample_sum: f64,
    /// Quantiles
    pub quantiles: Vec<Quantile>,
}

/// Quantile value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quantile {
    /// Quantile (0.0 to 1.0)
    pub quantile: f64,
    /// Value at quantile
    pub value: f64,
}

/// Metric family
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricFamily {
    /// Metric name
    pub name: String,
    /// Metric help text
    pub help: String,
    /// Metric type
    pub r#type: MetricType,
    /// Metrics
    pub metrics: Vec<Metric>,
}

/// Metric type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetricType {
    /// Counter metric
    Counter,
    /// Gauge metric
    Gauge,
    /// Histogram metric
    Histogram,
    /// Summary metric
    Summary,
    /// Untyped metric
    Untyped,
}

/// Metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric {
    /// Metric labels
    pub labels: HashMap<String, String>,
    /// Metric value
    pub value: MetricValue,
    /// Timestamp (optional)
    pub timestamp: Option<i64>,
}

/// Metric label pair
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LabelPair {
    /// Label name
    pub name: String,
    /// Label value
    pub value: String,
}

/// Time series
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeries {
    /// Metric name
    pub name: String,
    /// Labels
    pub labels: HashMap<String, String>,
    /// Samples
    pub samples: Vec<Sample>,
}

/// Sample
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    /// Timestamp
    pub timestamp: i64,
    /// Value
    pub value: f64,
}

/// Query result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    /// Result type
    pub result_type: ResultType,
    /// Result data
    pub data: ResultData,
}

/// Result type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResultType {
    /// Vector result
    Vector,
    /// Matrix result
    Matrix,
    /// Scalar result
    Scalar,
    /// String result
    String,
}

/// Result data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResultData {
    /// Vector data
    Vector(Vec<TimeSeries>),
    /// Matrix data
    Matrix(Vec<TimeSeries>),
    /// Scalar data
    Scalar(ScalarData),
    /// String data
    String(StringData),
}

/// Scalar data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalarData {
    /// Timestamp
    pub timestamp: i64,
    /// Value
    pub value: f64,
}

/// String data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringData {
    /// Timestamp
    pub timestamp: i64,
    /// Value
    pub value: String,
}

/// Metric metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricMetadata {
    /// Metric name
    pub name: String,
    /// Metric help text
    pub help: String,
    /// Metric type
    pub r#type: MetricType,
    /// Metric unit (optional)
    pub unit: Option<String>,
    /// Metric labels (optional)
    pub labels: Option<HashMap<String, String>>,
}

/// Metric descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDescriptor {
    /// Metric name
    pub name: String,
    /// Metric description
    pub description: String,
    /// Metric type
    pub r#type: MetricType,
    /// Metric unit
    pub unit: String,
    /// Label names
    pub label_names: Vec<String>,
    /// Default label values
    pub default_labels: HashMap<String, String>,
}

/// Metric filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricFilter {
    /// Name pattern (optional)
    pub name_pattern: Option<String>,
    /// Label filters
    pub label_filters: HashMap<String, String>,
    /// Metric type filter (optional)
    pub metric_type: Option<MetricType>,
}

/// Metric aggregation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricAggregation {
    /// Aggregation operation
    pub operation: AggregationOperation,
    /// Grouping labels
    pub by: Vec<String>,
    /// Parameters
    pub parameters: HashMap<String, String>,
}

/// Aggregation operation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AggregationOperation {
    /// Sum aggregation
    Sum,
    /// Average aggregation
    Avg,
    /// Min aggregation
    Min,
    /// Max aggregation
    Max,
    /// Count aggregation
    Count,
    /// Group by aggregation
    GroupBy,
    /// TopK aggregation
    TopK,
    /// BottomK aggregation
    BottomK,
    /// Quantile aggregation
    Quantile,
    /// Standard deviation aggregation
    Stddev,
    /// Standard variance aggregation
    Stdvar,
}

/// Metric query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricQuery {
    /// Query string
    pub query: String,
    /// Time range
    pub time_range: TimeRange,
    /// Step interval
    pub step: Option<std::time::Duration>,
    /// Timeout
    pub timeout: Option<std::time::Duration>,
}

/// Time range
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    /// Start time
    pub start: chrono::DateTime<chrono::Utc>,
    /// End time
    pub end: chrono::DateTime<chrono::Utc>,
}

/// Metric alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricAlert {
    /// Alert name
    pub name: String,
    /// Alert description
    pub description: String,
    /// Query expression
    pub query: String,
    /// Alert condition
    pub condition: AlertCondition,
    /// Alert severity
    pub severity: AlertSeverity,
    /// Alert labels
    pub labels: HashMap<String, String>,
    /// Alert annotations
    pub annotations: HashMap<String, String>,
    /// Alert state
    pub state: AlertState,
    /// Last evaluation timestamp
    pub last_evaluation: Option<chrono::DateTime<chrono::Utc>>,
}

/// Alert condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertCondition {
    /// Condition operator
    pub operator: ComparisonOperator,
    /// Threshold value
    pub threshold: f64,
    /// Evaluation duration
    pub for_duration: Option<std::time::Duration>,
}

/// Comparison operator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComparisonOperator {
    /// Equal to
    Eq,
    /// Not equal to
    Ne,
    /// Greater than
    Gt,
    /// Greater than or equal to
    Gte,
    /// Less than
    Lt,
    /// Less than or equal to
    Lte,
}

/// Alert severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertSeverity {
    /// Critical severity
    Critical,
    /// High severity
    High,
    /// Warning severity
    Warning,
    /// Info severity
    Info,
}

/// Alert state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertState {
    /// Alert is firing
    Firing,
    /// Alert is resolved
    Resolved,
    /// Alert is pending
    Pending,
    /// Alert is inactive
    Inactive,
}

/// Metric rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricRule {
    /// Rule name
    pub name: String,
    /// Rule expression
    pub expression: String,
    /// Rule type
    pub rule_type: RuleType,
    /// Rule labels
    pub labels: HashMap<String, String>,
    /// Rule annotations
    pub annotations: HashMap<String, String>,
    /// Rule is enabled
    pub enabled: bool,
}

/// Rule type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleType {
    /// Recording rule
    Recording,
    /// Alerting rule
    Alerting,
}

/// Metric target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricTarget {
    /// Target name
    pub name: String,
    /// Target address
    pub address: String,
    /// Target type
    pub target_type: TargetType,
    /// Target labels
    pub labels: HashMap<String, String>,
    /// Scrape interval
    pub scrape_interval: std::time::Duration,
    /// Scrape timeout
    pub scrape_timeout: std::time::Duration,
    /// Target is enabled
    pub enabled: bool,
}

/// Target type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetType {
    /// HTTP target
    Http,
    /// gRPC target
    Grpc,
    /// Custom target
    Custom,
}

/// Metric scrape config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrapeConfig {
    /// Job name
    pub job_name: String,
    /// Scrape interval
    pub scrape_interval: std::time::Duration,
    /// Scrape timeout
    pub scrape_timeout: std::time::Duration,
    /// Metrics path
    pub metrics_path: String,
    /// Scheme (http/https)
    pub scheme: String,
    /// Static targets
    pub static_configs: Vec<StaticConfig>,
    /// Relabel configs
    pub relabel_configs: Vec<RelabelConfig>,
    /// Metric relabel configs
    pub metric_relabel_configs: Vec<RelabelConfig>,
}

/// Static config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticConfig {
    /// Targets
    pub targets: Vec<String>,
    /// Labels
    pub labels: HashMap<String, String>,
}

/// Relabel config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelabelConfig {
    /// Source labels
    pub source_labels: Vec<String>,
    /// Separator
    pub separator: String,
    /// Target label
    pub target_label: String,
    /// Regex pattern
    pub regex: String,
    /// Replacement string
    pub replacement: String,
    /// Action
    pub action: RelabelAction,
}

/// Relabel action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelabelAction {
    /// Replace action
    Replace,
    /// Keep action
    Keep,
    /// Drop action
    Drop,
    /// Hashmod action
    Hashmod,
    /// Labelmap action
    Labelmap,
    /// Labeldrop action
    Labeldrop,
    /// Labelkeep action
    Labelkeep,
}

/// Metric format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetricFormat {
    /// Prometheus format
    Prometheus,
    /// OpenMetrics format
    OpenMetrics,
    /// JSON format
    Json,
    /// InfluxDB format
    InfluxDB,
    /// Graphite format
    Graphite,
    /// StatsD format
    StatsD,
}

/// Metric export options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricExportOptions {
    /// Export format
    pub format: MetricFormat,
    /// Include timestamp
    pub include_timestamp: bool,
    /// Include help text
    pub include_help: bool,
    /// Include type information
    pub include_type: bool,
    /// Metric name prefix
    pub prefix: Option<String>,
    /// Metric name suffix
    pub suffix: Option<String>,
    /// Custom labels
    pub custom_labels: HashMap<String, String>,
}

/// Metric health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetricHealthStatus {
    /// Healthy
    Healthy,
    /// Warning
    Warning,
    /// Critical
    Critical,
    /// Unknown
    Unknown,
}

/// Metric health check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricHealthCheck {
    /// Check name
    pub name: String,
    /// Check description
    pub description: String,
    /// Health status
    pub status: MetricHealthStatus,
    /// Last check timestamp
    pub last_check: chrono::DateTime<chrono::Utc>,
    /// Check duration
    pub duration: std::time::Duration,
    /// Error message (if any)
    pub error: Option<String>,
}

/// Metric statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricStatistics {
    /// Total metrics
    pub total_metrics: u64,
    /// Metrics by type
    pub metrics_by_type: HashMap<MetricType, u64>,
    /// Total samples
    pub total_samples: u64,
    /// Samples per second
    pub samples_per_second: f64,
    /// Memory usage in bytes
    pub memory_usage_bytes: u64,
    /// Disk usage in bytes
    pub disk_usage_bytes: u64,
    /// Last scrape timestamp
    pub last_scrape_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    /// Scrape duration
    pub scrape_duration: std::time::Duration,
    /// Scrape errors
    pub scrape_errors: u64,
}

impl Default for MetricValue {
    fn default() -> Self {
        Self::Gauge(0.0)
    }
}

impl Default for MetricType {
    fn default() -> Self {
        Self::Untyped
    }
}

impl Default for ResultType {
    fn default() -> Self {
        Self::Vector
    }
}

impl Default for AlertSeverity {
    fn default() -> Self {
        Self::Warning
    }
}

impl Default for AlertState {
    fn default() -> Self {
        Self::Inactive
    }
}

impl Default for RuleType {
    fn default() -> Self {
        Self::Recording
    }
}

impl Default for TargetType {
    fn default() -> Self {
        Self::Http
    }
}

impl Default for RelabelAction {
    fn default() -> Self {
        Self::Replace
    }
}

impl Default for MetricFormat {
    fn default() -> Self {
        Self::Prometheus
    }
}

impl Default for MetricHealthStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_metric_value_serialization() {
        let value = MetricValue::Counter(42);
        let serialized = serde_json::to_string(&value).unwrap();
        let deserialized: MetricValue = serde_json::from_str(&serialized).unwrap();
        
        match deserialized {
            MetricValue::Counter(count) => assert_eq!(count, 42),
            _ => panic!("Expected Counter value"),
        }
    }

    #[test]
    fn test_metric_family() {
        let family = MetricFamily {
            name: "test_metric".to_string(),
            help: "Test metric".to_string(),
            r#type: MetricType::Counter,
            metrics: vec![
                Metric {
                    labels: HashMap::from([("label1".to_string(), "value1".to_string())]),
                    value: MetricValue::Counter(1),
                    timestamp: Some(1234567890),
                },
            ],
        };

        let serialized = serde_json::to_string(&family).unwrap();
        let deserialized: MetricFamily = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(deserialized.name, "test_metric");
        assert_eq!(deserialized.r#type, MetricType::Counter);
        assert_eq!(deserialized.metrics.len(), 1);
    }

    #[test]
    fn test_time_range() {
        let start = chrono::Utc::now();
        let end = start + chrono::Duration::hours(1);
        
        let time_range = TimeRange { start, end };
        
        assert!(time_range.end > time_range.start);
        assert_eq!(time_range.end - time_range.start, chrono::Duration::hours(1));
    }

    #[test]
    fn test_metric_alert() {
        let alert = MetricAlert {
            name: "test_alert".to_string(),
            description: "Test alert".to_string(),
            query: "up == 0".to_string(),
            condition: AlertCondition {
                operator: ComparisonOperator::Eq,
                threshold: 0.0,
                for_duration: Some(std::time::Duration::from_secs(300)),
            },
            severity: AlertSeverity::Critical,
            labels: HashMap::new(),
            annotations: HashMap::new(),
            state: AlertState::Firing,
            last_evaluation: Some(chrono::Utc::now()),
        };

        assert_eq!(alert.name, "test_alert");
        assert_eq!(alert.severity, AlertSeverity::Critical);
        assert_eq!(alert.state, AlertState::Firing);
    }

    #[test]
    fn test_metric_filter() {
        let filter = MetricFilter {
            name_pattern: Some("test_.*".to_string()),
            label_filters: HashMap::from([("env".to_string(), "prod".to_string())]),
            metric_type: Some(MetricType::Counter),
        };

        assert_eq!(filter.name_pattern, Some("test_.*".to_string()));
        assert_eq!(filter.metric_type, Some(MetricType::Counter));
        assert!(filter.label_filters.contains_key("env"));
    }
}