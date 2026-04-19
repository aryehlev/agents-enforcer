use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Unified configuration for all platforms and backends
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedConfig {
    pub version: String,
    pub backend: BackendConfig,
    pub gateways: Vec<GatewayConfig>,
    pub file_access: FileAccessConfig,
    pub metrics: MetricsConfig,
    pub logging: LoggingConfig,
    pub ui: UIConfig,
    pub agents: Vec<AgentConfig>,
}

impl Default for UnifiedConfig {
    fn default() -> Self {
        Self {
            version: "1.0".to_string(),
            backend: BackendConfig::default(),
            gateways: Vec::new(),
            file_access: FileAccessConfig::default(),
            metrics: MetricsConfig::default(),
            logging: LoggingConfig::default(),
            ui: UIConfig::default(),
            agents: Vec::new(),
        }
    }
}

/// Backend configuration with platform-specific settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    pub backend_type: BackendType,
    pub auto_detect: bool,
    pub platform_specific: HashMap<String, serde_json::Value>,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            backend_type: BackendType::Auto,
            auto_detect: true,
            platform_specific: HashMap::new(),
        }
    }
}

/// Supported backend types. Linux-only; kept as an enum so future
/// Linux variants (e.g. tc-only, Cilium-hosted) can be added without
/// a breaking config schema change.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendType {
    Auto,
    EbpfLinux,
}

/// Gateway configuration for network enforcement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    pub address: String,
    pub description: Option<String>,
    pub protocols: Vec<NetworkProtocol>,
    pub enabled: bool,
    pub priority: u32,
    pub tags: Vec<String>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            address: String::new(),
            description: None,
            protocols: vec![NetworkProtocol::Tcp],
            enabled: true,
            priority: 0,
            tags: Vec::new(),
        }
    }
}

/// Supported network protocols
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Tls,
    Http,
    Https,
    Ssh,
    Any,
}

/// File access control configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccessConfig {
    pub enabled: bool,
    pub default_policy: DefaultPolicy,
    pub rules: Vec<FileAccessRule>,
    pub protected_paths: Vec<PathPattern>,
    pub allowed_extensions: Vec<String>,
    pub monitored_processes: Vec<String>,
}

impl Default for FileAccessConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_policy: DefaultPolicy::Allow,
            rules: Vec::new(),
            protected_paths: Vec::new(),
            allowed_extensions: Vec::new(),
            monitored_processes: Vec::new(),
        }
    }
}

/// Default file access policy
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultPolicy {
    Allow,
    Deny,
    Prompt,
}

/// File access rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccessRule {
    pub path: String,
    pub pattern: PathPatternType,
    pub policy: RulePolicy,
    pub permissions: Vec<FilePermission>,
    pub applies_to: Vec<String>, // Agent names
    pub conditions: Vec<RuleCondition>,
}

/// Path pattern matching types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathPatternType {
    Exact,
    Prefix,
    Glob,
    Regex,
}

/// Rule policy for access control
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RulePolicy {
    Allow,
    Deny,
    Prompt,
    Log,
}

/// File permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilePermission {
    Read,
    Write,
    Execute,
    Delete,
    Create,
    Rename,
}

/// Rule conditions for advanced matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCondition {
    pub condition_type: ConditionType,
    pub value: String,
    pub operator: ConditionOperator,
}

/// Condition types for rules
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConditionType {
    ProcessName,
    UserId,
    TimeOfDay,
    DayOfWeek,
}

/// Condition operators
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    Contains,
    GreaterThan,
    LessThan,
}

/// Path pattern for matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathPattern {
    pub pattern: String,
    pub pattern_type: PathPatternType,
    pub case_sensitive: bool,
}

/// Metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub port: u16,
    pub endpoint: String,
    pub retention_days: u32,
    pub export_formats: Vec<MetricFormat>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 9090,
            endpoint: "/metrics".to_string(),
            retention_days: 7,
            export_formats: vec![MetricFormat::Prometheus],
        }
    }
}

/// Supported metrics export formats
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MetricFormat {
    Prometheus,
    Json,
    Csv,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: LogLevel,
    pub format: LogFormat,
    pub file: Option<PathBuf>,
    pub console: bool,
    pub structured: bool,
    pub fields: HashMap<String, LogField>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Text,
            file: None,
            console: true,
            structured: false,
            fields: HashMap::new(),
        }
    }
}

/// Log levels
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Log formats
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Text,
    Json,
    Structured,
}

/// Log field configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogField {
    pub enabled: bool,
    pub format: Option<String>,
}

/// UI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UIConfig {
    pub show_status_bar: bool,
    pub show_permission_prompts: bool,
    pub prompt_timeout: u32,
    pub theme: UITheme,
    pub language: String,
    pub web_dashboard: WebDashboardConfig,
}

impl Default for UIConfig {
    fn default() -> Self {
        Self {
            show_status_bar: true,
            show_permission_prompts: true,
            prompt_timeout: 30,
            theme: UITheme::System,
            language: "en".to_string(),
            web_dashboard: WebDashboardConfig::default(),
        }
    }
}

/// UI themes
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UITheme {
    Light,
    Dark,
    System,
}

/// Web dashboard configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebDashboardConfig {
    pub enabled: bool,
    pub port: u16,
    pub host: String,
    pub tls: bool,
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
}

impl Default for WebDashboardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 8080,
            host: "127.0.0.1".to_string(),
            tls: false,
            cert_file: None,
            key_file: None,
        }
    }
}

/// Agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub name: String,
    pub path: PathBuf,
    pub backend_specific: HashMap<String, serde_json::Value>,
    pub permissions: AgentPermissions,
}

/// Agent permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPermissions {
    pub network_access: bool,
    pub file_access: bool,
    pub system_access: bool,
    pub elevated_privileges: bool,
}

impl Default for AgentPermissions {
    fn default() -> Self {
        Self {
            network_access: true,
            file_access: true,
            system_access: false,
            elevated_privileges: false,
        }
    }
}

/// Platform detection utilities. The project is Kubernetes-native
/// and Linux-only; any other host falls back to `Linux` so config
/// validation doesn't crash mid-serde.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Platform {
    Linux,
}

impl Platform {
    /// Get current platform. Always `Linux`; tests that want to
    /// simulate another host should inject `Platform::current` via
    /// a mock.
    pub fn current() -> Self {
        Platform::Linux
    }

    /// Whether the current platform is supported. Always true today
    /// — retained for forward compatibility when we add Linux
    /// variants (e.g. eBPF-less fallback).
    pub fn is_supported(&self) -> bool {
        matches!(self, Platform::Linux)
    }
}

/// Configuration validation errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConfigValidationError {
    InvalidBackend(String),
    InvalidGateway(String),
    InvalidFileRule(String),
    InvalidPath(String),
    InvalidPort(u16),
    MissingRequiredField(String),
    UnsupportedPlatform(String),
}

impl std::fmt::Display for ConfigValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigValidationError::InvalidBackend(msg) => write!(f, "Invalid backend: {}", msg),
            ConfigValidationError::InvalidGateway(msg) => write!(f, "Invalid gateway: {}", msg),
            ConfigValidationError::InvalidFileRule(msg) => write!(f, "Invalid file rule: {}", msg),
            ConfigValidationError::InvalidPath(msg) => write!(f, "Invalid path: {}", msg),
            ConfigValidationError::InvalidPort(port) => write!(f, "Invalid port: {}", port),
            ConfigValidationError::MissingRequiredField(field) => {
                write!(f, "Missing required field: {}", field)
            }
            ConfigValidationError::UnsupportedPlatform(platform) => {
                write!(f, "Unsupported platform: {}", platform)
            }
        }
    }
}

impl std::error::Error for ConfigValidationError {}

/// Configuration template presets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConfigTemplate {
    Minimal,
    Development,
    Production,
    Security,
}

impl ConfigTemplate {
    /// Generate configuration from template
    pub fn generate_config(&self) -> UnifiedConfig {
        match self {
            ConfigTemplate::Minimal => self.minimal_config(),
            ConfigTemplate::Development => self.development_config(),
            ConfigTemplate::Production => self.production_config(),
            ConfigTemplate::Security => self.security_config(),
        }
    }

    fn minimal_config(&self) -> UnifiedConfig {
        UnifiedConfig {
            version: "1.0".to_string(),
            backend: BackendConfig {
                backend_type: BackendType::Auto,
                auto_detect: true,
                platform_specific: HashMap::new(),
            },
            gateways: vec![],
            file_access: FileAccessConfig {
                enabled: false,
                default_policy: DefaultPolicy::Allow,
                rules: vec![],
                protected_paths: vec![],
                allowed_extensions: vec![],
                monitored_processes: vec![],
            },
            metrics: MetricsConfig {
                enabled: false,
                port: 9090,
                endpoint: "/metrics".to_string(),
                retention_days: 1,
                export_formats: vec![],
            },
            logging: LoggingConfig {
                level: LogLevel::Info,
                format: LogFormat::Text,
                file: None,
                console: true,
                structured: false,
                fields: HashMap::new(),
            },
            ui: UIConfig {
                show_status_bar: false,
                show_permission_prompts: false,
                prompt_timeout: 0,
                theme: UITheme::System,
                language: "en".to_string(),
                web_dashboard: WebDashboardConfig {
                    enabled: false,
                    port: 8080,
                    host: "127.0.0.1".to_string(),
                    tls: false,
                    cert_file: None,
                    key_file: None,
                },
            },
            agents: vec![],
        }
    }

    fn development_config(&self) -> UnifiedConfig {
        let mut config = self.minimal_config();
        config.metrics.enabled = true;
        config.logging.level = LogLevel::Debug;
        config.logging.structured = true;
        config.ui.show_status_bar = true;
        config.ui.web_dashboard.enabled = true;
        config
    }

    fn production_config(&self) -> UnifiedConfig {
        let mut config = self.minimal_config();
        config.metrics.enabled = true;
        config.metrics.retention_days = 30;
        config.logging.level = LogLevel::Warn;
        config.logging.structured = true;
        config.file_access.enabled = true;
        config.file_access.default_policy = DefaultPolicy::Deny;
        config
    }

    fn security_config(&self) -> UnifiedConfig {
        let mut config = self.production_config();
        config.file_access.default_policy = DefaultPolicy::Deny;
        config.ui.show_permission_prompts = true;
        config.ui.prompt_timeout = 60;
        config.logging.level = LogLevel::Info;
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = UnifiedConfig::default();
        assert_eq!(config.version, "1.0");
        assert_eq!(config.metrics.port, 9090);
        assert_eq!(config.logging.level, LogLevel::Info);
    }

    #[test]
    fn test_config_serialization() {
        let config = UnifiedConfig::default();
        let yaml = serde_yaml::to_string(&config).unwrap();
        let deserialized: UnifiedConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(config.version, deserialized.version);
    }

    #[test]
    fn test_platform_detection() {
        let platform = Platform::current();
        assert!(platform.is_supported());
    }

    #[test]
    fn test_config_templates() {
        let minimal = ConfigTemplate::Minimal.generate_config();
        assert!(!minimal.metrics.enabled);

        let dev = ConfigTemplate::Development.generate_config();
        assert!(dev.metrics.enabled);
        assert_eq!(dev.logging.level, LogLevel::Debug);

        let prod = ConfigTemplate::Production.generate_config();
        assert!(prod.metrics.enabled);
        assert_eq!(prod.logging.level, LogLevel::Warn);
    }

    #[test]
    fn test_gateway_config_default() {
        let gateway = GatewayConfig::default();
        assert!(gateway.enabled);
        assert_eq!(gateway.priority, 0);
        assert_eq!(gateway.protocols.len(), 1);
        assert!(matches!(gateway.protocols[0], NetworkProtocol::Tcp));
    }

    #[test]
    fn test_file_access_config_default() {
        let file_access = FileAccessConfig::default();
        assert!(file_access.enabled);
        assert!(matches!(file_access.default_policy, DefaultPolicy::Allow));
    }

    #[test]
    fn test_validation_error_display() {
        let error = ConfigValidationError::InvalidPort(80);
        let display = format!("{}", error);
        assert!(display.contains("Invalid port: 80"));
    }
}
