//! Unified event system for agent gateway enforcer

pub mod aggregation;
pub mod bus;
pub mod export;
pub mod handlers;
pub mod streaming;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

pub use aggregation::{AggregatedEvent, AggregationRule, EventAggregator};
pub use bus::{EventBus, EventBusHandle, EventBusStats};
pub use export::{EventExporter, ExportFormat};
pub use handlers::{
    EventFilter, EventHandler, EventSeverityFilter, EventSourceFilter, EventTypeFilter,
};
pub use streaming::{EventStreamer, StreamHandle, StreamedEvent};

/// Unified event structure for all platforms and backends
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedEvent {
    /// Unique event identifier
    pub id: Uuid,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Event type
    pub event_type: EventType,
    /// Event source
    pub source: EventSource,
    /// Event severity
    pub severity: EventSeverity,
    /// Event data
    pub data: EventData,
    /// Event metadata
    pub metadata: EventMetadata,
}

impl UnifiedEvent {
    /// Create a new event
    pub fn new(event_type: EventType, source: EventSource, data: EventData) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            source,
            severity: data.default_severity(),
            data,
            metadata: EventMetadata::default(),
        }
    }

    /// Create a network event
    pub fn network(
        action: NetworkAction,
        dst_ip: std::net::IpAddr,
        dst_port: u16,
        protocol: NetworkProtocol,
        pid: Option<u32>,
        source: EventSource,
    ) -> Self {
        let data = EventData::Network(NetworkEvent {
            action,
            dst_ip,
            dst_port,
            protocol,
            pid,
            src_ip: None,
            src_port: None,
            interface: None,
            bytes_transferred: None,
            duration_ms: None,
        });

        Self::new(EventType::Network, source, data)
    }

    /// Create a file access event
    pub fn file_access(
        action: FileAction,
        path: String,
        access_type: FileAccessType,
        pid: Option<u32>,
        source: EventSource,
    ) -> Self {
        let data = EventData::FileAccess(FileAccessEvent {
            action,
            path,
            access_type,
            pid,
            process_name: None,
            user_id: None,
            file_size: None,
            file_hash: None,
        });

        Self::new(EventType::FileAccess, source, data)
    }

    /// Create a system event
    pub fn system(
        action: SystemAction,
        component: String,
        message: String,
        source: EventSource,
    ) -> Self {
        let data = EventData::System(SystemEvent {
            action,
            component,
            message,
            old_state: None,
            new_state: None,
            error_code: None,
        });

        Self::new(EventType::System, source, data)
    }

    /// Create a security event
    pub fn security(
        threat_type: SecurityThreatType,
        severity: SecuritySeverity,
        description: String,
        source: EventSource,
    ) -> Self {
        let data = EventData::Security(SecurityEvent {
            threat_type,
            severity,
            description,
            confidence: None,
            indicators: HashMap::new(),
            remediation: None,
        });

        Self::new(EventType::Security, source, data)
    }

    /// Add metadata to the event
    pub fn with_metadata(mut self, metadata: EventMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Add a tag to the event
    pub fn with_tag(mut self, key: String, value: String) -> Self {
        self.metadata.tags.insert(key, value);
        self
    }

    /// Set custom fields
    pub fn with_custom_fields(mut self, fields: HashMap<String, serde_json::Value>) -> Self {
        self.metadata.custom_fields.extend(fields);
        self
    }
}

impl std::fmt::Display for UnifiedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} {} - {:?}",
            self.timestamp.format("%Y-%m-%d %H:%M:%S"),
            self.event_type,
            self.severity,
            self.data
        )
    }
}

/// Event types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventType {
    /// Network-related events
    Network,
    /// File access events
    FileAccess,
    /// System events
    System,
    /// Security events
    Security,
    /// Performance events
    Performance,
    /// Configuration events
    Configuration,
    /// Custom event type
    Custom(String),
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network => write!(f, "network"),
            Self::FileAccess => write!(f, "file_access"),
            Self::System => write!(f, "system"),
            Self::Security => write!(f, "security"),
            Self::Performance => write!(f, "performance"),
            Self::Configuration => write!(f, "configuration"),
            Self::Custom(s) => write!(f, "custom:{}", s),
        }
    }
}

/// Event source
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventSource {
    /// Linux eBPF backend
    EbpfLinux,
    /// macOS desktop backend
    MacOSDesktop,
    /// Windows desktop backend
    WindowsDesktop,
    /// Core system
    Core,
    /// Configuration system
    Config,
    /// Metrics system
    Metrics,
    /// CLI interface
    Cli,
    /// Web dashboard
    WebDashboard,
    /// Custom source
    Custom(String),
}

impl std::fmt::Display for EventSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EbpfLinux => write!(f, "ebpf_linux"),
            Self::MacOSDesktop => write!(f, "macos_desktop"),
            Self::WindowsDesktop => write!(f, "windows_desktop"),
            Self::Core => write!(f, "core"),
            Self::Config => write!(f, "config"),
            Self::Metrics => write!(f, "metrics"),
            Self::Cli => write!(f, "cli"),
            Self::WebDashboard => write!(f, "web_dashboard"),
            Self::Custom(s) => write!(f, "custom:{}", s),
        }
    }
}

impl EventSource {
    /// Get the current platform's default source
    pub fn current_platform() -> Self {
        match crate::backend::Platform::current() {
            crate::backend::Platform::Linux => Self::EbpfLinux,
            crate::backend::Platform::MacOS => Self::MacOSDesktop,
            crate::backend::Platform::Windows => Self::WindowsDesktop,
            _ => Self::Core,
        }
    }
}

/// Event severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EventSeverity {
    /// Debug information
    Debug = 0,
    /// Informational
    Info = 1,
    /// Warning
    Warning = 2,
    /// Error
    Error = 3,
    /// Critical
    Critical = 4,
}

impl EventSeverity {
    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }

    /// Convert from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "debug" => Some(Self::Debug),
            "info" | "information" => Some(Self::Info),
            "warn" | "warning" => Some(Self::Warning),
            "error" => Some(Self::Error),
            "crit" | "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

impl std::fmt::Display for EventSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventData {
    /// Network event
    Network(NetworkEvent),
    /// File access event
    FileAccess(FileAccessEvent),
    /// System event
    System(SystemEvent),
    /// Security event
    Security(SecurityEvent),
    /// Performance event
    Performance(PerformanceEvent),
    /// Configuration event
    Configuration(ConfigurationEvent),
    /// Custom event data
    Custom(HashMap<String, serde_json::Value>),
}

impl EventData {
    /// Get the default severity for this event data
    pub fn default_severity(&self) -> EventSeverity {
        match self {
            Self::Network(event) => match event.action {
                NetworkAction::Blocked => EventSeverity::Warning,
                NetworkAction::Allowed => EventSeverity::Info,
                NetworkAction::RateLimited => EventSeverity::Warning,
                NetworkAction::Unknown => EventSeverity::Debug,
            },
            Self::FileAccess(event) => match event.action {
                FileAction::Blocked => EventSeverity::Warning,
                FileAction::Allowed => EventSeverity::Info,
                FileAction::Quarantined => EventSeverity::Error,
                FileAction::Unknown => EventSeverity::Debug,
            },
            Self::System(event) => match event.action {
                SystemAction::Started => EventSeverity::Info,
                SystemAction::Stopped => EventSeverity::Info,
                SystemAction::Error => EventSeverity::Error,
                SystemAction::ConfigurationChanged => EventSeverity::Info,
                SystemAction::HealthCheck => EventSeverity::Debug,
            },
            Self::Security(event) => match event.severity {
                SecuritySeverity::Low => EventSeverity::Warning,
                SecuritySeverity::Medium => EventSeverity::Error,
                SecuritySeverity::High => EventSeverity::Critical,
                SecuritySeverity::Critical => EventSeverity::Critical,
            },
            Self::Performance(_) => EventSeverity::Info,
            Self::Configuration(_) => EventSeverity::Info,
            Self::Custom(_) => EventSeverity::Info,
        }
    }
}

/// Event metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventMetadata {
    /// Event tags
    pub tags: HashMap<String, String>,
    /// Custom fields
    pub custom_fields: HashMap<String, serde_json::Value>,
    /// Correlation ID for related events
    pub correlation_id: Option<Uuid>,
    /// Session ID
    pub session_id: Option<String>,
    /// User ID
    pub user_id: Option<String>,
    /// Request ID
    pub request_id: Option<String>,
}

/// Network event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    /// Network action
    pub action: NetworkAction,
    /// Destination IP
    pub dst_ip: std::net::IpAddr,
    /// Destination port
    pub dst_port: u16,
    /// Network protocol
    pub protocol: NetworkProtocol,
    /// Process ID
    pub pid: Option<u32>,
    /// Source IP
    pub src_ip: Option<std::net::IpAddr>,
    /// Source port
    pub src_port: Option<u16>,
    /// Network interface
    pub interface: Option<String>,
    /// Bytes transferred
    pub bytes_transferred: Option<u64>,
    /// Duration in milliseconds
    pub duration_ms: Option<u64>,
}

/// Network action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkAction {
    /// Connection was blocked
    Blocked,
    /// Connection was allowed
    Allowed,
    /// Connection was rate limited
    RateLimited,
    /// Unknown action
    Unknown,
}

/// Network protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkProtocol {
    /// TCP
    Tcp,
    /// UDP
    Udp,
    /// ICMP
    Icmp,
    /// Other protocol
    Other(u8),
}

impl From<agent_gateway_enforcer_common::Protocol> for NetworkProtocol {
    fn from(protocol: agent_gateway_enforcer_common::Protocol) -> Self {
        match protocol {
            agent_gateway_enforcer_common::Protocol::Tcp => Self::Tcp,
            agent_gateway_enforcer_common::Protocol::Udp => Self::Udp,
            agent_gateway_enforcer_common::Protocol::Icmp => Self::Icmp,
            agent_gateway_enforcer_common::Protocol::Other(code) => Self::Other(code),
        }
    }
}

/// File access event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccessEvent {
    /// File action
    pub action: FileAction,
    /// File path
    pub path: String,
    /// Access type
    pub access_type: FileAccessType,
    /// Process ID
    pub pid: Option<u32>,
    /// Process name
    pub process_name: Option<String>,
    /// User ID
    pub user_id: Option<String>,
    /// File size
    pub file_size: Option<u64>,
    /// File hash
    pub file_hash: Option<String>,
}

/// File action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileAction {
    /// Access was blocked
    Blocked,
    /// Access was allowed
    Allowed,
    /// File was quarantined
    Quarantined,
    /// Unknown action
    Unknown,
}

/// File access type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileAccessType {
    /// Read access
    Read,
    /// Write access
    Write,
    /// Execute access
    Execute,
    /// Delete access
    Delete,
    /// Create access
    Create,
    /// Other access
    Other(String),
}

impl From<agent_gateway_enforcer_common::FileAccessType> for FileAccessType {
    fn from(access_type: agent_gateway_enforcer_common::FileAccessType) -> Self {
        match access_type {
            agent_gateway_enforcer_common::FileAccessType::Read => Self::Read,
            agent_gateway_enforcer_common::FileAccessType::Write => Self::Write,
            agent_gateway_enforcer_common::FileAccessType::Execute => Self::Execute,
            agent_gateway_enforcer_common::FileAccessType::Delete => Self::Delete,
        }
    }
}

/// System event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemEvent {
    /// System action
    pub action: SystemAction,
    /// Component name
    pub component: String,
    /// Event message
    pub message: String,
    /// Previous state
    pub old_state: Option<String>,
    /// New state
    pub new_state: Option<String>,
    /// Error code
    pub error_code: Option<String>,
}

/// System action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SystemAction {
    /// Component started
    Started,
    /// Component stopped
    Stopped,
    /// Error occurred
    Error,
    /// Configuration changed
    ConfigurationChanged,
    /// Health check
    HealthCheck,
}

/// Security event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Threat type
    pub threat_type: SecurityThreatType,
    /// Security severity
    pub severity: SecuritySeverity,
    /// Event description
    pub description: String,
    /// Confidence level (0-100)
    pub confidence: Option<u8>,
    /// Security indicators
    pub indicators: HashMap<String, String>,
    /// Recommended remediation
    pub remediation: Option<String>,
}

/// Security threat type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityThreatType {
    /// Malware detected
    Malware,
    /// Suspicious network activity
    SuspiciousNetwork,
    /// Unauthorized file access
    UnauthorizedFileAccess,
    /// Privilege escalation
    PrivilegeEscalation,
    /// Data exfiltration
    DataExfiltration,
    /// Command injection
    CommandInjection,
    /// Custom threat type
    Custom(String),
}

/// Security severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SecuritySeverity {
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

/// Performance event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceEvent {
    /// Performance metric name
    pub metric: String,
    /// Metric value
    pub value: f64,
    /// Unit of measurement
    pub unit: String,
    /// Component name
    pub component: String,
    /// Additional dimensions
    pub dimensions: HashMap<String, String>,
}

/// Configuration event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigurationEvent {
    /// Configuration action
    pub action: ConfigurationAction,
    /// Configuration section
    pub section: String,
    /// Configuration key
    pub key: Option<String>,
    /// Old value
    pub old_value: Option<serde_json::Value>,
    /// New value
    pub new_value: Option<serde_json::Value>,
    /// Configuration source
    pub source: String,
}

/// Configuration action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigurationAction {
    /// Configuration loaded
    Loaded,
    /// Configuration saved
    Saved,
    /// Configuration validated
    Validated,
    /// Configuration value changed
    Changed,
    /// Configuration reloaded
    Reloaded,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_event_creation() {
        let event = UnifiedEvent::network(
            NetworkAction::Blocked,
            "192.168.1.1".parse().unwrap(),
            443,
            NetworkProtocol::Tcp,
            Some(1234),
            EventSource::EbpfLinux,
        );

        assert_eq!(event.event_type, EventType::Network);
        assert_eq!(event.source, EventSource::EbpfLinux);
        assert_eq!(event.severity, EventSeverity::Warning);
    }

    #[test]
    fn test_event_with_metadata() {
        let event = UnifiedEvent::system(
            SystemAction::Started,
            "backend".to_string(),
            "Backend started".to_string(),
            EventSource::Core,
        )
        .with_tag("environment".to_string(), "test".to_string())
        .with_custom_fields(HashMap::from([("version".to_string(), "1.0.0".into())]));

        assert_eq!(
            event.metadata.tags.get("environment"),
            Some(&"test".to_string())
        );
        assert_eq!(
            event.metadata.custom_fields.get("version"),
            Some(&"1.0.0".into())
        );
    }

    #[test]
    fn test_security_event() {
        let event = UnifiedEvent::security(
            SecurityThreatType::Malware,
            SecuritySeverity::High,
            "Suspicious file detected".to_string(),
            EventSource::MacOSDesktop,
        );

        assert_eq!(event.event_type, EventType::Security);
        assert_eq!(event.severity, EventSeverity::Critical);
    }

    #[test]
    fn test_event_severity_from_str() {
        assert_eq!(EventSeverity::from_str("info"), Some(EventSeverity::Info));
        assert_eq!(
            EventSeverity::from_str("warning"),
            Some(EventSeverity::Warning)
        );
        assert_eq!(EventSeverity::from_str("error"), Some(EventSeverity::Error));
        assert_eq!(
            EventSeverity::from_str("critical"),
            Some(EventSeverity::Critical)
        );
        assert_eq!(EventSeverity::from_str("invalid"), None);
    }
}
