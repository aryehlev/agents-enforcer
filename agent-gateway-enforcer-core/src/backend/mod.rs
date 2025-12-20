//! Backend trait definitions for platform-specific implementations
//!
//! This module provides the core abstractions for enforcement backends,
//! including the `EnforcementBackend` trait that all platform-specific
//! implementations must implement.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::SystemTime;

pub mod error;
pub mod lifecycle;
pub mod platform;
pub mod registry;

pub use error::BackendError;
pub use lifecycle::BackendLifecycleManager;
pub use platform::Platform;
pub use registry::{BackendFactory, BackendInfo, BackendRegistry};

/// Type alias for backend-related operations
pub type Result<T> = std::result::Result<T, anyhow::Error>;

/// Backend type identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BackendType {
    /// Linux eBPF backend
    EbpfLinux,
    /// macOS Desktop backend
    MacOSDesktop,
    /// Windows Desktop backend
    WindowsDesktop,
    /// Auto-detect backend based on platform
    Auto,
}

/// Backend capabilities descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendCapabilities {
    /// Supports network traffic filtering
    pub network_filtering: bool,
    /// Supports file access control
    pub file_access_control: bool,
    /// Supports process monitoring
    pub process_monitoring: bool,
    /// Supports real-time event streaming
    pub real_time_events: bool,
    /// Supports metrics collection
    pub metrics_collection: bool,
    /// Supports hot-reload of configuration
    pub configuration_hot_reload: bool,
}

impl Default for BackendCapabilities {
    fn default() -> Self {
        Self {
            network_filtering: false,
            file_access_control: false,
            process_monitoring: false,
            real_time_events: false,
            metrics_collection: false,
            configuration_hot_reload: false,
        }
    }
}

/// Backend health status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Backend is healthy and functioning normally
    Healthy,
    /// Backend is partially functional (degraded performance)
    Degraded,
    /// Backend is not functioning properly
    Unhealthy,
    /// Health status is unknown
    Unknown,
}

/// Backend health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendHealth {
    /// Current health status
    pub status: HealthStatus,
    /// Timestamp of last health check
    pub last_check: SystemTime,
    /// Additional details about health status
    pub details: String,
}

impl Default for BackendHealth {
    fn default() -> Self {
        Self {
            status: HealthStatus::Unknown,
            last_check: SystemTime::now(),
            details: String::new(),
        }
    }
}

/// Gateway configuration for network filtering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Gateway address (IPv4 or IPv6)
    pub address: String,
    /// Port number
    pub port: u16,
    /// Whether this gateway is enabled
    pub enabled: bool,
    /// Optional description
    pub description: Option<String>,
}

/// File access control configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccessConfig {
    /// List of allowed file paths (prefix matching)
    pub allowed_paths: Vec<String>,
    /// List of denied file paths (prefix matching)
    pub denied_paths: Vec<String>,
    /// Default action (allow or deny)
    pub default_deny: bool,
}

impl Default for FileAccessConfig {
    fn default() -> Self {
        Self {
            allowed_paths: Vec::new(),
            denied_paths: Vec::new(),
            default_deny: false,
        }
    }
}

/// Unified configuration for enforcement backends
///
/// This is a simplified configuration structure. The full configuration
/// will be defined in the configuration module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedConfig {
    /// Gateway configurations
    pub gateways: Vec<GatewayConfig>,
    /// File access control configuration
    pub file_access: FileAccessConfig,
    /// Backend-specific settings
    pub backend_settings: serde_json::Value,
}

impl Default for UnifiedConfig {
    fn default() -> Self {
        Self {
            gateways: Vec::new(),
            file_access: FileAccessConfig::default(),
            backend_settings: serde_json::Value::Null,
        }
    }
}

/// Metrics collector trait for backend implementations
pub trait MetricsCollector: Send + Sync {
    /// Get current metrics as JSON
    fn get_metrics(&self) -> Result<serde_json::Value>;
    
    /// Reset metrics counters
    fn reset(&self) -> Result<()>;
}

/// Event handler trait for backend implementations
pub trait EventHandler: Send + Sync {
    /// Register an event callback
    fn on_event(&self, callback: Box<dyn Fn(serde_json::Value) + Send + Sync>) -> Result<()>;
}

/// Core enforcement backend trait
///
/// This trait defines the interface that all platform-specific enforcement
/// backends must implement. It provides methods for initialization, lifecycle
/// management, configuration, and monitoring.
#[async_trait]
pub trait EnforcementBackend: Send + Sync {
    /// Returns the backend type identifier
    fn backend_type(&self) -> BackendType;
    
    /// Returns the platform this backend supports
    fn platform(&self) -> Platform;
    
    /// Returns the backend's capabilities
    fn capabilities(&self) -> BackendCapabilities;
    
    /// Initialize the backend with configuration
    ///
    /// This method should prepare the backend for operation but not
    /// start enforcement. It should validate the configuration and
    /// allocate necessary resources.
    async fn initialize(&mut self, config: &UnifiedConfig) -> Result<()>;
    
    /// Start enforcement operations
    ///
    /// After this method returns successfully, the backend should be
    /// actively enforcing policies.
    async fn start(&mut self) -> Result<()>;
    
    /// Stop enforcement operations gracefully
    ///
    /// This method should stop enforcement but not release resources.
    /// The backend should be able to be restarted without re-initialization.
    async fn stop(&mut self) -> Result<()>;
    
    /// Configure network gateway rules
    ///
    /// Update the list of allowed network gateways. This may be called
    /// while the backend is running if hot-reload is supported.
    async fn configure_gateways(&mut self, gateways: &[GatewayConfig]) -> Result<()>;
    
    /// Configure file access rules
    ///
    /// Update file access control rules. This may be called while the
    /// backend is running if hot-reload is supported.
    async fn configure_file_access(&mut self, config: &FileAccessConfig) -> Result<()>;
    
    /// Get the metrics collector if supported
    ///
    /// Returns `None` if the backend doesn't support metrics collection.
    fn metrics_collector(&self) -> Option<Arc<dyn MetricsCollector>>;
    
    /// Get the event handler if supported
    ///
    /// Returns `None` if the backend doesn't support event streaming.
    fn event_handler(&self) -> Option<Arc<dyn EventHandler>>;
    
    /// Perform a health check on the backend
    ///
    /// This method should verify that the backend is functioning properly
    /// and return detailed health information.
    async fn health_check(&self) -> Result<BackendHealth>;
    
    /// Cleanup resources
    ///
    /// This method should release all resources held by the backend.
    /// After calling this method, the backend must be re-initialized
    /// before it can be used again.
    async fn cleanup(&mut self) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_type_serialization() {
        let backend_type = BackendType::EbpfLinux;
        let serialized = serde_json::to_string(&backend_type).unwrap();
        let deserialized: BackendType = serde_json::from_str(&serialized).unwrap();
        assert_eq!(backend_type, deserialized);
    }

    #[test]
    fn test_backend_capabilities_default() {
        let caps = BackendCapabilities::default();
        assert!(!caps.network_filtering);
        assert!(!caps.file_access_control);
        assert!(!caps.process_monitoring);
    }

    #[test]
    fn test_health_status_variants() {
        let statuses = vec![
            HealthStatus::Healthy,
            HealthStatus::Degraded,
            HealthStatus::Unhealthy,
            HealthStatus::Unknown,
        ];
        
        for status in statuses {
            let health = BackendHealth {
                status,
                last_check: SystemTime::now(),
                details: "test".to_string(),
            };
            assert!(matches!(health.status, HealthStatus::Healthy | HealthStatus::Degraded | HealthStatus::Unhealthy | HealthStatus::Unknown));
        }
    }

    #[test]
    fn test_unified_config_default() {
        let config = UnifiedConfig::default();
        assert!(config.gateways.is_empty());
        assert!(config.file_access.allowed_paths.is_empty());
    }

    #[test]
    fn test_gateway_config_creation() {
        let gateway = GatewayConfig {
            address: "10.0.0.1".to_string(),
            port: 443,
            enabled: true,
            description: Some("Test gateway".to_string()),
        };
        assert_eq!(gateway.port, 443);
        assert!(gateway.enabled);
    }

    #[test]
    fn test_file_access_config_default() {
        let config = FileAccessConfig::default();
        assert!(!config.default_deny);
        assert!(config.allowed_paths.is_empty());
        assert!(config.denied_paths.is_empty());
    }
}
