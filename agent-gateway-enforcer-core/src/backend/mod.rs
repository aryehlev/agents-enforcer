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

/// Convenience function to create core errors
pub fn create_error(context: &str, message: impl Into<String>) -> anyhow::Error {
    anyhow::anyhow!("{}: {}", context, message.into())
}

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Identity of a pod being enforced.
///
/// Kubernetes pods are identified by UID globally and namespace/name for
/// humans; the cgroup v2 path is what we actually attach eBPF programs to.
/// All three are carried explicitly so the controller side doesn't have
/// to re-derive them from the kubelet, and so logs / events are always
/// attributable without an extra lookup.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PodIdentity {
    /// Kubernetes pod UID (e.g. "550e8400-e29b-41d4-a716-446655440000").
    pub uid: String,
    /// Pod namespace.
    pub namespace: String,
    /// Pod name.
    pub name: String,
    /// Absolute cgroup v2 path the node agent should attach to,
    /// e.g. `/sys/fs/cgroup/kubepods.slice/.../pod<uid>`.
    pub cgroup_path: String,
}

/// Content hash of a compiled policy bundle.
///
/// Node agents deduplicate programming by hash — two pods with the same
/// `PolicyHash` share the same eBPF map contents, so we only pay the
/// upload cost once per distinct policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyHash(pub String);

impl PolicyHash {
    /// Construct from a hex-encoded sha256 string.
    pub fn new(hex: impl Into<String>) -> Self {
        Self(hex.into())
    }

    /// Access the raw hex representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Compiled, node-ready policy ready to be programmed into eBPF maps.
///
/// This is intentionally flat rather than nested like `AgentPolicy` CRDs:
/// the controller does the CR → bundle compilation (DNS resolution,
/// catalog expansion, conflict resolution), nodes only see the result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyBundle {
    /// Hash identifying this exact bundle. Must match
    /// `sha256(bincode::serialize(&bundle_without_hash))` so nodes can
    /// verify what they received.
    pub hash: PolicyHash,
    /// Egress gateways. Empty means default-deny egress.
    pub gateways: Vec<GatewayConfig>,
    /// File access rules.
    pub file_access: FileAccessConfig,
    /// Exec-allowlist paths (prefix match). Empty = exec allowlist disabled.
    pub exec_allowlist: Vec<String>,
    /// When true, block path mutations (unlink/mkdir/rmdir) from
    /// processes matched by `blocked_processes`.
    pub block_mutations: bool,
}

impl Default for PolicyBundle {
    fn default() -> Self {
        Self {
            hash: PolicyHash::new(""),
            gateways: Vec::new(),
            file_access: FileAccessConfig::default(),
            exec_allowlist: Vec::new(),
            block_mutations: false,
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
    /// Implementations should use interior mutability (e.g., RwLock) for state changes.
    async fn configure_gateways(&self, gateways: &[GatewayConfig]) -> Result<()>;

    /// Configure file access rules
    ///
    /// Update file access control rules. This may be called while the
    /// backend is running if hot-reload is supported.
    /// Implementations should use interior mutability (e.g., RwLock) for state changes.
    async fn configure_file_access(&self, config: &FileAccessConfig) -> Result<()>;

    /// Get the metrics collector if supported
    ///
    /// Returns `None` if the backend doesn't support metrics collection.
    fn metrics_collector(&self) -> Option<Arc<dyn MetricsCollector>>;

    /// Get the event handler if supported
    ///
    /// Returns `None` if the backend doesn't support event streaming.
    fn event_handler(&self) -> Option<Arc<dyn EventHandler>>;

    /// Perform a health check on backend
    ///
    /// This method should verify that backend is functioning properly
    /// and return detailed health information.
    async fn health_check(&self) -> Result<BackendHealth>;

    /// Cleanup resources
    ///
    /// This method should release all resources held by the backend.
    /// After calling this method, the backend must be re-initialized
    /// before it can be used again.
    async fn cleanup(&mut self) -> Result<()>;

    /// Attach enforcement to a specific pod's cgroup.
    ///
    /// The controller calls this when a matching pod is scheduled on
    /// this node. Idempotent: attaching the same (pod, policy_hash)
    /// twice must be a no-op. Returning an error leaves the pod
    /// unenforced and the controller will mark the policy `Degraded`.
    ///
    /// The default implementation returns "unsupported" so existing
    /// single-tenant backends keep compiling; per-pod support is
    /// declared via `BackendCapabilities::per_pod_enforcement` in a
    /// later change.
    async fn attach_pod(&self, _pod: &PodIdentity, _policy_hash: &PolicyHash) -> Result<()> {
        Err(anyhow::anyhow!(
            "attach_pod is not supported by this backend"
        ))
    }

    /// Detach enforcement from a pod's cgroup.
    ///
    /// Called when the pod terminates or the policy selector stops
    /// matching. Must tolerate being called for a pod that was never
    /// attached (no-op in that case) — pod lifecycle races are the
    /// norm, not the exception.
    async fn detach_pod(&self, _pod: &PodIdentity) -> Result<()> {
        Err(anyhow::anyhow!(
            "detach_pod is not supported by this backend"
        ))
    }

    /// Install or update a compiled policy bundle, keyed by its hash.
    ///
    /// After this returns, the backend has the bundle's rules staged
    /// and ready to be used by subsequent `attach_pod` calls that
    /// reference the same hash. Implementations should keep a bundle
    /// alive as long as any attached pod references it, and drop it
    /// once the last reference detaches.
    async fn update_policy(&self, _bundle: &PolicyBundle) -> Result<()> {
        Err(anyhow::anyhow!(
            "update_policy is not supported by this backend"
        ))
    }
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
            assert!(matches!(
                health.status,
                HealthStatus::Healthy
                    | HealthStatus::Degraded
                    | HealthStatus::Unhealthy
                    | HealthStatus::Unknown
            ));
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

    #[test]
    fn pod_identity_is_hashable_and_equatable() {
        use std::collections::HashSet;
        let a = PodIdentity {
            uid: "abc".into(),
            namespace: "prod".into(),
            name: "agent-0".into(),
            cgroup_path: "/sys/fs/cgroup/kubepods.slice/abc".into(),
        };
        let b = a.clone();
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b), "same UID -> same bucket");
    }

    #[test]
    fn policy_hash_round_trips_as_string() {
        let h = PolicyHash::new("deadbeef");
        assert_eq!(h.as_str(), "deadbeef");
        let json = serde_json::to_string(&h).unwrap();
        let back: PolicyHash = serde_json::from_str(&json).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn policy_bundle_default_is_empty() {
        let b = PolicyBundle::default();
        assert!(b.gateways.is_empty());
        assert!(b.exec_allowlist.is_empty());
        assert!(!b.block_mutations);
        assert_eq!(b.hash.as_str(), "");
    }

    #[tokio::test]
    async fn trait_default_pod_methods_return_unsupported() {
        struct Noop;
        #[async_trait]
        impl EnforcementBackend for Noop {
            fn backend_type(&self) -> BackendType {
                BackendType::Auto
            }
            fn platform(&self) -> Platform {
                Platform::Linux
            }
            fn capabilities(&self) -> BackendCapabilities {
                BackendCapabilities::default()
            }
            async fn initialize(&mut self, _: &UnifiedConfig) -> Result<()> {
                Ok(())
            }
            async fn start(&mut self) -> Result<()> {
                Ok(())
            }
            async fn stop(&mut self) -> Result<()> {
                Ok(())
            }
            async fn configure_gateways(&self, _: &[GatewayConfig]) -> Result<()> {
                Ok(())
            }
            async fn configure_file_access(&self, _: &FileAccessConfig) -> Result<()> {
                Ok(())
            }
            fn metrics_collector(&self) -> Option<Arc<dyn MetricsCollector>> {
                None
            }
            fn event_handler(&self) -> Option<Arc<dyn EventHandler>> {
                None
            }
            async fn health_check(&self) -> Result<BackendHealth> {
                Ok(BackendHealth::default())
            }
            async fn cleanup(&mut self) -> Result<()> {
                Ok(())
            }
        }

        let b = Noop;
        let pod = PodIdentity {
            uid: "u".into(),
            namespace: "n".into(),
            name: "p".into(),
            cgroup_path: "/c".into(),
        };
        assert!(b.attach_pod(&pod, &PolicyHash::new("h")).await.is_err());
        assert!(b.detach_pod(&pod).await.is_err());
        assert!(b.update_policy(&PolicyBundle::default()).await.is_err());
    }
}
