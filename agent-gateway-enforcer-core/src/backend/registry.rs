//! Backend registry and factory system

use super::{BackendCapabilities, BackendType, EnforcementBackend, Platform, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

/// Backend factory trait for creating backend instances
#[async_trait]
pub trait BackendFactory: Send + Sync {
    /// Create a new backend instance
    fn create(&self) -> Result<Arc<dyn EnforcementBackend>>;

    /// Get the backend type this factory creates
    fn backend_type(&self) -> BackendType;

    /// Get the platform this backend supports
    fn platform(&self) -> Platform;

    /// Get the capabilities of backends created by this factory
    fn capabilities(&self) -> BackendCapabilities;
}

/// Information about an available backend
#[derive(Debug, Clone)]
pub struct BackendInfo {
    /// The type of backend
    pub backend_type: BackendType,
    /// The platform this backend supports
    pub platform: Platform,
    /// The backend's capabilities
    pub capabilities: BackendCapabilities,
}

/// Registry for managing backend factories and instances
///
/// The registry maintains a collection of backend factories and provides
/// methods for creating and retrieving backend instances.
pub struct BackendRegistry {
    /// Registered backend factories
    factories: HashMap<BackendType, Box<dyn BackendFactory>>,
}

impl BackendRegistry {
    /// Create a new backend registry
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_gateway_enforcer_core::backend::BackendRegistry;
    ///
    /// let registry = BackendRegistry::new();
    /// ```
    pub fn new() -> Self {
        let mut registry = Self {
            factories: HashMap::new(),
        };

        // Register available backends based on compile-time platform
        registry.register_available_backends();
        registry
    }

    /// Register a backend factory
    ///
    /// # Arguments
    ///
    /// * `backend_type` - The type identifier for the backend
    /// * `factory` - The factory that creates backend instances
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use agent_gateway_enforcer_core::backend::{BackendRegistry, BackendType};
    ///
    /// let mut registry = BackendRegistry::new();
    /// // registry.register_factory(BackendType::EbpfLinux, Box::new(MyFactory::new()));
    /// ```
    pub fn register_factory(
        &mut self,
        backend_type: BackendType,
        factory: Box<dyn BackendFactory>,
    ) {
        self.factories.insert(backend_type, factory);
    }

    /// Get or create a backend instance by type
    ///
    /// # Arguments
    ///
    /// * `backend_type` - The type of backend to create
    ///
    /// # Returns
    ///
    /// A new backend instance or an error if the backend type is not registered
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use agent_gateway_enforcer_core::backend::{BackendRegistry, BackendType};
    ///
    /// # async fn example() -> anyhow::Result<()> {
    /// let registry = BackendRegistry::new();
    /// let backend = registry.get_backend(&BackendType::Auto).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_backend(
        &self,
        backend_type: &BackendType,
    ) -> Result<Arc<dyn EnforcementBackend>> {
        // Handle auto-detection
        if backend_type == &BackendType::Auto {
            return self.auto_detect_backend();
        }

        let factory = self.factories.get(backend_type).ok_or_else(|| {
            anyhow::anyhow!("No factory registered for backend type: {:?}", backend_type)
        })?;

        factory.create()
    }

    /// Auto-detect and create a backend for the current platform
    ///
    /// This method detects the current platform and creates an appropriate
    /// backend instance.
    ///
    /// # Returns
    ///
    /// A backend instance for the current platform or an error if no
    /// suitable backend is available
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use agent_gateway_enforcer_core::backend::BackendRegistry;
    ///
    /// # async fn example() -> anyhow::Result<()> {
    /// let registry = BackendRegistry::new();
    /// let backend = registry.auto_detect_backend()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn auto_detect_backend(&self) -> Result<Arc<dyn EnforcementBackend>> {
        let current_platform = Platform::current();

        // Find a factory that supports the current platform
        for factory in self.factories.values() {
            if factory.platform() == current_platform {
                return factory.create();
            }
        }

        Err(anyhow::anyhow!(
            "No backend available for platform: {}",
            current_platform.name()
        ))
    }

    /// List all available backends
    ///
    /// # Returns
    ///
    /// A vector of information about all registered backends
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_gateway_enforcer_core::backend::BackendRegistry;
    ///
    /// let registry = BackendRegistry::new();
    /// let backends = registry.list_available();
    /// // At least one backend should be registered on supported platforms
    /// ```
    pub fn list_available(&self) -> Vec<BackendInfo> {
        self.factories
            .iter()
            .map(|(backend_type, factory)| BackendInfo {
                backend_type: backend_type.clone(),
                platform: factory.platform(),
                capabilities: factory.capabilities(),
            })
            .collect()
    }

    /// Register built-in backends based on the compile-time platform
    ///
    /// This method is called automatically by `new()` and registers the
    /// appropriate backends for the current platform.
    fn register_available_backends(&mut self) {
        // Note: Actual factory implementations will be provided by
        // platform-specific backend crates. For now, we just set up
        // the structure.

        #[cfg(target_os = "linux")]
        {
            // EbpfLinux backend would be registered here
            // self.register_factory(
            //     BackendType::EbpfLinux,
            //     Box::new(backends::ebpf_linux::Factory::new())
            // );
        }

    }

    /// Check if a backend is registered
    ///
    /// # Arguments
    ///
    /// * `backend_type` - The backend type to check for
    ///
    /// # Returns
    ///
    /// `true` if a factory is registered for the backend type
    pub fn has_backend(&self, backend_type: &BackendType) -> bool {
        self.factories.contains_key(backend_type)
    }

    /// Get the number of registered backends
    pub fn backend_count(&self) -> usize {
        self.factories.len()
    }
}

impl Default for BackendRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::RwLock;

    // Mock backend for testing
    struct MockBackend {
        backend_type: BackendType,
        platform: Platform,
        initialized: RwLock<bool>,
    }

    impl MockBackend {
        fn new(backend_type: BackendType, platform: Platform) -> Self {
            Self {
                backend_type,
                platform,
                initialized: RwLock::new(false),
            }
        }
    }

    #[async_trait]
    impl EnforcementBackend for MockBackend {
        fn backend_type(&self) -> BackendType {
            self.backend_type.clone()
        }

        fn platform(&self) -> Platform {
            self.platform
        }

        fn capabilities(&self) -> BackendCapabilities {
            BackendCapabilities {
                network_filtering: true,
                file_access_control: true,
                process_monitoring: false,
                real_time_events: true,
                metrics_collection: true,
                configuration_hot_reload: true,
            }
        }

        async fn initialize(&mut self, _config: &super::super::UnifiedConfig) -> Result<()> {
            *self.initialized.write().unwrap() = true;
            Ok(())
        }

        async fn start(&mut self) -> Result<()> {
            Ok(())
        }

        async fn stop(&mut self) -> Result<()> {
            Ok(())
        }

        async fn configure_gateways(
            &self,
            _gateways: &[super::super::GatewayConfig],
        ) -> Result<()> {
            Ok(())
        }

        async fn configure_file_access(
            &self,
            _config: &super::super::FileAccessConfig,
        ) -> Result<()> {
            Ok(())
        }

        fn metrics_collector(&self) -> Option<Arc<dyn super::super::MetricsCollector>> {
            None
        }

        fn event_handler(&self) -> Option<Arc<dyn super::super::EventHandler>> {
            None
        }

        async fn health_check(&self) -> Result<super::super::BackendHealth> {
            Ok(super::super::BackendHealth::default())
        }

        async fn cleanup(&mut self) -> Result<()> {
            *self.initialized.write().unwrap() = false;
            Ok(())
        }
    }

    // Mock factory for testing
    struct MockFactory {
        backend_type: BackendType,
        platform: Platform,
    }

    impl MockFactory {
        fn new(backend_type: BackendType, platform: Platform) -> Self {
            Self {
                backend_type,
                platform,
            }
        }
    }

    #[async_trait]
    impl BackendFactory for MockFactory {
        async fn create(&self) -> Result<Arc<dyn EnforcementBackend>> {
            Ok(Arc::new(MockBackend::new(
                self.backend_type.clone(),
                self.platform,
            )))
        }

        fn backend_type(&self) -> BackendType {
            self.backend_type.clone()
        }

        fn platform(&self) -> Platform {
            self.platform
        }

        fn capabilities(&self) -> BackendCapabilities {
            BackendCapabilities {
                network_filtering: true,
                file_access_control: true,
                process_monitoring: false,
                real_time_events: true,
                metrics_collection: true,
                configuration_hot_reload: true,
            }
        }
    }

    #[test]
    fn test_registry_creation() {
        let registry = BackendRegistry::new();
        // Registry should be created successfully
        let _ = registry.backend_count();
    }

    #[test]
    fn test_registry_default() {
        let registry = BackendRegistry::default();
        // Registry should be created successfully
        let _ = registry.backend_count();
    }

    #[tokio::test]
    async fn test_registry_with_mock_backend() {
        let mut registry = BackendRegistry::new();
        let factory = Box::new(MockFactory::new(BackendType::EbpfLinux, Platform::Linux));

        registry.register_factory(BackendType::EbpfLinux, factory);

        assert!(registry.has_backend(&BackendType::EbpfLinux));
        assert_eq!(registry.backend_count(), 1);
    }

    #[tokio::test]
    async fn test_get_backend() {
        let mut registry = BackendRegistry::new();
        let factory = Box::new(MockFactory::new(BackendType::EbpfLinux, Platform::Linux));

        registry.register_factory(BackendType::EbpfLinux, factory);

        let backend = registry.get_backend(&BackendType::EbpfLinux).await.unwrap();
        assert_eq!(backend.backend_type(), BackendType::EbpfLinux);
        assert_eq!(backend.platform(), Platform::Linux);
    }

    #[tokio::test]
    async fn test_get_nonexistent_backend() {
        let registry = BackendRegistry::new();
        // Register nothing, then ask for Auto — registry should error.
        let result = registry.get_backend(&BackendType::Auto).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_list_available() {
        let mut registry = BackendRegistry::new();
        let factory = Box::new(MockFactory::new(BackendType::EbpfLinux, Platform::Linux));

        registry.register_factory(BackendType::EbpfLinux, factory);

        let available = registry.list_available();
        assert_eq!(available.len(), 1);
        assert_eq!(available[0].backend_type, BackendType::EbpfLinux);
        assert_eq!(available[0].platform, Platform::Linux);
    }

    #[tokio::test]
    async fn test_auto_detect_backend() {
        let mut registry = BackendRegistry::new();
        let current_platform = Platform::current();

        let backend_type = match current_platform {
            Platform::Linux => BackendType::EbpfLinux,
            Platform::Unknown => return, // non-Linux hosts have nothing to register
        };

        let factory = Box::new(MockFactory::new(backend_type.clone(), current_platform));
        registry.register_factory(backend_type, factory);

        let backend = registry.auto_detect_backend().await.unwrap();
        assert_eq!(backend.platform(), current_platform);
    }
}
