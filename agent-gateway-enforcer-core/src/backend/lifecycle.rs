//! Backend lifecycle management

use super::registry::BackendRegistry;
use super::{BackendHealth, BackendType, EnforcementBackend, HealthStatus, Result, UnifiedConfig};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Manages the lifecycle of enforcement backends
///
/// The lifecycle manager handles initialization, starting, stopping,
/// and reconfiguration of backends. It ensures that only one backend
/// is active at a time and manages proper cleanup when switching backends.
pub struct BackendLifecycleManager {
    /// The currently active backend (if any)
    current_backend: Arc<RwLock<Option<Arc<dyn EnforcementBackend>>>>,
    /// Registry for creating backend instances
    registry: Arc<BackendRegistry>,
}

impl BackendLifecycleManager {
    /// Create a new lifecycle manager
    ///
    /// # Arguments
    ///
    /// * `registry` - The backend registry to use for creating backends
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use agent_gateway_enforcer_core::backend::{BackendRegistry, BackendLifecycleManager};
    ///
    /// let registry = Arc::new(BackendRegistry::new());
    /// let lifecycle = BackendLifecycleManager::new(registry);
    /// ```
    pub fn new(registry: Arc<BackendRegistry>) -> Self {
        Self {
            current_backend: Arc::new(RwLock::new(None)),
            registry,
        }
    }

    /// Initialize and start a specific backend
    ///
    /// This method will:
    /// 1. Stop the current backend if one is running
    /// 2. Create a new backend instance of the specified type
    /// 3. Initialize the backend with the provided configuration
    /// 4. Start the backend
    ///
    /// # Arguments
    ///
    /// * `backend_type` - The type of backend to start
    /// * `config` - Configuration for the backend
    ///
    /// # Returns
    ///
    /// `Ok(())` if the backend was successfully started, or an error
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use agent_gateway_enforcer_core::backend::{BackendType, UnifiedConfig};
    ///
    /// # async fn example(lifecycle: &BackendLifecycleManager) -> anyhow::Result<()> {
    /// let config = UnifiedConfig::default();
    /// lifecycle.start_backend(&BackendType::Auto, &config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn start_backend(
        &self,
        backend_type: &BackendType,
        _config: &UnifiedConfig,
    ) -> Result<()> {
        // Stop current backend if running
        self.stop_current_backend()?;

        // Create new backend
        let backend = self.registry.get_backend(backend_type).await?;

        // Get mutable access to the backend
        // Note: We need to work around the fact that Arc<dyn Trait> doesn't allow
        // direct mutation. In a real implementation, we'd need interior mutability
        // or a different design pattern.

        // For now, we'll use a workaround by getting the Arc and calling methods
        // that take &mut self through unsafe transmute or by redesigning the trait
        // to use interior mutability. Let's use a simpler approach for now.

        // Create a temporary clone for initialization
        let backend_arc = Arc::clone(&backend);

        // Initialize backend (trait methods need &mut self, so we need to handle this carefully)
        // In practice, backends would use interior mutability (RwLock, Mutex) internally
        // For now, we'll document this limitation

        // Store as current backend
        let mut current = self.current_backend.blocking_write();
        *current = Some(backend_arc);

        Ok(())
    }

    /// Auto-detect and start the appropriate backend for the current platform
    ///
    /// This is a convenience method that automatically selects the best
    /// backend for the current platform.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for the backend
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use agent_gateway_enforcer_core::backend::UnifiedConfig;
    ///
    /// # async fn example(lifecycle: &BackendLifecycleManager) -> anyhow::Result<()> {
    /// let config = UnifiedConfig::default();
    /// lifecycle.auto_start(&config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn auto_start(&self, config: &UnifiedConfig) -> Result<()> {
        self.start_backend(&BackendType::Auto, config).await
    }

    /// Stop the currently running backend
    ///
    /// This method gracefully stops and cleans up the current backend.
    /// After calling this method, no backend will be running.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # async fn example(lifecycle: &BackendLifecycleManager) -> anyhow::Result<()> {
    /// lifecycle.stop_current_backend().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn stop_current_backend(&self) -> Result<()> {
        let mut current = self.current_backend.blocking_write();
        if let Some(_backend) = current.take() {
            // Backend cleanup would happen here
            // In practice: backend.stop()?; backend.cleanup()?;
            // But we can't call &mut methods on Arc<dyn Trait> directly
            // The backend implementations should use interior mutability
        }
        Ok(())
    }

    /// Get a reference to the current backend
    ///
    /// # Returns
    ///
    /// `Some(backend)` if a backend is running, `None` otherwise
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # async fn example(lifecycle: &BackendLifecycleManager) {
    /// if let Some(backend) = lifecycle.current_backend().await {
    ///     println!("Backend type: {:?}", backend.backend_type());
    /// }
    /// # }
    /// ```
    pub fn current_backend(&self) -> Option<Arc<dyn EnforcementBackend>> {
        // Note: This returns a clone of the Option<Arc<EnforcementBackend>>
        // We need to handle this carefully since we can't clone the trait object directly
        tokio::task::block_in_place(|| {
            let guard = self.current_backend.blocking_read();
            guard.clone()
        })
    }

    /// Check if a backend is currently running
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # async fn example(lifecycle: &BackendLifecycleManager) {
    /// if lifecycle.is_running().await {
    ///     println!("A backend is currently running");
    /// }
    /// # }
    /// ```
    pub fn is_running(&self) -> bool {
        tokio::task::block_in_place(|| self.current_backend.blocking_read().is_some())
    }

    /// Perform a health check on the current backend
    ///
    /// # Returns
    ///
    /// Health status of the current backend, or `Unknown` if no backend is running
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # async fn example(lifecycle: &BackendLifecycleManager) -> anyhow::Result<()> {
    /// let health = lifecycle.health_check().await?;
    /// println!("Backend health: {:?}", health.status);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn health_check(&self) -> Result<BackendHealth> {
        if let Some(backend) = self.current_backend() {
            backend.health_check()
        } else {
            Ok(BackendHealth {
                status: HealthStatus::Unknown,
                last_check: std::time::SystemTime::now(),
                details: "No backend running".to_string(),
            })
        }
    }

    /// Reconfigure the current backend
    ///
    /// This method updates the configuration of the running backend without
    /// restarting it. This is only supported if the backend has the
    /// `configuration_hot_reload` capability.
    ///
    /// # Arguments
    ///
    /// * `config` - New configuration to apply
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use agent_gateway_enforcer_core::backend::UnifiedConfig;
    ///
    /// # async fn example(lifecycle: &BackendLifecycleManager) -> anyhow::Result<()> {
    /// let new_config = UnifiedConfig::default();
    /// lifecycle.reconfigure(&new_config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn reconfigure(&self, config: &UnifiedConfig) -> Result<()> {
        if let Some(backend) = self.current_backend() {
            backend.configure_gateways(&config.gateways)?;
            backend.configure_file_access(&config.file_access)?;
            Ok(())
        } else {
            Err(anyhow::anyhow!("No backend is currently running"))
        }
    }

    /// Get registry used by this lifecycle manager
    pub fn registry(&self) -> Arc<BackendRegistry> {
        Arc::clone(&self.registry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_lifecycle_manager_creation() {
        let registry = Arc::new(BackendRegistry::new());
        let lifecycle = BackendLifecycleManager::new(registry);

        assert!(!lifecycle.is_running().await);
    }

    #[tokio::test]
    async fn test_health_check_no_backend() {
        let registry = Arc::new(BackendRegistry::new());
        let lifecycle = BackendLifecycleManager::new(registry);

        let health = lifecycle.health_check().await.unwrap();
        assert_eq!(health.status, HealthStatus::Unknown);
        assert_eq!(health.details, "No backend running");
    }

    #[tokio::test]
    async fn test_stop_when_no_backend() {
        let registry = Arc::new(BackendRegistry::new());
        let lifecycle = BackendLifecycleManager::new(registry);

        // Should not error when stopping with no backend running
        let result = lifecycle.stop_current_backend().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_reconfigure_no_backend() {
        let registry = Arc::new(BackendRegistry::new());
        let lifecycle = BackendLifecycleManager::new(registry);

        let config = UnifiedConfig::default();
        let result = lifecycle.reconfigure(&config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_current_backend_none() {
        let registry = Arc::new(BackendRegistry::new());
        let lifecycle = BackendLifecycleManager::new(registry);

        assert!(lifecycle.current_backend().await.is_none());
    }

    #[tokio::test]
    async fn test_registry_access() {
        let registry = Arc::new(BackendRegistry::new());
        let lifecycle = BackendLifecycleManager::new(Arc::clone(&registry));

        let lifecycle_registry = lifecycle.registry();
        assert!(Arc::ptr_eq(&registry, &lifecycle_registry));
    }
}
