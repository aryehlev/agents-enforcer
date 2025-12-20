use std::sync::Arc;
use std::path::{Path, PathBuf};
use tokio::sync::RwLock;
use anyhow::Result;
use async_trait::async_trait;
use agent_gateway_enforcer_common::config::*;

/// Configuration manager for loading, saving, and managing unified configuration
pub struct ConfigManager {
    config_path: PathBuf,
    current_config: Arc<RwLock<UnifiedConfig>>,
    watchers: Arc<RwLock<Vec<Box<dyn ConfigWatcher>>>>,
    validators: Vec<Box<dyn ConfigValidator>>,
}

impl ConfigManager {
    /// Create a new configuration manager
    pub fn new(config_path: impl AsRef<Path>) -> Self {
        Self {
            config_path: config_path.as_ref().to_path_buf(),
            current_config: Arc::new(RwLock::new(UnifiedConfig::default())),
            watchers: Arc::new(RwLock::new(Vec::new())),
            validators: Vec::new(),
        }
    }
    
    /// Load configuration from file with validation
    pub async fn load(&mut self) -> Result<UnifiedConfig> {
        let config_content = tokio::fs::read_to_string(&self.config_path).await
            .map_err(|e| anyhow::anyhow!("Failed to read config file {}: {}", self.config_path.display(), e))?;
        
        let mut config = self.parse_config(&config_content)?;
        
        // Apply environment variable overrides
        self.apply_env_overrides(&mut config).await?;
        
        // Validate configuration
        self.validate(&config)?;
        
        // Store in memory
        let mut current = self.current_config.write().await;
        *current = config.clone();
        
        // Notify watchers
        self.notify_watchers(ConfigEvent::Loaded(config.clone())).await;
        
        Ok(config)
    }
    
    /// Save configuration to file
    pub async fn save(&self, config: &UnifiedConfig) -> Result<()> {
        // Validate before saving
        self.validate(config)?;
        
        // Serialize with pretty printing
        let content = self.serialize_config(config)?;
        
        // Write to temporary file first
        let temp_path = self.config_path.with_extension("tmp");
        tokio::fs::write(&temp_path, content).await
            .map_err(|e| anyhow::anyhow!("Failed to write temp config file {}: {}", temp_path.display(), e))?;
        
        // Atomic rename
        tokio::fs::rename(&temp_path, &self.config_path).await
            .map_err(|e| anyhow::anyhow!("Failed to rename temp config file to {}: {}", self.config_path.display(), e))?;
        
        // Update in-memory copy
        let mut current = self.current_config.write().await;
        *current = config.clone();
        
        // Notify watchers
        self.notify_watchers(ConfigEvent::Saved(config.clone())).await;
        
        Ok(())
    }
    
    /// Get current configuration
    pub async fn get(&self) -> UnifiedConfig {
        self.current_config.read().await.clone()
    }
    
    /// Update specific configuration section
    pub async fn update_section<F>(&self, updater: F) -> Result<()> 
    where 
        F: FnOnce(&mut UnifiedConfig)
    {
        let mut config = self.current_config.read().await.clone();
        updater(&mut config);
        self.validate(&config)?;
        self.save(&config).await?;
        self.notify_watchers(ConfigEvent::Updated(config)).await;
        Ok(())
    }
    
    /// Add configuration change watcher
    pub async fn add_watcher(&self, watcher: Box<dyn ConfigWatcher>) {
        let mut watchers = self.watchers.write().await;
        watchers.push(watcher);
    }
    
    /// Add configuration validator
    pub fn add_validator(&mut self, validator: Box<dyn ConfigValidator>) {
        self.validators.push(validator);
    }
    
    /// Start configuration file watching for hot reload
    pub async fn start_hot_reload(&self) -> Result<()> {
        use notify::{Watcher, RecursiveMode, recommended_watcher, Config, EventKind};
        use std::time::Duration;
        
        let (mut watcher, mut rx) = recommended_watcher(Config::default())?;
        
        watcher.watch(&self.config_path, RecursiveMode::NonRecursive)?;
        
        let current_config = self.current_config.clone();
        let watchers = self.watchers.clone();
        let config_path = self.config_path.clone();
        
        tokio::spawn(async move {
            // Debounce file system events
            let mut last_event = None;
            let debounce_duration = Duration::from_millis(500);
            
            while let Ok(event) = rx.recv() {
                match event {
                    Ok(event) => {
                        if matches!(event.kind, EventKind::Modify(_)) {
                            let now = std::time::Instant::now();
                            
                            // Check if this is a duplicate event within debounce window
                            if let Some(last_time) = last_event {
                                if now.duration_since(last_time) < debounce_duration {
                                    continue;
                                }
                            }
                            
                            last_event = Some(now);
                            
                            // Add a small delay to ensure file write is complete
                            tokio::time::sleep(debounce_duration).await;
                            
                            match Self::reload_config(&config_path).await {
                                Ok(new_config) => {
                                    let mut current = current_config.write().await;
                                    *current = new_config.clone();
                                    
                                    // Notify watchers
                                    let mut watchers = watchers.write().await;
                                    for watcher in watchers.iter_mut() {
                                        let _ = watcher.on_config_changed(ConfigEvent::HotReloaded(new_config.clone())).await;
                                    }
                                }
                                Err(e) => {
                                    tracing::error!("Hot reload failed: {}", e);
                                    
                                    // Notify watchers of error
                                    let mut watchers = watchers.write().await;
                                    for watcher in watchers.iter_mut() {
                                        let _ = watcher.on_config_changed(ConfigEvent::ValidationError(e)).await;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("File watcher error: {}", e);
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Generate configuration from template
    pub fn generate_from_template(&self, template: ConfigTemplate) -> UnifiedConfig {
        template.generate_config()
    }
    
    /// Validate configuration without loading
    pub fn validate_config(&self, config: &UnifiedConfig) -> Result<()> {
        self.validate(config)
    }
    
    /// Get configuration file path
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }
    
    /// Check if configuration file exists
    pub async fn config_exists(&self) -> bool {
        tokio::fs::metadata(&self.config_path).await.is_ok()
    }
    
    /// Create default configuration file
    pub async fn create_default_config(&self, template: ConfigTemplate) -> Result<()> {
        let config = self.generate_from_template(template);
        self.save(&config).await
    }
    
    fn parse_config(&self, content: &str) -> Result<UnifiedConfig> {
        let trimmed = content.trim();
        
        // Try YAML first (most common for configuration)
        if trimmed.starts_with("---") || trimmed.contains(":") && !trimmed.starts_with("{") {
            return serde_yaml::from_str(content)
                .map_err(|e| anyhow::anyhow!("Failed to parse YAML configuration: {}", e));
        }
        
        // Try TOML
        if trimmed.contains("=") && !trimmed.contains("---") && !trimmed.starts_with("{") {
            return toml::from_str(content)
                .map_err(|e| anyhow::anyhow!("Failed to parse TOML configuration: {}", e));
        }
        
        // Try JSON
        if trimmed.starts_with("{") {
            return serde_json::from_str(content)
                .map_err(|e| anyhow::anyhow!("Failed to parse JSON configuration: {}", e));
        }
        
        Err(anyhow::anyhow!("Unable to determine configuration format. Supported formats: YAML, TOML, JSON"))
    }
    
    fn serialize_config(&self, config: &UnifiedConfig) -> Result<String> {
        // Use YAML for human-readable format
        serde_yaml::to_string_pretty(config)
            .map_err(|e| anyhow::anyhow!("Failed to serialize configuration to YAML: {}", e))
    }
    
    async fn apply_env_overrides(&self, config: &mut UnifiedConfig) -> Result<()> {
        // Apply environment variable overrides with clear precedence
        
        // Backend configuration
        if let Ok(backend) = std::env::var("AGENT_GATEWAY_BACKEND") {
            config.backend.backend_type = match backend.to_lowercase().as_str() {
                "auto" => BackendType::Auto,
                "ebpf_linux" => BackendType::EbpfLinux,
                "macos_desktop" => BackendType::MacOSDesktop,
                "windows_desktop" => BackendType::WindowsDesktop,
                _ => return Err(anyhow::anyhow!("Invalid backend type: {}", backend)),
            };
        }
        
        // Metrics configuration
        if let Ok(port) = std::env::var("AGENT_GATEWAY_METRICS_PORT") {
            config.metrics.port = port.parse()
                .map_err(|e| anyhow::anyhow!("Invalid metrics port {}: {}", port, e))?;
        }
        
        if let Ok(enabled) = std::env::var("AGENT_GATEWAY_METRICS_ENABLED") {
            config.metrics.enabled = enabled.parse()
                .map_err(|e| anyhow::anyhow!("Invalid metrics enabled flag {}: {}", enabled, e))?;
        }
        
        // Logging configuration
        if let Ok(level) = std::env::var("AGENT_GATEWAY_LOG_LEVEL") {
            config.logging.level = match level.to_lowercase().as_str() {
                "trace" => LogLevel::Trace,
                "debug" => LogLevel::Debug,
                "info" => LogLevel::Info,
                "warn" => LogLevel::Warn,
                "error" => LogLevel::Error,
                _ => return Err(anyhow::anyhow!("Invalid log level: {}", level)),
            };
        }
        
        // Gateway configuration (support multiple gateways)
        let gateway_envs: Vec<(String, String)> = std::env::vars()
            .filter(|(k, _)| k.starts_with("AGENT_GATEWAY_GATEWAY_"))
            .collect();
            
        for (key, value) in gateway_envs {
            let parts: Vec<&str> = key.split('_').collect();
            if parts.len() >= 4 {
                let index: usize = parts[3].parse()
                    .unwrap_or(0);
                
                // Ensure we have enough gateway entries
                while config.gateways.len() <= index {
                    config.gateways.push(GatewayConfig::default());
                }
                
                match parts[2] {
                    "ADDRESS" => config.gateways[index].address = value,
                    "DESCRIPTION" => config.gateways[index].description = Some(value),
                    "ENABLED" => config.gateways[index].enabled = value.parse()
                        .map_err(|e| anyhow::anyhow!("Invalid gateway enabled flag {}: {}", value, e))?,
                    "PRIORITY" => config.gateways[index].priority = value.parse()
                        .map_err(|e| anyhow::anyhow!("Invalid gateway priority {}: {}", value, e))?,
                    _ => {}
                }
            }
        }
        
        // File access configuration
        if let Ok(enabled) = std::env::var("AGENT_GATEWAY_FILE_ACCESS_ENABLED") {
            config.file_access.enabled = enabled.parse()
                .map_err(|e| anyhow::anyhow!("Invalid file access enabled flag {}: {}", enabled, e))?;
        }
        
        if let Ok(policy) = std::env::var("AGENT_GATEWAY_DEFAULT_POLICY") {
            config.file_access.default_policy = match policy.to_lowercase().as_str() {
                "allow" => DefaultPolicy::Allow,
                "deny" => DefaultPolicy::Deny,
                "prompt" => DefaultPolicy::Prompt,
                _ => return Err(anyhow::anyhow!("Invalid default policy: {}", policy)),
            };
        }
        
        // UI configuration
        if let Ok(enabled) = std::env::var("AGENT_GATEWAY_WEB_DASHBOARD_ENABLED") {
            config.ui.web_dashboard.enabled = enabled.parse()
                .map_err(|e| anyhow::anyhow!("Invalid web dashboard enabled flag {}: {}", enabled, e))?;
        }
        
        if let Ok(port) = std::env::var("AGENT_GATEWAY_WEB_DASHBOARD_PORT") {
            config.ui.web_dashboard.port = port.parse()
                .map_err(|e| anyhow::anyhow!("Invalid web dashboard port {}: {}", port, e))?;
        }
        
        Ok(())
    }
    
    fn validate(&self, config: &UnifiedConfig) -> Result<()> {
        // Run all validators
        for validator in &self.validators {
            validator.validate(config)?;
        }
        Ok(())
    }
    
    async fn notify_watchers(&self, event: ConfigEvent) {
        let mut watchers = self.watchers.write().await;
        for watcher in watchers.iter_mut() {
            let _ = watcher.on_config_changed(event.clone()).await;
        }
    }
    
    async fn reload_config(config_path: &Path) -> Result<UnifiedConfig> {
        let content = tokio::fs::read_to_string(config_path).await
            .map_err(|e| anyhow::anyhow!("Failed to read config file {}: {}", config_path.display(), e))?;
        
        let manager = ConfigManager::new(config_path);
        manager.parse_config(&content)
    }
}

/// Configuration events
#[derive(Debug, Clone)]
pub enum ConfigEvent {
    Loaded(UnifiedConfig),
    Saved(UnifiedConfig),
    Updated(UnifiedConfig),
    HotReloaded(UnifiedConfig),
    ValidationError(anyhow::Error),
}

/// Trait for configuration change watchers
#[async_trait]
pub trait ConfigWatcher: Send + Sync {
    async fn on_config_changed(&mut self, event: ConfigEvent);
}

/// Trait for configuration validators
#[async_trait]
pub trait ConfigValidator: Send + Sync {
    fn validate(&self, config: &UnifiedConfig) -> Result<()>;
}

/// Default configuration watcher that logs events
pub struct LoggingConfigWatcher;

#[async_trait]
impl ConfigWatcher for LoggingConfigWatcher {
    async fn on_config_changed(&mut self, event: ConfigEvent) {
        match event {
            ConfigEvent::Loaded(_) => tracing::info!("Configuration loaded"),
            ConfigEvent::Saved(_) => tracing::info!("Configuration saved"),
            ConfigEvent::Updated(_) => tracing::info!("Configuration updated"),
            ConfigEvent::HotReloaded(_) => tracing::info!("Configuration hot-reloaded"),
            ConfigEvent::ValidationError(e) => tracing::error!("Configuration validation error: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;
    
    #[tokio::test]
    async fn test_config_loading() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");
        
        // Create test configuration
        let config = UnifiedConfig::default();
        let yaml = serde_yaml::to_string(&config).unwrap();
        fs::write(&config_path, yaml).unwrap();
        
        // Test loading
        let mut manager = ConfigManager::new(&config_path);
        let loaded = manager.load().await.unwrap();
        
        assert_eq!(config.version, loaded.version);
        assert_eq!(config.metrics.port, loaded.metrics.port);
    }
    
    #[tokio::test]
    async fn test_config_saving() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");
        
        let manager = ConfigManager::new(&config_path);
        let config = UnifiedConfig::default();
        
        // Test saving
        manager.save(&config).await.unwrap();
        
        // Verify file exists and contains valid YAML
        assert!(manager.config_exists().await);
        let content = fs::read_to_string(&config_path).unwrap();
        let parsed: UnifiedConfig = serde_yaml::from_str(&content).unwrap();
        assert_eq!(config.version, parsed.version);
    }
    
    #[tokio::test]
    async fn test_env_overrides() {
        std::env::set_var("AGENT_GATEWAY_METRICS_PORT", "9091");
        std::env::set_var("AGENT_GATEWAY_LOG_LEVEL", "debug");
        
        let mut config = UnifiedConfig::default();
        let manager = ConfigManager::new("dummy_path");
        manager.apply_env_overrides(&mut config).await.unwrap();
        
        assert_eq!(config.metrics.port, 9091);
        assert_eq!(config.logging.level, LogLevel::Debug);
        
        std::env::remove_var("AGENT_GATEWAY_METRICS_PORT");
        std::env::remove_var("AGENT_GATEWAY_LOG_LEVEL");
    }
    
    #[tokio::test]
    async fn test_config_format_detection() {
        let manager = ConfigManager::new("dummy_path");
        
        // Test YAML
        let yaml = "version: \"1.0\"\nmetrics:\n  port: 9090";
        let config = manager.parse_config(yaml).unwrap();
        assert_eq!(config.version, "1.0");
        
        // Test JSON
        let json = "{\"version\":\"1.0\",\"metrics\":{\"port\":9090}}";
        let config = manager.parse_config(json).unwrap();
        assert_eq!(config.version, "1.0");
        
        // Test TOML
        let toml = "version = \"1.0\"\n[metrics]\nport = 9090";
        let config = manager.parse_config(toml).unwrap();
        assert_eq!(config.version, "1.0");
    }
    
    #[tokio::test]
    async fn test_config_watchers() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");
        
        let manager = ConfigManager::new(&config_path);
        let config = UnifiedConfig::default();
        
        // Add logging watcher
        manager.add_watcher(Box::new(LoggingConfigWatcher)).await;
        
        // Save and trigger event
        manager.save(&config).await.unwrap();
        
        // Test should pass without panicking
        assert!(manager.config_exists().await);
    }
    
    #[tokio::test]
    async fn test_template_generation() {
        let manager = ConfigManager::new("dummy_path");
        
        let minimal = manager.generate_from_template(ConfigTemplate::Minimal);
        assert!(!minimal.metrics.enabled);
        
        let dev = manager.generate_from_template(ConfigTemplate::Development);
        assert!(dev.metrics.enabled);
        assert_eq!(dev.logging.level, LogLevel::Debug);
    }
    
    #[tokio::test]
    async fn test_section_update() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");
        
        let manager = ConfigManager::new(&config_path);
        let config = UnifiedConfig::default();
        manager.save(&config).await.unwrap();
        
        // Update metrics port
        manager.update_section(|c| c.metrics.port = 9091).await.unwrap();
        
        let updated = manager.get().await;
        assert_eq!(updated.metrics.port, 9091);
    }
    
    #[test]
    fn test_config_event_display() {
        let event = ConfigEvent::Loaded(UnifiedConfig::default());
        // Should not panic
        let _ = format!("{:?}", event);
    }
}