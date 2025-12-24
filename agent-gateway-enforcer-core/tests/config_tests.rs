//! Integration tests for configuration system
//!
//! These tests verify configuration loading, saving, validation,
//! and hot-reloading functionality.

mod common;

use agent_gateway_enforcer_common::config::*;
use agent_gateway_enforcer_core::config::{ConfigEvent, ConfigManager, ConfigWatcher};
use async_trait::async_trait;
use common::create_test_config;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;

/// Test watcher that tracks events
struct TestWatcher {
    events: Arc<Mutex<Vec<String>>>,
}

impl TestWatcher {
    fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    async fn get_events(&self) -> Vec<String> {
        self.events.lock().await.clone()
    }

    async fn clear_events(&self) {
        self.events.lock().await.clear();
    }
}

#[async_trait]
impl ConfigWatcher for TestWatcher {
    async fn on_config_changed(&mut self, event: ConfigEvent) {
        let event_name = match event {
            ConfigEvent::Loaded(_) => "loaded",
            ConfigEvent::Saved(_) => "saved",
            ConfigEvent::Updated(_) => "updated",
            ConfigEvent::HotReloaded(_) => "hot_reloaded",
            ConfigEvent::ValidationError(_) => "validation_error",
        };
        self.events.lock().await.push(event_name.to_string());
    }
}

#[tokio::test]
async fn test_config_manager_creation() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("config.yaml");

    let manager = ConfigManager::new(&config_path);
    assert_eq!(manager.config_path(), config_path.as_path());
}

#[tokio::test]
async fn test_config_loading_yaml() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("config.yaml");

    // Create test configuration file
    let config = create_test_config();
    let yaml = serde_yaml::to_string(&config).unwrap();
    std::fs::write(&config_path, yaml).unwrap();

    // Load configuration
    let mut manager = ConfigManager::new(&config_path);
    let loaded = manager.load().await.unwrap();

    assert_eq!(config.version, loaded.version);
    assert_eq!(config.metrics.port, loaded.metrics.port);
}

#[tokio::test]
async fn test_config_loading_json() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("config.json");

    // Create test configuration file in JSON
    let config = create_test_config();
    let json = serde_json::to_string_pretty(&config).unwrap();
    std::fs::write(&config_path, json).unwrap();

    // Load configuration
    let mut manager = ConfigManager::new(&config_path);
    let loaded = manager.load().await.unwrap();

    assert_eq!(config.version, loaded.version);
    assert_eq!(config.metrics.port, loaded.metrics.port);
}

#[tokio::test]
async fn test_config_loading_toml() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    // Create test configuration file in TOML
    let config = create_test_config();
    let toml = toml::to_string_pretty(&config).unwrap();
    std::fs::write(&config_path, toml).unwrap();

    // Load configuration
    let mut manager = ConfigManager::new(&config_path);
    let loaded = manager.load().await.unwrap();

    assert_eq!(config.version, loaded.version);
}

#[tokio::test]
async fn test_config_saving() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("config.yaml");

    let manager = ConfigManager::new(&config_path);
    let config = create_test_config();

    // Save configuration
    manager.save(&config).await.unwrap();

    // Verify file exists and is valid
    assert!(config_path.exists());
    let content = std::fs::read_to_string(&config_path).unwrap();
    let parsed: UnifiedConfig = serde_yaml::from_str(&content).unwrap();
    assert_eq!(config.version, parsed.version);
}

#[tokio::test]
async fn test_config_get_current() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("config.yaml");

    let manager = ConfigManager::new(&config_path);
    let config = create_test_config();

    manager.save(&config).await.unwrap();

    let current = manager.get_current().await;
    assert_eq!(config.version, current.version);
}

#[tokio::test]
async fn test_config_update_current() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("config.yaml");

    let manager = ConfigManager::new(&config_path);
    let mut config = create_test_config();

    manager.save(&config).await.unwrap();

    // Update configuration
    config.version = "2.0".to_string();
    manager.update_current(config.clone()).await.unwrap();

    let current = manager.get_current().await;
    assert_eq!(current.version, "2.0");
}

#[tokio::test]
async fn test_config_section_update() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("config.yaml");

    let manager = ConfigManager::new(&config_path);
    let config = create_test_config();
    manager.save(&config).await.unwrap();

    // Update metrics port
    manager
        .update_section(|c| c.metrics.port = 9091)
        .await
        .unwrap();

    let updated = manager.get().await;
    assert_eq!(updated.metrics.port, 9091);

    // Verify file was updated
    let content = std::fs::read_to_string(&config_path).unwrap();
    let parsed: UnifiedConfig = serde_yaml::from_str(&content).unwrap();
    assert_eq!(parsed.metrics.port, 9091);
}

#[tokio::test]
async fn test_config_watcher() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("config.yaml");

    let manager = ConfigManager::new(&config_path);
    let config = create_test_config();

    let watcher = TestWatcher::new();
    let events = watcher.events.clone();

    manager.add_watcher(Box::new(watcher)).await;

    // Save should trigger event
    manager.save(&config).await.unwrap();

    // Give watcher time to process
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let recorded_events = events.lock().await;
    assert!(recorded_events.contains(&"saved".to_string()));
}

#[tokio::test]
async fn test_config_exists() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("config.yaml");

    let manager = ConfigManager::new(&config_path);

    // Should not exist initially
    assert!(!manager.config_exists().await);

    // Create config
    let config = create_test_config();
    manager.save(&config).await.unwrap();

    // Should exist now
    assert!(manager.config_exists().await);
}

#[tokio::test]
async fn test_create_default_config() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("config.yaml");

    let manager = ConfigManager::new(&config_path);

    // Create default config
    manager
        .create_default_config(ConfigTemplate::Minimal)
        .await
        .unwrap();

    assert!(manager.config_exists().await);

    let loaded = manager.get_current().await;
    assert!(!loaded.metrics.enabled); // Minimal template has metrics disabled
}

#[tokio::test]
async fn test_env_variable_overrides() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("config.yaml");

    // Set environment variables
    std::env::set_var("AGENT_GATEWAY_METRICS_PORT", "9999");
    std::env::set_var("AGENT_GATEWAY_LOG_LEVEL", "debug");

    let mut manager = ConfigManager::new(&config_path);
    let config = create_test_config();
    std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();

    // Load should apply env overrides
    let loaded = manager.load().await.unwrap();

    assert_eq!(loaded.metrics.port, 9999);
    assert_eq!(loaded.logging.level, LogLevel::Debug);

    // Clean up
    std::env::remove_var("AGENT_GATEWAY_METRICS_PORT");
    std::env::remove_var("AGENT_GATEWAY_LOG_LEVEL");
}

#[tokio::test]
async fn test_config_template_minimal() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("config.yaml");

    let manager = ConfigManager::new(&config_path);
    let config = manager.generate_from_template(ConfigTemplate::Minimal);

    assert!(!config.metrics.enabled);
    assert_eq!(config.logging.level, LogLevel::Warn);
}

#[tokio::test]
async fn test_config_template_development() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("config.yaml");

    let manager = ConfigManager::new(&config_path);
    let config = manager.generate_from_template(ConfigTemplate::Development);

    assert!(config.metrics.enabled);
    assert_eq!(config.logging.level, LogLevel::Debug);
}

#[tokio::test]
async fn test_config_template_production() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("config.yaml");

    let manager = ConfigManager::new(&config_path);
    let config = manager.generate_from_template(ConfigTemplate::Production);

    assert!(config.metrics.enabled);
    assert_eq!(config.logging.level, LogLevel::Info);
}

#[tokio::test]
async fn test_invalid_config_format() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("config.txt");

    // Write invalid content
    std::fs::write(&config_path, "not valid yaml, json, or toml").unwrap();

    let mut manager = ConfigManager::new(&config_path);
    let result = manager.load().await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_missing_config_file() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("nonexistent.yaml");

    let mut manager = ConfigManager::new(&config_path);
    let result = manager.load().await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_config_validation() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("config.yaml");

    let manager = ConfigManager::new(&config_path);
    let config = create_test_config();

    // Validation should succeed for valid config
    let result = manager.validate_config(&config);
    assert!(result.is_ok());
}
