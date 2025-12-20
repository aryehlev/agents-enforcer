//! Configuration migration utilities
//!
//! This module provides utilities for migrating from old configuration formats
//! to the new unified configuration system.

use agent_gateway_enforcer_core::backend::{GatewayConfig, FileAccessConfig, UnifiedConfig};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Legacy configuration structure (old format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyConfig {
    /// List of gateway addresses in "IP:PORT" format
    pub gateways: Vec<String>,
    /// File enforcement settings
    pub file_enforcement: Option<LegacyFileEnforcement>,
    /// Additional settings
    pub settings: Option<HashMap<String, serde_json::Value>>,
}

/// Legacy file enforcement structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyFileEnforcement {
    /// Whether file enforcement is enabled
    pub enabled: bool,
    /// Default action
    pub default_deny: Option<bool>,
    /// Allowed paths
    pub allow_paths: Option<Vec<String>>,
    /// Denied paths
    pub deny_paths: Option<Vec<String>>,
}

/// Configuration migrator
pub struct ConfigMigrator;

impl ConfigMigrator {
    /// Create a new migrator
    pub fn new() -> Self {
        Self
    }

    /// Migrate legacy configuration to unified format
    pub fn migrate_legacy_config(&self, legacy: LegacyConfig) -> Result<UnifiedConfig> {
        let mut unified = UnifiedConfig::default();

        // Migrate gateways
        unified.gateways = self.migrate_gateways(&legacy.gateways)?;

        // Migrate file access configuration
        if let Some(file_enforcement) = legacy.file_enforcement {
            unified.file_access = self.migrate_file_enforcement(&file_enforcement)?;
        }

        // Migrate backend settings
        if let Some(settings) = legacy.settings {
            unified.backend_settings = serde_json::to_value(settings)?;
        }

        Ok(unified)
    }

    /// Migrate gateway configurations
    fn migrate_gateways(&self, gateway_strings: &[String]) -> Result<Vec<GatewayConfig>> {
        let mut gateways = Vec::new();

        for (index, gateway_str) in gateway_strings.iter().enumerate() {
            let gateway = self.parse_gateway_string(gateway_str)
                .ok_or_else(|| anyhow!("Invalid gateway format: {}", gateway_str))?;

            gateways.push(GatewayConfig {
                address: gateway.ip.to_string(),
                port: gateway.port,
                enabled: true,
                description: Some(format!("Migrated gateway {}", index + 1)),
            });
        }

        Ok(gateways)
    }

    /// Parse gateway string in "IP:PORT" format
    fn parse_gateway_string(&self, gateway_str: &str) -> Option<GatewayAddr> {
        let parts: Vec<&str> = gateway_str.split(':').collect();
        if parts.len() != 2 {
            return None;
        }

        let ip: std::net::IpAddr = parts[0].trim().parse().ok()?;
        let port: u16 = parts[1].trim().parse().ok()?;

        Some(GatewayAddr { ip, port })
    }

    /// Migrate file enforcement configuration
    fn migrate_file_enforcement(&self, legacy: &LegacyFileEnforcement) -> Result<FileAccessConfig> {
        let mut config = FileAccessConfig {
            default_deny: legacy.default_deny.unwrap_or(false),
            allowed_paths: legacy.allow_paths.clone().unwrap_or_default(),
            denied_paths: legacy.deny_paths.clone().unwrap_or_default(),
        };

        // If enforcement is disabled but paths are specified, keep the paths
        if !legacy.enabled && (config.allowed_paths.is_empty() && config.denied_paths.is_empty()) {
            // Disable completely
            config.allowed_paths.clear();
            config.denied_paths.clear();
        }

        Ok(config)
    }

    /// Load configuration from file and migrate
    pub fn load_and_migrate_file<P: AsRef<Path>>(&self, path: P) -> Result<UnifiedConfig> {
        let content = fs::read_to_string(path)?;
        self.load_and_migrate_str(&content)
    }

    /// Load configuration from string and migrate
    pub fn load_and_migrate_str(&self, content: &str) -> Result<UnifiedConfig> {
        // Try to detect format
        if content.trim_start().starts_with('{') {
            // JSON format
            let legacy: LegacyConfig = serde_json::from_str(content)?;
            self.migrate_legacy_config(legacy)
        } else {
            // Try TOML format
            let legacy: LegacyConfig = toml::from_str(content)
                .map_err(|e| anyhow!("Failed to parse TOML: {}", e))?;
            self.migrate_legacy_config(legacy)
        }
    }

    /// Validate migrated configuration
    pub fn validate_config(&self, config: &UnifiedConfig) -> Result<()> {
        // Validate gateways
        for gateway in &config.gateways {
            if gateway.address.is_empty() {
                return Err(anyhow!("Gateway address cannot be empty"));
            }
            if gateway.port == 0 {
                return Err(anyhow!("Gateway port cannot be 0"));
            }
        }

        // Validate file paths
        for path in &config.file_access.allowed_paths {
            if path.is_empty() {
                return Err(anyhow!("Allowed path cannot be empty"));
            }
        }

        for path in &config.file_access.denied_paths {
            if path.is_empty() {
                return Err(anyhow!("Denied path cannot be empty"));
            }
        }

        Ok(())
    }

    /// Generate migration report
    pub fn generate_migration_report(&self, legacy: &LegacyConfig, unified: &UnifiedConfig) -> MigrationReport {
        MigrationReport {
            original_gateways: legacy.gateways.len(),
            migrated_gateways: unified.gateways.len(),
            file_enforcement_enabled: legacy.file_enforcement
                .as_ref()
                .map(|f| f.enabled)
                .unwrap_or(false),
            allowed_paths_count: unified.file_access.allowed_paths.len(),
            denied_paths_count: unified.file_access.denied_paths.len(),
            backend_settings_count: if unified.backend_settings.is_null() { 0 } else { 1 },
        }
    }
}

/// Gateway address representation
#[derive(Debug, Clone)]
struct GatewayAddr {
    ip: std::net::IpAddr,
    port: u16,
}

/// Migration report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationReport {
    /// Number of gateways in original config
    pub original_gateways: usize,
    /// Number of gateways in migrated config
    pub migrated_gateways: usize,
    /// Whether file enforcement was enabled
    pub file_enforcement_enabled: bool,
    /// Number of allowed paths
    pub allowed_paths_count: usize,
    /// Number of denied paths
    pub denied_paths_count: usize,
    /// Whether backend settings were migrated
    pub backend_settings_count: usize,
}

impl Default for ConfigMigrator {
    fn default() -> Self {
        Self::new()
    }
}

/// Command-line interface for migration
pub struct MigratorCli;

impl MigratorCli {
    /// Run migration with command-line arguments
    pub async fn run_migration(args: &MigrationArgs) -> Result<()> {
        let migrator = ConfigMigrator::new();

        // Load configuration
        let unified = if args.input_file.exists() {
            migrator.load_and_migrate_file(&args.input_file)?
        } else {
            return Err(anyhow!("Input file does not exist: {}", args.input_file.display()));
        };

        // Validate configuration
        migrator.validate_config(&unified)?;

        // Write output
        if let Some(output_file) = &args.output_file {
            let content = if output_file.extension().and_then(|s| s.to_str()) == Some("toml") {
                toml::to_string_pretty(&unified)?
            } else {
                serde_json::to_string_pretty(&unified)?
            };

            fs::write(output_file, content)?;
            println!("Migrated configuration written to: {}", output_file.display());
        } else {
            // Print to stdout
            let output = serde_json::to_string_pretty(&unified)?;
            println!("{}", output);
        }

        Ok(())
    }
}

/// Command-line arguments for migration
#[derive(Debug, Clone)]
pub struct MigrationArgs {
    /// Input configuration file
    pub input_file: std::path::PathBuf,
    /// Output configuration file (optional)
    pub output_file: Option<std::path::PathBuf>,
    /// Validate only (don't migrate)
    pub validate_only: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_gateway_parsing() {
        let migrator = ConfigMigrator::new();

        let gateway = migrator.parse_gateway_string("192.168.1.1:8080").unwrap();
        assert_eq!(gateway.ip.to_string(), "192.168.1.1");
        assert_eq!(gateway.port, 8080);

        let gateway = migrator.parse_gateway_string("[::1]:9090").unwrap();
        assert_eq!(gateway.ip.to_string(), "::1");
        assert_eq!(gateway.port, 9090);

        assert!(migrator.parse_gateway_string("invalid").is_none());
        assert!(migrator.parse_gateway_string("192.168.1.1").is_none());
    }

    #[test]
    fn test_legacy_config_migration() {
        let migrator = ConfigMigrator::new();

        let legacy = LegacyConfig {
            gateways: vec![
                "10.0.0.1:8080".to_string(),
                "192.168.1.100:443".to_string(),
            ],
            file_enforcement: Some(LegacyFileEnforcement {
                enabled: true,
                default_deny: Some(true),
                allow_paths: Some(vec![
                    "/tmp/allowed".to_string(),
                    "/var/log".to_string(),
                ]),
                deny_paths: Some(vec![
                    "/etc/shadow".to_string(),
                    "/root".to_string(),
                ]),
            }),
            settings: None,
        };

        let unified = migrator.migrate_legacy_config(legacy).unwrap();

        assert_eq!(unified.gateways.len(), 2);
        assert_eq!(unified.gateways[0].address, "10.0.0.1");
        assert_eq!(unified.gateways[0].port, 8080);
        assert_eq!(unified.gateways[1].address, "192.168.1.100");
        assert_eq!(unified.gateways[1].port, 443);

        assert!(unified.file_access.default_deny);
        assert_eq!(unified.file_access.allowed_paths.len(), 2);
        assert_eq!(unified.file_access.denied_paths.len(), 2);
    }

    #[test]
    fn test_config_validation() {
        let migrator = ConfigMigrator::new();

        // Valid config
        let valid_config = UnifiedConfig {
            gateways: vec![
                GatewayConfig {
                    address: "10.0.0.1".to_string(),
                    port: 8080,
                    enabled: true,
                    description: None,
                },
            ],
            file_access: FileAccessConfig {
                allowed_paths: vec!["/tmp".to_string()],
                denied_paths: vec!["/etc".to_string()],
                default_deny: false,
            },
            backend_settings: serde_json::Value::Null,
        };

        assert!(migrator.validate_config(&valid_config).is_ok());

        // Invalid config - empty gateway address
        let invalid_config = UnifiedConfig {
            gateways: vec![
                GatewayConfig {
                    address: "".to_string(),
                    port: 8080,
                    enabled: true,
                    description: None,
                },
            ],
            file_access: FileAccessConfig::default(),
            backend_settings: serde_json::Value::Null,
        };

        assert!(migrator.validate_config(&invalid_config).is_err());
    }

    #[test]
    fn test_migration_report() {
        let migrator = ConfigMigrator::new();

        let legacy = LegacyConfig {
            gateways: vec!["10.0.0.1:8080".to_string()],
            file_enforcement: Some(LegacyFileEnforcement {
                enabled: true,
                default_deny: Some(false),
                allow_paths: Some(vec!["/tmp".to_string()]),
                deny_paths: Some(vec!["/root".to_string()]),
            }),
            settings: Some(HashMap::from([
                ("debug".to_string(), serde_json::Value::Bool(true)),
            ])),
        };

        let unified = migrator.migrate_legacy_config(legacy.clone()).unwrap();
        let report = migrator.generate_migration_report(&legacy, &unified);

        assert_eq!(report.original_gateways, 1);
        assert_eq!(report.migrated_gateways, 1);
        assert!(report.file_enforcement_enabled);
        assert_eq!(report.allowed_paths_count, 1);
        assert_eq!(report.denied_paths_count, 1);
        assert_eq!(report.backend_settings_count, 1);
    }
}