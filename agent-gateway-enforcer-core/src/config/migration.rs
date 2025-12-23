use agent_gateway_enforcer_common::config::*;
use serde_json::Value;
use anyhow::Result;
use std::path::{Path, PathBuf};
use std::collections::HashMap;

/// Configuration migrator for handling legacy configurations
pub struct ConfigMigrator;

impl ConfigMigrator {
    pub fn new() -> Self {
        Self
    }
    
    /// Migrate configuration from legacy format
    pub async fn migrate_from_legacy(&self, legacy_path: &Path) -> Result<UnifiedConfig> {
        let legacy_content = tokio::fs::read_to_string(legacy_path).await
            .map_err(|e| anyhow::anyhow!("Failed to read legacy config file {}: {}", legacy_path.display(), e))?;
        
        // Try to detect legacy format
        if self.detect_cli_args_format(&legacy_content) {
            return self.migrate_from_cli_args(&legacy_content).await;
        }
        
        if self.detect_ebpf_config_format(&legacy_content) {
            return self.migrate_from_ebpf_config(&legacy_content).await;
        }
        
        if self.detect_json_config_format(&legacy_content) {
            return self.migrate_from_json_config(&legacy_content).await;
        }
        
        Err(anyhow::anyhow!("Unable to detect legacy configuration format"))
    }
    
    /// Upgrade configuration version
    pub fn upgrade_version(&self, mut config: UnifiedConfig, from_version: &str, to_version: &str) -> Result<UnifiedConfig> {
        match (from_version, to_version) {
            ("1.0", "1.1") => {
                self.upgrade_from_1_0_to_1_1(&mut config)?;
            }
            ("1.1", "1.2") => {
                self.upgrade_from_1_1_to_1_2(&mut config)?;
            }
            ("1.0", "1.2") => {
                self.upgrade_from_1_0_to_1_1(&mut config)?;
                self.upgrade_from_1_1_to_1_2(&mut config)?;
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Migration from {} to {} not supported", from_version, to_version
                ));
            }
        }
        
        config.version = to_version.to_string();
        Ok(config)
    }
    
    /// Create backup of configuration before migration
    pub async fn create_backup(&self, config_path: &Path) -> Result<PathBuf> {
        let backup_path = config_path.with_extension("bak");
        
        if config_path.exists() {
            tokio::fs::copy(config_path, &backup_path).await
                .map_err(|e| anyhow::anyhow!("Failed to create backup of {}: {}", config_path.display(), e))?;
        }
        
        Ok(backup_path)
    }
    
    /// Validate migrated configuration
    pub fn validate_migrated_config(&self, config: &UnifiedConfig) -> Result<()> {
        // Basic validation
        if config.version.is_empty() {
            return Err(anyhow::anyhow!("Migrated config has empty version"));
        }
        
        // Validate gateways
        for (index, gateway) in config.gateways.iter().enumerate() {
            if gateway.address.is_empty() {
                return Err(anyhow::anyhow!("Gateway {} has empty address after migration", index));
            }
        }
        
        // Validate file access rules
        for (index, rule) in config.file_access.rules.iter().enumerate() {
            if rule.path.is_empty() {
                return Err(anyhow::anyhow!("File access rule {} has empty path after migration", index));
            }
        }
        
        Ok(())
    }
    
    /// Detect CLI arguments format
    fn detect_cli_args_format(&self, content: &str) -> bool {
        content.contains("--gateway") || 
        content.contains("--default-deny") || 
        content.contains("--metrics-port")
    }
    
    /// Detect eBPF configuration format
    fn detect_ebpf_config_format(&self, content: &str) -> bool {
        content.contains("DEFAULT_DENY") || 
        content.contains("ALLOWED_GATEWAYS") || 
        content.contains("FILE_ACCESS_RULES")
    }
    
    /// Detect JSON configuration format
    fn detect_json_config_format(&self, content: &str) -> bool {
        content.trim_start().starts_with("{") && 
        (content.contains("backend") || content.contains("gateways"))
    }
    
    /// Migrate from CLI arguments format
    async fn migrate_from_cli_args(&self, args: &str) -> Result<UnifiedConfig> {
        let mut config = UnifiedConfig::default();
        
        // Parse legacy CLI arguments and convert to unified config
        let words: Vec<&str> = args.split_whitespace().collect();
        let mut i = 0;
        
        while i < words.len() {
            match words[i] {
                "--gateway" if i + 1 < words.len() => {
                    config.gateways.push(GatewayConfig {
                        address: words[i + 1].to_string(),
                        description: Some("Migrated from legacy CLI".to_string()),
                        protocols: vec![NetworkProtocol::Tcp, NetworkProtocol::Udp],
                        enabled: true,
                        priority: 0,
                        tags: vec!["legacy".to_string(), "cli-migrated".to_string()],
                    });
                    i += 2;
                }
                "--default-deny" => {
                    config.file_access.default_policy = DefaultPolicy::Deny;
                    config.file_access.enabled = true;
                    i += 1;
                }
                "--default-allow" => {
                    config.file_access.default_policy = DefaultPolicy::Allow;
                    config.file_access.enabled = true;
                    i += 1;
                }
                "--metrics-port" if i + 1 < words.len() => {
                    config.metrics.port = words[i + 1].parse()
                        .map_err(|e| anyhow::anyhow!("Invalid metrics port in CLI args: {}", e))?;
                    config.metrics.enabled = true;
                    i += 2;
                }
                "--log-level" if i + 1 < words.len() => {
                    config.logging.level = match words[i + 1].to_lowercase().as_str() {
                        "trace" => LogLevel::Trace,
                        "debug" => LogLevel::Debug,
                        "info" => LogLevel::Info,
                        "warn" => LogLevel::Warn,
                        "error" => LogLevel::Error,
                        _ => return Err(anyhow::anyhow!("Invalid log level in CLI args: {}", words[i + 1])),
                    };
                    i += 2;
                }
                "--backend" if i + 1 < words.len() => {
                    config.backend.backend_type = match words[i + 1].to_lowercase().as_str() {
                        "auto" => BackendType::Auto,
                        "ebpf" | "ebpf_linux" => BackendType::EbpfLinux,
                        "macos" | "macos_desktop" => BackendType::MacOSDesktop,
                        "windows" | "windows_desktop" => BackendType::WindowsDesktop,
                        _ => return Err(anyhow::anyhow!("Invalid backend in CLI args: {}", words[i + 1])),
                    };
                    i += 2;
                }
                _ => i += 1,
            }
        }
        
        // Add migration metadata
        config.version = "1.0".to_string();
        
        Ok(config)
    }
    
    /// Migrate from eBPF configuration format
    async fn migrate_from_ebpf_config(&self, config_content: &str) -> Result<UnifiedConfig> {
        let legacy: Value = serde_json::from_str(config_content)
            .map_err(|e| anyhow::anyhow!("Failed to parse eBPF config JSON: {}", e))?;
        
        let mut config = UnifiedConfig::default();
        
        // Convert eBPF backend configuration
        if let Some(default_deny) = legacy.get("DEFAULT_DENY") {
            config.file_access.default_policy = if default_deny.as_bool().unwrap_or(false) {
                DefaultPolicy::Deny
            } else {
                DefaultPolicy::Allow
            };
            config.file_access.enabled = true;
        }
        
        // Convert allowed gateways
        if let Some(allowed_gateways) = legacy.get("ALLOWED_GATEWAYS") {
            if let Some(array) = allowed_gateways.as_array() {
                for gateway in array {
                    if let Some(address) = gateway.as_str() {
                        config.gateways.push(GatewayConfig {
                            address: address.to_string(),
                            description: Some("Migrated from eBPF config".to_string()),
                            protocols: vec![NetworkProtocol::Tcp],
                            enabled: true,
                            priority: 0,
                            tags: vec!["legacy".to_string(), "ebpf-migrated".to_string()],
                        });
                    }
                }
            }
        }
        
        // Convert file access rules
        if let Some(file_rules) = legacy.get("FILE_ACCESS_RULES") {
            if let Some(rules_array) = file_rules.as_array() {
                for rule_value in rules_array {
                    if let Ok(rule) = self.convert_ebpf_file_rule(rule_value) {
                        config.file_access.rules.push(rule);
                    }
                }
            }
        }
        
        // Convert metrics configuration
        if let Some(metrics) = legacy.get("METRICS") {
            if let Some(enabled) = metrics.get("enabled") {
                config.metrics.enabled = enabled.as_bool().unwrap_or(false);
            }
            if let Some(port) = metrics.get("port") {
                config.metrics.port = port.as_u64().unwrap_or(9090) as u16;
            }
        }
        
        // Set backend to eBPF Linux
        config.backend.backend_type = BackendType::EbpfLinux;
        config.backend.auto_detect = false;
        
        // Add migration metadata
        config.version = "1.0".to_string();
        
        Ok(config)
    }
    
    /// Migrate from JSON configuration format
    async fn migrate_from_json_config(&self, config_content: &str) -> Result<UnifiedConfig> {
        let mut config: UnifiedConfig = serde_json::from_str(config_content)
            .map_err(|e| anyhow::anyhow!("Failed to parse JSON config: {}", e))?;
        
        // Ensure version is set
        if config.version.is_empty() {
            config.version = "1.0".to_string();
        }
        
        // Add migration tags to gateways
        for gateway in &mut config.gateways {
            if !gateway.tags.iter().any(|tag| tag.contains("migrated")) {
                gateway.tags.push("json-migrated".to_string());
            }
        }
        
        Ok(config)
    }
    
    /// Convert eBPF file rule to unified format
    fn convert_ebpf_file_rule(&self, rule_value: &Value) -> Result<FileAccessRule> {
        let path = rule_value.get("path")
            .and_then(|p| p.as_str())
            .ok_or_else(|| anyhow::anyhow!("File rule missing path"))?;
        
        let rule_type_str = rule_value.get("rule_type")
            .and_then(|rt| rt.as_str())
            .unwrap_or("allow");
        
        let permissions_value = rule_value.get("permissions")
            .and_then(|p| p.as_u64())
            .unwrap_or(0) as u8;
        
        let is_prefix = rule_value.get("is_prefix")
            .and_then(|ip| ip.as_bool())
            .unwrap_or(false);
        
        // Convert to unified format
        let policy = match rule_type_str {
            "allow" => RulePolicy::Allow,
            "deny" => RulePolicy::Deny,
            _ => RulePolicy::Allow, // Default to allow
        };
        
        let pattern = if is_prefix {
            PathPatternType::Prefix
        } else {
            PathPatternType::Exact
        };
        
        let mut permissions = Vec::new();
        if permissions_value & 1 != 0 { permissions.push(FilePermission::Read); }
        if permissions_value & 2 != 0 { permissions.push(FilePermission::Write); }
        if permissions_value & 4 != 0 { permissions.push(FilePermission::Execute); }
        if permissions_value & 8 != 0 { permissions.push(FilePermission::Delete); }
        
        Ok(FileAccessRule {
            path: path.to_string(),
            pattern,
            policy,
            permissions,
            applies_to: vec!["*".to_string()], // Apply to all agents
            conditions: vec![],
        })
    }
    
    /// Upgrade from version 1.0 to 1.1
    fn upgrade_from_1_0_to_1_1(&self, config: &mut UnifiedConfig) -> Result<()> {
        // Add new web dashboard configuration if not present
        if config.ui.web_dashboard.port == 8080 && !config.ui.web_dashboard.enabled {
            config.ui.web_dashboard = WebDashboardConfig {
                enabled: false,
                port: 8080,
                host: "127.0.0.1".to_string(),
                tls: false,
                cert_file: None,
                key_file: None,
            };
        }
        
        // Add new agent permissions field if not present
        for agent in &mut config.agents {
            if agent.backend_specific.is_empty() {
                agent.backend_specific = HashMap::new();
            }
        }
        
        // Add new metrics export formats
        if config.metrics.export_formats.is_empty() {
            config.metrics.export_formats = vec![MetricFormat::Prometheus];
        }
        
        Ok(())
    }
    
    /// Upgrade from version 1.1 to 1.2
    fn upgrade_from_1_1_to_1_2(&self, config: &mut UnifiedConfig) -> Result<()> {
        // Add new structured logging field
        if !config.logging.structured {
            config.logging.structured = false;
        }
        
        // Add new log fields configuration
        if config.logging.fields.is_empty() {
            config.logging.fields = HashMap::new();
        }
        
        // Add new file access monitored processes
        if config.file_access.monitored_processes.is_empty() {
            config.file_access.monitored_processes = Vec::new();
        }
        
        // Add new protected paths
        if config.file_access.protected_paths.is_empty() {
            config.file_access.protected_paths = Vec::new();
        }
        
        Ok(())
    }
}

/// Migration report for tracking what was changed
#[derive(Debug, Clone)]
pub struct MigrationReport {
    pub source_format: String,
    pub target_version: String,
    pub changes_made: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

impl MigrationReport {
    pub fn new(source_format: &str, target_version: &str) -> Self {
        Self {
            source_format: source_format.to_string(),
            target_version: target_version.to_string(),
            changes_made: Vec::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }
    
    pub fn add_change(&mut self, change: &str) {
        self.changes_made.push(change.to_string());
    }
    
    pub fn add_warning(&mut self, warning: &str) {
        self.warnings.push(warning.to_string());
    }
    
    pub fn add_error(&mut self, error: &str) {
        self.errors.push(error.to_string());
    }
    
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }
    
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }
}

/// Enhanced migrator with reporting
pub struct ReportingConfigMigrator {
    migrator: ConfigMigrator,
    report: MigrationReport,
}

impl ReportingConfigMigrator {
    pub fn new(source_format: &str, target_version: &str) -> Self {
        Self {
            migrator: ConfigMigrator::new(),
            report: MigrationReport::new(source_format, target_version),
        }
    }
    
    pub async fn migrate_from_legacy(&mut self, legacy_path: &Path) -> Result<(UnifiedConfig, MigrationReport)> {
        let config = self.migrator.migrate_from_legacy(legacy_path).await?;
        
        // Generate report based on detected changes
        self.generate_migration_report(&config);
        
        Ok((config, self.report.clone()))
    }
    
    fn generate_migration_report(&mut self, config: &UnifiedConfig) {
        self.report.add_change("Migrated to unified configuration format");
        
        if !config.gateways.is_empty() {
            self.report.add_change(&format!("Migrated {} gateway configurations", config.gateways.len()));
        }
        
        if config.file_access.enabled {
            self.report.add_change("Migrated file access control settings");
        }
        
        if config.metrics.enabled {
            self.report.add_change("Migrated metrics configuration");
        }
        
        // Add warnings for potential issues
        if config.gateways.is_empty() {
            self.report.add_warning("No gateways configured - network access may be blocked");
        }
        
        if config.file_access.enabled && config.file_access.rules.is_empty() {
            self.report.add_warning("File access enabled but no rules configured");
        }
    }
    
    pub fn take_report(&mut self) -> MigrationReport {
        std::mem::replace(&mut self.report, MigrationReport::new("", ""))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    
    #[tokio::test]
    async fn test_cli_args_migration() {
        let migrator = ConfigMigrator::new();
        let args = "--gateway 127.0.0.1:8080 --default-deny --metrics-port 9090";
        
        let config = migrator.migrate_from_cli_args(args).await.unwrap();
        
        assert_eq!(config.gateways.len(), 1);
        assert_eq!(config.gateways[0].address, "127.0.0.1:8080");
        assert_eq!(config.file_access.default_policy, DefaultPolicy::Deny);
        assert_eq!(config.metrics.port, 9090);
        assert!(config.metrics.enabled);
    }
    
    #[tokio::test]
    async fn test_ebpf_config_migration() {
        let migrator = ConfigMigrator::new();
        let eBPF_config = r#"
        {
            "DEFAULT_DENY": true,
            "ALLOWED_GATEWAYS": ["127.0.0.1:8080", "10.0.0.1:443"],
            "FILE_ACCESS_RULES": [
                {
                    "path": "/tmp",
                    "rule_type": "allow",
                    "permissions": 3,
                    "is_prefix": true
                }
            ],
            "METRICS": {
                "enabled": true,
                "port": 9090
            }
        }
        "#;
        
        let config = migrator.migrate_from_ebpf_config(eBPF_config).await.unwrap();
        
        assert_eq!(config.gateways.len(), 2);
        assert_eq!(config.file_access.default_policy, DefaultPolicy::Deny);
        assert_eq!(config.file_access.rules.len(), 1);
        assert_eq!(config.metrics.port, 9090);
        assert!(config.metrics.enabled);
        assert_eq!(config.backend.backend_type, BackendType::EbpfLinux);
    }
    
    #[test]
    fn test_version_upgrade() {
        let migrator = ConfigMigrator::new();
        let mut config = UnifiedConfig::default();
        
        // Test 1.0 to 1.1 upgrade
        let upgraded = migrator.upgrade_version(config, "1.0", "1.1").unwrap();
        assert_eq!(upgraded.version, "1.1");
        assert!(!upgraded.metrics.export_formats.is_empty());
    }
    
    #[test]
    fn test_ebpf_file_rule_conversion() {
        let migrator = ConfigMigrator::new();
        let rule_json = r#"
        {
            "path": "/tmp/test",
            "rule_type": "allow",
            "permissions": 3,
            "is_prefix": false
        }
        "#;
        let rule_value: Value = serde_json::from_str(rule_json).unwrap();
        
        let rule = migrator.convert_ebpf_file_rule(&rule_value).unwrap();
        
        assert_eq!(rule.path, "/tmp/test");
        assert_eq!(rule.pattern, PathPatternType::Exact);
        assert_eq!(rule.policy, RulePolicy::Allow);
        assert_eq!(rule.permissions.len(), 2); // Read + Write
    }
    
    #[tokio::test]
    async fn test_backup_creation() {
        let migrator = ConfigMigrator::new();
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("config.yaml");
        
        // Create original file
        fs::write(&config_path, "test content").unwrap();
        
        // Create backup
        let backup_path = migrator.create_backup(&config_path).await.unwrap();
        
        assert!(backup_path.exists());
        assert_eq!(fs::read_to_string(&config_path).unwrap(), fs::read_to_string(&backup_path).unwrap());
    }
    
    #[test]
    fn test_migration_report() {
        let mut report = MigrationReport::new("cli", "1.0");
        
        report.add_change("Added gateway configuration");
        report.add_warning("No file access rules configured");
        report.add_error("Invalid port format");
        
        assert_eq!(report.changes_made.len(), 1);
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.errors.len(), 1);
        assert!(report.has_errors());
        assert!(report.has_warnings());
    }
    
    #[tokio::test]
    async fn test_reporting_migrator() {
        let mut migrator = ReportingConfigMigrator::new("cli", "1.0");
        let args = "--gateway 127.0.0.1:8080 --default-deny";
        
        let (config, report) = migrator.migrate_from_cli_args(args).await.unwrap();
        
        assert_eq!(config.gateways.len(), 1);
        assert!(!report.changes_made.is_empty());
        assert_eq!(report.source_format, "cli");
        assert_eq!(report.target_version, "1.0");
    }
    
    #[test]
    fn test_format_detection() {
        let migrator = ConfigMigrator::new();
        
        // CLI args format
        assert!(migrator.detect_cli_args_format("--gateway 127.0.0.1:8080"));
        assert!(migrator.detect_cli_args_format("--default-deny"));
        
        // eBPF config format
        assert!(migrator.detect_ebpf_config_format("DEFAULT_DENY: true"));
        assert!(migrator.detect_ebpf_config_format("ALLOWED_GATEWAYS: []"));
        
        // JSON config format
        assert!(migrator.detect_json_config_format("{\"backend\": \"auto\"}"));
        assert!(migrator.detect_json_config_format("{\"gateways\": []}"));
    }
}