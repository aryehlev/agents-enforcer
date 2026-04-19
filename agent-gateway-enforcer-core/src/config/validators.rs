use crate::backend::Platform;
use crate::config::ConfigValidator;
use agent_gateway_enforcer_common::config::*;
use anyhow::Result;
use async_trait::async_trait;
use std::net::SocketAddr;

/// Backend configuration validator
pub struct BackendValidator;

impl BackendValidator {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ConfigValidator for BackendValidator {
    fn name(&self) -> &'static str {
        "backend"
    }

    async fn validate(&self, config: &UnifiedConfig) -> Result<()> {
        match &config.backend.backend_type {
            BackendType::Auto => {
                // Auto-detect validation
                let platform = Platform::current();
                if !platform.is_supported() {
                    return Err(anyhow::anyhow!(
                        "Auto-detection not supported on platform: {:?}",
                        platform
                    ));
                }
            }
            BackendType::EbpfLinux => {
                if Platform::current() != Platform::Linux {
                    return Err(anyhow::anyhow!(
                        "eBPF Linux backend can only be used on Linux"
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Network configuration validator
pub struct NetworkValidator;

impl NetworkValidator {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ConfigValidator for NetworkValidator {
    fn name(&self) -> &'static str {
        "network"
    }

    async fn validate(&self, config: &UnifiedConfig) -> Result<()> {
        for (index, gateway) in config.gateways.iter().enumerate() {
            // Validate address format
            if gateway.address.is_empty() {
                return Err(anyhow::anyhow!("Gateway {} has empty address", index));
            }

            // Parse and validate address
            if let Err(e) = gateway.address.parse::<SocketAddr>() {
                return Err(anyhow::anyhow!(
                    "Gateway {} has invalid address '{}': {}",
                    index,
                    gateway.address,
                    e
                ));
            }

            // Validate protocols
            if gateway.protocols.is_empty() {
                return Err(anyhow::anyhow!(
                    "Gateway {} has no protocols specified",
                    index
                ));
            }

            // Validate port range
            if let Ok(addr) = gateway.address.parse::<SocketAddr>() {
                if addr.port() < 1 || addr.port() > 65535 {
                    return Err(anyhow::anyhow!(
                        "Gateway {} has invalid port: {}",
                        index,
                        addr.port()
                    ));
                }
            }

            // Validate priority
            if gateway.priority > 1000 {
                return Err(anyhow::anyhow!(
                    "Gateway {} has priority {} exceeding maximum of 1000",
                    index,
                    gateway.priority
                ));
            }
        }

        // Check for duplicate addresses
        let mut addresses = std::collections::HashSet::new();
        for (index, gateway) in config.gateways.iter().enumerate() {
            if !addresses.insert(&gateway.address) {
                return Err(anyhow::anyhow!(
                    "Duplicate gateway address found: {} (gateway {})",
                    gateway.address,
                    index
                ));
            }
        }

        Ok(())
    }
}

/// File access configuration validator
pub struct FileAccessValidator;

impl FileAccessValidator {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ConfigValidator for FileAccessValidator {
    fn name(&self) -> &'static str {
        "file_access"
    }

    async fn validate(&self, config: &UnifiedConfig) -> Result<()> {
        for (index, rule) in config.file_access.rules.iter().enumerate() {
            // Validate path
            if rule.path.is_empty() {
                return Err(anyhow::anyhow!("File access rule {} has empty path", index));
            }

            // Validate permissions
            if rule.permissions.is_empty() {
                return Err(anyhow::anyhow!(
                    "File access rule {} has no permissions specified",
                    index
                ));
            }

            // Validate path pattern
            match rule.pattern {
                PathPatternType::Regex => {
                    if let Err(e) = regex::Regex::new(&rule.path) {
                        return Err(anyhow::anyhow!(
                            "File access rule {} has invalid regex pattern '{}': {}",
                            index,
                            rule.path,
                            e
                        ));
                    }
                }
                PathPatternType::Glob => {
                    // Validate glob pattern
                    if let Err(e) = glob::Pattern::new(&rule.path) {
                        return Err(anyhow::anyhow!(
                            "File access rule {} has invalid glob pattern '{}': {}",
                            index,
                            rule.path,
                            e
                        ));
                    }
                }
                PathPatternType::Exact => {
                    // Validate exact path format
                    if !rule.path.starts_with('/') {
                        return Err(anyhow::anyhow!(
                            "File access rule {} has exact path '{}' that doesn't start with '/'",
                            index,
                            rule.path
                        ));
                    }
                }
                PathPatternType::Prefix => {
                    // Validate prefix path format
                    if !rule.path.starts_with('/') {
                        return Err(anyhow::anyhow!(
                            "File access rule {} has prefix path '{}' that doesn't start with '/'",
                            index,
                            rule.path
                        ));
                    }
                }
            }

            // Validate agent applications
            if rule.applies_to.is_empty() {
                return Err(anyhow::anyhow!(
                    "File access rule {} has no target agents specified",
                    index
                ));
            }

            // Validate conditions
            for (cond_index, condition) in rule.conditions.iter().enumerate() {
                self.validate_condition(condition, index, cond_index)
                    .await?;
            }
        }

        // Validate protected paths
        for (index, path_pattern) in config.file_access.protected_paths.iter().enumerate() {
            if path_pattern.pattern.is_empty() {
                return Err(anyhow::anyhow!(
                    "Protected path {} has empty pattern",
                    index
                ));
            }

            // Validate pattern format
            match path_pattern.pattern_type {
                PathPatternType::Regex => {
                    if let Err(e) = regex::Regex::new(&path_pattern.pattern) {
                        return Err(anyhow::anyhow!(
                            "Protected path {} has invalid regex pattern '{}': {}",
                            index,
                            path_pattern.pattern,
                            e
                        ));
                    }
                }
                PathPatternType::Glob => {
                    if let Err(e) = glob::Pattern::new(&path_pattern.pattern) {
                        return Err(anyhow::anyhow!(
                            "Protected path {} has invalid glob pattern '{}': {}",
                            index,
                            path_pattern.pattern,
                            e
                        ));
                    }
                }
                _ => {
                    if !path_pattern.pattern.starts_with('/') {
                        return Err(anyhow::anyhow!(
                            "Protected path {} has pattern '{}' that doesn't start with '/'",
                            index,
                            path_pattern.pattern
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

impl FileAccessValidator {
    async fn validate_condition(
        &self,
        condition: &RuleCondition,
        rule_index: usize,
        cond_index: usize,
    ) -> Result<()> {
        // Validate condition value
        if condition.value.is_empty() {
            return Err(anyhow::anyhow!(
                "File access rule {} condition {} has empty value",
                rule_index,
                cond_index
            ));
        }

        // Validate condition type and value format
        match &condition.condition_type {
            ConditionType::ProcessName => {
                // Process name should be alphanumeric with some allowed characters
                if !condition
                    .value
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
                {
                    return Err(anyhow::anyhow!(
                        "File access rule {} condition {} has invalid process name format: '{}'",
                        rule_index,
                        cond_index,
                        condition.value
                    ));
                }
            }
            ConditionType::UserId => {
                // User ID should be numeric
                if condition.value.parse::<u32>().is_err() {
                    return Err(anyhow::anyhow!(
                        "File access rule {} condition {} has invalid user ID: '{}'",
                        rule_index,
                        cond_index,
                        condition.value
                    ));
                }
            }
            ConditionType::TimeOfDay => {
                // Time should be in HH:MM format
                if condition.value.len() != 5 || !condition.value.contains(':') {
                    return Err(anyhow::anyhow!(
                        "File access rule {} condition {} has invalid time format: '{}'. Expected HH:MM", 
                        rule_index, cond_index, condition.value
                    ));
                }

                let parts: Vec<&str> = condition.value.split(':').collect();
                if parts.len() != 2 {
                    return Err(anyhow::anyhow!(
                        "File access rule {} condition {} has invalid time format: '{}'",
                        rule_index,
                        cond_index,
                        condition.value
                    ));
                }

                if let (Ok(hour), Ok(minute)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                    if hour > 23 || minute > 59 {
                        return Err(anyhow::anyhow!(
                            "File access rule {} condition {} has invalid time: '{}'",
                            rule_index,
                            cond_index,
                            condition.value
                        ));
                    }
                } else {
                    return Err(anyhow::anyhow!(
                        "File access rule {} condition {} has invalid time format: '{}'",
                        rule_index,
                        cond_index,
                        condition.value
                    ));
                }
            }
            ConditionType::DayOfWeek => {
                // Day should be one of: monday, tuesday, wednesday, thursday, friday, saturday, sunday
                let valid_days = [
                    "monday",
                    "tuesday",
                    "wednesday",
                    "thursday",
                    "friday",
                    "saturday",
                    "sunday",
                ];
                if !valid_days.contains(&condition.value.to_lowercase().as_str()) {
                    return Err(anyhow::anyhow!(
                        "File access rule {} condition {} has invalid day of week: '{}'. Expected one of: {}", 
                        rule_index, cond_index, condition.value, valid_days.join(", ")
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Metrics configuration validator
pub struct MetricsValidator;

impl MetricsValidator {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ConfigValidator for MetricsValidator {
    fn name(&self) -> &'static str {
        "metrics"
    }

    async fn validate(&self, config: &UnifiedConfig) -> Result<()> {
        // Validate port range
        if config.metrics.port < 1 || config.metrics.port > 65535 {
            return Err(anyhow::anyhow!(
                "Metrics port {} is out of valid range (1-65535)",
                config.metrics.port
            ));
        }

        // Validate endpoint
        if config.metrics.endpoint.is_empty() {
            return Err(anyhow::anyhow!("Metrics endpoint cannot be empty"));
        }

        if !config.metrics.endpoint.starts_with('/') {
            return Err(anyhow::anyhow!(
                "Metrics endpoint '{}' must start with '/'",
                config.metrics.endpoint
            ));
        }

        // Validate retention days
        if config.metrics.retention_days > 3650 {
            return Err(anyhow::anyhow!(
                "Metrics retention days {} exceeds maximum of 3650 (10 years)",
                config.metrics.retention_days
            ));
        }

        // Validate export formats
        if config.metrics.export_formats.is_empty() {
            return Err(anyhow::anyhow!(
                "At least one metrics export format must be specified"
            ));
        }

        Ok(())
    }
}

/// Logging configuration validator
pub struct LoggingValidator;

impl LoggingValidator {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ConfigValidator for LoggingValidator {
    fn name(&self) -> &'static str {
        "logging"
    }

    async fn validate(&self, config: &UnifiedConfig) -> Result<()> {
        // Validate log file path if specified
        if let Some(file_path) = &config.logging.file {
            if file_path.as_os_str().is_empty() {
                return Err(anyhow::anyhow!("Logging file path cannot be empty"));
            }

            // Check if parent directory exists (or if we can create it)
            if let Some(parent) = file_path.parent() {
                if !parent.as_os_str().is_empty() && !parent.exists() {
                    return Err(anyhow::anyhow!(
                        "Logging file parent directory '{}' does not exist: {}",
                        parent.display(),
                        file_path.display()
                    ));
                }
            }
        }

        // Validate log fields
        for (field_name, log_field) in &config.logging.fields {
            if field_name.is_empty() {
                return Err(anyhow::anyhow!("Log field name cannot be empty"));
            }

            // Validate field format if specified
            if let Some(format) = &log_field.format {
                if format.is_empty() {
                    return Err(anyhow::anyhow!(
                        "Log field '{}' format cannot be empty",
                        field_name
                    ));
                }
            }
        }

        Ok(())
    }
}

/// UI configuration validator
pub struct UIValidator;

impl UIValidator {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ConfigValidator for UIValidator {
    fn name(&self) -> &'static str {
        "ui"
    }

    async fn validate(&self, config: &UnifiedConfig) -> Result<()> {
        // Validate prompt timeout
        if config.ui.prompt_timeout > 300 {
            return Err(anyhow::anyhow!(
                "UI prompt timeout {} exceeds maximum of 300 seconds (5 minutes)",
                config.ui.prompt_timeout
            ));
        }

        // Validate language code
        if config.ui.language.len() != 2 {
            return Err(anyhow::anyhow!(
                "UI language code '{}' must be exactly 2 characters (ISO 639-1)",
                config.ui.language
            ));
        }

        // Validate web dashboard configuration
        if config.ui.web_dashboard.enabled {
            // Validate port
            if config.ui.web_dashboard.port < 1 || config.ui.web_dashboard.port > 65535 {
                return Err(anyhow::anyhow!(
                    "Web dashboard port {} is out of valid range (1-65535)",
                    config.ui.web_dashboard.port
                ));
            }

            // Validate host
            if config.ui.web_dashboard.host.is_empty() {
                return Err(anyhow::anyhow!("Web dashboard host cannot be empty"));
            }

            // Validate TLS configuration
            if config.ui.web_dashboard.tls {
                if config.ui.web_dashboard.cert_file.is_none()
                    || config.ui.web_dashboard.key_file.is_none()
                {
                    return Err(anyhow::anyhow!(
                        "Web dashboard TLS is enabled but cert_file or key_file is not specified"
                    ));
                }

                if let (Some(cert_file), Some(key_file)) = (
                    &config.ui.web_dashboard.cert_file,
                    &config.ui.web_dashboard.key_file,
                ) {
                    if !cert_file.exists() {
                        return Err(anyhow::anyhow!(
                            "Web dashboard TLS certificate file does not exist: {}",
                            cert_file.display()
                        ));
                    }

                    if !key_file.exists() {
                        return Err(anyhow::anyhow!(
                            "Web dashboard TLS key file does not exist: {}",
                            key_file.display()
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

/// Agent configuration validator
pub struct AgentValidator;

impl AgentValidator {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ConfigValidator for AgentValidator {
    fn name(&self) -> &'static str {
        "agent"
    }

    async fn validate(&self, config: &UnifiedConfig) -> Result<()> {
        for (index, agent) in config.agents.iter().enumerate() {
            // Validate agent name
            if agent.name.is_empty() {
                return Err(anyhow::anyhow!("Agent {} has empty name", index));
            }

            // Validate agent path
            if agent.path.as_os_str().is_empty() {
                return Err(anyhow::anyhow!("Agent {} has empty path", index));
            }

            if !agent.path.exists() {
                return Err(anyhow::anyhow!(
                    "Agent {} path does not exist: {}",
                    index,
                    agent.path.display()
                ));
            }

            // Validate agent name uniqueness
            for (other_index, other_agent) in config.agents.iter().enumerate() {
                if index != other_index && agent.name == other_agent.name {
                    return Err(anyhow::anyhow!(
                        "Duplicate agent name '{}' found (agents {} and {})",
                        agent.name,
                        index,
                        other_index
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Composite validator that runs multiple validators
pub struct CompositeValidator {
    validators: Vec<Box<dyn ConfigValidator>>,
}

impl CompositeValidator {
    pub fn new() -> Self {
        Self {
            validators: Vec::new(),
        }
    }

    pub fn add_validator(mut self, validator: Box<dyn ConfigValidator>) -> Self {
        self.validators.push(validator);
        self
    }

    /// Create a default composite validator with all standard validators
    pub fn default() -> Self {
        Self::new()
            .add_validator(Box::new(BackendValidator::new()))
            .add_validator(Box::new(NetworkValidator::new()))
            .add_validator(Box::new(FileAccessValidator::new()))
            .add_validator(Box::new(MetricsValidator::new()))
            .add_validator(Box::new(LoggingValidator::new()))
            .add_validator(Box::new(UIValidator::new()))
            .add_validator(Box::new(AgentValidator::new()))
    }
}

#[async_trait]
impl ConfigValidator for CompositeValidator {
    fn name(&self) -> &'static str {
        "composite"
    }

    async fn validate(&self, config: &UnifiedConfig) -> Result<()> {
        for validator in &self.validators {
            validator.validate(config).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_backend_validator() {
        let validator = BackendValidator::new();

        // Test valid auto-detect config
        let mut config = UnifiedConfig::default();
        config.backend.backend_type = BackendType::Auto;
        assert!(validator.validate(&config).await.is_ok());
    }

    #[tokio::test]
    async fn test_network_validator() {
        let validator = NetworkValidator::new();

        // Test valid gateway
        let mut config = UnifiedConfig::default();
        config.gateways.push(GatewayConfig {
            address: "127.0.0.1:8080".to_string(),
            protocols: vec![NetworkProtocol::Tcp],
            ..Default::default()
        });
        assert!(validator.validate(&config).await.is_ok());

        // Test invalid address
        config.gateways[0].address = "invalid-address".to_string();
        assert!(validator.validate(&config).await.is_err());

        // Test empty protocols
        config.gateways[0].address = "127.0.0.1:8080".to_string();
        config.gateways[0].protocols.clear();
        assert!(validator.validate(&config).await.is_err());

        // Test duplicate addresses
        config.gateways[0].protocols = vec![NetworkProtocol::Tcp];
        config.gateways.push(GatewayConfig {
            address: "127.0.0.1:8080".to_string(),
            protocols: vec![NetworkProtocol::Udp],
            ..Default::default()
        });
        assert!(validator.validate(&config).await.is_err());
    }

    #[tokio::test]
    async fn test_file_access_validator() {
        let validator = FileAccessValidator::new();

        // Test valid rule
        let mut config = UnifiedConfig::default();
        config.file_access.rules.push(FileAccessRule {
            path: "/tmp/test".to_string(),
            pattern: PathPatternType::Exact,
            policy: RulePolicy::Allow,
            permissions: vec![FilePermission::Read],
            applies_to: vec!["test-agent".to_string()],
            conditions: vec![],
        });
        assert!(validator.validate(&config).await.is_ok());

        // Test invalid regex
        config.file_access.rules[0].pattern = PathPatternType::Regex;
        config.file_access.rules[0].path = "[invalid regex".to_string();
        assert!(validator.validate(&config).await.is_err());

        // Test empty permissions
        config.file_access.rules[0].pattern = PathPatternType::Exact;
        config.file_access.rules[0].path = "/tmp/test".to_string();
        config.file_access.rules[0].permissions.clear();
        assert!(validator.validate(&config).await.is_err());
    }

    #[tokio::test]
    async fn test_metrics_validator() {
        let validator = MetricsValidator::new();

        // Test valid config
        let mut config = UnifiedConfig::default();
        config.metrics.port = 9090;
        config.metrics.endpoint = "/metrics".to_string();
        config.metrics.export_formats = vec![MetricFormat::Prometheus];
        assert!(validator.validate(&config).await.is_ok());

        // Test invalid port
        config.metrics.port = 70000;
        assert!(validator.validate(&config).await.is_err());

        // Test empty endpoint
        config.metrics.port = 9090;
        config.metrics.endpoint = "".to_string();
        assert!(validator.validate(&config).await.is_err());

        // Test empty export formats
        config.metrics.endpoint = "/metrics".to_string();
        config.metrics.export_formats.clear();
        assert!(validator.validate(&config).await.is_err());
    }

    #[tokio::test]
    async fn test_ui_validator() {
        let validator = UIValidator::new();

        // Test valid config
        let mut config = UnifiedConfig::default();
        config.ui.web_dashboard.enabled = true;
        config.ui.web_dashboard.port = 8080;
        config.ui.web_dashboard.host = "127.0.0.1".to_string();
        assert!(validator.validate(&config).await.is_ok());

        // Test invalid timeout
        config.ui.prompt_timeout = 400;
        assert!(validator.validate(&config).await.is_err());

        // Test invalid language
        config.ui.prompt_timeout = 30;
        config.ui.language = "eng".to_string();
        assert!(validator.validate(&config).await.is_err());

        // Test TLS without cert/key
        config.ui.language = "en".to_string();
        config.ui.web_dashboard.tls = true;
        assert!(validator.validate(&config).await.is_err());
    }

    #[tokio::test]
    async fn test_agent_validator() {
        let validator = AgentValidator::new();
        let temp_dir = tempdir().unwrap();
        let test_file = temp_dir.path().join("test-agent");
        std::fs::write(&test_file, "test").unwrap();

        // Test valid agent
        let mut config = UnifiedConfig::default();
        config.agents.push(AgentConfig {
            name: "test-agent".to_string(),
            path: test_file.clone(),
            backend_specific: std::collections::HashMap::new(),
            permissions: AgentPermissions::default(),
        });
        assert!(validator.validate(&config).await.is_ok());

        // Test non-existent file
        config.agents[0].path = PathBuf::from("/non/existent/file");
        assert!(validator.validate(&config).await.is_err());

        // Test duplicate name
        config.agents[0].path = test_file;
        config.agents.push(AgentConfig {
            name: "test-agent".to_string(),
            path: test_file,
            backend_specific: std::collections::HashMap::new(),
            permissions: AgentPermissions::default(),
        });
        assert!(validator.validate(&config).await.is_err());
    }

    #[tokio::test]
    async fn test_composite_validator() {
        let validator = CompositeValidator::default();

        // Test valid config
        let config = UnifiedConfig::default();
        assert!(validator.validate(&config).await.is_ok());

        // Test invalid config
        let mut config = UnifiedConfig::default();
        config.metrics.port = 70000; // Invalid port
        assert!(validator.validate(&config).await.is_err());
    }
}
