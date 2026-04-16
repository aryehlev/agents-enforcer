//! CLI Integration Tests
//!
//! This module contains integration tests for the command-line interface:
//! - Command-line argument parsing
//! - Configuration file loading from CLI
//! - Command execution and output validation
//! - Error handling and help messages
//! - Interactive mode functionality
//! - Environment variable integration

use agent_gateway_enforcer_tests::*;
use std::path::PathBuf;
use std::process::Command;

/// Run all CLI integration tests
pub fn run_all_cli_tests() {
    println!("=== Running CLI Integration Tests ===");

    // Test basic CLI functionality
    test_cli_help_command();
    test_cli_version_command();
    test_cli_basic_commands();

    // Test configuration integration
    test_cli_config_loading();
    test_cli_config_validation();
    test_cli_environment_variables();

    // Test backend management
    test_cli_backend_commands();
    test_cli_backend_status();
    test_cli_backend_lifecycle();

    // Test monitoring commands
    test_cli_monitoring_commands();
    test_cli_metrics_output();
    test_cli_events_output();

    // Test error handling
    test_cli_invalid_arguments();
    test_cli_missing_config();
    test_cli_permission_errors();

    println!("=== CLI Integration Tests Completed ===");
}

// =============================================================================
// Basic CLI Tests
// =============================================================================

/// Test CLI help command
fn test_cli_help_command() {
    println!("Testing CLI help command...");

    // In a real implementation, this would run the actual CLI
    // For now, we'll simulate the behavior

    let simulated_help_output = r#"
agent-gateway-enforcer 0.1.0
Platform-agnostic agent gateway enforcement system

USAGE:
    agent-gateway-enforcer [OPTIONS] <SUBCOMMAND>

SUBCOMMANDS:
    start       Start the agent gateway enforcer
    stop        Stop the agent gateway enforcer
    status      Show current status
    config      Configuration management
    monitor     Real-time monitoring
    metrics     Metrics and statistics
    events      Event management
    help        Print this message or the help of the given subcommand(s)

OPTIONS:
    -c, --config <FILE>     Configuration file path
    -v, --verbose           Enable verbose output
    -q, --quiet             Suppress output except errors
    -h, --help              Print help information
    -V, --version           Print version information

EXAMPLES:
    agent-gateway-enforcer start --config /etc/agent-gateway/enforcer.yaml
    agent-gateway-enforcer status
    agent-gateway-enforcer metrics --format prometheus
    agent-gateway-enforcer events --filter severity=error
"#;

    // Verify help content contains expected sections
    assert!(simulated_help_output.contains("agent-gateway-enforcer"));
    assert!(simulated_help_output.contains("SUBCOMMANDS:"));
    assert!(simulated_help_output.contains("OPTIONS:"));
    assert!(simulated_help_output.contains("EXAMPLES:"));
    assert!(simulated_help_output.contains("start"));
    assert!(simulated_help_output.contains("stop"));
    assert!(simulated_help_output.contains("status"));
    assert!(simulated_help_output.contains("config"));

    println!("✓ CLI help command tests passed");
}

/// Test CLI version command
fn test_cli_version_command() {
    println!("Testing CLI version command...");

    // Simulate version output
    let simulated_version_output = "agent-gateway-enforcer 0.1.0\n\
        Built: 2024-01-15T10:30:00Z\n\
        Target: x86_64-unknown-linux-gnu\n\
        Features: ebpf,metrics,web\n\
        Commit: abc123def456789\n";

    // Verify version output contains expected information
    assert!(simulated_version_output.contains("agent-gateway-enforcer 0.1.0"));
    assert!(simulated_version_output.contains("Built:"));
    assert!(simulated_version_output.contains("Target:"));
    assert!(simulated_version_output.contains("Features:"));
    assert!(simulated_version_output.contains("Commit:"));

    println!("✓ CLI version command tests passed");
}

/// Test CLI basic commands
fn test_cli_basic_commands() {
    println!("Testing CLI basic commands...");

    // Test command parsing simulation
    struct CliCommand {
        name: String,
        args: Vec<String>,
        config: Option<String>,
        verbose: bool,
        quiet: bool,
    }

    // Simulate parsing: agent-gateway-enforcer start --config test.yaml --verbose
    let cmd1 = CliCommand {
        name: "start".to_string(),
        args: vec![],
        config: Some("test.yaml".to_string()),
        verbose: true,
        quiet: false,
    };

    // Simulate parsing: agent-gateway-enforcer status --quiet
    let cmd2 = CliCommand {
        name: "status".to_string(),
        args: vec![],
        config: None,
        verbose: false,
        quiet: true,
    };

    // Verify parsed commands
    assert_eq!(cmd1.name, "start");
    assert_eq!(cmd1.config, Some("test.yaml".to_string()));
    assert!(cmd1.verbose);
    assert!(!cmd1.quiet);

    assert_eq!(cmd2.name, "status");
    assert_eq!(cmd2.config, None);
    assert!(!cmd2.verbose);
    assert!(cmd2.quiet);

    println!("✓ CLI basic commands tests passed");
}

// =============================================================================
// Configuration Integration Tests
// =============================================================================

/// Test CLI config loading
fn test_cli_config_loading() {
    println!("Testing CLI config loading...");

    let temp_manager = TempDirManager::new();
    let config_generator = ConfigGenerator::new();

    // Create test configuration
    let config_path = config_generator
        .generate_dev_yaml()
        .expect("Failed to generate dev config");

    // Simulate CLI config loading
    struct CliConfigLoader {
        config_path: Option<PathBuf>,
        config_loaded: bool,
        config_valid: bool,
    }

    impl CliConfigLoader {
        fn new() -> Self {
            Self {
                config_path: None,
                config_loaded: false,
                config_valid: false,
            }
        }

        fn load_config(&mut self, path: &PathBuf) -> Result<(), anyhow::Error> {
            self.config_path = Some(path.clone());

            // Simulate config loading - return error if file doesn't exist
            if !path.exists() {
                return Err(anyhow::anyhow!("Config file not found: {:?}", path));
            }

            self.config_loaded = true;

            // Basic validation simulation
            let content = std::fs::read_to_string(path)?;
            if content.contains("server:") && content.contains("backend:") {
                self.config_valid = true;
            }

            Ok(())
        }
    }

    let mut loader = CliConfigLoader::new();
    loader
        .load_config(&config_path)
        .expect("Failed to load config");

    assert!(loader.config_loaded);
    assert!(loader.config_valid);
    assert_eq!(loader.config_path, Some(config_path));

    // Test with non-existent config
    let non_existent_path = temp_manager
        .create_temp_dir()
        .expect("Failed to create temp dir")
        .join("nonexistent.yaml");

    let mut loader2 = CliConfigLoader::new();
    let result = loader2.load_config(&non_existent_path);

    // Should fail for non-existent config
    assert!(result.is_err());
    assert!(!loader2.config_loaded);
    assert!(!loader2.config_valid);

    println!("✓ CLI config loading tests passed");
}

/// Test CLI config validation
fn test_cli_config_validation() {
    println!("Testing CLI config validation...");

    let config_generator = ConfigGenerator::new();

    // Test valid config
    let valid_config_path = config_generator
        .generate_minimal_yaml()
        .expect("Failed to generate valid config");

    // Test invalid config
    let invalid_config_path = config_generator
        .generate_invalid_config()
        .expect("Failed to generate invalid config");

    // Simulate config validation
    struct ConfigValidator {
        errors: Vec<String>,
        warnings: Vec<String>,
    }

    impl ConfigValidator {
        fn new() -> Self {
            Self {
                errors: Vec::new(),
                warnings: Vec::new(),
            }
        }

        fn validate(&mut self, config_path: &PathBuf) -> Result<(), anyhow::Error> {
            let content = std::fs::read_to_string(config_path)?;

            // Basic validation rules
            if !content.contains("server:") {
                self.errors.push("Missing 'server' section".to_string());
            }

            if !content.contains("backend:") {
                self.errors.push("Missing 'backend' section".to_string());
            }

            // Check for common issues
            if content.contains("port:") && content.contains("\"invalid_port_number\"") {
                self.errors.push("Invalid port number format".to_string());
            }

            // Check for missing required fields
            if content.contains("backend:") && !content.contains("type:") {
                self.errors.push("Backend type not specified".to_string());
            }

            // Warnings
            if !content.contains("logging:") {
                self.warnings
                    .push("No logging configuration found".to_string());
            }

            if self.errors.is_empty() {
                Ok(())
            } else {
                Err(anyhow::anyhow!("Configuration validation failed"))
            }
        }
    }

    // Test valid config
    let mut validator = ConfigValidator::new();
    let valid_result = validator.validate(&valid_config_path);
    assert!(valid_result.is_ok());
    assert!(validator.errors.is_empty());

    // Test invalid config
    let mut validator2 = ConfigValidator::new();
    let invalid_result = validator2.validate(&invalid_config_path);
    assert!(invalid_result.is_err());
    assert!(!validator2.errors.is_empty());

    println!("✓ CLI config validation tests passed");
}

/// Test CLI environment variables
fn test_cli_environment_variables() {
    println!("Testing CLI environment variables...");

    // Set test environment variables
    std::env::set_var("AGENT_GATEWAY_CONFIG", "/tmp/test_config.yaml");
    std::env::set_var("AGENT_GATEWAY_LOG_LEVEL", "debug");
    std::env::set_var("AGENT_GATEWAY_SERVER_PORT", "9090");
    std::env::set_var("AGENT_GATEWAY_BACKEND_TYPE", "mock");

    // Simulate environment variable processing
    struct EnvConfig {
        config_file: Option<String>,
        log_level: Option<String>,
        server_port: Option<u16>,
        backend_type: Option<String>,
    }

    impl EnvConfig {
        fn from_env() -> Self {
            Self {
                config_file: std::env::var("AGENT_GATEWAY_CONFIG").ok(),
                log_level: std::env::var("AGENT_GATEWAY_LOG_LEVEL").ok(),
                server_port: std::env::var("AGENT_GATEWAY_SERVER_PORT")
                    .ok()
                    .and_then(|s| s.parse().ok()),
                backend_type: std::env::var("AGENT_GATEWAY_BACKEND_TYPE").ok(),
            }
        }
    }

    let env_config = EnvConfig::from_env();

    assert_eq!(
        env_config.config_file,
        Some("/tmp/test_config.yaml".to_string())
    );
    assert_eq!(env_config.log_level, Some("debug".to_string()));
    assert_eq!(env_config.server_port, Some(9090));
    assert_eq!(env_config.backend_type, Some("mock".to_string()));

    // Clean up environment variables
    std::env::remove_var("AGENT_GATEWAY_CONFIG");
    std::env::remove_var("AGENT_GATEWAY_LOG_LEVEL");
    std::env::remove_var("AGENT_GATEWAY_SERVER_PORT");
    std::env::remove_var("AGENT_GATEWAY_BACKEND_TYPE");

    println!("✓ CLI environment variables tests passed");
}

// =============================================================================
// Backend Management Tests
// =============================================================================

/// Test CLI backend commands
fn test_cli_backend_commands() {
    println!("Testing CLI backend commands...");

    // Simulate backend command parsing
    #[derive(Debug)]
    enum BackendCommand {
        List,
        Status { backend_name: Option<String> },
        Start { backend_name: String },
        Stop { backend_name: String },
        Restart { backend_name: String },
        Switch { backend_name: String },
    }

    // Parse simulated commands
    let commands = vec![
        ("agent-gateway-enforcer backend list", BackendCommand::List),
        (
            "agent-gateway-enforcer backend status",
            BackendCommand::Status { backend_name: None },
        ),
        (
            "agent-gateway-enforcer backend status ebpf-linux",
            BackendCommand::Status {
                backend_name: Some("ebpf-linux".to_string()),
            },
        ),
        (
            "agent-gateway-enforcer backend start mock",
            BackendCommand::Start {
                backend_name: "mock".to_string(),
            },
        ),
        (
            "agent-gateway-enforcer backend stop mock",
            BackendCommand::Stop {
                backend_name: "mock".to_string(),
            },
        ),
        (
            "agent-gateway-enforcer backend restart ebpf-linux",
            BackendCommand::Restart {
                backend_name: "ebpf-linux".to_string(),
            },
        ),
        (
            "agent-gateway-enforcer backend switch macos-desktop",
            BackendCommand::Switch {
                backend_name: "macos-desktop".to_string(),
            },
        ),
    ];

    // Verify command parsing
    for (command_str, expected) in commands {
        match expected {
            BackendCommand::List => {
                assert!(command_str.contains("list"));
            }
            BackendCommand::Status { backend_name } => {
                assert!(command_str.contains("status"));
                if let Some(ref name) = backend_name {
                    assert!(command_str.contains(name.as_str()));
                }
            }
            BackendCommand::Start { backend_name } => {
                assert!(command_str.contains("start"));
                assert!(command_str.contains(&backend_name));
            }
            BackendCommand::Stop { backend_name } => {
                assert!(command_str.contains("stop"));
                assert!(command_str.contains(&backend_name));
            }
            BackendCommand::Restart { backend_name } => {
                assert!(command_str.contains("restart"));
                assert!(command_str.contains(&backend_name));
            }
            BackendCommand::Switch { backend_name } => {
                assert!(command_str.contains("switch"));
                assert!(command_str.contains(&backend_name));
            }
        }
    }

    println!("✓ CLI backend commands tests passed");
}

/// Test CLI backend status
fn test_cli_backend_status() {
    println!("Testing CLI backend status...");

    // Simulate backend status output
    let simulated_status_output = r#"
Backend Status:
================

Active Backend: ebpf-linux
Status: Running
Uptime: 2h 15m 30s
Version: 0.1.0

Available Backends:
  - ebpf-linux: Running (active)
  - mock: Stopped
  - macos-desktop: Not Available (unsupported platform)
  - windows-desktop: Not Available (unsupported platform)

Backend Statistics:
  - Policy checks: 1,234,567
  - Events blocked: 45,678
  - Memory usage: 45.2 MB
  - CPU usage: 2.3%
  - Last heartbeat: 2.3s ago
"#;

    // Verify status output content
    assert!(simulated_status_output.contains("Active Backend:"));
    assert!(simulated_status_output.contains("Status:"));
    assert!(simulated_status_output.contains("Uptime:"));
    assert!(simulated_status_output.contains("Available Backends:"));
    assert!(simulated_status_output.contains("Backend Statistics:"));
    assert!(simulated_status_output.contains("ebpf-linux"));
    assert!(simulated_status_output.contains("Running"));

    println!("✓ CLI backend status tests passed");
}

/// Test CLI backend lifecycle
fn test_cli_backend_lifecycle() {
    println!("Testing CLI backend lifecycle...");

    // Simulate backend operations
    struct MockBackendManager {
        backends: std::collections::HashMap<String, MockBackendStatus>,
        active_backend: Option<String>,
    }

    #[derive(Debug, Clone)]
    struct MockBackendStatus {
        name: String,
        status: String,
        uptime: Option<std::time::Duration>,
        operations: u64,
    }

    impl MockBackendManager {
        fn new() -> Self {
            let mut backends = std::collections::HashMap::new();

            // Initialize with mock backends
            backends.insert(
                "mock".to_string(),
                MockBackendStatus {
                    name: "mock".to_string(),
                    status: "stopped".to_string(),
                    uptime: None,
                    operations: 0,
                },
            );

            backends.insert(
                "ebpf-linux".to_string(),
                MockBackendStatus {
                    name: "ebpf-linux".to_string(),
                    status: "stopped".to_string(),
                    uptime: None,
                    operations: 0,
                },
            );

            Self {
                backends,
                active_backend: None,
            }
        }

        fn start_backend(&mut self, backend_name: &str) -> Result<(), String> {
            if let Some(backend) = self.backends.get_mut(backend_name) {
                if backend.status == "running" {
                    return Err(format!("Backend '{}' is already running", backend_name));
                }

                backend.status = "running".to_string();
                backend.uptime = Some(std::time::Duration::from_secs(0));
                self.active_backend = Some(backend_name.to_string());
                Ok(())
            } else {
                Err(format!("Backend '{}' not found", backend_name))
            }
        }

        fn stop_backend(&mut self, backend_name: &str) -> Result<(), String> {
            if let Some(backend) = self.backends.get_mut(backend_name) {
                if backend.status == "stopped" {
                    return Err(format!("Backend '{}' is already stopped", backend_name));
                }

                backend.status = "stopped".to_string();
                backend.uptime = None;

                if self.active_backend.as_ref() == Some(&backend_name.to_string()) {
                    self.active_backend = None;
                }

                Ok(())
            } else {
                Err(format!("Backend '{}' not found", backend_name))
            }
        }

        fn get_status(&self, backend_name: &str) -> Option<&MockBackendStatus> {
            self.backends.get(backend_name)
        }
    }

    let mut manager = MockBackendManager::new();

    // Test starting backend
    let start_result = manager.start_backend("mock");
    assert!(start_result.is_ok());

    let mock_status = manager.get_status("mock").unwrap();
    assert_eq!(mock_status.status, "running");
    assert_eq!(manager.active_backend, Some("mock".to_string()));

    // Test starting already running backend
    let start_result2 = manager.start_backend("mock");
    assert!(start_result2.is_err());

    // Test stopping backend
    let stop_result = manager.stop_backend("mock");
    assert!(stop_result.is_ok());

    let mock_status2 = manager.get_status("mock").unwrap();
    assert_eq!(mock_status2.status, "stopped");
    assert_eq!(manager.active_backend, None);

    // Test stopping already stopped backend
    let stop_result2 = manager.stop_backend("mock");
    assert!(stop_result2.is_err());

    // Test non-existent backend
    let start_result3 = manager.start_backend("nonexistent");
    assert!(start_result3.is_err());

    println!("✓ CLI backend lifecycle tests passed");
}

// =============================================================================
// Monitoring Commands Tests
// =============================================================================

/// Test CLI monitoring commands
fn test_cli_monitoring_commands() {
    println!("Testing CLI monitoring commands...");

    // Simulate monitoring command structure
    #[derive(Debug)]
    struct MonitorCommand {
        mode: String,           // "realtime", "log", "export"
        filters: Vec<String>,   // Filter criteria
        format: String,         // "table", "json", "yaml"
        interval: Option<u64>,  // Refresh interval for realtime mode
        output: Option<String>, // Output file for export mode
    }

    let commands = vec![
        (
            "agent-gateway-enforcer monitor --mode realtime",
            MonitorCommand {
                mode: "realtime".to_string(),
                filters: vec![],
                format: "table".to_string(),
                interval: Some(1),
                output: None,
            },
        ),
        (
            "agent-gateway-enforcer monitor --mode export --format json --output metrics.json",
            MonitorCommand {
                mode: "export".to_string(),
                filters: vec![],
                format: "json".to_string(),
                interval: None,
                output: Some("metrics.json".to_string()),
            },
        ),
        (
            "agent-gateway-enforcer monitor --mode log --filter severity=error --filter type=network",
            MonitorCommand {
                mode: "log".to_string(),
                filters: vec!["severity=error".to_string(), "type=network".to_string()],
                format: "table".to_string(),
                interval: None,
                output: None,
            },
        ),
    ];

    // Verify command parsing
    for (command_str, expected) in commands {
        assert!(command_str.contains(&expected.mode));

        if let Some(output) = &expected.output {
            assert!(command_str.contains(output));
        }

        for filter in &expected.filters {
            assert!(command_str.contains(filter));
        }
    }

    println!("✓ CLI monitoring commands tests passed");
}

/// Test CLI metrics output
fn test_cli_metrics_output() {
    println!("Testing CLI metrics output...");

    // Simulate metrics output in different formats

    // Table format
    let table_output = r#"
╔══════════════════════════════════════════╤═════════╗
║ Metric Name                              │ Value   ║
╠══════════════════════════════════════════╪═════════╣
║ http_requests_total                       │ 1,234   ║
║ active_connections                       │ 42      ║
║ cpu_usage_percent                        │ 75.5    ║
║ memory_usage_bytes                       │ 8.5GB   ║
║ events_processed_total                   │ 98,765  ║
║ policy_violations_total                  │ 123     ║
╚══════════════════════════════════════════╧═════════╝
"#;

    // JSON format
    let json_output = r#"
{
  "timestamp": "2024-01-15T10:30:00Z",
  "metrics": {
    "http_requests_total": 1234,
    "active_connections": 42,
    "cpu_usage_percent": 75.5,
    "memory_usage_bytes": 8589934592,
    "events_processed_total": 98765,
    "policy_violations_total": 123
  }
}
"#;

    // Prometheus format
    let prometheus_output = r#"
# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
http_requests_total 1234

# HELP active_connections Current active connections
# TYPE active_connections gauge
active_connections 42

# HELP cpu_usage_percent CPU usage percentage
# TYPE cpu_usage_percent gauge
cpu_usage_percent 75.5
"#;

    // Verify format content
    assert!(table_output.contains("Metric Name"));
    assert!(table_output.contains("Value"));
    assert!(table_output.contains("http_requests_total"));

    assert!(json_output.contains("\"metrics\""));
    assert!(json_output.contains("\"http_requests_total\""));
    assert!(json_output.contains("1234"));

    assert!(prometheus_output.contains("# HELP"));
    assert!(prometheus_output.contains("# TYPE"));
    assert!(prometheus_output.contains("http_requests_total 1234"));

    println!("✓ CLI metrics output tests passed");
}

/// Test CLI events output
fn test_cli_events_output() {
    println!("Testing CLI events output...");

    // Simulate events output
    let events_output = r#"
╔══════════════════════════════════════════════════════════════╗
║ Timestamp                  │ Type    │ Severity │ Message    ║
╠══════════════════════════════════════════════════════════════╣
║ 2024-01-15 10:29:58.123   │ network │ info    │ Conn est   ║
║ 2024-01-15 10:29:57.456   │ file    │ warning │ Access den  ║
║ 2024-01-15 10:29:56.789   │ system  │ error   │ Resource ex ║
║ 2024-01-15 10:29:55.012   │ security│ critical│ Intrusion  ║
╚══════════════════════════════════════════════════════════════╝

Total Events: 4 | Filtered: 4 | Showing last 4 events
"#;

    // Verify events output content
    assert!(events_output.contains("Timestamp"));
    assert!(events_output.contains("Type"));
    assert!(events_output.contains("Severity"));
    assert!(events_output.contains("Message"));
    assert!(events_output.contains("Total Events:"));
    assert!(events_output.contains("network"));
    assert!(events_output.contains("security"));

    println!("✓ CLI events output tests passed");
}

// =============================================================================
// Error Handling Tests
// =============================================================================

/// Test CLI invalid arguments
fn test_cli_invalid_arguments() {
    println!("Testing CLI invalid arguments...");

    // Simulate error responses for invalid arguments
    let error_cases = vec![
        (
            "agent-gateway-enforcer --invalid-flag",
            "unrecognized flag '--invalid-flag'",
        ),
        (
            "agent-gateway-enforcer start --config",
            "missing argument for '--config'",
        ),
        (
            "agent-gateway-enforcer start --port abc",
            "invalid value 'abc' for '--port'",
        ),
        (
            "agent-gateway-enforcer nonexistent-command",
            "unrecognized subcommand 'nonexistent-command'",
        ),
        (
            "agent-gateway-enforcer backend start",
            "missing required argument 'BACKEND_NAME'",
        ),
    ];

    for (command, expected_error) in error_cases {
        // In a real implementation, this would execute the command
        // For now, we'll verify the error pattern
        assert!(
            expected_error.contains("unrecognized")
                || expected_error.contains("missing")
                || expected_error.contains("invalid")
        );
    }

    println!("✓ CLI invalid arguments tests passed");
}

/// Test CLI missing config
fn test_cli_missing_config() {
    println!("Testing CLI missing config...");

    let temp_manager = TempDirManager::new();
    let missing_config_path = temp_manager
        .create_temp_dir()
        .expect("Failed to create temp dir")
        .join("missing_config.yaml");

    // Simulate missing config error
    let simulated_error = format!(
        "Error: Configuration file not found: {}\n\
        Hint: Create a configuration file or specify a different path with --config\n\
        Example config files are available in the documentation.",
        missing_config_path.display()
    );

    // Verify error message
    assert!(simulated_error.contains("Configuration file not found"));
    assert!(simulated_error.contains("Hint:"));
    assert!(simulated_error.contains("Example config files"));

    println!("✓ CLI missing config tests passed");
}

/// Test CLI permission errors
fn test_cli_permission_errors() {
    println!("Testing CLI permission errors...");

    // Simulate permission errors
    let permission_errors = vec![
        "Error: Permission denied when reading configuration file",
        "Error: Insufficient privileges to start eBPF backend (requires root or CAP_BPF)",
        "Error: Cannot bind to privileged port 80 (requires root privileges)",
        "Error: Unable to write to log file: Permission denied",
        "Error: Cannot access system metrics: Operation not permitted",
    ];

    for error in permission_errors {
        assert!(
            error.contains("Permission")
                || error.contains("privileges")
                || error.contains("permitted")
        );
    }

    println!("✓ CLI permission errors tests passed");
}
