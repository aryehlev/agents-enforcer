//! Test utilities and helper functions for the integration test suite
//!
//! This module provides common utilities used across all test modules including:
//! - Temporary file and directory management
//! - Network port allocation and management
//! - Mock backend implementations
//! - Configuration file generation
//! - Async test helpers
//! - Process and system utilities

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::time::timeout;

// Re-export commonly used items
pub use tempfile;
pub use tokio;

// =============================================================================
// Temporary Directory Management
// =============================================================================

/// Manages temporary test directories with automatic cleanup
pub struct TempDirManager {
    temp_dirs: Arc<Mutex<Vec<TempDir>>>,
}

impl TempDirManager {
    /// Create a new temporary directory manager
    pub fn new() -> Self {
        Self {
            temp_dirs: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create a new temporary directory and return its path
    pub fn create_temp_dir(&self) -> Result<PathBuf, anyhow::Error> {
        let temp_dir = tempdir()?;
        let path = temp_dir.path().to_path_buf();
        self.temp_dirs.lock().unwrap().push(temp_dir);
        Ok(path)
    }

    /// Create a temporary file with given content
    pub fn create_temp_file(&self, name: &str, content: &str) -> Result<PathBuf, anyhow::Error> {
        let temp_path = self.create_temp_dir()?;
        let file_path = temp_path.join(name);
        fs::write(&file_path, content)?;
        Ok(file_path)
    }

    /// Get the number of managed temporary directories
    pub fn count(&self) -> usize {
        self.temp_dirs.lock().unwrap().len()
    }
}

impl Default for TempDirManager {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Network Port Management
// =============================================================================

/// Manages allocation of network ports for testing
#[derive(Debug)]
pub struct PortManager {
    base_port: u16,
    allocated_ports: Arc<Mutex<HashMap<String, u16>>>,
}

impl PortManager {
    /// Create a new port manager starting from base_port
    pub fn new(base_port: u16) -> Self {
        Self {
            base_port,
            allocated_ports: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Allocate a port for a specific test component
    pub fn allocate_port(&self, component: &str) -> Result<u16, anyhow::Error> {
        let mut ports = self.allocated_ports.lock().unwrap();

        if ports.contains_key(component) {
            return Ok(ports[component]);
        }

        let port = self.base_port + ports.len() as u16;
        ports.insert(component.to_string(), port);
        Ok(port)
    }

    /// Get the base socket address for allocated port
    pub fn get_socket_addr(&self, component: &str) -> Result<SocketAddr, anyhow::Error> {
        let port = self.allocate_port(component)?;
        Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port,
        ))
    }

    /// Check if a port is available
    pub fn is_port_available(&self, port: u16) -> bool {
        use std::net::TcpListener;
        TcpListener::bind(("127.0.0.1", port)).is_ok()
    }
}

// =============================================================================
// Mock Backend Implementation
// =============================================================================

/// Mock backend for testing purposes
#[derive(Debug, Clone)]
pub struct MockBackend {
    name: String,
    backend_type: String,
    platform: String,
    initialized: Arc<Mutex<bool>>,
    operations: Arc<Mutex<Vec<String>>>,
    config: Arc<Mutex<HashMap<String, String>>>,
}

impl MockBackend {
    /// Create a new mock backend
    pub fn new(name: &str, backend_type: &str, platform: &str) -> Self {
        Self {
            name: name.to_string(),
            backend_type: backend_type.to_string(),
            platform: platform.to_string(),
            initialized: Arc::new(Mutex::new(false)),
            operations: Arc::new(Mutex::new(Vec::new())),
            config: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Initialize the mock backend
    pub fn initialize(&self) -> Result<(), anyhow::Error> {
        self.log_operation("initialize".to_string());
        *self.initialized.lock().unwrap() = true;
        Ok(())
    }

    /// Shutdown the mock backend
    pub fn shutdown(&self) -> Result<(), anyhow::Error> {
        self.log_operation("shutdown".to_string());
        *self.initialized.lock().unwrap() = false;
        Ok(())
    }

    /// Check if backend is initialized
    pub fn is_initialized(&self) -> bool {
        *self.initialized.lock().unwrap()
    }

    /// Get the backend name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the backend type
    pub fn backend_type(&self) -> &str {
        &self.backend_type
    }

    /// Get the platform
    pub fn platform(&self) -> &str {
        &self.platform
    }

    /// Set a configuration value
    pub fn set_config(&self, key: &str, value: &str) {
        self.config
            .lock()
            .unwrap()
            .insert(key.to_string(), value.to_string());
    }

    /// Get a configuration value
    pub fn get_config(&self, key: &str) -> Option<String> {
        self.config.lock().unwrap().get(key).cloned()
    }

    /// Log an operation
    pub fn log_operation(&self, operation: String) {
        self.operations.lock().unwrap().push(operation);
    }

    /// Get all logged operations
    pub fn get_operations(&self) -> Vec<String> {
        self.operations.lock().unwrap().clone()
    }

    /// Clear operation log
    pub fn clear_operations(&self) {
        self.operations.lock().unwrap().clear();
    }

    /// Check if specific operation was performed
    pub fn has_operation(&self, operation: &str) -> bool {
        self.operations
            .lock()
            .unwrap()
            .contains(&operation.to_string())
    }

    /// Count operations of a specific type
    pub fn count_operations(&self, operation: &str) -> usize {
        self.operations
            .lock()
            .unwrap()
            .iter()
            .filter(|op| *op == operation)
            .count()
    }
}

// =============================================================================
// Configuration File Generation
// =============================================================================

/// Generate test configuration files in various formats
pub struct ConfigGenerator {
    temp_dir_manager: TempDirManager,
}

impl ConfigGenerator {
    /// Create a new configuration generator
    pub fn new() -> Self {
        Self {
            temp_dir_manager: TempDirManager::new(),
        }
    }

    /// Generate a minimal YAML configuration
    pub fn generate_minimal_yaml(&self) -> Result<PathBuf, anyhow::Error> {
        let config = r#"
# Minimal agent-gateway-enforcer configuration
server:
  host: "127.0.0.1"
  port: 8080

backend:
  type: "mock"
  
logging:
  level: "info"
"#;
        self.temp_dir_manager
            .create_temp_file("config.yaml", config)
    }

    /// Generate a development YAML configuration
    pub fn generate_dev_yaml(&self) -> Result<PathBuf, anyhow::Error> {
        let config = r#"
# Development configuration for agent-gateway-enforcer
server:
  host: "127.0.0.1"
  port: 8080
  workers: 4

backend:
  type: "mock"
  auto_start: true
  health_check_interval: 30

logging:
  level: "debug"
  format: "pretty"

metrics:
  enabled: true
  prometheus:
    enabled: true
    port: 9090
    
events:
  buffer_size: 1000
  max_events_per_second: 1000

security:
  default_policy: "deny"
  log_blocked_access: true
"#;
        self.temp_dir_manager
            .create_temp_file("config-dev.yaml", config)
    }

    /// Generate a production YAML configuration
    pub fn generate_prod_yaml(&self) -> Result<PathBuf, anyhow::Error> {
        let config = r#"
# Production configuration for agent-gateway-enforcer
server:
  host: "0.0.0.0"
  port: 8080
  workers: 8
  timeout: 30

backend:
  type: "ebpf"
  auto_start: true
  health_check_interval: 10
  restart_on_failure: true

logging:
  level: "warn"
  format: "json"
  file: "/var/log/agent-gateway-enforcer.log"

metrics:
  enabled: true
  prometheus:
    enabled: true
    port: 9090
    path: "/metrics"
    
events:
  buffer_size: 10000
  max_events_per_second: 5000
  export:
    type: "file"
    path: "/var/log/agent-gateway-enforcer-events.json"

security:
  default_policy: "deny"
  log_blocked_access: true
  audit_log: "/var/log/agent-gateway-enforcer-audit.log"

cors:
  allowed_origins: ["https://dashboard.example.com"]
  allowed_methods: ["GET", "POST", "PUT", "DELETE"]
  allowed_headers: ["Content-Type", "Authorization"]
"#;
        self.temp_dir_manager
            .create_temp_file("config-prod.yaml", config)
    }

    /// Generate JSON configuration
    pub fn generate_json(&self) -> Result<PathBuf, anyhow::Error> {
        let config = r#"
{
  "server": {
    "host": "127.0.0.1",
    "port": 8080
  },
  "backend": {
    "type": "mock"
  },
  "logging": {
    "level": "info"
  }
}
"#;
        self.temp_dir_manager
            .create_temp_file("config.json", config)
    }

    /// Generate TOML configuration
    pub fn generate_toml(&self) -> Result<PathBuf, anyhow::Error> {
        let config = r#"
[server]
host = "127.0.0.1"
port = 8080

[backend]
type = "mock"

[logging]
level = "info"
"#;
        self.temp_dir_manager
            .create_temp_file("config.toml", config)
    }

    /// Generate invalid configuration for testing error handling
    pub fn generate_invalid_config(&self) -> Result<PathBuf, anyhow::Error> {
        let config = r#"
# Invalid configuration for testing
server:
  port: "invalid_port_number"  # Should be a number
  
backend:
  type: 123  # Should be a string
  
missing_required_field: true
"#;
        self.temp_dir_manager
            .create_temp_file("config-invalid.yaml", config)
    }
}

impl Default for ConfigGenerator {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Async Test Helpers
// =============================================================================

/// Helper for async testing with timeouts
pub struct AsyncTestHelper;

impl AsyncTestHelper {
    /// Run an async function with a timeout
    pub async fn with_timeout<F, T>(duration: Duration, future: F) -> Result<T, anyhow::Error>
    where
        F: std::future::Future<Output = T>,
    {
        match timeout(duration, future).await {
            Ok(result) => Ok(result),
            Err(_) => Err(anyhow::anyhow!("Test timed out after {:?}", duration)),
        }
    }

    /// Wait for a condition to become true with timeout
    pub async fn wait_for_condition<F>(
        duration: Duration,
        interval: Duration,
        condition: F,
    ) -> Result<(), anyhow::Error>
    where
        F: Fn() -> bool + Send + Sync + 'static,
    {
        let condition = Arc::new(condition);
        let start = std::time::Instant::now();

        loop {
            if (condition)() {
                return Ok(());
            }

            if start.elapsed() > duration {
                return Err(anyhow::anyhow!("Condition not met within timeout"));
            }

            tokio::time::sleep(interval).await;
        }
    }
}

// =============================================================================
// Process Utilities
// =============================================================================

/// Utilities for managing external processes in tests
pub struct ProcessUtils;

impl ProcessUtils {
    /// Start a process and return its child handle
    pub fn start_process(
        program: &str,
        args: &[&str],
    ) -> Result<std::process::Child, anyhow::Error> {
        let child = Command::new(program)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        Ok(child)
    }

    /// Check if a process is running by PID
    pub fn is_process_running(pid: u32) -> bool {
        #[cfg(unix)]
        {
            use std::process;
            let output = process::Command::new("kill")
                .arg("-0")
                .arg(pid.to_string())
                .output();
            output.map(|o| o.status.success()).unwrap_or(false)
        }
        #[cfg(windows)]
        {
            // Windows equivalent using tasklist or similar
            true // Placeholder
        }
    }

    /// Wait for a process to exit with timeout
    pub fn wait_for_exit(
        child: &mut std::process::Child,
        timeout: Duration,
    ) -> Result<std::process::ExitStatus, anyhow::Error> {
        let start = std::time::Instant::now();

        loop {
            match child.try_wait()? {
                Some(status) => return Ok(status),
                None => {
                    if start.elapsed() > timeout {
                        return Err(anyhow::anyhow!("Process didn't exit within timeout"));
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
}

// =============================================================================
// File System Utilities
// =============================================================================

/// File system utilities for testing
pub struct FsUtils;

impl FsUtils {
    /// Create a directory structure for testing
    pub fn create_directory_structure(
        base: &Path,
        structure: &[&str],
    ) -> Result<(), anyhow::Error> {
        for path in structure {
            let full_path = base.join(path);
            if path.ends_with('/') {
                fs::create_dir_all(full_path)?;
            } else {
                if let Some(parent) = full_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(full_path, "test content")?;
            }
        }
        Ok(())
    }

    /// Check if a file exists and has the expected content
    pub fn verify_file_content(path: &Path, expected_content: &str) -> Result<bool, anyhow::Error> {
        if !path.exists() {
            return Ok(false);
        }

        let content = fs::read_to_string(path)?;
        Ok(content == expected_content)
    }

    /// Get file permissions
    #[cfg(unix)]
    pub fn get_file_permissions(path: &Path) -> Result<u32, anyhow::Error> {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(path)?;
        Ok(metadata.permissions().mode())
    }

    /// Set file permissions
    #[cfg(unix)]
    pub fn set_file_permissions(path: &Path, mode: u32) -> Result<(), anyhow::Error> {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(path)?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(mode);
        fs::set_permissions(path, permissions)?;
        Ok(())
    }
}

// =============================================================================
// Network Utilities
// =============================================================================

/// Network utilities for testing
pub struct NetUtils;

impl NetUtils {
    /// Check if a port is in use
    pub fn is_port_in_use(port: u16) -> bool {
        use std::net::TcpListener;
        TcpListener::bind(("127.0.0.1", port)).is_err()
    }

    /// Find an available port starting from base_port
    pub fn find_available_port(base_port: u16) -> Option<u16> {
        for port in base_port..(base_port + 100) {
            if !Self::is_port_in_use(port) {
                return Some(port);
            }
        }
        None
    }

    /// Wait for a service to be available on a port
    pub async fn wait_for_service(port: u16, timeout: Duration) -> Result<(), anyhow::Error> {
        let start = std::time::Instant::now();

        loop {
            if Self::is_port_in_use(port) {
                return Ok(());
            }

            if start.elapsed() > timeout {
                return Err(anyhow::anyhow!(
                    "Service not available on port {} within {:?}",
                    port,
                    timeout
                ));
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
