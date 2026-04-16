//! Test utilities and shared infrastructure for agent-gateway-enforcer integration tests
//!
//! This crate provides common utilities used across all test modules including:
//! - Temporary file and directory management
//! - Network port allocation and management
//! - Mock backend implementations
//! - Configuration file generation
//! - Async test helpers
//! - Process and system utilities
//! - Platform requirement macros

pub mod test_utils;

// Re-export commonly used items at crate root
pub use test_utils::*;

// =============================================================================
// Platform Requirement Macros
// =============================================================================

/// Skip test on non-Linux platforms
#[macro_export]
macro_rules! require_linux {
    () => {
        if cfg!(not(target_os = "linux")) {
            println!("Skipping test: requires Linux");
            return;
        }
    };
}

/// Skip test on non-macOS platforms
#[macro_export]
macro_rules! require_macos {
    () => {
        if cfg!(not(target_os = "macos")) {
            println!("Skipping test: requires macOS");
            return;
        }
    };
}

/// Skip test on non-Windows platforms
#[macro_export]
macro_rules! require_windows {
    () => {
        if cfg!(not(target_os = "windows")) {
            println!("Skipping test: requires Windows");
            return;
        }
    };
}

/// Skip test if eBPF is not available
#[macro_export]
macro_rules! require_ebpf {
    () => {
        if cfg!(not(target_os = "linux")) {
            println!("Skipping test: eBPF requires Linux");
            return;
        }
        // Additional check for eBPF availability could be added here
    };
}

/// Skip test if root/admin privileges are not available
#[macro_export]
macro_rules! require_privileges {
    () => {
        #[cfg(unix)]
        {
            if !nix::unistd::Uid::effective().is_root() {
                println!("Skipping test: requires root privileges");
                return;
            }
        }
        #[cfg(windows)]
        {
            // Windows privilege check would go here
            println!("Skipping test: privilege check not implemented on Windows");
            return;
        }
    };
}

// =============================================================================
// Base Test Configuration
// =============================================================================

/// Basic test configuration - tests may define more specific configs
#[derive(Debug, Clone)]
pub struct BaseTestConfig {
    /// Base port for test servers
    pub base_port: u16,
    /// Temporary directory path
    pub temp_dir: String,
    /// Test timeout in seconds
    pub timeout_secs: u64,
    /// Enable verbose logging
    pub verbose: bool,
    /// Current platform
    pub platform: String,
}

impl Default for BaseTestConfig {
    fn default() -> Self {
        Self {
            base_port: 18080,
            temp_dir: std::env::temp_dir()
                .join("agent-gateway-enforcer-tests")
                .to_string_lossy()
                .to_string(),
            timeout_secs: 30,
            verbose: std::env::var("TEST_VERBOSE").is_ok(),
            platform: std::env::consts::OS.to_string(),
        }
    }
}

/// Get the basic test configuration
pub fn base_test_config() -> BaseTestConfig {
    BaseTestConfig::default()
}

// =============================================================================
// Test Result Types
// =============================================================================

/// Result type for test operations
pub type TestResult<T> = Result<T, anyhow::Error>;

/// Assert that a result is Ok and return the value
#[macro_export]
macro_rules! assert_ok {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => panic!("Expected Ok, got Err: {:?}", e),
        }
    };
}

/// Assert that a result is Err
#[macro_export]
macro_rules! assert_err {
    ($expr:expr) => {
        match $expr {
            Ok(val) => panic!("Expected Err, got Ok: {:?}", val),
            Err(_) => {}
        }
    };
}
