//! Integration Test Suite for Agent Gateway Enforcer
//!
//! This is the main integration test suite that covers all components of the
//! agent-gateway-enforcer system including core functionality, backends, CLI,
//! and web interfaces.
//!
//! ## Test Categories
//!
//! 1. **Platform Integration Tests** - Cross-platform functionality
//! 2. **Backend Integration Tests** - eBPF, macOS, Windows backends
//! 3. **CLI Integration Tests** - Command-line interface functionality
//! 4. **Web Interface Tests** - Web dashboard and API
//! 5. **Configuration Tests** - Multi-format configuration handling
//! 6. **Event System Tests** - Event publishing and handling
//! 7. **Metrics Collection Tests** - Metrics gathering and export
//! 8. **Security Tests** - Security policy enforcement
//! 9. **Performance Tests** - Performance and load testing
//!
//! ## Running Tests
//!
//! ```bash
//! # Run all integration tests
//! cargo test --test integration_suite
//!
//! # Run specific test categories
//! cargo test --test integration_suite platform
//! cargo test --test integration_suite backend
//! cargo test --test integration_suite cli
//! cargo test --test integration_suite web
//!
//! # Run with verbose output
//! cargo test --test integration_suite -- --nocapture
//!
//! # Run with specific features
//! cargo test --test integration_suite --features "ebpf macos windows"
//! ```
//!
//! ## Test Environment Requirements
//!
//! ### Linux (eBPF Tests)
//! - Linux kernel 5.8+
//! - Root privileges or CAP_BPF capability
//! - eBPF program built: `cargo xtask build-ebpf`
//!
//! ### macOS (macOS Backend Tests)
//! - macOS 10.15+
//! - Swift/Objective-C runtime for system integration
//!
//! ### Windows (Windows Backend Tests)
//! - Windows 10+
//! - Administrator privileges for API hooks
//!
//! ## Test Utilities
//!
//! The test suite provides utilities for:
//! - Temporary file and directory management
//! - Mock backend implementations
//! - Network port allocation
//! - Configuration file generation
//! - Async test helpers
//! - Platform detection

use std::env;
use std::path::Path;
use std::time::Duration;

// Test utilities
mod test_utils;

// Test modules
// TODO: Add platform_tests when implemented
// mod platform_tests;
mod backend_integration_tests;
mod cli_integration_tests;
mod configuration_tests;
mod event_system_tests;
mod metrics_tests;
mod web_interface_tests;
// TODO: Add security_tests when implemented
// mod security_tests;
// TODO: Add performance_tests when implemented
// mod performance_tests;

/// Test configuration and environment setup
#[derive(Debug, Clone)]
pub struct TestConfig {
    /// Temporary directory for test files
    pub temp_dir: String,
    /// Base port for web server tests
    pub base_port: u16,
    /// Whether running in CI environment
    pub ci_mode: bool,
    /// Test timeout in seconds
    pub timeout: Duration,
    /// Platform-specific test configuration
    pub platform: PlatformTestConfig,
}

/// Platform-specific test configuration
#[derive(Debug, Clone)]
pub struct PlatformTestConfig {
    /// Whether to run Linux/eBPF tests
    pub run_linux_tests: bool,
    /// Whether to run macOS tests
    pub run_macos_tests: bool,
    /// Whether to run Windows tests
    pub run_windows_tests: bool,
    /// Whether we have root/administrator privileges
    pub has_privileges: bool,
    /// Whether eBPF programs are built and available
    pub ebpf_available: bool,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl TestConfig {
    /// Create a new test configuration
    pub fn new() -> Self {
        let temp_dir = env::temp_dir()
            .join("agent-gateway-enforcer-tests")
            .to_string_lossy()
            .to_string();

        Self {
            temp_dir,
            base_port: 18080,
            ci_mode: env::var("CI").is_ok(),
            timeout: Duration::from_secs(30),
            platform: PlatformTestConfig::detect(),
        }
    }
}

impl PlatformTestConfig {
    /// Detect platform capabilities and test requirements
    pub fn detect() -> Self {
        let is_linux = cfg!(target_os = "linux");
        let is_macos = cfg!(target_os = "macos");
        let is_windows = cfg!(target_os = "windows");

        let has_privileges = detect_privileges();
        let ebpf_available = is_linux && has_privileges && ebpf_program_exists();

        Self {
            run_linux_tests: is_linux,
            run_macos_tests: is_macos,
            run_windows_tests: is_windows,
            has_privileges,
            ebpf_available,
        }
    }
}

/// Detect if running with elevated privileges
fn detect_privileges() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        // On Windows, check if running as administrator
        // This is a simplified check - in practice you'd want to check token privileges
        true // Placeholder
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Check if eBPF program has been built
fn ebpf_program_exists() -> bool {
    #[cfg(target_os = "linux")]
    {
        let paths = [
            "target/bpf/agent-gateway-enforcer.bpf.o",
            "../target/bpf/agent-gateway-enforcer.bpf.o",
            "backends/ebpf-linux/target/bpf/agent-gateway-enforcer.bpf.o",
        ];
        paths.iter().any(|p| Path::new(p).exists())
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Global test configuration instance
lazy_static::lazy_static! {
    static ref TEST_CONFIG: TestConfig = TestConfig::new();
}

/// Get the global test configuration
pub fn test_config() -> &'static TestConfig {
    &TEST_CONFIG
}

/// Macro for skipping tests that require Linux
#[macro_export]
macro_rules! require_linux {
    () => {
        if !test_config().platform.run_linux_tests {
            eprintln!("Skipping test: not running on Linux");
            return;
        }
    };
}

/// Macro for skipping tests that require macOS
#[macro_export]
macro_rules! require_macos {
    () => {
        if !test_config().platform.run_macos_tests {
            eprintln!("Skipping test: not running on macOS");
            return;
        }
    };
}

/// Macro for skipping tests that require Windows
#[macro_export]
macro_rules! require_windows {
    () => {
        if !test_config().platform.run_windows_tests {
            eprintln!("Skipping test: not running on Windows");
            return;
        }
    };
}

/// Macro for skipping tests that require elevated privileges
#[macro_export]
macro_rules! require_privileges {
    () => {
        if !test_config().platform.has_privileges {
            eprintln!("Skipping test: requires elevated privileges");
            return;
        }
    };
}

/// Macro for skipping tests that require eBPF
#[macro_export]
macro_rules! require_ebpf {
    () => {
        if !test_config().platform.ebpf_available {
            eprintln!("Skipping test: eBPF not available. Build eBPF programs with 'cargo xtask build-ebpf'");
            return;
        }
    };
}

// =============================================================================
// Test Environment Setup
// =============================================================================

/// Setup test environment before running tests
#[cfg(test)]
fn setup_test_environment() {
    // Initialize logging for tests
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    // Create temporary directory if it doesn't exist
    let temp_dir = Path::new(&test_config().temp_dir);
    if !temp_dir.exists() {
        let _ = std::fs::create_dir_all(temp_dir);
    }
}

/// Cleanup test environment after running tests
#[cfg(test)]
fn cleanup_test_environment() {
    // In CI mode, don't cleanup to allow inspection of test artifacts
    if test_config().ci_mode {
        return;
    }

    // Cleanup temporary directory
    let temp_dir = Path::new(&test_config().temp_dir);
    if temp_dir.exists() {
        let _ = std::fs::remove_dir_all(temp_dir);
    }
}

// =============================================================================
// Main Integration Test Entry Points
// =============================================================================

/// Test environment detection and setup
#[test]
fn test_environment_detection() {
    let config = test_config();

    println!("=== Agent Gateway Enforcer Integration Test Environment ===");
    println!("Temp Directory: {}", config.temp_dir);
    println!("Base Port: {}", config.base_port);
    println!("CI Mode: {}", config.ci_mode);
    println!("Test Timeout: {:?}", config.timeout);
    println!();

    println!("=== Platform Configuration ===");
    println!("Linux Tests: {}", config.platform.run_linux_tests);
    println!("macOS Tests: {}", config.platform.run_macos_tests);
    println!("Windows Tests: {}", config.platform.run_windows_tests);
    println!("Has Privileges: {}", config.platform.has_privileges);
    println!("eBPF Available: {}", config.platform.ebpf_available);
    println!();

    // Basic assertions
    assert!(!config.temp_dir.is_empty());
    assert!(config.base_port > 0);
    assert!(config.timeout > Duration::from_secs(0));
}

/// Test that all required dependencies are available
#[test]
fn test_dependency_availability() {
    // Test that common library is available
    #[cfg(feature = "common")]
    {
        use agent_gateway_enforcer_common::{GatewayKey, PathKey};
        let _gateway_key = GatewayKey::new(0, 8080);
        let _path_key = PathKey::new("/test");
    }

    // Test that core library is available
    #[cfg(feature = "core")]
    {
        // Add core library test when available
    }

    // Test that CLI components are available
    #[cfg(feature = "cli")]
    {
        // Add CLI test when available
    }

    println!("All required dependencies are available");
}

// =============================================================================
// Test Suite Runner
// =============================================================================

/// Run all integration tests
#[cfg(test)]
mod test_runner {
    use super::*;

    // #[test]
    // fn run_all_platform_tests() {
    //     platform_tests::run_all_platform_tests();
    // }

    #[test]
    fn run_all_backend_tests() {
        backend_integration_tests::run_all_backend_tests();
    }

    #[test]
    fn run_all_cli_tests() {
        cli_integration_tests::run_all_cli_tests();
    }

    #[test]
    fn run_all_web_interface_tests() {
        web_interface_tests::run_all_web_interface_tests();
    }

    #[test]
    fn run_all_configuration_tests() {
        configuration_tests::run_all_configuration_tests();
    }

    #[test]
    fn run_all_event_system_tests() {
        event_system_tests::run_all_event_system_tests();
    }

    #[test]
    fn run_all_metrics_tests() {
        metrics_tests::run_all_metrics_tests();
    }

    // #[test]
    // fn run_all_security_tests() {
    //     security_tests::run_all_security_tests();
    // }

    // #[test]
    // fn run_all_performance_tests() {
    //     performance_tests::run_all_performance_tests();
    // }
}
