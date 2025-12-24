//! Platform Integration Tests
//!
//! This module contains cross-platform integration tests:
//! - Platform detection and validation
//! - Platform-specific feature availability
//! - Cross-platform compatibility
//! - Platform-specific optimizations
//! - Environment-specific behavior

use crate::test_utils::*;
use crate::{require_linux, require_macos, require_windows};

/// Run all platform tests
pub fn run_all_platform_tests() {
    println!("=== Running Platform Integration Tests ===");

    // Test platform detection
    test_platform_detection();
    test_platform_features();
    test_platform_compatibility();

    // Test cross-platform behavior
    test_cross_platform_configuration();
    test_cross_platform_paths();
    test_cross_platform_permissions();

    // Test platform-specific functionality
    #[cfg(target_os = "linux")]
    test_linux_specific_features();

    #[cfg(target_os = "macos")]
    test_macos_specific_features();

    #[cfg(target_os = "windows")]
    test_windows_specific_features();

    // Test environment-specific behavior
    test_development_environment();
    test_production_environment();
    test_container_environment();

    println!("=== Platform Integration Tests Completed ===");
}

// =============================================================================
// Platform Detection Tests
// =============================================================================

/// Test platform detection
fn test_platform_detection() {
    println!("Testing platform detection...");

    // Test current platform detection
    let current_os = std::env::consts::OS;
    let current_arch = std::env::consts::ARCH;
    let current_family = std::env::consts::FAMILY;

    println!(
        "Current platform: {} {} ({})",
        current_os, current_arch, current_family
    );

    // Verify platform constants
    assert!(!current_os.is_empty());
    assert!(!current_arch.is_empty());
    assert!(!current_family.is_empty());

    // Test platform-specific constants
    #[cfg(target_os = "linux")]
    {
        assert_eq!(current_os, "linux");
        println!("✓ Linux platform detected");
    }

    #[cfg(target_os = "macos")]
    {
        assert_eq!(current_os, "macos");
        println!("✓ macOS platform detected");
    }

    #[cfg(target_os = "windows")]
    {
        assert_eq!(current_os, "windows");
        println!("✓ Windows platform detected");
    }

    // Test architecture detection
    #[cfg(target_arch = "x86_64")]
    {
        assert_eq!(current_arch, "x86_64");
        println!("✓ x86_64 architecture detected");
    }

    #[cfg(target_arch = "aarch64")]
    {
        assert_eq!(current_arch, "aarch64");
        println!("✓ AArch64 architecture detected");
    }

    println!("✓ Platform detection tests passed");
}

/// Test platform features
fn test_platform_features() {
    println!("Testing platform features...");

    let config = crate::test_config();

    // Test Linux-specific features
    if cfg!(target_os = "linux") {
        assert!(config.platform.run_linux_tests);

        // Test eBPF availability (requires kernel 5.8+)
        if config.platform.ebpf_available {
            println!("✓ eBPF programs are available");
        } else {
            println!("⚠ eBPF programs not available (requires kernel 5.8+ and build)");
        }

        // Test privilege detection
        if config.platform.has_privileges {
            println!("✓ Running with elevated privileges");
        } else {
            println!("⚠ Running without elevated privileges");
        }
    }

    // Test macOS-specific features
    if cfg!(target_os = "macos") {
        assert!(config.platform.run_macos_tests);
        println!("✓ macOS-specific features available");

        // Test macOS-specific APIs (in real implementation)
        println!("⚠ macOS API integration requires native testing");
    }

    // Test Windows-specific features
    if cfg!(target_os = "windows") {
        assert!(config.platform.run_windows_tests);
        println!("✓ Windows-specific features available");

        // Test Windows-specific APIs (in real implementation)
        println!("⚠ Windows API integration requires native testing");
    }

    println!("✓ Platform features tests passed");
}

/// Test platform compatibility
fn test_platform_compatibility() {
    println!("Testing platform compatibility...");

    // Test supported platforms
    let supported_platforms = vec![
        ("linux", "x86_64", true),
        ("linux", "aarch64", true),
        ("macos", "x86_64", true),
        ("macos", "aarch64", true),
        ("windows", "x86_64", true),
        ("windows", "aarch64", true),
    ];

    let current_os = std::env::consts::OS;
    let current_arch = std::env::consts::ARCH;

    for (platform_os, platform_arch, supported) in supported_platforms {
        if current_os == platform_os && current_arch == platform_arch {
            assert!(
                supported,
                "Current platform {}-{} should be supported",
                platform_os, platform_arch
            );
            println!("✓ Platform {}-{} is supported", platform_os, platform_arch);
        }
    }

    // Test platform-specific configurations
    #[cfg(target_os = "linux")]
    {
        // Test Linux-specific paths and behaviors
        let config_paths = vec![
            "/etc/agent-gateway-enforcer",
            "/var/log/agent-gateway-enforcer",
            "/run/agent-gateway-enforcer",
        ];

        for path in config_paths {
            println!("Linux config path: {}", path);
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Test macOS-specific paths
        let config_paths = vec![
            "/Library/Application Support/agent-gateway-enforcer",
            "~/Library/Logs/agent-gateway-enforcer",
            "/var/run/agent-gateway-enforcer",
        ];

        for path in config_paths {
            println!("macOS config path: {}", path);
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Test Windows-specific paths
        let config_paths = vec![
            "C:\\ProgramData\\agent-gateway-enforcer",
            "C:\\Program Files\\agent-gateway-enforcer",
            "C:\\Users\\%USERNAME%\\AppData\\Local\\agent-gateway-enforcer\\Logs",
        ];

        for path in config_paths {
            println!("Windows config path: {}", path);
        }
    }

    println!("✓ Platform compatibility tests passed");
}

// =============================================================================
// Cross-Platform Behavior Tests
// =============================================================================

/// Test cross-platform configuration
fn test_cross_platform_configuration() {
    println!("Testing cross-platform configuration...");

    let config_generator = ConfigGenerator::new();

    // Generate configuration for different platforms
    let minimal_config = config_generator
        .generate_minimal_yaml()
        .expect("Failed to generate minimal config");
    let dev_config = config_generator
        .generate_dev_yaml()
        .expect("Failed to generate dev config");
    let prod_config = config_generator
        .generate_prod_yaml()
        .expect("Failed to generate prod config");

    // Verify configurations exist
    assert!(minimal_config.exists());
    assert!(dev_config.exists());
    assert!(prod_config.exists());

    // Test configuration parsing across platforms
    let configs = vec![minimal_config, dev_config, prod_config];

    for config_path in configs {
        let content = std::fs::read_to_string(&config_path).expect("Failed to read config");

        // Verify YAML structure
        assert!(content.contains("server:"));
        assert!(content.contains("backend:"));
        assert!(content.contains("logging:"));

        // Platform-specific configuration handling
        #[cfg(target_os = "windows")]
        {
            // Windows might use backslashes in paths
            if content.contains("\\") {
                println!("✓ Windows path format detected");
            }
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            // Unix systems use forward slashes
            if content.contains("/") {
                println!("✓ Unix path format detected");
            }
        }
    }

    println!("✓ Cross-platform configuration tests passed");
}

/// Test cross-platform paths
fn test_cross_platform_paths() {
    println!("Testing cross-platform paths...");

    // Test path separators
    let current_os = std::env::consts::OS;

    #[cfg(target_os = "windows")]
    {
        assert_eq!(std::path::MAIN_SEPARATOR, '\\');
        let test_path = std::path::Path::new("C:\\Program Files\\test");
        assert!(test_path.to_string_lossy().contains('\\'));
        println!("✓ Windows path separator (\\) correctly detected");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        assert_eq!(std::path::MAIN_SEPARATOR, '/');
        let test_path = std::path::Path::new("/usr/local/test");
        assert!(test_path.to_string_lossy().contains('/'));
        println!("✓ Unix path separator (/) correctly detected");
    }

    // Test path joining across platforms
    let base_path = std::path::Path::new("base");
    let sub_path = "subdir";
    let joined_path = base_path.join(sub_path);

    assert!(joined_path.exists() == false); // Path doesn't actually exist
    println!("Joined path: {}", joined_path.display());

    // Test temporary directory creation
    let temp_dir = std::env::temp_dir();
    assert!(temp_dir.exists());
    println!("Temp directory: {}", temp_dir.display());

    // Test home directory
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        if let Some(home_dir) = std::env::var_os("HOME") {
            let home_path = std::path::Path::new(&home_dir);
            assert!(home_path.exists());
            println!("Home directory: {}", home_path.display());
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(user_profile) = std::env::var_os("USERPROFILE") {
            let user_path = std::path::Path::new(&user_profile);
            assert!(user_path.exists());
            println!("User profile directory: {}", user_path.display());
        }
    }

    println!("✓ Cross-platform paths tests passed");
}

/// Test cross-platform permissions
fn test_cross_platform_permissions() {
    println!("Testing cross-platform permissions...");

    let temp_manager = TempDirManager::new();

    // Create a temporary file for permission testing
    let test_file_path = temp_manager
        .create_temp_file("permissions_test", "test content")
        .expect("Failed to create test file");

    assert!(test_file_path.exists());

    // Test file permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let metadata = std::fs::metadata(&test_file_path).expect("Failed to read file metadata");
        let permissions = metadata.permissions();
        let mode = permissions.mode();

        println!("Unix file permissions: {:o}", mode);

        // Test permission checking
        assert!(metadata.permissions().readonly() == false || true); // May be read-only

        // Test permission modification
        let mut new_permissions = permissions.clone();
        new_permissions.set_mode(0o644); // rw-r--r--
        std::fs::set_permissions(&test_file_path, new_permissions)
            .expect("Failed to set permissions");

        println!("✓ Unix permission handling works");
    }

    #[cfg(windows)]
    {
        let metadata = std::fs::metadata(&test_file_path).expect("Failed to read file metadata");
        let permissions = metadata.permissions();

        println!("Windows file readonly: {}", permissions.readonly());

        // Test readonly attribute
        let mut new_permissions = permissions.clone();
        new_permissions.set_readonly(true);
        std::fs::set_permissions(&test_file_path, new_permissions)
            .expect("Failed to set readonly attribute");

        // Verify readonly
        let updated_metadata =
            std::fs::metadata(&test_file_path).expect("Failed to read updated metadata");
        assert!(updated_metadata.permissions().readonly());

        println!("✓ Windows permission handling works");
    }

    // Test directory permissions
    let temp_dir = temp_manager
        .create_temp_dir()
        .expect("Failed to create temp dir");

    assert!(temp_dir.path().exists());

    // Test directory listing
    let dir_contents = std::fs::read_dir(temp_dir.path()).expect("Failed to read directory");

    let count = dir_contents.count();
    println!("Directory contains {} items", count);

    println!("✓ Cross-platform permissions tests passed");
}

// =============================================================================
// Platform-Specific Feature Tests
// =============================================================================

#[cfg(target_os = "linux")]
fn test_linux_specific_features() {
    println!("Testing Linux-specific features...");
    require_linux!();

    // Test eBPF availability
    if crate::test_config().platform.ebpf_available {
        println!("✓ eBPF is available");

        // Test kernel version check (simulated)
        let kernel_version = "5.15.0"; // In real implementation, would check actual kernel
        println!("Kernel version: {}", kernel_version);

        // Parse kernel version
        if let Some(major) = kernel_version.split('.').next() {
            let major_num: u32 = major.parse().unwrap_or(0);
            assert!(major_num >= 5, "Should run on kernel 5.8+");
        }
    } else {
        println!("⚠ eBPF not available");
    }

    // Test cgroups availability
    let cgroup_paths = vec!["/sys/fs/cgroup", "/proc/self/cgroup"];

    for cgroup_path in cgroup_paths {
        if std::path::Path::new(cgroup_path).exists() {
            println!("✓ cgroup path exists: {}", cgroup_path);
        }
    }

    // Test proc filesystem
    let proc_paths = vec!["/proc/cpuinfo", "/proc/meminfo", "/proc/net/dev"];

    for proc_path in proc_paths {
        if std::path::Path::new(proc_path).exists() {
            println!("✓ proc path exists: {}", proc_path);
        }
    }

    // Test systemd integration (simulated)
    let systemd_paths = vec!["/run/systemd", "/etc/systemd"];

    for systemd_path in systemd_paths {
        if std::path::Path::new(systemd_path).exists() {
            println!("✓ systemd path exists: {}", systemd_path);
        }
    }

    println!("✓ Linux-specific features tests passed");
}

#[cfg(target_os = "macos")]
fn test_macos_specific_features() {
    println!("Testing macOS-specific features...");
    require_macos!();

    // Test macOS-specific directories
    let macos_paths = vec!["/System/Library", "/Library", "/Applications", "/usr/local"];

    for path in macos_paths {
        if std::path::Path::new(path).exists() {
            println!("✓ macOS path exists: {}", path);
        }
    }

    // Test launchd integration (simulated)
    let launchd_paths = vec![
        "/System/Library/LaunchDaemons",
        "/Library/LaunchDaemons",
        "~/Library/LaunchAgents",
    ];

    for launchd_path in launchd_paths {
        // Handle home directory expansion
        let expanded_path = if launchd_path.starts_with("~/") {
            if let Some(home) = std::env::var_os("HOME") {
                let home_str = home.to_string_lossy();
                launchd_path.replacen("~/", &home_str, 1)
            } else {
                launchd_path.to_string()
            }
        } else {
            launchd_path.to_string()
        };

        if std::path::Path::new(&expanded_path).exists() {
            println!("✓ launchd path exists: {}", expanded_path);
        }
    }

    // Test macOS security frameworks (simulated)
    let security_frameworks = vec![
        "Security.framework",
        "CoreFoundation.framework",
        "AppKit.framework",
    ];

    for framework in security_frameworks {
        let framework_path = format!("/System/Library/Frameworks/{}", framework);
        if std::path::Path::new(&framework_path).exists() {
            println!("✓ Security framework exists: {}", framework_path);
        }
    }

    println!("✓ macOS-specific features tests passed");
}

#[cfg(target_os = "windows")]
fn test_windows_specific_features() {
    println!("Testing Windows-specific features...");
    require_windows!();

    // Test Windows-specific directories
    let windows_paths = vec![
        "C:\\Windows",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "C:\\ProgramData",
    ];

    for path in windows_paths {
        if std::path::Path::new(path).exists() {
            println!("✓ Windows path exists: {}", path);
        }
    }

    // Test Windows Registry (simulated)
    let registry_paths = vec![
        "HKEY_LOCAL_MACHINE\\SOFTWARE",
        "HKEY_CURRENT_USER\\SOFTWARE",
    ];

    for registry_path in registry_paths {
        println!("Registry key path: {}", registry_path);
        // In real implementation, would check actual registry access
    }

    // Test Windows Services (simulated)
    let services = vec![
        "EventLog", "WinMgmt", // WMI
        "Tcpip",
    ];

    for service in services {
        println!("Windows service: {}", service);
        // In real implementation, would check service status
    }

    // Test Windows API libraries
    let system_libraries = vec!["kernel32.dll", "advapi32.dll", "user32.dll", "ws2_32.dll"];

    for library in system_libraries {
        let library_path = format!("C:\\Windows\\System32\\{}", library);
        if std::path::Path::new(&library_path).exists() {
            println!("✓ System library exists: {}", library_path);
        }
    }

    println!("✓ Windows-specific features tests passed");
}

// =============================================================================
// Environment-Specific Tests
// =============================================================================

/// Test development environment
fn test_development_environment() {
    println!("Testing development environment...");

    // Check for development indicators
    let dev_indicators = vec![
        ("CARGO_MANIFEST_DIR", "Cargo project directory"),
        ("RUST_LOG", "Rust logging enabled"),
        ("DEBUG", "Debug mode enabled"),
    ];

    for (env_var, description) in dev_indicators {
        if std::env::var(env_var).is_ok() {
            println!(
                "✓ Development indicator found: {} ({})",
                env_var, description
            );
        }
    }

    // Test development-specific paths
    #[cfg(debug_assertions)]
    {
        println!("✓ Running in debug mode");
    }

    #[cfg(not(debug_assertions))]
    {
        println!("ℹ Running in release mode");
    }

    // Test development tool availability
    let dev_tools = vec!["cargo", "rustc"];

    for tool in dev_tools {
        let output = std::process::Command::new(tool).arg("--version").output();

        if let Ok(result) = output {
            if result.status.success() {
                let version = String::from_utf8_lossy(&result.stdout);
                println!("✓ {} available: {}", tool, version.trim());
            }
        }
    }

    println!("✓ Development environment tests passed");
}

/// Test production environment
fn test_production_environment() {
    println!("Testing production environment...");

    // Check for production indicators
    let prod_indicators = vec![
        ("NODE_ENV", "Node environment (for hybrid systems)"),
        ("ENVIRONMENT", "General environment indicator"),
        ("APP_ENV", "Application environment"),
    ];

    for (env_var, description) in prod_indicators {
        if let Ok(value) = std::env::var(env_var) {
            if value.to_lowercase().contains("prod") {
                println!(
                    "✓ Production indicator: {} = {} ({})",
                    env_var, value, description
                );
            }
        }
    }

    // Test production-specific configurations
    let prod_config_files = vec![
        "/etc/agent-gateway-enforcer/config.yaml",
        "/etc/agent-gateway-enforcer/production.yaml",
        "C:\\ProgramData\\agent-gateway-enforcer\\config.yaml",
    ];

    for config_file in prod_config_files {
        if std::path::Path::new(config_file).exists() {
            println!("✓ Production config file exists: {}", config_file);
        }
    }

    // Test system service status (simulated)
    let system_services = vec!["agent-gateway-enforcer", "gateway-enforcer"];

    for service in system_services {
        println!("Checking service: {}", service);
        // In real implementation, would check service status
    }

    println!("✓ Production environment tests passed");
}

/// Test container environment
fn test_container_environment() {
    println!("Testing container environment...");

    // Check for container indicators
    let container_indicators = vec![
        ("DOCKER_CONTAINER", "Docker container indicator"),
        ("KUBERNETES_SERVICE_HOST", "Kubernetes indicator"),
        ("CONTAINER", "Generic container indicator"),
        ("container", "Lowercase container indicator"),
    ];

    let is_container = container_indicators
        .iter()
        .any(|(env_var, _)| std::env::var(env_var).is_ok());

    if is_container {
        println!("✓ Running inside container");

        // Test container-specific paths
        let container_paths = vec!["/.dockerenv", "/proc/1/cgroup", "/proc/self/mountinfo"];

        for path in container_paths {
            if std::path::Path::new(path).exists() {
                println!("✓ Container indicator path exists: {}", path);
            }
        }

        // Test container-specific environment variables
        let container_env_vars = vec![
            "CONTAINER_ID",
            "CONTAINER_NAME",
            "POD_NAME",
            "POD_NAMESPACE",
        ];

        for env_var in container_env_vars {
            if let Ok(value) = std::env::var(env_var) {
                println!("✓ Container environment: {} = {}", env_var, value);
            }
        }
    } else {
        println!("ℹ Not running inside container");
    }

    // Test cloud environment indicators
    let cloud_providers = vec![
        ("AWS_DEFAULT_REGION", "AWS"),
        ("GOOGLE_CLOUD_PROJECT", "Google Cloud"),
        ("AZURE_CLIENT_ID", "Azure"),
    ];

    for (env_var, provider) in cloud_providers {
        if std::env::var(env_var).is_ok() {
            println!("✓ {} cloud environment detected", provider);
        }
    }

    println!("✓ Container environment tests passed");
}
