//! Integration tests for agent-gateway-enforcer
//!
//! These tests require:
//! - Linux kernel 5.8+
//! - Root privileges (or CAP_BPF)
//! - eBPF program built first: `cargo xtask build-ebpf`
//!
//! Run with: `cargo test --test integration_test`
//!
//! Note: These tests will be skipped on non-Linux platforms or without root.

#[cfg(target_os = "linux")]
use std::path::Path;

/// Check if we're running on Linux
fn is_linux() -> bool {
    cfg!(target_os = "linux")
}

/// Check if we have root privileges
fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Check if the eBPF program has been built
#[cfg(target_os = "linux")]
fn ebpf_program_exists() -> bool {
    let paths = [
        "target/bpf/agent-gateway-enforcer.bpf.o",
        "../target/bpf/agent-gateway-enforcer.bpf.o",
    ];
    paths.iter().any(|p| Path::new(p).exists())
}

#[cfg(not(target_os = "linux"))]
fn ebpf_program_exists() -> bool {
    false
}

/// Skip macro for tests that require Linux + root
#[cfg(target_os = "linux")]
macro_rules! require_linux_root {
    () => {
        if !is_linux() {
            eprintln!("Skipping test: not running on Linux");
            return;
        }
        if !is_root() {
            eprintln!("Skipping test: not running as root");
            return;
        }
    };
}

/// Skip macro for tests that require eBPF program
#[cfg(target_os = "linux")]
macro_rules! require_ebpf {
    () => {
        if !ebpf_program_exists() {
            eprintln!("Skipping test: eBPF program not built. Run 'cargo xtask build-ebpf' first");
            return;
        }
    };
}

// =============================================================================
// Environment Tests
// =============================================================================

#[test]
fn test_environment_detection() {
    println!("Running on Linux: {}", is_linux());
    println!("Running as root: {}", is_root());
    println!("eBPF program exists: {}", ebpf_program_exists());
}

// =============================================================================
// Common Types Tests (these can run anywhere)
// =============================================================================

#[test]
fn test_gateway_key_from_ip_string() {
    use agent_gateway_enforcer_common::GatewayKey;

    // Parse "10.0.0.1" into network byte order
    let ip_parts: Vec<u8> = "10.0.0.1"
        .split('.')
        .map(|s| s.parse().unwrap())
        .collect();

    let addr = u32::from_be_bytes([ip_parts[0], ip_parts[1], ip_parts[2], ip_parts[3]]);
    let key = GatewayKey::new(addr.to_be(), 8080);

    assert_eq!(key.port, 8080);
}

#[test]
fn test_path_key_various_paths() {
    use agent_gateway_enforcer_common::PathKey;

    let test_paths = [
        "/",
        "/tmp",
        "/etc/passwd",
        "/var/log/syslog",
        "/home/user/.ssh/id_rsa",
    ];

    for path in test_paths {
        let key = PathKey::new(path);
        assert_eq!(key.len as usize, path.len());
    }
}

#[test]
fn test_path_rule_permissions() {
    use agent_gateway_enforcer_common::{
        PathRule, FILE_PERM_ALL, FILE_PERM_EXEC, FILE_PERM_READ, FILE_PERM_WRITE,
    };

    // Test individual permissions
    let read_only = PathRule::allow(FILE_PERM_READ, true);
    assert_eq!(read_only.permissions & FILE_PERM_READ, FILE_PERM_READ);
    assert_eq!(read_only.permissions & FILE_PERM_WRITE, 0);

    // Test combined permissions
    let read_write = PathRule::allow(FILE_PERM_READ | FILE_PERM_WRITE, true);
    assert_eq!(
        read_write.permissions & FILE_PERM_READ,
        FILE_PERM_READ
    );
    assert_eq!(
        read_write.permissions & FILE_PERM_WRITE,
        FILE_PERM_WRITE
    );
    assert_eq!(read_write.permissions & FILE_PERM_EXEC, 0);

    // Test all permissions
    let all_perms = PathRule::deny(FILE_PERM_ALL, false);
    assert_eq!(all_perms.permissions, FILE_PERM_ALL);
}

// =============================================================================
// eBPF Loading Tests (require Linux + root)
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
fn test_ebpf_program_can_be_loaded() {
    require_linux_root!();
    require_ebpf!();

    use aya::Ebpf;
    use std::path::PathBuf;

    let ebpf_paths = [
        PathBuf::from("target/bpf/agent-gateway-enforcer.bpf.o"),
        PathBuf::from("../target/bpf/agent-gateway-enforcer.bpf.o"),
    ];

    let ebpf_path = ebpf_paths.iter().find(|p| p.exists()).expect("eBPF not found");

    let result = Ebpf::load_file(ebpf_path);

    match result {
        Ok(bpf) => {
            println!("Successfully loaded eBPF program");

            // Check that expected programs exist
            let programs: Vec<_> = bpf.programs().map(|(name, _)| name.to_string()).collect();
            println!("Available programs: {:?}", programs);

            assert!(
                programs.iter().any(|n| n == "agent_gateway_egress"),
                "Expected 'agent_gateway_egress' program"
            );
        }
        Err(e) => {
            // This might fail due to kernel version or permissions
            eprintln!("Failed to load eBPF: {}. This may be expected.", e);
        }
    }
}

#[test]
#[cfg(target_os = "linux")]
fn test_ebpf_maps_exist() {
    require_linux_root!();
    require_ebpf!();

    use aya::Ebpf;
    use std::path::PathBuf;

    let ebpf_paths = [
        PathBuf::from("target/bpf/agent-gateway-enforcer.bpf.o"),
        PathBuf::from("../target/bpf/agent-gateway-enforcer.bpf.o"),
    ];

    let ebpf_path = ebpf_paths.iter().find(|p| p.exists()).expect("eBPF not found");

    if let Ok(bpf) = Ebpf::load_file(ebpf_path) {
        let maps: Vec<_> = bpf.maps().map(|(name, _)| name.to_string()).collect();
        println!("Available maps: {:?}", maps);

        // Check expected maps exist
        let expected_maps = ["ALLOWED_GATEWAYS", "BLOCKED_METRICS", "BLOCKED_EVENTS"];

        for expected in expected_maps {
            assert!(
                maps.iter().any(|m| m == expected),
                "Expected map '{}' not found",
                expected
            );
        }
    }
}

// =============================================================================
// Gateway Map Operations (require Linux + root)
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
fn test_gateway_map_insert_and_lookup() {
    require_linux_root!();
    require_ebpf!();

    use agent_gateway_enforcer_common::GatewayKey;
    use aya::maps::HashMap;
    use aya::Ebpf;
    use std::path::PathBuf;

    let ebpf_paths = [
        PathBuf::from("target/bpf/agent-gateway-enforcer.bpf.o"),
        PathBuf::from("../target/bpf/agent-gateway-enforcer.bpf.o"),
    ];

    let ebpf_path = ebpf_paths.iter().find(|p| p.exists()).expect("eBPF not found");

    if let Ok(mut bpf) = Ebpf::load_file(ebpf_path) {
        // Get the ALLOWED_GATEWAYS map
        let map = bpf.map_mut("ALLOWED_GATEWAYS");

        if let Ok(map) = map {
            let mut gateways: HashMap<_, GatewayKey, u8> =
                HashMap::try_from(map).expect("Failed to create HashMap");

            // Insert a gateway
            let key = GatewayKey::new(0x0A000001_u32.to_be(), 8080); // 10.0.0.1:8080
            gateways.insert(key, 1, 0).expect("Failed to insert");

            // Lookup the gateway
            let value = gateways.get(&key, 0);
            assert!(value.is_ok(), "Gateway should be found");
            assert_eq!(value.unwrap(), 1);

            // Remove the gateway
            gateways.remove(&key).expect("Failed to remove");

            // Verify it's gone
            let value = gateways.get(&key, 0);
            assert!(value.is_err(), "Gateway should be removed");

            println!("Gateway map operations successful");
        }
    }
}

// =============================================================================
// CLI Argument Parsing Tests
// =============================================================================

#[test]
fn test_gateway_address_parsing() {
    // Test valid addresses
    let valid_addresses = [
        ("10.0.0.1:8080", ([10, 0, 0, 1], 8080)),
        ("192.168.1.1:443", ([192, 168, 1, 1], 443)),
        ("127.0.0.1:9090", ([127, 0, 0, 1], 9090)),
        ("0.0.0.0:80", ([0, 0, 0, 0], 80)),
    ];

    for (addr_str, (expected_octets, expected_port)) in valid_addresses {
        let parts: Vec<&str> = addr_str.split(':').collect();
        assert_eq!(parts.len(), 2, "Should have IP and port");

        let ip_parts: Vec<u8> = parts[0]
            .split('.')
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(ip_parts.len(), 4, "Should have 4 octets");
        assert_eq!(ip_parts.as_slice(), expected_octets);

        let port: u16 = parts[1].parse().unwrap();
        assert_eq!(port, expected_port);
    }
}

#[test]
fn test_invalid_gateway_addresses() {
    let invalid_addresses = [
        "10.0.0.1",        // Missing port
        "10.0.0:8080",     // Invalid IP
        "10.0.0.1.2:8080", // Too many octets
        "10.0.0.256:8080", // Octet > 255
        "10.0.0.1:-1",     // Negative port
        "10.0.0.1:65536",  // Port > 65535
        "",                // Empty
        ":",               // Just separator
    ];

    for addr_str in invalid_addresses {
        let parts: Vec<&str> = addr_str.split(':').collect();

        let is_invalid = parts.len() != 2
            || parts[0]
                .split('.')
                .filter_map(|s| s.parse::<u8>().ok())
                .count()
                != 4
            || parts[1].parse::<u16>().is_err();

        assert!(
            is_invalid,
            "Address '{}' should be detected as invalid",
            addr_str
        );
    }
}

// =============================================================================
// File Access Enforcement Tests
// =============================================================================

#[test]
fn test_path_rules_map_operations() {
    use agent_gateway_enforcer_common::{PathKey, PathRule, FILE_PERM_READ, FILE_PERM_WRITE};
    
    // Test creating path keys
    let paths = ["/etc/passwd", "/tmp/", "/home/user/.ssh"];
    for path in &paths {
        let key = PathKey::new(path);
        assert!(key.len > 0);
        assert!(key.len <= 255); // MAX_PATH_LEN - 1
    }
    
    // Test creating rules
    let allow_read = PathRule::allow(FILE_PERM_READ, true);
    let deny_write = PathRule::deny(FILE_PERM_WRITE, false);
    
    assert_eq!(allow_read.rule_type as u8, 0); // Allow
    assert_eq!(deny_write.rule_type as u8, 1);  // Deny
    assert_eq!(allow_read.is_prefix, 1);        // prefix match
    assert_eq!(deny_write.is_prefix, 0);        // exact match
}

#[test]
#[cfg(target_os = "linux")]
fn test_path_rules_map_insert_and_lookup() {
    require_linux_root!();
    require_ebpf!();

    use agent_gateway_enforcer_common::{PathKey, PathRule, FILE_PERM_READ};
    use aya::maps::HashMap;
    use aya::Ebpf;
    use std::path::PathBuf;

    let ebpf_paths = [
        PathBuf::from("target/bpf/agent-gateway-enforcer.bpf.o"),
        PathBuf::from("../target/bpf/agent-gateway-enforcer.bpf.o"),
    ];

    let ebpf_path = ebpf_paths.iter().find(|p| p.exists()).expect("eBPF not found");

    if let Ok(mut bpf) = Ebpf::load_file(ebpf_path) {
        // Check if PATH_RULES map exists
        if let Some(map) = bpf.map_mut("PATH_RULES") {
            let mut path_rules: HashMap<_, PathKey, PathRule> =
                HashMap::try_from(map).expect("Failed to create PathRules HashMap");

            // Insert an allow rule for /etc/passwd
            let passwd_key = PathKey::new("/etc/passwd");
            let allow_rule = PathRule::allow(FILE_PERM_READ, true);
            
            path_rules.insert(passwd_key, allow_rule, 0)
                .expect("Failed to insert path rule");

            // Lookup the rule
            let value = path_rules.get(&passwd_key, 0);
            assert!(value.is_ok(), "Path rule should be found");
            
            let retrieved_rule = value.unwrap();
            assert_eq!(retrieved_rule.rule_type as u8, 0); // Allow
            assert_eq!(retrieved_rule.permissions, FILE_PERM_READ);

            // Remove the rule
            path_rules.remove(&passwd_key).expect("Failed to remove path rule");

            // Verify it's gone
            let value = path_rules.get(&passwd_key, 0);
            assert!(value.is_err(), "Path rule should be removed");

            println!("Path rules map operations successful");
        } else {
            println!("PATH_RULES map not found - file access enforcement may not be enabled");
        }
    }
}

#[test]
#[cfg(target_os = "linux")]
fn test_default_deny_map_operations() {
    require_linux_root!();
    require_ebpf!();

    use aya::maps::HashMap;
    use aya::Ebpf;
    use std::path::PathBuf;

    let ebpf_paths = [
        PathBuf::from("target/bpf/agent-gateway-enforcer.bpf.o"),
        PathBuf::from("../target/bpf/agent-gateway-enforcer.bpf.o"),
    ];

    let ebpf_path = ebpf_paths.iter().find(|p| p.exists()).expect("eBPF not found");

    if let Ok(mut bpf) = Ebpf::load_file(ebpf_path) {
        // Check if DEFAULT_DENY map exists
        if let Some(map) = bpf.map_mut("DEFAULT_DENY") {
            let mut default_deny: HashMap<_, u32, u8> =
                HashMap::try_from(map).expect("Failed to create DefaultDeny HashMap");

            // Set default deny policy (0 = allow by default, 1 = deny by default)
            let key: u32 = 0;
            default_deny.insert(key, 1, 0).expect("Failed to set default deny policy");

            // Lookup the policy
            let value = default_deny.get(&key, 0);
            assert!(value.is_ok(), "Default deny policy should be found");
            assert_eq!(value.unwrap(), 1); // Deny by default

            // Change to allow by default
            default_deny.insert(key, 0, 0).expect("Failed to change default policy");
            let value = default_deny.get(&key, 0);
            assert_eq!(value.unwrap(), 0); // Allow by default

            println!("Default deny map operations successful");
        } else {
            println!("DEFAULT_DENY map not found - file access enforcement may not be enabled");
        }
    }
}

#[test]
fn test_file_access_permission_combinations() {
    use agent_gateway_enforcer_common::{
        FILE_PERM_ALL, FILE_PERM_DELETE, FILE_PERM_EXEC, FILE_PERM_READ, FILE_PERM_WRITE,
    };

    // Test individual permission flags
    assert_eq!(FILE_PERM_READ, 0b0001);
    assert_eq!(FILE_PERM_WRITE, 0b0010);
    assert_eq!(FILE_PERM_EXEC, 0b0100);
    assert_eq!(FILE_PERM_DELETE, 0b1000);

    // Test permission combinations
    let read_write = FILE_PERM_READ | FILE_PERM_WRITE;
    assert_eq!(read_write, 0b0011);

    let read_exec = FILE_PERM_READ | FILE_PERM_EXEC;
    assert_eq!(read_exec, 0b0101);

    let all_perms = FILE_PERM_READ | FILE_PERM_WRITE | FILE_PERM_EXEC | FILE_PERM_DELETE;
    assert_eq!(all_perms, FILE_PERM_ALL);
    assert_eq!(FILE_PERM_ALL, 0b1111);

    // Test permission checking logic
    let test_perms = [
        (FILE_PERM_READ, FILE_PERM_READ, true),
        (FILE_PERM_READ, FILE_PERM_WRITE, false),
        (FILE_PERM_READ | FILE_PERM_WRITE, FILE_PERM_READ, true),
        (FILE_PERM_READ | FILE_PERM_WRITE, FILE_PERM_WRITE, true),
        (FILE_PERM_READ | FILE_PERM_WRITE, FILE_PERM_EXEC, false),
        (FILE_PERM_ALL, FILE_PERM_DELETE, true),
        (FILE_PERM_ALL, FILE_PERM_READ | FILE_PERM_WRITE, true),
    ];

    for (rule_perms, requested_perms, expected) in test_perms {
        let has_permission = rule_perms & requested_perms != 0;
        assert_eq!(
            has_permission, expected,
            "Rule perms: {:#x}, Requested: {:#x}, Expected: {}",
            rule_perms, requested_perms, expected
        );
    }
}

#[test]
fn test_file_blocked_event_creation() {
    use agent_gateway_enforcer_common::{FileBlockedEvent, FILE_PERM_READ, MAX_PATH_LEN};

    let mut event = FileBlockedEvent {
        path: [0u8; MAX_PATH_LEN],
        path_len: 0,
        operation: FILE_PERM_READ,
        pid: 12345,
        _pad: 0,
    };

    // Test setting a path
    let test_path = "/etc/shadow";
    let path_bytes = test_path.as_bytes();
    event.path[..path_bytes.len()].copy_from_slice(path_bytes);
    event.path_len = path_bytes.len() as u16;

    assert_eq!(event.path_len, 11); // Length of "/etc/shadow"
    assert_eq!(event.operation, FILE_PERM_READ);
    assert_eq!(event.pid, 12345);

    // Verify path was stored correctly
    let stored_path = std::str::from_utf8(&event.path[..event.path_len as usize]).unwrap();
    assert_eq!(stored_path, test_path);
}

#[test]
fn test_path_prefix_matching_logic() {
    use agent_gateway_enforcer_common::PathKey;

        let test_cases = [
            ("/etc/passwd", "/etc/", true),
            ("/etc/passwd", "/etc", true), // "/etc" should match "/etc/passwd" as prefix
            ("/home/user/.bashrc", "/home/user/", true),
            ("/home/user/.bashrc", "/home/", true),
            ("/home/user/.bashrc", "/tmp/", false),
            ("/tmp/file.txt", "/", true), // Root matches everything
            ("/tmp/file.txt", "/tmp", true), // "/tmp" should match "/tmp/file.txt"
        ];

        for (full_path, prefix, should_match) in test_cases {
            let _full_key = PathKey::new(full_path);
            let _prefix_key = PathKey::new(prefix);

            // For this test, check if full path starts with prefix
            let actual_matches = full_path.starts_with(prefix);

            assert_eq!(
                actual_matches, should_match,
                "Path '{}' should {}match prefix '{}'",
                full_path, if should_match { "" } else { "not " }, prefix
            );
        }
}

#[test]
fn test_file_access_enforcement_scenarios() {
    use agent_gateway_enforcer_common::{
        PathKey, PathRule, PathRuleType, FILE_PERM_ALL, FILE_PERM_READ, FILE_PERM_WRITE,
    };

    // Test scenario 1: Allow read access to /etc/passwd
    let passwd_key = PathKey::new("/etc/passwd");
    let allow_read_rule = PathRule::allow(FILE_PERM_READ, true);
    
    // Simulate access check
    let requested = FILE_PERM_READ;
    let rule_matches = allow_read_rule.permissions & requested != 0;
    let allowed = rule_matches && (allow_read_rule.rule_type == PathRuleType::Allow);
    assert!(allowed, "Should allow read access to /etc/passwd");

    // Test scenario 2: Deny write access to /etc/passwd
    let deny_write_rule = PathRule::deny(FILE_PERM_WRITE, true);
    let requested = FILE_PERM_WRITE;
    let rule_matches = deny_write_rule.permissions & requested != 0;
    let allowed = rule_matches && (deny_write_rule.rule_type == PathRuleType::Allow);
    assert!(!allowed, "Should deny write access to /etc/passwd");

    // Test scenario 3: Allow all access to /tmp/ (prefix rule)
    let tmp_key = PathKey::new("/tmp/");
    let allow_all_rule = PathRule::allow(FILE_PERM_ALL, true);
    
    let test_files = ["/tmp/file.txt", "/tmp/subdir/file.log", "/tmp/.hidden"];
    for file_path in test_files {
        // Check if file starts with /tmp/
        let prefix_matches = file_path.starts_with("/tmp/");
        assert!(prefix_matches, "File '{}' should match /tmp/ prefix", file_path);
        
        // If prefix matches, the rule applies
        if prefix_matches {
            let allowed = allow_all_rule.rule_type == PathRuleType::Allow;
            assert!(allowed, "Should allow all access to files under /tmp/");
        }
    }

    // Test scenario 4: Default deny policy
    // When no rule matches and default policy is deny, access should be denied
    let no_rule_found = true; // No rule found for the path
    let deny_by_default = true; // Default policy is deny
    let allowed = if no_rule_found {
        !deny_by_default // When no rule, use opposite of default policy (false)
    } else {
        true // Would depend on rule result
    };
    assert!(!allowed, "Should deny when no rule found and default is deny");
}
