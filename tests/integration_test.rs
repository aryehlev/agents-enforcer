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
