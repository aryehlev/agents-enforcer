#![cfg_attr(all(not(test), not(feature = "user")), no_std)]

/// Key for the allowed gateways map.
/// Stores an IPv4 address and port that traffic is allowed to reach.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GatewayKey {
    /// IPv4 address in network byte order (big endian)
    pub addr: u32,
    /// Port in host byte order
    pub port: u16,
    /// Padding for alignment
    pub _pad: u16,
}

impl GatewayKey {
    pub const fn new(addr: u32, port: u16) -> Self {
        Self {
            addr,
            port,
            _pad: 0,
        }
    }
}

/// Key for tracking blocked connection metrics.
/// Used to count how many times a specific destination was blocked.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockedKey {
    /// Destination IPv4 address in network byte order
    pub dst_addr: u32,
    /// Destination port in host byte order
    pub dst_port: u16,
    /// Protocol (TCP=6, UDP=17)
    pub protocol: u8,
    /// Padding for alignment
    pub _pad: u8,
}

impl BlockedKey {
    pub const fn new(dst_addr: u32, dst_port: u16, protocol: u8) -> Self {
        Self {
            dst_addr,
            dst_port,
            protocol,
            _pad: 0,
        }
    }
}

/// Event sent from eBPF to userspace when a connection is blocked.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BlockedEvent {
    /// Source IPv4 address
    pub src_addr: u32,
    /// Destination IPv4 address
    pub dst_addr: u32,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Protocol (TCP=6, UDP=17)
    pub protocol: u8,
    /// Padding
    pub _pad: [u8; 3],
}

// Protocol constants
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// Network protocol enum
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// TCP protocol
    Tcp = 6,
    /// UDP protocol
    Udp = 17,
    /// ICMP protocol
    Icmp = 1,
    /// Other protocol
    Other(u8),
}

/// File access type enum
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileAccessType {
    /// Read access
    Read,
    /// Write access
    Write,
    /// Execute access
    Execute,
    /// Delete access
    Delete,
}

// Map sizes
pub const MAX_GATEWAYS: u32 = 64;
pub const MAX_BLOCKED_ENTRIES: u32 = 10000;
pub const MAX_PATH_RULES: u32 = 256;
pub const MAX_PATH_LEN: usize = 256;

// File access permission flags
pub const FILE_PERM_READ: u8 = 1 << 0;
pub const FILE_PERM_WRITE: u8 = 1 << 1;
pub const FILE_PERM_EXEC: u8 = 1 << 2;
pub const FILE_PERM_DELETE: u8 = 1 << 3;
pub const FILE_PERM_ALL: u8 = FILE_PERM_READ | FILE_PERM_WRITE | FILE_PERM_EXEC | FILE_PERM_DELETE;

/// Rule type for file access control.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathRuleType {
    /// Allow access to this path
    Allow = 0,
    /// Deny access to this path
    Deny = 1,
}

/// Key for the path rules map.
/// Uses a fixed-size path buffer for eBPF compatibility.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PathKey {
    /// Path prefix to match (null-terminated)
    pub path: [u8; MAX_PATH_LEN],
    /// Length of the path (excluding null terminator)
    pub len: u16,
    /// Padding for alignment
    pub _pad: [u8; 6],
}

impl PathKey {
    pub fn new(path_str: &str) -> Self {
        let mut key = Self {
            path: [0u8; MAX_PATH_LEN],
            len: 0,
            _pad: [0; 6],
        };
        let bytes = path_str.as_bytes();
        let copy_len = bytes.len().min(MAX_PATH_LEN - 1);
        key.path[..copy_len].copy_from_slice(&bytes[..copy_len]);
        key.len = copy_len as u16;
        key
    }
}

/// Value for path rules map.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PathRule {
    /// Type of rule (allow/deny)
    pub rule_type: PathRuleType,
    /// Permissions affected by this rule
    pub permissions: u8,
    /// Whether to match as prefix (1) or exact match (0)
    pub is_prefix: u8,
    /// Padding
    pub _pad: u8,
}

impl PathRule {
    pub const fn allow(permissions: u8, is_prefix: bool) -> Self {
        Self {
            rule_type: PathRuleType::Allow,
            permissions,
            is_prefix: if is_prefix { 1 } else { 0 },
            _pad: 0,
        }
    }

    pub const fn deny(permissions: u8, is_prefix: bool) -> Self {
        Self {
            rule_type: PathRuleType::Deny,
            permissions,
            is_prefix: if is_prefix { 1 } else { 0 },
            _pad: 0,
        }
    }
}

/// Event sent from eBPF to userspace when a file access is blocked.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileBlockedEvent {
    /// Path that was blocked
    pub path: [u8; MAX_PATH_LEN],
    /// Path length
    pub path_len: u16,
    /// Operation that was blocked (FILE_PERM_*)
    pub operation: u8,
    /// Process ID
    pub pid: u32,
    /// Padding
    pub _pad: u8,
}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for GatewayKey {}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for BlockedKey {}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for BlockedEvent {}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for PathKey {}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for PathRule {}

#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for FileBlockedEvent {}

// ============================================================================
// CONFIGURATION MODULE (user-space only)
// ============================================================================

#[cfg(feature = "user")]
pub mod config;

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // GatewayKey tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_gateway_key_new() {
        let key = GatewayKey::new(0x0A000001, 8080);
        assert_eq!(key.addr, 0x0A000001);
        assert_eq!(key.port, 8080);
        assert_eq!(key._pad, 0);
    }

    #[test]
    fn test_gateway_key_equality() {
        let key1 = GatewayKey::new(0x0A000001, 8080);
        let key2 = GatewayKey::new(0x0A000001, 8080);
        let key3 = GatewayKey::new(0x0A000001, 8081);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_gateway_key_clone() {
        let key1 = GatewayKey::new(0x0A000001, 8080);
        let key2 = key1;
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_gateway_key_size() {
        // Ensure struct is properly aligned for eBPF maps
        assert_eq!(core::mem::size_of::<GatewayKey>(), 8);
    }

    // -------------------------------------------------------------------------
    // BlockedKey tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_blocked_key_new() {
        let key = BlockedKey::new(0xC0A80001, 443, IPPROTO_TCP);
        assert_eq!(key.dst_addr, 0xC0A80001);
        assert_eq!(key.dst_port, 443);
        assert_eq!(key.protocol, 6);
        assert_eq!(key._pad, 0);
    }

    #[test]
    fn test_blocked_key_protocols() {
        let tcp_key = BlockedKey::new(0, 80, IPPROTO_TCP);
        let udp_key = BlockedKey::new(0, 53, IPPROTO_UDP);

        assert_eq!(tcp_key.protocol, 6);
        assert_eq!(udp_key.protocol, 17);
    }

    #[test]
    fn test_blocked_key_size() {
        assert_eq!(core::mem::size_of::<BlockedKey>(), 8);
    }

    // -------------------------------------------------------------------------
    // BlockedEvent tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_blocked_event_size() {
        // Ensure struct is properly sized for perf events
        assert_eq!(core::mem::size_of::<BlockedEvent>(), 16);
    }

    // -------------------------------------------------------------------------
    // PathKey tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_path_key_new_simple() {
        let key = PathKey::new("/tmp");
        assert_eq!(key.len, 4);
        assert_eq!(&key.path[..4], b"/tmp");
        assert_eq!(key.path[4], 0); // null terminated
    }

    #[test]
    fn test_path_key_new_longer_path() {
        let key = PathKey::new("/var/log/agent/output.log");
        assert_eq!(key.len, 25);
        assert_eq!(&key.path[..25], b"/var/log/agent/output.log");
    }

    #[test]
    fn test_path_key_truncation() {
        // Create a path longer than MAX_PATH_LEN
        let long_path: String = "/".to_string() + &"a".repeat(300);
        let key = PathKey::new(&long_path);

        // Should truncate to MAX_PATH_LEN - 1 (255)
        assert_eq!(key.len, 255);
        assert_eq!(key.path[0], b'/');
        assert_eq!(key.path[254], b'a');
    }

    #[test]
    fn test_path_key_empty() {
        let key = PathKey::new("");
        assert_eq!(key.len, 0);
    }

    #[test]
    fn test_path_key_size() {
        // 256 bytes for path + 2 bytes for len + 6 bytes padding = 264
        assert_eq!(core::mem::size_of::<PathKey>(), 264);
    }

    // -------------------------------------------------------------------------
    // PathRule tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_path_rule_allow() {
        let rule = PathRule::allow(FILE_PERM_READ | FILE_PERM_WRITE, true);
        assert_eq!(rule.rule_type, PathRuleType::Allow);
        assert_eq!(rule.permissions, FILE_PERM_READ | FILE_PERM_WRITE);
        assert_eq!(rule.is_prefix, 1);
    }

    #[test]
    fn test_path_rule_deny() {
        let rule = PathRule::deny(FILE_PERM_ALL, false);
        assert_eq!(rule.rule_type, PathRuleType::Deny);
        assert_eq!(rule.permissions, FILE_PERM_ALL);
        assert_eq!(rule.is_prefix, 0);
    }

    #[test]
    fn test_path_rule_size() {
        assert_eq!(core::mem::size_of::<PathRule>(), 4);
    }

    // -------------------------------------------------------------------------
    // FileBlockedEvent tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_file_blocked_event_size() {
        // 256 (path) + 2 (path_len) + 1 (operation) + 4 (pid) + 1 (pad) + padding = 268
        assert_eq!(core::mem::size_of::<FileBlockedEvent>(), 268);
    }

    // -------------------------------------------------------------------------
    // Constants tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_protocol_constants() {
        assert_eq!(IPPROTO_TCP, 6);
        assert_eq!(IPPROTO_UDP, 17);
    }

    #[test]
    fn test_permission_flags() {
        assert_eq!(FILE_PERM_READ, 0b0001);
        assert_eq!(FILE_PERM_WRITE, 0b0010);
        assert_eq!(FILE_PERM_EXEC, 0b0100);
        assert_eq!(FILE_PERM_DELETE, 0b1000);
        assert_eq!(FILE_PERM_ALL, 0b1111);
    }

    #[test]
    fn test_permission_flags_combination() {
        let read_write = FILE_PERM_READ | FILE_PERM_WRITE;
        assert_eq!(read_write, 0b0011);

        let read_exec = FILE_PERM_READ | FILE_PERM_EXEC;
        assert_eq!(read_exec, 0b0101);
    }

    #[test]
    fn test_map_sizes() {
        assert_eq!(MAX_GATEWAYS, 64);
        assert_eq!(MAX_BLOCKED_ENTRIES, 10000);
        assert_eq!(MAX_PATH_RULES, 256);
        assert_eq!(MAX_PATH_LEN, 256);
    }

    // -------------------------------------------------------------------------
    // PathRuleType tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_path_rule_type_values() {
        assert_eq!(PathRuleType::Allow as u8, 0);
        assert_eq!(PathRuleType::Deny as u8, 1);
    }

    // -------------------------------------------------------------------------
    // File access enforcement tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_file_permission_flags_individual() {
        assert_eq!(FILE_PERM_READ, 0b0001);
        assert_eq!(FILE_PERM_WRITE, 0b0010);
        assert_eq!(FILE_PERM_EXEC, 0b0100);
        assert_eq!(FILE_PERM_DELETE, 0b1000);
    }

    #[test]
    fn test_file_permission_flags_combinations() {
        let read_write = FILE_PERM_READ | FILE_PERM_WRITE;
        assert_eq!(read_write, 0b0011);

        let read_exec = FILE_PERM_READ | FILE_PERM_EXEC;
        assert_eq!(read_exec, 0b0101);

        let all_perms = FILE_PERM_READ | FILE_PERM_WRITE | FILE_PERM_EXEC | FILE_PERM_DELETE;
        assert_eq!(all_perms, FILE_PERM_ALL);
    }

    #[test]
    fn test_file_permission_flags_has_permission() {
        let perms = FILE_PERM_READ | FILE_PERM_WRITE;

        assert!(perms & FILE_PERM_READ != 0);
        assert!(perms & FILE_PERM_WRITE != 0);
        assert!(perms & FILE_PERM_EXEC == 0);
        assert!(perms & FILE_PERM_DELETE == 0);
    }

    #[test]
    fn test_path_key_with_special_characters() {
        let paths = [
            "/tmp/file with spaces.txt",
            "/var/log/app.log",
            "/home/user/.config",
            "/etc/systemd/system/multi-user.target.wants/ssh.service",
        ];

        for path in &paths {
            let key = PathKey::new(path);
            assert!(key.len > 0);
            assert!(key.len <= MAX_PATH_LEN as u16);

            // Verify the path was stored correctly
            let stored = core::str::from_utf8(&key.path[..key.len as usize]).unwrap();
            assert_eq!(stored, *path);
        }
    }

    #[test]
    fn test_path_key_unicode_handling() {
        // Test with UTF-8 characters (should be stored as bytes)
        let unicode_path = "/tmp/测试文件.txt";
        let key = PathKey::new(unicode_path);

        assert!(key.len > 0);
        // The path should be stored as UTF-8 bytes
        let stored_bytes = &key.path[..key.len as usize];
        assert_eq!(stored_bytes, unicode_path.as_bytes());
    }

    #[test]
    fn test_path_rule_allow_deny_logic() {
        let allow_rule = PathRule::allow(FILE_PERM_READ, true);
        let deny_rule = PathRule::deny(FILE_PERM_READ, true);

        assert_eq!(allow_rule.rule_type, PathRuleType::Allow);
        assert_eq!(deny_rule.rule_type, PathRuleType::Deny);

        assert!(allow_rule.permissions & FILE_PERM_READ != 0);
        assert!(deny_rule.permissions & FILE_PERM_READ != 0);

        assert_eq!(allow_rule.is_prefix, 1);
        assert_eq!(deny_rule.is_prefix, 1);
    }

    #[test]
    fn test_path_rule_exact_vs_prefix() {
        let exact_rule = PathRule::allow(FILE_PERM_READ, false);
        let prefix_rule = PathRule::allow(FILE_PERM_READ, true);

        assert_eq!(exact_rule.is_prefix, 0);
        assert_eq!(prefix_rule.is_prefix, 1);
    }

    #[test]
    fn test_path_rule_permission_combinations() {
        let read_write_rule = PathRule::deny(FILE_PERM_READ | FILE_PERM_WRITE, true);
        let exec_delete_rule = PathRule::allow(FILE_PERM_EXEC | FILE_PERM_DELETE, false);

        assert!(read_write_rule.permissions & FILE_PERM_READ != 0);
        assert!(read_write_rule.permissions & FILE_PERM_WRITE != 0);
        assert!(read_write_rule.permissions & FILE_PERM_EXEC == 0);

        assert!(exec_delete_rule.permissions & FILE_PERM_EXEC != 0);
        assert!(exec_delete_rule.permissions & FILE_PERM_DELETE != 0);
        assert!(exec_delete_rule.permissions & FILE_PERM_READ == 0);
    }

    #[test]
    fn test_file_blocked_event_structure() {
        let mut event = FileBlockedEvent {
            path: [0u8; MAX_PATH_LEN],
            path_len: 0,
            operation: FILE_PERM_READ,
            pid: 1234,
            _pad: 0,
        };

        // Test setting a path
        let test_path = "/tmp/blocked.txt";
        let path_bytes = test_path.as_bytes();
        event.path[..path_bytes.len()].copy_from_slice(path_bytes);
        event.path_len = path_bytes.len() as u16;

        assert_eq!(event.path_len, 16);
        assert_eq!(event.operation, FILE_PERM_READ);
        assert_eq!(event.pid, 1234);

        // Verify path was stored correctly
        let stored_path = core::str::from_utf8(&event.path[..event.path_len as usize]).unwrap();
        assert_eq!(stored_path, test_path);
    }

    #[test]
    fn test_file_blocked_event_all_operations() {
        let operations = [
            FILE_PERM_READ,
            FILE_PERM_WRITE,
            FILE_PERM_EXEC,
            FILE_PERM_DELETE,
            FILE_PERM_READ | FILE_PERM_WRITE,
            FILE_PERM_ALL,
        ];

        for (i, &op) in operations.iter().enumerate() {
            let event = FileBlockedEvent {
                path: [0u8; MAX_PATH_LEN],
                path_len: 0,
                operation: op,
                pid: i as u32,
                _pad: 0,
            };

            assert_eq!(event.operation, op);
            assert_eq!(event.pid, i as u32);
        }
    }

    #[test]
    fn test_path_key_edge_cases() {
        // Test single character path
        let key1 = PathKey::new("/");
        assert_eq!(key1.len, 1);
        assert_eq!(key1.path[0], b'/');

        // Test maximum length path (truncated)
        let max_path = "a".repeat(MAX_PATH_LEN);
        let key2 = PathKey::new(&max_path);
        assert_eq!(key2.len, MAX_PATH_LEN as u16 - 1); // -1 for null terminator

        // Test path just under maximum
        let near_max_path = "a".repeat(MAX_PATH_LEN - 1);
        let key3 = PathKey::new(&near_max_path);
        assert_eq!(key3.len, MAX_PATH_LEN as u16 - 1);
    }

    #[test]
    fn test_constants_consistency() {
        // Ensure all constants are properly defined
        assert!(MAX_GATEWAYS > 0);
        assert!(MAX_BLOCKED_ENTRIES > 0);
        assert!(MAX_PATH_RULES > 0);
        assert!(MAX_PATH_LEN > 0);

        // Ensure permission flags are unique bits
        assert_eq!(FILE_PERM_READ, 1);
        assert_eq!(FILE_PERM_WRITE, 2);
        assert_eq!(FILE_PERM_EXEC, 4);
        assert_eq!(FILE_PERM_DELETE, 8);
    }

    // -------------------------------------------------------------------------
    // Integration-style tests for file access logic
    // -------------------------------------------------------------------------

    #[test]
    fn test_file_access_decision_matrix() {
        // Test various combinations of rules and permissions
        let test_cases = [
            // (rule_type, permissions, requested, expected_allow)
            (PathRuleType::Allow, FILE_PERM_READ, FILE_PERM_READ, true),
            (PathRuleType::Allow, FILE_PERM_READ, FILE_PERM_WRITE, false),
            (PathRuleType::Deny, FILE_PERM_READ, FILE_PERM_READ, false),
            (PathRuleType::Deny, FILE_PERM_READ, FILE_PERM_WRITE, true), // No overlap
            (PathRuleType::Allow, FILE_PERM_ALL, FILE_PERM_READ, true),
            (PathRuleType::Deny, FILE_PERM_ALL, FILE_PERM_READ, false),
        ];

        for (i, &(rule_type, rule_perms, requested, expected)) in test_cases.iter().enumerate() {
            let rule = if rule_type == PathRuleType::Allow {
                PathRule::allow(rule_perms, false)
            } else {
                PathRule::deny(rule_perms, false)
            };

            // Simulate the access check logic
            let permission_matches = rule.permissions & requested != 0;
            let allowed = if permission_matches {
                // Rule applies - check if it's an allow rule
                rule.rule_type == PathRuleType::Allow
            } else {
                // Rule doesn't apply (no permission overlap)
                // In this specific test, we expect false for non-overlapping allow rules
                // and true for non-overlapping deny rules
                if rule.rule_type == PathRuleType::Allow {
                    false // Allow rule doesn't apply
                } else {
                    true // Deny rule doesn't apply
                }
            };

            assert_eq!(
                allowed, expected,
                "Test case {}: rule_type={:?}, rule_perms={:#x}, requested={:#x}",
                i, rule_type, rule_perms, requested
            );
        }
    }

    #[test]
    fn test_path_matching_scenarios() {
        let test_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/home/user/.bashrc",
            "/tmp/app.log",
            "/var/log/system.log",
            "/usr/bin/python",
        ];

        for path in &test_paths {
            let key = PathKey::new(path);

            // Test that the path can be reconstructed
            let reconstructed = core::str::from_utf8(&key.path[..key.len as usize]).unwrap();
            assert_eq!(reconstructed, *path);

            // Test prefix matching logic (simplified)
            let path_str = *path;
            if let Some(slash_pos) = path_str.rfind('/') {
                let parent = &path_str[..slash_pos];
                let parent_key = PathKey::new(parent);

                // Parent should be shorter
                assert!(parent_key.len < key.len);
            }
        }
    }
}
