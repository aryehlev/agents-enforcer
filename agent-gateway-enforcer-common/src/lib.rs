#![no_std]

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

#[cfg(feature = "user")]
unsafe impl aya::Pod for GatewayKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BlockedKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BlockedEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PathKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PathRule {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FileBlockedEvent {}
