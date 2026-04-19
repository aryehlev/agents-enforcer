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

/// Key for the per-pod allowed gateways map.
///
/// Combines a cgroup v2 id (returned by `bpf_get_current_cgroup_id()` in
/// the kernel and by `stat(cgroup_path).st_ino` in userspace) with the
/// destination (addr, port). This gives us per-pod allowlisting without
/// paying the cost of a `BPF_MAP_TYPE_HASH_OF_MAPS` scheme — an inner
/// map per pod — which aya 0.12 doesn't expose well for runtime-created
/// inner maps. Switching to HASH_OF_MAPS later is a drop-in
/// replacement: the (cgroup_id, addr, port) triple is equivalent to
/// (cgroup_id) -> (addr, port) map-in-map.
///
/// A cgroup_id of 0 means "global" — used by `configure_gateways` to
/// keep backwards-compatible behavior for single-tenant deployments.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PodGatewayKey {
    /// Kernel cgroup id (u64). 0 = global entry.
    pub cgroup_id: u64,
    /// IPv4 address in network byte order (big endian).
    pub addr: u32,
    /// Port in host byte order; 0 matches any port for this (cgroup,addr).
    pub port: u16,
    /// Padding for alignment.
    pub _pad: u16,
}

impl PodGatewayKey {
    pub const fn new(cgroup_id: u64, addr: u32, port: u16) -> Self {
        Self {
            cgroup_id,
            addr,
            port,
            _pad: 0,
        }
    }

    pub const fn global(addr: u32, port: u16) -> Self {
        Self::new(0, addr, port)
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

/// Event sent from eBPF to userspace when a connection is decided.
///
/// Mirrors `struct net_event` in `backends/ebpf-linux/ebpf/network.c`.
/// `cgroup_id` is populated by `bpf_get_current_cgroup_id()` so
/// userspace can attribute the event back to the enforcing pod via
/// the per-pod attachment registry; 0 means host-networking /
/// unattributed.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BlockedEvent {
    /// Kernel cgroup id of the process that triggered the event.
    pub cgroup_id: u64,
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
    /// Event type tag (1 = blocked, 2 = allowed); see
    /// `NET_EVENT_*` in `network.c`.
    pub event_type: u8,
    /// Padding to keep layout 8-byte aligned.
    pub _pad: [u8; 2],
}

/// Event-type tag for [`BlockedEvent::event_type`]: connection was denied.
pub const NET_EVENT_BLOCKED: u8 = 1;
/// Event-type tag for [`BlockedEvent::event_type`]: connection was allowed
/// (emitted in audit mode as well as on pass).
pub const NET_EVENT_ALLOWED: u8 = 2;

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

/// Length of the ASCII `comm` field an LSM event carries (matches
/// `MAX_COMM_LEN` in `lsm.c`).
pub const COMM_LEN: usize = 16;

/// Event sent from eBPF to userspace on every LSM hook decision.
///
/// Mirrors `struct file_event` in `backends/ebpf-linux/ebpf/lsm.c`.
/// The file-blocking hooks (`file_open`, `bprm_check_security`,
/// `path_*`) all emit this layout so consumers can switch on
/// [`Self::event_type`] without per-hook deserialization.
///
/// Field order matches the C struct exactly so `ptr::read` over a
/// ringbuf frame is safe. Size is 296 bytes on a 64-bit target.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileEvent {
    /// Kernel cgroup id of the process that triggered the event.
    pub cgroup_id: u64,
    /// One of the `FILE_EVENT_*` tags.
    pub event_type: u32,
    /// PID of the triggering thread-group leader.
    pub pid: u32,
    /// UID of the triggering process.
    pub uid: u32,
    /// 0 = allowed, -1 = blocked; set by the hook before emitting.
    pub action: i32,
    /// Null-padded `comm` (first 16 bytes of `/proc/<pid>/comm`).
    pub comm: [u8; COMM_LEN],
    /// Null-padded path. For `path_*` hooks this is the op tag
    /// (`unlink` / `mkdir` / `rmdir`) rather than the actual inode path.
    pub path: [u8; MAX_PATH_LEN],
}

/// `file_event.event_type` tag: file opened (observed, not blocked).
pub const FILE_EVENT_OPEN: u32 = 1;
/// `file_event.event_type` tag: file open was denied.
pub const FILE_EVENT_BLOCKED: u32 = 2;
/// `file_event.event_type` tag: `bprm_check_security` denied an exec.
pub const FILE_EVENT_EXEC_BLOCKED: u32 = 3;
/// `file_event.event_type` tag: `path_unlink|mkdir|rmdir` denied a mutation.
pub const FILE_EVENT_PATH_BLOCKED: u32 = 4;

/// Direction tag for [`TlsEventHdr::direction`].
pub mod tls {
    /// Plaintext captured pre-encryption from `SSL_write`.
    pub const TLS_WRITE: u8 = 1;
    /// Plaintext captured post-decryption from `SSL_read`.
    pub const TLS_READ: u8 = 2;
}

/// Maximum captured payload bytes per TLS event. Must equal
/// `MAX_PLAINTEXT` in `backends/ebpf-linux/ebpf/tls.c`.
pub const TLS_MAX_PLAINTEXT: usize = 16384;

/// Header that prefixes every TLS plaintext event in the
/// `tls_events` ringbuf. Mirrors `struct tls_event_hdr` in
/// `backends/ebpf-linux/ebpf/tls.c`.
///
/// The kernel writes a fixed-layout struct (`tls_event_hdr` followed
/// by `MAX_PLAINTEXT` bytes of payload). Userspace reads
/// `core::mem::size_of::<TlsEventHdr>()` for the header, then
/// `hdr.len` bytes of plaintext.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TlsEventHdr {
    /// Cgroup id of the process that made the SSL_* call. Used to
    /// attribute the event back to a pod.
    pub cgroup_id: u64,
    /// Opaque connection identifier — the `SSL *` userspace pointer.
    /// Stable for the life of the connection; reassemblers key on it.
    pub conn_id: u64,
    /// Linux PID (LWP id).
    pub pid: u32,
    /// Linux TGID (process id).
    pub tgid: u32,
    /// Number of plaintext bytes that follow this header
    /// (`<= TLS_MAX_PLAINTEXT`).
    pub len: u32,
    /// One of [`tls::TLS_WRITE`] / [`tls::TLS_READ`].
    pub direction: u8,
    /// 1 when the kernel hit `MAX_PLAINTEXT` and chopped the
    /// payload — userspace treats truncated streams as
    /// "give up parsing" rather than guess the rest of the JSON.
    pub truncated: u8,
    /// Padding to keep size 8-aligned and matching the C struct.
    pub _pad: [u8; 2],
}

#[cfg(target_os = "linux")]
unsafe impl aya::Pod for TlsEventHdr {}

// Userspace helpers — require `std` (for `String`), so gated on the
// `user` feature. The kernel-side aya Pod impl above stays feature-free.
#[cfg(any(feature = "user", test))]
impl FileEvent {
    /// Return `comm` as a `&str`, trimming the trailing nulls. Invalid
    /// UTF-8 (rare in real comms, guaranteed by the kernel to be
    /// printable but just in case) is replaced with the lossy char.
    pub fn comm_str(&self) -> std::borrow::Cow<'_, str> {
        let end = self
            .comm
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(self.comm.len());
        String::from_utf8_lossy(&self.comm[..end])
    }

    /// Return `path` as a `&str`, trimming the trailing nulls.
    pub fn path_str(&self) -> std::borrow::Cow<'_, str> {
        let end = self
            .path
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(self.path.len());
        String::from_utf8_lossy(&self.path[..end])
    }
}

#[cfg(target_os = "linux")]
unsafe impl aya::Pod for GatewayKey {}

#[cfg(target_os = "linux")]
unsafe impl aya::Pod for PodGatewayKey {}

#[cfg(target_os = "linux")]
unsafe impl aya::Pod for BlockedKey {}

#[cfg(target_os = "linux")]
unsafe impl aya::Pod for BlockedEvent {}

#[cfg(target_os = "linux")]
unsafe impl aya::Pod for PathKey {}

#[cfg(target_os = "linux")]
unsafe impl aya::Pod for PathRule {}

#[cfg(target_os = "linux")]
unsafe impl aya::Pod for FileBlockedEvent {}

#[cfg(target_os = "linux")]
unsafe impl aya::Pod for FileEvent {}

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

    #[test]
    fn pod_gateway_key_layout_is_16_bytes() {
        // 8 (cgroup_id) + 4 (addr) + 2 (port) + 2 (pad). Size must match
        // the BPF map key size we declare in ebpf/network.c.
        assert_eq!(core::mem::size_of::<PodGatewayKey>(), 16);
    }

    #[test]
    fn pod_gateway_key_global_uses_zero_cgroup() {
        let k = PodGatewayKey::global(0x0A00_0001, 443);
        assert_eq!(k.cgroup_id, 0);
        assert_eq!(k.addr, 0x0A00_0001);
        assert_eq!(k.port, 443);
    }

    #[test]
    fn pod_gateway_key_hash_distinguishes_cgroups() {
        use std::collections::HashMap;
        let a = PodGatewayKey::new(42, 0x0100_0001, 443);
        let b = PodGatewayKey::new(43, 0x0100_0001, 443);
        let mut m = HashMap::new();
        m.insert(a, 1u8);
        m.insert(b, 2u8);
        assert_eq!(m.len(), 2, "different cgroup ids must hash distinctly");
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
        // 8 (cgroup_id) + 4 + 4 + 2 + 2 + 1 + 1 + 2 = 24. Must match
        // `sizeof(struct net_event)` in `ebpf/network.c`.
        assert_eq!(core::mem::size_of::<BlockedEvent>(), 24);
    }

    #[test]
    fn test_file_event_size() {
        // 8 (cgroup_id) + 4 + 4 + 4 + 4 + 16 (comm) + 256 (path) = 296.
        // Must match `sizeof(struct file_event)` in `ebpf/lsm.c`.
        assert_eq!(core::mem::size_of::<FileEvent>(), 296);
    }

    #[test]
    fn test_tls_event_hdr_size() {
        // 8 (cgroup_id) + 8 (conn_id) + 4 (pid) + 4 (tgid) + 4 (len)
        // + 1 (direction) + 1 (truncated) + 2 (pad) = 32 bytes.
        // Must match `sizeof(struct tls_event_hdr)` in `ebpf/tls.c`.
        assert_eq!(core::mem::size_of::<TlsEventHdr>(), 32);
    }

    #[test]
    fn tls_direction_constants_match_c_macros() {
        // Trip-wire if someone renumbers the C side.
        assert_eq!(tls::TLS_WRITE, 1);
        assert_eq!(tls::TLS_READ, 2);
    }

    #[test]
    fn file_event_comm_and_path_trim_nulls() {
        let mut ev = FileEvent {
            cgroup_id: 42,
            event_type: FILE_EVENT_BLOCKED,
            pid: 1,
            uid: 0,
            action: -1,
            comm: [0u8; COMM_LEN],
            path: [0u8; MAX_PATH_LEN],
        };
        ev.comm[..4].copy_from_slice(b"bash");
        ev.path[..9].copy_from_slice(b"/bin/true");
        assert_eq!(&*ev.comm_str(), "bash");
        assert_eq!(&*ev.path_str(), "/bin/true");
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
