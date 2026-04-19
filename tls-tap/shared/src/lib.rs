//! Wire types shared between the eBPF kernel program and the
//! userspace consumer. `no_std` so the BPF crate can depend on us.
//!
//! Layout invariant: `repr(C)` and field-for-field identical to
//! how the BPF program writes them. The userspace test in
//! `tls-tap` pins `size_of::<TlsEventHdr>()` so a renumber on
//! either side breaks loudly.

#![no_std]

/// Direction tag for [`TlsEventHdr::direction`].
pub mod direction {
    /// Captured pre-encryption from `SSL_write`.
    pub const WRITE: u8 = 1;
    /// Captured post-decryption from `SSL_read` (uretprobe).
    pub const READ: u8 = 2;
}

/// Maximum plaintext bytes per event. The BPF side clamps to
/// this. 16 KiB is two 4K pages on x86_64; bigger payloads come
/// across as multiple events that the userspace reassembler
/// stitches by `(conn_id, direction)`.
pub const MAX_PLAINTEXT: usize = 16384;

/// Header that prefixes every TLS plaintext event in the ringbuf.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TlsEventHdr {
    /// Cgroup id of the calling process.
    pub cgroup_id: u64,
    /// Opaque connection id — the `SSL *` userspace pointer.
    pub conn_id: u64,
    /// Linux PID (LWP id).
    pub pid: u32,
    /// Linux TGID (process id).
    pub tgid: u32,
    /// Plaintext bytes that follow this header.
    pub len: u32,
    /// Tag matching one of [`direction`].
    pub direction: u8,
    /// 1 when the kernel hit `MAX_PLAINTEXT` and clamped.
    pub truncated: u8,
    /// Padding to keep size 8-aligned.
    pub _pad: [u8; 2],
}

/// In-flight `SSL_read` argument stash. The uprobe (entry) writes
/// this; the uretprobe (exit) reads it back to recover the buffer
/// pointer captured before the call. Keyed by `pid_tgid`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SslReadArgs {
    pub ssl: u64,
    pub buf: u64,
    pub want: u32,
    pub _pad: u32,
}
