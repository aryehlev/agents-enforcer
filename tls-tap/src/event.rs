//! Event types crossing the kernel/userspace boundary.
//!
//! The ringbuf payload is laid out as `[TlsEventHdr][bytes]` where
//! `bytes` is the captured plaintext (length = `hdr.len`). The
//! kernel writes a fixed-size header then the variable payload;
//! userspace reads the header by `ptr::read_unaligned` and slices
//! the payload directly.
//!
//! The owned [`TlsEvent`] is what consumers see — header fields
//! lifted into Rust types plus an owned `Vec<u8>` of plaintext.
//! Owning the plaintext is the right tradeoff: it lets the
//! consumer hand the event off to a tokio task or channel without
//! lifetime pain, at the cost of one allocation per event. At
//! ringbuf budget (16KB max per event) this is bounded.

// Wire layout (TlsEventHdr, MAX_PLAINTEXT, direction tags) lives
// in `tls-tap-shared` so the eBPF program and this crate use the
// same definitions. Re-exported here for ergonomic
// `tls_tap::TlsEventHdr` usage.
use tls_tap_shared::direction;
pub use tls_tap_shared::{TlsEventHdr, MAX_PLAINTEXT};

/// Direction discriminator for [`TlsEvent`]. Keeps the userspace
/// API enum-shaped while the wire format is a `u8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsDirection {
    /// Captured pre-encryption from `SSL_write`.
    Write,
    /// Captured post-decryption from `SSL_read` (uretprobe).
    Read,
}

impl TlsDirection {
    /// Parse the on-wire `u8` tag the eBPF program emits. Unknown
    /// values are dropped by the consumer rather than panicking;
    /// we shouldn't crash because the kernel emitted a tag we
    /// don't recognize (e.g. forward-compat with a future v2
    /// program).
    pub fn from_tag(t: u8) -> Option<Self> {
        match t {
            direction::WRITE => Some(Self::Write),
            direction::READ => Some(Self::Read),
            _ => None,
        }
    }

    /// Stable string label for logging / serialization.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Write => "write",
            Self::Read => "read",
        }
    }
}

/// Owned, parsed TLS event handed to consumers. One allocation
/// for the plaintext copy; the header is by-value.
#[derive(Debug, Clone)]
pub struct TlsEvent {
    /// Cgroup id of the calling process.
    pub cgroup_id: u64,
    /// Opaque per-connection identifier.
    pub conn_id: u64,
    /// Process id.
    pub pid: u32,
    /// Thread-group id.
    pub tgid: u32,
    /// Direction (write / read).
    pub direction: TlsDirection,
    /// True when the kernel hit `MAX_PLAINTEXT` and clamped.
    pub truncated: bool,
    /// Captured plaintext, length ≤ [`MAX_PLAINTEXT`].
    pub plaintext: Vec<u8>,
}

impl TlsEvent {
    /// Parse a ringbuf payload (header + bytes). Returns `None`
    /// for malformed payloads (too short, unknown direction tag) —
    /// callers count + skip rather than fail loudly.
    pub fn from_ringbuf(payload: &[u8]) -> Option<Self> {
        let hdr_size = std::mem::size_of::<TlsEventHdr>();
        if payload.len() < hdr_size {
            return None;
        }
        // Safety: the kernel writes a fixed-layout repr(C) struct;
        // the size check above guarantees enough bytes; layouts
        // are pinned by the C/Rust size assertion in tests.
        let hdr: TlsEventHdr =
            unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const TlsEventHdr) };
        let direction = TlsDirection::from_tag(hdr.direction)?;
        let captured = (hdr.len as usize).min(payload.len() - hdr_size);
        let plaintext = payload[hdr_size..hdr_size + captured].to_vec();
        Some(Self {
            cgroup_id: hdr.cgroup_id,
            conn_id: hdr.conn_id,
            pid: hdr.pid,
            tgid: hdr.tgid,
            direction,
            truncated: hdr.truncated != 0,
            plaintext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_size_matches_c_struct() {
        // Trip-wire if anyone reorders fields. The C side is 32
        // bytes (8+8+4+4+4+1+1+2). MUST match.
        assert_eq!(std::mem::size_of::<TlsEventHdr>(), 32);
    }

    #[test]
    fn direction_round_trips_known_tags() {
        assert_eq!(TlsDirection::from_tag(1), Some(TlsDirection::Write));
        assert_eq!(TlsDirection::from_tag(2), Some(TlsDirection::Read));
        assert_eq!(TlsDirection::from_tag(99), None);
    }

    #[test]
    fn from_ringbuf_parses_full_event() {
        let mut buf = vec![0u8; std::mem::size_of::<TlsEventHdr>() + 5];
        let hdr = TlsEventHdr {
            cgroup_id: 42,
            conn_id: 0xdeadbeef,
            pid: 100,
            tgid: 100,
            len: 5,
            direction: direction::WRITE,
            truncated: 0,
            _pad: [0; 2],
        };
        unsafe {
            std::ptr::write_unaligned(buf.as_mut_ptr() as *mut TlsEventHdr, hdr);
        }
        buf[std::mem::size_of::<TlsEventHdr>()..].copy_from_slice(b"hello");
        let ev = TlsEvent::from_ringbuf(&buf).unwrap();
        assert_eq!(ev.cgroup_id, 42);
        assert_eq!(ev.direction, TlsDirection::Write);
        assert_eq!(ev.plaintext, b"hello");
        assert!(!ev.truncated);
    }

    #[test]
    fn from_ringbuf_rejects_short_payload() {
        // A short payload means the ringbuf gave us garbage —
        // skip rather than guess.
        let buf = vec![0u8; 4];
        assert!(TlsEvent::from_ringbuf(&buf).is_none());
    }

    #[test]
    fn from_ringbuf_clamps_overstated_length() {
        // Defensive: header says len=999 but only 3 payload bytes
        // present. Take what's there, don't read past the buffer.
        let mut buf = vec![0u8; std::mem::size_of::<TlsEventHdr>() + 3];
        let hdr = TlsEventHdr {
            cgroup_id: 1,
            conn_id: 1,
            pid: 1,
            tgid: 1,
            len: 999, // lie
            direction: direction::READ,
            truncated: 0,
            _pad: [0; 2],
        };
        unsafe {
            std::ptr::write_unaligned(buf.as_mut_ptr() as *mut TlsEventHdr, hdr);
        }
        buf[std::mem::size_of::<TlsEventHdr>()..].copy_from_slice(b"abc");
        let ev = TlsEvent::from_ringbuf(&buf).unwrap();
        assert_eq!(ev.plaintext, b"abc");
    }

    #[test]
    fn from_ringbuf_drops_unknown_direction() {
        let mut buf = vec![0u8; std::mem::size_of::<TlsEventHdr>()];
        let hdr = TlsEventHdr {
            cgroup_id: 0,
            conn_id: 0,
            pid: 0,
            tgid: 0,
            len: 0,
            direction: 7, // not write nor read
            truncated: 0,
            _pad: [0; 2],
        };
        unsafe {
            std::ptr::write_unaligned(buf.as_mut_ptr() as *mut TlsEventHdr, hdr);
        }
        assert!(TlsEvent::from_ringbuf(&buf).is_none());
    }
}
