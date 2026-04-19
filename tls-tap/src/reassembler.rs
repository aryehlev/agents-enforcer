//! Per-connection plaintext reassembler.
//!
//! `SSL_write` may chunk a single logical message across multiple
//! calls (16KB ringbuf cap, large request bodies, etc). The
//! reassembler buffers chunks per `(conn_id, direction)` and lets
//! the consumer either:
//!
//! - inspect the partial buffer at any point (best-effort decode),
//!   or
//! - wait for a logical boundary and consume the full message.
//!
//! "Logical boundary" is consumer-defined — `tls-tap` doesn't
//! know what a complete message is (HTTP request, gRPC frame,
//! Postgres protocol message, …). Consumers call
//! [`Reassembler::take`] when their parser says "this is enough."
//!
//! Bounded memory is non-negotiable: a misbehaving (or hostile)
//! process must not be able to grow this map without limit.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::event::TlsDirection;

/// Per-connection buffer cap. Bigger than this and we drop the
/// stream — at that point parsing is the consumer's problem on a
/// best-effort basis. 256 KiB covers tools-heavy LLM requests
/// without letting a runaway process pin gigs of memory.
pub const MAX_BUFFER_BYTES: usize = 256 * 1024;

/// Idle timeout. A buffer untouched for this long is evicted.
pub const IDLE_EVICTION: Duration = Duration::from_secs(30);

/// Soft cap on tracked connections. Past this we evict the
/// oldest. LRU is overkill for our cardinality (real traffic is
/// hundreds, not millions).
pub const MAX_INFLIGHT_CONNS: usize = 4096;

#[derive(Debug, Clone)]
/// What the reassembler hands back when a consumer calls
/// [`Reassembler::take`].
pub struct ReassembledMessage {
    /// Full accumulated bytes for this `(conn_id, direction)`.
    pub plaintext: Vec<u8>,
    /// True if any contributing event had its payload clamped at
    /// MAX_PLAINTEXT — consumers may want to discard rather than
    /// parse a truncated body.
    pub had_truncation: bool,
}

/// Connection-buffer map. One per consumer task; not thread-safe
/// internally — wrap in a Mutex if multiple tasks need to push.
#[derive(Default)]
pub struct Reassembler {
    by_key: HashMap<Key, Buffer>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    conn_id: u64,
    direction: TlsDirection,
}

struct Buffer {
    bytes: Vec<u8>,
    had_truncation: bool,
    last_touched: Instant,
}

impl Reassembler {
    /// Construct empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append `chunk` to the buffer for `(conn_id, direction)`.
    /// `now` is injected so tests can drive the eviction clock
    /// without sleeping; production passes `Instant::now()`.
    /// Returns `true` if the chunk was buffered, `false` if the
    /// buffer was at the cap and the chunk was dropped.
    pub fn push(
        &mut self,
        conn_id: u64,
        direction: TlsDirection,
        chunk: &[u8],
        truncated: bool,
        now: Instant,
    ) -> bool {
        self.evict_idle(now);
        let key = Key { conn_id, direction };
        let entry = self.by_key.entry(key).or_insert_with(|| Buffer {
            bytes: Vec::new(),
            had_truncation: false,
            last_touched: now,
        });
        entry.last_touched = now;
        entry.had_truncation |= truncated;

        if entry.bytes.len() + chunk.len() > MAX_BUFFER_BYTES {
            self.by_key.remove(&key);
            return false;
        }
        entry.bytes.extend_from_slice(chunk);

        if self.by_key.len() > MAX_INFLIGHT_CONNS {
            if let Some(oldest_key) = self.oldest_key() {
                self.by_key.remove(&oldest_key);
            }
        }
        true
    }

    /// Borrow the current buffer for `(conn_id, direction)` —
    /// useful for incremental parsers that want to peek without
    /// consuming.
    pub fn peek(&self, conn_id: u64, direction: TlsDirection) -> Option<&[u8]> {
        self.by_key
            .get(&Key { conn_id, direction })
            .map(|b| b.bytes.as_slice())
    }

    /// Remove and return the buffer for `(conn_id, direction)`.
    /// Consumers call this after their parser confirms a full
    /// logical message has arrived.
    pub fn take(
        &mut self,
        conn_id: u64,
        direction: TlsDirection,
    ) -> Option<ReassembledMessage> {
        let buf = self.by_key.remove(&Key { conn_id, direction })?;
        Some(ReassembledMessage {
            plaintext: buf.bytes,
            had_truncation: buf.had_truncation,
        })
    }

    fn evict_idle(&mut self, now: Instant) {
        self.by_key
            .retain(|_, b| now.duration_since(b.last_touched) < IDLE_EVICTION);
    }

    fn oldest_key(&self) -> Option<Key> {
        self.by_key
            .iter()
            .min_by_key(|(_, b)| b.last_touched)
            .map(|(k, _)| *k)
    }

    /// Number of in-flight connections.
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    /// True when nothing is buffered.
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_then_peek_returns_appended_bytes() {
        let mut r = Reassembler::new();
        let now = Instant::now();
        assert!(r.push(1, TlsDirection::Write, b"hel", false, now));
        assert!(r.push(1, TlsDirection::Write, b"lo", false, now));
        assert_eq!(r.peek(1, TlsDirection::Write).unwrap(), b"hello");
    }

    #[test]
    fn distinct_directions_buffer_independently() {
        // SSL_write and SSL_read on the same SSL* are different
        // logical streams (request vs response). Sharing a key
        // would scramble both.
        let mut r = Reassembler::new();
        let now = Instant::now();
        r.push(1, TlsDirection::Write, b"req", false, now);
        r.push(1, TlsDirection::Read, b"resp", false, now);
        assert_eq!(r.peek(1, TlsDirection::Write).unwrap(), b"req");
        assert_eq!(r.peek(1, TlsDirection::Read).unwrap(), b"resp");
    }

    #[test]
    fn take_returns_buffer_and_clears_entry() {
        let mut r = Reassembler::new();
        r.push(1, TlsDirection::Write, b"abc", false, Instant::now());
        let msg = r.take(1, TlsDirection::Write).unwrap();
        assert_eq!(msg.plaintext, b"abc");
        assert!(r.is_empty());
        // Second take is None — entry already consumed.
        assert!(r.take(1, TlsDirection::Write).is_none());
    }

    #[test]
    fn truncation_propagates_through_take() {
        let mut r = Reassembler::new();
        r.push(1, TlsDirection::Write, b"a", true, Instant::now());
        r.push(1, TlsDirection::Write, b"b", false, Instant::now());
        let msg = r.take(1, TlsDirection::Write).unwrap();
        assert!(msg.had_truncation);
    }

    #[test]
    fn oversized_buffer_is_dropped_not_resized() {
        // A hostile process could SSL_write a giant body to
        // exhaust node memory. The cap is non-negotiable.
        let mut r = Reassembler::new();
        let big = vec![b'x'; MAX_BUFFER_BYTES + 1];
        let kept = r.push(1, TlsDirection::Write, &big, false, Instant::now());
        assert!(!kept);
        assert!(r.is_empty());
    }

    #[test]
    fn idle_buffers_evict_after_timeout() {
        let mut r = Reassembler::new();
        let t0 = Instant::now();
        r.push(1, TlsDirection::Write, b"x", false, t0);
        let later = t0 + IDLE_EVICTION + Duration::from_secs(1);
        // A push for a different conn triggers the evict sweep.
        r.push(2, TlsDirection::Write, b"y", false, later);
        // conn 1 evicted; conn 2 is the only one left.
        assert_eq!(r.len(), 1);
        assert!(r.peek(1, TlsDirection::Write).is_none());
    }
}
