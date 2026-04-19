//! Per-connection plaintext buffer.
//!
//! `SSL_write` may chunk a single HTTP request across multiple
//! calls (16KB ringbuf cap, multi-KB JSON tool definitions, etc).
//! The reassembler holds a small bounded buffer per `conn_id`,
//! re-runs the parser after each chunk, and evicts on success /
//! garbage / timeout.
//!
//! Constraints:
//! - Bounded memory: each entry capped at 256KB. Bigger requests
//!   are dropped with a counter; we never want this map to grow
//!   without bound from a misbehaving (or attacking) agent.
//! - LRU-style eviction by last-touched time so a process that
//!   opens 10k connections and never sends doesn't pin memory.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::decoder::{parse, LlmRequestFacts, ParseStatus};

/// How big a single in-flight request may grow before we give up.
/// 256KB covers tools-heavy chat requests; bigger means something
/// is wrong (or hostile) and we'd rather drop than buffer forever.
pub const MAX_BUFFER_BYTES: usize = 256 * 1024;

/// Idle timeout. A buffer untouched for this long is evicted.
pub const IDLE_EVICTION: Duration = Duration::from_secs(30);

/// Keep at most this many in-flight connections per node. At full
/// occupancy we evict the oldest on insert; LRU is overkill for
/// our cardinality (real traffic is hundreds, not millions).
pub const MAX_INFLIGHT_CONNS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkOutcome {
    /// Successfully parsed a full LLM request from the accumulated
    /// buffer. The reassembler has dropped the entry (callers
    /// should not push more chunks under this `conn_id` until a
    /// new request starts; the next chunk seeds a fresh entry).
    Complete(LlmRequestFacts),
    /// Buffer is HTTP for an LLM path but body is incomplete.
    Buffering,
    /// Plaintext is recognizably non-LLM (different path, GET, …);
    /// we've dropped the entry to free memory.
    NotLlm,
    /// Garbage or oversized; entry dropped.
    Dropped,
}

#[derive(Default)]
pub struct Reassembler {
    by_conn: HashMap<u64, Buffer>,
}

struct Buffer {
    bytes: Vec<u8>,
    last_touched: Instant,
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append `chunk` to the buffer for `conn_id` and try to parse.
    ///
    /// `now` is injected so tests can drive the eviction clock
    /// without sleeping; production passes `Instant::now()`.
    pub fn push(&mut self, conn_id: u64, chunk: &[u8], now: Instant) -> ChunkOutcome {
        self.evict_idle(now);

        let entry = self.by_conn.entry(conn_id).or_insert_with(|| Buffer {
            bytes: Vec::new(),
            last_touched: now,
        });
        entry.last_touched = now;

        if entry.bytes.len() + chunk.len() > MAX_BUFFER_BYTES {
            self.by_conn.remove(&conn_id);
            return ChunkOutcome::Dropped;
        }
        entry.bytes.extend_from_slice(chunk);

        let outcome = match parse(&entry.bytes) {
            ParseStatus::Ok(facts) => {
                self.by_conn.remove(&conn_id);
                return ChunkOutcome::Complete(facts);
            }
            ParseStatus::NeedMore => ChunkOutcome::Buffering,
            ParseStatus::NotLlm => {
                self.by_conn.remove(&conn_id);
                ChunkOutcome::NotLlm
            }
            ParseStatus::Garbage => {
                self.by_conn.remove(&conn_id);
                ChunkOutcome::Dropped
            }
        };

        // Bound total occupancy *after* the entry is finalized so
        // a single-shot complete request doesn't trigger eviction.
        if self.by_conn.len() > MAX_INFLIGHT_CONNS {
            if let Some(oldest_key) = self.oldest_key() {
                self.by_conn.remove(&oldest_key);
            }
        }

        outcome
    }

    /// Drop entries that haven't been touched within
    /// [`IDLE_EVICTION`]. Cheap O(n) sweep — n is bounded by
    /// `MAX_INFLIGHT_CONNS` so this is fine on the hot path.
    fn evict_idle(&mut self, now: Instant) {
        self.by_conn
            .retain(|_, b| now.duration_since(b.last_touched) < IDLE_EVICTION);
    }

    fn oldest_key(&self) -> Option<u64> {
        self.by_conn
            .iter()
            .min_by_key(|(_, b)| b.last_touched)
            .map(|(k, _)| *k)
    }

    pub fn len(&self) -> usize {
        self.by_conn.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_conn.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_request() -> Vec<u8> {
        let body = r#"{"model":"gpt-4o","messages":[]}"#;
        format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .into_bytes()
    }

    #[test]
    fn single_chunk_completes_immediately() {
        let mut r = Reassembler::new();
        let now = Instant::now();
        let out = r.push(1, &full_request(), now);
        let ChunkOutcome::Complete(f) = out else {
            panic!("got {:?}", out)
        };
        assert_eq!(f.model, "gpt-4o");
        // Buffer freed on Complete so a follow-up chunk starts fresh.
        assert!(r.is_empty());
    }

    #[test]
    fn split_chunks_buffer_then_complete() {
        // Real-world: SSL_write breaks a 32KB request across two
        // 16KB calls. The second call's chunk on its own is not
        // valid HTTP — only the concatenation parses.
        let mut r = Reassembler::new();
        let req = full_request();
        let split = req.len() / 2;
        let now = Instant::now();
        assert_eq!(r.push(1, &req[..split], now), ChunkOutcome::Buffering);
        let out = r.push(1, &req[split..], now);
        assert!(matches!(out, ChunkOutcome::Complete(_)));
    }

    #[test]
    fn distinct_conn_ids_buffer_independently() {
        // Two parallel LLM requests interleave on the wire; each
        // SSL connection is its own `conn_id` so they must not
        // contaminate each other's buffers.
        let mut r = Reassembler::new();
        let req = full_request();
        let split = req.len() / 2;
        let now = Instant::now();
        r.push(1, &req[..split], now);
        r.push(2, &req[..split], now);
        assert_eq!(r.len(), 2);
        assert!(matches!(r.push(1, &req[split..], now), ChunkOutcome::Complete(_)));
        assert_eq!(r.len(), 1, "completing conn 1 leaves conn 2 buffered");
    }

    #[test]
    fn oversized_buffer_is_dropped_not_resized() {
        // Defensive: a hostile process could SSL_write a giant
        // body to exhaust node memory. Cap is non-negotiable.
        let mut r = Reassembler::new();
        let mut chunk = b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: 999999\r\n\r\n".to_vec();
        chunk.extend(vec![b'x'; MAX_BUFFER_BYTES]);
        let out = r.push(1, &chunk, Instant::now());
        assert_eq!(out, ChunkOutcome::Dropped);
        assert!(r.is_empty());
    }

    #[test]
    fn idle_buffers_evict_after_timeout() {
        let mut r = Reassembler::new();
        let t0 = Instant::now();
        r.push(
            1,
            b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n",
            t0,
        );
        assert_eq!(r.len(), 1);
        // Touch a different conn long after the eviction window.
        let later = t0 + IDLE_EVICTION + Duration::from_secs(1);
        r.push(2, b"GET / HTTP/1.1\r\n", later);
        // conn 1 evicted; conn 2 was non-LLM so not retained either.
        assert!(r.is_empty());
    }

    #[test]
    fn non_llm_chunk_drops_entry() {
        let mut r = Reassembler::new();
        let out = r.push(1, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", Instant::now());
        assert_eq!(out, ChunkOutcome::NotLlm);
        assert!(r.is_empty());
    }
}
