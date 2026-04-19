//! Minimal Server-Sent Events parser scoped to what the LLM proxy
//! needs — enough to pull `event:` + `data:` lines out of a chunked
//! byte stream and hand them to the provider adapter for usage
//! extraction. We deliberately don't implement the full SSE spec
//! (retry, id, comments) because upstream bytes flow through to the
//! client verbatim — we just need to *observe* them.
//!
//! The parser operates on a rolling `Vec<u8>` buffer. Feed chunks
//! as they arrive with `push`, then call `drain_events()` to get
//! every complete event so far. Partial lines stay in the buffer.

/// One SSE event as surfaced by the parser. `data` is concatenated
/// from consecutive `data:` lines per the spec; `event` is the last
/// `event:` line before the blank terminator (or "" when unset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub event: String,
    pub data: Vec<u8>,
}

/// Incremental SSE line buffer.
#[derive(Default)]
pub struct SseParser {
    buf: Vec<u8>,
}

impl SseParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append raw bytes from the upstream stream.
    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// Extract every fully-terminated event from the buffer. Events
    /// are separated by a blank line (`\n\n`); anything after the
    /// last blank line is incomplete and stays buffered for the next
    /// `push`.
    pub fn drain_events(&mut self) -> Vec<SseEvent> {
        let mut events = Vec::new();

        // Walk the buffer, splitting on "\n\n". Support "\r\n\r\n"
        // too since some providers emit CRLF (OpenAI sometimes does
        // over HTTP/1.1).
        loop {
            let end = find_double_newline(&self.buf);
            let Some(end) = end else { break };
            let block: Vec<u8> = self.buf.drain(..end.end).collect();
            // Strip the trailing separator bytes so the block only
            // contains field lines.
            let block = &block[..block.len() - end.sep_len];
            if let Some(ev) = parse_block(block) {
                events.push(ev);
            }
        }
        events
    }
}

/// Position of a `\n\n` (or `\r\n\r\n`) terminator in the buffer.
/// `end` is the index *after* the separator; `sep_len` is 2 or 4.
struct SeparatorRange {
    end: usize,
    sep_len: usize,
}

fn find_double_newline(buf: &[u8]) -> Option<SeparatorRange> {
    for (i, w) in buf.windows(4).enumerate() {
        if w == b"\r\n\r\n" {
            return Some(SeparatorRange {
                end: i + 4,
                sep_len: 4,
            });
        }
    }
    for (i, w) in buf.windows(2).enumerate() {
        if w == b"\n\n" {
            return Some(SeparatorRange {
                end: i + 2,
                sep_len: 2,
            });
        }
    }
    None
}

fn parse_block(block: &[u8]) -> Option<SseEvent> {
    let mut event = String::new();
    let mut data: Vec<u8> = Vec::new();
    let mut saw_data = false;
    // SSE lines are separated by \n or \r\n; split on \n and strip
    // a trailing \r.
    for line in block.split(|b| *b == b'\n') {
        let line = if let Some(b) = line.strip_suffix(b"\r") {
            b
        } else {
            line
        };
        if line.is_empty() {
            continue;
        }
        if line.starts_with(b":") {
            // Comment — ignore per SSE spec.
            continue;
        }
        // Split on the first ':'. A missing colon means the line is
        // itself a field name with an empty value, per spec; we
        // ignore because OpenAI / Anthropic don't emit those.
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            continue;
        };
        let (field, rest) = line.split_at(colon);
        // Skip the ':' and an optional leading space.
        let value = if rest.starts_with(b": ") {
            &rest[2..]
        } else {
            &rest[1..]
        };
        match field {
            b"event" => {
                event = String::from_utf8_lossy(value).into_owned();
            }
            b"data" => {
                if saw_data {
                    data.push(b'\n');
                }
                data.extend_from_slice(value);
                saw_data = true;
            }
            // id / retry / anything else — we don't need them.
            _ => {}
        }
    }
    if !saw_data {
        return None;
    }
    Some(SseEvent { event, data })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drains_one_lf_terminated_event() {
        let mut p = SseParser::new();
        p.push(b"data: hello\n\n");
        let events = p.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "");
        assert_eq!(events[0].data, b"hello");
    }

    #[test]
    fn drains_crlf_terminated_event() {
        let mut p = SseParser::new();
        p.push(b"data: hi\r\n\r\n");
        assert_eq!(p.drain_events()[0].data, b"hi");
    }

    #[test]
    fn partial_event_stays_buffered() {
        let mut p = SseParser::new();
        p.push(b"data: partial");
        assert!(p.drain_events().is_empty());
        p.push(b"\n\n");
        assert_eq!(p.drain_events()[0].data, b"partial");
    }

    #[test]
    fn multiple_events_in_one_push() {
        let mut p = SseParser::new();
        p.push(b"data: a\n\ndata: b\n\n");
        let events = p.drain_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].data, b"a");
        assert_eq!(events[1].data, b"b");
    }

    #[test]
    fn named_event_round_trips() {
        let mut p = SseParser::new();
        p.push(b"event: message_start\ndata: {\"hello\":1}\n\n");
        let events = p.drain_events();
        assert_eq!(events[0].event, "message_start");
        assert_eq!(events[0].data, b"{\"hello\":1}");
    }

    #[test]
    fn multiline_data_concatenates_with_newlines() {
        let mut p = SseParser::new();
        p.push(b"data: line1\ndata: line2\n\n");
        assert_eq!(p.drain_events()[0].data, b"line1\nline2");
    }

    #[test]
    fn comment_lines_are_ignored() {
        // Providers send ": keepalive" to prevent idle-timeout drops.
        let mut p = SseParser::new();
        p.push(b": keepalive\ndata: {\"x\":1}\n\n");
        assert_eq!(p.drain_events()[0].data, b"{\"x\":1}");
    }

    #[test]
    fn blank_terminator_without_data_yields_no_event() {
        // `event:` alone with no data is legal SSE but useless to us.
        let mut p = SseParser::new();
        p.push(b"event: ping\n\n");
        assert!(p.drain_events().is_empty());
    }

    #[test]
    fn chunked_push_does_not_drop_events() {
        // Byte-by-byte feed simulates worst-case chunking from hyper.
        let raw = b"event: m\ndata: 1\n\ndata: 2\n\n";
        let mut p = SseParser::new();
        let mut all = Vec::new();
        for b in raw {
            p.push(&[*b]);
            all.extend(p.drain_events());
        }
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].event, "m");
        assert_eq!(all[0].data, b"1");
        assert_eq!(all[1].data, b"2");
    }
}
