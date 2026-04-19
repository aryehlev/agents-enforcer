// SPDX-License-Identifier: MIT
/*
 * Agent Gateway Enforcer - eBPF TLS Plaintext Probe
 *
 * Userspace uprobes on OpenSSL's SSL_write / SSL_read, capturing
 * plaintext to the ringbuf BEFORE encryption (write) and AFTER
 * decryption (read). The userspace consumer (in node-agent)
 * reassembles HTTP requests, parses the JSON body, looks up the
 * pod's AgentCapability, and either:
 *   - emits an audit DecisionEvent (default), or
 *   - sets a verdict bit that the SSL_write entry uprobe reads on
 *     the next call to short-circuit the write (Phase E.2).
 *
 * Library coverage notes
 * ----------------------
 * Today: dynamically-linked OpenSSL 1.1+ and BoringSSL on glibc.
 * Static-linked Go (`crypto/tls.(*Conn).Write`) and rustls land in
 * follow-on uprobe files; their signatures differ enough that
 * keeping them separate keeps the verifier simpler.
 *
 * Why entry+exit for SSL_read
 * ---------------------------
 * On entry we have the buffer pointer; we don't yet know how many
 * bytes were filled. On exit we have the byte count but the
 * register holding `buf` may have been clobbered. We stash the
 * buffer pointer in a per-thread map at entry and read it back at
 * exit — standard uprobe pattern.
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Hard cap per ringbuf event. 16KB is two pages on x86_64; bigger
// HTTP bodies arrive as multiple events that the userspace
// reassembler stitches by (pid, tgid, conn_id).
#define MAX_PLAINTEXT 16384

// Direction tags. Matches `TlsDirection` in the Rust mirror.
#define TLS_WRITE 1
#define TLS_READ  2

// Per-call event header.
//
// `conn_id` is the SSL* userspace pointer; opaque but stable for
// the life of the connection, which is what the reassembler keys on.
// `len` is the *captured* length (clamped to MAX_PLAINTEXT) — the
// actual plaintext may be longer; the reassembler treats truncation
// as "give up on this stream", which is the safe default for
// enforcement (we surface a `Truncated` decision rather than parse
// half a JSON body).
struct tls_event_hdr {
    __u64 cgroup_id;
    __u64 conn_id;
    __u32 pid;
    __u32 tgid;
    __u32 len;
    __u8  direction; // TLS_WRITE | TLS_READ
    __u8  truncated; // 1 if we hit MAX_PLAINTEXT
    __u8  _pad[2];
};

// Heap allocator: per-CPU array holding one tls_event so we don't
// blow the eBPF stack (512B limit). Layout matches what userspace
// reads directly from the ringbuf payload.
struct tls_event {
    struct tls_event_hdr hdr;
    __u8 data[MAX_PLAINTEXT];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tls_event);
} tls_event_scratch SEC(".maps");

// Output ringbuf. 1 MiB — sized to absorb burst chat traffic
// without dropping; userspace polls in tight loop with a per-tick
// fallback so this is mostly headroom.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} tls_events SEC(".maps");

// Per-thread "in-flight SSL_read" so uretprobe can recover the
// buffer pointer captured on entry.
struct ssl_read_args {
    __u64 ssl;
    __u64 buf;
    __u32 want;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);   // pid_tgid
    __type(value, struct ssl_read_args);
} ssl_read_inflight SEC(".maps");

static __always_inline void emit_event(__u8 direction,
                                       __u64 ssl_ptr,
                                       const void *user_buf,
                                       __s64 user_len) {
    if (user_len <= 0)
        return;

    __u32 zero = 0;
    struct tls_event *ev = bpf_map_lookup_elem(&tls_event_scratch, &zero);
    if (!ev)
        return;

    __u64 ptg = bpf_get_current_pid_tgid();
    ev->hdr.cgroup_id = bpf_get_current_cgroup_id();
    ev->hdr.conn_id   = ssl_ptr;
    ev->hdr.pid       = (__u32)(ptg >> 32);
    ev->hdr.tgid      = (__u32)ptg;
    ev->hdr.direction = direction;

    __u32 want = user_len > MAX_PLAINTEXT ? MAX_PLAINTEXT : (__u32)user_len;
    ev->hdr.truncated = (user_len > MAX_PLAINTEXT) ? 1 : 0;
    ev->hdr._pad[0]   = 0;
    ev->hdr._pad[1]   = 0;
    ev->hdr.len       = want;

    // Verifier-friendly bound: explicit constant cap so the loop
    // unroll knows the upper bound. bpf_probe_read_user returns 0
    // on success; a fault leaves stale bytes, so we'd rather skip.
    if (bpf_probe_read_user(ev->data, want, user_buf) != 0)
        return;

    // Reserve+copy in two steps because percpu-array gives us a
    // stable scratch pad outside the verifier-bounded ringbuf
    // reservation. Two memcpy on a 16KB buffer is fine on the hot
    // path — the alternative (read directly into a ringbuf
    // reservation) loses verifier checks for the variable len.
    void *dst = bpf_ringbuf_reserve(&tls_events, sizeof(*ev), 0);
    if (!dst)
        return;
    __builtin_memcpy(dst, ev, sizeof(*ev));
    bpf_ringbuf_submit(dst, 0);
}

// --- SSL_write(SSL *ssl, const void *buf, int num) -----------------
// Called pre-encryption. Plaintext is in `buf`. We capture on entry
// even though SSL_write may return short — the bytes we read will
// be sent on the next try, so we'd double-count. The userspace
// reassembler dedupes by (conn_id, monotonically-increasing offset)
// in a follow-on; for v1 we accept duplicate events on partial writes.
SEC("uprobe/SSL_write")
int BPF_KPROBE(uprobe_ssl_write, void *ssl, const void *buf, int num) {
    emit_event(TLS_WRITE, (__u64)ssl, buf, num);
    return 0;
}

// --- SSL_read(SSL *ssl, void *buf, int num) ------------------------
// Bytes only land in `buf` after the call returns. Stash the args
// at entry, read them back at uretprobe + use the return value
// (actual byte count) instead of `num`.
SEC("uprobe/SSL_read")
int BPF_KPROBE(uprobe_ssl_read, void *ssl, void *buf, int num) {
    __u64 key = bpf_get_current_pid_tgid();
    struct ssl_read_args args = {
        .ssl = (__u64)ssl,
        .buf = (__u64)buf,
        .want = (__u32)num,
    };
    bpf_map_update_elem(&ssl_read_inflight, &key, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int BPF_KRETPROBE(uretprobe_ssl_read, int ret) {
    __u64 key = bpf_get_current_pid_tgid();
    struct ssl_read_args *args = bpf_map_lookup_elem(&ssl_read_inflight, &key);
    if (!args)
        return 0;

    if (ret > 0) {
        emit_event(TLS_READ, args->ssl, (const void *)(unsigned long)args->buf, ret);
    }
    bpf_map_delete_elem(&ssl_read_inflight, &key);
    return 0;
}

char LICENSE[] SEC("license") = "MIT";
