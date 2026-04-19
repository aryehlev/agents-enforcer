# tls-tap

eBPF TLS plaintext sensor. Captures `SSL_write` / `SSL_read` payloads
**before encryption / after decryption**, attributes each event to the
calling process's cgroup, and emits structured events on a tokio
broadcast channel.

**This is a library**, not a product. It does one thing — get
plaintext off TLS-encrypted traffic without modifying it — and
hands the bytes to whatever consumer you build on top.

## What it isn't

- ❌ A policy engine. No allow/deny logic.
- ❌ A proxy. The agent's traffic still flows directly to the
  upstream over TLS; this just snoops the plaintext side.
- ❌ Kubernetes-coupled. The library knows nothing about pods or
  CRDs. You bring your own attribution (cgroup-id → whatever).
- ❌ A complete observability stack. No UI, no storage, no
  alerting. Pipe events into your existing tools.

## What it is

- ✅ One eBPF C program (uprobes on `SSL_write` / `SSL_read`).
- ✅ A pluggable userspace recipe system that finds the right
  symbols in the right binaries (OpenSSL, BoringSSL, Node.js
  today; Go / rustls / Java are recipe additions).
- ✅ A reassembler that stitches multi-chunk SSL_write calls
  back into one logical message per connection.
- ✅ A CLI that streams events to stdout as JSON for piping
  into `jq`, `vector`, or your demo.

## Coverage today

| Runtime | TLS stack | Status |
|---|---|---|
| Python, Ruby, PHP, C/C++ | libssl.so (dynamic) | ✅ |
| Node.js (nodejs.org releases) | bundled BoringSSL | ✅ |
| Go (statically linked) | crypto/tls | recipe stub — add yours |
| Rust (rustls) | rustls | recipe stub — add yours |
| Java | SSLEngine via JNI | recipe stub — add yours |
| Stripped Alpine static OpenSSL | static libssl | needs byte pattern |

Adding a runtime = one file in `src/uprobes/recipes/` + a line in the
recipe list.

## Stack

Rust top to bottom — both the kernel program (via [`aya-ebpf`]) and
the userspace loader (via [`aya`]). No clang, no libbpf headers, no
Makefile. Wire types live in `tls-tap-shared` so the BPF program
and userspace consumer use the same `repr(C)` definitions.

[`aya-ebpf`]: https://crates.io/crates/aya-ebpf
[`aya`]: https://crates.io/crates/aya

```
tls-tap/
├── shared/   # repr(C) wire types, no_std, used by both halves
├── bpf/      # the eBPF program (compiles to BPF bytecode)
└── src/      # userspace library + CLI
```

## Quickstart

```bash
# Build the BPF program (one-time toolchain setup in bpf/README.md)
cd bpf && cargo +nightly build --release \
    --target bpfel-unknown-none -Z build-std=core
cd ..

# Build + run the demo binary as root
cargo build --release
sudo TLS_TAP_BPF_OBJ=bpf/target/bpfel-unknown-none/release/tls-tap-bpf \
    target/release/tls-tap --pid 12345
```

Output:
```json
{"cgroup_id":4026531835,"pid":12345,"direction":"write","len":248,"truncated":false,"plaintext":"POST /v1/chat/completions HTTP/1.1\r\n…"}
```

## Embedding

```rust
use tls_tap::{Tap, recipes};

let tap = Tap::load()?;                  // mmap the eBPF object
tap.attach_to_pid(12345)?;               // resolves symbols, attaches uprobes
let mut events = tap.subscribe();        // tokio broadcast::Receiver<TlsEvent>
while let Ok(ev) = events.recv().await {
    println!("{} bytes from cgroup {}", ev.plaintext.len(), ev.cgroup_id);
}
```

## Threat model

`tls-tap` is observation, not enforcement. A process that controls
its own memory can defeat any plaintext-side probe (custom TLS,
in-process encryption, syscall-bypass). For enforcement guarantees,
combine with kernel-level egress controls (`cgroup/connect4`).

## Design notes

- Per-CPU scratch event in the kernel keeps stack usage at zero.
- Ringbuf is 1 MiB per node; userspace polls in a tight loop with
  10ms backoff so bursts don't drop.
- Plaintext is clamped to 16 KiB per event; longer payloads
  produce multiple events and the userspace `Reassembler`
  stitches them by `(conn_id, direction)`.
- Symbol resolution uses ELF `.dynsym` first, falls back to
  `.symtab` for unstripped statically-linked binaries.
- Recipes return *plans*; the framework dedups identical
  (binary, offset, is_ret) so one libssl on disk → one attach,
  not N.

## License

MIT OR Apache-2.0, your choice.
