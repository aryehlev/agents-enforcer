# tls-tap-bpf

The eBPF program. Written in Rust with `aya-ebpf`, compiles to BPF
bytecode. The userspace `tls-tap` crate loads the resulting object
at runtime via `aya`.

## Build

```bash
# One-time toolchain setup
rustup install nightly
rustup component add rust-src --toolchain nightly

# Build the BPF object
cd bpf
cargo +nightly build --release \
    --target bpfel-unknown-none \
    -Z build-std=core
```

Output: `bpf/target/bpfel-unknown-none/release/tls-tap-bpf` (ELF
with `.text` containing the BPF programs the userspace loader
attaches by name: `uprobe_ssl_write`, `uprobe_ssl_read`,
`uretprobe_ssl_read`).

## Why a separate crate

Cargo's nightly `-Z build-std=core` flag and the
`bpfel-unknown-none` target apply to every crate in a workspace.
Keeping the BPF program in its own out-of-workspace crate means
`cargo test` and `cargo build` on the userspace library don't
inherit those constraints — userspace stays plain stable Rust.

## Why aya-ebpf instead of C

- Same language top to bottom — types in `tls-tap-shared` are
  used by both the kernel and the userspace consumer with
  no risk of layout drift.
- No clang / libbpf-headers build dep — `cargo` does it.
- The verifier errors look the same either way; macros in
  `aya-ebpf` are thin sugar over the same kernel helpers C
  programs call.

## Why the `staticlib` crate-type

`aya-ebpf` programs build as a `staticlib`; the linker output is
an ELF object the BPF loader treats as a "BPF program file." The
`.text` section holds one program per `#[uprobe]` / `#[uretprobe]`
function, and the loader matches by symbol name.
