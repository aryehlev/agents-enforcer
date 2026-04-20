#!/usr/bin/env bash
# Local reproducibility of the full tls-tap build. Mirrors the CI
# workflow step-by-step so "works on my machine" means the same
# thing as "works in CI".
#
# Usage:
#   tls-tap/scripts/smoke.sh           # build everything
#   tls-tap/scripts/smoke.sh --docker  # also build the container
#
# Requirements: rust stable + nightly, rust-src on nightly,
# bpf-linker, docker (for --docker).

set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> userspace: fmt + clippy + test"
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-features

echo "==> userspace: release binary"
cargo build --release

echo "==> bpf: build"
(
    cd bpf
    cargo +nightly build --release \
        --target bpfel-unknown-none \
        -Z build-std=core
)

BPF_OBJ=bpf/target/bpfel-unknown-none/release/tls-tap-bpf
echo "==> bpf: verify sections"
if ! readelf -S "$BPF_OBJ" | grep -q 'uprobe'; then
    echo "ERROR: no uprobe sections in BPF object" >&2
    exit 1
fi
echo "   $(stat -c '%s' "$BPF_OBJ") bytes, uprobe sections present"

if [[ "${1-}" == "--docker" ]]; then
    echo "==> docker: build image"
    docker build -t tls-tap:local .
    echo "==> image: $(docker image inspect tls-tap:local --format '{{.Size}}' | numfmt --to=iec)"
fi

echo "==> done"
