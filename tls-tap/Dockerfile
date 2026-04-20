# Three-stage build: nightly for BPF, stable for userspace, slim
# distroless for runtime. The final image is just the binary and
# the BPF object — no build toolchain, no shell.
#
# Build locally:  docker build -t tls-tap tls-tap/
# Build in CI:    see .github/workflows/tls-tap.yml (uses buildx
#                 with layer caching for ~30s incrementals)

# ------------------------------------------------------------------
# Stage 1: eBPF program. Needs nightly + rust-src + bpf-linker.
# ------------------------------------------------------------------
FROM rust:1.83-bookworm AS bpf-builder
RUN rustup install nightly \
    && rustup component add rust-src --toolchain nightly \
    && cargo install bpf-linker --locked
WORKDIR /src
# Copy only what the bpf crate touches so the Docker cache stays
# useful: userspace-side edits don't invalidate the BPF layer.
COPY bpf/ bpf/
COPY shared/ shared/
WORKDIR /src/bpf
RUN cargo +nightly build --release \
    --target bpfel-unknown-none \
    -Z build-std=core

# ------------------------------------------------------------------
# Stage 2: userspace binary. Stable toolchain, everything in
# tls-tap/ plus the shared crate.
# ------------------------------------------------------------------
FROM rust:1.83-bookworm AS user-builder
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY shared/ shared/
COPY src/ src/
# Dummy bpf/ so the parent Cargo.toml's `exclude = ["bpf"]` still
# resolves — Cargo complains if the excluded path doesn't exist.
RUN mkdir -p bpf && echo "[package]\nname = \"dummy\"\nversion = \"0.0.0\"\nedition = \"2021\"" > bpf/Cargo.toml && mkdir -p bpf/src && echo "fn main(){}" > bpf/src/main.rs
RUN cargo build --release --bin tls-tap

# ------------------------------------------------------------------
# Stage 3: runtime. Distroless for surface area; the tls-tap binary
# needs CAP_BPF + CAP_SYS_PTRACE + CAP_PERFMON at runtime — those
# come from the DaemonSet securityContext, not the image.
#
# We can't use `distroless/static` because aya pulls libc for its
# dynamic loader interactions. `distroless/cc-debian12` is the
# minimum that actually runs; ~22 MB.
# ------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
LABEL org.opencontainers.image.source=https://github.com/aryehlev/tls-tap
LABEL org.opencontainers.image.description="eBPF TLS plaintext sensor"
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"

COPY --from=user-builder /src/target/release/tls-tap /usr/local/bin/tls-tap
COPY --from=bpf-builder /src/bpf/target/bpfel-unknown-none/release/tls-tap-bpf \
    /usr/lib/tls-tap/tls-tap-bpf

# Standard env-var hook the binary's find_object() checks first —
# explicit is better than relying on the candidate path walk.
ENV TLS_TAP_BPF_OBJ=/usr/lib/tls-tap/tls-tap-bpf

ENTRYPOINT ["/usr/local/bin/tls-tap"]
