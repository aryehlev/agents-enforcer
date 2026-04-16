# =============================================================================
# Agent Gateway Enforcer - Multi-stage Dockerfile
# =============================================================================

# Build: docker build -t agent-gateway-enforcer .
# Run:   docker run --privileged -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
#                   -v /sys/fs/bpf:/sys/fs/bpf \
#                   agent-gateway-enforcer run --gateway 10.0.0.1:8080
# -----------------------------------------------------------------------------
# 
# Stage 1: Build environment
# -----------------------------------------------------------------------------
FROM rust:1.75-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libelf-dev \
    linux-headers-generic \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install Rust nightly and components for eBPF
RUN rustup install nightly && \
    rustup component add rust-src --toolchain nightly

# Install bpf-linker
RUN cargo +nightly install bpf-linker

WORKDIR /app

# Copy workspace manifests first for better caching
COPY Cargo.toml rust-toolchain.toml ./
COPY .cargo ./.cargo

# Copy all package manifests
COPY agent-gateway-enforcer-common/Cargo.toml ./agent-gateway-enforcer-common/
COPY agent-gateway-enforcer-core/Cargo.toml ./agent-gateway-enforcer-core/
COPY agent-gateway-enforcer-cli/Cargo.toml ./agent-gateway-enforcer-cli/
COPY agent-gateway-enforcer-ebpf/Cargo.toml ./agent-gateway-enforcer-ebpf/
COPY agent-gateway-enforcer/Cargo.toml ./agent-gateway-enforcer/
COPY backends/ebpf-linux/Cargo.toml ./backends/ebpf-linux/
COPY xtask/Cargo.toml ./xtask/

# Create dummy source files to build dependencies
RUN mkdir -p agent-gateway-enforcer-common/src && echo 'fn main() {}' > agent-gateway-enforcer-common/src/lib.rs && \
    mkdir -p agent-gateway-enforcer-core/src && echo 'fn main() {}' > agent-gateway-enforcer-core/src/lib.rs && \
    mkdir -p agent-gateway-enforcer-cli/src && echo 'fn main() {}' > agent-gateway-enforcer-cli/src/main.rs && \
    mkdir -p agent-gateway-enforcer-ebpf/src && echo '#![no_std] #![no_main] #[panic_handler] fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }' > agent-gateway-enforcer-ebpf/src/main.rs && \
    mkdir -p agent-gateway-enforcer/src && echo 'fn main() {}' > agent-gateway-enforcer/src/main.rs && \
    mkdir -p backends/ebpf-linux/src && echo 'fn main() {}' > backends/ebpf-linux/src/lib.rs && \
    mkdir -p xtask/src && echo 'fn main() {}' > xtask/src/main.rs

# Build dependencies (this layer will be cached)
RUN cargo build --workspace --release || true

# Now copy actual source code
COPY . .

# Build workspace
RUN cargo build --workspace --release

# Build eBPF program (legacy support)
RUN cargo xtask build-ebpf --release || echo "eBPF build skipped"

# -----------------------------------------------------------------------------
# Stage 2: Runtime image
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libelf1 \
    ca-certificates \
    curl

# Create non-root user (note: eBPF requires CAP_BPF, usually run as root)
RUN useradd -m -s /bin/bash enforcer

# Copy built artifacts
COPY --from=builder /app/target/release/agent-gateway-enforcer-cli /usr/local/bin/agent-gateway-enforcer
COPY --from=builder /app/target/bpf/ /usr/local/share/agent-gateway-enforcer/ || echo "No eBPF artifacts"

# Set working directory
WORKDIR /app

# Default environment
ENV RUST_LOG=info

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f -s http://localhost:9090/health || exit 1

# Expose metrics port
EXPOSE 9090

# Note: Container must run with --privileged or specific capabilities:
# --cap-add=SYS_ADMIN --cap-add=BPF --cap-add=NET_ADMIN

# Plus volume mounts for /sys/fs/cgroup and /sys/fs/bpf
VOLUME ["/sys/fs/cgroup", "/sys/fs/bpf"]

ENTRYPOINT ["agent-gateway-enforcer"]
CMD ["--help"]