# =============================================================================
# Agent Gateway Enforcer - Multi-stage Dockerfile
# =============================================================================
#
# Build: docker build -t agent-gateway-enforcer .
# Run:   docker run --privileged -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
#                   -v /sys/fs/bpf:/sys/fs/bpf \
#                   agent-gateway-enforcer run --gateway 10.0.0.1:8080
#
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build environment
# -----------------------------------------------------------------------------
FROM rust:latest AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    linux-headers-generic \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install Rust nightly and components
RUN rustup install nightly && \
    rustup default nightly && \
    rustup component add rust-src

# Install bpf-linker
RUN cargo install bpf-linker

WORKDIR /app

# Copy manifests first for better caching
COPY Cargo.toml rust-toolchain.toml ./
COPY .cargo ./.cargo
COPY agent-gateway-enforcer-common/Cargo.toml ./agent-gateway-enforcer-common/
COPY agent-gateway-enforcer-ebpf/Cargo.toml ./agent-gateway-enforcer-ebpf/
COPY agent-gateway-enforcer/Cargo.toml ./agent-gateway-enforcer/
COPY xtask/Cargo.toml ./xtask/

# Create dummy source files to build dependencies
RUN mkdir -p agent-gateway-enforcer-common/src && \
    echo '#![no_std]' > agent-gateway-enforcer-common/src/lib.rs && \
    mkdir -p agent-gateway-enforcer-ebpf/src && \
    echo '#![no_std] #![no_main] #[panic_handler] fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }' > agent-gateway-enforcer-ebpf/src/main.rs && \
    mkdir -p agent-gateway-enforcer/src && \
    echo 'fn main() {}' > agent-gateway-enforcer/src/main.rs && \
    mkdir -p xtask/src && \
    echo 'fn main() {}' > xtask/src/main.rs

# Build dependencies (this layer will be cached)
RUN cargo build --package agent-gateway-enforcer-common --release || true
RUN cargo build --package xtask --release || true

# Now copy actual source code
COPY agent-gateway-enforcer-common/src ./agent-gateway-enforcer-common/src
COPY agent-gateway-enforcer-ebpf/src ./agent-gateway-enforcer-ebpf/src
COPY agent-gateway-enforcer/src ./agent-gateway-enforcer/src
COPY xtask/src ./xtask/src

# Touch to invalidate cache
RUN touch agent-gateway-enforcer-common/src/lib.rs \
    agent-gateway-enforcer-ebpf/src/main.rs \
    agent-gateway-enforcer/src/main.rs \
    xtask/src/main.rs

# Build eBPF program
RUN cargo xtask build-ebpf --release

# Build userspace daemon
RUN cargo build --package agent-gateway-enforcer --release

# -----------------------------------------------------------------------------
# Stage 2: Runtime image
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libelf1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user (note: eBPF requires CAP_BPF, usually run as root)
RUN useradd -m -s /bin/bash enforcer

# Copy built artifacts
COPY --from=builder /app/target/release/agent-gateway-enforcer /usr/local/bin/
COPY --from=builder /app/target/bpf/ /usr/local/share/agent-gateway-enforcer/

# Set working directory
WORKDIR /app

# Default environment
ENV RUST_LOG=info

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:9090/health || exit 1

# Expose metrics port
EXPOSE 9090

# Note: Container must run with --privileged or specific capabilities:
# --cap-add=SYS_ADMIN --cap-add=BPF --cap-add=NET_ADMIN
# Plus volume mounts for /sys/fs/cgroup and /sys/fs/bpf

ENTRYPOINT ["agent-gateway-enforcer"]
CMD ["--help"]
