# Agent Gateway Enforcer

An eBPF-based security enforcer that restricts AI agent network traffic and file system access. Ensures agents can only communicate through designated gateways and access approved files/directories.

## Features

- **Network Enforcement**: Restrict all outbound traffic to whitelisted gateway IP:port combinations
- **File Access Control**: Block or allow file operations using LSM BPF hooks
- **Cgroup-based**: Apply policies to all processes within a cgroup
- **Prometheus Metrics**: Monitor blocked connections and file access attempts
- **Dynamic Configuration**: Update rules via eBPF maps without restart

## Architecture

```mermaid
sequenceDiagram
    participant Kernel as Kernel (cgroup_skb)
    participant eBPF as eBPF Program
    participant Maps as eBPF Maps
    participant Perf as Perf Buffer
    participant Daemon as Userspace Daemon
    participant Metrics as Prometheus Registry
    HTTP Server as HTTP Server

    Kernel->eBPF: Egress packet (IPv4/TCP/UDP)
    eBPF->Maps: Lookup GatewayKey in ALLOWED_GATEWAYS
    Maps->>Perf Array: Increment BLOCKED_METRICS[BlockedKey]
    Perf->Daemon: BlockedEvent
    Daemon->Metrics: Update blocked counter

    Daemon->HTTP: Prometheus Registry
```

## How It Works

1. **Load eBPF**: The userspace daemon loads the eBPF bytecode and attaches it to a cgroup
2. **Attach to Cgroup**: Uses `cgroup_skb/egress` hook to intercept all network egress
3. **Populate Maps**: Insert allowed gateways into `ALLOWED_GATEWAYS` map
4. **Process Events**: Updates metrics and sends blocked events via perf buffers

## Security Benefits

- **Zero Trust Model**: Unlike traditional firewalls that operate at L3/L4, this enforcer operates at kernel level for complete visibility
- **Fine-grained Control**: Can enforce both network AND file access with a single system
- **Low Overhead**: eBPF programs run in kernel space, minimal overhead
- **Portable**: Works on any Linux system with eBPF support

## Quick Start

```bash
# Start enforcer with a gateway
sudo ./target/release/agent-gateway-enforcer run \
    --gateway 10.0.0.1:8080 \
    --cgroup /sys/fs/cgroup

# Monitor metrics
curl http://localhost:9090/metrics
```

## Test Network Enforcement

```bash
# Should fail (blocked by firewall)
curl google.com 80 -v

# Should succeed (allowed through gateway)
curl 10.0.0.1:8080
```

## Test File Access

```bash
# Should be denied (access to /etc/passwd)
sudo ./target/release/agent-gateway-enforcer run \
    --enable-file-enforcement \
    --deny-path /etc/passwd \
    --cgroup /sys/fs/cgroup

# Should be allowed (access to /tmp/app.log)
sudo ./target/release/agent-gateway-enforcer run \
    --allow-path /tmp \
    --cgroup /sys/fs/cgroup
```

## Monitor Blocked Events

```bash
# Watch for blocked events
strace -p agent_gateway_enforcer

# In another terminal:
curl http://localhost:9090/metrics
```
┌─────────────────────────────────────────────────────────────┐
│                    Customer Infrastructure                   │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │  AI Agent 1  │    │  AI Agent 2  │    │  AI Agent N  │   │
│  │  (cgroup)    │    │  (cgroup)    │    │  (cgroup)    │   │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘   │
│         │                   │                   │           │
│         ▼                   ▼                   ▼           │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              eBPF Traffic Controller                    ││
│  │  - Intercepts all egress from monitored cgroups         ││
│  │  - Allows only → Gateway IP:Port                        ││
│  │  - Drops + counts all other destinations                ││
│  └─────────────────────────────────────────────────────────┘│
│                            │                                 │
│                            ▼ (allowed)                       │
│                   ┌────────────────┐                        │
│                   │    Gateway     │ ──────► External APIs   │
│                   └────────────────┘                        │
└─────────────────────────────────────────────────────────────┘
```

## Requirements

### Kernel Requirements

**Minimum:** Linux kernel 5.15
- **5.15+** for stable BPF_LINK_TYPE and modern eBPF features
- **5.19+** recommended for improved LSM BPF stability and additional helpers
- **6.1+** preferred for best performance and feature completeness

#### Kernel Configuration

The following kernel configuration options must be enabled:

```
# Core eBPF support
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y                     # For better performance

# BTF (BPF Type Format) - required for modern eBPF
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_BTF=y

# LSM BPF support (for file access enforcement)
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_BPF_LSM=y                     # Available from 5.7+

# Network filtering support (for network enforcement)
CONFIG_NETFILTER=y
CONFIG_NET_CLS_BPF=y
CONFIG_NET_ACT_BPF=y

# Cgroup support (for attaching eBPF to cgroups)
CONFIG_CGROUPS=y
CONFIG_CGROUP_BPF=y
```

#### Runtime Configuration

For LSM BPF to work properly, the BPF LSM must be enabled at runtime:

```bash
# Method 1: Kernel boot parameter
lsm=lockdown,capability,bpf

# Method 2: Runtime (requires CONFIG_LSM_HOOK)
echo "bpf" > /sys/kernel/security/lsm

# Method 3: Check if BPF LSM is loaded
cat /sys/kernel/security/lsm
```

### Distribution Support

**Recommended distributions with modern kernels:**
- **Ubuntu 22.04+** (kernel 5.15+, kernel 6.2 in HWE)
- **Debian 12+** (kernel 6.1+)
- **RHEL 9+** (kernel 5.14+ with backports)
- **Fedora 37+** (kernel 6.0+)
- **Arch Linux** (rolling, always recent)
- **AlmaLinux 9+** / **Rocky Linux 9+** (kernel 5.14+ with backports)

**Legacy distributions (may require kernel upgrade):**
- Ubuntu 20.04: Upgrade to HWE kernel (5.15+)
- RHEL 8: Update to 8.8+ for backported eBPF features
- Debian 11: Upgrade to kernel 5.15+ from backports

### Development Requirements

- **Rust nightly toolchain** (required for eBPF compilation)
- **bpf-linker** for eBPF compilation
- **Root privileges** to load eBPF programs
- **libbpf** development libraries (usually included with kernel headers)

### Installation Commands

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y linux-headers-$(uname -r) build-essential
sudo apt install -y libbpf-dev libelf-dev

# RHEL/Fedora
sudo dnf install -y kernel-devel kernel-headers
sudo dnf install -y libbpf-devel elfutils-libelf-devel

# Install Rust and bpf-linker
rustup install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker
```

### Verification

Check that your system supports the required features:

```bash
# Check kernel version
uname -r  # Should be 5.15+ (5.19+ recommended)

# Check BTF support
test -f /sys/kernel/btf/vmlinux && echo "BTF: OK" || echo "BTF: Missing"

# Check BPF LSM support
grep -q bpf /sys/kernel/security/lsm 2>/dev/null && echo "LSM: OK" || echo "LSM: Not loaded"

# Check cgroup v2
test -f /sys/fs/cgroup/cgroup.controllers && echo "Cgroup2: OK" || echo "Cgroup2: Missing"
```

## Installation

### Install Dependencies

```bash
# Install Rust nightly
rustup install nightly
rustup component add rust-src --toolchain nightly

# Install bpf-linker
cargo install bpf-linker
```

### Build

```bash
# Build the eBPF program
cargo xtask build-ebpf

# Build the userspace daemon
cargo xtask build

# Or build both
cargo xtask build-all

# For release builds
cargo xtask build-all --release
```

## Usage

### Running the Daemon

```bash
# Run with a single gateway
sudo ./target/debug/agent-gateway-enforcer run \
    --gateway 10.0.0.1:8080 \
    --cgroup /sys/fs/cgroup/user.slice

# Run with multiple gateways
sudo ./target/debug/agent-gateway-enforcer run \
    --gateway 10.0.0.1:8080 \
    --gateway 10.0.0.2:443 \
    --cgroup /sys/fs/cgroup/docker

# Custom metrics port
sudo ./target/debug/agent-gateway-enforcer run \
    --gateway 10.0.0.1:8080 \
    --cgroup /sys/fs/cgroup \
    --metrics-port 9091
```

### File Access Enforcement

Enable file access control with LSM BPF hooks:

```bash
# Blocklist mode (default): allow all except denied paths
sudo ./target/debug/agent-gateway-enforcer run \
    --gateway 10.0.0.1:8080 \
    --cgroup /sys/fs/cgroup/agents \
    --enable-file-enforcement \
    --deny-path /etc/passwd \
    --deny-path /etc/shadow \
    --deny-path /root \
    --deny-path /home

# Allowlist mode: deny all except allowed paths
sudo ./target/debug/agent-gateway-enforcer run \
    --gateway 10.0.0.1:8080 \
    --cgroup /sys/fs/cgroup/agents \
    --enable-file-enforcement \
    --default-deny-files \
    --allow-path /tmp \
    --allow-path /app/workspace \
    --allow-path /var/log/agent

# Combined: allowlist with specific denials
sudo ./target/debug/agent-gateway-enforcer run \
    --gateway 10.0.0.1:8080 \
    --cgroup /sys/fs/cgroup/agents \
    --enable-file-enforcement \
    --allow-path /app \
    --deny-path /app/secrets
```

#### File Operations Intercepted

| LSM Hook | Operation |
|----------|-----------|
| `file_open` | Opening files |
| `file_permission` | Reading, writing, executing files |
| `path_unlink` | Deleting files |
| `path_mkdir` | Creating directories |
| `path_rmdir` | Removing directories |
| `bprm_check_security` | Executing programs |

### Metrics

The daemon exposes Prometheus metrics on the configured port (default 9090):

```bash
# View metrics
curl http://localhost:9090/metrics
```

Available metrics:
- `agent_gateway_blocked_total{dst_ip, dst_port, protocol}` - Count of blocked connections
- `agent_gateway_allowed_total` - Count of allowed connections

### Health Check

```bash
curl http://localhost:9090/health
```

## Cgroup Configuration

### Docker Containers

To restrict Docker containers, attach to the Docker cgroup:

```bash
sudo ./target/debug/agent-gateway-enforcer run \
    --gateway YOUR_GATEWAY_IP:PORT \
    --cgroup /sys/fs/cgroup/system.slice/docker.service
```

### Kubernetes Pods

For Kubernetes, attach to the pod's cgroup:

```bash
# Find the pod's cgroup
POD_CGROUP=$(cat /proc/<PID>/cgroup | grep -oP '(?<=::/)[^:]+' | head -1)

sudo ./target/debug/agent-gateway-enforcer run \
    --gateway YOUR_GATEWAY_IP:PORT \
    --cgroup /sys/fs/cgroup/${POD_CGROUP}
```

### Systemd Services

```bash
sudo ./target/debug/agent-gateway-enforcer run \
    --gateway YOUR_GATEWAY_IP:PORT \
    --cgroup /sys/fs/cgroup/system.slice/your-agent.service
```

## Project Structure

```
agent-gateway-enforcer/
├── Cargo.toml                    # Workspace root
├── agent-gateway-enforcer/       # Userspace daemon
│   ├── Cargo.toml
│   └── src/main.rs
├── agent-gateway-enforcer-ebpf/  # eBPF program
│   ├── Cargo.toml
│   └── src/main.rs
├── agent-gateway-enforcer-common/ # Shared types
│   ├── Cargo.toml
│   └── src/lib.rs
└── xtask/                        # Build tooling
    ├── Cargo.toml
    └── src/main.rs
```

## Troubleshooting

### Permission Denied

The daemon requires root privileges to load eBPF programs:

```bash
sudo ./target/debug/agent-gateway-enforcer run ...
```

### eBPF Program Not Found

Make sure to build the eBPF program first:

```bash
cargo xtask build-ebpf
```

### Kernel Too Old

This tool requires Linux kernel 5.15 or newer (5.19+ recommended). Check your kernel version:

```bash
uname -r
```

For older systems, consider:
- **Ubuntu 20.04**: `sudo apt install linux-image-generic-hwe-20.04`
- **RHEL 8**: Update to 8.8+ for backported eBPF features
- **Debian 11**: Use backports kernel (`linux-image-6.1.0-0.deb11.6-amd64`)

### BTF Support Missing

If you see BTF-related errors:

```bash
# Check if BTF is available
test -f /sys/kernel/btf/vmlinux || echo "BTF not available"

# Ubuntu/Debian: Install debug info
sudo apt install linux-image-$(uname -r)-dbgsym

# RHEL/Fedora: Install debug info
sudo dnf debuginfo-install kernel-$(uname -r)
```

### LSM BPF Not Working

If file access enforcement fails:

```bash
# Check if BPF LSM is loaded
cat /sys/kernel/security/lsm

# Add BPF to LSM stack if missing
echo "bpf" | sudo tee /sys/kernel/security/lsm

# Or reboot with lsm=... parameter
```

### Permission Denied

The daemon requires root privileges to load eBPF programs:

```bash
sudo ./target/debug/agent-gateway-enforcer run ...
```

### eBPF Program Not Found

Make sure to build the eBPF program first:

```bash
cargo xtask build-ebpf
```

## License

MIT
