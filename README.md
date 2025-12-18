# Agent Gateway Enforcer

An eBPF-based security enforcer that restricts AI agent network traffic and file system access. Ensures agents can only communicate through designated gateways and access approved files/directories.

## Features

- **Network Enforcement**: Restrict all outbound traffic to whitelisted gateway IP:port
- **File Access Control**: Block or allow file operations using LSM BPF hooks
- **Cgroup-based Isolation**: Applies to all processes within a cgroup (containers, pods, systemd services)
- **Prometheus Metrics**: Monitor blocked connections and file access attempts
- **Dynamic Configuration**: Update rules via eBPF maps without restart

## How It Works

This tool uses two eBPF program types:

1. **`cgroup_skb/egress`** - Intercepts all network egress from monitored cgroups
2. **`LSM BPF`** - Intercepts file operations (open, read, write, delete, execute)

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

- Linux kernel 5.8+ (for `cgroup_skb` and LSM BPF support)
- Kernel compiled with `CONFIG_BPF_LSM=y` (for file access enforcement)
- LSM BPF enabled in boot parameters: `lsm=...,bpf` or via sysctl
- Rust nightly toolchain
- `bpf-linker` for eBPF compilation
- Root privileges to load eBPF programs
- BTF (BPF Type Format) support for LSM programs

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

This tool requires Linux kernel 5.8 or newer. Check your kernel version:

```bash
uname -r
```

## License

MIT
