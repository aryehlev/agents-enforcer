# Agent Gateway Enforcer - Development Roadmap

## Phase 1: Testing

### 1.1 Unit Tests

**Location**: `agent-gateway-enforcer/src/tests/` and `agent-gateway-enforcer-common/src/tests/`

| Component | Tests |
|-----------|-------|
| `GatewayKey` | Serialization, byte order conversion |
| `PathKey` | Path construction, truncation handling |
| `PathRule` | Allow/deny rule creation |
| CLI parsing | Argument validation, defaults |
| Gateway address parsing | Valid/invalid IP:port formats |

```rust
// Example test structure
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gateway_key_byte_order() {
        let key = GatewayKey::new(0x0A000001, 8080); // 10.0.0.1:8080
        assert_eq!(key.addr, 0x0100000A_u32.to_be());
    }

    #[test]
    fn test_path_key_truncation() {
        let long_path = "a".repeat(300);
        let key = PathKey::new(&long_path);
        assert_eq!(key.len, 255);
    }
}
```

### 1.2 Integration Tests

**Location**: `tests/integration/`

| Test | Description |
|------|-------------|
| `test_ebpf_load` | Load eBPF program successfully |
| `test_gateway_map_operations` | Insert/delete/query gateway map |
| `test_path_rules_map` | Insert/delete/query path rules |
| `test_metrics_endpoint` | Prometheus metrics HTTP endpoint |
| `test_health_endpoint` | Health check returns 200 |

**Requirements**:
- Linux VM or container for eBPF tests
- Root privileges
- Kernel 5.8+

### 1.3 End-to-End Tests

**Location**: `tests/e2e/`

| Scenario | Steps |
|----------|-------|
| Network blocking | 1. Start enforcer with gateway 10.0.0.1:8080<br>2. Attempt curl to google.com → should fail<br>3. Attempt curl to 10.0.0.1:8080 → should succeed |
| File blocking | 1. Start enforcer with --deny-path /tmp/blocked<br>2. Attempt to read /tmp/blocked/file → should fail<br>3. Attempt to read /tmp/allowed/file → should succeed |
| Metrics collection | 1. Generate blocked traffic<br>2. Query /metrics endpoint<br>3. Verify counters incremented |

---

## Phase 2: CI/CD Pipeline

### 2.1 GitHub Actions Workflow

**File**: `.github/workflows/ci.yml`

```yaml
name: CI

on:
  push:
    branches: [main, feature/*]
  pull_request:
    branches: [main]

jobs:
  # Fast checks - run on every push
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
        with:
          components: rustfmt, clippy
      - run: cargo fmt --all -- --check
      - run: cargo clippy --workspace --all-targets -- -D warnings

  # Build userspace only (can run on any OS)
  build-userspace:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - uses: Swatinem/rust-cache@v2
      - run: cargo build --package agent-gateway-enforcer-common
      # Note: Full build requires Linux + bpf-linker

  # Unit tests (no eBPF)
  test-unit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - run: cargo test --package agent-gateway-enforcer-common

  # eBPF build + integration tests (requires special runner)
  test-ebpf:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/aya-rs/aya-build:latest
      options: --privileged
    steps:
      - uses: actions/checkout@v4
      - name: Install bpf-linker
        run: cargo install bpf-linker
      - name: Build eBPF
        run: cargo xtask build-ebpf
      - name: Build userspace
        run: cargo xtask build
      - name: Run integration tests
        run: cargo test --test integration -- --test-threads=1

  # Build release artifacts
  build-release:
    needs: [lint, test-unit, test-ebpf]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - name: Build release
        run: cargo xtask build-all --release
      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: agent-gateway-enforcer
          path: target/release/agent-gateway-enforcer
```

### 2.2 Release Workflow

**File**: `.github/workflows/release.yml`

```yaml
name: Release

on:
  push:
    tags: ['v*']

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build release binaries
        run: cargo xtask build-all --release
      - name: Create GitHub Release
        uses: softprops/action-gh-release@v1
        with:
          files: |
            target/release/agent-gateway-enforcer
            target/bpf/agent-gateway-enforcer.bpf.o
      - name: Build and push Docker image
        run: |
          docker build -t ghcr.io/${{ github.repository }}:${{ github.ref_name }} .
          docker push ghcr.io/${{ github.repository }}:${{ github.ref_name }}
```

---

## Phase 3: Deployment Options

### 3.1 Docker Image

**File**: `Dockerfile`

```dockerfile
# Build stage
FROM ghcr.io/aya-rs/aya-build:latest AS builder
WORKDIR /app
COPY . .
RUN cargo install bpf-linker
RUN cargo xtask build-all --release

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libelf1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/agent-gateway-enforcer /usr/local/bin/
COPY --from=builder /app/target/bpf/agent-gateway-enforcer.bpf.o /usr/local/share/

ENTRYPOINT ["agent-gateway-enforcer"]
```

### 3.2 Helm Chart

**Directory structure**: `deploy/helm/agent-gateway-enforcer/`

```
deploy/helm/agent-gateway-enforcer/
├── Chart.yaml
├── values.yaml
├── templates/
│   ├── _helpers.tpl
│   ├── daemonset.yaml
│   ├── configmap.yaml
│   ├── serviceaccount.yaml
│   ├── rbac.yaml
│   ├── service.yaml
│   └── servicemonitor.yaml (for Prometheus Operator)
```

**Key files**:

`Chart.yaml`:
```yaml
apiVersion: v2
name: agent-gateway-enforcer
description: eBPF-based gateway enforcer for AI agents
version: 0.1.0
appVersion: "0.1.0"
```

`values.yaml`:
```yaml
image:
  repository: ghcr.io/aryehlev/agents-enforcer
  tag: latest
  pullPolicy: IfNotPresent

# Gateway configuration
gateways:
  - "10.0.0.1:8080"

# File access enforcement
fileEnforcement:
  enabled: false
  defaultDeny: false
  allowPaths: []
  denyPaths:
    - /etc/shadow
    - /root

# Target cgroup (usually auto-detected)
cgroup: "/sys/fs/cgroup"

# Metrics
metrics:
  enabled: true
  port: 9090
  serviceMonitor:
    enabled: false

# Resources
resources:
  limits:
    cpu: 100m
    memory: 128Mi
  requests:
    cpu: 50m
    memory: 64Mi

# Node selector for Linux nodes
nodeSelector:
  kubernetes.io/os: linux

# Tolerations for running on all nodes
tolerations:
  - operator: Exists
```

`templates/daemonset.yaml`:
```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: {{ include "agent-gateway-enforcer.fullname" . }}
spec:
  selector:
    matchLabels:
      app: {{ include "agent-gateway-enforcer.name" . }}
  template:
    metadata:
      labels:
        app: {{ include "agent-gateway-enforcer.name" . }}
    spec:
      serviceAccountName: {{ include "agent-gateway-enforcer.serviceAccountName" . }}
      hostPID: true
      hostNetwork: true
      containers:
        - name: enforcer
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          securityContext:
            privileged: true
          args:
            - run
            {{- range .Values.gateways }}
            - --gateway={{ . }}
            {{- end }}
            - --cgroup={{ .Values.cgroup }}
            - --metrics-port={{ .Values.metrics.port }}
            {{- if .Values.fileEnforcement.enabled }}
            - --enable-file-enforcement
            {{- if .Values.fileEnforcement.defaultDeny }}
            - --default-deny-files
            {{- end }}
            {{- range .Values.fileEnforcement.allowPaths }}
            - --allow-path={{ . }}
            {{- end }}
            {{- range .Values.fileEnforcement.denyPaths }}
            - --deny-path={{ . }}
            {{- end }}
            {{- end }}
          volumeMounts:
            - name: cgroup
              mountPath: /sys/fs/cgroup
              readOnly: true
            - name: bpf
              mountPath: /sys/fs/bpf
            - name: debugfs
              mountPath: /sys/kernel/debug
          ports:
            - containerPort: {{ .Values.metrics.port }}
              name: metrics
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
      volumes:
        - name: cgroup
          hostPath:
            path: /sys/fs/cgroup
        - name: bpf
          hostPath:
            path: /sys/fs/bpf
        - name: debugfs
          hostPath:
            path: /sys/kernel/debug
      {{- with .Values.nodeSelector }}
      nodeSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with .Values.tolerations }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
```

### 3.3 Kustomize

**Directory**: `deploy/kustomize/`

```
deploy/kustomize/
├── base/
│   ├── kustomization.yaml
│   ├── daemonset.yaml
│   ├── configmap.yaml
│   └── rbac.yaml
└── overlays/
    ├── dev/
    │   └── kustomization.yaml
    └── prod/
        └── kustomization.yaml
```

### 3.4 Systemd Service

**File**: `deploy/systemd/agent-gateway-enforcer.service`

```ini
[Unit]
Description=Agent Gateway Enforcer
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/agent-gateway-enforcer run \
    --gateway 10.0.0.1:8080 \
    --cgroup /sys/fs/cgroup \
    --metrics-port 9090
Restart=always
RestartSec=5

# Security hardening (note: still needs CAP_BPF)
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_BPF CAP_NET_ADMIN
AmbientCapabilities=CAP_SYS_ADMIN CAP_BPF CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

---

## Phase 4: Documentation

| Document | Purpose |
|----------|---------|
| `docs/architecture.md` | System design, eBPF program flow |
| `docs/deployment.md` | Kubernetes, Docker, systemd guides |
| `docs/troubleshooting.md` | Common issues and solutions |
| `docs/api.md` | Metrics, health endpoints |
| `CONTRIBUTING.md` | Development setup, PR guidelines |

---

## Implementation Priority

1. **High Priority** (Week 1-2)
   - Unit tests for common types
   - Basic CI pipeline (lint + build)
   - Dockerfile

2. **Medium Priority** (Week 3-4)
   - Integration tests with eBPF
   - Helm chart
   - Release workflow

3. **Lower Priority** (Week 5+)
   - E2E tests
   - Kustomize overlays
   - ServiceMonitor for Prometheus Operator
   - Documentation
