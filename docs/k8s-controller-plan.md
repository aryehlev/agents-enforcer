# Next Level: eBPF-Powered Native Kubernetes Agents Controller

> **Vision**: Evolve `agents-enforcer` from a single-policy node daemon into a
> **Kubernetes-native controller** that delivers **complete control** (per-pod,
> per-agent, policy-driven enforcement in the kernel) and **complete
> observability** (every syscall-level agent action surfaced through the K8s
> API, Prometheus, and OpenTelemetry).

This plan complements [`ROADMAP.md`](../ROADMAP.md) (testing, CI, packaging)
and focuses on the K8s-native architectural leap. Existing components to
reuse are referenced by path.

---

## 1. Guiding Principles

1. **Kernel-enforced, not just kernel-observed.** eBPF LSM + cgroup attach per
   pod — violations never leave the kernel.
2. **Declarative API only.** All policy authored as CRs; the controller is
   the single source of truth. No CLI side-channel in prod.
3. **Identity is a pod, not an IP.** Rules are resolved via pod labels →
   cgroup v2 path → eBPF map keys. IPs are caches, not identity.
4. **Zero-trust default.** Namespaces opt in; enabled namespaces default-deny
   egress + file I/O outside declared allowlists.
5. **Observability is a first-class policy output.** Every decision (allow,
   deny, audit) is a structured event with pod/namespace/policy attribution.

---

## 2. Target Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Control Plane (1 pod)                    │
│  ┌────────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │   Controller   │  │  Admission   │  │   Aggregator   │  │
│  │  (kube-rs)     │  │  Webhook     │  │  (metrics/logs)│  │
│  └───────┬────────┘  └──────┬───────┘  └────────┬───────┘  │
└──────────┼──────────────────┼────────────────────┼──────────┘
           │  policy bundle   │                    │ events
           ▼ (gRPC/streaming) │                    ▲
┌─────────────────────────────────────────────────────────────┐
│                  Node Agent DaemonSet (per node)             │
│  ┌────────────────────────────────────────────────────────┐ │
│  │            Node Agent (Rust, reuses core/)             │ │
│  │  • Pod watcher (local kubelet CRI / PLEG)              │ │
│  │  • Cgroup resolver (pod UID → /sys/fs/cgroup/...)      │ │
│  │  • eBPF map programmer                                 │ │
│  │  • Ring-buffer consumer → Aggregator                   │ │
│  └──────────────┬─────────────────────────────────────────┘ │
│                 │ maps/progs                                 │
│  ┌──────────────▼─────────────────────────────────────────┐ │
│  │                   eBPF Data Plane                      │ │
│  │  cgroup/connect4/6 · sock_ops · LSM file_* · bprm_*    │ │
│  │  tc egress (DNS + SNI) · kprobe execve · uprobe TLS    │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### 2.1 Component Responsibilities

| Component | Responsibility | Reuses |
|---|---|---|
| **Controller** | Watch CRDs, compile policies, push bundles to nodes, reconcile `status`. | — (new crate `agent-gateway-enforcer-controller`) |
| **Admission Webhook** | Validate CR schema, detect conflicts, mutate pods with `enforcer.io/policy-hash` annotation for fast lookup. | — (new crate `agent-gateway-enforcer-webhook`) |
| **Node Agent** | Pod lifecycle → cgroup attach, program eBPF maps, stream events. | `backends/ebpf-linux`, `agent-gateway-enforcer-core/src/backend` |
| **eBPF Data Plane** | Enforce + emit events. | `backends/ebpf-linux/ebpf/lsm.c` (extend), `network.c` (implement) |
| **Aggregator** | Deduplicate, enrich (pod/ns), export to Prometheus / OTLP / K8s Events. | `agent-gateway-enforcer-core/src/events/*`, `.../metrics/*` |

---

## 3. Custom Resource Definitions

All CRDs live under API group `agents.enforcer.io`. Start at `v1alpha1`.

### 3.1 `AgentPolicy` (namespaced)

The primary user-facing resource. Selects pods and declares allowed behavior.

```yaml
apiVersion: agents.enforcer.io/v1alpha1
kind: AgentPolicy
metadata:
  name: openai-agent
  namespace: prod
spec:
  podSelector:
    matchLabels: { app: ai-agent }
  egress:
    defaultAction: Deny            # Deny | Audit | Allow
    gateways:
      - host: api.openai.com       # resolved + pinned via DNS snooping
        ports: [443]
        protocol: HTTPS
        sniPin: api.openai.com     # TLS SNI verification via tc/uprobe
    cidrs:
      - cidr: 10.0.0.0/8
        ports: [5432]
        action: Allow
  fileAccess:
    defaultAction: Deny
    rules:
      - paths: ["/app/workspace/**", "/tmp/agent-*"]
        ops: [Read, Write]
        action: Allow
      - paths: ["/etc/shadow", "/root/**"]
        ops: [Read, Write, Exec]
        action: Deny
  exec:
    allowedBinaries: ["/usr/local/bin/agent", "/usr/bin/python3"]
    action: Deny                   # deny all others (bprm_check_security)
  observability:
    sampleRate: 1.0                # 1.0 = log every decision
    redactPayloads: true
status:
  conditions:
    - type: Programmed
      status: "True"
      reason: AllNodesProgrammed
  enforcedPods: 42
  lastBundleHash: sha256:ab12...
  metrics:
    blockedEgress: 128
    blockedFileOps: 7
```

### 3.2 `GatewayCatalog` (cluster-scoped)

Reusable named gateway definitions (e.g., `openai`, `anthropic`, `internal-redis`) that `AgentPolicy` references by name — so platform teams curate the list, app teams consume it.

### 3.3 `EnforcerConfig` (cluster-scoped, singleton)

Operational knobs: ring buffer size, aggregation window, sampling, feature
flags (e.g., `enableTLSInspection: true`), namespace opt-in list.

### 3.4 `AgentViolation` (namespaced, controller-created, read-only)

Auto-generated records of sustained policy violations — queryable via `kubectl
get agentviolations -n prod`, with TTL cleanup.

> **Build tip**: Use [`kube-rs`](https://kube.rs) + `schemars` + `CustomResource`
> derive. Generate CRD YAML via `cargo xtask gen-crds` into `deploy/crds/`.

---

## 4. Complete Control: Enforcement Primitives

### 4.1 Expand eBPF Hook Coverage

| Hook | Purpose | File |
|---|---|---|
| `cgroup/connect4`, `connect6` | **Primary egress gate** — block pre-connect, per-cgroup. | `backends/ebpf-linux/ebpf/network.c` (new) |
| `cgroup/sock_ops` | Track established flows for metrics + RST injection on policy change. | same |
| `tc` egress (clsact) | **SNI pinning + DNS snooping** for hostname-based gateways. | `backends/ebpf-linux/ebpf/tc_egress.c` (new) |
| `lsm/file_open`, `file_permission` | File R/W/X control (already wired). | `ebpf/lsm.c:190-266` — extend |
| `lsm/bprm_check_security` | Exec allowlist (binary hash or path). | `ebpf/lsm.c` — new section |
| `lsm/path_unlink`, `path_mkdir`, `path_rmdir` | File mutation control. | `ebpf/lsm.c` — new section |
| `kprobe:__x64_sys_execve` (fallback pre-5.19) | Exec visibility when LSM unavailable. | new |
| `uprobe` on OpenSSL/rustls symbols | **Pre-encryption payload capture** for prompt/response audit (opt-in). | new, gated by `EnforcerConfig.enableTLSInspection` |

### 4.2 Per-Pod Cgroup Attachment

Current backend attaches at a single cgroup. Node agent must:

1. Watch kubelet CRI or `/var/run/containerd/...` for pod lifecycle.
2. Resolve pod UID → cgroup v2 path (`/sys/fs/cgroup/kubepods.slice/.../podXXX`).
3. Call `BPF_PROG_ATTACH` per cgroup with policy-specific map indices.
4. Detach on pod termination.

Extend `EnforcementBackend` trait (`agent-gateway-enforcer-core/src/backend/mod.rs`) with:

```rust
async fn attach_pod(&self, pod: PodIdentity, policy_hash: PolicyHash) -> Result<()>;
async fn detach_pod(&self, pod: PodIdentity) -> Result<()>;
async fn update_policy(&self, policy_hash: PolicyHash, bundle: PolicyBundle) -> Result<()>;
```

### 4.3 Policy Compilation Pipeline

Controller compiles CRs → a compact `PolicyBundle` (flatbuffer or protobuf):

```
AgentPolicy + GatewayCatalog  ──►  Resolver (DNS/CNI)  ──►  Bundle
                                                              │
                                                              ▼
                                                 gRPC stream to Node Agents
```

Bundle keyed by `sha256`; node agents cache by hash — idempotent reprogramming.

### 4.4 Failure Modes (must be explicit)

- **Controller down** → node agents keep enforcing last known bundle.
- **Node agent restart** → eBPF programs pinned in `/sys/fs/bpf` survive; reattach, no flap.
- **Kernel too old** → webhook rejects CRs using hooks the node can't satisfy; controller reports `Degraded` condition.

---

## 5. Complete Observability

### 5.1 Three Signals, One Pipeline

| Signal | Source | Export |
|---|---|---|
| **Metrics** | `core/src/metrics/*` (already Prometheus-ready) | `/metrics` on node agent + controller; `ServiceMonitor` CR. |
| **Events/Logs** | eBPF ringbuf → `core/src/events/*` | OTLP, stdout JSON, K8s `Events` API (for high-severity). |
| **Traces** | Correlate uprobe TLS intercepts across pod→gateway | OTLP to Tempo/Jaeger. |

### 5.2 Required Metrics (Prometheus)

```
enforcer_egress_decisions_total{namespace, pod, policy, action, gateway}
enforcer_file_decisions_total{namespace, pod, policy, action, op, path_bucket}
enforcer_exec_decisions_total{namespace, pod, policy, action, binary}
enforcer_policy_program_latency_seconds{phase=compile|push|attach}
enforcer_ebpf_map_utilization{map, node}           # early-warn before MAX_* hit
enforcer_node_agent_up{node}
enforcer_controller_reconcile_total{result}
```

### 5.3 K8s-Native Surfaces

- **`kubectl describe agentpolicy`** → conditions, pod count, recent violations.
- **`kubectl get agentviolations -n <ns>`** → structured violation records.
- **K8s `Event`s** for `PolicyProgrammed`, `PolicyDegraded`, `CriticalViolation`.
- **Built-in dashboard** (extend existing web UI in `core/src/web/`) scoped by namespace with RBAC passthrough.

### 5.4 Audit Log

Append-only JSON lines to stdout (for Fluentbit/Loki) + optional syslog export (already supported in `core/src/events/export`). Schema matches Falco/CloudEvents for tool interop.

---

## 6. Phased Roadmap

Each phase is shippable on its own.

### Phase A — Foundations (2 weeks)

- [ ] Implement `network.c` cgroup/connect4/6 + tests; remove placeholder.
- [ ] Add exec and path-mutation LSM hooks to `lsm.c`.
- [ ] Extend `EnforcementBackend` with `attach_pod` / `detach_pod` / `update_policy`.
- [ ] Add per-pod map indexing (today maps are global; switch to `BPF_MAP_TYPE_HASH_OF_MAPS` keyed by cgroup id).
- [ ] Kind-based e2e harness (`tests/e2e/kind/`) that loads eBPF in CI.

**Exit criteria**: A node agent enforces different rules for two pods on the same node, verified by e2e.

### Phase B — CRDs + Controller (2 weeks)

- [ ] New crate `agent-gateway-enforcer-controller` (kube-rs).
- [ ] `AgentPolicy`, `GatewayCatalog`, `EnforcerConfig` CRDs + schemas + `deploy/crds/`.
- [ ] Reconciler: CR → `PolicyBundle` → push via gRPC.
- [ ] Node agent gRPC server; local cache keyed by bundle hash.
- [ ] Status subresource writes (`Programmed`, `Degraded`, `enforcedPods`).

**Exit criteria**: `kubectl apply -f agentpolicy.yaml` programs enforcement on matching pods within 2s p99.

### Phase C — Admission Webhook (1 week)

- [ ] New crate `agent-gateway-enforcer-webhook` (axum + rustls).
- [ ] Validating webhook: schema, gateway resolvability, conflict detection across `AgentPolicy` in a namespace.
- [ ] Mutating webhook: inject `enforcer.io/policy-hash` annotation + readiness gate.
- [ ] cert-manager integration for webhook TLS.

**Exit criteria**: Invalid policies rejected at `kubectl apply` time with clear error.

### Phase D — Observability (1 week)

- [ ] Implement full metric set from §5.2.
- [ ] `AgentViolation` CR + controller creating records with TTL.
- [ ] K8s `Event` emission for critical state changes.
- [ ] Grafana dashboard JSON in `deploy/grafana/`.
- [ ] OTLP exporter wired through existing `core/src/events/export`.

**Exit criteria**: A blocked egress produces (a) an incremented counter, (b) a structured log line, (c) an `AgentViolation`, (d) a K8s Event — within 1s.

### Phase E — Advanced Control (2 weeks)

- [ ] tc-based SNI pinning + DNS snooping for hostname gateways.
- [ ] Opt-in uprobe TLS inspection (OpenSSL + rustls) behind `EnforcerConfig`.
- [ ] Binary-hash exec allowlist (integrity verification via `fsverity` where available).
- [ ] Policy dry-run mode (`defaultAction: Audit`) + diff tool: `kubectl enforcer simulate`.

**Exit criteria**: A policy can allow `api.openai.com:443` without hardcoding IPs and survive DNS rotation.

### Phase F — Hardening & GA (ongoing)

- [ ] Upgrade path: `v1alpha1` → `v1beta1` conversion webhook.
- [ ] Multi-arch (arm64) images.
- [ ] Fuzz tests on policy compiler.
- [ ] Chaos tests: controller kill, node reboot, bundle corruption.
- [ ] Security review: seccomp profile for control-plane pods, minimal RBAC (see §7).
- [ ] Docs: `docs/architecture.md`, `docs/writing-policies.md`, `docs/operations.md`.

---

## 7. RBAC & Security

Controller SA permissions (minimum):

| Resource | Verbs |
|---|---|
| `agents.enforcer.io/*` | `*` |
| `pods`, `namespaces` | `get`, `list`, `watch` |
| `events` | `create`, `patch` |
| `leases` (coordination) | `*` (for HA leader election) |

Node-agent SA: `get`/`list`/`watch` on `pods` (own node only via field selector).

Webhook SA: none beyond CR reads (validation only).

Control-plane pods run **non-privileged**. Only the node-agent DaemonSet needs `CAP_BPF`, `CAP_SYS_ADMIN`, `CAP_PERFMON`, and `hostPID` + `/sys/fs/cgroup`, `/sys/fs/bpf` mounts (current Helm chart covers this — see `deploy/helm/agent-gateway-enforcer/templates/daemonset.yaml`).

---

## 8. Open Questions (decide before Phase B)

1. **Policy distribution transport**: gRPC streaming vs. CR-on-every-node vs. CSI-style socket? → _Recommend gRPC for cardinality + back-pressure._
2. **Multi-cluster**: out of scope for v1alpha1, but CR schema should leave room (`spec.clusterRef`).
3. **Windows/macOS backends**: controller stays Linux-only; `macos-desktop` backend continues standalone — document the split.
4. **Conflict resolution**: when two `AgentPolicy` match the same pod, _union-allow_ vs. _intersect-deny_? → _Recommend intersect-deny, explicit `priority` field as tiebreaker._
5. **Hot reload vs. graceful drain**: on bundle change, do we flush in-flight connections? → _No by default; opt-in via `EnforcerConfig.strictReload`._

---

## 9. Risks

| Risk | Mitigation |
|---|---|
| Kernel version fragmentation across clusters | Feature-gate hooks; webhook blocks unsupported combinations; `Degraded` condition. |
| eBPF map size limits (current `MAX_GATEWAYS=64`, `MAX_PATH_RULES=256` in `agent-gateway-enforcer-common/src/lib.rs:102-112`) | Switch to `HASH_OF_MAPS`; raise limits; expose `enforcer_ebpf_map_utilization` metric. |
| Controller is SPOF | Leader-elected 2-replica deployment; node agents fail-static on bundle cache. |
| Cgroup path discovery races pod start | Use kubelet PLEG events + readiness gate (injected by mutating webhook). |
| TLS inspection is legally/ethically sensitive | Off by default; per-namespace opt-in; audit log of who enabled it. |

---

## 10. Definition of Done (v1.0)

- [ ] `helm install agents-enforcer` on a fresh EKS/GKE/AKS cluster enforces a sample `AgentPolicy` end-to-end.
- [ ] All three observability signals flow to Prometheus + OTLP collector.
- [ ] Policies survive controller restart, node reboot, and kernel upgrade (tested in chaos suite).
- [ ] p99 policy-to-enforcement latency < 2s, steady-state CPU < 2% per node.
- [ ] Zero-CVE on container scan; SBOM published.
- [ ] Docs: install, write-a-policy, troubleshoot, upgrade.
