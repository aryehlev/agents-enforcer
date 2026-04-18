# Architecture

Three processes cooperate to enforce `AgentPolicy` CRs inside a
Kubernetes cluster: a **controller** (Deployment, one replica), a
**node-agent** (DaemonSet, one pod per Linux node), and a
**validating admission webhook** (Deployment, HA).

```
┌──────────────────────────────────────────────────────────────────┐
│                   Control plane (enforcer-system ns)             │
│                                                                  │
│  ┌──────────────┐  gRPC   ┌─────────────────┐  webhook HTTPS      │
│  │  Controller  │────────▶│   Node-agent    │◀────┐               │
│  │ (Deployment) │         │  (DaemonSet)    │     │               │
│  └──────┬───────┘         └────────┬────────┘     │               │
│         │                          │              │               │
│         │ watch CR / pod / catalog │ eBPF map +   │               │
│         │ patch status + events    │ cgroup attach│               │
│         ▼                          ▼              │               │
│    apiserver ◀── admission ◀── kubectl apply ─────┘               │
└──────────────────────────────────────────────────────────────────┘
```

## Controller (`agent-gateway-enforcer-controller`)

- Watches `AgentPolicy` + `GatewayCatalog` + `Pod` via `kube-rs` and
  compiles each reconciled policy into a flat `PolicyBundle`.
- Pushes the bundle to every relevant node-agent through a
  `BundleDistributor` — `GrpcDistributor` in production,
  `LoggingDistributor` for dry-run, `InMemoryDistributor` for tests.
- Uses `kube::runtime::finalizer` to guarantee cleanup runs before
  Kubernetes deletes an `AgentPolicy`.
- Writes compilation and distribution outcomes to `status` and emits
  K8s Events (`Programmed` / `Degraded`).

## Node agent (`agent-gateway-enforcer-node-agent`)

- Serves the `NodeAgent` gRPC on :9091. Four RPCs: `UpdatePolicy`
  (stage a bundle), `AttachPod` / `DetachPod` (program per-pod eBPF
  maps), `Health`.
- Wraps an `EnforcementBackend`. The only production implementation
  is `EbpfLinuxBackend` which loads:
  - `backends/ebpf-linux/ebpf/network.c`: `cgroup/connect4` and
    `cgroup/connect6` with per-cgroup allowlists
    (`allowed_pod_gateways` keyed by `(cgroup_id, addr, port)`).
  - `backends/ebpf-linux/ebpf/lsm.c`: `lsm/file_open`,
    `lsm/file_permission`, `lsm/bprm_check_security`,
    `lsm/path_{unlink,mkdir,rmdir}`.
- Exposes `/metrics` (Prometheus text format) and `/healthz` on :9090.

## Admission webhook (`agent-gateway-enforcer-webhook`)

- HTTPS on :8443. cert-manager provisions the serving certificate
  and injects the CA bundle into `ValidatingWebhookConfiguration`
  via `cert-manager.io/inject-ca-from`.
- Rejects `AgentPolicy` CRs that reference unknown gateways, use
  unresolved hostnames, define an empty selector, or conflict with a
  sibling policy's `defaultAction` on an overlapping selector.

## Data types

- `PolicyBundle` (`agent-gateway-enforcer-core::backend`): the flat
  representation both sides of the gRPC agree on. Content-hashed
  with SHA-256 so two controllers produce byte-identical bundles.
- `PodIdentity`: `uid`, `namespace`, `name`, `cgroup_path`,
  `node_name`. `node_name` tells the distributor which node-agent
  to call.
- `PolicyHash`: hex-sha256 wrapper; used as a map key everywhere.

## Metrics

Prometheus text format on `/metrics`. All names are prefixed
`enforcer_` and match the schema in
[`k8s-controller-plan.md`](./k8s-controller-plan.md) §5.2. Any
Prometheus-compatible scraper works — **Prometheus**,
**VictoriaMetrics vmagent/vmsingle**, Grafana **Mimir**, **Thanos**,
**Cortex**. An OTLP metrics pipeline would add surface area without
fitting a data shape that isn't already counters and histograms.

(Traces stay OTLP-bound — Tempo / Jaeger don't have a scrape
alternative — but tracing isn't wired in v1alpha1.)

## Failure modes

| Failure | Behavior |
|---|---|
| Controller crashes | Node-agents keep enforcing the last staged bundle; kube restarts the controller; on startup the reconciler reasserts state from CRs. |
| Node-agent crashes | eBPF programs persist via `/sys/fs/bpf` pinning; on restart the agent reattaches without flap. |
| Apiserver unreachable | Webhook returns 503 → `failurePolicy=Fail` means new `AgentPolicy` applies are rejected (safe default); existing enforcement continues unchanged. |
| Pod deletion | `detach_pod` runs from either the finalizer cleanup path or the next reconcile's diff set; fast delete is not possible because the controller holds a finalizer. |
