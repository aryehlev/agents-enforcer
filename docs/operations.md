# Operating agents-enforcer

This doc covers the day-2 concerns: install, upgrade, scrape
metrics, triage a degraded policy, and respond to a compromise.

## Install

```sh
helm install agents-enforcer ./deploy/helm/agent-gateway-enforcer \
  --namespace enforcer-system --create-namespace \
  --set controller.distributor=grpc
```

What this creates:
- CRDs (`agentpolicies`, `gatewaycatalogs`, `enforcerconfigs`,
  `agentviolations`)
- ServiceAccount + ClusterRole + ClusterRoleBinding
- Controller Deployment (1 replica, unprivileged)
- Node-agent DaemonSet (one per Linux node, privileged, CAP_BPF)
- Webhook Deployment + cert-manager `Certificate` + `Issuer` +
  `ValidatingWebhookConfiguration`

Before the first policy apply:
```sh
kubectl get pods -n enforcer-system       # all Running?
kubectl get validatingwebhookconfiguration | grep agents-enforcer
```

## Upgrade

CRDs are not templated — Helm installs them once via the chart's
`crds/` dir and never touches them again. To pick up CRD changes,
apply `deploy/crds/` separately:
```sh
kubectl apply -f deploy/crds/
helm upgrade agents-enforcer ./deploy/helm/agent-gateway-enforcer -n enforcer-system
```

DaemonSet rolls one pod at a time (`maxUnavailable: 1`) so
coverage drops to at most N-1 during upgrade.

## Metrics

`/metrics` is Prometheus text format on `:9090` (controller, node
agent). Any of these scrape it without an adapter:

- Prometheus (via the shipped `ServiceMonitor`)
- VictoriaMetrics `vmagent` / `vmsingle` (VM scrapes the same
  exposition format — no conversion needed)
- Grafana Mimir, Thanos, Cortex

Enable the `ServiceMonitor` with `--set metrics.serviceMonitor.enabled=true`.

### Useful queries

```promql
# Bundles programmed per minute
sum(rate(enforcer_controller_reconcile_total{result="ok"}[5m])) * 60

# Top 10 blocked destinations in the last hour, by pod
topk(10, sum by (namespace, pod, gateway) (
  increase(enforcer_egress_decisions_total{action="Deny"}[1h])
))

# eBPF map pressure
max by (map, node) (enforcer_ebpf_map_utilization) > 80
```

The dashboard at `deploy/grafana/agents-enforcer-overview.json` is
the starting point.

## Triage a `Degraded` policy

```sh
kubectl describe agentpolicy -n prod ai-agent
```

Read `.status.message`. Four common causes, in frequency order:

1. **Unknown gateway ref** — the `GatewayCatalog` is missing or was
   renamed. `kubectl get gatewaycatalogs` to find it.
2. **Unresolved host** — a catalog entry uses a hostname. See
   [writing-policies.md](./writing-policies.md#hostname-gateways).
3. **Distributor error** — a node-agent is down. Check the
   DaemonSet: `kubectl rollout status ds -n enforcer-system
   agents-enforcer-node-agent`.
4. **Webhook timeout during apply** — `kubectl get events -n
   enforcer-system | grep webhook` and watch its logs.

## Kernel / eBPF requirements

- Linux 5.8+ (LSM BPF + cgroup-v2 `connect4`/`connect6`).
- cgroup-v2 mounted unified. RHEL/CentOS 8 ships cgroup-v1 by
  default; add `systemd.unified_cgroup_hierarchy=1` to the kernel
  cmdline.
- On managed Kubernetes: EKS AL2023, GKE COS, AKS Ubuntu 22.04 all
  satisfy this out of the box.

## Compromise response

If an agent is suspected compromised:

1. **Pin to Audit**: flip the policy's `defaultAction` back to
   `Audit` *without* removing it so the allowlist keeps filtering
   and the Grafana dashboards still light up.
2. **Freeze the cgroup**: `kubectl label pod <pod> agents.enforcer.io/quarantine=true`
   and apply a namespace policy that selects the label and blocks
   all egress. The node-agent reprograms the map in ≤2s.
3. **Evidence**: `AgentViolation` objects are retained for 24h by
   default (`EnforcerConfig.spec.violationTTL`); export them with
   `kubectl get agentviolations -n prod -o yaml > violations.yaml`.

## Upgrading the data plane

The DaemonSet reloads eBPF programs on pod restart. BPF objects
pinned under `/sys/fs/bpf/agents-enforcer/` survive the pod restart
so there's no enforcement gap. Detaching is done explicitly during
pod shutdown via SIGTERM handling.

When the eBPF C code changes (`backends/ebpf-linux/ebpf/*.c`), rebuild
the container image and roll the DaemonSet. BPF CO-RE means the same
object loads across kernels ≥5.8.

## What's missing (and when)

See `docs/k8s-controller-plan.md` for the complete roadmap. The
operational pieces that still need attention:

- **Violation aggregator**: `AgentViolation` CRs are not yet
  generated; only the type is defined.
- **tc SNI pinning**: hostname egress at L7, enabling policies like
  "allow `api.openai.com` regardless of DNS rotation".
- **Multi-cluster**: every `AgentPolicy` today is cluster-scoped;
  federation across fleets is tracked as Phase F.
- **arm64 images**: GA target; amd64 only in v1alpha1.
