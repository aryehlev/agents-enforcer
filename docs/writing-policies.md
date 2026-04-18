# Writing an AgentPolicy

An `AgentPolicy` selects pods in a namespace and declares what
network destinations, files, and binaries they're allowed to use.
Every other CR (`GatewayCatalog`, `EnforcerConfig`, `AgentViolation`)
exists to support this one.

## Minimal example

```yaml
apiVersion: agents.enforcer.io/v1alpha1
kind: AgentPolicy
metadata:
  name: ai-agent
  namespace: prod
spec:
  podSelector:
    matchLabels:
      app: ai-agent
  egress:
    defaultAction: Deny
    gatewayRefs: [openai]
  exec:
    allowedBinaries:
      - /usr/local/bin/agent
      - /usr/bin/python3
  blockMutations: true
```

`gatewayRefs` resolves through a `GatewayCatalog`:

```yaml
apiVersion: agents.enforcer.io/v1alpha1
kind: GatewayCatalog
metadata:
  name: platform
spec:
  gateways:
    - name: openai
      host: 1.2.3.4        # pre-resolved IP literal (see below)
      ports: [443]
```

## Safe rollout: Audit → Deny

Never apply `defaultAction: Deny` first. Roll in three steps so bad
policies don't take the workload offline:

1. **Audit** mode: `defaultAction: Audit` with real `gatewayRefs`.
   Every connection still succeeds, but `enforcer_egress_decisions_total`
   records what *would* have been blocked.
2. Watch the Grafana "Top blocked gateways" panel for 24h. Fix any
   missing catalog entries.
3. Flip to `defaultAction: Deny`. Keep the Audit version commented
   in version control — easy rollback.

## Selectors

Only `matchLabels` is supported in v1alpha1. The webhook rejects an
empty selector: "match every pod in the namespace" is a footgun you
have to spell out explicitly with `matchLabels: {}`.

Multiple policies may select the same pod as long as their
`defaultAction` agrees. Conflicting defaults on overlapping
selectors are rejected at `kubectl apply` time.

## Hostname gateways

`GatewayCatalog.spec.gateways[].host` must be an IPv4 literal. The
webhook rejects anything else with a clear message. The recommended
workflow is:

1. Run `dig +short api.openai.com` (or your provider's resolver).
2. Pick two or three stable IPs and list them as separate catalog
   entries — one per IP so DNS rotation doesn't invalidate the
   entire policy.
3. Automate the resolve step via a catalog operator; that operator
   is out of scope for v1alpha1 but fits cleanly above the existing
   CRDs.

## Previewing the compiled bundle

Never apply a policy blind. Use the built-in simulator:

```sh
cargo run -p xtask -- simulate \
    --policy examples/simulate/policy.yaml \
    --catalog examples/simulate/catalog.yaml
```

Output is the exact `PolicyBundle` node-agents will enforce. If the
simulator errors, the webhook will reject the same CR at apply time.

## Fields reference

| Field | Required | Meaning |
|---|---|---|
| `podSelector.matchLabels` | yes | label match; `{}` = every pod in ns |
| `egress.defaultAction` | no (Audit) | `Deny` / `Audit` / `Allow` |
| `egress.gatewayRefs[]` | no | names from any `GatewayCatalog` |
| `egress.cidrs[].cidr` | no | IPv4 /32 only in v1alpha1 |
| `egress.cidrs[].ports` | no | empty = any port |
| `fileAccess.defaultDeny` | no (false) | `true` = denylist becomes allowlist |
| `fileAccess.allowedPaths` | no | prefix match |
| `fileAccess.deniedPaths` | no | prefix match |
| `exec.allowedBinaries` | no | prefix match; empty = exec gate off |
| `blockMutations` | no (false) | deny unlink/mkdir/rmdir from matched pods |

## What's not supported yet

- `matchExpressions` — coming with v1beta1.
- Layer-7 rules (URL paths, headers) — tc egress + SNI pinning is
  tracked in the plan as Phase E.
- IPv6 gateways — `connect6` falls through to `defaultAction`.
- CIDR wider than /32 — upper prefix bits ignored until LPM maps
  land.
