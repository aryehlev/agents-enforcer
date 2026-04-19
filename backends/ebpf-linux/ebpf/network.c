// SPDX-License-Identifier: MIT
/*
 * Agent Gateway Enforcer - eBPF Network Program
 *
 * Per-cgroup egress control via cgroup/connect4 and cgroup/connect6 hooks.
 * A connect() syscall issued from within an attached cgroup is evaluated
 * against an allowlist of (address, port) gateway tuples; traffic to any
 * destination not in the list is denied in the kernel before a packet
 * leaves the host.
 *
 * This file intentionally stays small and side-effect free (no kprobes,
 * no TC) so it can be loaded on kernels as old as 5.8. Hostname / SNI
 * pinning lives in a separate tc_egress program (see roadmap Phase E).
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Keep in sync with agent_gateway_enforcer_common::{GatewayKey,PodGatewayKey,BlockedEvent}.
// If you change these, update agent-gateway-enforcer-common/src/lib.rs.
#define MAX_GATEWAYS        64
// Per-pod allowlist capacity. Sized for ~256 pods x 4 rules each on a
// busy node; raise via CO-RE overrides when profiling shows pressure.
#define MAX_POD_GATEWAYS    1024
#define MAX_BLOCKED_ENTRIES 10000

// Protocol constants.
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// Config slots (BPF_MAP_TYPE_ARRAY indexed by these keys).
#define NET_CONFIG_ENABLED         0
#define NET_CONFIG_DEFAULT_ACTION  1 // 0 = allow-all, 1 = deny-unlisted
#define NET_CONFIG_NUM_GATEWAYS    2
#define NET_CONFIG_SLOTS           4

// Event tags for the ring buffer.
#define NET_EVENT_BLOCKED 1
#define NET_EVENT_ALLOWED 2

// Key for the allowed_gateways map. Mirrors common::GatewayKey.
struct gateway_key {
    __u32 addr; // network byte order
    __u16 port; // host byte order
    __u16 _pad;
};

// Key for the per-pod allowlist. Mirrors common::PodGatewayKey.
// cgroup_id of 0 is reserved for the global allowlist and should not be
// written into this map (use `allowed_gateways` instead).
struct pod_gateway_key {
    __u64 cgroup_id;
    __u32 addr;
    __u16 port;
    __u16 _pad;
};

// Event emitted to userspace when a connect() is decided. Kept in
// sync with common::BlockedEvent (24 bytes, repr(C)). cgroup_id lets
// the node-agent attribute the event to the enforcing pod without a
// second syscall — ringbuf consumers reverse-lookup it in the
// per-pod attachment registry.
struct net_event {
    __u64 cgroup_id;
    __u32 src_addr;
    __u32 dst_addr;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  event_type;
    __u8  _pad[2];
};

// Global allowlist: (addr, port) -> 1. Applies to every cgroup and is
// checked as a fallback when no per-pod rule matches. `configure_gateways`
// in userspace still writes here for single-tenant / legacy deployments.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_GATEWAYS);
    __type(key, struct gateway_key);
    __type(value, __u8);
} allowed_gateways SEC(".maps");

// Per-pod allowlist: (cgroup_id, addr, port) -> 1. Written by
// `attach_pod`; entries are scoped to a single pod. The lookup order
// in `gateway_allowed` is per-pod first, global second.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_POD_GATEWAYS);
    __type(key, struct pod_gateway_key);
    __type(value, __u8);
} allowed_pod_gateways SEC(".maps");

// Per-destination block counter, for metrics. Lossy under pressure; that's fine.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_BLOCKED_ENTRIES);
    __type(key, struct gateway_key);
    __type(value, __u64);
} blocked_counts SEC(".maps");

// Runtime knobs (enabled, default action, gateway count).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, NET_CONFIG_SLOTS);
    __type(key, __u32);
    __type(value, __u32);
} net_config SEC(".maps");

// Event stream back to the node agent.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} net_events SEC(".maps");

static __always_inline __u32 read_config(__u32 key) {
    __u32 *v = bpf_map_lookup_elem(&net_config, &key);
    return v ? *v : 0;
}

static __always_inline int is_enabled(void) {
    return read_config(NET_CONFIG_ENABLED) != 0;
}

static __always_inline int default_deny(void) {
    return read_config(NET_CONFIG_DEFAULT_ACTION) != 0;
}

static __always_inline int gateway_allowed(__u32 addr_be, __u16 port_host) {
    // --- Per-pod first. A 0 cgroup_id here means "not in a tracked
    // cgroup" (e.g. host networking); fall through to global in that case.
    __u64 cgid = bpf_get_current_cgroup_id();
    if (cgid != 0) {
        struct pod_gateway_key pkey = {
            .cgroup_id = cgid,
            .addr = addr_be,
            .port = port_host,
            ._pad = 0,
        };
        __u8 *pv = bpf_map_lookup_elem(&allowed_pod_gateways, &pkey);
        if (pv && *pv)
            return 1;

        // Wildcard port for this cgroup.
        pkey.port = 0;
        pv = bpf_map_lookup_elem(&allowed_pod_gateways, &pkey);
        if (pv && *pv)
            return 1;
    }

    // --- Global allowlist.
    struct gateway_key key = {
        .addr = addr_be,
        .port = port_host,
        ._pad = 0,
    };
    __u8 *v = bpf_map_lookup_elem(&allowed_gateways, &key);
    if (v && *v)
        return 1;

    // Wildcard port: key with port=0 allows any port to this address.
    key.port = 0;
    v = bpf_map_lookup_elem(&allowed_gateways, &key);
    return v && *v;
}

static __always_inline void bump_blocked(__u32 addr_be, __u16 port_host) {
    struct gateway_key key = {
        .addr = addr_be,
        .port = port_host,
        ._pad = 0,
    };
    __u64 *cnt = bpf_map_lookup_elem(&blocked_counts, &key);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&blocked_counts, &key, &one, BPF_ANY);
    }
}

static __always_inline void emit_event(__u8 event_type,
                                       __u32 dst_addr_be,
                                       __u16 dst_port_host,
                                       __u8 protocol) {
    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e)
        return;
    // cgroup_id 0 means "host-networking / unattributed"; userspace
    // treats that as a no-op for attribution but still exports metrics.
    e->cgroup_id  = bpf_get_current_cgroup_id();
    e->src_addr   = 0;
    e->dst_addr   = dst_addr_be;
    e->src_port   = 0;
    e->dst_port   = dst_port_host;
    e->protocol   = protocol;
    e->event_type = event_type;
    e->_pad[0]    = 0;
    e->_pad[1]    = 0;
    bpf_ringbuf_submit(e, 0);
}

// cgroup_sock_addr return values: 1 = allow, 0 = deny.
static __always_inline int decide_v4(struct bpf_sock_addr *ctx) {
    if (!is_enabled())
        return 1;

    __u8 proto = ctx->protocol;
    // Only gate TCP/UDP; let kernel handle everything else (ICMP, raw).
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        return 1;

    __u32 dst_addr = ctx->user_ip4;          // network byte order already
    __u16 dst_port = bpf_ntohs(ctx->user_port);

    if (gateway_allowed(dst_addr, dst_port)) {
        emit_event(NET_EVENT_ALLOWED, dst_addr, dst_port, proto);
        return 1;
    }

    if (!default_deny()) {
        // Audit-mode: observe but don't block.
        emit_event(NET_EVENT_ALLOWED, dst_addr, dst_port, proto);
        return 1;
    }

    bump_blocked(dst_addr, dst_port);
    emit_event(NET_EVENT_BLOCKED, dst_addr, dst_port, proto);
    return 0;
}

SEC("cgroup/connect4")
int connect4_gate(struct bpf_sock_addr *ctx) {
    return decide_v4(ctx);
}

// IPv6 gating. For now we only allowlist IPv4 gateways in the map, so any
// IPv6 egress is treated as "not in allowlist" and follows default_action.
// A future PR can add an ipv6_gateways map keyed on (in6_addr, port).
SEC("cgroup/connect6")
int connect6_gate(struct bpf_sock_addr *ctx) {
    if (!is_enabled())
        return 1;

    __u8 proto = ctx->protocol;
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        return 1;

    __u16 dst_port = bpf_ntohs(ctx->user_port);

    if (!default_deny()) {
        emit_event(NET_EVENT_ALLOWED, 0, dst_port, proto);
        return 1;
    }

    // Use addr=0 so v6 blocks aggregate into a single metric bucket until
    // v6 allowlisting lands.
    bump_blocked(0, dst_port);
    emit_event(NET_EVENT_BLOCKED, 0, dst_port, proto);
    return 0;
}

char LICENSE[] SEC("license") = "MIT";
