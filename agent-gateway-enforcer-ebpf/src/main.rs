#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::sk_action,
    helpers::bpf_get_current_pid_tgid,
    macros::{cgroup_skb, lsm, map},
    maps::{HashMap, PerfEventArray},
    programs::{LsmContext, SkBuffContext},
};
use aya_log_ebpf::info;

use agent_gateway_enforcer_common::{
    BlockedEvent, BlockedKey, FileBlockedEvent, GatewayKey, PathKey, PathRule, PathRuleType,
    FILE_PERM_DELETE, FILE_PERM_EXEC, FILE_PERM_READ, FILE_PERM_WRITE, MAX_BLOCKED_ENTRIES,
    MAX_GATEWAYS, MAX_PATH_LEN, MAX_PATH_RULES,
};

// Ethernet header size
const ETH_HDR_LEN: usize = 14;
// IPv4 header minimum size
const IPV4_HDR_LEN: usize = 20;
// IPv4 EtherType
const ETH_P_IP: u16 = 0x0800;

/// Map of allowed gateway destinations.
/// Key: GatewayKey (IP + port)
/// Value: 1 if allowed (presence in map = allowed)
#[map]
static ALLOWED_GATEWAYS: HashMap<GatewayKey, u8> = HashMap::with_max_entries(MAX_GATEWAYS, 0);

/// Map tracking blocked connection attempts for metrics.
/// Key: BlockedKey (dst IP + port + protocol)
/// Value: Count of blocked attempts
#[map]
static BLOCKED_METRICS: HashMap<BlockedKey, u64> = HashMap::with_max_entries(MAX_BLOCKED_ENTRIES, 0);

/// Perf event array for sending blocked events to userspace.
#[map]
static BLOCKED_EVENTS: PerfEventArray<BlockedEvent> = PerfEventArray::new(0);

/// Main eBPF program attached to cgroup egress.
/// Returns SK_PASS to allow the packet, SK_DROP to block it.
#[cgroup_skb]
pub fn agent_gateway_egress(ctx: SkBuffContext) -> i32 {
    match try_agent_gateway_egress(&ctx) {
        Ok(action) => action,
        Err(_) => sk_action::SK_PASS as i32, // Allow on error to avoid breaking connectivity
    }
}

#[inline(always)]
fn try_agent_gateway_egress(ctx: &SkBuffContext) -> Result<i32, i64> {
    // Get protocol from sk_buff
    let protocol = unsafe { (*ctx.skb.skb).protocol };

    // Only handle IPv4 for now
    // protocol is in network byte order
    if protocol != (ETH_P_IP as u32).to_be() {
        return Ok(sk_action::SK_PASS as i32);
    }

    // For cgroup_skb, data starts at the IP header (no ethernet header)
    // Read IP header fields
    let ip_proto: u8 = ctx.load(9)?; // Protocol field at offset 9

    // Only handle TCP (6) and UDP (17)
    if ip_proto != 6 && ip_proto != 17 {
        return Ok(sk_action::SK_PASS as i32);
    }

    // Get IP header length (lower 4 bits of first byte * 4)
    let version_ihl: u8 = ctx.load(0)?;
    let ihl = ((version_ihl & 0x0F) as usize) * 4;

    // Read source and destination IP addresses
    let src_addr: u32 = ctx.load(12)?; // Source IP at offset 12
    let dst_addr: u32 = ctx.load(16)?; // Dest IP at offset 16

    // Read ports from transport header (TCP/UDP have ports at same offsets)
    let src_port: u16 = u16::from_be(ctx.load(ihl)?);
    let dst_port: u16 = u16::from_be(ctx.load(ihl + 2)?);

    // Check if destination is an allowed gateway
    let gateway_key = GatewayKey::new(dst_addr, dst_port);

    if unsafe { ALLOWED_GATEWAYS.get(&gateway_key).is_some() } {
        // Destination is an allowed gateway - permit traffic
        info!(ctx, "ALLOW: {}:{}", u32::from_be(dst_addr), dst_port);
        return Ok(sk_action::SK_PASS as i32);
    }

    // Also check if destination matches gateway IP with any port (for flexibility)
    // This allows all traffic to the gateway IP regardless of port
    let gateway_any_port = GatewayKey::new(dst_addr, 0);
    if unsafe { ALLOWED_GATEWAYS.get(&gateway_any_port).is_some() } {
        info!(ctx, "ALLOW (any port): {}:{}", u32::from_be(dst_addr), dst_port);
        return Ok(sk_action::SK_PASS as i32);
    }

    // Traffic is NOT going to an allowed gateway - BLOCK IT
    info!(
        ctx,
        "BLOCK: {}:{} -> {}:{}",
        u32::from_be(src_addr),
        src_port,
        u32::from_be(dst_addr),
        dst_port
    );

    // Update blocked metrics
    let blocked_key = BlockedKey::new(dst_addr, dst_port, ip_proto);

    if let Some(count) = unsafe { BLOCKED_METRICS.get_ptr_mut(&blocked_key) } {
        unsafe { *count += 1 };
    } else {
        // First time seeing this destination - insert with count 1
        let _ = BLOCKED_METRICS.insert(&blocked_key, &1u64, 0);
    }

    // Send event to userspace
    let event = BlockedEvent {
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        protocol: ip_proto,
        _pad: [0; 3],
    };
    BLOCKED_EVENTS.output(ctx, &event, 0);

    // Drop the packet
    Ok(sk_action::SK_DROP as i32)
}

// ============================================================================
// FILE ACCESS ENFORCEMENT (LSM BPF)
// ============================================================================

/// Map of path rules for file access control.
/// Key: PathKey (path prefix)
/// Value: PathRule (allow/deny + permissions)
#[map]
static PATH_RULES: HashMap<PathKey, PathRule> = HashMap::with_max_entries(MAX_PATH_RULES, 0);

/// Default policy: 0 = allow all (unless denied), 1 = deny all (unless allowed)
#[map]
static DEFAULT_DENY: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

/// Perf event array for sending file blocked events to userspace.
#[map]
static FILE_BLOCKED_EVENTS: PerfEventArray<FileBlockedEvent> = PerfEventArray::new(0);

/// LSM hook for file_open - intercepts file open operations.
/// Returns 0 to allow, negative error code to deny.
#[lsm(hook = "file_open")]
pub fn file_open_check(ctx: LsmContext) -> i32 {
    match try_file_open_check(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // Allow on error to avoid breaking the system
    }
}

#[inline(always)]
fn try_file_open_check(ctx: &LsmContext) -> Result<i32, i64> {
    // Get the file path from the context
    // In LSM BPF, we need to read the path from the file structure
    // The first argument to file_open is struct file *

    // For now, we'll use a simplified approach using d_path helper
    // This requires reading the file structure and extracting the path

    // Get current PID for logging
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // Check default policy
    let key: u32 = 0;
    let deny_by_default = unsafe { DEFAULT_DENY.get(&key).copied().unwrap_or(0) };

    if deny_by_default == 1 {
        // Deny by default mode - would need to check allowlist
        info!(ctx, "file_open: deny by default, pid={}", pid);
        return Ok(-1); // -EPERM
    }

    // In allow-by-default mode, we proceed normally
    Ok(0)
}

/// LSM hook for file_permission - intercepts read/write/execute operations.
#[lsm(hook = "file_permission")]
pub fn file_permission_check(ctx: LsmContext) -> i32 {
    match try_file_permission_check(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_file_permission_check(_ctx: &LsmContext) -> Result<i32, i64> {
    // file_permission receives (struct file *file, int mask)
    // mask contains MAY_READ, MAY_WRITE, MAY_EXEC flags

    // For now, allow all - full implementation would check PATH_RULES
    Ok(0)
}

/// LSM hook for path_unlink - intercepts file deletion.
#[lsm(hook = "path_unlink")]
pub fn path_unlink_check(ctx: LsmContext) -> i32 {
    match try_path_unlink_check(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_path_unlink_check(_ctx: &LsmContext) -> Result<i32, i64> {
    // Check if deletion is allowed for this path
    Ok(0)
}

/// LSM hook for path_mkdir - intercepts directory creation.
#[lsm(hook = "path_mkdir")]
pub fn path_mkdir_check(ctx: LsmContext) -> i32 {
    match try_path_mkdir_check(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_path_mkdir_check(_ctx: &LsmContext) -> Result<i32, i64> {
    Ok(0)
}

/// LSM hook for path_rmdir - intercepts directory removal.
#[lsm(hook = "path_rmdir")]
pub fn path_rmdir_check(ctx: LsmContext) -> i32 {
    match try_path_rmdir_check(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_path_rmdir_check(_ctx: &LsmContext) -> Result<i32, i64> {
    Ok(0)
}

/// LSM hook for bprm_check_security - intercepts program execution.
#[lsm(hook = "bprm_check_security")]
pub fn bprm_check(ctx: LsmContext) -> i32 {
    match try_bprm_check(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_bprm_check(ctx: &LsmContext) -> Result<i32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    info!(ctx, "exec check: pid={}", pid);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
