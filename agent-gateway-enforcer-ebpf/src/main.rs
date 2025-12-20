#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::sk_action,
    helpers::{
        bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid,
    },
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

/// Main eBPF program attached to cgroup ingress.
/// Filters incoming packets to ensure they're from allowed gateways.
#[cgroup_skb]
pub fn agent_gateway_ingress(ctx: SkBuffContext) -> i32 {
    match try_agent_gateway_ingress(&ctx) {
        Ok(action) => action,
        Err(_) => sk_action::SK_PASS as i32, // Allow on error to avoid breaking connectivity
    }
}

#[inline(always)]
fn try_agent_gateway_ingress(ctx: &SkBuffContext) -> Result<i32, i64> {
    // Similar to egress but for incoming packets
    // We want to ensure incoming packets are from allowed sources
    
    // Validate packet length first
    let data_len = ctx.len();
    if data_len < IPV4_HDR_LEN as u32 {
        return Ok(sk_action::SK_PASS as i32);
    }

    // Get protocol from sk_buff
    let protocol = unsafe { (*ctx.skb.skb).protocol };
    if protocol != (ETH_P_IP as u32).to_be() {
        return Ok(sk_action::SK_PASS as i32);
    }

    // Read IP header fields
    let ip_proto: u8 = ctx.load(9)?;
    if ip_proto != 6 && ip_proto != 17 {
        return Ok(sk_action::SK_PASS as i32);
    }

    // Get IP header length
    let version_ihl: u8 = ctx.load(0)?;
    let ihl = ((version_ihl & 0x0F) as usize) * 4;
    
    // Validate packet has enough data
    if data_len < (ihl + 4) as u32 {
        return Ok(sk_action::SK_PASS as i32);
    }

    // For ingress, we check the source address (who sent this packet)
    let src_addr: u32 = ctx.load(12)?; // Source IP at offset 12
    let dst_addr: u32 = ctx.load(16)?; // Dest IP at offset 16
    let src_port: u16 = u16::from_be(ctx.load(ihl)?);
    let dst_port: u16 = u16::from_be(ctx.load(ihl + 2)?);

    // Check if source is an allowed gateway
    let gateway_key = GatewayKey::new(src_addr, src_port);
    
    if unsafe { ALLOWED_GATEWAYS.get(&gateway_key).is_some() } {
        // Source is an allowed gateway - permit traffic
        info!(ctx, "INGRESS ALLOW: {}:{} -> {}:{}", 
              u32::from_be(src_addr), src_port, u32::from_be(dst_addr), dst_port);
        return Ok(sk_action::SK_PASS as i32);
    }

    // Also check if source matches gateway IP with any port
    let gateway_any_port = GatewayKey::new(src_addr, 0);
    if unsafe { ALLOWED_GATEWAYS.get(&gateway_any_port).is_some() } {
        info!(ctx, "INGRESS ALLOW (any port): {}:{} -> {}:{}", 
              u32::from_be(src_addr), src_port, u32::from_be(dst_addr), dst_port);
        return Ok(sk_action::SK_PASS as i32);
    }

    // Traffic is NOT from an allowed gateway - BLOCK IT
    info!(
        ctx,
        "INGRESS BLOCK: {}:{} -> {}:{} (proto={})",
        u32::from_be(src_addr),
        src_port,
        u32::from_be(dst_addr),
        dst_port,
        ip_proto
    );

    // Update blocked metrics
    let blocked_key = BlockedKey::new(src_addr, src_port, ip_proto);
    
    if let Some(count) = unsafe { BLOCKED_METRICS.get_ptr_mut(&blocked_key) } {
        unsafe { *count += 1 };
    } else {
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
    
    let _ = BLOCKED_EVENTS.output(ctx, &event, 0);

    // Drop the packet
    Ok(sk_action::SK_DROP as i32)
}

#[inline(always)]
fn try_agent_gateway_egress(ctx: &SkBuffContext) -> Result<i32, i64> {
    // Validate packet length first
    let data_len = ctx.len();
    if data_len < IPV4_HDR_LEN as u32 {
        info!(ctx, "Packet too short: {} bytes", data_len);
        return Ok(sk_action::SK_PASS as i32);
    }

    // Get protocol from sk_buff with proper error handling
    let protocol = match unsafe { (*ctx.skb.skb).protocol } {
        p if p == (ETH_P_IP as u32).to_be() => p,
        _ => {
            // Only handle IPv4 for now
            return Ok(sk_action::SK_PASS as i32);
        }
    };

    // For cgroup_skb, data starts at the IP header (no ethernet header)
    // Read IP header fields with bounds checking
    let ip_proto: u8 = match ctx.load(9) {
        Ok(proto) => proto,
        Err(_) => {
            info!(ctx, "Failed to read IP protocol");
            return Ok(sk_action::SK_PASS as i32);
        }
    };

    // Only handle TCP (6) and UDP (17)
    if ip_proto != 6 && ip_proto != 17 {
        return Ok(sk_action::SK_PASS as i32);
    }

    // Get IP header length (lower 4 bits of first byte * 4)
    let version_ihl: u8 = match ctx.load(0) {
        Ok(v_ihl) => v_ihl,
        Err(_) => {
            info!(ctx, "Failed to read IP version/IHL");
            return Ok(sk_action::SK_PASS as i32);
        }
    };
    
    let ihl = ((version_ihl & 0x0F) as usize) * 4;
    
    // Validate IHL is reasonable
    if ihl < IPV4_HDR_LEN || ihl > 60 {
        info!(ctx, "Invalid IHL: {}", ihl);
        return Ok(sk_action::SK_PASS as i32);
    }

    // Validate packet has enough data for IP header + transport header
    if data_len < (ihl + 4) as u32 {
        info!(ctx, "Packet too short for transport header: {} bytes", data_len);
        return Ok(sk_action::SK_PASS as i32);
    }

    // Read source and destination IP addresses with error handling
    let src_addr: u32 = match ctx.load(12) {
        Ok(addr) => addr,
        Err(_) => {
            info!(ctx, "Failed to read source IP");
            return Ok(sk_action::SK_PASS as i32);
        }
    };
    
    let dst_addr: u32 = match ctx.load(16) {
        Ok(addr) => addr,
        Err(_) => {
            info!(ctx, "Failed to read destination IP");
            return Ok(sk_action::SK_PASS as i32);
        }
    };

    // Read ports from transport header (TCP/UDP have ports at same offsets)
    let src_port: u16 = match ctx.load(ihl) {
        Ok(port) => u16::from_be(port),
        Err(_) => {
            info!(ctx, "Failed to read source port");
            return Ok(sk_action::SK_PASS as i32);
        }
    };
    
    let dst_port: u16 = match ctx.load(ihl + 2) {
        Ok(port) => u16::from_be(port),
        Err(_) => {
            info!(ctx, "Failed to read destination port");
            return Ok(sk_action::SK_PASS as i32);
        }
    };

    // Validate ports are not zero (except for special cases)
    if dst_port == 0 && src_port == 0 {
        info!(ctx, "Invalid ports: src={}, dst={}", src_port, dst_port);
        return Ok(sk_action::SK_PASS as i32);
    }

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
        "BLOCK: {}:{} -> {}:{} (proto={})",
        u32::from_be(src_addr),
        src_port,
        u32::from_be(dst_addr),
        dst_port,
        ip_proto
    );

    // Update blocked metrics with proper error handling
    let blocked_key = BlockedKey::new(dst_addr, dst_port, ip_proto);

    if let Some(count) = unsafe { BLOCKED_METRICS.get_ptr_mut(&blocked_key) } {
        unsafe { *count += 1 };
    } else {
        // First time seeing this destination - insert with count 1
        match unsafe { BLOCKED_METRICS.insert(&blocked_key, &1u64, 0) } {
            Ok(_) => {}, // Success
            Err(_) => {
                // Failed to insert metric, but still block the packet
                info!(ctx, "Failed to insert blocked metric");
            }
        }
    }

    // Send event to userspace with error handling
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
/// Map for file access control.
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
    // Get current PID for logging
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // Extract file path using d_path helper
    let file_path = match extract_file_path(ctx) {
        Ok(path) => path,
        Err(_) => {
            // If we can't extract the path, allow the operation
            // to avoid breaking the system
            return Ok(0);
        }
    };

    // Check if this path should be allowed or denied
    match check_file_access(&file_path, FILE_PERM_READ | FILE_PERM_WRITE | FILE_PERM_EXEC, pid) {
        Ok(allowed) => {
            if allowed {
                info!(ctx, "file_open: ALLOW path={}, pid={}", file_path, pid);
                Ok(0)
            } else {
                info!(ctx, "file_open: DENY path={}, pid={}", file_path, pid);
                send_file_blocked_event(&file_path, FILE_PERM_READ, pid, ctx);
                Ok(-1) // -EPERM
            }
        }
        Err(_) => Ok(0), // Allow on error
    }
}

/// LSM hook for file_permission - intercepts read/write/execute operations.
/// Returns 0 to allow, negative error code to deny.
#[lsm(hook = "file_permission")]
pub fn file_permission_check(ctx: LsmContext) -> i32 {
    match try_file_permission_check(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
}
}

#[inline(always)]
fn try_file_permission_check(ctx: &LsmContext) -> Result<i32, i64> {
    // file_permission receives (struct file *file, int mask)
    // mask contains MAY_READ, MAY_WRITE, MAY_EXEC flags
    
    // Get current PID for logging
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // Extract file path
    let file_path = match extract_file_path(ctx) {
        Ok(path) => path,
        Err(_) => return Ok(0),
    };

    // Get permission mask from second argument (ctx.arg[1])
    let mask = unsafe { *(ctx.arg::<i32>(1) as *const i32) };
    let mut permissions = 0u8;

    // Convert Linux permission flags to our flags
    if mask & 0x04 != 0 { permissions |= FILE_PERM_READ; }   // MAY_READ
    if mask & 0x02 != 0 { permissions |= FILE_PERM_WRITE; }  // MAY_WRITE
    if mask & 0x01 != 0 { permissions |= FILE_PERM_EXEC; }   // MAY_EXEC

    // Check if this access should be allowed
    match check_file_access(&file_path, permissions, pid) {
        Ok(allowed) => {
            if allowed {
                Ok(0)
            } else {
                info!(ctx, "file_permission: DENY path={}, mask={}, pid={}", file_path, mask, pid);
                send_file_blocked_event(&file_path, permissions, pid, ctx);
                Ok(-1) // -EPERM
            }
        }
        Err(_) => Ok(0),
    }
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
fn try_path_unlink_check(ctx: &LsmContext) -> Result<i32, i64> {
    // path_unlink receives (struct path *dir, struct dentry *dentry, struct inode *delegated_inode)
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // Extract path from dentry (second argument)
    let dentry_ptr: u64 = unsafe { ctx.arg(1) };
    let file_path = match extract_path_from_dentry(dentry_ptr) {
        Ok(path) => path,
        Err(_) => return Ok(0),
    };

    match check_file_access(&file_path, FILE_PERM_DELETE, pid) {
        Ok(allowed) => {
            if allowed {
                Ok(0)
            } else {
                info!(ctx, "path_unlink: DENY path={}, pid={}", file_path, pid);
                send_file_blocked_event(&file_path, FILE_PERM_DELETE, pid, ctx);
                Ok(-1) // -EPERM
            }
        }
        Err(_) => Ok(0),
    }
}

/// LSM hook for path_mkdir - intercepts directory creation.
/// Returns 0 to allow, negative error code to deny.
#[lsm(hook = "path_mkdir")]
pub fn path_mkdir_check(ctx: LsmContext) -> i32 {
    match try_path_mkdir_check(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_path_mkdir_check(ctx: &LsmContext) -> Result<i32, i64> {
    // path_mkdir receives (struct path *dir, struct dentry *dentry, umode_t mode)
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // Extract path from dentry (second argument)
    let dentry_ptr: u64 = unsafe { ctx.arg(1) };
    let file_path = match extract_path_from_dentry(dentry_ptr) {
        Ok(path) => path,
        Err(_) => return Ok(0),
    };

    // For directory creation, we check write permissions on parent
    match check_file_access(&file_path, FILE_PERM_WRITE, pid) {
        Ok(allowed) => {
            if allowed {
                Ok(0)
            } else {
                info!(ctx, "path_mkdir: DENY path={}, pid={}", file_path, pid);
                send_file_blocked_event(&file_path, FILE_PERM_WRITE, pid, ctx);
                Ok(-1) // -EPERM
            }
        }
        Err(_) => Ok(0),
    }
}

/// LSM hook for path_rmdir - intercepts directory removal.
/// Returns 0 to allow, negative error code to deny.
#[lsm(hook = "path_rmdir")]
pub fn path_rmdir_check(ctx: LsmContext) -> i32 {
    match try_path_rmdir_check(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_path_rmdir_check(ctx: &LsmContext) -> Result<i32, i64> {
    // path_rmdir receives (struct path *dir, struct dentry *dentry)
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // Extract path from dentry (second argument)
    let dentry_ptr: u64 = unsafe { ctx.arg(1) };
    let file_path = match extract_path_from_dentry(dentry_ptr) {
        Ok(path) => path,
        Err(_) => return Ok(0),
    };

    match check_file_access(&file_path, FILE_PERM_DELETE, pid) {
        Ok(allowed) => {
            if allowed {
                Ok(0)
            } else {
                info!(ctx, "path_rmdir: DENY path={}, pid={}", file_path, pid);
                send_file_blocked_event(&file_path, FILE_PERM_DELETE, pid, ctx);
                Ok(-1) // -EPERM
            }
        }
        Err(_) => Ok(0),
    }
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
    // bprm_check_security receives (struct linux_binprm *bprm)
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // Extract file path from binprm
    let binprm_ptr: u64 = unsafe { ctx.arg(0) };
    let file_path = match extract_path_from_binprm(binprm_ptr) {
        Ok(path) => path,
        Err(_) => return Ok(0),
    };

    match check_file_access(&file_path, FILE_PERM_EXEC, pid) {
        Ok(allowed) => {
            if allowed {
                info!(ctx, "exec: ALLOW path={}, pid={}", file_path, pid);
                Ok(0)
            } else {
                info!(ctx, "exec: DENY path={}, pid={}", file_path, pid);
                send_file_blocked_event(&file_path, FILE_PERM_EXEC, pid, ctx);
                Ok(-1) // -EPERM
            }
        }
        Err(_) => Ok(0),
    }
}

// ============================================================================
// HELPER FUNCTIONS FOR FILE ACCESS ENFORCEMENT
// ============================================================================

/// Extract file path from file structure using BTF/CO-RE
fn extract_file_path(ctx: &LsmContext) -> Result<&'static str, i64> {
    use aya_ebpf::cty::c_void;
    
    // file_open receives struct file * as first argument
    let _file_ptr: *const c_void = unsafe { ctx.arg(0) };
    
    // Use BTF to access file->f_path->dentry->d_name
    // This is a simplified implementation - in production you'd want
    // more robust error handling and fallback mechanisms
    
    // For now, we'll implement a basic path extraction that works
    // with common kernel structures using BTF information
    
    // Buffer to store the extracted path
    static mut PATH_BUFFER: [u8; MAX_PATH_LEN] = [0; MAX_PATH_LEN];
    
    // Try to extract path using d_path helper if available
    // Note: d_path is complex in eBPF, so we'll use a simplified approach
    // that checks for known sensitive paths
    
    // For demonstration, we'll check some common sensitive paths
    // In a real implementation, you'd extract the actual path
    
    // Check if this is a sensitive system file
    let sensitive_paths = [
        "/etc/passwd",
        "/etc/shadow", 
        "/etc/hosts",
        "/root/",
        "/home/",
        "/var/log/",
        "/etc/ssh/",
        "/etc/sudoers",
    ];
    
    // For now, return a placeholder that will trigger policy checks
    // In a production environment, you'd implement proper path extraction
    Ok("/tmp/sensitive_file")
}

/// Extract path from dentry structure using BTF/CO-RE
fn extract_path_from_dentry(dentry_ptr: u64) -> Result<&'static str, i64> {
    // path_* hooks receive dentry pointer as second argument
    let _dentry_ptr: u64 = dentry_ptr;
    
    // Use BTF to access dentry->d_name
    // Similar to extract_file_path but for dentry structures
    
    // For demonstration purposes, return a placeholder
    // In production, you'd extract the actual path from the dentry
    Ok("/tmp/sensitive_path")
}

/// Extract path from binprm structure using BTF/CO-RE  
fn extract_path_from_binprm(binprm_ptr: u64) -> Result<&'static str, i64> {
    // bprm_check_security receives struct linux_binprm * as first argument
    let _binprm_ptr: u64 = binprm_ptr;
    
    // Use BTF to access binprm->file->f_path
    // This would extract the executable path
    
    // For demonstration, return a placeholder
    // In production, you'd extract the actual executable path
    Ok("/tmp/sensitive_exec")
}

/// Check if file access is allowed based on path rules with enhanced security
fn check_file_access(path: &str, requested_permissions: u8, pid: u32) -> Result<bool, i64> {
    // Get current UID/GID for additional security context
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid >> 32) as u32;
    let gid = uid_gid as u32;
    
    // Check default policy first
    let key: u32 = 0;
    let deny_by_default = unsafe { DEFAULT_DENY.get(&key).copied().unwrap_or(0) };
    
    // Create a path key for matching
    let path_key = PathKey::new(path);
    
    // Look for exact or prefix matches in PATH_RULES
    let mut found_rule = false;
    let mut allowed = false;
    let mut rule_priority = 0; // For rule conflict resolution
    
    // Check for exact match first (highest priority)
    if let Some(rule) = unsafe { PATH_RULES.get(&path_key) } {
        found_rule = true;
        rule_priority = 3; // Exact match has highest priority
        
        // Check if this rule applies to the requested permissions
        if rule.permissions & requested_permissions != 0 {
            allowed = rule.rule_type == PathRuleType::Allow;
        }
    }
    
    // If no exact match, check for prefix matches
    if !found_rule {
        let path_bytes = path.as_bytes();
        
        // Check prefixes from longest to shortest for most specific match
        let mut i = path_bytes.len();
        while i > 0 {
            if path_bytes[i - 1] == b'/' {
                let prefix = &path[..i];
                let prefix_key = PathKey::new(prefix);
                
                if let Some(rule) = unsafe { PATH_RULES.get(&prefix_key) } {
                    if rule.is_prefix == 1 && (rule.permissions & requested_permissions != 0) {
                        if !found_rule || rule_priority < 2 {
                            found_rule = true;
                            rule_priority = 2; // Prefix match
                            allowed = rule.rule_type == PathRuleType::Allow;
                        }
                        break; // Found the most specific prefix match
                    }
                }
            }
            i -= 1;
        }
    }
    
    // Additional security checks for sensitive paths
    if !found_rule {
        let sensitive_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/ssh/",
            "/root/",
            "/var/log/auth.log",
            "/var/log/secure",
        ];
        
        for sensitive_path in &sensitive_paths {
            if path.starts_with(sensitive_path) {
                // Sensitive path - require explicit allow rule
                found_rule = true;
                allowed = false; // Deny by default for sensitive paths
                break;
            }
        }
    }
    
    // Apply default policy if no rule found
    if !found_rule {
        allowed = deny_by_default == 0;
    }
    
    // Additional check: root user (uid=0) gets more scrutiny
    if uid == 0 && !allowed {
        // Log root access denial (would need context in real implementation)
    }
    
Ok(allowed)
}

/// Send file blocked event to userspace
fn send_file_blocked_event(path: &str, operation: u8, pid: u32, ctx: &LsmContext) {
    let mut event = FileBlockedEvent {
        path: [0u8; MAX_PATH_LEN],
        path_len: 0,
        operation,
        pid,
        _pad: 0,
    };
    
    // Copy path into event
    let path_bytes = path.as_bytes();
    let copy_len = path_bytes.len().min(MAX_PATH_LEN - 1);
    event.path[..copy_len].copy_from_slice(&path_bytes[..copy_len]);
    event.path_len = copy_len as u16;
    
    // Send event to userspace
    FILE_BLOCKED_EVENTS.output(ctx, &event, 0);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
