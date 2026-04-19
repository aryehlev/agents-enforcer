//! tls-tap eBPF program.
//!
//! Userspace uprobes on `SSL_write` and `SSL_read` from libssl /
//! BoringSSL. Captures plaintext (pre-encryption / post-decryption)
//! into a ringbuf for the userspace consumer to attribute and ship.
//!
//! Same semantics as the C version this replaced — the rewrite is
//! about staying in one language for the whole stack.

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_probe_read_user,
    },
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::ProbeContext,
};
use core::mem;
use tls_tap_shared::{direction, SslReadArgs, TlsEventHdr, MAX_PLAINTEXT};

/// Per-CPU scratch event so we don't blow the eBPF stack (512B
/// limit). Layout matches what userspace reads from the ringbuf.
#[repr(C)]
#[derive(Clone, Copy)]
struct ScratchEvent {
    hdr: TlsEventHdr,
    data: [u8; MAX_PLAINTEXT],
}

#[map]
static EVENT_SCRATCH: PerCpuArray<ScratchEvent> = PerCpuArray::with_max_entries(1, 0);

/// Output ringbuf. 1 MiB sized to absorb burst traffic without
/// dropping; the userspace consumer polls in a tight loop with
/// 10ms backoff so this is mostly headroom.
#[map]
static TLS_EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

/// Per-thread "in-flight SSL_read" so the uretprobe can recover
/// the buf pointer captured at entry.
#[map]
static SSL_READ_INFLIGHT: HashMap<u64, SslReadArgs> = HashMap::with_max_entries(8192, 0);

/// `SSL_write(SSL *ssl, const void *buf, int num)` — captured at
/// entry so we see the plaintext before the library encrypts it.
#[uprobe]
pub fn uprobe_ssl_write(ctx: ProbeContext) -> u32 {
    let _ = try_ssl_write(ctx);
    0
}

fn try_ssl_write(ctx: ProbeContext) -> Result<u32, i64> {
    let ssl: u64 = ctx.arg(0).ok_or(1i64)?;
    let buf: *const u8 = ctx.arg(1).ok_or(1i64)?;
    let num: i32 = ctx.arg(2).ok_or(1i64)?;
    emit(direction::WRITE, ssl, buf, num as i64);
    Ok(0)
}

/// `SSL_read(SSL *ssl, void *buf, int num)` — entry stashes args
/// so the uretprobe can use the actual byte count.
#[uprobe]
pub fn uprobe_ssl_read(ctx: ProbeContext) -> u32 {
    let _ = try_ssl_read_entry(ctx);
    0
}

fn try_ssl_read_entry(ctx: ProbeContext) -> Result<u32, i64> {
    let ssl: u64 = ctx.arg(0).ok_or(1i64)?;
    let buf: u64 = ctx.arg(1).ok_or(1i64)?;
    let num: i32 = ctx.arg(2).ok_or(1i64)?;
    let key = unsafe { bpf_get_current_pid_tgid() };
    let args = SslReadArgs {
        ssl,
        buf,
        want: num as u32,
        _pad: 0,
    };
    let _ = SSL_READ_INFLIGHT.insert(&key, &args, 0);
    Ok(0)
}

#[uretprobe]
pub fn uretprobe_ssl_read(ctx: ProbeContext) -> u32 {
    let _ = try_ssl_read_exit(ctx);
    0
}

fn try_ssl_read_exit(ctx: ProbeContext) -> Result<u32, i64> {
    let ret: i32 = ctx.ret().ok_or(1i64)?;
    let key = unsafe { bpf_get_current_pid_tgid() };
    let args = unsafe { SSL_READ_INFLIGHT.get(&key) }.ok_or(1i64)?;
    if ret > 0 {
        emit(direction::READ, args.ssl, args.buf as *const u8, ret as i64);
    }
    let _ = SSL_READ_INFLIGHT.remove(&key);
    Ok(0)
}

/// Allocate the per-CPU scratch, fill the header + plaintext,
/// reserve a ringbuf slot, copy, submit. Splitting reserve/copy
/// keeps the verifier happy with a variable-length payload.
#[inline(always)]
fn emit(dir: u8, ssl_ptr: u64, user_buf: *const u8, user_len: i64) {
    if user_len <= 0 {
        return;
    }
    let want = if user_len > MAX_PLAINTEXT as i64 {
        MAX_PLAINTEXT as u32
    } else {
        user_len as u32
    };
    let truncated = if user_len > MAX_PLAINTEXT as i64 {
        1
    } else {
        0
    };

    let scratch_ptr = match EVENT_SCRATCH.get_ptr_mut(0) {
        Some(p) => p,
        None => return,
    };
    let scratch = unsafe { &mut *scratch_ptr };

    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    scratch.hdr.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    scratch.hdr.conn_id = ssl_ptr;
    scratch.hdr.pid = (pid_tgid >> 32) as u32;
    scratch.hdr.tgid = pid_tgid as u32;
    scratch.hdr.len = want;
    scratch.hdr.direction = dir;
    scratch.hdr.truncated = truncated;
    scratch.hdr._pad = [0; 2];

    if unsafe {
        bpf_probe_read_user(
            scratch.data.as_mut_ptr() as *mut _,
            want,
            user_buf as *const _,
        )
    } != 0
    {
        return;
    }

    // Reserve enough for header + payload. Verifier needs a constant
    // upper bound; we always reserve max_size and tell userspace the
    // real length via hdr.len.
    let total = mem::size_of::<TlsEventHdr>() + MAX_PLAINTEXT;
    let mut entry = match TLS_EVENTS.reserve::<u8>(total as u32) {
        Some(e) => e,
        None => return,
    };
    let dst = entry.as_mut_ptr();
    unsafe {
        core::ptr::copy_nonoverlapping(
            scratch as *const _ as *const u8,
            dst,
            mem::size_of::<TlsEventHdr>() + want as usize,
        );
    }
    entry.submit(0);
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // BPF programs can't panic. The verifier rejects unreachable
    // calls, so this body never runs — it's only here to satisfy
    // the no_std + no_main build.
    loop {}
}

/// SPDX license tag the BPF loader requires for unrestricted helpers.
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
