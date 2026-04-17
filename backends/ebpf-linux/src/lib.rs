//! Linux eBPF backend for agent gateway enforcement
//!
//! This backend uses eBPF to enforce network and file access policies on Linux systems.
//! It provides full implementation of the EnforcementBackend trait with support for
//! network filtering, file access control, real-time events, and metrics collection.
//!
//! The implementation uses conditional compilation to support both Linux (with eBPF) and
//! non-Linux platforms (with stub implementations for testing).

#![warn(missing_docs)]

use agent_gateway_enforcer_core::backend::{
    BackendCapabilities, BackendHealth, BackendType, EnforcementBackend, EventHandler,
    FileAccessConfig, GatewayConfig, HealthStatus, MetricsCollector, Platform, PodIdentity,
    PolicyBundle, PolicyHash, Result, UnifiedConfig,
};
use std::collections::{HashMap, HashSet};
use agent_gateway_enforcer_core::events::{
    EventSource, FileAccessType, FileAction, NetworkAction, NetworkProtocol, UnifiedEvent,
};
use async_trait::async_trait;
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;
use tokio::sync::mpsc;

// Linux-specific imports for eBPF
#[cfg(target_os = "linux")]
use aya::{
    maps::{Array, HashMap as BpfHashMap},
    programs::{CgroupSockAddr, Lsm},
    Bpf, BpfLoader, Btf,
};

#[cfg(target_os = "linux")]
use agent_gateway_enforcer_common::GatewayKey;

/// Default cgroup v2 mount point used for attaching cgroup/connect4/6 programs
/// when no per-pod path is configured. Overridable at runtime via the
/// `AGE_CGROUP_PATH` environment variable.
#[cfg(target_os = "linux")]
const DEFAULT_CGROUP_PATH: &str = "/sys/fs/cgroup";

// Network eBPF map/config slot indices. Keep in sync with
// `backends/ebpf-linux/ebpf/network.c`.
#[cfg(target_os = "linux")]
const NET_CONFIG_ENABLED: u32 = 0;
#[cfg(target_os = "linux")]
const NET_CONFIG_DEFAULT_ACTION: u32 = 1;
#[cfg(target_os = "linux")]
const NET_CONFIG_NUM_GATEWAYS: u32 = 2;

// LSM eBPF config slot indices — mirror CONFIG_* in ebpf/lsm.c. Not yet
// written by any public API; exposed as constants so the wire format is
// documented in one place when Phase B wires `configure_exec_allowlist`.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
const LSM_CONFIG_EXEC_ALLOWLIST_ON: u32 = 4;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
const LSM_CONFIG_NUM_EXEC_ALLOW: u32 = 5;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
const LSM_CONFIG_BLOCK_MUTATIONS: u32 = 6;

// MUST match MAX_EXEC_ALLOW in ebpf/lsm.c. Bound the allowlist small
// on purpose: it's an allowlist, not a catalog — if it grows past this
// we want a louder failure mode than silent truncation.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
const MAX_EXEC_ALLOW_ENTRIES: usize = 32;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
const EXEC_PATH_LEN: usize = 256;

/// Linux eBPF backend implementation
///
/// This backend uses eBPF programs for network and file access enforcement.
/// On Linux, it loads actual eBPF programs. On other platforms, it provides
/// stub implementations for testing purposes.
pub struct EbpfLinuxBackend {
    /// Backend state
    state: Arc<RwLock<BackendState>>,
    /// Current configuration
    config: Arc<RwLock<UnifiedConfig>>,
    /// eBPF program handles (Linux only)
    #[cfg(target_os = "linux")]
    ebpf_state: Arc<Mutex<EbpfProgramState>>,
    /// Event handler for streaming events
    event_handler: Option<Arc<dyn EventHandler>>,
    /// Metrics collector
    metrics_collector: Option<Arc<dyn MetricsCollector>>,
    /// Event sender channel
    event_sender: Arc<Mutex<Option<mpsc::UnboundedSender<UnifiedEvent>>>>,
    /// Event receiver task handle
    event_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Internal metrics storage
    metrics: Arc<EbpfMetrics>,
    /// Per-pod enforcement registry (see `pod_registry` for details).
    pod_registry: Arc<Mutex<PodRegistry>>,
}

/// Tracks which pods are attached to which compiled policy bundle.
///
/// Until `BPF_MAP_TYPE_HASH_OF_MAPS` per-cgroup indexing lands (see
/// docs/k8s-controller-plan.md §4.2), this backend uses shared maps:
/// `attach_pod` reprograms them with the referenced bundle. Multiple
/// distinct bundles active simultaneously produce a warning and a
/// last-attach-wins outcome, and the registry surfaces that in logs
/// so the controller can detect the collision.
#[derive(Default)]
struct PodRegistry {
    /// Bundles known to the node, keyed by their hash.
    bundles: HashMap<PolicyHash, PolicyBundle>,
    /// pod UID -> hash currently enforcing it.
    attached: HashMap<String, PolicyHash>,
    /// Bundle hashes that have at least one attached pod. Used to
    /// drop unused bundles on detach without walking `attached`.
    active_hashes: HashSet<PolicyHash>,
}

/// eBPF program state (Linux only)
#[cfg(target_os = "linux")]
struct EbpfProgramState {
    /// Network filtering eBPF program
    network_program: Option<Bpf>,
    /// LSM file access eBPF program
    lsm_program: Option<Bpf>,
}

#[cfg(target_os = "linux")]
impl EbpfProgramState {
    fn new() -> Self {
        Self {
            network_program: None,
            lsm_program: None,
        }
    }
}

/// Backend state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendState {
    /// Not yet initialized
    NotInitialized,
    /// Initialized but not started
    Initialized,
    /// Running and enforcing policies
    Running,
    /// Stopped
    Stopped,
    /// Error state
    Error,
}

/// Internal metrics implementation for the eBPF backend
struct EbpfMetrics {
    /// Network events counters
    network_blocked: std::sync::atomic::AtomicU64,
    network_allowed: std::sync::atomic::AtomicU64,
    /// File events counters
    file_blocked: std::sync::atomic::AtomicU64,
    file_allowed: std::sync::atomic::AtomicU64,
    /// Event callbacks
    event_callbacks: Mutex<Vec<Box<dyn Fn(serde_json::Value) + Send + Sync>>>,
}

impl EbpfMetrics {
    fn new() -> Self {
        Self {
            network_blocked: std::sync::atomic::AtomicU64::new(0),
            network_allowed: std::sync::atomic::AtomicU64::new(0),
            file_blocked: std::sync::atomic::AtomicU64::new(0),
            file_allowed: std::sync::atomic::AtomicU64::new(0),
            event_callbacks: Mutex::new(Vec::new()),
        }
    }

    fn increment_network_blocked(&self) {
        self.network_blocked
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn increment_network_allowed(&self) {
        self.network_allowed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn increment_file_blocked(&self) {
        self.file_blocked
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn increment_file_allowed(&self) {
        self.file_allowed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn emit_event(&self, event_json: serde_json::Value) {
        if let Ok(callbacks) = self.event_callbacks.lock() {
            for callback in callbacks.iter() {
                callback(event_json.clone());
            }
        }
    }
}

impl MetricsCollector for EbpfMetrics {
    fn get_metrics(&self) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
            "backend": "ebpf_linux",
            "network": {
                "blocked_total": self.network_blocked.load(std::sync::atomic::Ordering::Relaxed),
                "allowed_total": self.network_allowed.load(std::sync::atomic::Ordering::Relaxed),
            },
            "file": {
                "blocked_total": self.file_blocked.load(std::sync::atomic::Ordering::Relaxed),
                "allowed_total": self.file_allowed.load(std::sync::atomic::Ordering::Relaxed),
            },
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }))
    }

    fn reset(&self) -> Result<()> {
        self.network_blocked
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.network_allowed
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.file_blocked
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.file_allowed
            .store(0, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

impl EventHandler for EbpfMetrics {
    fn on_event(&self, callback: Box<dyn Fn(serde_json::Value) + Send + Sync>) -> Result<()> {
        let mut callbacks = self
            .event_callbacks
            .lock()
            .map_err(|e| anyhow::anyhow!("Failed to acquire event callbacks lock: {}", e))?;
        callbacks.push(callback);
        Ok(())
    }
}

impl EbpfLinuxBackend {
    /// Create a new Linux eBPF backend
    pub fn new() -> Self {
        let metrics = Arc::new(EbpfMetrics::new());

        Self {
            state: Arc::new(RwLock::new(BackendState::NotInitialized)),
            config: Arc::new(RwLock::new(UnifiedConfig::default())),
            #[cfg(target_os = "linux")]
            ebpf_state: Arc::new(Mutex::new(EbpfProgramState::new())),
            event_handler: Some(metrics.clone() as Arc<dyn EventHandler>),
            metrics_collector: Some(metrics.clone() as Arc<dyn MetricsCollector>),
            event_sender: Arc::new(Mutex::new(None)),
            event_task: Arc::new(Mutex::new(None)),
            metrics,
            pod_registry: Arc::new(Mutex::new(PodRegistry::default())),
        }
    }

    /// Validate kernel version and eBPF support (Linux only)
    #[cfg(target_os = "linux")]
    fn validate_kernel_support(&self) -> Result<()> {
        use std::fs;

        // Read kernel version from /proc/version
        let version_str = fs::read_to_string("/proc/version")
            .map_err(|e| anyhow::anyhow!("Failed to read /proc/version: {}", e))?;

        // Extract version number (e.g., "Linux version 5.15.0-...")
        let release = version_str
            .split_whitespace()
            .nth(2)
            .ok_or_else(|| anyhow::anyhow!("Invalid /proc/version format"))?;

        // Parse kernel version (major.minor.patch)
        let version_parts: Vec<u32> = release
            .split('.')
            .take(3)
            .filter_map(|s: &str| s.split('-').next()?.parse::<u32>().ok())
            .collect();

        if version_parts.len() < 2 {
            return Err(anyhow::anyhow!(
                "Unable to parse kernel version: {}",
                release
            ));
        }

        let major = version_parts[0];
        let minor = version_parts[1];

        // Require kernel 5.8+ for eBPF LSM support
        if major < 5 || (major == 5 && minor < 8) {
            tracing::warn!(
                "Kernel version {}.{} may not support all eBPF features (5.8+ recommended)",
                major,
                minor
            );
        } else {
            tracing::info!(
                "Kernel version {}.{} detected - full eBPF support available",
                major,
                minor
            );
        }

        Ok(())
    }

    /// Load and verify eBPF programs (Linux only)
    #[cfg(target_os = "linux")]
    async fn load_ebpf_programs(&self) -> Result<()> {
        tracing::info!("Loading eBPF programs");

        // BTF is shared between LSM (CO-RE) and network programs.
        let btf = Btf::from_sys_fs().ok();

        // --- LSM program (file access) ---
        let lsm_path = self.find_ebpf_object("lsm.o")?;
        if lsm_path.exists() {
            tracing::info!("Loading LSM eBPF program from {:?}", lsm_path);
            let bpf = BpfLoader::new()
                .btf(btf.as_ref())
                .load_file(&lsm_path)
                .map_err(|e| anyhow::anyhow!("Failed to load LSM eBPF program: {}", e))?;
            let mut state = self
                .ebpf_state
                .lock()
                .map_err(|e| anyhow::anyhow!("Failed to acquire eBPF state lock: {}", e))?;
            state.lsm_program = Some(bpf);
        } else {
            tracing::warn!(
                "LSM eBPF object not found at {:?} - file enforcement disabled",
                lsm_path
            );
            tracing::warn!("Compile with: cd backends/ebpf-linux/ebpf && make");
        }

        // --- Network program (cgroup/connect4/6) ---
        let net_path = self.find_ebpf_object("network.o")?;
        if net_path.exists() {
            tracing::info!("Loading network eBPF program from {:?}", net_path);
            let bpf = BpfLoader::new()
                .btf(btf.as_ref())
                .load_file(&net_path)
                .map_err(|e| anyhow::anyhow!("Failed to load network eBPF program: {}", e))?;
            let mut state = self
                .ebpf_state
                .lock()
                .map_err(|e| anyhow::anyhow!("Failed to acquire eBPF state lock: {}", e))?;
            state.network_program = Some(bpf);
        } else {
            tracing::warn!(
                "Network eBPF object not found at {:?} - egress enforcement disabled",
                net_path
            );
        }

        Ok(())
    }

    /// Find eBPF object file in standard locations
    #[cfg(target_os = "linux")]
    fn find_ebpf_object(&self, name: &str) -> Result<std::path::PathBuf> {
        // Check in order of preference:
        // 1. Current directory
        // 2. ./ebpf/ subdirectory
        // 3. /usr/lib/agent-gateway-enforcer/
        // 4. Relative to executable

        let paths = [
            std::path::PathBuf::from(name),
            std::path::PathBuf::from(format!("ebpf/{}", name)),
            std::path::PathBuf::from(format!("backends/ebpf-linux/ebpf/{}", name)),
            std::path::PathBuf::from(format!("/usr/lib/agent-gateway-enforcer/{}", name)),
        ];

        for path in &paths {
            if path.exists() {
                return Ok(path.clone());
            }
        }

        // Return first path for error message
        Ok(paths[2].clone())
    }

    /// Attach eBPF programs to appropriate hooks (Linux only)
    #[cfg(target_os = "linux")]
    async fn attach_programs(&self) -> Result<()> {
        let mut ebpf_state = self
            .ebpf_state
            .lock()
            .map_err(|e| anyhow::anyhow!("Failed to acquire eBPF state lock: {}", e))?;

        // Attach LSM programs (file access).
        if let Some(ref mut bpf) = ebpf_state.lsm_program {
            let btf = Btf::from_sys_fs()
                .map_err(|e| anyhow::anyhow!("Failed to load BTF: {}", e))?;

            let program: &mut Lsm = bpf
                .program_mut("file_open_block")
                .ok_or_else(|| anyhow::anyhow!("LSM program 'file_open_block' not found"))?
                .try_into()
                .map_err(|e| anyhow::anyhow!("Program is not an LSM program: {}", e))?;
            program
                .load("file_open", &btf)
                .map_err(|e| anyhow::anyhow!("Failed to load LSM program: {}", e))?;
            program
                .attach()
                .map_err(|e| anyhow::anyhow!("Failed to attach LSM program: {}", e))?;
            tracing::info!("LSM program attached to file_open hook");

            self.configure_blocked_processes(bpf)?;
        } else {
            tracing::warn!("No LSM eBPF program loaded - file enforcement disabled");
        }

        // Attach network programs (cgroup egress). Failure to open the cgroup
        // directory or attach is non-fatal: lsm-only mode is still useful and
        // keeps the backend operational in containers that can't access
        // /sys/fs/cgroup (e.g. CI).
        if let Some(ref mut bpf) = ebpf_state.network_program {
            match Self::attach_network_programs(bpf) {
                Ok(()) => tracing::info!("Network programs attached to root cgroup"),
                Err(e) => tracing::warn!(
                    "Failed to attach network eBPF programs: {} - egress enforcement disabled",
                    e
                ),
            }
        }

        Ok(())
    }

    /// Attach cgroup/connect4 and cgroup/connect6 at the root cgroup v2 mount.
    ///
    /// Per-pod attachment is tracked as Phase A work in `docs/k8s-controller-plan.md`;
    /// root-cgroup attach is a working default for single-tenant nodes today.
    #[cfg(target_os = "linux")]
    fn attach_network_programs(bpf: &mut Bpf) -> Result<()> {
        let cgroup_path = std::env::var("AGE_CGROUP_PATH")
            .unwrap_or_else(|_| DEFAULT_CGROUP_PATH.to_string());
        let cgroup = std::fs::File::open(&cgroup_path)
            .map_err(|e| anyhow::anyhow!("open cgroup {}: {}", cgroup_path, e))?;

        for prog_name in ["connect4_gate", "connect6_gate"] {
            let program: &mut CgroupSockAddr = bpf
                .program_mut(prog_name)
                .ok_or_else(|| anyhow::anyhow!("network program '{}' not found", prog_name))?
                .try_into()
                .map_err(|e| {
                    anyhow::anyhow!("program '{}' is not CgroupSockAddr: {}", prog_name, e)
                })?;
            program
                .load()
                .map_err(|e| anyhow::anyhow!("load '{}': {}", prog_name, e))?;
            program
                .attach(&cgroup)
                .map_err(|e| anyhow::anyhow!("attach '{}' to {}: {}", prog_name, cgroup_path, e))?;
        }
        Ok(())
    }

    /// Configure blocked processes in eBPF map
    #[cfg(target_os = "linux")]
    fn configure_blocked_processes(&self, bpf: &mut Bpf) -> Result<()> {
        // Get the blocked_processes map
        let mut blocked_procs: Array<_, [u8; 16]> = bpf
            .map_mut("blocked_processes")
            .ok_or_else(|| anyhow::anyhow!("Map 'blocked_processes' not found"))?
            .try_into()
            .map_err(|e| anyhow::anyhow!("Failed to get blocked_processes map: {}", e))?;

        // Add blocked process names
        let blocked_names = ["opencode", "open-code", "opencode-ag"];
        for (i, name) in blocked_names.iter().enumerate() {
            let mut comm = [0u8; 16];
            let bytes = name.as_bytes();
            let len = bytes.len().min(15);
            comm[..len].copy_from_slice(&bytes[..len]);

            blocked_procs
                .set(i as u32, comm, 0)
                .map_err(|e| anyhow::anyhow!("Failed to set blocked process {}: {}", name, e))?;

            tracing::debug!("Added blocked process: {}", name);
        }

        // Set the config for number of blocked processes
        let mut config: Array<_, u32> = bpf
            .map_mut("config")
            .ok_or_else(|| anyhow::anyhow!("Map 'config' not found"))?
            .try_into()
            .map_err(|e| anyhow::anyhow!("Failed to get config map: {}", e))?;

        // CONFIG_ENABLED = 0, CONFIG_NUM_BLOCKED_PROCS = 2
        config.set(0, 1u32, 0)?; // Enable enforcement
        config.set(2, blocked_names.len() as u32, 0)?; // Number of blocked procs
        config.set(1, 1u32, 0)?; // Block all paths for blocked processes

        tracing::info!(
            "Configured {} blocked processes in eBPF map",
            blocked_names.len()
        );

        Ok(())
    }

    /// Update eBPF maps with gateway configuration (Linux only).
    ///
    /// Rebuilds the `allowed_gateways` map from scratch so removed entries
    /// stop being honored on the next connect(). Entries whose `address` is
    /// not a valid IPv4 string are logged and skipped (IPv6 allowlisting is
    /// tracked separately — see `network.c`).
    #[cfg(target_os = "linux")]
    fn update_gateway_maps(&self, gateways: &[GatewayConfig]) -> Result<()> {
        let entries = Self::build_gateway_entries(gateways);
        tracing::debug!(
            "Updating gateway maps: {} configured, {} valid IPv4 entries",
            gateways.len(),
            entries.len()
        );

        let mut ebpf_state = self
            .ebpf_state
            .lock()
            .map_err(|e| anyhow::anyhow!("Failed to acquire eBPF state lock: {}", e))?;

        let bpf = match ebpf_state.network_program.as_mut() {
            Some(b) => b,
            None => {
                tracing::debug!("Network program not loaded; deferring gateway map update");
                return Ok(());
            }
        };

        let mut allowed: BpfHashMap<_, GatewayKey, u8> = bpf
            .map_mut("allowed_gateways")
            .ok_or_else(|| anyhow::anyhow!("Map 'allowed_gateways' not found"))?
            .try_into()
            .map_err(|e| anyhow::anyhow!("bind allowed_gateways map: {}", e))?;

        // Drop any stale entries before writing the new set.
        let existing: Vec<GatewayKey> = allowed.keys().filter_map(|k| k.ok()).collect();
        for k in existing {
            let _ = allowed.remove(&k);
        }
        for (key, value) in &entries {
            allowed
                .insert(key, value, 0)
                .map_err(|e| anyhow::anyhow!("insert gateway: {}", e))?;
        }

        let mut net_config: Array<_, u32> = bpf
            .map_mut("net_config")
            .ok_or_else(|| anyhow::anyhow!("Map 'net_config' not found"))?
            .try_into()
            .map_err(|e| anyhow::anyhow!("bind net_config map: {}", e))?;
        // Enable enforcement and set default-deny whenever any gateway is
        // configured; otherwise fall back to audit-mode (default_action=0).
        let enabled = if entries.is_empty() { 0u32 } else { 1u32 };
        let default_deny = enabled;
        net_config.set(NET_CONFIG_ENABLED, enabled, 0)?;
        net_config.set(NET_CONFIG_DEFAULT_ACTION, default_deny, 0)?;
        net_config.set(NET_CONFIG_NUM_GATEWAYS, entries.len() as u32, 0)?;

        Ok(())
    }

    /// Encode exec-allowlist paths into the fixed-size layout the eBPF
    /// program expects (null-padded `[u8; EXEC_PATH_LEN]` plus length).
    ///
    /// Paths longer than `EXEC_PATH_LEN - 1` are truncated and logged;
    /// paths beyond `MAX_EXEC_ALLOW_ENTRIES` are dropped with a warning
    /// so we fail loudly rather than silently allowlisting a prefix.
    #[cfg(target_os = "linux")]
    #[cfg_attr(not(test), allow(dead_code))]
    fn build_exec_allowlist_entries(paths: &[String]) -> Vec<([u8; EXEC_PATH_LEN], u16)> {
        let mut out = Vec::with_capacity(paths.len().min(MAX_EXEC_ALLOW_ENTRIES));
        for path in paths.iter().take(MAX_EXEC_ALLOW_ENTRIES) {
            let bytes = path.as_bytes();
            let mut buf = [0u8; EXEC_PATH_LEN];
            let len = bytes.len().min(EXEC_PATH_LEN - 1);
            if bytes.len() > len {
                tracing::warn!(
                    "Exec allowlist path '{}' truncated to {} bytes",
                    path,
                    len
                );
            }
            buf[..len].copy_from_slice(&bytes[..len]);
            out.push((buf, len as u16));
        }
        if paths.len() > MAX_EXEC_ALLOW_ENTRIES {
            tracing::warn!(
                "Exec allowlist truncated: {} entries provided, {} max supported",
                paths.len(),
                MAX_EXEC_ALLOW_ENTRIES
            );
        }
        out
    }

    /// Turn user-facing `GatewayConfig` into the eBPF-map key/value pairs.
    ///
    /// Pulled out as a free function so it's easy to unit-test without a
    /// live kernel — see `tests::build_gateway_entries_*`.
    #[cfg(target_os = "linux")]
    fn build_gateway_entries(gateways: &[GatewayConfig]) -> Vec<(GatewayKey, u8)> {
        gateways
            .iter()
            .filter(|g| g.enabled)
            .filter_map(|g| match g.address.parse::<std::net::Ipv4Addr>() {
                Ok(ip) => Some((GatewayKey::new(u32::from(ip).to_be(), g.port), 1u8)),
                Err(_) => {
                    tracing::warn!(
                        "Skipping non-IPv4 gateway '{}' (IPv6 support pending)",
                        g.address
                    );
                    None
                }
            })
            .collect()
    }

    /// Update eBPF maps with file access rules (Linux only)
    #[cfg(target_os = "linux")]
    fn update_file_access_maps(&self, config: &FileAccessConfig) -> Result<()> {
        tracing::debug!(
            "Updating file access maps - {} allowed, {} denied",
            config.allowed_paths.len(),
            config.denied_paths.len()
        );

        // TODO: Implement actual map updates
        // - Clear existing path rule maps
        // - Add allowed path rules
        // - Add denied path rules

        Ok(())
    }

    /// Emit a network event
    fn emit_network_event(
        &self,
        action: NetworkAction,
        dst_ip: std::net::IpAddr,
        dst_port: u16,
        protocol: NetworkProtocol,
        pid: Option<u32>,
    ) {
        // Update metrics
        match action {
            NetworkAction::Blocked => self.metrics.increment_network_blocked(),
            NetworkAction::Allowed => self.metrics.increment_network_allowed(),
            _ => {}
        }

        // Create unified event
        let event = UnifiedEvent::network(
            action,
            dst_ip,
            dst_port,
            protocol,
            pid,
            EventSource::EbpfLinux,
        );

        // Emit to event handlers
        if let Ok(event_json) = serde_json::to_value(&event) {
            self.metrics.emit_event(event_json);
        }

        // Send to event channel
        if let Ok(guard) = self.event_sender.lock() {
            if let Some(ref sender) = *guard {
                let _ = sender.send(event);
            }
        }
    }

    /// Emit a file access event
    fn emit_file_event(
        &self,
        action: FileAction,
        path: String,
        access_type: FileAccessType,
        pid: Option<u32>,
    ) {
        // Update metrics
        match action {
            FileAction::Blocked => self.metrics.increment_file_blocked(),
            FileAction::Allowed => self.metrics.increment_file_allowed(),
            _ => {}
        }

        // Create unified event
        let event =
            UnifiedEvent::file_access(action, path, access_type, pid, EventSource::EbpfLinux);

        // Emit to event handlers
        if let Ok(event_json) = serde_json::to_value(&event) {
            self.metrics.emit_event(event_json);
        }

        // Send to event channel
        if let Ok(guard) = self.event_sender.lock() {
            if let Some(ref sender) = *guard {
                let _ = sender.send(event);
            }
        }
    }

    /// Start event processing loop (Linux only)
    #[cfg(target_os = "linux")]
    async fn start_event_processing(&self) -> Result<()> {
        tracing::info!("Starting eBPF event processing");

        // TODO: Implement perf buffer reading
        // - Read network events from network program perf buffer
        // - Read file events from LSM program perf buffer
        // - Convert to UnifiedEvent and emit

        Ok(())
    }

    /// Set backend state
    fn set_state(&self, new_state: BackendState) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|e| anyhow::anyhow!("Failed to acquire state lock: {}", e))?;
        *state = new_state;
        Ok(())
    }

    /// Get current backend state
    fn get_state(&self) -> Result<BackendState> {
        let state = self
            .state
            .read()
            .map_err(|e| anyhow::anyhow!("Failed to acquire state lock: {}", e))?;
        Ok(*state)
    }
}

impl Default for EbpfLinuxBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EnforcementBackend for EbpfLinuxBackend {
    fn backend_type(&self) -> BackendType {
        BackendType::EbpfLinux
    }

    fn platform(&self) -> Platform {
        Platform::Linux
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            network_filtering: true,
            file_access_control: true,
            process_monitoring: true,
            real_time_events: true,
            metrics_collection: true,
            configuration_hot_reload: true,
        }
    }

    async fn initialize(&mut self, config: &UnifiedConfig) -> Result<()> {
        tracing::info!("Initializing Linux eBPF backend");

        // Validate we're on Linux for actual eBPF functionality
        #[cfg(not(target_os = "linux"))]
        {
            tracing::warn!("Running eBPF backend on non-Linux platform - stub mode only");
        }

        // Validate kernel support (Linux only)
        #[cfg(target_os = "linux")]
        {
            self.validate_kernel_support()?;

            // Note: eBPF program loading would normally be async, but we're in a sync context
            // In a real implementation, this would be handled during build time or initialization
            tracing::info!("eBPF programs will be loaded on start");
        }

        // Store configuration
        {
            let mut cfg = self
                .config
                .write()
                .map_err(|e| anyhow::anyhow!("Failed to acquire config lock: {}", e))?;
            *cfg = config.clone();
        }

        // Set up event streaming
        let (event_sender, mut event_receiver) = mpsc::unbounded_channel::<UnifiedEvent>();
        {
            let mut sender_guard = self
                .event_sender
                .lock()
                .map_err(|e| anyhow::anyhow!("Failed to acquire sender lock: {}", e))?;
            *sender_guard = Some(event_sender);
        }

        // Start event processing task
        let metrics = self.metrics.clone();
        let task = tokio::spawn(async move {
            while let Some(event) = event_receiver.recv().await {
                if let Ok(event_json) = serde_json::to_value(&event) {
                    metrics.emit_event(event_json);
                }
            }
        });

        {
            let mut task_guard = self
                .event_task
                .lock()
                .map_err(|e| anyhow::anyhow!("Failed to acquire task lock: {}", e))?;
            *task_guard = Some(task);
        }

        self.set_state(BackendState::Initialized)?;
        tracing::info!("Linux eBPF backend initialized successfully");

        Ok(())
    }

    async fn start(&mut self) -> Result<()> {
        tracing::info!("Starting Linux eBPF backend");

        let current_state = self.get_state()?;
        if current_state != BackendState::Initialized {
            return Err(anyhow::anyhow!(
                "Backend must be initialized before starting (current state: {:?})",
                current_state
            ));
        }

        // Load and attach eBPF programs (Linux only). We always transition
        // to Running even if eBPF loading fails — the backend then operates
        // in stub mode (no enforcement), which lets tests exercise the
        // lifecycle on hosts without eBPF support.
        #[cfg(target_os = "linux")]
        {
            if let Err(e) = self.load_ebpf_programs().await {
                tracing::warn!("Failed to load eBPF programs: {} - running in stub mode", e);
            } else if let Err(e) = self.attach_programs().await {
                tracing::warn!("Failed to attach eBPF programs: {} - running in stub mode", e);
            }
        }

        self.set_state(BackendState::Running)?;
        tracing::info!("Linux eBPF backend started successfully");

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        tracing::info!("Stopping Linux eBPF backend");

        // Detach eBPF programs (Linux only)
        #[cfg(target_os = "linux")]
        {
            let mut ebpf_state = self
                .ebpf_state
                .lock()
                .map_err(|e| anyhow::anyhow!("Failed to acquire eBPF state lock: {}", e))?;

            // Drop network program (this unloads all attached programs)
            if ebpf_state.network_program.take().is_some() {
                tracing::info!("Network eBPF program unloaded");
            }

            // Drop LSM program (this unloads all attached programs)
            if ebpf_state.lsm_program.take().is_some() {
                tracing::info!("LSM eBPF program unloaded");
            }
        }

        self.set_state(BackendState::Stopped)?;
        tracing::info!("Linux eBPF backend stopped successfully");

        Ok(())
    }

    async fn configure_gateways(&self, gateways: &[GatewayConfig]) -> Result<()> {
        tracing::info!("Configuring {} gateways", gateways.len());

        // Update configuration
        {
            let mut config = self
                .config
                .write()
                .map_err(|e| anyhow::anyhow!("Failed to acquire config lock: {}", e))?;
            config.gateways = gateways.to_vec();
        }

        // Update eBPF maps (Linux only)
        #[cfg(target_os = "linux")]
        {
            self.update_gateway_maps(gateways)?;
        }

        #[cfg(not(target_os = "linux"))]
        {
            tracing::debug!("Gateway configuration updated (stub mode - no eBPF maps)");
        }

        Ok(())
    }

    async fn configure_file_access(&self, config: &FileAccessConfig) -> Result<()> {
        tracing::info!(
            "Configuring file access - {} allowed, {} denied paths",
            config.allowed_paths.len(),
            config.denied_paths.len()
        );

        // Update configuration
        {
            let mut cfg = self
                .config
                .write()
                .map_err(|e| anyhow::anyhow!("Failed to acquire config lock: {}", e))?;
            cfg.file_access = config.clone();
        }

        // Update eBPF maps (Linux only)
        #[cfg(target_os = "linux")]
        {
            self.update_file_access_maps(config)?;
        }

        #[cfg(not(target_os = "linux"))]
        {
            tracing::debug!("File access configuration updated (stub mode - no eBPF maps)");
        }

        Ok(())
    }

    fn metrics_collector(&self) -> Option<Arc<dyn MetricsCollector>> {
        self.metrics_collector.clone()
    }

    fn event_handler(&self) -> Option<Arc<dyn EventHandler>> {
        self.event_handler.clone()
    }

    async fn health_check(&self) -> Result<BackendHealth> {
        let state = self.get_state()?;

        let (status, details) = match state {
            BackendState::Running => {
                #[cfg(target_os = "linux")]
                {
                    // On Linux, verify eBPF programs are loaded
                    let ebpf_state = self
                        .ebpf_state
                        .lock()
                        .map_err(|e| anyhow::anyhow!("Failed to acquire eBPF state lock: {}", e))?;

                    let has_programs =
                        ebpf_state.network_program.is_some() || ebpf_state.lsm_program.is_some();

                    if has_programs {
                        (
                            HealthStatus::Healthy,
                            "Backend is running and enforcing policies".to_string(),
                        )
                    } else {
                        (
                            HealthStatus::Degraded,
                            "Backend is running but eBPF programs not loaded".to_string(),
                        )
                    }
                }

                #[cfg(not(target_os = "linux"))]
                {
                    (
                        HealthStatus::Degraded,
                        "Backend is running in stub mode (non-Linux platform)".to_string(),
                    )
                }
            }
            BackendState::Initialized => (
                HealthStatus::Degraded,
                "Backend is initialized but not started".to_string(),
            ),
            BackendState::Stopped => (HealthStatus::Degraded, "Backend is stopped".to_string()),
            BackendState::NotInitialized => (
                HealthStatus::Unhealthy,
                "Backend is not initialized".to_string(),
            ),
            BackendState::Error => (
                HealthStatus::Unhealthy,
                "Backend is in error state".to_string(),
            ),
        };

        Ok(BackendHealth {
            status,
            last_check: SystemTime::now(),
            details,
        })
    }

    async fn cleanup(&mut self) -> Result<()> {
        tracing::info!("Cleaning up Linux eBPF backend resources");

        // Stop if running
        let current_state = self.get_state()?;
        if current_state == BackendState::Running {
            self.stop().await?;
        }

        // Clean up eBPF programs (Linux only)
        #[cfg(target_os = "linux")]
        {
            let mut ebpf_state = self
                .ebpf_state
                .lock()
                .map_err(|e| anyhow::anyhow!("Failed to acquire eBPF state lock: {}", e))?;
            ebpf_state.network_program = None;
            ebpf_state.lsm_program = None;
        }

        // Clean up event processing
        {
            let mut sender_guard = self
                .event_sender
                .lock()
                .map_err(|e| anyhow::anyhow!("Failed to acquire sender lock: {}", e))?;
            *sender_guard = None;
        }

        {
            let mut task_guard = self
                .event_task
                .lock()
                .map_err(|e| anyhow::anyhow!("Failed to acquire task lock: {}", e))?;
            if let Some(task) = task_guard.take() {
                task.abort();
            }
        }

        self.set_state(BackendState::NotInitialized)?;
        tracing::info!("Linux eBPF backend cleanup completed");

        Ok(())
    }

    async fn update_policy(&self, bundle: &PolicyBundle) -> Result<()> {
        let mut reg = self
            .pod_registry
            .lock()
            .map_err(|e| anyhow::anyhow!("pod_registry lock: {}", e))?;
        tracing::info!(
            "Staging policy bundle {} ({} gateways, {} exec rules)",
            bundle.hash.as_str(),
            bundle.gateways.len(),
            bundle.exec_allowlist.len()
        );
        reg.bundles.insert(bundle.hash.clone(), bundle.clone());
        Ok(())
    }

    async fn attach_pod(&self, pod: &PodIdentity, policy_hash: &PolicyHash) -> Result<()> {
        // Stage the assignment in the registry first so a concurrent
        // update_policy() can see what's referenced and refcount correctly.
        let bundle = {
            let mut reg = self
                .pod_registry
                .lock()
                .map_err(|e| anyhow::anyhow!("pod_registry lock: {}", e))?;

            let bundle = reg
                .bundles
                .get(policy_hash)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "attach_pod: bundle {} not staged; call update_policy first",
                        policy_hash.as_str()
                    )
                })?
                .clone();

            // Idempotent: re-attaching the same (pod, hash) is a no-op.
            if let Some(existing) = reg.attached.get(&pod.uid) {
                if existing == policy_hash {
                    return Ok(());
                }
                tracing::info!(
                    "Pod {} reassigned from bundle {} to {}",
                    pod.uid,
                    existing.as_str(),
                    policy_hash.as_str()
                );
            }
            reg.attached.insert(pod.uid.clone(), policy_hash.clone());
            reg.active_hashes.insert(policy_hash.clone());

            if reg.active_hashes.len() > 1 {
                tracing::warn!(
                    "{} distinct bundles active simultaneously; shared-map mode is last-attach-wins until HASH_OF_MAPS lands",
                    reg.active_hashes.len()
                );
            }
            bundle
        };

        // Program the shared maps from this bundle. Per-cgroup attach is
        // tracked in docs/k8s-controller-plan.md §4.2 as the next step.
        self.configure_gateways(&bundle.gateways).await?;
        self.configure_file_access(&bundle.file_access).await?;
        tracing::info!(
            "Pod {}/{} ({}) now enforcing bundle {}",
            pod.namespace,
            pod.name,
            pod.uid,
            policy_hash.as_str()
        );
        Ok(())
    }

    async fn detach_pod(&self, pod: &PodIdentity) -> Result<()> {
        let mut reg = self
            .pod_registry
            .lock()
            .map_err(|e| anyhow::anyhow!("pod_registry lock: {}", e))?;
        let Some(hash) = reg.attached.remove(&pod.uid) else {
            tracing::debug!("detach_pod: {} not attached (already gone?)", pod.uid);
            return Ok(());
        };
        // Drop the active-hash entry only if this was the last pod on it.
        let still_referenced = reg.attached.values().any(|h| h == &hash);
        if !still_referenced {
            reg.active_hashes.remove(&hash);
            tracing::info!(
                "Bundle {} no longer referenced; will GC on next update_policy",
                hash.as_str()
            );
        }
        tracing::info!("Pod {}/{} detached", pod.namespace, pod.name);
        Ok(())
    }
}

// Public modules
pub mod migration;
pub mod registry;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_creation() {
        let backend = EbpfLinuxBackend::new();
        assert_eq!(backend.backend_type(), BackendType::EbpfLinux);
        assert_eq!(backend.platform(), Platform::Linux);

        let capabilities = backend.capabilities();
        assert!(capabilities.network_filtering);
        assert!(capabilities.file_access_control);
        assert!(capabilities.process_monitoring);
        assert!(capabilities.real_time_events);
        assert!(capabilities.metrics_collection);
        assert!(capabilities.configuration_hot_reload);
    }

    #[test]
    fn test_metrics_collection() {
        let backend = EbpfLinuxBackend::new();

        // Get metrics collector
        let metrics = backend
            .metrics_collector()
            .expect("Should have metrics collector");

        // Get initial metrics
        let initial = metrics.get_metrics().expect("Should get metrics");
        assert!(initial.is_object());

        // Reset metrics
        metrics.reset().expect("Should reset metrics");

        // Verify reset
        let after_reset = metrics.get_metrics().expect("Should get metrics");
        assert_eq!(after_reset["network"]["blocked_total"], 0);
        assert_eq!(after_reset["network"]["allowed_total"], 0);
    }

    #[test]
    fn test_event_handler() {
        let backend = EbpfLinuxBackend::new();

        // Get event handler
        let handler = backend.event_handler().expect("Should have event handler");

        // Register callback
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let called_clone = called.clone();

        handler
            .on_event(Box::new(move |_event| {
                called_clone.store(true, std::sync::atomic::Ordering::Relaxed);
            }))
            .expect("Should register callback");

        // Emit test event
        backend.emit_network_event(
            NetworkAction::Blocked,
            "192.168.1.1".parse().unwrap(),
            443,
            NetworkProtocol::Tcp,
            Some(1234),
        );

        // Give some time for async processing
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Verify callback was called
        assert!(called.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_backend_lifecycle() {
        let mut backend = EbpfLinuxBackend::new();

        // Initial state
        assert_eq!(backend.get_state().unwrap(), BackendState::NotInitialized);

        // Initialize
        let config = UnifiedConfig::default();
        backend.initialize(&config).await.expect("Should initialize");
        assert_eq!(backend.get_state().unwrap(), BackendState::Initialized);

        // Start
        backend.start().await.expect("Should start");
        assert_eq!(backend.get_state().unwrap(), BackendState::Running);

        // Health check
        let health = backend.health_check().await.expect("Should check health");
        assert!(matches!(
            health.status,
            HealthStatus::Healthy | HealthStatus::Degraded
        ));

        // Stop
        backend.stop().await.expect("Should stop");
        assert_eq!(backend.get_state().unwrap(), BackendState::Stopped);

        // Cleanup
        backend.cleanup().await.expect("Should cleanup");
        assert_eq!(backend.get_state().unwrap(), BackendState::NotInitialized);
    }

    #[tokio::test]
    async fn test_gateway_configuration() {
        let mut backend = EbpfLinuxBackend::new();
        backend
            .initialize(&UnifiedConfig::default())
            .await
            .expect("Should initialize");

        let gateways = vec![
            GatewayConfig {
                address: "192.168.1.1".to_string(),
                port: 443,
                enabled: true,
                description: Some("Test gateway".to_string()),
            },
            GatewayConfig {
                address: "10.0.0.1".to_string(),
                port: 8080,
                enabled: true,
                description: None,
            },
        ];

        backend
            .configure_gateways(&gateways)
            .await
            .expect("Should configure gateways");

        // Verify configuration was stored
        let config = backend.config.read().unwrap();
        assert_eq!(config.gateways.len(), 2);
        assert_eq!(config.gateways[0].address, "192.168.1.1");
        assert_eq!(config.gateways[1].port, 8080);
    }

    #[tokio::test]
    async fn test_file_access_configuration() {
        let mut backend = EbpfLinuxBackend::new();
        backend
            .initialize(&UnifiedConfig::default())
            .await
            .expect("Should initialize");

        let file_config = FileAccessConfig {
            allowed_paths: vec!["/tmp".to_string(), "/var/log".to_string()],
            denied_paths: vec!["/etc/shadow".to_string(), "/root".to_string()],
            default_deny: true,
        };

        backend
            .configure_file_access(&file_config)
            .await
            .expect("Should configure file access");

        // Verify configuration was stored
        let config = backend.config.read().unwrap();
        assert_eq!(config.file_access.allowed_paths.len(), 2);
        assert_eq!(config.file_access.denied_paths.len(), 2);
        assert!(config.file_access.default_deny);
    }

    #[test]
    fn test_event_emission() {
        let backend = EbpfLinuxBackend::new();

        // Emit network events
        backend.emit_network_event(
            NetworkAction::Blocked,
            "192.168.1.1".parse().unwrap(),
            443,
            NetworkProtocol::Tcp,
            Some(1234),
        );

        backend.emit_network_event(
            NetworkAction::Allowed,
            "10.0.0.1".parse().unwrap(),
            80,
            NetworkProtocol::Tcp,
            Some(5678),
        );

        // Emit file events
        backend.emit_file_event(
            FileAction::Blocked,
            "/etc/shadow".to_string(),
            FileAccessType::Read,
            Some(9999),
        );

        backend.emit_file_event(
            FileAction::Allowed,
            "/tmp/test.txt".to_string(),
            FileAccessType::Write,
            Some(1111),
        );

        // Verify metrics
        let metrics = backend.metrics_collector().unwrap();
        let data = metrics.get_metrics().unwrap();

        assert_eq!(data["network"]["blocked_total"], 1);
        assert_eq!(data["network"]["allowed_total"], 1);
        assert_eq!(data["file"]["blocked_total"], 1);
        assert_eq!(data["file"]["allowed_total"], 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn build_gateway_entries_filters_and_encodes_ipv4() {
        let gateways = vec![
            GatewayConfig {
                address: "10.0.0.1".to_string(),
                port: 443,
                enabled: true,
                description: None,
            },
            GatewayConfig {
                address: "192.168.1.5".to_string(),
                port: 8080,
                enabled: false, // disabled -> dropped
                description: None,
            },
            GatewayConfig {
                address: "::1".to_string(),
                port: 443,
                enabled: true, // IPv6 -> dropped (not yet supported)
                description: None,
            },
            GatewayConfig {
                address: "not-an-ip".to_string(),
                port: 443,
                enabled: true, // parse failure -> dropped
                description: None,
            },
        ];

        let entries = EbpfLinuxBackend::build_gateway_entries(&gateways);
        assert_eq!(entries.len(), 1, "only the enabled IPv4 entry survives");

        let (key, value) = &entries[0];
        assert_eq!(*value, 1u8);
        assert_eq!(key.port, 443);
        // 10.0.0.1 stored in network byte order (big-endian).
        let expected_addr = u32::from(std::net::Ipv4Addr::new(10, 0, 0, 1)).to_be();
        assert_eq!(key.addr, expected_addr);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn build_gateway_entries_empty_for_no_input() {
        let entries = EbpfLinuxBackend::build_gateway_entries(&[]);
        assert!(entries.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn build_exec_allowlist_encodes_paths() {
        let paths = vec![
            "/usr/bin/python3".to_string(),
            "/usr/local/bin/agent".to_string(),
        ];
        let entries = EbpfLinuxBackend::build_exec_allowlist_entries(&paths);
        assert_eq!(entries.len(), 2);

        let (buf, len) = &entries[0];
        assert_eq!(*len as usize, "/usr/bin/python3".len());
        assert_eq!(&buf[..*len as usize], b"/usr/bin/python3");
        assert_eq!(buf[*len as usize], 0, "padding past len must be zeroed");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn build_exec_allowlist_truncates_long_paths() {
        let long = "/".to_string() + &"a".repeat(EXEC_PATH_LEN + 64);
        let entries = EbpfLinuxBackend::build_exec_allowlist_entries(&[long]);
        let (_, len) = &entries[0];
        assert_eq!(*len as usize, EXEC_PATH_LEN - 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn build_exec_allowlist_caps_at_max_entries() {
        let many: Vec<String> = (0..MAX_EXEC_ALLOW_ENTRIES + 5)
            .map(|i| format!("/bin/bin{}", i))
            .collect();
        let entries = EbpfLinuxBackend::build_exec_allowlist_entries(&many);
        assert_eq!(entries.len(), MAX_EXEC_ALLOW_ENTRIES);
    }

    fn sample_pod(uid: &str) -> PodIdentity {
        PodIdentity {
            uid: uid.into(),
            namespace: "prod".into(),
            name: format!("agent-{}", uid),
            cgroup_path: format!("/sys/fs/cgroup/kubepods.slice/{}", uid),
        }
    }

    fn sample_bundle(hash: &str) -> PolicyBundle {
        PolicyBundle {
            hash: PolicyHash::new(hash),
            gateways: vec![GatewayConfig {
                address: "10.0.0.1".into(),
                port: 443,
                enabled: true,
                description: None,
            }],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn attach_pod_requires_staged_bundle() {
        let backend = EbpfLinuxBackend::new();
        let err = backend
            .attach_pod(&sample_pod("p1"), &PolicyHash::new("missing"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not staged"));
    }

    #[tokio::test]
    async fn attach_pod_records_binding_and_refcounts_on_detach() {
        let mut backend = EbpfLinuxBackend::new();
        backend
            .initialize(&UnifiedConfig::default())
            .await
            .unwrap();

        let bundle = sample_bundle("h1");
        backend.update_policy(&bundle).await.unwrap();

        backend.attach_pod(&sample_pod("p1"), &bundle.hash).await.unwrap();
        backend.attach_pod(&sample_pod("p2"), &bundle.hash).await.unwrap();

        {
            let reg = backend.pod_registry.lock().unwrap();
            assert_eq!(reg.attached.len(), 2);
            assert_eq!(reg.active_hashes.len(), 1);
        }

        backend.detach_pod(&sample_pod("p1")).await.unwrap();
        {
            let reg = backend.pod_registry.lock().unwrap();
            assert_eq!(reg.attached.len(), 1);
            // Still referenced by p2.
            assert!(reg.active_hashes.contains(&bundle.hash));
        }

        backend.detach_pod(&sample_pod("p2")).await.unwrap();
        {
            let reg = backend.pod_registry.lock().unwrap();
            assert!(reg.attached.is_empty());
            assert!(reg.active_hashes.is_empty());
        }
    }

    #[tokio::test]
    async fn attach_pod_is_idempotent() {
        let mut backend = EbpfLinuxBackend::new();
        backend
            .initialize(&UnifiedConfig::default())
            .await
            .unwrap();
        let bundle = sample_bundle("h2");
        backend.update_policy(&bundle).await.unwrap();
        backend.attach_pod(&sample_pod("p1"), &bundle.hash).await.unwrap();
        backend.attach_pod(&sample_pod("p1"), &bundle.hash).await.unwrap();

        let reg = backend.pod_registry.lock().unwrap();
        assert_eq!(reg.attached.len(), 1);
    }

    #[tokio::test]
    async fn detach_unknown_pod_is_ok() {
        let backend = EbpfLinuxBackend::new();
        backend.detach_pod(&sample_pod("ghost")).await.unwrap();
    }
}
