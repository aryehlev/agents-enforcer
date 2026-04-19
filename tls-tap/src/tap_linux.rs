//! Linux-only convenience wrapper. Loads `tls.o`, attaches uprobes
//! per recipe, drains the ringbuf, and produces [`TlsEvent`]s on a
//! tokio broadcast channel.
//!
//! Embedders who want finer control can skip [`Tap`] and use
//! `aya::Bpf` directly + the [`crate::uprobes`] framework — Tap is
//! just sugar for the common case.

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use aya::maps::{MapData, RingBuf};
use aya::{Bpf, BpfLoader};
use tokio::sync::broadcast;

use crate::event::{TlsEvent, MAX_PLAINTEXT};
use crate::uprobes::{discover_targets, plan_all, ProbeRecipe};

/// High-level handle to the loaded TLS uprobe program.
///
/// Lifecycle: [`Tap::load`] → [`Tap::attach_to_pid`] (one or more
/// times) → [`Tap::subscribe`] to start receiving events.
pub struct Tap {
    bpf: Arc<tokio::sync::Mutex<Bpf>>,
    events_tx: broadcast::Sender<TlsEvent>,
    recipes: Vec<Box<dyn ProbeRecipe>>,
}

impl Tap {
    /// Load `tls.o` from the standard search paths and start the
    /// ringbuf consumer task. The default recipe set covers
    /// OpenSSL + Node.js; replace via [`Tap::with_recipes`] for
    /// custom runtime support.
    pub async fn load() -> Result<Self> {
        let path = find_object()?;
        Self::load_from(&path).await
    }

    /// Load a specific path (mostly for tests / non-standard
    /// install layouts).
    pub async fn load_from(path: &Path) -> Result<Self> {
        let bpf = BpfLoader::new()
            .load_file(path)
            .with_context(|| format!("load {}", path.display()))?;

        // Channel sized so that even a slow consumer can lag a
        // few hundred events without losing anything; broadcast
        // drops the oldest when full.
        let (events_tx, _) = broadcast::channel::<TlsEvent>(2048);
        let bpf = Arc::new(tokio::sync::Mutex::new(bpf));
        Self::spawn_consumer(bpf.clone(), events_tx.clone()).await?;

        Ok(Self {
            bpf,
            events_tx,
            recipes: default_recipes(),
        })
    }

    /// Replace the recipe set. Useful when embedding tls-tap in a
    /// product that wants to add proprietary runtime detection
    /// (closed-source Java/Erlang/etc).
    pub fn with_recipes(mut self, recipes: Vec<Box<dyn ProbeRecipe>>) -> Self {
        self.recipes = recipes;
        self
    }

    /// Discover probe targets for `pid` and attach every recipe
    /// that matches. Returns the number of uprobes attached so
    /// callers can warn if zero (= no recognized TLS lib in the
    /// process).
    pub async fn attach_to_pid(&self, pid: u32) -> Result<usize> {
        let targets = discover_targets(&[pid]);
        if targets.is_empty() {
            return Err(anyhow!("pid {} not found / not readable", pid));
        }
        let plans = plan_all(&self.recipes, &targets);
        let mut bpf = self.bpf.lock().await;
        crate::uprobes::attach::attach_all(&mut bpf, &plans)
    }

    /// Subscribe to the event stream. Late subscribers miss prior
    /// events, which is the right behavior — there's no "replay
    /// the previous request" use case here.
    pub fn subscribe(&self) -> broadcast::Receiver<TlsEvent> {
        self.events_tx.subscribe()
    }

    async fn spawn_consumer(
        bpf: Arc<tokio::sync::Mutex<Bpf>>,
        tx: broadcast::Sender<TlsEvent>,
    ) -> Result<()> {
        // Take the ringbuf out of the loaded bpf object so the
        // consumer task owns it for the lifetime of the Tap. Aya
        // requires &mut Bpf for take_map; we hold the lock briefly.
        let map = {
            let mut bpf = bpf.lock().await;
            bpf.take_map("tls_events")
                .ok_or_else(|| anyhow!("tls_events ringbuf missing"))?
        };
        let rb: RingBuf<MapData> = map
            .try_into()
            .map_err(|e| anyhow!("tls_events → RingBuf: {}", e))?;

        tokio::spawn(consumer_loop(rb, tx));
        Ok(())
    }
}

async fn consumer_loop(mut rb: RingBuf<MapData>, tx: broadcast::Sender<TlsEvent>) {
    // Sized to absorb the largest possible event (header + max
    // plaintext) so we don't keep reallocating; per-event copies
    // happen inside TlsEvent::from_ringbuf.
    let _hint_capacity = std::mem::size_of::<crate::event::TlsEventHdr>() + MAX_PLAINTEXT;
    loop {
        let mut drained = 0usize;
        while let Some(item) = rb.next() {
            drained += 1;
            let bytes: &[u8] = &item;
            let Some(ev) = TlsEvent::from_ringbuf(bytes) else {
                continue;
            };
            // broadcast::send returns Err only when there are
            // zero receivers — that's fine, we just drop.
            let _ = tx.send(ev);
        }
        if drained == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}

fn default_recipes() -> Vec<Box<dyn ProbeRecipe>> {
    vec![
        Box::new(crate::uprobes::recipes::openssl::OpenSsl),
        Box::new(crate::uprobes::recipes::nodejs::NodeJs),
    ]
}

fn find_object() -> Result<std::path::PathBuf> {
    // The aya-ebpf build (see bpf/README.md) produces an ELF
    // staticlib named `tls-tap-bpf` at:
    //   bpf/target/bpfel-unknown-none/release/tls-tap-bpf
    // Search order mirrors what an operator would expect:
    //   1. TLS_TAP_BPF_OBJ env var (explicit override)
    //   2. Same dir as the binary (container image layout)
    //   3. bpf/target/bpfel-unknown-none/release/ (cargo dev)
    //   4. /usr/lib/tls-tap/ (package install)
    let from_env = std::env::var("TLS_TAP_BPF_OBJ").ok().map(Into::into);
    let exe_sibling = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("tls-tap-bpf")));
    let candidates = [
        from_env,
        exe_sibling,
        Some("bpf/target/bpfel-unknown-none/release/tls-tap-bpf".into()),
        Some("/usr/lib/tls-tap/tls-tap-bpf".into()),
    ];
    for c in candidates.into_iter().flatten() {
        if c.exists() {
            return Ok(c);
        }
    }
    Err(anyhow!(
        "BPF object not found; build with `cargo +nightly build --release \
         --target bpfel-unknown-none -Z build-std=core` from bpf/, \
         or set TLS_TAP_BPF_OBJ"
    ))
}
