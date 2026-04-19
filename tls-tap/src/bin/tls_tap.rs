//! Demo CLI: load tls.o, attach to a target pid, stream plaintext
//! events to stdout as JSON-Lines. Pipe through `jq` for ad-hoc
//! inspection or feed into `vector` for shipping.
//!
//! ```bash
//! sudo tls-tap --pid 12345 | jq 'select(.direction == "write")'
//! ```

#![cfg(feature = "cli")]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tls-tap is Linux-only (uprobes require BPF). Build on a Linux host.");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser;
    use serde_json::json;
    use tls_tap::Tap;

    #[derive(Parser, Debug)]
    #[command(
        name = "tls-tap",
        about = "Stream TLS plaintext from a target pid as JSON-Lines"
    )]
    struct Args {
        /// Target process id. Repeat for multiple processes.
        #[arg(long)]
        pid: Vec<u32>,

        /// Cap event payload size in the output (bytes).
        /// Truncates the JSON payload but the underlying capture
        /// still happens at full size — useful for tail-following.
        #[arg(long, default_value_t = 4096)]
        max_print_bytes: usize,

        /// Print payloads as plain UTF-8 instead of base64 when the
        /// bytes happen to be valid UTF-8. Off by default because
        /// it can break shells on binary data.
        #[arg(long)]
        utf8: bool,
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();
    let tap = Tap::load().await?;
    if args.pid.is_empty() {
        anyhow::bail!("at least one --pid is required");
    }
    let mut total = 0;
    for pid in &args.pid {
        match tap.attach_to_pid(*pid).await {
            Ok(n) => {
                tracing::info!(pid, attached = n, "attached");
                total += n;
            }
            Err(e) => tracing::warn!(pid, err = %e, "attach failed"),
        }
    }
    if total == 0 {
        anyhow::bail!("no uprobes attached — none of the target pids load a recognized TLS lib");
    }

    let mut events = tap.subscribe();
    tracing::info!("streaming events; ctrl-c to stop");
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    use std::io::Write;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("stopping");
                break;
            }
            ev = events.recv() => {
                let Ok(ev) = ev else { continue };
                let payload_repr = if args.utf8
                    && std::str::from_utf8(&ev.plaintext).is_ok()
                {
                    let s = std::str::from_utf8(&ev.plaintext).unwrap();
                    let s = if s.len() > args.max_print_bytes {
                        &s[..args.max_print_bytes]
                    } else {
                        s
                    };
                    json!(s)
                } else {
                    // Hex for binary so the line stays single-line
                    // and copy/pasteable. Operators wanting raw
                    // bytes pipe through `xxd -r -p`.
                    let bytes = if ev.plaintext.len() > args.max_print_bytes {
                        &ev.plaintext[..args.max_print_bytes]
                    } else {
                        &ev.plaintext[..]
                    };
                    let mut hex = String::with_capacity(bytes.len() * 2);
                    for b in bytes {
                        use std::fmt::Write;
                        let _ = write!(hex, "{:02x}", b);
                    }
                    json!(hex)
                };
                let line = json!({
                    "cgroup_id": ev.cgroup_id,
                    "conn_id": ev.conn_id,
                    "pid": ev.pid,
                    "tgid": ev.tgid,
                    "direction": ev.direction.as_str(),
                    "len": ev.plaintext.len(),
                    "truncated": ev.truncated,
                    "payload": payload_repr,
                });
                let _ = writeln!(stdout, "{}", line);
                let _ = stdout.flush();
            }
        }
    }
    Ok(())
}
