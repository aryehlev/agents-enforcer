use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Subcommand,
}

#[derive(Debug, Parser)]
enum Subcommand {
    /// Build the eBPF program
    BuildEbpf(BuildEbpfOptions),
    /// Build the userspace program
    Build(BuildOptions),
    /// Build both eBPF and userspace programs
    BuildAll(BuildOptions),
    /// Run the userspace program
    Run(RunOptions),
}

#[derive(Debug, Parser)]
struct BuildEbpfOptions {
    /// Build in release mode
    #[clap(long)]
    release: bool,
}

#[derive(Debug, Parser)]
struct BuildOptions {
    /// Build in release mode
    #[clap(long)]
    release: bool,
}

#[derive(Debug, Parser)]
struct RunOptions {
    /// Build in release mode
    #[clap(long)]
    release: bool,
    /// Arguments to pass to the program
    #[clap(last = true)]
    args: Vec<String>,
}

fn main() -> Result<()> {
    let opts = Options::parse();

    match opts.command {
        Subcommand::BuildEbpf(opts) => build_ebpf(opts),
        Subcommand::Build(opts) => build_userspace(opts),
        Subcommand::BuildAll(opts) => {
            build_ebpf(BuildEbpfOptions {
                release: opts.release,
            })?;
            build_userspace(opts)
        }
        Subcommand::Run(opts) => run(opts),
    }
}

fn build_ebpf(opts: BuildEbpfOptions) -> Result<()> {
    let dir = project_root().join("agent-gateway-enforcer-ebpf");

    // Build for BPF target
    let target = "bpfel-unknown-none";

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .args([
            "+nightly",
            "build",
            "--target",
            target,
            "-Z",
            "build-std=core",
        ]);

    if opts.release {
        cmd.arg("--release");
    }

    let status = cmd
        .status()
        .context("Failed to run cargo build for eBPF")?;

    if !status.success() {
        bail!("Failed to build eBPF program");
    }

    // Copy the built eBPF object to a known location
    let profile = if opts.release { "release" } else { "dev" };
    let src = project_root()
        .join("target")
        .join(target)
        .join(profile)
        .join("agent-gateway-enforcer-ebpf");

    let dest_dir = project_root().join("target").join("bpf");
    std::fs::create_dir_all(&dest_dir)?;

    let dest = dest_dir.join("agent-gateway-enforcer.bpf.o");

    // The eBPF binary doesn't have an extension, but we need to copy it
    if src.exists() {
        std::fs::copy(&src, &dest)
            .with_context(|| format!("Failed to copy {} to {}", src.display(), dest.display()))?;
        println!("eBPF program built: {}", dest.display());
    } else {
        println!("Warning: eBPF binary not found at {}", src.display());
        println!("Looking for alternative locations...");

        // Try to find the binary
        let alt_src = project_root()
            .join("agent-gateway-enforcer-ebpf")
            .join("target")
            .join(target)
            .join(profile)
            .join("agent-gateway-enforcer-ebpf");

        if alt_src.exists() {
            std::fs::copy(&alt_src, &dest)?;
            println!("eBPF program built: {}", dest.display());
        }
    }

    Ok(())
}

fn build_userspace(opts: BuildOptions) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(project_root())
        .args(["build", "--package", "agent-gateway-enforcer"]);

    if opts.release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("Failed to run cargo build")?;

    if !status.success() {
        bail!("Failed to build userspace program");
    }

    Ok(())
}

fn run(opts: RunOptions) -> Result<()> {
    // First build everything
    build_ebpf(BuildEbpfOptions {
        release: opts.release,
    })?;
    build_userspace(BuildOptions {
        release: opts.release,
    })?;

    // Then run
    let profile = if opts.release { "release" } else { "debug" };
    let bin = project_root()
        .join("target")
        .join(profile)
        .join("agent-gateway-enforcer");

    let mut cmd = Command::new("sudo");
    cmd.arg(bin);
    cmd.args(&opts.args);

    let status = cmd.status().context("Failed to run program")?;

    if !status.success() {
        bail!("Program exited with error");
    }

    Ok(())
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}
