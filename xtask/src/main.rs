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
    /// Generate CRD YAML manifests into deploy/crds/
    GenCrds(GenCrdsOptions),
    /// Compile a policy YAML + catalogs into a PolicyBundle without
    /// pushing to a cluster. Use to check what a policy will actually
    /// enforce before applying it.
    Simulate(SimulateOptions),
}

#[derive(Debug, Parser)]
struct GenCrdsOptions {
    /// Output directory (defaults to <repo>/deploy/crds)
    #[clap(long)]
    out_dir: Option<PathBuf>,
}

#[derive(Debug, Parser)]
struct SimulateOptions {
    /// Path to an `AgentPolicy` YAML. Must be a single document, not
    /// a multi-doc stream — use a `GatewayCatalog` file for catalogs.
    #[clap(long)]
    policy: PathBuf,
    /// Optional paths to `GatewayCatalog` YAMLs referenced by the
    /// policy. Any number; later files override earlier ones on
    /// duplicate gateway names.
    #[clap(long = "catalog")]
    catalogs: Vec<PathBuf>,
    /// Output format: `yaml` (default) or `json`.
    #[clap(long, default_value = "yaml")]
    format: String,
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
        Subcommand::GenCrds(opts) => gen_crds(opts),
        Subcommand::Simulate(opts) => simulate(opts),
    }
}

/// Read a policy + its catalogs off disk and print the compiled
/// bundle. Pure: no kube client, no DNS resolution, no side effects.
/// Catalog files with hostnames instead of IP literals will fail
/// compilation with a clear message — the simulator is the recommended
/// way to validate a policy before `kubectl apply`.
fn simulate(opts: SimulateOptions) -> Result<()> {
    use agent_gateway_enforcer_controller::{
        compile_policy, AgentPolicy, AgentPolicySpec, GatewayCatalog, GatewayCatalogSpec,
    };
    use std::collections::BTreeMap;

    let policy_yaml = std::fs::read_to_string(&opts.policy)
        .with_context(|| format!("read {}", opts.policy.display()))?;
    let policy: AgentPolicy = serde_yaml::from_str(&policy_yaml)
        .with_context(|| format!("parse AgentPolicy from {}", opts.policy.display()))?;
    let spec: AgentPolicySpec = policy.spec;

    let mut catalogs: BTreeMap<String, GatewayCatalogSpec> = BTreeMap::new();
    for path in &opts.catalogs {
        let yaml = std::fs::read_to_string(path)
            .with_context(|| format!("read {}", path.display()))?;
        let cat: GatewayCatalog = serde_yaml::from_str(&yaml)
            .with_context(|| format!("parse GatewayCatalog from {}", path.display()))?;
        // Name collisions overwrite: matches the controller's fetch
        // behavior (later listings beat earlier ones).
        let name = cat
            .metadata
            .name
            .clone()
            .unwrap_or_else(|| "unnamed".into());
        catalogs.insert(name, cat.spec);
    }

    let bundle = compile_policy(&spec, &catalogs)
        .map_err(|e| anyhow::anyhow!("compile failed: {}", e))?;

    match opts.format.as_str() {
        "yaml" => println!("{}", serde_yaml::to_string(&bundle)?),
        "json" => println!("{}", serde_json::to_string_pretty(&bundle)?),
        other => bail!("unknown --format {} (expected yaml|json)", other),
    }
    Ok(())
}

/// Write one YAML file per CRD into `deploy/crds/`. Paired with the
/// in-tree tests (see `agent-gateway-enforcer-controller` tests) that
/// verify the CRD definitions round-trip; this task just materializes
/// them to disk so `kubectl apply -f deploy/crds/` works without the
/// controller running.
fn gen_crds(opts: GenCrdsOptions) -> Result<()> {
    use agent_gateway_enforcer_controller::{
        AgentPolicy, AgentViolation, EnforcerConfig, GatewayCatalog,
    };
    use kube::CustomResourceExt;

    let out_dir = opts
        .out_dir
        .unwrap_or_else(|| project_root().join("deploy").join("crds"));
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("create {}", out_dir.display()))?;

    let crds: [(&str, serde_yaml::Value); 4] = [
        ("agentpolicies.agents.enforcer.io.yaml", serde_yaml::to_value(AgentPolicy::crd())?),
        ("gatewaycatalogs.agents.enforcer.io.yaml", serde_yaml::to_value(GatewayCatalog::crd())?),
        ("enforcerconfigs.agents.enforcer.io.yaml", serde_yaml::to_value(EnforcerConfig::crd())?),
        ("agentviolations.agents.enforcer.io.yaml", serde_yaml::to_value(AgentViolation::crd())?),
    ];

    for (name, value) in crds {
        let path = out_dir.join(name);
        let yaml = serde_yaml::to_string(&value)?;
        std::fs::write(&path, yaml).with_context(|| format!("write {}", path.display()))?;
        println!("wrote {}", path.display());
    }
    Ok(())
}

fn build_ebpf(opts: BuildEbpfOptions) -> Result<()> {
    let dir = project_root().join("agent-gateway-enforcer-ebpf");

    // Build for BPF target
    let target = "bpfel-unknown-none";

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&dir).env_remove("RUSTUP_TOOLCHAIN").args([
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

    let status = cmd.status().context("Failed to run cargo build for eBPF")?;

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
