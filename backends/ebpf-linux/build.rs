use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=ebpf/lsm.c");
    println!("cargo:rerun-if-changed=ebpf/network.c");

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest_path = PathBuf::from(&out_dir);

    #[cfg(target_os = "linux")]
    {
        compile_ebpf_programs(&dest_path);
    }

    #[cfg(not(target_os = "linux"))]
    {
        // On non-Linux platforms, create placeholder files
        // The actual eBPF programs can only be compiled on Linux
        println!("cargo:warning=Building on non-Linux platform - creating eBPF placeholders");
        println!("cargo:warning=To compile real eBPF programs, build on Linux with:");
        println!("cargo:warning=  apt install clang llvm libelf-dev linux-headers-$(uname -r)");

        std::fs::write(dest_path.join("lsm.o"), b"placeholder-non-linux")
            .expect("Failed to create lsm.o placeholder");
        std::fs::write(dest_path.join("network.o"), b"placeholder-non-linux")
            .expect("Failed to create network.o placeholder");
    }
}

#[cfg(target_os = "linux")]
fn compile_ebpf_programs(out_dir: &PathBuf) {
    use std::fs;

    // Check if clang is available
    let clang_check = Command::new("clang")
        .arg("--version")
        .output();

    if clang_check.is_err() {
        println!("cargo:warning=clang not found - creating eBPF placeholders");
        println!("cargo:warning=Install clang with: apt install clang llvm");
        create_placeholders(out_dir, "clang-not-found");
        return;
    }

    // Get kernel headers path
    let kernel_version = get_kernel_version();
    let headers_path = format!("/lib/modules/{}/build", kernel_version);

    if !std::path::Path::new(&headers_path).exists() {
        println!("cargo:warning=Kernel headers not found at {}", headers_path);
        println!("cargo:warning=Install with: apt install linux-headers-$(uname -r)");
        create_placeholders(out_dir, "no-kernel-headers");
        return;
    }

    // Compile LSM program
    let lsm_result = compile_ebpf_file(
        "ebpf/lsm.c",
        &out_dir.join("lsm.o"),
        &headers_path,
    );

    if lsm_result.is_err() {
        println!("cargo:warning=Failed to compile lsm.c: {:?}", lsm_result.err());
        fs::write(out_dir.join("lsm.o"), b"compile-failed")
            .expect("Failed to create lsm.o placeholder");
    }

    // Compile network program
    let network_result = compile_ebpf_file(
        "ebpf/network.c",
        &out_dir.join("network.o"),
        &headers_path,
    );

    if network_result.is_err() {
        println!("cargo:warning=Failed to compile network.c: {:?}", network_result.err());
        fs::write(out_dir.join("network.o"), b"compile-failed")
            .expect("Failed to create network.o placeholder");
    }
}

#[cfg(target_os = "linux")]
fn compile_ebpf_file(
    source: &str,
    output: &PathBuf,
    kernel_headers: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")?;
    let source_path = PathBuf::from(&manifest_dir).join(source);

    println!("cargo:rerun-if-changed={}", source_path.display());

    // eBPF compilation flags
    let status = Command::new("clang")
        .args(&[
            "-O2",
            "-g",
            "-target", "bpf",
            "-c",
            source_path.to_str().unwrap(),
            "-o", output.to_str().unwrap(),
            // Include paths
            "-I", kernel_headers,
            &format!("-I{}/include", kernel_headers),
            &format!("-I{}/arch/x86/include", kernel_headers),
            &format!("-I{}/arch/x86/include/generated", kernel_headers),
            &format!("-I{}/include/uapi", kernel_headers),
            &format!("-I{}/include/generated/uapi", kernel_headers),
            &format!("-I{}/arch/x86/include/uapi", kernel_headers),
            // BPF specific flags
            "-D__KERNEL__",
            "-D__BPF_TRACING__",
            "-Wno-unused-value",
            "-Wno-pointer-sign",
            "-Wno-compare-distinct-pointer-types",
            "-Wno-gnu-variable-sized-type-not-at-end",
            "-Wno-address-of-packed-member",
            "-Wno-tautological-compare",
            "-Wno-unknown-warning-option",
        ])
        .status()?;

    if !status.success() {
        return Err(format!("clang compilation failed with status: {}", status).into());
    }

    println!("cargo:warning=Successfully compiled {} to {}", source, output.display());
    Ok(())
}

#[cfg(target_os = "linux")]
fn get_kernel_version() -> String {
    let output = Command::new("uname")
        .arg("-r")
        .output()
        .expect("Failed to get kernel version");

    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[cfg(target_os = "linux")]
fn create_placeholders(out_dir: &PathBuf, reason: &str) {
    let placeholder = format!("placeholder-{}", reason);
    std::fs::write(out_dir.join("lsm.o"), placeholder.as_bytes())
        .expect("Failed to create lsm.o placeholder");
    std::fs::write(out_dir.join("network.o"), placeholder.as_bytes())
        .expect("Failed to create network.o placeholder");
}
