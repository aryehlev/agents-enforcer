// Compile the .proto into Rust at build time. Generated code lands
// in OUT_DIR and is pulled into the crate via `include!` from
// `src/proto.rs`. We intentionally don't check in the generated code
// so a stale proto never drifts from the generated bindings.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(&["proto/node_agent.proto"], &["proto"])?;
    Ok(())
}
