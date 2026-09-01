fn main() -> Result<(), Box<dyn std::error::Error>> {
    // NOTE: proto compilation here is intentional duplication with root build.rs.
    // The root crate generates mesh proto into its OUT_DIR (gated on CARGO_FEATURE_MESH),
    // while this crate generates into its own OUT_DIR unconditionally because
    // synvoid-mesh always requires the proto. Workspace builds with --features mesh
    // therefore compile the same proto twice into distinct OUT_DIRs; this is expected
    // and harmless. A shared generated file would require a separate -sys crate.
    let proto_files = &["src/mesh/proto/mesh.proto"];
    let out_dir = std::env::var("OUT_DIR")?;

    tonic_prost_build::configure()
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .out_dir(out_dir)
        .build_server(true)
        .compile_protos(proto_files, &["src/"])?;

    println!("cargo:rerun-if-changed=src/mesh/proto/mesh.proto");

    Ok(())
}
