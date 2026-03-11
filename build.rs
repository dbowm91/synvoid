fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_files = &["src/mesh/proto/mesh.proto"];
    let out_dir = std::env::var("OUT_DIR")?;

    tonic_build::configure()
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .out_dir(&out_dir)
        .build_server(true)
        .compile_protos(proto_files, &["src/"])?;

    println!("cargo:rerun-if-changed=src/mesh/proto/mesh.proto");

    let build_timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    println!("cargo:rustc-env=BUILD_TIMESTAMP={}", build_timestamp);

    Ok(())
}
