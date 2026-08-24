fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    println!("cargo:rustc-env=BUILD_TIMESTAMP={}", build_timestamp());

    // Only compile protobuf when mesh feature is enabled (requires protoc)
    if std::env::var("CARGO_FEATURE_MESH").is_ok() {
        let proto_files = &["src/mesh/proto/mesh.proto", "proto/control.proto"];
        let out_dir = std::env::var("OUT_DIR")?;

        tonic_prost_build::configure()
            .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
            .out_dir(out_dir)
            .build_server(true)
            .compile_protos(proto_files, &["src/", "proto/"])?;

        println!("cargo:rerun-if-changed=src/mesh/proto/mesh.proto");
        println!("cargo:rerun-if-changed=proto/control.proto");
    }

    Ok(())
}

fn build_timestamp() -> String {
    let epoch = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .or_else(|| {
            std::process::Command::new("git")
                .args(["show", "-s", "--format=%ct", "HEAD"])
                .output()
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .and_then(|value| value.trim().parse::<i64>().ok())
        })
        .unwrap_or(0);

    chrono::DateTime::<chrono::Utc>::from_timestamp(epoch, 0)
        .map(|timestamp| timestamp.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "1970-01-01 00:00:00".to_string())
}
