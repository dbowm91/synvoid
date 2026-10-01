use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn rust_sources(path: &std::path::Path, output: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, output);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            output.push(path);
        }
    }
}

#[test]
fn reusable_honeypot_has_no_application_crate_dependencies() {
    let root = repo_root();
    let manifest = fs::read_to_string(root.join("crates/synvoid-honeypot/Cargo.toml")).unwrap();
    for forbidden in [
        "synvoid-config =",
        "synvoid-config-model =",
        "synvoid-core =",
        "synvoid-mesh =",
        "synvoid-http-client =",
        "synvoid-utils =",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "synvoid-honeypot must not depend on {forbidden}"
        );
    }
    let mut sources = Vec::new();
    rust_sources(&root.join("crates/synvoid-honeypot/src"), &mut sources);
    for path in sources {
        let text = fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains("synvoid_config_model")
                && !text.contains("synvoid_http_client")
                && !text.contains("synvoid_utils")
                && !text.contains("synvoid_mesh::")
                && !text.contains("synvoid_core::"),
            "application dependency path found in {}",
            path.display()
        );
    }
}
