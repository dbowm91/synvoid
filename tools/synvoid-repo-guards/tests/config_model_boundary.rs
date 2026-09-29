use std::fs;
use synvoid_repo_guards::{workspace_root, Violations};

#[test]
fn config_model_has_no_runtime_authority() {
    let root = workspace_root();
    let source = root.join("crates/synvoid-config-model/src");
    let forbidden = [
        "std::fs",
        "std::path::",
        "OpenOptions",
        "create_dir",
        "write_all(",
        "rand::",
        "OsRng",
        "thread_rng",
        "SystemTime",
        "tokio::",
        "spawn_blocking",
    ];
    let mut violations = Violations::new();
    for entry in fs::read_dir(&source).expect("read config model source") {
        let path = entry.expect("read source entry").path();
        if path.extension().is_some_and(|extension| extension == "rs") {
            let text = fs::read_to_string(&path).expect("read Rust source");
            for token in forbidden {
                if text.contains(token) {
                    violations.push(format!(
                        "{} contains forbidden runtime API token {token:?}",
                        path.display()
                    ));
                }
            }
        }
    }
    violations.assert_ok("config_model_has_no_runtime_authority");
}
