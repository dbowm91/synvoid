use std::path::PathBuf;

/// Recursively find all .rs files under the given directories.
fn rust_files_under(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(dir).expect("read_dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                files.extend(rust_files_under(&[path]));
            } else if path.extension().map_or(false, |e| e == "rs") {
                files.push(path);
            }
        }
    }
    files
}

#[test]
fn server_runtime_does_not_leak_lifecycle_handles() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let roots = [repo.join("src/server"), repo.join("src/plugin")];
    let mut offenders = Vec::new();

    for file in rust_files_under(&roots) {
        let text = std::fs::read_to_string(&file).unwrap();
        for (idx, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("#[") {
                continue;
            }
            if trimmed.contains("std::mem::forget") || trimmed.contains("mem::forget") {
                offenders.push(format!("{}:{}: {}", file.display(), idx + 1, trimmed));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "server/plugin lifecycle handles must be owned, not leaked:\n{}",
        offenders.join("\n")
    );
}
