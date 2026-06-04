/// Creates a temporary directory for test configuration.
pub fn temp_config_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("failed to create temp dir")
}

/// Returns a minimal TOML config string for testing.
pub fn minimal_config() -> String {
    r#"
[server]
listen = "127.0.0.1:8080"

[sites]
"#
    .to_string()
}
