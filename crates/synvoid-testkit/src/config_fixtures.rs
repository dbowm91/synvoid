/// Creates a temporary directory suitable for test configuration files.
///
/// The directory is automatically removed when the returned [`TempDir`] is
/// dropped. Useful for tests that need a writable path for config I/O
/// without polluting the host filesystem.
///
/// [`TempDir`]: tempfile::TempDir
pub fn temp_config_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("failed to create temp dir")
}

/// Returns a minimal valid TOML configuration string for testing.
///
/// The config specifies only `listen = "127.0.0.1:8080"` and an empty
/// `[sites]` table — enough to satisfy basic config-parsing tests without
/// requiring a full production configuration.
pub fn minimal_config() -> String {
    r#"
[server]
listen = "127.0.0.1:8080"

[sites]
"#
    .to_string()
}
