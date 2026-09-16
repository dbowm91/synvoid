//! Path-construction coverage for `synvoid-platform` (Phase 32, Part D).
//!
//! - `PlatformPaths::new()` preserves the exact historical SynVoid layout.
//! - `PlatformPaths::for_app(..)` parameterizes the layout per application.
//! - Application identifiers reject separators and traversal.
//! - `with_base(..)` stays deterministic for tests.

use synvoid_platform::fs::{validate_app_id, PlatformPaths};
use synvoid_platform::PlatformError;

#[test]
fn test_new_matches_for_app_synvoid() {
    let historical = PlatformPaths::new();
    let explicit = PlatformPaths::for_app("synvoid").expect("synvoid is a valid app id");

    assert_eq!(historical.app_id(), "synvoid");
    assert_eq!(explicit.app_id(), "synvoid");
    assert_eq!(historical.data_dir(), explicit.data_dir());
    assert_eq!(historical.config_dir(), explicit.config_dir());
    assert_eq!(historical.log_dir(), explicit.log_dir());
    assert_eq!(historical.cache_dir(), explicit.cache_dir());
    assert_eq!(historical.runtime_dir(), explicit.runtime_dir());
    assert_eq!(historical.pid_file(), explicit.pid_file());
    assert_eq!(historical.socket_path(), explicit.socket_path());
    assert_eq!(
        historical.supervisor_socket_path(),
        explicit.supervisor_socket_path()
    );
    assert_eq!(
        historical.cpu_worker_socket_path(),
        explicit.cpu_worker_socket_path()
    );
    assert_eq!(
        historical.unified_worker_socket_path(3),
        explicit.unified_worker_socket_path(3)
    );
}

#[test]
fn test_new_preserves_historical_synvoid_names() {
    let paths = PlatformPaths::new();
    for path in [
        paths.pid_file(),
        paths.socket_path(),
        paths.supervisor_socket_path(),
        paths.cpu_worker_socket_path(),
        paths.unified_worker_socket_path(0),
    ] {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            name.starts_with("synvoid"),
            "SynVoid helper must keep synvoid prefix, got {name}"
        );
    }
    assert_eq!(
        paths.pid_file().file_name().unwrap(),
        "synvoid.pid",
        "operator-visible pid filename must not change"
    );
    assert_eq!(
        paths.supervisor_socket_path().file_name().unwrap(),
        "synvoid-supervisor.sock",
        "operator-visible supervisor socket name must not change"
    );
}

#[test]
fn test_for_app_parameterizes_layout() {
    let paths = PlatformPaths::for_app("my-app_2.0").expect("valid app id");
    assert_eq!(paths.app_id(), "my-app_2.0");

    let pid_name = paths
        .pid_file()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert_eq!(pid_name, "my-app_2.0.pid");
    let sup_name = paths
        .supervisor_socket_path()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert_eq!(sup_name, "my-app_2.0-supervisor.sock");
    let worker_name = paths
        .unified_worker_socket_path(7)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert_eq!(worker_name, "my-app_2.0-unified-7.sock");

    // Generic primitives keep working for arbitrary caller-supplied names.
    assert_eq!(
        paths.ipc_path("custom.sock").file_name().unwrap(),
        "custom.sock"
    );
    assert_eq!(
        paths.panic_log_path("worker").file_name().unwrap(),
        "worker-panic.log"
    );

    // The app id must appear in the runtime dir on every platform default.
    assert!(
        paths.runtime_dir().to_string_lossy().contains("my-app_2.0"),
        "runtime dir should embed the app id: {}",
        paths.runtime_dir().display()
    );
}

#[test]
fn test_for_app_rejects_traversal_and_separators() {
    for bad in [
        "",
        ".",
        "..",
        "../escape",
        "a/b",
        "a\\b",
        "a:b",
        "a b",
        "a/b/../c",
        "..\\win",
        "semi;colon",
        "quote\"x",
        "dollar$x",
        "back`tick",
        "nul\0byte",
        "ünïcodé",
    ] {
        let err = PlatformPaths::for_app(bad).unwrap_err();
        assert!(
            matches!(err, PlatformError::InvalidAppId(_)),
            "app id {bad:?} must be rejected with InvalidAppId, got {err:?}"
        );
        assert!(
            validate_app_id(bad).is_err(),
            "validate_app_id({bad:?}) must fail"
        );
    }
}

#[test]
fn test_for_app_rejects_overlong_id() {
    let long = "a".repeat(65);
    assert!(matches!(
        PlatformPaths::for_app(&long).unwrap_err(),
        PlatformError::InvalidAppId(_)
    ));
    let max = "a".repeat(64);
    assert!(PlatformPaths::for_app(&max).is_ok());
}

#[test]
fn test_for_app_accepts_sane_ids() {
    for good in ["a", "myapp", "my-app", "my_app", "app2.0", "A-._9"] {
        assert!(
            PlatformPaths::for_app(good).is_ok(),
            "app id {good:?} should be accepted"
        );
    }
}

#[test]
fn test_with_base_is_deterministic() {
    let base = std::env::temp_dir().join("synvoid-platform-path-test");
    let first = PlatformPaths::with_base(&base);
    let second = PlatformPaths::with_base(&base);
    assert_eq!(first.data_dir(), second.data_dir());
    assert_eq!(first.config_dir(), second.config_dir());
    assert_eq!(first.log_dir(), second.log_dir());
    assert_eq!(first.cache_dir(), second.cache_dir());
    assert_eq!(first.runtime_dir(), second.runtime_dir());
    assert_eq!(
        first.supervisor_socket_path(),
        second.supervisor_socket_path()
    );
    // with_base is the SynVoid-compatible test helper.
    assert_eq!(first.app_id(), "synvoid");
    assert_eq!(
        first.supervisor_socket_path().file_name().unwrap(),
        "synvoid-supervisor.sock"
    );
}

#[test]
fn test_invalid_app_id_display() {
    let err = PlatformError::InvalidAppId("bad/id".into());
    assert!(err.to_string().contains("bad/id"));
}
