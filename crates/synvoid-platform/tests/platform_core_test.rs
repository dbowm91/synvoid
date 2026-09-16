//! Core platform coverage for the canonical `synvoid-platform` crate
//! (Phase 32, Part G): detection, process liveness/termination, socket
//! creation, secure permissions, and sandbox fail-closed behavior.

use synvoid_platform::fs::{set_dir_permissions, set_file_permissions, SecureDir};
use synvoid_platform::{
    is_admin_required_for_tun, is_daemonize_supported, is_reuse_port_supported,
    is_sandbox_supported, is_signals_supported, is_socket_fd_passing_supported, is_tun_supported,
    is_wireguard_kernel_supported, is_wireguard_userspace_supported, platform, Platform,
};

#[test]
fn test_platform_current_matches_compile_time_target() {
    let current = Platform::current();
    assert_eq!(current, platform());
    assert_eq!(Platform::current(), platform());

    #[cfg(all(target_os = "linux", not(target_env = "musl")))]
    assert_eq!(current, Platform::Linux);
    #[cfg(all(target_os = "linux", target_env = "musl"))]
    assert_eq!(current, Platform::LinuxMusl);
    #[cfg(target_os = "macos")]
    assert_eq!(current, Platform::Macos);
    #[cfg(target_os = "freebsd")]
    assert_eq!(current, Platform::FreeBSD);
    #[cfg(target_os = "openbsd")]
    assert_eq!(current, Platform::OpenBSD);
    #[cfg(target_os = "netbsd")]
    assert_eq!(current, Platform::NetBSD);
    #[cfg(target_os = "windows")]
    assert_eq!(current, Platform::Windows);
}

#[test]
fn test_platform_capability_consistency() {
    let current = Platform::current();
    assert_eq!(current.is_unix(), is_socket_fd_passing_supported());
    assert_eq!(current.is_unix(), is_signals_supported());
    assert_eq!(current.is_unix(), is_daemonize_supported());
    assert_eq!(current.supports_reuse_port(), is_reuse_port_supported());
    assert_eq!(current.supports_tun(), is_tun_supported());
    assert_eq!(
        current.supports_wireguard_userspace(),
        is_wireguard_userspace_supported()
    );
    assert_eq!(
        current.supports_wireguard_kernel(),
        is_wireguard_kernel_supported()
    );
    assert_eq!(
        current.is_admin_required_for_tun(),
        is_admin_required_for_tun()
    );
    assert_eq!(current.supports_sandbox(), is_sandbox_supported());

    #[cfg(unix)]
    {
        assert!(current.is_unix());
        assert!(is_socket_fd_passing_supported());
        assert!(is_signals_supported());
        // Unix TUN works via capabilities, no admin user required.
        assert!(!is_admin_required_for_tun());
    }

    // Variant predicates are mutually coherent.
    assert_eq!(
        current.is_linux(),
        matches!(current, Platform::Linux | Platform::LinuxMusl)
    );
    assert_eq!(
        current.is_bsd(),
        matches!(
            current,
            Platform::FreeBSD | Platform::OpenBSD | Platform::NetBSD
        )
    );
    assert!(!current.libc_name().is_empty());
}

#[test]
fn test_convenience_fns_match_platform_methods() {
    // Spot-check the free-function surface against the enum methods.
    assert_eq!(
        synvoid_platform::is_sandbox_supported(),
        Platform::current().supports_sandbox()
    );
    assert_eq!(
        synvoid_platform::is_reuse_port_supported(),
        Platform::current().supports_reuse_port()
    );
}

#[test]
fn test_process_liveness_self() {
    let own_pid = std::process::id();
    assert!(
        synvoid_platform::process::is_process_running(own_pid),
        "current process must be reported running"
    );
}

#[test]
fn test_process_liveness_absent_pid() {
    // PIDs above 2^22 are reserved on Linux and beyond the macOS/Windows
    // ranges; no live process can hold this value on supported hosts.
    assert!(!synvoid_platform::process::is_process_running(4_194_303));
}

#[cfg(unix)]
#[test]
fn test_terminate_process_graceful_and_forced() {
    use std::process::Command;

    // Graceful path: SIGTERM a sleeping child, expect prompt exit.
    let mut child = Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("sleep binary must exist on unix test hosts");
    synvoid_platform::process::terminate_process(&mut child, true, 10)
        .expect("graceful termination should succeed");
    assert!(
        child.try_wait().expect("wait status").is_some(),
        "child must have exited after graceful termination"
    );

    // Forced path: kill immediately without waiting for a signal round-trip.
    let mut child = Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("sleep binary must exist on unix test hosts");
    synvoid_platform::process::terminate_process(&mut child, false, 0)
        .expect("forced termination should succeed");
    assert!(
        child.try_wait().expect("wait status").is_some(),
        "child must have exited after forced termination"
    );
}

#[test]
fn test_create_listening_sockets() {
    use synvoid_platform::socket::{create_listening_socket, create_listening_socket_v6};

    let info = create_listening_socket(0, true).expect("ipv4 listen socket");
    assert_eq!(info.socket_type, synvoid_platform::socket::SocketType::Tcp);

    let info_v6 = create_listening_socket_v6(0, true);
    // IPv6 may be unavailable in sandboxed CI; only assert success shape.
    if let Ok(info_v6) = info_v6 {
        assert_eq!(
            info_v6.socket_type,
            synvoid_platform::socket::SocketType::Tcp
        );
    }
}

#[test]
fn test_secure_dir_permissions_unix() {
    let temp = tempfile::TempDir::new().unwrap();
    let dir = temp.path().join("secure");
    let secure = SecureDir::new(&dir);
    secure.create().unwrap();
    assert!(secure.exists());
    assert_eq!(secure.path(), dir.as_path());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "secure dirs must be owner-only");
    }

    let file_path = dir.join("secret");
    std::fs::write(&file_path, b"data").unwrap();
    set_file_permissions(&file_path, false).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    set_file_permissions(&file_path, true).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o400);
    }

    set_dir_permissions(&dir, true).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
    set_dir_permissions(&dir, false).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }
}

#[test]
fn test_sandbox_off_always_succeeds_and_reports() {
    use synvoid_platform::sandbox::{ProcessSandbox, SandboxLevel, SandboxPaths};

    let sandbox = ProcessSandbox::with_paths(SandboxLevel::Off, SandboxPaths::new())
        .expect("sandbox Off must always succeed");
    assert_eq!(sandbox.level(), SandboxLevel::Off);
    assert_eq!(SandboxLevel::Off.as_str(), "off");
    assert_eq!(SandboxLevel::Basic.as_str(), "basic");
    assert_eq!(SandboxLevel::Strict.as_str(), "strict");
}

#[test]
fn test_sandbox_stub_is_fail_closed_for_strict() {
    use synvoid_platform::sandbox::{ProcessSandbox, SandboxLevel, SandboxPaths};

    // The stub backend (used on platforms without OS enforcement, and via
    // with_stub in tests) must not claim strict enforcement.
    let stub = ProcessSandbox::with_stub(SandboxLevel::Strict);
    assert!(!stub.capabilities().can_enforce_strict());

    // with_paths(Strict) on a stub must fail closed rather than silently
    // running unenforced.
    let result = ProcessSandbox::with_paths(SandboxLevel::Strict, SandboxPaths::new());
    if !ProcessSandbox::new(SandboxLevel::Strict)
        .capabilities()
        .can_enforce_strict()
    {
        assert!(
            result.is_err(),
            "strict sandbox without an enforcing backend must fail"
        );
    }
}

#[test]
fn test_sandbox_paths_builder() {
    use synvoid_platform::sandbox::SandboxPaths;

    let paths = SandboxPaths::new()
        .add_read_path("/usr/share")
        .add_write_path("/tmp/work")
        .add_no_access_path("/etc/secrets");
    assert_eq!(paths.read_paths().len(), 1);
    assert_eq!(paths.write_paths().len(), 1);
    assert_eq!(paths.no_access_paths().len(), 1);
}
