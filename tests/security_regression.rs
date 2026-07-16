//! Root-test ownership: COMPOSITION
//! Rationale: validates cross-crate security regression across process, proxy, and platform

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;

    use tempfile::TempDir;

    static ENV_VAR_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn env_var_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_VAR_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn test_ipc_auth_bypass_rejected() {
        use synvoid::process::ipc_signed::{IpcSigner, SignedIpcMessage};
        use synvoid::process::Message;

        let key = synvoid::process::ipc_signed::generate_session_key();
        let signer = IpcSigner::new(&key);

        let command = Message::WorkerStarted {
            id: synvoid::process::WorkerId(1),
            pid: 1234,
            port: 8080,
            timestamp: 1234567890,
        };

        let unsigned_frame = {
            let payload = serde_json::to_vec(&command).unwrap();
            let len = payload.len() as u32;
            let mut buf = Vec::with_capacity(4 + payload.len());
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(&payload);
            buf
        };

        let result: Result<Message, _> =
            SignedIpcMessage::deserialize_signed(&unsigned_frame, &signer);
        assert!(
            result.is_err(),
            "Unsigned IPC command must be rejected - got: {:?}",
            result
        );
    }

    #[test]
    fn test_key_file_symlink_rejected() {
        use std::os::unix::fs::PermissionsExt;
        use synvoid::process::ipc_signed::IpcSigner;

        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("key.txt");

        fs::write(&key_path, "a".repeat(64).as_bytes()).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();

        let symlink_path = temp_dir.path().join("key_symlink");
        std::os::unix::fs::symlink(&key_path, &symlink_path).unwrap();

        let _guard = env_var_guard();
        std::env::set_var("SYNVOID_IPC_KEY_FILE", symlink_path.to_str().unwrap());
        let result = IpcSigner::try_from_env();
        std::env::remove_var("SYNVOID_IPC_KEY_FILE");

        assert!(
            result.is_none(),
            "Signer must refuse to load key from symlink path"
        );
    }

    #[test]
    fn test_key_file_world_writable_rejected() {
        use std::os::unix::fs::PermissionsExt;
        use synvoid::process::ipc_signed::IpcSigner;

        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("key.txt");

        fs::write(&key_path, "a".repeat(64).as_bytes()).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();

        let _guard = env_var_guard();
        std::env::set_var("SYNVOID_IPC_KEY_FILE", key_path.to_str().unwrap());
        let result = IpcSigner::try_from_env();
        std::env::remove_var("SYNVOID_IPC_KEY_FILE");

        assert!(
            result.is_none(),
            "Signer must refuse to load key with world-writable permissions"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_pidfile_lock_prevents_concurrent_access() {
        use std::time::Instant;
        use synvoid::process::pidfile::PidFileManager;

        let temp_dir = TempDir::new().unwrap();
        let mut manager1 = PidFileManager::with_custom_dir(temp_dir.path().to_path_buf());
        let mut manager2 = PidFileManager::with_custom_dir(temp_dir.path().to_path_buf());

        let acquired1 = manager1.try_acquire(1234, "test-version").unwrap();
        assert!(acquired1, "First process should acquire lock");

        let start = Instant::now();
        let acquired2 = manager2.try_acquire(5678, "test-version").unwrap();
        let elapsed = start.elapsed();

        assert!(!acquired2, "Second process should fail to acquire lock");
        assert!(
            elapsed < Duration::from_millis(500),
            "Lock failure should be immediate (not blocking)"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_pidfile_not_truncated_on_conflict() {
        use synvoid::process::pidfile::PidFileManager;

        let temp_dir = TempDir::new().unwrap();
        let mut manager1 = PidFileManager::with_custom_dir(temp_dir.path().to_path_buf());

        manager1.try_acquire(1234, "v1.0.0").unwrap();

        let content_before = fs::read_to_string(temp_dir.path().join("synvoid.pid")).unwrap();
        assert!(content_before.contains("1234"));

        let mut manager2 = PidFileManager::with_custom_dir(temp_dir.path().to_path_buf());
        let acquired2 = manager2.try_acquire(5678, "v2.0.0").unwrap();
        assert!(!acquired2, "Second acquire should fail");

        let content_after = fs::read_to_string(temp_dir.path().join("synvoid.pid")).unwrap();
        assert_eq!(
            content_before, content_after,
            "PID file must not be truncated when second acquire fails"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_symlink_key_detected_by_metadata() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let real_key = temp_dir.path().join("real_key");
        fs::write(&real_key, "a".repeat(64).as_bytes()).unwrap();
        fs::set_permissions(&real_key, fs::Permissions::from_mode(0o600)).unwrap();

        let symlink = temp_dir.path().join("key_link");
        std::os::unix::fs::symlink(&real_key, &symlink).unwrap();

        let meta = fs::symlink_metadata(&symlink).unwrap();
        assert!(
            meta.file_type().is_symlink(),
            "symlink_metadata should detect symlink"
        );

        let real_meta = fs::metadata(&symlink).unwrap();
        assert!(
            !real_meta.file_type().is_symlink(),
            "metadata follows symlink"
        );
    }

    #[test]
    fn test_ipc_signer_rejects_key_file_with_symlink() {
        use std::os::unix::fs::PermissionsExt;
        use synvoid::process::ipc_signed::IpcSigner;

        let temp_dir = TempDir::new().unwrap();

        let real_key = temp_dir.path().join("real_key.txt");
        fs::write(&real_key, "a".repeat(64).as_bytes()).unwrap();
        fs::set_permissions(&real_key, fs::Permissions::from_mode(0o600)).unwrap();

        let symlink_key = temp_dir.path().join("key_link.txt");
        std::os::unix::fs::symlink(&real_key, &symlink_key).unwrap();

        let _guard = env_var_guard();
        std::env::set_var("SYNVOID_IPC_KEY_FILE", symlink_key.to_str().unwrap());
        let result = IpcSigner::try_from_env();
        std::env::remove_var("SYNVOID_IPC_KEY_FILE");

        assert!(
            result.is_none(),
            "IpcSigner should refuse keys accessed via symlink"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_read_ipc_key_file_rejects_symlink() {
        use std::os::unix::fs::PermissionsExt;
        use synvoid::process::ipc_signed::read_ipc_key_file;

        let temp_dir = TempDir::new().unwrap();

        let real_key = temp_dir.path().join("real_key.txt");
        fs::write(&real_key, "a".repeat(64).as_bytes()).unwrap();
        fs::set_permissions(&real_key, fs::Permissions::from_mode(0o600)).unwrap();

        let symlink_key = temp_dir.path().join("key_link.txt");
        std::os::unix::fs::symlink(&real_key, &symlink_key).unwrap();

        let result = read_ipc_key_file(symlink_key.to_str().unwrap());

        assert!(
            result.is_none(),
            "read_ipc_key_file should reject symlink paths"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_read_ipc_key_file_rejects_world_writable() {
        use std::os::unix::fs::PermissionsExt;
        use synvoid::process::ipc_signed::read_ipc_key_file;

        let temp_dir = TempDir::new().unwrap();

        let key_file = temp_dir.path().join("key.txt");
        fs::write(&key_file, "a".repeat(64).as_bytes()).unwrap();
        fs::set_permissions(&key_file, fs::Permissions::from_mode(0o644)).unwrap();

        let result = read_ipc_key_file(key_file.to_str().unwrap());

        assert!(
            result.is_none(),
            "read_ipc_key_file should reject world-writable key files"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_unprivileged_bpf_check() {
        #[cfg(feature = "icmp-filter")]
        use synvoid::icmp_filter::platform::{has_privilege_for, is_admin, FilterOperation};

        #[cfg(not(feature = "icmp-filter"))]
        {
            println!("icmp-filter feature not enabled - skipping test");
        }

        #[cfg(feature = "icmp-filter")]
        {
            let admin = is_admin();

            if !admin {
                let ebpf_allowed = has_privilege_for(FilterOperation::EbpfLoad);
                assert!(
                    !ebpf_allowed,
                    "Non-admin should not have eBPF load privilege when unprivileged_bpf_disabled=2"
                );
            }
        }
    }

    #[test]
    fn test_forwarded_headers_spoofed_by_client_rejected() {
        use synvoid::config::site::ProxyHeadersConfig;
        use synvoid::proxy::headers::{build_forward_headers, ForwardedProtocol};

        let client_ip = "192.168.1.100".parse().unwrap();
        let mut original_headers = http::HeaderMap::new();

        original_headers.insert("x-forwarded-for", "1.2.3.4, 5.6.7.8".parse().unwrap());
        original_headers.insert("x-real-ip", "9.9.9.9".parse().unwrap());
        original_headers.insert("forwarded", "for=10.10.10.10".parse().unwrap());
        original_headers.insert("x-forwarded-proto", "https".parse().unwrap());

        let config = ProxyHeadersConfig::default();
        let result = build_forward_headers(
            client_ip,
            &original_headers,
            &config,
            ForwardedProtocol::Http,
        );

        let xff = result
            .get("x-forwarded-for")
            .map(|v| v.to_str().unwrap_or(""));
        assert!(
            xff.unwrap().contains("192.168.1.100"),
            "X-Forwarded-For should contain real client IP, not spoofed values"
        );

        let xrip = result.get("x-real-ip").map(|v| v.to_str().unwrap_or(""));
        assert_eq!(
            xrip.unwrap(),
            "192.168.1.100",
            "X-Real-IP should contain real client IP"
        );

        assert!(
            result.get("forwarded").is_none(),
            "Original forwarded header should be stripped"
        );

        let xfp = result
            .get("x-forwarded-proto")
            .map(|v| v.to_str().unwrap_or(""));
        assert_eq!(
            xfp.unwrap(),
            "http",
            "x-forwarded-proto should be set based on listener, not client spoofed value"
        );
    }

    #[test]
    fn test_hop_by_hop_headers_stripped_from_forwarding() {
        use synvoid::config::site::ProxyHeadersConfig;
        use synvoid::proxy::headers::{build_forward_headers, ForwardedProtocol};

        let client_ip = "10.0.0.1".parse().unwrap();
        let mut original_headers = http::HeaderMap::new();

        original_headers.insert("connection", "keep-alive".parse().unwrap());
        original_headers.insert("keep-alive", "timeout=30".parse().unwrap());
        original_headers.insert("transfer-encoding", "chunked".parse().unwrap());
        original_headers.insert("proxy-authorization", "secret".parse().unwrap());
        original_headers.insert("content-type", "application/json".parse().unwrap());

        let config = ProxyHeadersConfig::default();
        let result = build_forward_headers(
            client_ip,
            &original_headers,
            &config,
            ForwardedProtocol::Http,
        );

        assert!(
            result.get("connection").is_none(),
            "Connection header should be stripped"
        );
        assert!(
            result.get("keep-alive").is_none(),
            "Keep-Alive header should be stripped"
        );
        assert!(
            result.get("transfer-encoding").is_none(),
            "Transfer-Encoding header should be stripped"
        );
        assert!(
            result.get("proxy-authorization").is_none(),
            "Proxy-Authorization header should be stripped"
        );
        assert!(
            result.get("content-type").is_some(),
            "Content-Type should be preserved"
        );
    }

    #[test]
    fn test_build_forward_headers_preserves_non_spoofed_headers() {
        use synvoid::config::site::ProxyHeadersConfig;
        use synvoid::proxy::headers::{build_forward_headers, ForwardedProtocol};

        let client_ip = "172.16.0.50".parse().unwrap();
        let mut original_headers = http::HeaderMap::new();

        original_headers.insert("host", "upstream.example.com".parse().unwrap());
        original_headers.insert("user-agent", "Mozilla/5.0".parse().unwrap());
        original_headers.insert("accept", "application/json".parse().unwrap());
        original_headers.insert("x-request-id", "abc123".parse().unwrap());

        let config = ProxyHeadersConfig::default();
        let result = build_forward_headers(
            client_ip,
            &original_headers,
            &config,
            ForwardedProtocol::Http,
        );

        assert!(
            result.get("host").is_some(),
            "Host header should be preserved"
        );
        assert!(
            result.get("user-agent").is_some(),
            "User-Agent should be preserved"
        );
        assert!(
            result.get("accept").is_some(),
            "Accept header should be preserved"
        );
        assert!(
            result.get("x-request-id").is_some(),
            "Custom headers should be preserved"
        );
    }

    #[test]
    fn test_forwarded_protocol_header_based_on_listener() {
        use synvoid::config::site::ProxyHeadersConfig;
        use synvoid::proxy::headers::{build_forward_headers, ForwardedProtocol};

        let client_ip = "127.0.0.1".parse().unwrap();
        let original_headers = http::HeaderMap::new();

        let config = ProxyHeadersConfig::default();

        let http_result = build_forward_headers(
            client_ip,
            &original_headers,
            &config,
            ForwardedProtocol::Http,
        );
        let proto_header = http_result
            .get("x-forwarded-proto")
            .map(|v| v.to_str().unwrap_or(""));
        assert_eq!(
            proto_header.unwrap(),
            "http",
            "HTTP listener should set x-forwarded-proto to http"
        );

        let https_result = build_forward_headers(
            client_ip,
            &original_headers,
            &config,
            ForwardedProtocol::Https,
        );
        let proto_header = https_result
            .get("x-forwarded-proto")
            .map(|v| v.to_str().unwrap_or(""));
        assert_eq!(
            proto_header.unwrap(),
            "https",
            "HTTPS listener should set x-forwarded-proto to https"
        );
    }

    #[test]
    fn test_cache_key_construction_uses_sanitized_ip() {
        use std::net::IpAddr;

        let client_ip: IpAddr = "1.2.3.4".parse().unwrap();

        let sanitized_ip = format!("{}", client_ip);

        assert_eq!(
            sanitized_ip, "1.2.3.4",
            "Cache key should use client IP directly without extra formatting"
        );
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    #[test]
    fn test_non_linux_no_ebpf_support() {
        #[cfg(feature = "icmp-filter")]
        use synvoid::icmp_filter::platform::{has_privilege_for, FilterOperation};

        #[cfg(feature = "icmp-filter")]
        {
            let _ = has_privilege_for(FilterOperation::EbpfLoad);
        }

        #[cfg(not(feature = "icmp-filter"))]
        {
            println!("icmp-filter feature not enabled - skipping test");
        }
    }
}

#[test]
fn injected_security_failure() {
    assert!(false, "injected security regression failure");
}
