#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::Duration;

    use tempfile::TempDir;

    #[test]
    fn test_ipc_auth_bypass_rejected() {
        use maluwaf::process::ipc_signed::{IpcSigner, SignedIpcMessage};
        use maluwaf::process::Message;

        let key = maluwaf::process::ipc_signed::generate_session_key();
        let signer = IpcSigner::new(&key);

        let command = Message::WorkerStarted {
            id: maluwaf::process::WorkerId(1),
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
        use maluwaf::process::ipc_signed::IpcSigner;
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("key.txt");

        fs::write(&key_path, "a".repeat(64).as_bytes()).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();

        let symlink_path = temp_dir.path().join("key_symlink");
        std::os::unix::fs::symlink(&key_path, &symlink_path).unwrap();

        std::env::set_var("MALUWAF_IPC_KEY_FILE", symlink_path.to_str().unwrap());
        let result = IpcSigner::try_from_env();
        std::env::remove_var("MALUWAF_IPC_KEY_FILE");

        assert!(
            result.is_none(),
            "Signer must refuse to load key from symlink path"
        );
    }

    #[test]
    fn test_key_file_world_writable_rejected() {
        use maluwaf::process::ipc_signed::IpcSigner;
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("key.txt");

        fs::write(&key_path, "a".repeat(64).as_bytes()).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();

        std::env::set_var("MALUWAF_IPC_KEY_FILE", key_path.to_str().unwrap());
        let result = IpcSigner::try_from_env();
        std::env::remove_var("MALUWAF_IPC_KEY_FILE");

        assert!(
            result.is_none(),
            "Signer must refuse to load key with world-writable permissions"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_pidfile_lock_prevents_concurrent_access() {
        use maluwaf::process::pidfile::PidFileManager;
        use std::time::Instant;

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
        use maluwaf::process::pidfile::PidFileManager;

        let temp_dir = TempDir::new().unwrap();
        let mut manager1 = PidFileManager::with_custom_dir(temp_dir.path().to_path_buf());

        manager1.try_acquire(1234, "v1.0.0").unwrap();

        let content_before = fs::read_to_string(temp_dir.path().join("maluwaf.pid")).unwrap();
        assert!(content_before.contains("1234"));

        let mut manager2 = PidFileManager::with_custom_dir(temp_dir.path().to_path_buf());
        let acquired2 = manager2.try_acquire(5678, "v2.0.0").unwrap();
        assert!(!acquired2, "Second acquire should fail");

        let content_after = fs::read_to_string(temp_dir.path().join("maluwaf.pid")).unwrap();
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
        use maluwaf::process::ipc_signed::IpcSigner;
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();

        let real_key = temp_dir.path().join("real_key.txt");
        fs::write(&real_key, "a".repeat(64).as_bytes()).unwrap();
        fs::set_permissions(&real_key, fs::Permissions::from_mode(0o600)).unwrap();

        let symlink_key = temp_dir.path().join("key_link.txt");
        std::os::unix::fs::symlink(&real_key, &symlink_key).unwrap();

        std::env::set_var("MALUWAF_IPC_KEY_FILE", symlink_key.to_str().unwrap());
        let result = IpcSigner::try_from_env();
        std::env::remove_var("MALUWAF_IPC_KEY_FILE");

        assert!(
            result.is_none(),
            "IpcSigner should refuse keys accessed via symlink"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_read_ipc_key_file_rejects_symlink() {
        use maluwaf::process::ipc_signed::read_ipc_key_file;
        use std::os::unix::fs::PermissionsExt;

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
        use maluwaf::process::ipc_signed::read_ipc_key_file;
        use std::os::unix::fs::PermissionsExt;

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
        use maluwaf::icmp_filter::platform::{has_privilege_for, is_admin, FilterOperation};

        #[cfg(not(feature = "icmp-filter"))]
        {
            println!("icmp-filter feature not enabled - skipping test");
            return;
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

    #[cfg(all(unix, not(target_os = "linux")))]
    #[test]
    fn test_non_linux_no_ebpf_support() {
        #[cfg(feature = "icmp-filter")]
        use maluwaf::icmp_filter::platform::{has_privilege_for, FilterOperation};

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
