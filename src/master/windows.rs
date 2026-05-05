use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::config::ConfigManager;
use crate::process::ipc_signed::{IpcSigner, SignedIpcMessage};
use crate::process::ipc_transport::IpcStream as AsyncIpcStream;
use crate::process::write_message_sync;
use crate::process::{
    CommandResponse, MasterCommand, MasterStatus, ProcessManager, StatusStats, ThreatSummary,
};

#[cfg(windows)]
pub async fn windows_ipc_accept_loop(process_manager: Arc<ProcessManager>, pipe_name: PathBuf) {
    use std::os::windows::ffi::OsStrExt;

    let pipe_name_str = format!("\\\\.\\pipe\\synvoid-master");
    let pipe_name_wide: Vec<u16> = std::ffi::OsStr::new(&pipe_name_str)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    loop {
        // SAFETY: CreateNamedPipeW called with valid pipe name; we check for zero handle.
        let pipe_handle = unsafe {
            windows_sys::Win32::System::Pipes::CreateNamedPipeW(
                pipe_name_wide.as_ptr(),
                windows_sys::Win32::System::Pipes::PIPE_ACCESS_DUPLEX,
                windows_sys::Win32::System::Pipes::PIPE_TYPE_MESSAGE
                    | windows_sys::Win32::System::Pipes::PIPE_READMODE_MESSAGE
                    | windows_sys::Win32::System::Pipes::PIPE_WAIT,
                1,
                65536,
                65536,
                0,
                std::ptr::null_mut(),
            )
        };

        if pipe_handle == 0 {
            tracing::error!(
                "Failed to create named pipe: {:?}",
                std::io::Error::last_os_error()
            );
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            continue;
        }

        // SAFETY: ConnectNamedPipe called with valid pipe handle; we check return value.
        let connected = unsafe {
            windows_sys::Win32::System::Pipes::ConnectNamedPipe(pipe_handle, std::ptr::null_mut())
        };

        if connected == 0 {
            // SAFETY: GetLastError reads thread-local errno; always safe.
            let error = unsafe { *windows_sys::Win32::Foundation::GetLastError() };
            if error != windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED {
                tracing::warn!("ConnectNamedPipe failed with error: {}", error);
                // SAFETY: CloseHandle called on valid handle we own from failed ConnectNamedPipe.
                unsafe {
                    windows_sys::Win32::Foundation::CloseHandle(pipe_handle);
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        }

        // SAFETY: from_raw_handle takes ownership of pipe_handle; we validated it's non-zero above.
        let stream = unsafe {
            std::fs::File::from_raw_handle(pipe_handle as std::os::windows::io::RawHandle)
        };

        let pm = process_manager.clone();
        // TODO(ipc): This creates a sync `IpcStream` but `handle_worker_connection`
        // expects an async `AsyncIpcStream`. This is a type mismatch that would fail
        // on Windows. Should be refactored to use `ipc_transport::IpcListener` for
        // proper async named pipe handling.
        tokio::spawn(async move {
            super::handle_worker_connection(IpcStream::new(stream), pm).await;
        });
    }
}

#[cfg(windows)]
pub async fn windows_command_pipe_listener(
    config_manager: Arc<RwLock<ConfigManager>>,
    signer: Option<Arc<IpcSigner>>,
) {
    use std::os::windows::ffi::OsStrExt;

    let pipe_name_str = "\\\\.\\pipe\\synvoid-commands";
    let pipe_name_wide: Vec<u16> = std::ffi::OsStr::new(pipe_name_str)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    loop {
        // SAFETY: CreateNamedPipeW called with valid pipe name; we check for zero handle.
        let pipe_handle = unsafe {
            windows_sys::Win32::System::Pipes::CreateNamedPipeW(
                pipe_name_wide.as_ptr(),
                windows_sys::Win32::System::Pipes::PIPE_ACCESS_DUPLEX,
                windows_sys::Win32::System::Pipes::PIPE_TYPE_MESSAGE
                    | windows_sys::Win32::System::Pipes::PIPE_READMODE_MESSAGE
                    | windows_sys::Win32::System::Pipes::PIPE_WAIT,
                1,
                65536,
                65536,
                0,
                std::ptr::null_mut(),
            )
        };

        if pipe_handle == 0 {
            tracing::error!(
                "Failed to create command pipe: {:?}",
                std::io::Error::last_os_error()
            );
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            continue;
        }

        // SAFETY: ConnectNamedPipe called with valid pipe handle; we check return value.
        let connected = unsafe {
            windows_sys::Win32::System::Pipes::ConnectNamedPipe(pipe_handle, std::ptr::null_mut())
        };

        if connected == 0 {
            // SAFETY: GetLastError reads thread-local errno; always safe.
            let error = unsafe { *windows_sys::Win32::Foundation::GetLastError() };
            if error != windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED {
                tracing::warn!("ConnectNamedPipe failed with error: {}", error);
                // SAFETY: CloseHandle called on valid handle we own from failed ConnectNamedPipe.
                unsafe {
                    windows_sys::Win32::Foundation::CloseHandle(pipe_handle);
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        }

        // SAFETY: from_raw_handle takes ownership of pipe_handle; we validated it's non-zero above.
        let stream = unsafe {
            std::fs::File::from_raw_handle(pipe_handle as std::os::windows::io::RawHandle)
        };
        let signer = signer.clone();
        tokio::spawn(async move {
            handle_command_connection(stream, config_manager.clone(), signer).await;
        });
    }
}

/// Handle an incoming command on the Windows named command pipe.
///
/// Privileged commands (Stop, ReloadConfig) require HMAC-signed IPC messages.
/// Read-only commands (Status, HealthCheck) are accepted unsigned but this
/// should be migrated to require signing in a future release.
///
/// TODO(security): Full signed IPC migration — accept ONLY signed messages
/// when a signing key is configured, removing the unsigned fallback entirely.
#[cfg(windows)]
async fn handle_command_connection(
    stream: std::fs::File,
    config_manager: Arc<RwLock<ConfigManager>>,
    signer: Option<Arc<IpcSigner>>,
) {
    use std::io::{Read, Write};

    let mut stream = stream;

    let mut length_buf = [0u8; 4];
    match stream.read_exact(&mut length_buf) {
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("Failed to read command length: {}", e);
            return;
        }
    }

    let len = u32::from_be_bytes(length_buf) as usize;
    if len > 1024 * 1024 {
        let _ = stream.write_all(&0u32.to_be_bytes());
        return;
    }

    let mut msg_buf = vec![0u8; len];
    if let Err(e) = stream.read_exact(&mut msg_buf) {
        tracing::warn!("Failed to read command: {}", e);
        return;
    }

    let mut frame = Vec::with_capacity(4 + len);
    frame.extend_from_slice(&length_buf);
    frame.extend_from_slice(&msg_buf);

    let (command, authenticated) = if let Some(ref s) = signer {
        match SignedIpcMessage::deserialize_signed::<MasterCommand>(&frame, s) {
            Ok(cmd) => (cmd, true),
            Err(_) => match crate::serialization::deserialize::<MasterCommand>(&msg_buf) {
                Ok(c) => (c, false),
                Err(_) => match serde_json::from_slice::<MasterCommand>(&msg_buf) {
                    Ok(c) => (c, false),
                    Err(e) => {
                        tracing::warn!("Failed to parse command: {}", e);
                        let _ = write_message_sync(
                            &mut stream,
                            &CommandResponse::Error("Failed to parse command".to_string()),
                        );
                        return;
                    }
                },
            },
        }
    } else {
        match crate::serialization::deserialize::<MasterCommand>(&msg_buf) {
            Ok(c) => (c, false),
            Err(_) => match serde_json::from_slice::<MasterCommand>(&msg_buf) {
                Ok(c) => (c, false),
                Err(e) => {
                    tracing::warn!("Failed to parse command: {}", e);
                    let _ = write_message_sync(
                        &mut stream,
                        &CommandResponse::Error("Failed to parse command".to_string()),
                    );
                    return;
                }
            },
        }
    };

    match &command {
        MasterCommand::Stop { .. } | MasterCommand::ReloadConfig => {
            if !authenticated {
                tracing::error!(
                    "SECURITY: Rejected unauthenticated privileged command ({:?}) \
                     on command pipe. Configure SYNVOID_IPC_KEY or SYNVOID_IPC_KEY_FILE \
                     for signed IPC.",
                    command
                );
                let _ = write_message_sync(
                    &mut stream,
                    &CommandResponse::Error(
                        "Authentication required: configure IPC signing key".to_string(),
                    ),
                );
                return;
            }
        }
        MasterCommand::Status | MasterCommand::HealthCheck => {
            // SECURITY NOTE: Status and HealthCheck are non-mutating read-only
            // operations and may remain unsigned. Future releases should require
            // signing for all commands when a signing key is configured.
            if !authenticated {
                tracing::debug!("Unsigned read-only command ({:?}) on command pipe", command);
            }
        }
        _ => {
            if !authenticated {
                tracing::warn!("Rejected unauthenticated unknown command on command pipe");
                let _ = write_message_sync(
                    &mut stream,
                    &CommandResponse::Error("Authentication required".to_string()),
                );
                return;
            }
        }
    }

    match command {
        MasterCommand::Stop { graceful } => {
            tracing::info!("CLI: Stop command received (graceful: {})", graceful);
            let _ = write_message_sync(&mut stream, &CommandResponse::Ok("true".to_string()));
        }
        MasterCommand::ReloadConfig => {
            tracing::info!("CLI: ReloadConfig command received");
            {
                let config = config_manager.read();
                let mimes_config = &config.main.mimes;
                if mimes_config.enabled {
                    if let Some(ref mimes_file) = mimes_config.file {
                        match crate::mime::reload_mimes_from_file(mimes_file) {
                            Ok(()) => {
                                tracing::info!("MIME types reloaded from {}", mimes_file);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to reload MIME types from {}: {}",
                                    mimes_file,
                                    e
                                );
                            }
                        }
                    }
                }
            }
            {
                let mut config = config_manager.write();
                config.reload_all();
            }
            let _ = write_message_sync(&mut stream, &CommandResponse::Ok("true".to_string()));
        }
        MasterCommand::Status => {
            let status = MasterStatus {
                master_pid: std::process::id(),
                started_at: 0,
                uptime_secs: 0,
                version: env!("CARGO_PKG_VERSION").to_string(),
                workers: vec![],
                stats: StatusStats::default(),
                threat_summary: ThreatSummary::default(),
            };
            let _ = write_message_sync(&mut stream, &CommandResponse::Status(status));
        }
        MasterCommand::HealthCheck => {
            let _ = write_message_sync(&mut stream, &CommandResponse::Ok("true".to_string()));
        }
        _ => {}
    }
}
