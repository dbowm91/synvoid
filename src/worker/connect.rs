use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use synvoid_ipc::ipc_signed::IpcSigner;
use synvoid_ipc::ipc_transport::IpcEndpoint;
use synvoid_ipc::ipc_transport::IpcStream as AsyncIpcStream;
use synvoid_ipc::{connect_to_supervisor, IpcStream};

pub fn connect_to_supervisor_with_retry(
    socket_path: &Path,
    max_retries: u32,
    retry_delay: Duration,
    worker_name: &str,
) -> Result<IpcStream, Box<dyn std::error::Error + Send + Sync>> {
    let mut last_error = None;

    for attempt in 1..=max_retries {
        match connect_to_supervisor(socket_path) {
            Ok(ipc) => {
                if attempt > 1 {
                    tracing::info!(
                        "{} connected to supervisor on attempt {}",
                        worker_name,
                        attempt
                    );
                }
                return Ok(ipc);
            }
            Err(e) => {
                let err_msg = e.to_string();
                last_error = Some(e);
                if attempt < max_retries {
                    tracing::warn!(
                        "{} failed to connect to supervisor (attempt {}/{}): {}, retrying in {:?}",
                        worker_name,
                        attempt,
                        max_retries,
                        err_msg,
                        retry_delay
                    );
                    std::thread::sleep(retry_delay);
                }
            }
        }
    }

    let error_msg = last_error
        .map(|e| e.to_string())
        .unwrap_or_else(|| "unknown error".to_string());
    Err(format!(
        "{} failed to connect to supervisor after {} attempts: {}",
        worker_name, max_retries, error_msg
    )
    .into())
}

fn try_load_ipc_signer() -> Option<Arc<IpcSigner>> {
    if let Ok(key_file) = std::env::var("SYNVOID_IPC_KEY_FILE") {
        if let Some(key) = crate::process::ipc_signed::read_ipc_key_file(&key_file) {
            return Some(key);
        }
    } else if let Ok(key_hex) = std::env::var("SYNVOID_IPC_KEY") {
        if key_hex.len() == 64 {
            let mut key = [0u8; 32];
            let mut valid = true;
            for (i, chunk) in key_hex.as_bytes().chunks(2).enumerate() {
                if chunk.len() != 2 {
                    valid = false;
                    break;
                }
                let Ok(s) = std::str::from_utf8(chunk) else {
                    valid = false;
                    break;
                };
                match u8::from_str_radix(s, 16) {
                    Ok(b) => key[i] = b,
                    Err(_) => {
                        valid = false;
                        break;
                    }
                }
            }
            if valid {
                return Some(Arc::new(IpcSigner::new(&key)));
            }
        }
    }
    None
}

pub async fn connect_to_supervisor_async(
    socket_path: &Path,
    max_retries: u32,
    retry_delay: Duration,
    worker_name: &str,
) -> Result<AsyncIpcStream, Box<dyn std::error::Error + Send + Sync>> {
    let socket_name = socket_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("supervisor");

    let endpoint = IpcEndpoint::new(socket_name);
    let mut last_error = None;

    if let Some(signer) = try_load_ipc_signer() {
        for attempt in 1..=max_retries {
            match endpoint.connect_with_signer(Arc::clone(&signer)).await {
                Ok(ipc) => {
                    if attempt > 1 {
                        tracing::info!(
                            "{} connected to supervisor on attempt {}",
                            worker_name,
                            attempt
                        );
                    }
                    return Ok(ipc);
                }
                Err(e) => {
                    let err_msg = e.to_string();
                    last_error = Some(e);
                    if attempt < max_retries {
                        tracing::warn!(
                            "{} failed to connect to supervisor (attempt {}/{}): {}, retrying in {:?}",
                            worker_name,
                            attempt,
                            max_retries,
                            err_msg,
                            retry_delay
                        );
                        tokio::time::sleep(retry_delay).await;
                    }
                }
            }
        }
    } else {
        for attempt in 1..=max_retries {
            match endpoint.connect().await {
                Ok(ipc) => {
                    if attempt > 1 {
                        tracing::info!(
                            "{} connected to supervisor on attempt {}",
                            worker_name,
                            attempt
                        );
                    }
                    return Ok(ipc);
                }
                Err(e) => {
                    let err_msg = e.to_string();
                    last_error = Some(e);
                    if attempt < max_retries {
                        tracing::warn!(
                            "{} failed to connect to supervisor (attempt {}/{}): {}, retrying in {:?}",
                            worker_name,
                            attempt,
                            max_retries,
                            err_msg,
                            retry_delay
                        );
                        tokio::time::sleep(retry_delay).await;
                    }
                }
            }
        }
    }

    let error_msg = last_error
        .map(|e| e.to_string())
        .unwrap_or_else(|| "unknown error".to_string());
    Err(format!(
        "{} failed to connect to supervisor after {} attempts: {}",
        worker_name, max_retries, error_msg
    )
    .into())
}

pub async fn connect_to_supervisor_async_signed(
    socket_path: &Path,
    max_retries: u32,
    retry_delay: Duration,
    worker_name: &str,
    signer: Arc<IpcSigner>,
) -> Result<AsyncIpcStream, Box<dyn std::error::Error + Send + Sync>> {
    let socket_name = socket_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("supervisor");

    let endpoint = IpcEndpoint::new(socket_name);
    let mut last_error = None;

    for attempt in 1..=max_retries {
        match endpoint.connect_with_signer(Arc::clone(&signer)).await {
            Ok(ipc) => {
                if attempt > 1 {
                    tracing::info!(
                        "{} connected to supervisor on attempt {}",
                        worker_name,
                        attempt
                    );
                }
                return Ok(ipc);
            }
            Err(e) => {
                let err_msg = e.to_string();
                last_error = Some(e);
                if attempt < max_retries {
                    tracing::warn!(
                        "{} failed to connect to supervisor (attempt {}/{}): {}, retrying in {:?}",
                        worker_name,
                        attempt,
                        max_retries,
                        err_msg,
                        retry_delay
                    );
                    tokio::time::sleep(retry_delay).await;
                }
            }
        }
    }

    let error_msg = last_error
        .map(|e| e.to_string())
        .unwrap_or_else(|| "unknown error".to_string());
    Err(format!(
        "{} failed to connect to supervisor after {} attempts: {}",
        worker_name, max_retries, error_msg
    )
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    #[test]
    fn test_connect_to_supervisor_with_retry_invalid_path() {
        let socket_path = PathBuf::from("/nonexistent/path/socket.sock");
        let result = connect_to_supervisor_with_retry(
            &socket_path,
            1,
            Duration::from_millis(10),
            "test_worker",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_connect_to_supervisor_zero_retries() {
        let socket_path = PathBuf::from("/nonexistent/path/socket.sock");
        let result = connect_to_supervisor_with_retry(
            &socket_path,
            0,
            Duration::from_millis(10),
            "test_worker",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_connect_to_supervisor_with_retry_delay() {
        let socket_path = PathBuf::from("/nonexistent/path/socket.sock");
        let start = std::time::Instant::now();
        let result = connect_to_supervisor_with_retry(
            &socket_path,
            2,
            Duration::from_millis(50),
            "test_worker",
        );
        assert!(result.is_err());
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(50),
            "Should have waited at least one retry delay, got {:?}",
            elapsed
        );
    }

    #[test]
    fn test_connect_to_supervisor_single_attempt_no_delay() {
        let socket_path = PathBuf::from("/nonexistent/path/socket.sock");
        let start = std::time::Instant::now();
        let result = connect_to_supervisor_with_retry(
            &socket_path,
            1,
            Duration::from_millis(100),
            "single_attempt_worker",
        );
        assert!(result.is_err());
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(50),
            "Should not delay on single attempt, got {:?}",
            elapsed
        );
    }

    #[test]
    fn test_pathbuf_file_name_extraction() {
        let path = PathBuf::from("/var/run/supervisor.sock");
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("supervisor");
        assert_eq!(file_name, "supervisor.sock");
    }

    #[test]
    fn test_empty_path_handling() {
        let path = PathBuf::from("");
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("supervisor");
        assert_eq!(file_name, "supervisor");
    }
}
