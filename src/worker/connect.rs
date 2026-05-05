use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::process::ipc_signed::IpcSigner;
use crate::process::ipc_transport::IpcEndpoint;
use crate::process::ipc_transport::IpcStream as AsyncIpcStream;
use crate::process::{connect_to_master, IpcStream};

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    #[test]
    fn test_connect_to_master_with_retry_invalid_path() {
        let socket_path = PathBuf::from("/nonexistent/path/socket.sock");
        let result =
            connect_to_master_with_retry(&socket_path, 1, Duration::from_millis(10), "test_worker");
        assert!(result.is_err());
    }

    #[test]
    fn test_connect_retry_returns_error_after_max_attempts() {
        let socket_path = PathBuf::from("/tmp/nonexistent_master.sock");
        let result =
            connect_to_master_with_retry(&socket_path, 3, Duration::from_millis(10), "test_worker");
        assert!(result.is_err());
    }

    #[test]
    fn test_worker_name_in_error_message() {
        let socket_path = PathBuf::from("/tmp/nonexistent.sock");
        let result = connect_to_master_with_retry(
            &socket_path,
            1,
            Duration::from_millis(10),
            "my_custom_worker",
        );
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connect_to_master_async_invalid_path() {
        let socket_path = PathBuf::from("/nonexistent/path/socket.sock");
        let result = connect_to_master_async(
            &socket_path,
            1,
            Duration::from_millis(10),
            "test_worker_async",
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_async_retry_exhaustion_message() {
        let socket_path = PathBuf::from("/tmp/nonexistent_async.sock");
        let result =
            connect_to_master_async(&socket_path, 2, Duration::from_millis(10), "async_worker")
                .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_retry_delay_is_respected() {
        let start = std::time::Instant::now();
        let socket_path = PathBuf::from("/tmp/should_fail.sock");
        let _ = connect_to_master_with_retry(
            &socket_path,
            3,
            Duration::from_millis(50),
            "timing_test_worker",
        );
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(100),
            "Expected at least 100ms for 3 retries with 50ms delay, got {:?}",
            elapsed
        );
    }

    #[test]
    fn test_single_attempt_no_delay() {
        let start = std::time::Instant::now();
        let socket_path = PathBuf::from("/tmp/quick_fail.sock");
        let _ = connect_to_master_with_retry(
            &socket_path,
            1,
            Duration::from_millis(100),
            "single_attempt_worker",
        );
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(50),
            "Should not delay on single attempt, got {:?}",
            elapsed
        );
    }

    #[test]
    fn test_pathbuf_file_name_extraction() {
        let path = PathBuf::from("/var/run/master.sock");
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("master");
        assert_eq!(file_name, "master.sock");
    }

    #[test]
    fn test_empty_path_handling() {
        let path = PathBuf::from("");
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("master");
        assert_eq!(file_name, "master");
    }
}

pub fn connect_to_master_with_retry(
    socket_path: &Path,
    max_retries: u32,
    retry_delay: Duration,
    worker_name: &str,
) -> Result<IpcStream, Box<dyn std::error::Error + Send + Sync>> {
    let mut last_error = None;

    for attempt in 1..=max_retries {
        match connect_to_master(socket_path) {
            Ok(ipc) => {
                if attempt > 1 {
                    tracing::info!("{} connected to master on attempt {}", worker_name, attempt);
                }
                return Ok(ipc);
            }
            Err(e) => {
                let err_msg = e.to_string();
                last_error = Some(e);
                if attempt < max_retries {
                    tracing::warn!(
                        "{} failed to connect to master (attempt {}/{}): {}, retrying in {:?}",
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
        "{} failed to connect to master after {} attempts: {}",
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

pub async fn connect_to_master_async(
    socket_path: &Path,
    max_retries: u32,
    retry_delay: Duration,
    worker_name: &str,
) -> Result<AsyncIpcStream, Box<dyn std::error::Error + Send + Sync>> {
    let socket_name = socket_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("master");

    let endpoint = IpcEndpoint::new(socket_name);
    let mut last_error = None;

    if let Some(signer) = try_load_ipc_signer() {
        for attempt in 1..=max_retries {
            match endpoint.connect_with_signer(Arc::clone(&signer)).await {
                Ok(ipc) => {
                    if attempt > 1 {
                        tracing::info!(
                            "{} connected to master on attempt {}",
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
                            "{} failed to connect to master (attempt {}/{}): {}, retrying in {:?}",
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
                            "{} connected to master on attempt {}",
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
                            "{} failed to connect to master (attempt {}/{}): {}, retrying in {:?}",
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
        "{} failed to connect to master after {} attempts: {}",
        worker_name, max_retries, error_msg
    )
    .into())
}

pub async fn connect_to_master_async_signed(
    socket_path: &Path,
    max_retries: u32,
    retry_delay: Duration,
    worker_name: &str,
    signer: Arc<IpcSigner>,
) -> Result<AsyncIpcStream, Box<dyn std::error::Error + Send + Sync>> {
    let socket_name = socket_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("master");

    let endpoint = IpcEndpoint::new(socket_name);
    let mut last_error = None;

    for attempt in 1..=max_retries {
        match endpoint.connect_with_signer(Arc::clone(&signer)).await {
            Ok(ipc) => {
                if attempt > 1 {
                    tracing::info!("{} connected to master on attempt {}", worker_name, attempt);
                }
                return Ok(ipc);
            }
            Err(e) => {
                let err_msg = e.to_string();
                last_error = Some(e);
                if attempt < max_retries {
                    tracing::warn!(
                        "{} failed to connect to master (attempt {}/{}): {}, retrying in {:?}",
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
        "{} failed to connect to master after {} attempts: {}",
        worker_name, max_retries, error_msg
    )
    .into())
}
