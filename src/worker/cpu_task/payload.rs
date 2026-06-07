// Submodule: payload helpers (deadline, file-backed payloads, sizing,
// backpressure-error shaping, site-id extraction).

use std::fs;
use std::path::PathBuf;

use ::metrics::counter;
use std::sync::atomic::Ordering;

use synvoid_ipc::{CpuTaskKind, CpuTaskPayload, CpuTaskPolicy, Message};

use super::metrics::{cpu_task_kind_label, CPU_TASK_REJECTED_TOTAL, CPU_TASK_TIMEOUT_TOTAL};

pub const INLINE_SMALL_TASK_MAX_BYTES: usize = 64 * 1024;

pub fn is_deadline_exceeded(deadline_unix_ms: u64) -> bool {
    if deadline_unix_ms == 0 {
        return false;
    }
    let now_unix_ms = crate::utils::current_timestamp().saturating_mul(1000);
    now_unix_ms > deadline_unix_ms
}

pub fn deadline_timeout_error(request_id: u64, task_kind: CpuTaskKind, message: String) -> Message {
    Message::CpuTaskError {
        request_id,
        task_kind,
        code: crate::process::CpuTaskErrorCode::Timeout,
        message,
        retryable: false,
    }
}

pub fn apply_file_backed_payload(
    payload: CpuTaskPayload,
    file_payload_path: Option<&str>,
    effective_payload_limit: usize,
) -> Result<CpuTaskPayload, String> {
    let Some(path_str) = file_payload_path else {
        return Ok(payload);
    };

    let raw_path = PathBuf::from(path_str);
    let canonical_path =
        fs::canonicalize(&raw_path).map_err(|e| format!("Invalid file_payload_path: {}", e))?;

    let temp_root = std::env::temp_dir();
    let canonical_temp_root = fs::canonicalize(&temp_root).unwrap_or(temp_root.clone());
    if !canonical_path.starts_with(&canonical_temp_root) && !canonical_path.starts_with(&temp_root)
    {
        return Err("file_payload_path must be under temp_dir".to_string());
    }
    let file_name = canonical_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| "file_payload_path missing filename".to_string())?;
    if !file_name.starts_with("synvoid-cpu-task-") {
        return Err("file_payload_path missing trusted prefix".to_string());
    }

    let metadata = fs::metadata(&canonical_path)
        .map_err(|e| format!("Failed to read file_payload metadata: {}", e))?;
    let file_len = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    if file_len > effective_payload_limit {
        return Err(format!(
            "file_payload exceeds limit: {} > {}",
            file_len, effective_payload_limit
        ));
    }
    let bytes = fs::read(&canonical_path)
        .map_err(|e| format!("Failed to read file_payload bytes: {}", e))?;
    let _ = fs::remove_file(&canonical_path);

    match payload {
        CpuTaskPayload::PoisonImage {
            site_id,
            body,
            last_modified,
            level,
            intensity,
            seed,
            max_dimension,
            jpeg_quality,
        } => {
            if !body.is_empty() {
                return Err(
                    "PoisonImage payload must use either inline body or file payload, not both"
                        .to_string(),
                );
            }
            Ok(CpuTaskPayload::PoisonImage {
                site_id,
                body: bytes,
                last_modified,
                level,
                intensity,
                seed,
                max_dimension,
                jpeg_quality,
            })
        }
        CpuTaskPayload::YaraScan {
            site_id,
            body,
            excluded_categories,
        } => {
            if !body.is_empty() {
                return Err(
                    "YaraScan payload must use either inline body or file payload, not both"
                        .to_string(),
                );
            }
            Ok(CpuTaskPayload::YaraScan {
                site_id,
                body: bytes,
                excluded_categories,
            })
        }
        _ => Err(
            "file_payload_path is currently supported only for PoisonImage and YaraScan"
                .to_string(),
        ),
    }
}

pub fn cpu_task_backpressure_error(
    request_id: u64,
    task_kind: CpuTaskKind,
    policy: CpuTaskPolicy,
    message: &str,
) -> Message {
    CPU_TASK_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
    counter!(
        "synvoid.static.cpu_offload.task_rejections",
        "task_kind" => cpu_task_kind_label(task_kind)
    )
    .increment(1);
    if matches!(policy, CpuTaskPolicy::FailOpenWithLog) {
        tracing::warn!(
            "CPU task backpressure fail-open path triggered for request {} kind {:?}: {}",
            request_id,
            task_kind,
            message
        );
    }
    let retryable = !matches!(policy, CpuTaskPolicy::FailClosed);
    Message::CpuTaskError {
        request_id,
        task_kind,
        code: crate::process::CpuTaskErrorCode::QueueSaturated,
        message: message.to_string(),
        retryable,
    }
}

pub fn cpu_task_site_id(payload: &CpuTaskPayload) -> Option<String> {
    match payload {
        CpuTaskPayload::Minify { site_id, .. }
        | CpuTaskPayload::GetCompressed { site_id, .. }
        | CpuTaskPayload::PoisonImage { site_id, .. }
        | CpuTaskPayload::YaraScan { site_id, .. }
        | CpuTaskPayload::WasmExecute { site_id, .. }
        | CpuTaskPayload::ServerlessInvoke { site_id, .. }
        | CpuTaskPayload::WasmTransformResponse { site_id, .. } => Some(site_id.clone()),
    }
}

pub fn estimate_cpu_task_payload_size(payload: &CpuTaskPayload) -> usize {
    match payload {
        CpuTaskPayload::Minify {
            site_id,
            path,
            encoding,
        } => site_id.len() + path.len() + encoding.as_ref().map_or(0, |v| v.len()),
        CpuTaskPayload::GetCompressed {
            site_id,
            path,
            encoding,
        } => site_id.len() + path.len() + encoding.len(),
        CpuTaskPayload::PoisonImage {
            site_id,
            body,
            last_modified,
            level,
            ..
        } => {
            site_id.len()
                + body.len()
                + last_modified.as_ref().map_or(0, |v| v.len())
                + level.as_ref().map_or(0, |v| v.len())
        }
        CpuTaskPayload::YaraScan {
            site_id,
            body,
            excluded_categories,
        } => {
            site_id.len()
                + body.len()
                + excluded_categories
                    .iter()
                    .map(std::string::String::len)
                    .sum::<usize>()
        }
        CpuTaskPayload::WasmExecute {
            site_id,
            plugin_name,
            function_name,
            input,
            ..
        } => site_id.len() + plugin_name.len() + function_name.len() + input.len(),
        CpuTaskPayload::ServerlessInvoke {
            site_id,
            function_name,
            input,
            ..
        } => site_id.len() + function_name.len() + input.len(),
        CpuTaskPayload::WasmTransformResponse {
            site_id,
            plugin_names,
            body,
            ..
        } => {
            site_id.len()
                + plugin_names
                    .iter()
                    .map(std::string::String::len)
                    .sum::<usize>()
                + body.len()
        }
    }
}

pub fn estimate_cpu_task_output_size(message: &Message) -> usize {
    match message {
        Message::CpuTaskResponse { result, .. } => match result {
            crate::process::CpuTaskResult::Minify {
                content,
                content_type,
                encoding,
                queued_encodings,
                site_id,
                path,
            } => {
                site_id.len()
                    + path.len()
                    + content.len()
                    + content_type.len()
                    + encoding.as_ref().map_or(0, |v| v.len())
                    + queued_encodings.iter().map(|e| e.len()).sum::<usize>()
            }
            crate::process::CpuTaskResult::GetCompressed { content } => content.len(),
            crate::process::CpuTaskResult::PoisonImage { poisoned_body } => poisoned_body.len(),
            crate::process::CpuTaskResult::YaraScan { matches } => {
                matches.iter().map(std::string::String::len).sum::<usize>()
            }
            crate::process::CpuTaskResult::WasmExecute { output }
            | crate::process::CpuTaskResult::ServerlessInvoke { output } => output.len(),
            crate::process::CpuTaskResult::WasmTransformResponse { body, .. } => body.len(),
        },
        Message::CpuTaskError { message, .. } => message.len(),
        _ => 0,
    }
}

#[allow(dead_code)]
pub fn record_deadline_timeout_metric(task_kind: CpuTaskKind, label: &'static str) {
    CPU_TASK_TIMEOUT_TOTAL.fetch_add(1, Ordering::Relaxed);
    counter!(
        "synvoid.static.cpu_offload.task_timeouts",
        "task_kind" => label
    )
    .increment(1);
    let _ = task_kind;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::CpuTaskPolicy;
    use std::io::Write;
    use tempfile::{Builder, NamedTempFile};

    #[test]
    fn test_apply_file_backed_payload_image_rights_success_and_cleanup() {
        let mut temp_file = Builder::new()
            .prefix("synvoid-cpu-task-")
            .tempfile_in(std::env::temp_dir())
            .expect("create temp payload file");
        temp_file
            .write_all(b"payload-bytes")
            .expect("write payload bytes");
        let payload_path = temp_file.path().to_string_lossy().to_string();

        let payload = CpuTaskPayload::PoisonImage {
            site_id: "site-a".to_string(),
            body: Vec::new(),
            last_modified: None,
            level: None,
            intensity: None,
            seed: None,
            max_dimension: None,
            jpeg_quality: None,
        };

        let updated =
            apply_file_backed_payload(payload, Some(&payload_path), 1024).expect("apply payload");
        drop(temp_file);

        match updated {
            CpuTaskPayload::PoisonImage { body, .. } => {
                assert_eq!(body, b"payload-bytes");
            }
            _ => panic!("unexpected payload variant"),
        }

        assert!(!PathBuf::from(&payload_path).exists());
    }

    #[test]
    fn test_apply_file_backed_payload_rejects_untrusted_prefix() {
        let mut temp_file = NamedTempFile::new_in(std::env::temp_dir()).expect("create temp file");
        temp_file.write_all(b"data").expect("write data");
        let payload_path = temp_file.path().to_string_lossy().to_string();

        let payload = CpuTaskPayload::PoisonImage {
            site_id: "site-a".to_string(),
            body: Vec::new(),
            last_modified: None,
            level: None,
            intensity: None,
            seed: None,
            max_dimension: None,
            jpeg_quality: None,
        };

        let result = apply_file_backed_payload(payload, Some(&payload_path), 1024);
        assert!(result.is_err());
    }

    #[test]
    fn test_apply_file_backed_payload_rejects_oversized_file() {
        let mut temp_file = Builder::new()
            .prefix("synvoid-cpu-task-")
            .tempfile_in(std::env::temp_dir())
            .expect("create temp payload file");
        temp_file.write_all(b"1234567890").expect("write data");
        let payload_path = temp_file.path().to_string_lossy().to_string();

        let payload = CpuTaskPayload::PoisonImage {
            site_id: "site-a".to_string(),
            body: Vec::new(),
            last_modified: None,
            level: None,
            intensity: None,
            seed: None,
            max_dimension: None,
            jpeg_quality: None,
        };

        let result = apply_file_backed_payload(payload, Some(&payload_path), 4);
        assert!(result.is_err());
    }

    #[test]
    fn test_apply_file_backed_payload_yara_scan_success_and_cleanup() {
        let mut temp_file = Builder::new()
            .prefix("synvoid-cpu-task-")
            .tempfile_in(std::env::temp_dir())
            .expect("create temp payload file");
        temp_file
            .write_all(b"yara-bytes")
            .expect("write payload bytes");
        let payload_path = temp_file.path().to_string_lossy().to_string();

        let payload = CpuTaskPayload::YaraScan {
            site_id: "site-a".to_string(),
            body: Vec::new(),
            excluded_categories: vec!["archive".to_string()],
        };

        let updated =
            apply_file_backed_payload(payload, Some(&payload_path), 1024).expect("apply payload");
        drop(temp_file);

        match updated {
            CpuTaskPayload::YaraScan {
                body,
                excluded_categories,
                ..
            } => {
                assert_eq!(body, b"yara-bytes");
                assert_eq!(excluded_categories, vec!["archive".to_string()]);
            }
            _ => panic!("unexpected payload variant"),
        }

        assert!(!PathBuf::from(&payload_path).exists());
    }

    #[test]
    fn test_cpu_task_backpressure_error_fail_closed_is_not_retryable() {
        let message = cpu_task_backpressure_error(
            7,
            CpuTaskKind::YaraScan,
            CpuTaskPolicy::FailClosed,
            "queue saturated",
        );

        match message {
            Message::CpuTaskError {
                request_id,
                task_kind,
                code,
                retryable,
                ..
            } => {
                assert_eq!(request_id, 7);
                assert_eq!(task_kind, CpuTaskKind::YaraScan);
                assert_eq!(code, crate::process::CpuTaskErrorCode::QueueSaturated);
                assert!(!retryable);
            }
            _ => panic!("expected CpuTaskError"),
        }
    }

    #[test]
    fn test_cpu_task_backpressure_error_fail_open_is_retryable() {
        let message = cpu_task_backpressure_error(
            8,
            CpuTaskKind::WasmExecute,
            CpuTaskPolicy::FailOpenWithLog,
            "global queue full",
        );

        match message {
            Message::CpuTaskError {
                request_id,
                task_kind,
                code,
                retryable,
                ..
            } => {
                assert_eq!(request_id, 8);
                assert_eq!(task_kind, CpuTaskKind::WasmExecute);
                assert_eq!(code, crate::process::CpuTaskErrorCode::QueueSaturated);
                assert!(retryable);
            }
            _ => panic!("expected CpuTaskError"),
        }
    }

    #[test]
    fn test_cpu_task_backpressure_error_skip_transform_is_retryable() {
        let message = cpu_task_backpressure_error(
            9,
            CpuTaskKind::Minify,
            CpuTaskPolicy::SkipTransform,
            "site queue full",
        );

        match message {
            Message::CpuTaskError {
                request_id,
                task_kind,
                code,
                retryable,
                ..
            } => {
                assert_eq!(request_id, 9);
                assert_eq!(task_kind, CpuTaskKind::Minify);
                assert_eq!(code, crate::process::CpuTaskErrorCode::QueueSaturated);
                assert!(retryable);
            }
            _ => panic!("expected CpuTaskError"),
        }
    }

    #[test]
    fn test_cpu_task_site_id_for_new_payloads() {
        let wasm_payload = CpuTaskPayload::WasmExecute {
            site_id: "site-x".to_string(),
            plugin_name: "p".to_string(),
            function_name: "f".to_string(),
            input: Vec::new(),
            timeout_ms: 1000,
        };
        assert_eq!(cpu_task_site_id(&wasm_payload), Some("site-x".to_string()));

        let serverless_payload = CpuTaskPayload::ServerlessInvoke {
            site_id: "site-y".to_string(),
            function_name: "f".to_string(),
            input: Vec::new(),
            timeout_ms: 1000,
        };
        assert_eq!(
            cpu_task_site_id(&serverless_payload),
            Some("site-y".to_string())
        );
    }

    #[test]
    fn test_estimate_cpu_task_payload_size_for_new_variants() {
        let wasm_payload = CpuTaskPayload::WasmExecute {
            site_id: "abc".to_string(),
            plugin_name: "pname".to_string(),
            function_name: "fname".to_string(),
            input: vec![0u8; 10],
            timeout_ms: 1000,
        };
        assert_eq!(
            estimate_cpu_task_payload_size(&wasm_payload),
            3 + 5 + 5 + 10
        );

        let serverless_payload = CpuTaskPayload::ServerlessInvoke {
            site_id: "site".to_string(),
            function_name: "fn".to_string(),
            input: vec![0u8; 4],
            timeout_ms: 1000,
        };
        assert_eq!(
            estimate_cpu_task_payload_size(&serverless_payload),
            4 + 2 + 4
        );
    }

    #[test]
    fn test_estimate_cpu_task_output_size_for_new_results() {
        let wasm_response = Message::CpuTaskResponse {
            request_id: 1,
            task_kind: CpuTaskKind::WasmExecute,
            result: crate::process::CpuTaskResult::WasmExecute {
                output: vec![0u8; 7],
            },
        };
        assert_eq!(estimate_cpu_task_output_size(&wasm_response), 7);

        let serverless_response = Message::CpuTaskResponse {
            request_id: 2,
            task_kind: CpuTaskKind::ServerlessInvoke,
            result: crate::process::CpuTaskResult::ServerlessInvoke {
                output: vec![0u8; 9],
            },
        };
        assert_eq!(estimate_cpu_task_output_size(&serverless_response), 9);
    }

    #[test]
    fn test_is_deadline_exceeded_zero_is_disabled() {
        assert!(!is_deadline_exceeded(0));
    }

    #[test]
    fn test_is_deadline_exceeded_past_timestamp() {
        assert!(is_deadline_exceeded(1));
    }

    #[test]
    fn test_deadline_timeout_error_shape() {
        let msg = deadline_timeout_error(42, CpuTaskKind::YaraScan, "deadline".to_string());
        match msg {
            Message::CpuTaskError {
                request_id,
                task_kind,
                code,
                message,
                retryable,
            } => {
                assert_eq!(request_id, 42);
                assert_eq!(task_kind, CpuTaskKind::YaraScan);
                assert_eq!(code, crate::process::CpuTaskErrorCode::Timeout);
                assert_eq!(message, "deadline");
                assert!(!retryable);
            }
            _ => panic!("expected CpuTaskError"),
        }
    }
}
