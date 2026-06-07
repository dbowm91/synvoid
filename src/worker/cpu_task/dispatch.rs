// Submodule: CPU task request dispatch (the main per-request handler).

use std::sync::atomic::Ordering;
use std::time::Instant;

use ::metrics::{counter, gauge, histogram};

use crate::worker::image_rights;
use crate::worker::response_builder;
use synvoid_ipc::{
    CpuTaskErrorCode, CpuTaskKind, CpuTaskPayload, CpuTaskPolicy, CpuTaskResult, Message,
};

use super::metrics::{
    cpu_task_kind_label, decrement_task_kind_active, decrement_task_kind_queued,
    increment_task_kind_active, increment_task_kind_completed, increment_task_kind_queued,
    record_cpu_task_duration, CPU_TASK_FAILED_TOTAL, CPU_TASK_FALLBACK_INLINE_SMALL_TOTAL,
    CPU_TASK_PAYLOAD_BYTES_IN_TOTAL, CPU_TASK_PAYLOAD_BYTES_OUT_TOTAL, CPU_TASK_REJECTED_TOTAL,
    CPU_TASK_SUBMITTED_TOTAL, CPU_TASK_TIMEOUT_TOTAL,
};
use super::payload::{
    apply_file_backed_payload, cpu_task_backpressure_error, cpu_task_site_id,
    deadline_timeout_error, estimate_cpu_task_output_size, estimate_cpu_task_payload_size,
    is_deadline_exceeded, INLINE_SMALL_TASK_MAX_BYTES,
};
use super::state::{CpuTaskPermit, CpuWorkerState};

pub fn process_cpu_task_request_sync(
    state: &CpuWorkerState,
    request_id: u64,
    task_kind: CpuTaskKind,
    policy: CpuTaskPolicy,
    deadline_unix_ms: u64,
    payload_size_limit: u64,
    output_size_limit: u64,
    file_payload_path: Option<String>,
    payload: CpuTaskPayload,
) -> Message {
    let task_kind_label = cpu_task_kind_label(task_kind);
    if is_deadline_exceeded(deadline_unix_ms) {
        CPU_TASK_TIMEOUT_TOTAL.fetch_add(1, Ordering::Relaxed);
        counter!(
            "synvoid.static.cpu_offload.task_timeouts",
            "task_kind" => task_kind_label
        )
        .increment(1);
        return deadline_timeout_error(
            request_id,
            task_kind,
            "CPU task deadline exceeded before execution".to_string(),
        );
    }
    let effective_payload_limit =
        payload_size_limit.min(state.cpu_task_limiter.limits.max_payload_bytes as u64) as usize;
    let payload = match apply_file_backed_payload(
        payload,
        file_payload_path.as_deref(),
        effective_payload_limit,
    ) {
        Ok(p) => p,
        Err(msg) => {
            return Message::CpuTaskError {
                request_id,
                task_kind,
                code: CpuTaskErrorCode::InvalidRequest,
                message: msg,
                retryable: false,
            };
        }
    };

    let payload_size = estimate_cpu_task_payload_size(&payload);
    if payload_size > effective_payload_limit {
        return Message::CpuTaskError {
            request_id,
            task_kind,
            code: CpuTaskErrorCode::PayloadTooLarge,
            message: format!(
                "CPU task payload too large: {} bytes > {} bytes",
                payload_size, effective_payload_limit
            ),
            retryable: false,
        };
    }

    let site_id = cpu_task_site_id(&payload);
    increment_task_kind_queued(task_kind);
    gauge!(
        "synvoid.static.cpu_offload.queue_depth",
        "task_kind" => task_kind_label
    )
    .increment(1.0);
    let _permit = match state.cpu_task_limiter.try_acquire(site_id.as_deref()) {
        Ok(()) => Some(CpuTaskPermit {
            limiter: state.cpu_task_limiter.clone(),
            site_id,
        }),
        Err(backpressure_err) => {
            if matches!(policy, CpuTaskPolicy::DegradeToInlineSmallOnly)
                && payload_size <= INLINE_SMALL_TASK_MAX_BYTES
            {
                tracing::warn!(
                    "CPU task request {} saturated offload queue; degrading to inline small-task execution ({} bytes)",
                    request_id,
                    payload_size
                );
                CPU_TASK_FALLBACK_INLINE_SMALL_TOTAL.fetch_add(1, Ordering::Relaxed);
                None
            } else {
                decrement_task_kind_queued(task_kind);
                gauge!(
                    "synvoid.static.cpu_offload.queue_depth",
                    "task_kind" => task_kind_label
                )
                .decrement(1.0);
                return cpu_task_backpressure_error(
                    request_id,
                    task_kind,
                    policy,
                    backpressure_err,
                );
            }
        }
    };
    decrement_task_kind_queued(task_kind);
    gauge!(
        "synvoid.static.cpu_offload.queue_depth",
        "task_kind" => task_kind_label
    )
    .decrement(1.0);

    CPU_TASK_SUBMITTED_TOTAL.fetch_add(1, Ordering::Relaxed);

    increment_task_kind_active(task_kind);
    gauge!(
        "synvoid.static.cpu_offload.active_tasks",
        "task_kind" => task_kind_label
    )
    .increment(1.0);
    let started = Instant::now();
    CPU_TASK_PAYLOAD_BYTES_IN_TOTAL.fetch_add(payload_size as u64, Ordering::Relaxed);
    counter!(
        "synvoid.static.cpu_offload.payload_bytes_in_total",
        "task_kind" => task_kind_label
    )
    .increment(payload_size as u64);

    let mut response = match payload {
        CpuTaskPayload::Minify {
            site_id,
            path,
            encoding,
        } => match response_builder::process_minify_request(
            state, request_id, site_id, path, encoding,
        ) {
            Ok(CpuTaskResult::Minify {
                site_id,
                path,
                content,
                content_type,
                encoding,
                queued_encodings,
            }) => {
                let response = Message::CpuTaskResponse {
                    request_id,
                    task_kind,
                    result: CpuTaskResult::Minify {
                        site_id,
                        path,
                        content,
                        content_type,
                        encoding,
                        queued_encodings,
                    },
                };
                if estimate_cpu_task_output_size(&response)
                    > output_size_limit.min(state.cpu_task_limiter.limits.max_output_bytes as u64)
                        as usize
                {
                    Message::CpuTaskError {
                        request_id,
                        task_kind,
                        code: CpuTaskErrorCode::PayloadTooLarge,
                        message: "CPU task output exceeds configured cap".to_string(),
                        retryable: false,
                    }
                } else {
                    response
                }
            }
            Ok(_) => Message::CpuTaskError {
                request_id,
                task_kind,
                code: CpuTaskErrorCode::InternalError,
                message: "Unexpected minify response shape".to_string(),
                retryable: false,
            },
            Err(error) => Message::CpuTaskError {
                request_id,
                task_kind,
                code: CpuTaskErrorCode::InternalError,
                message: error,
                retryable: false,
            },
        },
        CpuTaskPayload::GetCompressed {
            site_id,
            path,
            encoding,
        } => match response_builder::process_compressed_request(
            state, request_id, site_id, path, encoding,
        ) {
            Ok(CpuTaskResult::GetCompressed { content }) => {
                let response = Message::CpuTaskResponse {
                    request_id,
                    task_kind,
                    result: CpuTaskResult::GetCompressed { content },
                };
                if estimate_cpu_task_output_size(&response)
                    > output_size_limit.min(state.cpu_task_limiter.limits.max_output_bytes as u64)
                        as usize
                {
                    Message::CpuTaskError {
                        request_id,
                        task_kind,
                        code: CpuTaskErrorCode::PayloadTooLarge,
                        message: "CPU task output exceeds configured cap".to_string(),
                        retryable: false,
                    }
                } else {
                    response
                }
            }
            Ok(_) => Message::CpuTaskError {
                request_id,
                task_kind,
                code: CpuTaskErrorCode::InternalError,
                message: "Unexpected compressed response shape".to_string(),
                retryable: false,
            },
            Err(error) => Message::CpuTaskError {
                request_id,
                task_kind,
                code: CpuTaskErrorCode::InternalError,
                message: error,
                retryable: false,
            },
        },
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
            let poisoned_body = image_rights::mark_image_rights_sync(
                state,
                &site_id,
                body,
                last_modified,
                level,
                intensity,
                seed,
                max_dimension,
                jpeg_quality,
            );
            let response = Message::CpuTaskResponse {
                request_id,
                task_kind,
                result: crate::process::CpuTaskResult::PoisonImage { poisoned_body },
            };
            if estimate_cpu_task_output_size(&response)
                > output_size_limit.min(state.cpu_task_limiter.limits.max_output_bytes as u64)
                    as usize
            {
                Message::CpuTaskError {
                    request_id,
                    task_kind,
                    code: CpuTaskErrorCode::PayloadTooLarge,
                    message: "CPU task output exceeds configured cap".to_string(),
                    retryable: false,
                }
            } else {
                response
            }
        }
        CpuTaskPayload::YaraScan {
            site_id: _site_id,
            body,
            excluded_categories,
        } => {
            let Some(scanner) = state.yara_scanner.as_ref() else {
                return Message::CpuTaskError {
                    request_id,
                    task_kind,
                    code: CpuTaskErrorCode::InvalidRequest,
                    message: "YARA scanner is not enabled for static CPU offload worker"
                        .to_string(),
                    retryable: false,
                };
            };

            let excluded_refs: Vec<&str> = excluded_categories.iter().map(|s| s.as_str()).collect();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            match runtime {
                Ok(rt) => match rt.block_on(scanner.scan_bytes(&body, &excluded_refs)) {
                    Ok(matches) => {
                        let response = Message::CpuTaskResponse {
                            request_id,
                            task_kind,
                            result: crate::process::CpuTaskResult::YaraScan {
                                matches: matches.into_iter().map(|m| m.rule_name).collect(),
                            },
                        };
                        if estimate_cpu_task_output_size(&response)
                            > output_size_limit
                                .min(state.cpu_task_limiter.limits.max_output_bytes as u64)
                                as usize
                        {
                            Message::CpuTaskError {
                                request_id,
                                task_kind,
                                code: CpuTaskErrorCode::PayloadTooLarge,
                                message: "CPU task output exceeds configured cap".to_string(),
                                retryable: false,
                            }
                        } else {
                            response
                        }
                    }
                    Err(e) => Message::CpuTaskError {
                        request_id,
                        task_kind,
                        code: CpuTaskErrorCode::InternalError,
                        message: format!("YARA scan failed: {}", e),
                        retryable: false,
                    },
                },
                Err(e) => Message::CpuTaskError {
                    request_id,
                    task_kind,
                    code: CpuTaskErrorCode::InternalError,
                    message: format!("Failed to create YARA scan runtime: {}", e),
                    retryable: false,
                },
            }
        }
        // Serverless handler ABI (handle_request) — NOT for response transforms.
        // Response transforms use CpuTaskPayload::WasmTransformResponse instead.
        CpuTaskPayload::WasmExecute {
            site_id: _site_id,
            plugin_name,
            function_name: _function_name,
            input,
            timeout_ms: _timeout_ms,
        } => {
            let plugin_manager = crate::plugin::get_global_plugin_manager();
            let wasm_manager = plugin_manager.get_wasm_manager();
            let runtime_result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            let invocation = runtime_result.map(|rt| {
                rt.block_on(async {
                    let env = std::collections::HashMap::new();
                    let headers = "{}".to_string();
                    let uri = "/".to_string();
                    let method = "POST";
                    let result = tokio::task::spawn_blocking({
                        let manager = wasm_manager.clone();
                        let name = plugin_name.clone();
                        let uri = uri.clone();
                        let headers = headers.clone();
                        let body = input.clone();
                        move || manager.invoke_by_name(&name, method, &uri, &headers, &body, env)
                    })
                    .await;
                    match result {
                        Ok(Ok(response)) => Ok(response.into_body().to_vec()),
                        Ok(Err(e)) => Err(e.to_string()),
                        Err(e) => Err(format!("WASM invoke join error: {}", e)),
                    }
                })
            });
            match invocation {
                Ok(Ok(output)) => {
                    let response = Message::CpuTaskResponse {
                        request_id,
                        task_kind,
                        result: crate::process::CpuTaskResult::WasmExecute { output },
                    };
                    if estimate_cpu_task_output_size(&response)
                        > output_size_limit
                            .min(state.cpu_task_limiter.limits.max_output_bytes as u64)
                            as usize
                    {
                        Message::CpuTaskError {
                            request_id,
                            task_kind,
                            code: CpuTaskErrorCode::PayloadTooLarge,
                            message: "CPU task output exceeds configured cap".to_string(),
                            retryable: false,
                        }
                    } else {
                        response
                    }
                }
                Ok(Err(e)) => Message::CpuTaskError {
                    request_id,
                    task_kind,
                    code: CpuTaskErrorCode::InternalError,
                    message: format!("WASM execute failed: {}", e),
                    retryable: false,
                },
                Err(e) => Message::CpuTaskError {
                    request_id,
                    task_kind,
                    code: CpuTaskErrorCode::InternalError,
                    message: format!("Failed to create WASM execute runtime: {}", e),
                    retryable: false,
                },
            }
        }
        CpuTaskPayload::WasmTransformResponse {
            site_id: _site_id,
            plugin_names,
            status_code,
            body,
            env,
            timeout_ms: _timeout_ms,
        } => {
            let plugin_manager = crate::plugin::get_global_plugin_manager();
            let wasm_manager = plugin_manager.get_wasm_manager();

            let wasm_resp = http::Response::builder()
                .status(status_code)
                .body(bytes::Bytes::from(body))
                .unwrap_or_else(|_| {
                    http::Response::builder()
                        .status(200)
                        .body(bytes::Bytes::new())
                        .unwrap_or_else(|_| http::Response::new(bytes::Bytes::new()))
                });

            let transform_result =
                wasm_manager.transform_response_with_plugins(wasm_resp, &plugin_names, env);

            match transform_result {
                Ok(transformed) => {
                    let (parts, transformed_body) = transformed.into_parts();
                    let result = CpuTaskResult::WasmTransformResponse {
                        status_code: parts.status.as_u16(),
                        body: transformed_body.to_vec(),
                    };
                    let response = Message::CpuTaskResponse {
                        request_id,
                        task_kind,
                        result,
                    };
                    if estimate_cpu_task_output_size(&response)
                        > output_size_limit
                            .min(state.cpu_task_limiter.limits.max_output_bytes as u64)
                            as usize
                    {
                        Message::CpuTaskError {
                            request_id,
                            task_kind,
                            code: CpuTaskErrorCode::PayloadTooLarge,
                            message: "CPU task output exceeds configured cap".to_string(),
                            retryable: false,
                        }
                    } else {
                        response
                    }
                }
                Err(e) => Message::CpuTaskError {
                    request_id,
                    task_kind,
                    code: CpuTaskErrorCode::InternalError,
                    message: format!("WASM response transform failed: {}", e),
                    retryable: false,
                },
            }
        }
        CpuTaskPayload::ServerlessInvoke {
            site_id: _site_id,
            function_name,
            input,
            timeout_ms,
        } => {
            let manager = crate::serverless::manager::get_global_serverless_manager();
            let Some(manager) = manager else {
                return Message::CpuTaskError {
                    request_id,
                    task_kind,
                    code: CpuTaskErrorCode::InternalError,
                    message: "no serverless manager configured for CPU offload".to_string(),
                    retryable: false,
                };
            };
            let runtime_result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            let invocation = runtime_result.map(|rt| {
                rt.block_on(manager.invoke_for_cpu_offload(&function_name, &input, timeout_ms))
            });
            match invocation {
                Ok(Ok(output)) => {
                    let response = Message::CpuTaskResponse {
                        request_id,
                        task_kind,
                        result: crate::process::CpuTaskResult::ServerlessInvoke { output },
                    };
                    if estimate_cpu_task_output_size(&response)
                        > output_size_limit
                            .min(state.cpu_task_limiter.limits.max_output_bytes as u64)
                            as usize
                    {
                        Message::CpuTaskError {
                            request_id,
                            task_kind,
                            code: CpuTaskErrorCode::PayloadTooLarge,
                            message: "CPU task output exceeds configured cap".to_string(),
                            retryable: false,
                        }
                    } else {
                        response
                    }
                }
                Ok(Err(e)) => Message::CpuTaskError {
                    request_id,
                    task_kind,
                    code: CpuTaskErrorCode::InternalError,
                    message: format!("serverless invoke failed: {}", e),
                    retryable: false,
                },
                Err(e) => Message::CpuTaskError {
                    request_id,
                    task_kind,
                    code: CpuTaskErrorCode::InternalError,
                    message: format!("Failed to create serverless invoke runtime: {}", e),
                    retryable: false,
                },
            }
        }
    };

    if is_deadline_exceeded(deadline_unix_ms) {
        response = match response {
            Message::CpuTaskResponse { .. } => {
                CPU_TASK_TIMEOUT_TOTAL.fetch_add(1, Ordering::Relaxed);
                counter!(
                    "synvoid.static.cpu_offload.task_timeouts",
                    "task_kind" => task_kind_label
                )
                .increment(1);
                deadline_timeout_error(
                    request_id,
                    task_kind,
                    "CPU task deadline exceeded during execution".to_string(),
                )
            }
            other => other,
        };
    }

    let task_duration = started.elapsed();
    histogram!(
        "synvoid.static.cpu_offload.task_duration_seconds",
        "task_kind" => task_kind_label
    )
    .record(task_duration.as_secs_f64());
    record_cpu_task_duration(task_kind, task_duration.as_millis() as u64);
    decrement_task_kind_active(task_kind);
    gauge!(
        "synvoid.static.cpu_offload.active_tasks",
        "task_kind" => task_kind_label
    )
    .decrement(1.0);

    if let Message::CpuTaskError { code, .. } = &response {
        match code {
            CpuTaskErrorCode::QueueSaturated
            | CpuTaskErrorCode::PayloadTooLarge
            | CpuTaskErrorCode::InvalidRequest => {
                CPU_TASK_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
                counter!(
                    "synvoid.static.cpu_offload.task_rejections",
                    "task_kind" => task_kind_label
                )
                .increment(1);
            }
            CpuTaskErrorCode::Timeout => {
                CPU_TASK_TIMEOUT_TOTAL.fetch_add(1, Ordering::Relaxed);
                counter!(
                    "synvoid.static.cpu_offload.task_timeouts",
                    "task_kind" => task_kind_label
                )
                .increment(1);
            }
            CpuTaskErrorCode::InternalError => {
                CPU_TASK_FAILED_TOTAL.fetch_add(1, Ordering::Relaxed);
                counter!(
                    "synvoid.static.cpu_offload.task_failures",
                    "task_kind" => task_kind_label
                )
                .increment(1);
            }
        }
    } else {
        let output_size = estimate_cpu_task_output_size(&response) as u64;
        CPU_TASK_PAYLOAD_BYTES_OUT_TOTAL.fetch_add(output_size, Ordering::Relaxed);
        counter!(
            "synvoid.static.cpu_offload.payload_bytes_out_total",
            "task_kind" => task_kind_label
        )
        .increment(output_size);
        increment_task_kind_completed(task_kind);
    }

    response
}
