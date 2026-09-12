//! WASM jail execution service (child side).
//!
//! Canonical owner (Phase 29): `synvoid-jail-runtime`. The root
//! `src/sandbox/wasm_service.rs` is a pure re-export facade.
//!
//! Implements [`synvoid_ipc::JailHandler`] for [`synvoid_ipc::JailKind::Wasm`]
//! by loading parent-approved modules with [`WasmRuntime`] and invoking their
//! `handle_request` export with bounded input.
//!
//! Trust model: the parent validated plugin identity, signatures, manifests,
//! and capability policy before sending the load. The jail independently
//! verifies the content digest (constant-time), enforces runtime limits
//! (fuel, memory, timeout, epoch backstop), and — crucially — never grants
//! ambient authority: capabilities are rebuilt from the narrow
//! [`synvoid_ipc::JailHookCapabilities`] in the load request, so filesystem,
//! network, mesh, admin, persistence, and metrics authority cannot be granted
//! inside the jail regardless of the parent-side manifest.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use synvoid_ipc::{
    JailError, JailErrorDto, JailHandler, JailHookCapabilities, JailOperation, JailOutput,
    JailResult, JAIL_MAX_INVOKE_OUTPUT_BYTES, JAIL_MAX_MODULES,
};
use synvoid_plugin_runtime::{PluginCapabilities, WasmResourceLimits, WasmRuntime};

/// Jail-side WASM module registry plus execution.
pub struct WasmJailService {
    modules: HashMap<String, Arc<WasmRuntime>>,
}

impl WasmJailService {
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
        }
    }

    /// Number of loaded modules (for limit tests).
    pub fn loaded_count(&self) -> usize {
        self.modules.len()
    }

    #[allow(clippy::too_many_arguments)]
    fn load(
        &mut self,
        module_id: &str,
        digest_sha256_hex: &str,
        wasm_bytes: &[u8],
        fuel: u64,
        memory_pages: Option<u32>,
        timeout_ms: u64,
        capabilities: &JailHookCapabilities,
    ) -> JailResult {
        if self.modules.len() >= JAIL_MAX_MODULES && !self.modules.contains_key(module_id) {
            return JailResult::Err(
                JailError::ResourceExhausted("too many loaded modules".to_string()).to_dto(),
            );
        }
        if !synvoid_ipc::verify_sha256_hex(wasm_bytes, digest_sha256_hex) {
            return JailResult::Err(
                JailError::DigestMismatch("wasm digest mismatch".to_string()).to_dto(),
            );
        }
        // Rebuild capabilities from hook flags only: ambient authority
        // (filesystem, network, mesh, admin, persistence, metrics) is
        // structurally ungrantable here.
        let caps = PluginCapabilities {
            request_inspect: capabilities.request_inspect,
            request_mutate: capabilities.request_mutate,
            response_inspect: capabilities.response_inspect,
            response_mutate: capabilities.response_mutate,
            ..Default::default()
        };

        // memory_pages (64 KiB each) converted to whole MiB, at least 1.
        let max_memory_mb = memory_pages
            .map(|pages| (pages as usize * 65536).div_ceil(1024 * 1024))
            .unwrap_or(64)
            .max(1);
        let limits = WasmResourceLimits {
            max_memory_mb,
            max_cpu_fuel: fuel,
            timeout: Duration::from_millis(timeout_ms),
            max_instances: 1,
            capabilities: Arc::new(caps),
            epoch_deadline_enabled: true,
            ..Default::default()
        };
        match WasmRuntime::load_from_bytes_with_priority(module_id, wasm_bytes, limits, 0) {
            Ok(runtime) => {
                self.modules
                    .insert(module_id.to_string(), Arc::new(runtime));
                tracing::info!("jail loaded wasm module");
                JailResult::Ok(JailOutput::WasmLoaded)
            }
            Err(e) => {
                // Load failure text may name exports; keep the message but
                // bounded via the DTO constructor.
                JailResult::Err(JailErrorDto::new(
                    synvoid_ipc::JailErrorCode::ExecutionFailed,
                    format!("wasm load failed: {e}"),
                ))
            }
        }
    }

    fn invoke(
        &self,
        module_id: &str,
        method: &str,
        uri: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> JailResult {
        let runtime = match self.modules.get(module_id) {
            Some(runtime) => runtime,
            None => {
                return JailResult::Err(
                    JailError::NotFound("wasm module not loaded".to_string()).to_dto(),
                );
            }
        };
        let headers_json = match crate::headers::headers_to_guest_json(headers) {
            Ok(json) => json,
            Err(e) => return JailResult::Err(e.to_dto()),
        };
        match runtime.invoke_handler(method, uri, &headers_json, body, HashMap::new()) {
            Ok(response) => {
                let status = response.status().as_u16();
                let mut out_headers = Vec::new();
                for (name, value) in response.headers().iter() {
                    if out_headers.len() >= synvoid_ipc::JAIL_MAX_HEADERS {
                        break;
                    }
                    if let Ok(v) = value.to_str() {
                        out_headers.push((name.to_string(), v.to_string()));
                    }
                }
                let body = response.into_body();
                if body.len() > JAIL_MAX_INVOKE_OUTPUT_BYTES {
                    return JailResult::Err(
                        JailError::Oversized("wasm output too large".to_string()).to_dto(),
                    );
                }
                JailResult::Ok(JailOutput::WasmResult {
                    status,
                    headers: out_headers,
                    body: body.to_vec(),
                })
            }
            Err(e) => JailResult::Err(JailErrorDto::new(
                synvoid_ipc::JailErrorCode::ExecutionFailed,
                format!("wasm invoke failed: {e}"),
            )),
        }
    }
}

impl Default for WasmJailService {
    fn default() -> Self {
        Self::new()
    }
}

impl JailHandler for WasmJailService {
    fn handle(&mut self, op: &JailOperation) -> JailResult {
        match op {
            JailOperation::Ping => JailResult::Ok(JailOutput::Pong),
            JailOperation::Shutdown => JailResult::Ok(JailOutput::ShutdownAck),
            JailOperation::WasmLoad {
                module_id,
                digest_sha256_hex,
                wasm_bytes,
                fuel,
                memory_pages,
                timeout_ms,
                capabilities,
            } => self.load(
                module_id,
                digest_sha256_hex,
                wasm_bytes,
                *fuel,
                *memory_pages,
                *timeout_ms,
                capabilities,
            ),
            JailOperation::WasmInvoke {
                module_id,
                method,
                uri,
                headers,
                body,
            } => self.invoke(module_id, method, uri, headers, body),
            JailOperation::WasmUnload { module_id } => {
                if self.modules.remove(module_id).is_some() {
                    JailResult::Ok(JailOutput::WasmUnloaded)
                } else {
                    JailResult::Err(
                        JailError::NotFound("wasm module not loaded".to_string()).to_dto(),
                    )
                }
            }
            // Wrong-kind operations are rejected, never executed.
            JailOperation::YaraLoadRules { .. }
            | JailOperation::YaraScan { .. }
            | JailOperation::YaraUnload { .. } => JailResult::Err(
                JailError::PolicyDenied("yara operation sent to wasm jail".to_string()).to_dto(),
            ),
        }
    }
}
