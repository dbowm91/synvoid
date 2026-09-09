//! Policy-gated jail call sites (parent side).
//!
//! [`JailClient`] routes WASM/YARA work through supervised jail handles
//! according to [`synvoid_ipc::IsolationPolicy`]. Migration is incremental:
//! production defaults to in-process execution and each call site opts into
//! jail routing explicitly. The single decision point is
//! [`synvoid_ipc::resolve_route`]; this module adds handle ownership and the
//! shared header-encoding helper used identically by the jail service and by
//! in-process comparison paths.
//!
//! Fallback rule: [`synvoid_ipc::IsolationPolicy::Preferred`] with
//! `fallback_in_process: true` is only safe where the call site documents the
//! fallback (YARA detection scans, fail-open response transforms). Fail-closed
//! request filtering must use `Required` or `Preferred { fallback: false }`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use synvoid_ipc::{
    IsolationPolicy, JailError, JailHandle, JailHandleConfig, JailKind, JailOperation, JailOutput,
    JailRoute, JailSpawnSpec, JAIL_MAX_HEADERS, JAIL_MAX_HEADER_NAME_LEN,
    JAIL_MAX_HEADER_VALUE_LEN,
};

/// Encode guest header pairs to the JSON object string the `handle_request`
/// ABI expects (same encoding as the in-process serverless path: duplicate
/// names collapse last-wins). Used by the jail WASM service and by
/// in-process comparison harnesses so both paths observe identical input.
pub fn headers_to_guest_json(headers: &[(String, String)]) -> Result<String, JailError> {
    if headers.len() > JAIL_MAX_HEADERS {
        return Err(JailError::Oversized("too many headers".to_string()));
    }
    let mut map: HashMap<&str, &str> = HashMap::with_capacity(headers.len());
    for (name, value) in headers {
        if name.is_empty()
            || name.len() > JAIL_MAX_HEADER_NAME_LEN
            || value.len() > JAIL_MAX_HEADER_VALUE_LEN
        {
            return Err(JailError::Oversized(
                "header name/value length out of bounds".to_string(),
            ));
        }
        map.insert(name.as_str(), value.as_str());
    }
    serde_json::to_string(&map)
        .map_err(|e| JailError::FramingError(format!("header encoding failed: {e}")))
}

/// Policy plus supervised handles for both jail kinds.
pub struct JailClient {
    wasm_policy: IsolationPolicy,
    yara_policy: IsolationPolicy,
    wasm: Option<JailHandle>,
    yara: Option<JailHandle>,
}

impl JailClient {
    /// Spawn supervised jails for both kinds. Any spawn/handshake failure
    /// fails closed with the typed error (no partial client).
    pub fn spawn(
        program: PathBuf,
        wasm_policy: IsolationPolicy,
        yara_policy: IsolationPolicy,
        config: JailHandleConfig,
    ) -> Result<Self, JailError> {
        let wasm = JailHandle::spawn(
            JailSpawnSpec {
                program: program.clone(),
                args: vec![JailKind::Wasm.cli_flag().to_string()],
                env: Vec::new(),
                kind: JailKind::Wasm,
            },
            config.clone(),
        )?;
        let yara = JailHandle::spawn(
            JailSpawnSpec {
                program,
                args: vec![JailKind::Yara.cli_flag().to_string()],
                env: Vec::new(),
                kind: JailKind::Yara,
            },
            config,
        )?;
        Ok(Self {
            wasm_policy,
            yara_policy,
            wasm: Some(wasm),
            yara: Some(yara),
        })
    }

    /// Build a client over already-spawned handles (tests, custom supervision).
    pub fn from_handles(
        wasm_policy: IsolationPolicy,
        yara_policy: IsolationPolicy,
        wasm: Option<JailHandle>,
        yara: Option<JailHandle>,
    ) -> Self {
        Self {
            wasm_policy,
            yara_policy,
            wasm,
            yara,
        }
    }

    pub fn wasm_route(&self) -> JailRoute {
        synvoid_ipc::resolve_route(
            self.wasm_policy,
            self.wasm.as_ref().is_some_and(|h| h.is_alive()),
        )
    }

    pub fn yara_route(&self) -> JailRoute {
        synvoid_ipc::resolve_route(
            self.yara_policy,
            self.yara.as_ref().is_some_and(|h| h.is_alive()),
        )
    }

    /// Execute a WASM jail operation. Fails with [`JailError::Unavailable`]
    /// when no live WASM handle exists — callers must consult
    /// [`JailClient::wasm_route`] first so `Required` policy fails closed
    /// instead of erroring ambiguously.
    pub fn call_wasm(&self, op: &JailOperation) -> Result<JailOutput, JailError> {
        self.call_wasm_with_timeout(op, None)
    }

    pub fn call_wasm_with_timeout(
        &self,
        op: &JailOperation,
        timeout: Option<Duration>,
    ) -> Result<JailOutput, JailError> {
        let handle = self.wasm.as_ref().ok_or_else(|| {
            JailError::Unavailable("no wasm jail handle; failing closed".to_string())
        })?;
        match timeout {
            Some(t) => handle.call_with_timeout(op, t),
            None => handle.call(op),
        }
    }

    /// Execute a YARA jail operation (same availability contract as WASM).
    pub fn call_yara(&self, op: &JailOperation) -> Result<JailOutput, JailError> {
        let handle = self.yara.as_ref().ok_or_else(|| {
            JailError::Unavailable("no yara jail handle; failing closed".to_string())
        })?;
        handle.call(op)
    }

    /// Deterministic shutdown of both handles (reaps children).
    pub fn shutdown(&self) {
        if let Some(handle) = self.wasm.as_ref() {
            handle.shutdown();
        }
        if let Some(handle) = self.yara.as_ref() {
            handle.shutdown();
        }
    }
}
