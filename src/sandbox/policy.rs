//! Policy-gated jail call sites (parent side).
//!
//! [`JailClient`] routes WASM/YARA work through supervised jail handles
//! according to [`synvoid_ipc::IsolationPolicy`]. Migration is incremental:
//! production defaults to in-process execution and each call site opts into
//! jail routing explicitly. The single decision point is
//! [`synvoid_ipc::resolve_route`]; this module adds handle ownership.
//!
//! Header encoding (`headers_to_guest_json`) is canonically owned by
//! `synvoid-jail-runtime` (Phase 29) and re-exported here for in-process
//! comparison harnesses so both paths observe identical input.
//!
//! Binary resolution: production call sites should use
//! [`JailClient::spawn_resolved`] (dedicated `synvoid-*-jail` binaries via
//! exe-dir lookup, no CWD/PATH search). [`JailClient::spawn`] is retained for
//! hermetic tests that pass an explicit program path.
//!
//! Fallback rule: [`synvoid_ipc::IsolationPolicy::Preferred`] with
//! `fallback_in_process: true` is only safe where the call site documents the
//! fallback (YARA detection scans, fail-open response transforms). Fail-closed
//! request filtering must use `Required` or `Preferred { fallback: false }`.

use std::path::PathBuf;
use std::time::Duration;

use synvoid_ipc::{
    IsolationPolicy, JailError, JailHandle, JailHandleConfig, JailKind, JailOperation, JailOutput,
    JailRoute, JailSpawnSpec,
};

/// Canonical header encoder re-export (owner: `synvoid-jail-runtime`).
pub use synvoid_jail_runtime::headers_to_guest_json;

/// Policy plus supervised handles for both jail kinds.
pub struct JailClient {
    wasm_policy: IsolationPolicy,
    yara_policy: IsolationPolicy,
    wasm: Option<JailHandle>,
    yara: Option<JailHandle>,
}

impl JailClient {
    /// Spawn supervised jails for both kinds from an explicit program path.
    /// Any spawn/handshake failure fails closed with the typed error (no
    /// partial client). Tests use this with `CARGO_BIN_EXE_synvoid` or the
    /// dedicated binaries; production should prefer [`JailClient::spawn_resolved`].
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

    /// Spawn supervised jails via deterministic dedicated-binary resolution
    /// (Phase 29 Part C): `synvoid-wasm-jail` / `synvoid-yara-jail` beside
    /// the current executable when installed, otherwise the legacy compat
    /// fallback. Never searches CWD, `PATH`, or writable plugin dirs.
    /// Any spawn/handshake failure fails closed (no partial client).
    pub fn spawn_resolved(
        wasm_policy: IsolationPolicy,
        yara_policy: IsolationPolicy,
        config: JailHandleConfig,
    ) -> Result<Self, JailError> {
        let wasm = JailHandle::spawn(
            synvoid_ipc::resolved_jail_spawn_spec(JailKind::Wasm, Vec::new()),
            config.clone(),
        )?;
        let yara = JailHandle::spawn(
            synvoid_ipc::resolved_jail_spawn_spec(JailKind::Yara, Vec::new()),
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
