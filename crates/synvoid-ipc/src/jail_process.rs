//! Jail process supervision: child serve loop, restart policy, and the
//! parent-side [`JailHandle`].
//!
//! Transport is parent-created anonymous stdio pipes (see
//! `architecture/sandbox_jail_protocol.md`): the parent spawns the jail with
//! piped stdin/stdout, the child inherits the descriptors, applies the strict
//! sandbox, then enters [`serve_jail_connection`]. There is no connectable
//! namespace, so peer identity rests on descriptor inheritance.
//!
//! The parent allows at most one in-flight request per jail (no pipelining). A
//! dedicated reader thread demultiplexes the single outstanding response with
//! a deadline; any timeout, mismatch, or framing error quarantines that
//! instance (pipes discarded) and restarts within a bounded budget rather than
//! continuing on a desynchronized stream.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::jail_protocol::*;

// ---------------------------------------------------------------------------
// Child side: request handler trait and serve loop
// ---------------------------------------------------------------------------

/// Workload executor behind the jail boundary. Implementations live with the
/// workload owner (`src/sandbox/wasm_service.rs`, `src/sandbox/yara_service.rs`);
/// this crate only drives the framed loop.
pub trait JailHandler {
    /// Execute one validated operation. Must be total: never panic, never
    /// block unboundedly, never return oversized output (the serve loop
    /// re-validates output bounds before writing).
    fn handle(&mut self, op: &JailOperation) -> JailResult;
}

/// How the serve loop terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeOutcome {
    /// Peer sent `Shutdown`; a `ShutdownAck` was delivered.
    CleanShutdown,
    /// Clean EOF on stdin (parent exited or closed the pipe).
    ConnectionClosed,
    /// Unrecoverable framing/desync error; the child must exit so the parent
    /// restarts a fresh instance.
    ProtocolFatal,
}

/// Run the jail request loop to completion.
///
/// Reads length-delimited [`JailRequest`] frames from `reader`, dispatches
/// validated operations to `handler`, and writes [`JailResponse`] frames to
/// `writer`. Request IDs must be nonzero and strictly increasing; violations
/// are answered with a typed error without breaking stream sync. Malformed
/// frames (bad length, truncated payload, bad postcard) desynchronize the
/// stream, so the loop returns [`ServeOutcome::ProtocolFatal`] and the child
/// exits nonzero — the parent observes EOF and restarts the jail.
pub fn serve_jail_connection<R: Read, W: Write>(
    kind: JailKind,
    reader: &mut R,
    writer: &mut W,
    handler: &mut impl JailHandler,
) -> ServeOutcome {
    tracing::info!(kind = kind.as_str(), "jail serve loop started");
    let mut last_id: u64 = 0;
    loop {
        let payload = match read_frame(reader, JAIL_MAX_FRAME_BYTES) {
            Ok(FrameRead::Frame(payload)) => payload,
            Ok(FrameRead::CleanEof) => {
                tracing::info!(kind = kind.as_str(), "jail parent EOF; exiting");
                return ServeOutcome::ConnectionClosed;
            }
            Err(e) => {
                tracing::warn!(kind = kind.as_str(), error = %e, "jail frame read failed");
                record_jail_failure(&e);
                return ServeOutcome::ProtocolFatal;
            }
        };
        let req = match decode_request(&payload) {
            Ok(req) => req,
            Err(e) => {
                tracing::warn!(kind = kind.as_str(), error = %e, "jail request decode failed");
                record_jail_failure(&e);
                return ServeOutcome::ProtocolFatal;
            }
        };
        if req.id <= last_id {
            tracing::warn!(
                kind = kind.as_str(),
                id = req.id,
                "jail duplicate/non-increasing request id"
            );
            let err =
                JailError::ProtocolViolation("duplicate or non-increasing request id".to_string());
            record_jail_failure(&err);
            // IDs are unusable for sync here only if id == 0, which decode
            // already rejected; echo the offending id so the parent can match
            // the rejection to its outstanding call.
            let response = JailResponse::new(req.id, JailResult::Err(err.to_dto()));
            match encode_response(&response) {
                Ok(frame) => {
                    if write_frame(writer, &frame).is_err() {
                        return ServeOutcome::ProtocolFatal;
                    }
                }
                Err(_) => return ServeOutcome::ProtocolFatal,
            }
            continue;
        }
        last_id = req.id;

        if matches!(req.op, JailOperation::Shutdown) {
            tracing::info!(kind = kind.as_str(), "jail orderly shutdown requested");
            let response = JailResponse::new(req.id, JailResult::Ok(JailOutput::ShutdownAck));
            match encode_response(&response) {
                Ok(frame) => {
                    let _ = write_frame(writer, &frame);
                }
                Err(e) => {
                    tracing::warn!(kind = kind.as_str(), error = %e, "shutdown ack encode failed");
                }
            }
            record_jail_shutdown();
            return ServeOutcome::CleanShutdown;
        }

        record_jail_invocation(kind);
        let result = handler.handle(&req.op);
        // Defense in depth: re-check output bounds even though handlers must.
        let result = match &result {
            JailResult::Ok(JailOutput::WasmResult { body, .. })
                if body.len() > JAIL_MAX_INVOKE_OUTPUT_BYTES =>
            {
                let err = JailError::Oversized("handler output too large".to_string());
                record_jail_failure(&err);
                JailResult::Err(err.to_dto())
            }
            JailResult::Ok(JailOutput::YaraScanResult { matches })
                if matches.len() > JAIL_MAX_MATCHES =>
            {
                let err = JailError::Oversized("handler returned too many matches".to_string());
                record_jail_failure(&err);
                JailResult::Err(err.to_dto())
            }
            _ => result,
        };
        if let JailResult::Err(dto) = &result {
            record_jail_failure(&JailError::from(dto.clone()));
        }
        let response = JailResponse::new(req.id, result);
        match encode_response(&response) {
            Ok(frame) => {
                if write_frame(writer, &frame).is_err() {
                    return ServeOutcome::ProtocolFatal;
                }
            }
            Err(e) => {
                tracing::warn!(kind = kind.as_str(), error = %e, "jail response encode failed");
                return ServeOutcome::ProtocolFatal;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Restart policy (platform-independent, unit-tested)
// ---------------------------------------------------------------------------

/// Bounded restart tracker with exponential backoff. Shared by [`JailHandle`];
/// also unit-testable without spawning processes.
#[derive(Debug)]
pub struct RestartTracker {
    max_restarts: u32,
    base_backoff_ms: u64,
    max_backoff_ms: u64,
    consecutive_failures: u32,
}

impl RestartTracker {
    pub fn new(max_restarts: u32, base_backoff_ms: u64, max_backoff_ms: u64) -> Self {
        Self {
            max_restarts,
            base_backoff_ms: base_backoff_ms.max(1),
            max_backoff_ms: max_backoff_ms.max(1),
            consecutive_failures: 0,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(
            JAIL_MAX_RESTARTS,
            JAIL_RESTART_BASE_BACKOFF_MS,
            JAIL_RESTART_MAX_BACKOFF_MS,
        )
    }

    /// Record a crash/violation. Returns the backoff to sleep before respawn,
    /// or [`JailError::RestartBudgetExhausted`] when the budget is spent.
    pub fn record_failure(&mut self) -> Result<Duration, JailError> {
        if self.consecutive_failures >= self.max_restarts {
            let err = JailError::RestartBudgetExhausted(format!(
                "jail restart budget exhausted after {} restarts",
                self.consecutive_failures
            ));
            record_jail_failure(&err);
            return Err(err);
        }
        let shift = self.consecutive_failures.min(8);
        let backoff_ms = self
            .base_backoff_ms
            .saturating_mul(1u64 << shift)
            .min(self.max_backoff_ms);
        self.consecutive_failures += 1;
        Ok(Duration::from_millis(backoff_ms))
    }

    /// Record a successful call; resets the consecutive-failure count so
    /// intermittent crashes over a long uptime do not exhaust the budget.
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    pub fn restarts_used(&self) -> u32 {
        self.consecutive_failures
    }
}

// ---------------------------------------------------------------------------
// Parent side: spawn spec and handle
// ---------------------------------------------------------------------------

/// How to spawn a jail child. Argv carries only the mode flag — never
/// secrets, digests, or payloads.
#[derive(Debug, Clone)]
pub struct JailSpawnSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    /// Extra environment for the child. Argv/env carry no secrets or
    /// payloads; tests use this solely for the sandbox hatch.
    pub env: Vec<(String, String)>,
    pub kind: JailKind,
}

impl JailSpawnSpec {
    /// Spawn spec for the current executable (`synvoid --wasm-jail` etc.).
    pub fn current_exe(kind: JailKind) -> std::io::Result<Self> {
        let program = std::env::current_exe()?;
        Ok(Self {
            program,
            args: vec![kind.cli_flag().to_string()],
            env: Vec::new(),
            kind,
        })
    }
}

/// Parent-side configuration for a jail handle.
#[derive(Debug, Clone)]
pub struct JailHandleConfig {
    pub call_timeout: Duration,
    pub shutdown_grace: Duration,
    pub max_restarts: u32,
    pub base_backoff_ms: u64,
    pub max_backoff_ms: u64,
}

impl Default for JailHandleConfig {
    fn default() -> Self {
        Self {
            call_timeout: Duration::from_millis(JAIL_DEFAULT_CALL_TIMEOUT_MS),
            shutdown_grace: Duration::from_millis(JAIL_SHUTDOWN_GRACE_MS),
            max_restarts: JAIL_MAX_RESTARTS,
            base_backoff_ms: JAIL_RESTART_BASE_BACKOFF_MS,
            max_backoff_ms: JAIL_RESTART_MAX_BACKOFF_MS,
        }
    }
}

struct StampedResponse {
    generation: u64,
    id: u64,
    outcome: Result<JailResponse, JailError>,
}

struct JailChild {
    child: Child,
    stdin: Option<ChildStdin>,
    reader: Option<JoinHandle<()>>,
}

/// Supervised handle to one jail process.
///
/// At most one request is in flight at a time; concurrent `call` invocations
/// are serialized internally. Any timeout, ID mismatch, framing error, or
/// unexpected child exit quarantines the instance (pipes discarded) and
/// restarts within the bounded budget. When the budget is exhausted the handle
/// fails closed with [`JailError::RestartBudgetExhausted`].
pub struct JailHandle {
    spec: JailSpawnSpec,
    config: JailHandleConfig,
    state: Mutex<JailHandleState>,
    shutting_down: AtomicBool,
    next_id: AtomicU64,
    generation: AtomicU64,
}

struct JailHandleState {
    child: Option<JailChild>,
    responses: Option<mpsc::Receiver<StampedResponse>>,
    tracker: RestartTracker,
    restarts: u64,
}

impl std::fmt::Debug for JailHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JailHandle")
            .field("kind", &self.spec.kind)
            .field("shutting_down", &self.shutting_down.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl JailHandle {
    /// Spawn and handshake a supervised jail. The handshake is a `Ping`
    /// (version-checked); failure fails closed without retrying here so the
    /// caller sees [`JailError::HandshakeFailed`] or [`JailError::ChildExited`].
    pub fn spawn(spec: JailSpawnSpec, config: JailHandleConfig) -> Result<Self, JailError> {
        let tracker = RestartTracker::new(
            config.max_restarts,
            config.base_backoff_ms,
            config.max_backoff_ms,
        );
        let handle = Self {
            spec,
            config,
            state: Mutex::new(JailHandleState {
                child: None,
                responses: None,
                tracker,
                restarts: 0,
            }),
            shutting_down: AtomicBool::new(false),
            next_id: AtomicU64::new(1),
            generation: AtomicU64::new(0),
        };
        handle.start_child()?;
        // Version handshake: the first Ping must Pong.
        match handle.call_inner(&JailOperation::Ping, handle.config.call_timeout, true) {
            Ok(JailOutput::Pong) => {
                tracing::info!(
                    kind = handle.spec.kind.as_str(),
                    "jail handshake established"
                );
                Ok(handle)
            }
            Ok(other) => {
                let err = JailError::HandshakeFailed(format!(
                    "jail handshake unexpected output: {other:?}"
                ));
                record_jail_failure(&err);
                handle.terminate();
                Err(err)
            }
            Err(e) => {
                // Preserve precise terminal errors (e.g. an exhausted restart
                // budget from the handshake call's own recovery attempt)
                // instead of nesting them inside another handshake wrapper.
                let err = match e {
                    JailError::RestartBudgetExhausted(_)
                    | JailError::HandshakeFailed(_)
                    | JailError::ChildExited(_) => e,
                    _ => JailError::HandshakeFailed(format!("jail handshake failed: {e}")),
                };
                record_jail_failure(&err);
                handle.terminate();
                Err(err)
            }
        }
    }

    pub fn kind(&self) -> JailKind {
        self.spec.kind
    }

    /// Total restarts performed by this handle.
    pub fn restart_count(&self) -> u64 {
        self.state.lock().map(|s| s.restarts).unwrap_or(0)
    }

    /// Whether the child process is currently alive (non-blocking probe).
    pub fn is_alive(&self) -> bool {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return false,
        };
        match state.child.as_mut() {
            Some(child) => matches!(child.child.try_wait(), Ok(None)),
            None => false,
        }
    }

    /// Execute one operation with the configured deadline.
    pub fn call(&self, op: &JailOperation) -> Result<JailOutput, JailError> {
        let timeout = self.config.call_timeout;
        self.call_inner(op, timeout, true)
    }

    /// Execute one operation with an explicit deadline.
    pub fn call_with_timeout(
        &self,
        op: &JailOperation,
        timeout: Duration,
    ) -> Result<JailOutput, JailError> {
        self.call_inner(op, timeout, true)
    }

    fn call_inner(
        &self,
        op: &JailOperation,
        timeout: Duration,
        check_shutdown: bool,
    ) -> Result<JailOutput, JailError> {
        if check_shutdown && self.shutting_down.load(Ordering::SeqCst) {
            return Err(JailError::Unavailable(
                "jail handle is shutting down".to_string(),
            ));
        }
        op.validate()?;
        // Restart a dead child before taking the call lock. (The call lock
        // below serializes requests; this probe uses its own short lock so
        // the restart path never re-locks while holding the call lock.)
        self.ensure_running()?;
        // Serialize calls: at most one in-flight request per jail.
        let mut state = self
            .state
            .lock()
            .map_err(|_| JailError::Unavailable("jail handle lock poisoned".to_string()))?;
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        if id == u64::MAX {
            return Err(JailError::Unavailable(
                "jail request id space exhausted".to_string(),
            ));
        }
        let generation = self.generation.load(Ordering::SeqCst);
        let request = JailRequest::new(id, op.clone());
        let frame = encode_request(&request)?;
        let started = Instant::now();
        {
            let child = state
                .child
                .as_mut()
                .ok_or_else(|| JailError::Unavailable("jail child missing".to_string()))?;
            let stdin = child
                .stdin
                .as_mut()
                .ok_or_else(|| JailError::Unavailable("jail stdin closed".to_string()))?;
            if let Err(e) = write_frame(stdin, &frame) {
                record_jail_failure(&JailError::ChildExited(format!("stdin write: {e}")));
                drop(state);
                self.quarantine_and_restart()?;
                return Err(JailError::ChildExited(format!(
                    "jail stdin write failed: {e}"
                )));
            }
        }
        let receiver = state
            .responses
            .as_ref()
            .ok_or_else(|| JailError::Unavailable("jail response channel missing".to_string()))?;
        let remaining = timeout.saturating_sub(started.elapsed());
        match receiver.recv_timeout(remaining) {
            Ok(stamped) => {
                if stamped.generation != generation {
                    drop(state);
                    let err =
                        JailError::ProtocolViolation("stale jail response generation".to_string());
                    record_jail_failure(&err);
                    self.quarantine_and_restart()?;
                    return Err(err);
                }
                if stamped.id != id {
                    drop(state);
                    let err = JailError::ProtocolViolation(
                        "jail response id mismatch (late response after deadline?)".to_string(),
                    );
                    record_jail_failure(&err);
                    self.quarantine_and_restart()?;
                    return Err(err);
                }
                match stamped.outcome {
                    Ok(response) => match response.result {
                        JailResult::Ok(output) => {
                            state.tracker.record_success();
                            record_jail_invocation(self.spec.kind);
                            Ok(output)
                        }
                        JailResult::Err(dto) => {
                            let err = JailError::from(dto);
                            // Workload errors (trap, compile, not-found) do not
                            // desynchronize the stream: no restart.
                            let desync = !matches!(
                                err.code(),
                                JailErrorCode::ExecutionFailed
                                    | JailErrorCode::NotFound
                                    | JailErrorCode::DigestMismatch
                                    | JailErrorCode::Oversized
                                    | JailErrorCode::PolicyDenied
                                    | JailErrorCode::ResourceExhausted
                            );
                            record_jail_failure(&err);
                            if desync {
                                drop(state);
                                self.quarantine_and_restart()?;
                            } else {
                                state.tracker.record_success();
                            }
                            Err(err)
                        }
                    },
                    Err(e) => {
                        record_jail_failure(&e);
                        drop(state);
                        // Reader-side failures (EOF, framing) mean the child is
                        // gone or the stream desynced: restart within budget.
                        self.quarantine_and_restart()?;
                        Err(e)
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                drop(state);
                let err = JailError::Timeout(format!(
                    "jail call exceeded {}ms; instance quarantined",
                    timeout.as_millis()
                ));
                record_jail_failure(&err);
                // A late response may still arrive: quarantine (never reuse
                // this stream) and restart rather than risk desync.
                let _ = self.quarantine_and_restart();
                Err(err)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                drop(state);
                let err = JailError::ChildExited("jail response channel disconnected".to_string());
                record_jail_failure(&err);
                self.quarantine_and_restart()?;
                Err(err)
            }
        }
    }

    /// Deterministic shutdown: stop new calls, best-effort `Shutdown` request
    /// within a short grace, then terminate and reap. Never leaves the child
    /// behind. Idempotent.
    pub fn shutdown(&self) {
        if self.shutting_down.swap(true, Ordering::SeqCst) {
            return;
        }
        // Best-effort orderly shutdown (bypasses the shutdown gate set
        // below); ignore the result — termination below is unconditional.
        let _ = self.call_inner(
            &JailOperation::Shutdown,
            Duration::from_millis(JAIL_SHUTDOWN_GRACE_MS.min(500)),
            false,
        );
        self.terminate();
        record_jail_shutdown();
        tracing::info!(kind = self.spec.kind.as_str(), "jail handle shut down");
    }

    fn terminate(&self) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return,
        };
        if let Some(mut child) = state.child.take() {
            // Close stdin first so a live child observes EOF promptly.
            drop(child.stdin.take());
            let grace = self.config.shutdown_grace;
            let deadline = Instant::now() + grace;
            loop {
                match child.child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => {
                        if Instant::now() >= deadline {
                            let _ = child.child.kill();
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => {
                        let _ = child.child.kill();
                        break;
                    }
                }
            }
            // Reap unconditionally; ignore the exit status here.
            let _ = child.child.wait();
            record_jail_exit();
            if let Some(reader) = child.reader.take() {
                let _ = reader.join();
            }
        }
        state.responses = None;
    }

    fn start_child(&self) -> Result<(), JailError> {
        let mut cmd = Command::new(&self.spec.program);
        cmd.args(&self.spec.args)
            .envs(self.spec.env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Stderr is the log channel; never parsed. Inherit so jail logs
            // remain visible to the operator.
            .stderr(Stdio::inherit());
        // Never leak caller environment secrets: the child argv/env carries no
        // payload. (Environment itself is inherited; jail-relevant secrets
        // must never be placed in the supervisor environment to begin with —
        // see the protocol doc.)
        let mut child: Child = cmd
            .spawn()
            .map_err(|e| JailError::Unavailable(format!("failed to spawn jail process: {e}")))?;
        let stdin: ChildStdin = child
            .stdin
            .take()
            .ok_or_else(|| JailError::Unavailable("failed to capture jail stdin".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| JailError::Unavailable("failed to capture jail stdout".to_string()))?;
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let (tx, rx) = mpsc::channel::<StampedResponse>();
        let kind = self.spec.kind;
        let reader = std::thread::Builder::new()
            .name(format!("jail-reader-{}", kind.as_str()))
            .spawn(move || {
                reader_loop(generation, stdout, tx);
            })
            .map_err(|e| {
                JailError::Unavailable(format!("failed to spawn jail reader thread: {e}"))
            })?;
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| JailError::Unavailable("jail handle lock poisoned".to_string()))?;
            state.child = Some(JailChild {
                child,
                stdin: Some(stdin),
                reader: Some(reader),
            });
            state.responses = Some(rx);
        }
        record_jail_start();
        tracing::info!(
            kind = self.spec.kind.as_str(),
            program = %self.spec.program.display(),
            "jail child spawned"
        );
        Ok(())
    }

    /// Caller must NOT hold `self.state` when calling this (it re-locks).
    fn quarantine_and_restart(&self) -> Result<(), JailError> {
        self.terminate();
        let backoff = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| JailError::Unavailable("jail handle lock poisoned".to_string()))?;
            let backoff = state.tracker.record_failure()?;
            state.restarts += 1;
            backoff
        };
        record_jail_restart();
        tracing::warn!(
            kind = self.spec.kind.as_str(),
            backoff_ms = backoff.as_millis(),
            "jail instance quarantined; restarting within budget"
        );
        if !backoff.is_zero() {
            std::thread::sleep(backoff);
        }
        self.start_child()?;
        // Re-handshake the fresh instance before handing it out.
        match self.call_inner(&JailOperation::Ping, self.config.call_timeout, false) {
            Ok(JailOutput::Pong) => Ok(()),
            Ok(other) => Err(JailError::HandshakeFailed(format!(
                "restarted jail handshake unexpected output: {other:?}"
            ))),
            Err(e) => Err(JailError::HandshakeFailed(format!(
                "restarted jail handshake failed: {e}"
            ))),
        }
    }

    /// Probe liveness under a short lock and restart a dead child within
    /// budget. Never called while holding the call lock.
    fn ensure_running(&self) -> Result<(), JailError> {
        let alive = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| JailError::Unavailable("jail handle lock poisoned".to_string()))?;
            match state.child.as_mut() {
                Some(child) => match child.child.try_wait() {
                    Ok(None) => true,
                    Ok(Some(_)) => false,
                    Err(_) => false,
                },
                None => false,
            }
        };
        if alive {
            return Ok(());
        }
        // Child died outside a call (or never started post-quarantine):
        // restart within budget.
        self.quarantine_and_restart()?;
        Ok(())
    }
}

impl Drop for JailHandle {
    fn drop(&mut self) {
        self.shutting_down.store(true, Ordering::SeqCst);
        self.terminate();
    }
}

fn reader_loop(
    generation: u64,
    stdout: std::process::ChildStdout,
    tx: mpsc::Sender<StampedResponse>,
) {
    let mut stdout = stdout;
    loop {
        let payload = match read_frame(&mut stdout, JAIL_MAX_FRAME_BYTES) {
            Ok(FrameRead::Frame(payload)) => payload,
            Ok(FrameRead::CleanEof) => {
                let _ = tx.send(StampedResponse {
                    generation,
                    id: 0,
                    outcome: Err(JailError::ChildExited(
                        "jail child closed stdout".to_string(),
                    )),
                });
                return;
            }
            Err(e) => {
                let _ = tx.send(StampedResponse {
                    generation,
                    id: 0,
                    outcome: Err(e),
                });
                return;
            }
        };
        match decode_response(&payload) {
            Ok(response) => {
                let id = response.id;
                let done = matches!(response.result, JailResult::Ok(JailOutput::ShutdownAck));
                let _ = tx.send(StampedResponse {
                    generation,
                    id,
                    outcome: Ok(response),
                });
                if done {
                    return;
                }
            }
            Err(e) => {
                let _ = tx.send(StampedResponse {
                    generation,
                    id: 0,
                    outcome: Err(e),
                });
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_tracker_backoff_grows_and_caps() {
        let mut tracker = RestartTracker::new(5, 100, 500);
        assert_eq!(
            tracker.record_failure().unwrap(),
            Duration::from_millis(100)
        );
        assert_eq!(
            tracker.record_failure().unwrap(),
            Duration::from_millis(200)
        );
        assert_eq!(
            tracker.record_failure().unwrap(),
            Duration::from_millis(400)
        );
        // Capped at max.
        assert_eq!(
            tracker.record_failure().unwrap(),
            Duration::from_millis(500)
        );
        assert_eq!(
            tracker.record_failure().unwrap(),
            Duration::from_millis(500)
        );
        // Budget spent after 5 restarts.
        let err = tracker.record_failure().unwrap_err();
        assert!(matches!(err, JailError::RestartBudgetExhausted(_)));
        assert_eq!(err.code(), JailErrorCode::RestartBudgetExhausted);
    }

    #[test]
    fn restart_tracker_success_resets_budget() {
        let mut tracker = RestartTracker::new(2, 10, 100);
        tracker.record_failure().unwrap();
        tracker.record_failure().unwrap();
        assert!(tracker.record_failure().is_err());
        tracker.record_success();
        assert_eq!(tracker.consecutive_failures(), 0);
        // Budget is usable again after a healthy period.
        assert!(tracker.record_failure().is_ok());
    }

    struct StubHandler {
        fail_ids: Vec<u64>,
    }

    impl JailHandler for StubHandler {
        fn handle(&mut self, op: &JailOperation) -> JailResult {
            match op {
                JailOperation::Ping => JailResult::Ok(JailOutput::Pong),
                _ => JailResult::Err(
                    JailError::NotFound("stub: nothing loaded".to_string()).to_dto(),
                ),
            }
        }
    }

    /// Drive the serve loop over an in-memory duplex pair. std has no portable
    /// duplex pipe, so tests use loopback TCP (framing is transport-agnostic).
    fn loopback_pair() -> (std::net::TcpStream, std::net::TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    fn send_request(stream: &mut impl Write, id: u64, op: JailOperation) {
        let frame = encode_request(&JailRequest::new(id, op)).unwrap();
        write_frame(stream, &frame).unwrap();
    }

    fn recv_response(stream: &mut impl Read) -> JailResponse {
        match read_frame(stream, JAIL_MAX_FRAME_BYTES).unwrap() {
            FrameRead::Frame(payload) => decode_response(&payload).unwrap(),
            FrameRead::CleanEof => panic!("expected response frame"),
        }
    }

    #[test]
    fn serve_loop_ping_shutdown_round_trip() {
        let (mut parent, child) = loopback_pair();
        let mut child_reader = child.try_clone().unwrap();
        let mut child_writer = child;
        let server = std::thread::spawn(move || {
            let mut handler = StubHandler { fail_ids: vec![] };
            serve_jail_connection(
                JailKind::Wasm,
                &mut child_reader,
                &mut child_writer,
                &mut handler,
            )
        });
        send_request(&mut parent, 1, JailOperation::Ping);
        let res = recv_response(&mut parent);
        assert_eq!(res.id, 1);
        assert_eq!(res.result, JailResult::Ok(JailOutput::Pong));

        send_request(&mut parent, 2, JailOperation::Shutdown);
        let res = recv_response(&mut parent);
        assert_eq!(res.result, JailResult::Ok(JailOutput::ShutdownAck));
        assert_eq!(server.join().unwrap(), ServeOutcome::CleanShutdown);
    }

    #[test]
    fn serve_loop_rejects_duplicate_ids_without_desync() {
        let (mut parent, child) = loopback_pair();
        let mut child_reader = child.try_clone().unwrap();
        let mut child_writer = child;
        let server = std::thread::spawn(move || {
            let mut handler = StubHandler { fail_ids: vec![] };
            serve_jail_connection(
                JailKind::Yara,
                &mut child_reader,
                &mut child_writer,
                &mut handler,
            )
        });
        send_request(&mut parent, 5, JailOperation::Ping);
        assert_eq!(
            recv_response(&mut parent).result,
            JailResult::Ok(JailOutput::Pong)
        );
        // Duplicate id: typed rejection, stream stays usable.
        send_request(&mut parent, 5, JailOperation::Ping);
        let res = recv_response(&mut parent);
        assert!(matches!(res.result, JailResult::Err(_)));
        send_request(&mut parent, 6, JailOperation::Ping);
        assert_eq!(
            recv_response(&mut parent).result,
            JailResult::Ok(JailOutput::Pong)
        );
        send_request(&mut parent, 7, JailOperation::Shutdown);
        recv_response(&mut parent);
        assert_eq!(server.join().unwrap(), ServeOutcome::CleanShutdown);
    }

    #[test]
    fn serve_loop_eof_reports_connection_closed() {
        let (parent, child) = loopback_pair();
        drop(parent);
        let mut child_reader = child.try_clone().unwrap();
        let mut child_writer = child;
        let mut handler = StubHandler { fail_ids: vec![] };
        assert_eq!(
            serve_jail_connection(
                JailKind::Wasm,
                &mut child_reader,
                &mut child_writer,
                &mut handler
            ),
            ServeOutcome::ConnectionClosed
        );
    }

    #[test]
    fn serve_loop_malformed_frame_is_fatal() {
        let (mut parent, child) = loopback_pair();
        let mut child_reader = child.try_clone().unwrap();
        let mut child_writer = child;
        let server = std::thread::spawn(move || {
            let mut handler = StubHandler { fail_ids: vec![] };
            serve_jail_connection(
                JailKind::Wasm,
                &mut child_reader,
                &mut child_writer,
                &mut handler,
            )
        });
        // Garbage bytes that fail postcard decode: stream desyncs, child exits.
        let garbage = b"definitely not a valid jail frame payload";
        let mut raw = Vec::new();
        raw.extend_from_slice(&(garbage.len() as u32).to_be_bytes());
        raw.extend_from_slice(garbage);
        parent.write_all(&raw).unwrap();
        parent.flush().unwrap();
        assert_eq!(server.join().unwrap(), ServeOutcome::ProtocolFatal);
    }

    #[test]
    fn serve_loop_unknown_version_is_fatal_not_hang() {
        // A version mismatch cannot be answered on-stream (envelope rejected
        // at decode), so the child must exit rather than hang.
        let (mut parent, child) = loopback_pair();
        let mut child_reader = child.try_clone().unwrap();
        let mut child_writer = child;
        let server = std::thread::spawn(move || {
            let mut handler = StubHandler { fail_ids: vec![] };
            serve_jail_connection(
                JailKind::Wasm,
                &mut child_reader,
                &mut child_writer,
                &mut handler,
            )
        });
        let mut req = JailRequest::new(1, JailOperation::Ping);
        req.version = 99;
        // encode_request refuses; hand-encode to simulate a future peer.
        let payload = synvoid_utils::serialization::serialize(&req).unwrap();
        let mut raw = Vec::new();
        raw.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        raw.extend_from_slice(&payload);
        parent.write_all(&raw).unwrap();
        parent.flush().unwrap();
        assert_eq!(server.join().unwrap(), ServeOutcome::ProtocolFatal);
    }
}
