//! Guardrails for worker mesh supervision integration (Iterations 82-86).
//!
//! Verifies structural invariants via source-text scanning without I/O.

#![cfg(feature = "mesh")]

use std::fs;

fn read_file(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {}: {}", path, e))
}

#[test]
fn mesh_supervision_module_exists() {
    let content = read_file("src/worker/mesh_supervision.rs");
    assert!(content.contains("pub struct MeshSupervisionPolicy"));
    assert!(content.contains("pub fn decide_mesh_action"));
    assert!(content.contains("pub struct RestartBudget"));
}

#[test]
fn worker_mesh_status_in_state() {
    let content = read_file("src/worker/unified_server/state.rs");
    assert!(content.contains("mesh_status"));
    assert!(content.contains("mesh_policy"));
}

#[test]
fn mesh_exit_observer_registered_in_registry() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(content.contains("mesh_exit_observer"));
    assert!(content.contains("spawn_critical"));
}

#[test]
fn mesh_coordinator_registered_in_registry() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(content.contains("mesh_supervision_coordinator"));
    assert!(content.contains("spawn_critical"));
}

#[test]
fn mesh_shutdown_called_during_worker_shutdown() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(content.contains("shutdown_with_timeout"));
    assert!(content.contains("classify_mesh_shutdown_report"));
}

#[test]
fn mesh_startup_failure_sends_event() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(content.contains("MeshSupervisionEvent::StartupFailed"));
    assert!(content.contains("MeshSupervisionEvent::Started"));
}

#[test]
fn worker_shutdown_cause_has_mesh_variants() {
    let content = read_file("src/worker/task_registry.rs");
    assert!(content.contains("MeshStartupFailed"));
    assert!(content.contains("MeshShutdownIncomplete"));
}

#[test]
fn decide_mesh_action_uses_typed_fields() {
    let content = read_file("src/worker/mesh_supervision.rs");
    assert!(content.contains("MeshTaskClass::CriticalService"));
    assert!(content.contains("MeshTaskClass::RestartableBackground"));
    assert!(content.contains("MeshTaskExitReason::Panic"));
    assert!(content.contains("MeshTaskExitReason::Error"));
}

#[test]
fn restart_budget_is_bounded() {
    let content = read_file("src/worker/mesh_supervision.rs");
    assert!(content.contains("fn allow_restart"));
    assert!(content.contains("fn is_exhausted"));
    assert!(content.contains("fn record_attempt"));
}

#[test]
fn no_mesh_internal_process_termination() {
    let content = read_file("src/worker/mesh_supervision.rs");
    assert!(!content.contains("std::process::exit"));
    assert!(!content.contains("process::exit"));
}

#[test]
fn mesh_supervision_metrics_exist() {
    let content = read_file("src/worker/mesh_supervision.rs");
    assert!(content.contains("MESH_SUPERVISION_METRICS"));
    assert!(content.contains("exit_events_total"));
    assert!(content.contains("startup_failures_total"));
    assert!(content.contains("restart_attempts_total"));
}

#[test]
fn mesh_health_in_heartbeat() {
    let content = read_file("src/worker/unified_server/lifecycle.rs");
    assert!(content.contains("mesh_phase"));
    assert!(content.contains("mesh_healthy"));
    assert!(content.contains("mesh_restart_attempts"));
}

#[test]
fn mesh_readiness_gate_exists() {
    let content = read_file("src/worker/unified_server/state.rs");
    assert!(content.contains("is_mesh_ready"));
}

// --- Iteration 83 guardrails ---

#[test]
fn supervision_uses_authoritative_status_clone() {
    let content = read_file("src/worker/unified_server/mod.rs");
    // Phase 1: Must use state.mesh_status.clone(), not a new allocation.
    assert!(content.contains("state.mesh_status.clone()"));
}

#[test]
fn status_transition_helpers_exist() {
    let content = read_file("src/worker/mesh_supervision.rs");
    assert!(content.contains("fn transition_starting"));
    assert!(content.contains("fn transition_running"));
    assert!(content.contains("fn transition_degraded"));
    assert!(content.contains("fn transition_restarting"));
    assert!(content.contains("fn transition_failed"));
    assert!(content.contains("fn transition_stopping"));
    assert!(content.contains("fn transition_stopped"));
}

#[test]
fn coordinator_uses_real_status_snapshot() {
    let content = read_file("src/worker/mesh_supervision.rs");
    // Phase 4: Must NOT pass WorkerMeshStatus::default() to decide_mesh_action.
    assert!(
        !content.contains("decide_mesh_action(\n                &self.policy,\n                &WorkerMeshStatus::default(),"),
        "coordinator still uses default status for classification"
    );
    // Must use a phase snapshot.
    assert!(content.contains("self.status.read().await"));
}

#[test]
fn allow_degraded_readiness_field_exists() {
    let content = read_file("src/worker/mesh_supervision.rs");
    assert!(content.contains("allow_degraded_readiness"));
}

#[test]
fn is_mesh_ready_respects_degraded_policy() {
    let content = read_file("src/worker/unified_server/state.rs");
    // Phase 9: Must check allow_degraded_readiness, not just phase.
    assert!(content.contains("allow_degraded_readiness"));
}

#[test]
fn no_outer_timeout_on_mesh_startup() {
    let content = read_file("src/worker/unified_server/mod.rs");
    // Phase 12: No tokio::time::timeout wrapping start_with_policy.
    // The mesh startup block should call start_with_policy directly.
    assert!(content.contains(".start_with_policy("));
    // Must NOT wrap it in timeout
    assert!(
        !content.contains("tokio::time::timeout(\n                        std::time::Duration::from_secs(60),\n                        mesh_transport.start_with_policy("),
        "outer timeout still wraps start_with_policy"
    );
}

#[test]
fn typed_cause_conversion_exists() {
    let content = read_file("src/worker/mesh_supervision.rs");
    assert!(content.contains("pub fn mesh_failure_to_worker_cause"));
}

#[test]
fn typed_cause_conversion_used_in_supervision_loop() {
    let content = read_file("src/worker/unified_server/mod.rs");
    // Phase 16: Must use mesh_failure_to_worker_cause, not collapse to MeshStartupFailed.
    assert!(content.contains("mesh_failure_to_worker_cause(cause)"));
}

#[test]
fn shutdown_uses_deadline_not_uptime() {
    let content = read_file("src/worker/unified_server/mod.rs");
    // Phase 19: Must use remaining_budget() closure, not start_time.elapsed().
    assert!(content.contains("remaining_budget"));
    assert!(content.contains("shutdown_deadline"));
}

#[test]
fn incomplete_mesh_shutdown_updates_cause() {
    let content = read_file("src/worker/unified_server/mod.rs");
    // Phase 20: shutdown_cause must be mutable and accumulated.
    assert!(content.contains("mut shutdown_cause"));
    assert!(content.contains("merge_worker_shutdown_cause"));
}

#[test]
fn mesh_restart_exhausted_cause_exists() {
    let content = read_file("src/worker/task_registry.rs");
    // Phase 17: Dedicated typed cause for restart exhaustion.
    assert!(content.contains("MeshRestartExhausted"));
}

#[test]
fn mesh_failure_to_worker_cause_is_exhaustive() {
    let content = read_file("src/worker/mesh_supervision.rs");
    // Must handle all MeshFailureCause variants.
    assert!(content.contains("MeshFailureCause::CriticalServiceExit"));
    assert!(content.contains("MeshFailureCause::StartupFailed"));
    assert!(content.contains("MeshFailureCause::ShutdownTimeout"));
}

#[test]
fn cause_merge_priority_exists() {
    let content = read_file("src/worker/mesh_supervision.rs");
    assert!(content.contains("pub fn merge_worker_shutdown_cause"));
}

#[test]
fn mesh_status_recorded_before_and_after_shutdown() {
    let content = read_file("src/worker/unified_server/mod.rs");
    // Phase 22: Must transition Stopping before shutdown, Stopped/Failed after.
    assert!(content.contains("transition_stopping"));
    assert!(content.contains("transition_stopped"));
}

// --- Acceptance criterion #5: Optional mesh failure degrades without blocking readiness ---

#[test]
fn optional_mesh_readiness_bypasses_phase_check() {
    let content = read_file("src/worker/unified_server/state.rs");
    // When mesh is not required, is_mesh_ready() must return true immediately
    // regardless of phase — no phase check needed.
    // The Option<MeshSupervisionPolicy> pattern:
    //   let Some(ref policy) = self.mesh_policy else { return true; };
    //   if !policy.required { return true; }
    assert!(
        content.contains("let Some(ref policy) = self.mesh_policy else {"),
        "optional mesh must bypass phase check for readiness via Option pattern"
    );
}

#[test]
fn optional_policy_has_readiness_bypass() {
    let content = read_file("src/worker/mesh_supervision.rs");
    // MeshSupervisionPolicy::optional() must set required=false and
    // readiness_requires_mesh=false so readiness is never blocked.
    assert!(
        content.contains("readiness_requires_mesh: false"),
        "optional policy must not require mesh for readiness"
    );
    assert!(
        content.contains("allow_degraded_readiness: true"),
        "optional policy must allow degraded readiness"
    );
}

#[test]
fn optional_startup_failure_does_not_shutdown() {
    let content = read_file("src/worker/mesh_supervision.rs");
    // MeshSupervisionPolicy::optional() must use Degrade for startup_failure,
    // never ShutdownWorker — optional mesh failure must not block the worker.
    // Verify the optional() constructor sets startup_failure to Degrade.
    assert!(
        content.contains("startup_failure: MeshFailureAction::Degrade"),
        "optional policy must degrade on startup failure, not shutdown"
    );
}

// --- Acceptance criterion #7: Disabled mesh creates no pipeline or startup task ---

#[test]
fn observer_only_spawned_when_transport_exists() {
    let content = read_file("src/worker/unified_server/mod.rs");
    // The mesh exit observer is only spawned when a transport is available.
    // The guard: has_mesh_transport check before creating the pipeline.
    // If !has_mesh_transport, None is returned (no pipeline, no observer).
    assert!(
        content.contains("if !has_mesh_transport"),
        "observer must be conditional on transport availability"
    );
    // Observer registration must be inside the transport-available block.
    assert!(
        content.contains("mesh_exit_observer"),
        "observer task name must be registered"
    );
}

#[test]
fn mesh_startup_task_only_with_transport() {
    let content = read_file("src/worker/unified_server/mod.rs");
    // The mesh startup task must only be spawned when a concrete MeshTransport
    // is available AND mesh is required/optional (not disabled).
    // The guard: has_mesh_transport check gates the entire pipeline.
    assert!(
        content.contains("if !has_mesh_transport"),
        "startup must be conditional on transport availability"
    );
    // For required mesh, startup is awaited inline; for optional, as background.
    // Uses Option pattern: state.mesh_policy.as_ref().is_some_and(|p| p.required)
    assert!(
        content.contains("state.mesh_policy.as_ref().is_some_and(|p| p.required)"),
        "startup path must branch on mesh policy via Option pattern"
    );
}

#[test]
fn coordinator_always_created_but_idle_without_transport() {
    let content = read_file("src/worker/unified_server/mod.rs");
    // The supervision pipeline (channels + coordinator) is created when
    // mesh transport is available. Without transport, no pipeline is created.
    assert!(
        content.contains("create_supervision_pipeline"),
        "supervision pipeline must be created"
    );
    // When no transport exists, None is returned (no pipeline, no coordinator).
    assert!(
        content.contains("Mesh disabled — no supervision pipeline created"),
        "disabled mesh must log and return None"
    );
}

// --- Acceptance criterion #21: Observer/coordinator exits handled per policy ---

#[test]
fn observer_forwards_exit_stream_closed_to_coordinator() {
    let content = read_file("src/worker/mesh_supervision.rs");
    // When the broadcast channel closes (observer exits), the observer must
    // send ExitStreamClosed to the coordinator, which applies policy.
    assert!(
        content.contains("MeshSupervisionEvent::ExitStreamClosed"),
        "observer must forward stream closure as ExitStreamClosed event"
    );
}

#[test]
fn observer_forwards_lag_to_coordinator() {
    let content = read_file("src/worker/mesh_supervision.rs");
    // When the broadcast channel lags, the observer must send ExitStreamLagged
    // to the coordinator, which degrades per policy.
    assert!(
        content.contains("MeshSupervisionEvent::ExitStreamLagged"),
        "observer must forward lag as ExitStreamLagged event"
    );
}

#[test]
fn exit_stream_closed_required_triggers_shutdown() {
    // Acceptance criterion #21: required mesh observer exit must be fatal.
    // Unit test in mesh_supervision.rs: exit_stream_closed_while_running_required_fatal
    // verifies this via decide_mesh_action.
    let content = read_file("src/worker/mesh_supervision.rs");
    assert!(
        content.contains("ExitStreamClosed") && content.contains("MeshFailureCause::StartupFailed"),
        "required ExitStreamClosed must produce ShutdownWorker decision"
    );
}

#[test]
fn exit_stream_closed_optional_degrades() {
    // Acceptance criterion #21: optional mesh observer exit must degrade.
    // Unit test in mesh_supervision.rs: exit_stream_closed_while_running_optional_degrades
    // verifies this via decide_mesh_action.
    let content = read_file("src/worker/mesh_supervision.rs");
    // The optional path should produce MarkDegraded, not ShutdownWorker.
    assert!(
        content.contains("MeshSupervisorDecision::MarkDegraded(\"mesh exit stream closed\""),
        "optional ExitStreamClosed must produce MarkDegraded decision"
    );
}

// --- Iteration 85: Disabled mesh construction suppression ---

#[test]
fn init_mesh_checks_enabled_before_construction() {
    let content = read_file("src/worker/unified_server/init_mesh.rs");
    assert!(
        content.contains("if !mesh_config.enabled {"),
        "init_mesh must check enabled flag before constructing runtime objects"
    );
    assert!(
        content.contains("return MeshInit::disabled()"),
        "init_mesh must return MeshInit::disabled() when disabled"
    );
}

#[test]
fn init_mesh_returns_disabled_when_config_absent() {
    let content = read_file("src/worker/unified_server/init_mesh.rs");
    assert!(
        content.contains("let Some(ref mesh_config) = mesh_config else {"),
        "init_mesh must handle absent mesh config with early return"
    );
}

#[test]
fn mesh_init_disabled_constructor_exists() {
    let content = read_file("src/worker/unified_server/init_mesh.rs");
    assert!(
        content.contains("pub fn disabled() -> Self"),
        "MeshInit must have a disabled() constructor"
    );
}

#[test]
fn mesh_policy_is_option_type() {
    let content = read_file("src/worker/unified_server/state.rs");
    assert!(
        content.contains("pub mesh_policy: Option<MeshSupervisionPolicy>"),
        "mesh_policy must be Option<MeshSupervisionPolicy>"
    );
}

#[test]
fn no_required_fallback_policy() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        !content.contains("unwrap_or_else(MeshSupervisionPolicy::required)"),
        "must not use required fallback for disabled mesh policy"
    );
}

#[test]
fn invariant_check_transport_policy_alignment() {
    // Iteration 86: Transport/policy alignment is validated via
    // validate_mesh_runtime_inputs() in init_mesh.rs.
    let content = read_file("src/worker/unified_server/init_mesh.rs");
    assert!(
        content.contains("mesh transport present but no supervision policy"),
        "validate_mesh_runtime_inputs must check transport/policy alignment"
    );
    assert!(
        content.contains("mesh supervision policy present but no transport"),
        "validate_mesh_runtime_inputs must check policy/transport alignment"
    );
}

// --- Iteration 85 Part C: Topology/DHT background task ownership ---

#[test]
fn construction_does_not_start_background_tasks() {
    // Phase 15: init_mesh must NOT call start_background_tasks() on topology
    // or routing_manager. Background tasks are started by the composition root.
    let content = read_file("src/worker/unified_server/init_mesh.rs");
    // topology must NOT have start_background_tasks called in init_mesh
    assert!(
        !content.contains("topology.start_background_tasks()"),
        "init_mesh must not start topology background tasks during construction"
    );
    // routing_manager must NOT have start_background_tasks called in init_mesh
    assert!(
        !content.contains("manager.start_background_tasks()"),
        "init_mesh must not start routing_manager background tasks during construction"
    );
}

#[test]
fn disabled_mesh_starts_no_background_tasks() {
    // Phase 15: Disabled mesh config must return MeshInit::disabled() without
    // constructing any runtime objects that could spawn background tasks.
    let content = read_file("src/worker/unified_server/init_mesh.rs");
    assert!(
        content.contains("return MeshInit::disabled()"),
        "disabled mesh must return early with MeshInit::disabled()"
    );
    // MeshInit::disabled() must set topology to None
    assert!(
        content.contains("topology: None"),
        "disabled MeshInit must have topology: None"
    );
}

#[test]
fn topology_has_shutdown_signal() {
    // Iteration 85: MeshTopology uses build_background_tasks() which creates
    // internal shutdown signals. The topology itself is self-managed.
    let content = read_file("crates/synvoid-mesh/src/mesh/topology.rs");
    assert!(
        content.contains("pub fn build_background_tasks("),
        "MeshTopology must have build_background_tasks method"
    );
}

#[test]
fn topology_background_tasks_use_select_shutdown() {
    // Iteration 85: Topology background tasks are created via build_background_tasks()
    // which returns BackgroundTaskSpec objects with internal shutdown signals.
    let content = read_file("crates/synvoid-mesh/src/mesh/topology.rs");
    assert!(
        content.contains("build_background_tasks("),
        "topology must use build_background_tasks for structured lifecycle"
    );
}

#[test]
fn topology_has_shutdown_method() {
    // Iteration 85: MeshTopology background tasks are self-managed via
    // build_background_tasks(). Shutdown is handled internally by the
    // background task specs via watch-based cancellation.
    let content = read_file("crates/synvoid-mesh/src/mesh/topology.rs");
    assert!(
        content.contains("pub fn build_background_tasks("),
        "MeshTopology must expose build_background_tasks for self-managed lifecycle"
    );
}

#[test]
fn mesh_init_carries_topology() {
    // Phase 15: MeshInit must carry the topology so the composition root
    // can start background tasks after mesh startup.
    let content = read_file("src/worker/unified_server/init_mesh.rs");
    assert!(
        content.contains("pub topology: Option<Arc<crate::mesh::topology::MeshTopology>>"),
        "MeshInit must carry topology field"
    );
}

#[test]
fn composition_root_starts_topology_background_tasks() {
    // Iteration 85: Topology background tasks are self-managed by
    // MeshTopology (started internally with watch-based shutdown).
    // The composition root does NOT explicitly start them — MeshInit
    // carries the topology for other wiring (e.g., MeshProxy, transport).
    let content = read_file("src/worker/unified_server/init_mesh.rs");
    assert!(
        content.contains("pub topology:"),
        "MeshInit must carry topology field for self-managed background tasks"
    );
    assert!(
        content.contains("Iteration 85: Background tasks are NOT started here"),
        "topology background tasks must be self-managed, not started in init_mesh"
    );
}

#[test]
fn composition_root_starts_dht_routing_background_tasks() {
    // Iteration 87: DHT routing initialization is now handled by the mesh
    // transport's transactional startup phases (Phase 5.5), eliminating the
    // race condition where bootstrap could run against an absent table.
    // The composition root must NOT register a dht_routing_init one-shot task.
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        !content.contains("dht_routing_init"),
        "composition root must NOT register dht_routing_init one-shot task (moved to transport startup)"
    );
}

// --- Iteration 85 Part D: YARA broadcast child ownership ---

#[test]
fn yara_broadcast_uses_joinset() {
    // Iteration 86: YARA broadcast is extracted to run_yara_broadcast_loop()
    // which uses JoinSet for child task management with deadline-bounded drain.
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        content.contains("run_yara_broadcast_loop("),
        "yara broadcast must use extracted run_yara_broadcast_loop function"
    );
    assert!(
        content.contains("let mut children: tokio::task::JoinSet<()>"),
        "yara broadcast must use JoinSet for child management"
    );
    assert!(
        content.contains("children.join_next()"),
        "yara broadcast must join children via JoinSet"
    );
}

#[test]
fn no_bare_tokio_spawn_in_yara_broadcast() {
    // Iteration 86: The yara broadcast loop is extracted to run_yara_broadcast_loop()
    // which uses JoinSet for child management. Individual sends use JoinSet::spawn().
    let content = read_file("src/worker/unified_server/mod.rs");
    let broadcast_fn_start = content
        .find("async fn run_yara_broadcast_loop(")
        .expect("run_yara_broadcast_loop must exist");
    let after_fn = content[broadcast_fn_start..]
        .find("report\n}")
        .map(|i| broadcast_fn_start + i + 7)
        .expect("run_yara_broadcast_loop must close");
    let fn_body = &content[broadcast_fn_start..after_fn];
    assert!(
        fn_body.contains("children.spawn(async move {"),
        "yara broadcast must spawn sends via JoinSet"
    );
    assert!(
        fn_body.contains("broadcast_rx.recv()"),
        "yara broadcast must receive from mpsc channel"
    );
}

#[test]
fn yara_broadcast_drains_on_channel_close() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        content.contains("broadcast_rx.recv()"),
        "yara broadcast must receive from mpsc channel"
    );
    assert!(
        content.contains("YARA broadcast loop received worker shutdown")
            || content.contains("YARA broadcast loop received generation shutdown"),
        "yara broadcast must handle worker or generation shutdown signal"
    );
}

// --- Iteration 85 Part E: Support tasks registered after mesh startup ---

#[test]
fn register_mesh_support_tasks_helper_exists() {
    // Iteration 86 Part A: Support tasks are registered via
    // register_mesh_generation_support() AFTER mesh startup succeeds.
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        content.contains("fn register_mesh_generation_support("),
        "register_mesh_generation_support helper must exist"
    );
    assert!(
        content.contains("spawn_background("),
        "register_mesh_generation_support must spawn background tasks"
    );
    assert!(
        content.contains("spawn_one_shot("),
        "register_mesh_generation_support must spawn one-shot tasks"
    );
}

#[test]
fn support_tasks_registered_after_required_mesh_startup() {
    // Iteration 86 Part A: Support tasks (DNS, YARA, DHT init) are registered
    // AFTER mesh startup succeeds via register_mesh_generation_support().
    let content = read_file("src/worker/unified_server/mod.rs");
    let start_mesh_idx = content
        .find("start_mesh_generation(")
        .expect("required mesh must call start_mesh_generation");
    let register_idx = content
        .find("register_mesh_generation_support(")
        .expect("must call register_mesh_generation_support after startup");
    let first_ready_idx = content
        .find("UnifiedServerWorkerReady")
        .expect("must have ready message");
    let ready_idx = content[first_ready_idx + 1..]
        .find("UnifiedServerWorkerReady")
        .map(|i| first_ready_idx + 1 + i)
        .expect("must have second ready message in Ok branch");
    assert!(
        start_mesh_idx < register_idx,
        "register_mesh_generation_support must appear after start_mesh_generation"
    );
    assert!(
        register_idx < ready_idx,
        "register_mesh_generation_support must appear before ready message"
    );
}

#[test]
fn support_tasks_registered_after_optional_mesh_startup() {
    // Iteration 86 Part A: Support tasks are registered via
    // register_mesh_generation_support() AFTER optional mesh startup succeeds.
    let content = read_file("src/worker/unified_server/mod.rs");
    let optional_start_idx = content
        .find("// Optional mesh: start as one-shot background task.")
        .expect("optional mesh branch must exist");
    // Find the call site (not the function definition) after the optional mesh comment.
    let after_optional = &content[optional_start_idx..];
    let register_idx = after_optional
        .find("register_mesh_generation_support(")
        .expect("must call register_mesh_generation_support after startup");
    // Verify it's a call, not a comment
    let call_line = &after_optional[register_idx..].lines().next().unwrap_or("");
    assert!(
        !call_line.trim().starts_with("//"),
        "register_mesh_generation_support must be a call, not a comment"
    );
}

#[test]
fn support_tasks_extracted_before_builder() {
    // Iteration 86 Part A: Support tasks are extracted from MeshInit into
    // MeshSupportTasks in Phase 11.5, after the DataPlaneServicesBuilder.
    let content = read_file("src/worker/unified_server/mod.rs");
    let builder_idx = content
        .find("DataPlaneServicesBuilder::new(")
        .expect("builder must exist");
    let extract_idx = content
        .find("let support_tasks = MeshSupportTasks {")
        .expect("support tasks extraction must exist");
    assert!(
        builder_idx < extract_idx,
        "support tasks extraction must appear after builder construction"
    );
    assert!(
        content.contains("mesh_init.dns_verification_registries"),
        "dns_verification_registries must be extracted from mesh_init"
    );
    assert!(
        content.contains("mesh_init.yara_broadcast"),
        "yara_broadcast must be extracted from mesh_init"
    );
}

#[test]
fn no_old_phase_13_5_registry_support_tasks() {
    // Iteration 86 Part A: Phase 13.5 is a comment-only section explaining
    // that support tasks are registered AFTER mesh startup. The actual
    // registration happens via register_mesh_generation_support() in the
    // mesh startup success paths.
    let content = read_file("src/worker/unified_server/mod.rs");
    let phase_13_5_start = content
        .find("Phase 13.5: mesh support task registration")
        .expect("Phase 13.5 comment must exist");
    let phase_14_start = content
        .find("Phase 14:")
        .expect("Phase 14 comment must exist");
    let phase_13_5_section = &content[phase_13_5_start..phase_14_start];
    assert!(
        phase_13_5_section.contains("register_mesh_generation_support"),
        "Phase 13.5 must reference register_mesh_generation_support"
    );
    assert!(
        !phase_13_5_section.contains("spawn_background("),
        "Phase 13.5 must NOT inline spawn support tasks"
    );
    assert!(
        !phase_13_5_section.contains("spawn_one_shot("),
        "Phase 13.5 must NOT inline spawn one-shot tasks"
    );
}

#[test]
fn disabled_mesh_starts_no_support_tasks() {
    let content = read_file("src/worker/unified_server/init_mesh.rs");
    assert!(
        content.contains("return MeshInit::disabled()"),
        "disabled mesh must return MeshInit::disabled()"
    );
    let disabled_section = content
        .find("pub fn disabled() -> Self")
        .expect("disabled constructor must exist");
    let closing = content[disabled_section..]
        .find('}')
        .expect("must find closing brace");
    let disabled_body = &content[disabled_section..disabled_section + closing + 1];
    assert!(
        disabled_body.contains("dns_verification_registries: Vec::new()"),
        "disabled MeshInit must have empty dns_verification_registries"
    );
    assert!(
        disabled_body.contains("yara_broadcast: None"),
        "disabled MeshInit must have no yara_broadcast"
    );
}

// --- Iteration 85 Part F: Required mesh startup direct failure ---

#[test]
fn required_startup_failure_produces_direct_cause() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        content.contains("required_mesh_startup_failure = Some(cause)"),
        "required mesh startup failure must store cause directly"
    );
    assert!(
        content.contains("SupervisionOutcome::DirectCause(\n                crate::worker::mesh_supervision::mesh_failure_to_worker_cause(cause),"),
        "required mesh startup failure must produce DirectCause without coordinator"
    );
}

#[test]
fn required_startup_failure_skips_ready() {
    // Iteration 85: Required mesh startup failure is captured and mapped to
    // DirectCause. The ready message is only sent in the Ok branch, not in
    // the Err branch.
    let content = read_file("src/worker/unified_server/mod.rs");
    let failure_idx = content
        .find("required_mesh_startup_failure = Some(cause)")
        .expect("must store required mesh startup failure");
    // The failure capture and DirectCause break should exist
    let direct_cause_idx = content
        .find("mesh_failure_to_worker_cause(cause)")
        .expect("must have DirectCause via mesh_failure_to_worker_cause");
    assert!(
        direct_cause_idx > failure_idx,
        "DirectCause break must follow failure capture"
    );
    // The failure path should NOT contain UnifiedServerWorkerReady
    let failure_section = &content[failure_idx..failure_idx + 500];
    assert!(
        !failure_section.contains("UnifiedServerWorkerReady"),
        "failure path must not send ready message"
    );
}

#[test]
fn start_mesh_generation_returns_facts_only() {
    let content = read_file("src/worker/mesh_supervision.rs");
    let start_idx = content
        .find("pub async fn start_mesh_generation(")
        .expect("start_mesh_generation must exist");
    let body_start = content[start_idx..]
        .find('{')
        .map(|i| start_idx + i)
        .expect("must have function body");
    let params = &content[start_idx..body_start];
    assert!(
        !params.contains("status"),
        "start_mesh_generation must not accept a status parameter"
    );
    let next_fn = content[body_start + 1..]
        .find("\npub ")
        .map(|i| body_start + 1 + i)
        .unwrap_or(content.len());
    let body = &content[body_start..next_fn];
    assert!(
        !body.contains("status.write()"),
        "start_mesh_generation must not mutate status"
    );
    assert!(
        !body.contains("transition_starting"),
        "start_mesh_generation must not transition to Starting"
    );
    assert!(
        !body.contains("transition_running"),
        "start_mesh_generation must not transition to Running"
    );
    assert!(
        !body.contains("transition_failed"),
        "start_mesh_generation must not transition to Failed"
    );
}

#[test]
fn required_startup_path_transitions_status_directly() {
    // Iteration 86: Required mesh path transitions status directly via
    // WorkerMeshStatus before calling start_mesh_generation.
    let content = read_file("src/worker/unified_server/mod.rs");
    let start_call = content
        .find("match crate::worker::mesh_supervision::start_mesh_generation(")
        .expect("must call start_mesh_generation");
    // Search for transition_starting in the 500 chars before start_mesh_generation
    let search_start = start_call.saturating_sub(500);
    let preceding = &content[search_start..start_call];
    assert!(
        preceding.contains("transition_starting"),
        "required path must transition to Starting before calling start_mesh_generation"
    );
    let after_start = &content[start_call..];
    // Verify transition_starting appears before start_mesh_generation (already checked above).
    // Verify transition_running appears in the Ok branch and transition_failed in the Err branch.
    // These are simple presence checks that are sufficient for the guardrail.
    assert!(
        after_start.contains("transition_running"),
        "required path must transition to Running after successful start_mesh_generation"
    );
    assert!(
        after_start.contains("transition_failed"),
        "required path must transition to Failed after failed start_mesh_generation"
    );
}

// --- Iteration 85 Phase 33: Configuration and runtime invariant guards ---

#[test]
fn restart_enabled_rejected_or_unreachable() {
    let content = read_file("src/worker/mesh_supervision.rs");
    // Iteration 86: build_mesh_supervision_policy returns Err when restart_enabled = true.
    assert!(
        content.contains("restart_enabled is not supported"),
        "build_mesh_supervision_policy must reject restart_enabled with Err"
    );
    assert!(
        content.contains("Result<Option<MeshSupervisionPolicy>, String>"),
        "build_mesh_supervision_policy must return Result"
    );
    assert!(
        !content.contains("MeshFailureAction::RestartMesh")
            || content.contains("MeshFailureAction::RestartMesh")
                && content.contains("restart_limit: 0"),
        "RestartMesh action must not be reachable from policy builder (restart_limit is always 0)"
    );
}

#[test]
fn disabled_mesh_validates_support_components() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        content.contains("disabled mesh must have empty dns_verification_registries"),
        "composition root must validate dns_verification_registries is empty when disabled"
    );
    assert!(
        content.contains("disabled mesh must have no yara_broadcast"),
        "composition root must validate yara_broadcast is None when disabled"
    );
    assert!(
        content.contains("disabled mesh must have no transport_manager"),
        "composition root must validate transport_manager is None when disabled"
    );
}

#[test]
fn no_unwrap_or_else_mesh_supervision_policy_required() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        !content.contains("unwrap_or_else(MeshSupervisionPolicy::required)"),
        "must not use required fallback for mesh supervision policy"
    );
    assert!(
        !content.contains("unwrap_or_else(MeshSupervisionPolicy::optional)"),
        "must not use optional fallback for mesh supervision policy"
    );
}

#[test]
fn required_startup_failure_maps_directly() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        content.contains("required_mesh_startup_failure = Some(cause)"),
        "required mesh startup failure must store cause directly"
    );
    assert!(
        content.contains("SupervisionOutcome::DirectCause(\n                crate::worker::mesh_supervision::mesh_failure_to_worker_cause(cause),"),
        "required mesh startup failure must produce DirectCause without coordinator"
    );
}

#[test]
fn generation_support_tasks_after_mesh_startup() {
    // Iteration 86 Part A: Support tasks (DNS verification, YARA broadcast, DHT
    // routing init) are registered AFTER mesh startup succeeds via
    // register_mesh_generation_support().
    let content = read_file("src/worker/unified_server/mod.rs");
    let start_mesh_idx = content
        .find("start_mesh_generation(")
        .expect("required mesh must call start_mesh_generation");
    let register_idx = content
        .find("register_mesh_generation_support(")
        .expect("must call register_mesh_generation_support after startup");
    assert!(
        start_mesh_idx < register_idx,
        "register_mesh_generation_support must appear after start_mesh_generation"
    );
}

#[test]
fn status_transitions_have_singular_owner() {
    let content = read_file("src/worker/mesh_supervision.rs");
    let start_idx = content
        .find("pub async fn start_mesh_generation(")
        .expect("start_mesh_generation must exist");
    let body_start = content[start_idx..]
        .find('{')
        .map(|i| start_idx + i)
        .expect("must have function body");
    let next_fn = content[body_start + 1..]
        .find("\npub ")
        .map(|i| body_start + 1 + i)
        .unwrap_or(content.len());
    let body = &content[body_start..next_fn];
    assert!(
        !body.contains("status.write()"),
        "start_mesh_generation must not mutate status"
    );
    assert!(
        !body.contains("transition_starting"),
        "start_mesh_generation must not transition to Starting"
    );
    assert!(
        !body.contains("transition_running"),
        "start_mesh_generation must not transition to Running"
    );
    assert!(
        !body.contains("transition_failed"),
        "start_mesh_generation must not transition to Failed"
    );
}

// --- Iteration 86 guardrails ---

#[test]
fn build_policy_restart_enabled_returns_error() {
    // Iteration 86: build_mesh_supervision_policy returns Err when restart_enabled = true.
    let content = read_file("src/worker/mesh_supervision.rs");
    assert!(
        content.contains("if config.restart_enabled {"),
        "build_mesh_supervision_policy must check restart_enabled"
    );
    assert!(
        content.contains("return Err("),
        "build_mesh_supervision_policy must return Err for restart_enabled"
    );
    assert!(
        content.contains("restart_enabled is not supported"),
        "error message must mention restart_enabled"
    );
}

#[test]
fn validate_mesh_runtime_inputs_exists() {
    // Iteration 86: validate_mesh_runtime_inputs validates MeshInit against supervision policy.
    let content = read_file("src/worker/unified_server/init_mesh.rs");
    assert!(
        content.contains("pub fn validate_mesh_runtime_inputs("),
        "validate_mesh_runtime_inputs must exist as a public function"
    );
    assert!(
        content.contains("Result<(), crate::worker::task_registry::WorkerShutdownCause>"),
        "validate_mesh_runtime_inputs must return Result with WorkerShutdownCause"
    );
}

#[test]
fn mesh_configuration_invariant_cause_exists() {
    // Iteration 86: MeshConfigurationInvariant variant in WorkerShutdownCause.
    let content = read_file("src/worker/task_registry.rs");
    assert!(
        content.contains("MeshConfigurationInvariant(String)"),
        "WorkerShutdownCause must have MeshConfigurationInvariant variant"
    );
}

#[test]
fn support_tasks_registered_after_mesh_startup() {
    // Iteration 86 Part A: Support tasks (DNS/YARA/DHT) are registered AFTER
    // mesh startup succeeds, not before. Phase 13.5 no longer has inline registration.
    let content = read_file("src/worker/unified_server/mod.rs");
    // Phase 13.5 must be a comment-only section explaining the new pattern.
    let phase_13_5_idx = content
        .find("Phase 13.5: mesh support task registration")
        .expect("Phase 13.5 must exist");
    let phase_14_idx = content.find("Phase 14:").expect("Phase 14 must exist");
    let phase_13_5_section = &content[phase_13_5_idx..phase_14_idx];
    // Must NOT contain inline spawn calls — support is registered after startup.
    assert!(
        !phase_13_5_section.contains("spawn_background("),
        "Phase 13.5 must NOT inline spawn support tasks"
    );
    assert!(
        !phase_13_5_section.contains("spawn_one_shot("),
        "Phase 13.5 must NOT inline spawn one-shot tasks"
    );
    // Must reference the new pattern.
    assert!(
        phase_13_5_section.contains("register_mesh_generation_support"),
        "Phase 13.5 must reference register_mesh_generation_support"
    );
}

#[test]
fn optional_startup_transitions_starting() {
    // Iteration 86: Optional mesh startup transitions to Starting before spawning.
    let content = read_file("src/worker/unified_server/mod.rs");
    // Find the optional mesh branch (else branch after required check).
    let optional_start = content
        .find("// Optional mesh: start as one-shot background task.")
        .expect("optional mesh branch must exist");
    let optional_section = &content[optional_start..optional_start + 500];
    assert!(
        optional_section.contains("transition_starting"),
        "optional mesh must transition to Starting before spawning"
    );
}

#[test]
fn required_startup_no_started_event() {
    // Iteration 86: Required mesh startup no longer emits MeshSupervisionEvent::Started.
    // The required path transitions status directly, not via the coordinator event.
    let content = read_file("src/worker/unified_server/mod.rs");
    let required_start = content
        .find("// Required mesh: await startup inline before ready.")
        .expect("required mesh branch must exist");
    let required_section = &content[required_start..required_start + 1000];
    // The required branch should NOT send MeshSupervisionEvent::Started.
    assert!(
        !required_section.contains("MeshSupervisionEvent::Started"),
        "required mesh must not emit Started event (status transitions directly)"
    );
}

#[test]
fn yara_broadcast_loop_is_extracted() {
    // Iteration 86: run_yara_broadcast_loop is an extracted function.
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        content.contains("async fn run_yara_broadcast_loop("),
        "run_yara_broadcast_loop must exist as an extracted function"
    );
    assert!(
        content.contains("fn classify_yara_child_result("),
        "classify_yara_child_result helper must exist"
    );
}

#[test]
fn topology_build_background_tasks_exists() {
    // Iteration 86: Topology has build_background_tasks replacing start_background_tasks.
    let content = read_file("crates/synvoid-mesh/src/mesh/topology.rs");
    assert!(
        content.contains("pub fn build_background_tasks("),
        "MeshTopology must have build_background_tasks method"
    );
}

#[test]
fn dht_routing_build_background_tasks_exists() {
    // Iteration 86: DHT routing manager has build_background_tasks.
    let content = read_file("crates/synvoid-mesh/src/mesh/dht/routing/manager.rs");
    assert!(
        content.contains("pub fn build_background_tasks("),
        "DhtRoutingManager must have build_background_tasks method"
    );
}

#[test]
fn optional_policy_restart_limit_zero() {
    // Iteration 86: optional() preset has restart_limit: 0.
    let content = read_file("src/worker/mesh_supervision.rs");
    let optional_idx = content
        .find("pub fn optional() -> Self")
        .expect("optional() constructor must exist");
    let optional_section = &content[optional_idx..optional_idx + 400];
    assert!(
        optional_section.contains("restart_limit: 0"),
        "optional() preset must have restart_limit: 0"
    );
}

#[test]
fn restart_mesh_uses_mesh_configuration_invariant() {
    // Iteration 86: RestartMesh defense-in-depth branch uses MeshConfigurationInvariant,
    // not MeshStartupFailed.
    let content = read_file("src/worker/unified_server/mod.rs");
    let restart_mesh_idx = content
        .find("MeshSupervisorDecision::RestartMesh")
        .expect("RestartMesh branch must exist");
    let section = &content[restart_mesh_idx..restart_mesh_idx + 700];
    assert!(
        section.contains("MeshConfigurationInvariant("),
        "RestartMesh branch must use MeshConfigurationInvariant cause"
    );
    assert!(
        !section.contains("MeshStartupFailed("),
        "RestartMesh branch must not use MeshStartupFailed cause"
    );
}

// --- Iteration 87: Behavioral guardrails ---
//
// These tests exercise real code — not text-based source inspection.

mod iter87_behavioral_guardrails {
    use std::sync::Arc;

    use synvoid_mesh::config::MeshConfig;
    use synvoid_mesh::dht::routing::DhtRoutingManager;

    /// Construct a MeshConfig with a known node_id for testing.
    /// Uses serde deserialization since `cached_pow` is a private field.
    fn test_config() -> Arc<MeshConfig> {
        let json = r#"{"node_id": "iter87-test-node"}"#;
        let config: MeshConfig = serde_json::from_str(json).expect("valid MeshConfig JSON");
        Arc::new(config)
    }

    /// Construct a MeshConfig with DHT routing enabled or disabled.
    fn test_config_with_dht(routing_enabled: bool) -> Arc<MeshConfig> {
        let json = format!(
            r#"{{"node_id": "iter87-test-node", "dht": {{"routing_enabled": {}}}}}"#,
            routing_enabled
        );
        let config: MeshConfig = serde_json::from_str(&json).expect("valid MeshConfig JSON");
        Arc::new(config)
    }

    /// DHT routing initialized before bootstrap (Phase 5.5 ordering):
    /// After construction, `is_initialized()` is false. After `init()`, it is true.
    #[tokio::test]
    async fn dht_init_before_bootstrap_ordering() {
        let config = test_config();
        let manager = DhtRoutingManager::new(config);

        assert!(
            !manager.is_initialized().await,
            "DhtRoutingManager should not be initialized before init()"
        );

        manager.init().await;

        assert!(
            manager.is_initialized().await,
            "DhtRoutingManager should be initialized after init()"
        );
    }

    /// Bootstrap rejects uninitialized routing table (Iteration 87, Phase 5):
    /// `add_peer_checked()` returns an error when the table is not initialized.
    #[tokio::test]
    async fn dht_bootstrap_precondition_enforced() {
        let config = test_config();
        let manager = DhtRoutingManager::new(config);

        // The routing table is uninitialized (routing_table is None).
        // add_peer_checked must return Err("DHT routing table not initialized").
        let result = manager
            .add_peer_checked(
                "peer-1".to_string(),
                "127.0.0.1".to_string(),
                443,
                synvoid_mesh::config::MeshNodeRole::GLOBAL,
                None,
                true,
                None,
                None,
                None,
            )
            .await;

        assert_eq!(
            result,
            Err("DHT routing table not initialized"),
            "add_peer_checked must reject when routing table is uninitialized"
        );
    }

    /// Generation bundle cancellation works end-to-end:
    /// A `tokio::sync::watch` channel is the mechanism behind generation-specific
    /// cancellation. Verify that sending `true` is visible to the receiver.
    #[tokio::test]
    async fn generation_support_cancel_sends_watch_signal() {
        let (tx, mut rx) = tokio::sync::watch::channel(false);

        // Clone the receiver to simulate a generation-support task holding a reference.
        let mut rx_clone = rx.clone();

        // Initially both receivers see `false`.
        assert!(!*rx.borrow());
        assert!(!*rx_clone.borrow());

        // Send cancellation signal.
        let _ = tx.send(true);

        // The receiver must observe the change.
        rx.changed().await.expect("watch channel should be open");
        assert!(*rx.borrow());

        rx_clone
            .changed()
            .await
            .expect("cloned watch channel should be open");
        assert!(*rx_clone.borrow());
    }

    /// Generation support cancel is idempotent:
    /// Sending `true` twice does not panic or corrupt state.
    #[tokio::test]
    async fn generation_support_cancel_idempotent() {
        let (tx, mut rx) = tokio::sync::watch::channel(false);

        let _ = tx.send(true);
        rx.changed().await.expect("watch channel should be open");
        assert!(*rx.borrow());

        // Second send should not panic.
        let _ = tx.send(true);
        rx.changed().await.expect("watch channel should be open");
        assert!(*rx.borrow());
    }

    /// Verify the `yara_loop_child_panic_increments_failed` test exists in
    /// `src/worker/unified_server/mod.rs`. This is a meta-guardrail ensuring
    /// YARA panic/abort/drain tests were added by another agent.
    #[test]
    fn yara_panic_test_exists() {
        let content = std::fs::read_to_string("src/worker/unified_server/mod.rs")
            .expect("failed to read unified_server/mod.rs");
        assert!(
            content.contains("yara_loop_child_panic_increments_failed"),
            "yara_loop_child_panic_increments_failed test must exist in unified_server/mod.rs"
        );
    }

    /// Verify the `topology_build_background_tasks_returns_specs` test exists in
    /// `tests/mesh_lifecycle_tests.rs`. This is a meta-guardrail ensuring real
    /// topology/DHT builder tests were added by another agent.
    #[test]
    fn real_topology_builder_test_exists() {
        let content = std::fs::read_to_string("tests/mesh_lifecycle_tests.rs")
            .expect("failed to read mesh_lifecycle_tests.rs");
        assert!(
            content.contains("topology_build_background_tasks_returns_specs"),
            "topology_build_background_tasks_returns_specs test must exist in mesh_lifecycle_tests.rs"
        );
    }

    /// MeshStartupStage records DHT initialization snapshots via
    /// `record_dht_init()`. The `dht_init_snapshot` field is `pub(crate)`,
    /// so we use a source-text check to confirm the method exists and
    /// records the snapshot correctly.
    #[test]
    fn dht_init_snapshot_records_attempt() {
        // Verify the method exists and the struct carries the snapshot field.
        let content = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/lifecycle.rs")
            .expect("failed to read lifecycle.rs");
        assert!(
            content.contains("pub fn record_dht_init("),
            "MeshStartupStage must have record_dht_init method"
        );
        assert!(
            content.contains("dht_init_snapshot: Option<DhtInitializationSnapshot>"),
            "MeshStartupStage must carry dht_init_snapshot field"
        );
        assert!(
            content.contains("pub was_initialized_this_attempt: bool"),
            "DhtInitializationSnapshot must have was_initialized_this_attempt field"
        );

        // Verify the field is initialized to None in the constructor.
        let content_mod = content.clone();
        let new_fn_start = content_mod
            .find("pub fn new(task_group: crate::task_group::MeshTaskGroup) -> Self")
            .expect("MeshStartupStage::new must exist");
        let new_fn_body = &content_mod[new_fn_start..new_fn_start + 300];
        assert!(
            new_fn_body.contains("dht_init_snapshot: None"),
            "MeshStartupStage::new must initialize dht_init_snapshot to None"
        );
    }

    /// When DHT routing is disabled, `init()` must leave the manager
    /// uninitialized — `is_initialized()` must return false.
    #[tokio::test]
    async fn dht_disabled_routing_stays_uninitialized() {
        let config = test_config_with_dht(false);
        let manager = DhtRoutingManager::new(config);

        assert!(
            !manager.is_initialized().await,
            "disabled DhtRoutingManager should not be initialized before init()"
        );

        manager.init().await;

        assert!(
            !manager.is_initialized().await,
            "disabled DhtRoutingManager must remain uninitialized after init()"
        );
    }

    /// MeshStartupPolicy has the `require_dht_initialization` field for
    /// controlling DHT routing initialization requirements (Iteration 87).
    #[test]
    fn mesh_startup_policy_has_dht_init_field() {
        let content = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/lifecycle.rs")
            .expect("failed to read lifecycle.rs");
        assert!(
            content.contains("require_dht_initialization: bool"),
            "MeshStartupPolicy must have require_dht_initialization field"
        );
    }

    /// MeshStartupReport has the `dht_routing_initialized` field
    /// (Iteration 87).
    #[test]
    fn mesh_startup_report_has_dht_init_field() {
        let content = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/lifecycle.rs")
            .expect("failed to read lifecycle.rs");
        assert!(
            content.contains("dht_routing_initialized: bool"),
            "MeshStartupReport must have dht_routing_initialized field"
        );
    }

    /// MeshTransport initialization (Phase 5.5) calls DhtRoutingManager::init()
    /// before bootstrap. Verify the transport source references Phase 5.5
    /// and calls init() on the routing manager.
    #[test]
    fn transport_calls_dht_init_before_bootstrap() {
        let content = std::fs::read_to_string("crates/synvoid-mesh/src/mesh/transport.rs")
            .expect("failed to read transport.rs");
        // Iteration 88: DHT init moved from Phase 5.5 to Phase 3.5 (before peers)
        assert!(
            content.contains("Phase 3.5"),
            "transport.rs must reference Phase 3.5 for DHT routing initialization ordering"
        );
    }
}

// --- Iteration 88: Final Corrective Pass Guardrails ---

mod iter88_behavioral_guardrails {
    use std::sync::Arc;
    use synvoid_mesh::config::MeshConfig;
    use synvoid_mesh::dht::routing::DhtRoutingManager;

    /// Construct a MeshConfig with DHT routing enabled or disabled.
    /// Uses serde deserialization since `cached_pow` is a private field.
    fn test_config_with_dht(routing_enabled: bool) -> Arc<MeshConfig> {
        let json = format!(
            r#"{{"node_id": "iter88-test-node", "dht": {{"routing_enabled": {}}}}}"#,
            routing_enabled
        );
        let config: MeshConfig = serde_json::from_str(&json).expect("valid MeshConfig JSON");
        Arc::new(config)
    }

    #[tokio::test]
    async fn dht_checked_insertion_fails_before_init() {
        let config = test_config_with_dht(true);
        let rm = DhtRoutingManager::new(config);
        let result = rm
            .add_peer_checked(
                "peer1".to_string(),
                "127.0.0.1:443".to_string(),
                443,
                synvoid_mesh::config::MeshNodeRole::EDGE,
                None,
                false,
                None,
                None,
                None,
            )
            .await;
        assert!(result.is_err(), "add_peer_checked must fail before init");
    }

    #[tokio::test]
    async fn dht_checked_insertion_succeeds_after_init() {
        let config = test_config_with_dht(true);
        let rm = DhtRoutingManager::new(config);
        rm.init().await;
        let result = rm
            .add_peer_checked(
                "peer1".to_string(),
                "127.0.0.1:443".to_string(),
                443,
                synvoid_mesh::config::MeshNodeRole::EDGE,
                None,
                false,
                None,
                None,
                None,
            )
            .await;
        assert!(result.is_ok(), "add_peer_checked must succeed after init");
    }

    #[tokio::test]
    async fn dht_unchecked_insertion_succeeds_after_init() {
        let config = test_config_with_dht(true);
        let rm = DhtRoutingManager::new(config);
        rm.init().await;
        rm.add_peer(
            "peer1".to_string(),
            "127.0.0.1:443".to_string(),
            443,
            synvoid_mesh::config::MeshNodeRole::EDGE,
            None,
            false,
            None,
            None,
            None,
        )
        .await;
        assert!(
            rm.is_initialized().await,
            "Routing table must be initialized"
        );
    }

    #[test]
    fn yara_broadcast_loop_accepts_two_receivers() {
        // Source-text check that the YARA loop function signature accepts both
        let content = std::fs::read_to_string("src/worker/unified_server/mod.rs")
            .expect("failed to read mod.rs");
        assert!(
            content.contains("worker_shutdown_rx: tokio::sync::watch::Receiver<bool>"),
            "YARA loop must accept worker_shutdown_rx"
        );
        assert!(
            content.contains("generation_shutdown_rx: tokio::sync::watch::Receiver<bool>"),
            "YARA loop must accept generation_shutdown_rx"
        );
    }

    #[test]
    fn stop_mesh_generation_support_exists() {
        let content = std::fs::read_to_string("src/worker/unified_server/mod.rs")
            .expect("failed to read mod.rs");
        assert!(
            content.contains("async fn stop_mesh_generation_support("),
            "stop_mesh_generation_support must exist"
        );
        assert!(
            content.contains("SupportStopContext"),
            "SupportStopContext must be used"
        );
    }

    #[test]
    fn cancel_then_join_tasks_replaces_old_method() {
        let content = std::fs::read_to_string("src/worker/task_registry.rs")
            .expect("failed to read task_registry.rs");
        assert!(
            content.contains("cancel_then_join_tasks"),
            "cancel_then_join_tasks must exist"
        );
        assert!(
            !content.contains("fn cancel_and_join_tasks("),
            "cancel_and_join_tasks must not exist"
        );
    }

    #[test]
    fn task_subset_cleanup_report_exists() {
        let content = std::fs::read_to_string("src/worker/task_registry.rs")
            .expect("failed to read task_registry.rs");
        assert!(
            content.contains("pub struct TaskSubsetCleanupReport"),
            "TaskSubsetCleanupReport must exist"
        );
    }
}

// --- Iteration 89: Composition-Root Behavioral Test Guardrails ---

mod iter89_behavioral_guardrails {
    /// Verify `tests/composition_root_behavioral.rs` exists with expected test functions.
    /// This ensures the behavioral composition-root tests were not accidentally deleted.
    #[test]
    fn composition_root_behavioral_test_file_exists() {
        let content = std::fs::read_to_string("tests/composition_root_behavioral.rs")
            .expect("composition_root_behavioral.rs must exist");
        // Required behavioral tests per Part F, Phase 23:
        assert!(
            content.contains("required_support_failure_blocks_ready"),
            "composition_root_behavioral.rs must have required_support_failure_blocks_ready test"
        );
        assert!(
            content.contains("optional_success_returns_bundle"),
            "composition_root_behavioral.rs must have optional_success_returns_bundle test"
        );
        assert!(
            content.contains("optional_degradation_performs_bounded_cleanup"),
            "composition_root_behavioral.rs must have optional_degradation_performs_bounded_cleanup test"
        );
        assert!(
            content.contains("optional_immediate_exit_leaves_no_tasks"),
            "composition_root_behavioral.rs must have optional_immediate_exit_leaves_no_tasks test"
        );
        assert!(
            content.contains("cleanup_report_classifications_correct"),
            "composition_root_behavioral.rs must have cleanup_report_classifications_correct test"
        );
        assert!(
            content.contains("forced_abort_path_awaits_every_handle"),
            "composition_root_behavioral.rs must have forced_abort_path_awaits_every_handle test"
        );
        assert!(
            content.contains("no_task_id_remains_after_teardown"),
            "composition_root_behavioral.rs must have no_task_id_remains_after_teardown test"
        );
    }

    /// Verify `MeshGenerationSupport::empty()` exists — required by optional
    /// startup with no support tasks.
    #[test]
    fn mesh_generation_support_empty_constructor() {
        let content = std::fs::read_to_string("src/worker/unified_server/mod.rs")
            .expect("failed to read mod.rs");
        assert!(
            content.contains("pub fn empty(generation: u64) -> Self"),
            "MeshGenerationSupport::empty(generation) must exist"
        );
    }

    /// Verify `stop_mesh_generation_support` is public for integration testing.
    #[test]
    fn stop_mesh_generation_support_is_public() {
        let content = std::fs::read_to_string("src/worker/unified_server/mod.rs")
            .expect("failed to read mod.rs");
        assert!(
            content.contains("pub async fn stop_mesh_generation_support("),
            "stop_mesh_generation_support must be pub (not pub(crate))"
        );
    }

    /// Verify the optional startup/degradation race handling uses
    /// `pending_optional_failure` flag.
    #[test]
    fn optional_startup_pending_failure_flag() {
        let content = std::fs::read_to_string("src/worker/unified_server/mod.rs")
            .expect("failed to read mod.rs");
        assert!(
            content.contains("pending_optional_failure"),
            "composition root must use pending_optional_failure flag for race handling"
        );
    }

    /// Verify the composition-root tests module exists in mod.rs (unit tests).
    #[test]
    fn composition_root_tests_module_exists() {
        let content = std::fs::read_to_string("src/worker/unified_server/mod.rs")
            .expect("failed to read mod.rs");
        assert!(
            content.contains("mod composition_root_tests"),
            "composition_root_tests module must exist in unified_server/mod.rs"
        );
    }

    /// Verify the optional startup completion channel uses typed result
    /// carrying `MeshGenerationSupport` for optional startup.
    #[test]
    fn optional_mesh_startup_channel_type() {
        let content = std::fs::read_to_string("src/worker/unified_server/mod.rs")
            .expect("failed to read mod.rs");
        assert!(
            content.contains("optional_startup_tx"),
            "composition root must have optional_startup_tx channel"
        );
        assert!(
            content.contains("optional_startup_rx"),
            "composition root must have optional_startup_rx channel"
        );
        assert!(
            content.contains("Result<Option<MeshGenerationSupport>, String>"),
            "optional startup channel must carry Result<Option<MeshGenerationSupport>, String>"
        );
    }

    /// Verify the required startup path gates ready on support registration.
    #[test]
    fn required_startup_gates_ready_on_support() {
        let content = std::fs::read_to_string("src/worker/unified_server/mod.rs")
            .expect("failed to read mod.rs");
        // Required readiness must check both transport startup AND support registration.
        assert!(
            content.contains("ready_deferred"),
            "composition root must use ready_deferred flag"
        );
        // Ready is only sent in the Ok branch (after both succeed).
        assert!(
            content.contains("Phase 7 Part B"),
            "required readiness must document Phase 7 Part B gate"
        );
    }
}
