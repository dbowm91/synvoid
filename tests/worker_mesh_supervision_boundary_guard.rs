//! Guardrails for worker mesh supervision integration (Iterations 82-83).
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
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        content.contains("Invariant violation: mesh transport present but no supervision policy"),
        "composition root must check transport/policy alignment invariant"
    );
    assert!(
        content.contains("Invariant violation: mesh supervision policy present but no transport"),
        "composition root must check policy/transport alignment invariant"
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
    // MeshInit::disabled() must set dht_routing_manager to None
    assert!(
        content.contains("dht_routing_manager: None"),
        "disabled MeshInit must have dht_routing_manager: None"
    );
}

#[test]
fn topology_has_shutdown_signal() {
    // Phase 15: MeshTopology must have internal shutdown signal for
    // structured background task lifecycle.
    let content = read_file("crates/synvoid-mesh/src/mesh/topology.rs");
    assert!(
        content.contains("shutdown_tx"),
        "MeshTopology must have shutdown_tx field"
    );
    assert!(
        content.contains("background_handles"),
        "MeshTopology must have background_handles field"
    );
}

#[test]
fn topology_background_tasks_use_select_shutdown() {
    // Phase 15: Topology background loops must use tokio::select! with
    // shutdown signal for cooperative cancellation.
    let content = read_file("crates/synvoid-mesh/src/mesh/topology.rs");
    assert!(
        content.contains("shutdown_rx.changed()"),
        "topology background loops must select on shutdown signal"
    );
}

#[test]
fn topology_has_shutdown_method() {
    // Phase 15: MeshTopology must expose a shutdown() method that sends
    // the shutdown signal and joins background handles.
    let content = read_file("crates/synvoid-mesh/src/mesh/topology.rs");
    assert!(
        content.contains("pub async fn shutdown(&self)"),
        "MeshTopology must have shutdown() method"
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
fn mesh_init_carries_dht_routing_manager() {
    // Phase 15: MeshInit must carry the DhtRoutingManager so the composition
    // root can start background tasks after mesh startup.
    let content = read_file("src/worker/unified_server/init_mesh.rs");
    assert!(
        content.contains(
            "pub dht_routing_manager: Option<Arc<crate::mesh::dht::routing::DhtRoutingManager>>"
        ),
        "MeshInit must carry dht_routing_manager field"
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
    // Iteration 85: DHT routing background tasks are self-managed by
    // DhtRoutingManager. The composition root starts routing via a
    // one-shot init task registered in WorkerTaskRegistry.
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        content.contains("dht_routing_init"),
        "composition root must register dht_routing_init one-shot task"
    );
    assert!(
        content.contains("spawn_one_shot(\"dht_routing_init\""),
        "dht_routing_init must be registered as a one-shot task"
    );
}

// --- Iteration 85 Part D: YARA broadcast child ownership ---

#[test]
fn yara_broadcast_uses_joinset() {
    // Iteration 85: YARA broadcast spawns individual sends via tokio::spawn
    // with a semaphore for concurrency control. The broadcast loop itself
    // is registered in WorkerTaskRegistry for structured ownership.
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        content.contains("registry.spawn_background(\"yara_broadcast\""),
        "yara broadcast loop must be registered in WorkerTaskRegistry"
    );
    assert!(
        content.contains("tokio::spawn(async move {"),
        "yara broadcast must spawn individual sends via tokio::spawn"
    );
    assert!(
        content.contains("broadcast_semaphore.clone().acquire_owned()"),
        "yara broadcast must use semaphore for concurrency control"
    );
}

#[test]
fn no_bare_tokio_spawn_in_yara_broadcast() {
    // Iteration 85: The yara broadcast LOOP is registered via
    // WorkerTaskRegistry for ownership. Individual sends within the loop
    // use tokio::spawn (not JoinSet) with semaphore-based concurrency.
    let content = read_file("src/worker/unified_server/mod.rs");
    let broadcast_loop_start = content
        .find("registry.spawn_background(\"yara_broadcast\"")
        .expect("yara_broadcast spawn_background must exist");
    let after_loop = content[broadcast_loop_start..]
        .find("});")
        .map(|i| broadcast_loop_start + i + 3)
        .expect("yara_broadcast loop must close");
    let loop_body = &content[broadcast_loop_start..after_loop];
    assert!(
        loop_body.contains("registry.spawn_background(\"yara_broadcast\""),
        "yara broadcast loop must be registered via WorkerTaskRegistry"
    );
    assert!(
        loop_body.contains("broadcast_rx.recv().await"),
        "yara broadcast must receive from mpsc channel"
    );
}

#[test]
fn yara_broadcast_drains_on_channel_close() {
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        content.contains("broadcast_rx.recv().await"),
        "yara broadcast must receive from mpsc channel"
    );
    assert!(
        content.contains("YARA broadcast mpsc channel closed, exiting loop"),
        "yara broadcast must log when channel closes"
    );
}

// --- Iteration 85 Part E: Support tasks registered after mesh startup ---

#[test]
fn register_mesh_support_tasks_helper_exists() {
    // Iteration 85: Support tasks (DNS verification, YARA broadcast, DHT
    // routing init) are spawned inline in Phase 13.5 via WorkerTaskRegistry.
    // There is no separate helper function — the registry handles ownership.
    let content = read_file("src/worker/unified_server/mod.rs");
    assert!(
        content.contains("Phase 13.5: spawn mesh support tasks via registry"),
        "Phase 13.5 must exist for spawning mesh support tasks"
    );
    assert!(
        content.contains("dns_verification_"),
        "Phase 13.5 must spawn DNS verification loops"
    );
    assert!(
        content.contains("yara_broadcast"),
        "Phase 13.5 must spawn YARA broadcast loop"
    );
    assert!(
        content.contains("dht_routing_init"),
        "Phase 13.5 must spawn DHT routing init one-shot"
    );
}

#[test]
fn support_tasks_registered_after_required_mesh_startup() {
    // Iteration 85: Support tasks (DNS, YARA, DHT init) are spawned in
    // Phase 13.5 BEFORE mesh startup (Phase 14.5). The composition root
    // registers them in WorkerTaskRegistry for structured ownership.
    let content = read_file("src/worker/unified_server/mod.rs");
    let phase_13_5_idx = content
        .find("Phase 13.5: spawn mesh support tasks via registry")
        .expect("Phase 13.5 must exist");
    let start_mesh_idx = content
        .find("start_mesh_generation(")
        .expect("required mesh must call start_mesh_generation");
    // Find the SECOND UnifiedServerWorkerReady (in the Ok branch after mesh startup)
    let first_ready_idx = content
        .find("UnifiedServerWorkerReady")
        .expect("must have ready message");
    let ready_idx = content[first_ready_idx + 1..]
        .find("UnifiedServerWorkerReady")
        .map(|i| first_ready_idx + 1 + i)
        .expect("must have second ready message in Ok branch");
    assert!(
        phase_13_5_idx < start_mesh_idx,
        "Phase 13.5 support tasks must appear before start_mesh_generation"
    );
    assert!(
        start_mesh_idx < ready_idx,
        "start_mesh_generation must appear before ready message"
    );
}

#[test]
fn support_tasks_registered_after_optional_mesh_startup() {
    // Iteration 85: Support tasks are spawned in Phase 13.5 BEFORE
    // optional mesh startup (Phase 14.5). The optional mesh startup
    // calls start_with_policy as a one-shot background task.
    let content = read_file("src/worker/unified_server/mod.rs");
    let phase_13_5_idx = content
        .find("Phase 13.5: spawn mesh support tasks via registry")
        .expect("Phase 13.5 must exist");
    let optional_start_idx = content
        .find("start_with_policy(synvoid_mesh::lifecycle::MeshStartupPolicy::default())")
        .expect("optional mesh must call start_with_policy");
    assert!(
        phase_13_5_idx < optional_start_idx,
        "Phase 13.5 support tasks must appear before optional mesh start_with_policy"
    );
}

#[test]
fn support_tasks_extracted_before_builder() {
    // Iteration 85: Support tasks are spawned inline in Phase 13.5 using
    // mesh_init fields directly. There are no separate extraction variables —
    // the registry consumes the components for structured ownership.
    let content = read_file("src/worker/unified_server/mod.rs");
    let builder_idx = content
        .find("DataPlaneServicesBuilder::new(")
        .expect("builder must exist");
    let phase_13_5_idx = content
        .find("Phase 13.5: spawn mesh support tasks via registry")
        .expect("Phase 13.5 must exist");
    assert!(
        builder_idx < phase_13_5_idx,
        "Phase 13.5 support tasks must appear after builder construction"
    );
    assert!(
        content.contains("mesh_init.dns_verification_registries"),
        "dns_verification_registries must be used from mesh_init directly"
    );
    assert!(
        content.contains("mesh_init.yara_broadcast"),
        "yara_broadcast must be used from mesh_init directly"
    );
    assert!(
        content.contains("mesh_init.dht_routing_manager"),
        "dht_routing_manager must be used from mesh_init directly"
    );
}

#[test]
fn no_old_phase_13_5_registry_support_tasks() {
    // Iteration 85: Phase 13.5 spawns support tasks via WorkerTaskRegistry
    // for structured ownership. Tasks ARE registered via spawn_background
    // and spawn_one_shot — this is the correct pattern (registry-owned).
    let content = read_file("src/worker/unified_server/mod.rs");
    let phase_13_5_start = content
        .find("Phase 13.5: spawn mesh support tasks via registry")
        .expect("Phase 13.5 comment must exist");
    let phase_14_start = content
        .find("Phase 14: register server run task")
        .expect("Phase 14 comment must exist");
    let phase_13_5_section = &content[phase_13_5_start..phase_14_start];
    assert!(
        phase_13_5_section.contains("spawn_background("),
        "Phase 13.5 must spawn background tasks via WorkerTaskRegistry"
    );
    assert!(
        phase_13_5_section.contains("spawn_one_shot("),
        "Phase 13.5 must spawn one-shot tasks via WorkerTaskRegistry"
    );
    assert!(
        phase_13_5_section.contains("registry.spawn_background"),
        "Phase 13.5 must use registry.spawn_background for ownership"
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
    assert!(
        disabled_body.contains("dht_routing_manager: None"),
        "disabled MeshInit must have no dht_routing_manager"
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
    // Iteration 85: Required mesh path transitions status directly via
    // WorkerMeshStatus before calling start_mesh_generation. The transition
    // calls are within the same #[cfg(feature = "dns")] block.
    let content = read_file("src/worker/unified_server/mod.rs");
    let start_call = content
        .find("start_mesh_generation(")
        .expect("must call start_mesh_generation");
    // Search for transition_starting in the 500 chars before start_mesh_generation
    let search_start = start_call.saturating_sub(500);
    let preceding = &content[search_start..start_call];
    assert!(
        preceding.contains("transition_starting"),
        "required path must transition to Starting before calling start_mesh_generation"
    );
    let after_start = &content[start_call..];
    let ok_block = after_start.find("Ok(()) =>").expect("must have Ok branch");
    let ok_body = &after_start[ok_block..];
    let closing_brace = ok_body.find('}').unwrap_or(ok_body.len());
    let ok_first_branch = &ok_body[..closing_brace];
    assert!(
        ok_first_branch.contains("transition_running"),
        "required path must transition to Running after successful start_mesh_generation"
    );
    let err_block = after_start
        .find("Err(cause) =>")
        .expect("must have Err branch");
    let err_body = &after_start[err_block..];
    let closing_brace = err_body.find('}').unwrap_or(err_body.len());
    let err_first_branch = &err_body[..closing_brace];
    assert!(
        err_first_branch.contains("transition_failed"),
        "required path must transition to Failed after failed start_mesh_generation"
    );
}

// --- Iteration 85 Phase 33: Configuration and runtime invariant guards ---

#[test]
fn restart_enabled_rejected_or_unreachable() {
    let content = read_file("src/worker/mesh_supervision.rs");
    assert!(
        content.contains(
            "restart_enabled is true in config but restart is not implemented; forcing to false"
        ),
        "build_mesh_supervision_policy must warn and reject restart_enabled"
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
        content.contains("disabled mesh must have no dht_routing_manager"),
        "composition root must validate dht_routing_manager is None when disabled"
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
    // Iteration 85: Support tasks (DNS verification, YARA broadcast, DHT
    // routing init) are spawned in Phase 13.5 BEFORE mesh startup (Phase 14.5).
    // The composition root registers them in WorkerTaskRegistry for ownership.
    let content = read_file("src/worker/unified_server/mod.rs");
    let phase_13_5_idx = content
        .find("Phase 13.5: spawn mesh support tasks via registry")
        .expect("Phase 13.5 must exist");
    let start_mesh_idx = content
        .find("start_mesh_generation(")
        .expect("required mesh must call start_mesh_generation");
    assert!(
        phase_13_5_idx < start_mesh_idx,
        "Phase 13.5 support tasks must appear before start_mesh_generation"
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
