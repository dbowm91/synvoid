// Submodule: Worker → Supervisor heartbeat task, bandwidth-persistence task,
// the IPC message-handling loop, and the request-blocklist request helper.

use std::fmt;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex as TokioMutex;

use super::state::{wait_for_drain, UnifiedServerWorkerState};
use crate::worker::common::collect_current_process_usage;
use synvoid_block_store::{BlockProvenance, BlockProvenanceKind};
use synvoid_ipc::{current_timestamp, Message};
use synvoid_static_files::client::get_global_async_cpu_offload_stats;

#[cfg(feature = "mesh")]
use synvoid_mesh::canonical::CanonicalTrustReader;
#[cfg(feature = "mesh")]
use synvoid_mesh::dht::advisory_source::{AdvisoryRecordSource, RecordStoreAdvisorySource};

/// The error type for IPC loop failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcLoopError {
    /// Supervisor connection lost.
    ConnectionLost,
    /// Unexpected panic or error.
    Unexpected(String),
}

impl fmt::Display for IpcLoopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionLost => write!(f, "connection_lost"),
            Self::Unexpected(msg) => write!(f, "unexpected: {}", msg),
        }
    }
}

/// Send a lifecycle event and wait for composition-root acknowledgement.
///
/// Returns `Err(IpcLoopError)` if the channel is closed or the acknowledgement
/// sender is dropped, making lifecycle send failures explicit rather than
/// silently ignored.
pub async fn request_lifecycle_transition(
    lifecycle_tx: &tokio::sync::mpsc::Sender<LifecycleRequest>,
    event: WorkerLifecycleEvent,
) -> Result<(), IpcLoopError> {
    let (accepted, ack_rx) = tokio::sync::oneshot::channel();
    lifecycle_tx
        .send(LifecycleRequest { event, accepted })
        .await
        .map_err(|_| {
            IpcLoopError::Unexpected("worker lifecycle coordinator channel closed".to_string())
        })?;

    ack_rx.await.map_err(|_| {
        IpcLoopError::Unexpected("worker lifecycle coordinator dropped acknowledgement".to_string())
    })
}

/// Lifecycle events emitted by the IPC task for composition-root orchestration.
#[derive(Debug, Clone)]
pub enum WorkerLifecycleEvent {
    MasterShutdown { graceful: bool, timeout: Duration },
    WorkerResize { worker_threads: usize },
    SupervisorDisconnected,
}

/// Handshake from IPC task to composition root.
///
/// Carries the lifecycle event and a oneshot acknowledgement sender.
/// The IPC task awaits the acknowledgement before returning, ensuring
/// that `begin_shutdown()` is called before the critical task exits.
pub struct LifecycleRequest {
    pub event: WorkerLifecycleEvent,
    pub accepted: tokio::sync::oneshot::Sender<()>,
}

/// Iteration 50: Convert optional IPC provenance strings back to a typed `BlockProvenance`.
/// When both fields are `None` (legacy messages), defaults to `SupervisorSync`.
fn ipc_data_to_provenance(kind_str: Option<&str>, source: Option<&str>) -> BlockProvenance {
    let kind = match kind_str {
        Some("LocalWaf") => BlockProvenanceKind::LocalWaf,
        Some("LocalHoneypot") => BlockProvenanceKind::LocalHoneypot,
        Some("LocalAsnTracker") => BlockProvenanceKind::LocalAsnTracker,
        Some("MeshThreatIntelPolicyGated") => BlockProvenanceKind::MeshThreatIntelPolicyGated,
        Some("SupervisorSync") => BlockProvenanceKind::SupervisorSync,
        Some("AdminManual") => BlockProvenanceKind::AdminManual,
        Some("SupervisorManual") => BlockProvenanceKind::SupervisorManual,
        Some("ProxyHealthProbe") => BlockProvenanceKind::ProxyHealthProbe,
        Some("Test") => BlockProvenanceKind::Test,
        Some("LegacyUnknown") | None => {
            // Iteration 50: Legacy messages without provenance default to SupervisorSync
            // since the supervisor is the relay context for these IPC messages.
            return BlockProvenance {
                // Iteration 50: relay default, not origin overwrite
                kind: BlockProvenanceKind::SupervisorSync,
                source: source.map(|s| s.to_string()),
            };
        }
        _ => {
            return BlockProvenance {
                // Iteration 50: relay default, not origin overwrite
                kind: BlockProvenanceKind::SupervisorSync,
                source: source.map(|s| s.to_string()),
            };
        }
    };
    BlockProvenance {
        kind,
        source: source.map(|s| s.to_string()),
    }
}

pub fn spawn_heartbeat_task(
    state: UnifiedServerWorkerState,
    registry: &mut crate::worker::task_registry::WorkerTaskRegistry,
) -> usize {
    let token = registry.child_token();
    registry.spawn_background("heartbeat", async move {
        let heartbeat_interval = Duration::from_secs(5);
        let mut interval = tokio::time::interval(heartbeat_interval);
        let mut next_heartbeat_at = Instant::now() + heartbeat_interval;
        let mut shutdown_rx = token;

        loop {
            tokio::select! {
                _ = interval.tick() => {}
                result = shutdown_rx.changed() => {
                    if result.is_ok() && *shutdown_rx.borrow() {
                        break;
                    }
                }
            }

            if !state.running.is_running() {
                break;
            }

            let lag_ms = Instant::now()
                .saturating_duration_since(next_heartbeat_at)
                .as_millis() as u64;
            state.metrics.record_event_loop_lag_ms(lag_ms);
            let (memory_bytes, cpu_percent) = collect_current_process_usage();
            state
                .metrics
                .record_process_usage(memory_bytes, cpu_percent);
            state
                .metrics
                .set_active_connections(state.drain_state.get_active_connections());
            let cpu_offload_stats = get_global_async_cpu_offload_stats();
            state.metrics.set_offload_counters(
                cpu_offload_stats.submissions,
                cpu_offload_stats.timeouts,
                cpu_offload_stats.rejections,
            );
            state
                .metrics
                .set_offload_fallbacks(cpu_offload_stats.fallbacks);
            next_heartbeat_at += heartbeat_interval;

            let uptime = state.start_time.elapsed().as_secs();
            let payload = state.metrics.to_payload(uptime);
            let timestamp = current_timestamp();
            let worker_id = state.worker_id;

            let app_health: Vec<(String, bool)> = {
                let app_servers = state.app_servers.read().await;
                app_servers
                    .iter()
                    .map(|(site_id, supervisor)| (site_id.clone(), supervisor.is_healthy()))
                    .collect()
            };

            let mut ipc = state.ipc.lock().await;
            let _ = ipc
                .send(&Message::UnifiedServerWorkerHeartbeat {
                    id: worker_id,
                    timestamp,
                    metrics: payload,
                })
                .await;

            for (site_id, healthy) in app_health {
                let _ = ipc
                    .send(&Message::AppServerHealth {
                        id: worker_id,
                        site_id,
                        healthy,
                        timestamp,
                    })
                    .await;
            }
        }
    })
}

pub fn spawn_bandwidth_persist_task(
    registry: &mut crate::worker::task_registry::WorkerTaskRegistry,
) -> usize {
    let token = registry.child_token();
    registry.spawn_background("bandwidth_persist", async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        let mut shutdown_rx = token;

        loop {
            tokio::select! {
                _ = interval.tick() => {}
                result = shutdown_rx.changed() => {
                    if result.is_ok() && *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
            crate::metrics::bandwidth::persist_global_bandwidth_tracker();
        }

        // Final flush on shutdown to avoid losing dirty state.
        crate::metrics::bandwidth::persist_global_bandwidth_tracker();
        tracing::debug!("Bandwidth persist task: final flush completed on shutdown");
    })
}

pub fn spawn_ipc_loop(
    state: UnifiedServerWorkerState,
    shared_config: Arc<tokio::sync::RwLock<crate::config::ConfigManager>>,
    registry: &mut crate::worker::task_registry::WorkerTaskRegistry,
) -> (usize, tokio::sync::mpsc::Receiver<LifecycleRequest>) {
    let (lifecycle_tx, lifecycle_rx) = tokio::sync::mpsc::channel::<LifecycleRequest>(4);
    let token = registry.child_token();
    let id = registry.spawn_critical_result("ipc_loop", async move {
        let mut shutdown_rx = token;
        loop {
            tokio::select! {
                _ = async {}, if !state.running.is_running() => {
                    return Ok(());
                }
                result = shutdown_rx.changed() => {
                    if result.is_ok() && *shutdown_rx.borrow() {
                        return Ok(());
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(50)).await;

            let message = {
                let mut ipc = state.ipc.lock().await;
                match ipc.recv_with_timeout::<Message>(50).await {
                    Ok(Some(msg)) => Some(msg),
                    Ok(None) => None,
                    Err(_) => {
                        tracing::warn!("Unified server worker lost connection to supervisor");
                        state.master_dead.stop();
                        // Send SupervisorDisconnected via channel and wait for ack.
                        let _ = request_lifecycle_transition(
                            &lifecycle_tx,
                            WorkerLifecycleEvent::SupervisorDisconnected,
                        ).await;
                        return Err(IpcLoopError::ConnectionLost);
                    }
                }
            };

            match message {
                Some(Message::MasterShutdown {
                    graceful,
                    timeout_secs,
                }) => {
                    tracing::info!(
                        "Unified Server Worker {} received shutdown signal (graceful: {}, timeout: {}s)",
                        state.worker_id,
                        graceful,
                        timeout_secs
                    );

                    let timeout = Duration::from_secs(timeout_secs as u64);
                    let event = WorkerLifecycleEvent::MasterShutdown { graceful, timeout };
                    let _ = request_lifecycle_transition(&lifecycle_tx, event).await;
                    return Ok(());
                }
                Some(Message::MasterConfigReload { config_path }) => {
                    tracing::info!(
                        "Unified Server Worker {} received config reload: {}",
                        state.worker_id,
                        config_path
                    );

                    if cfg!(feature = "mesh") {
                        tracing::error!(
                            "Config hot-reload is not supported when mesh feature is enabled. \
                             Mesh, YARA rules, threat intel, and honeypot changes require full worker restart. \
                             Please restart the worker to apply mesh-related configuration changes."
                        );
                        let mut ipc = state.ipc.lock().await;
                        let _ = ipc
                            .send(&Message::WorkerError {
                                id: state.worker_id,
                                error: "Config hot-reload not supported with mesh feature enabled"
                                    .to_string(),
                                severity: crate::process::ErrorSeverity::Warning,
                                error_code: crate::process::ErrorCode::ConfigLoadFailed,
                            })
                            .await;
                        continue;
                    }

                    let config_dir = std::path::Path::new(&config_path);
                    let mut cm = crate::config::ConfigManager::new(config_dir.to_path_buf());
                    let main_path = config_dir.join("main.toml");
                    if cm.load_main(&main_path).is_ok() {
                        cm.discover_sites();
                        *shared_config.write().await = cm;

                        tracing::info!(
                            "Unified Server Worker {} config reloaded.",
                            state.worker_id
                        );
                    } else {
                        tracing::warn!(
                            "Unified Server Worker {} failed to reload config from {}",
                            state.worker_id,
                            config_path
                        );
                    }
                }
                Some(Message::MasterHealthCheck { timestamp }) => {
                    let mut ipc = state.ipc.lock().await;
                    if ipc
                        .send(&Message::HealthCheckAck { timestamp })
                        .await
                        .is_err()
                    {
                        tracing::warn!("Failed to send health check ack to supervisor");
                    }
                }
                Some(Message::MasterCertReload) => {
                    tracing::info!(
                        "Unified Server Worker {} received cert reload",
                        state.worker_id
                    );
                    if let Some(cert_resolver) = state.unified_server.get_cert_resolver() {
                        if let Err(e) = cert_resolver.load_certificates() {
                            tracing::error!(
                                "Failed to reload certificates in worker {}: {}",
                                state.worker_id,
                                e
                            );
                        } else {
                            tracing::info!(
                                "Certificates reloaded successfully in worker {}",
                                state.worker_id
                            );
                        }
                    } else {
                        tracing::warn!(
                            "No cert_resolver in worker {}, cannot reload certificates",
                            state.worker_id
                        );
                    }
                }
                Some(Message::BlocklistUpdate {
                    blocks,
                    mesh_blocks,
                    version: _,
                }) => {
                    tracing::debug!(
                        "Received blocklist update with {} IP entries and {} mesh entries from Supervisor",
                        blocks.len(),
                        mesh_blocks.len()
                    );
                    if let Some(block_store) = state.unified_server.get_block_store() {
                        for block in blocks {
                            let provenance = ipc_data_to_provenance(
                                block.provenance_kind.as_deref(),
                                block.provenance_source.as_deref(),
                            );
                            if let Ok(ip) = block.ip.parse() {
                                let _ = block_store.block_ip_with_provenance(
                                    ip,
                                    &block.reason,
                                    block.ban_expire_seconds,
                                    &block.site_scope,
                                    provenance,
                                );
                            }
                        }
                        for block in mesh_blocks {
                            let provenance = ipc_data_to_provenance(
                                block.provenance_kind.as_deref(),
                                block.provenance_source.as_deref(),
                            );
                            let _ = block_store.block_mesh_id_with_provenance(
                                &block.mesh_id,
                                &block.reason,
                                block.ban_expire_seconds,
                                &block.site_scope,
                                provenance,
                            );
                        }
                    }
                }
                Some(Message::BlocklistEventUpdate {
                    event_json,
                    source_node,
                    event_id,
                }) => {
                    tracing::debug!(
                        "Received blocklist event from Supervisor: event_id={}, source={}",
                        event_id,
                        source_node
                    );
                    if let Some(block_store) = state.unified_server.get_block_store() {
                        match serde_json::from_str::<synvoid_core::block_store::BlocklistEvent>(
                            &event_json,
                        ) {
                            Ok(event) => {
                                let result = block_store.apply_blocklist_event(&event);
                                tracing::info!(
                                    "Applied supervisor blocklist event: {:?} {:?} on {:?} -> {:?}",
                                    event.operation,
                                    event.target_kind,
                                    event.identifier,
                                    result
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to deserialize blocklist event from Supervisor: {}",
                                    e
                                );
                            }
                        }
                    }
                }
                #[cfg(feature = "mesh")]
                Some(Message::CanonicalTrustSnapshotUpdate {
                    snapshot,
                    generated_at_unix,
                }) => {
                    tracing::info!(
                        "Received canonical trust snapshot from Supervisor (generated_at={}, {} bytes)",
                        generated_at_unix,
                        snapshot.len()
                    );
                    match postcard::from_bytes::<synvoid_mesh::canonical::CanonicalTrustSnapshot>(
                        &snapshot,
                    ) {
                        Ok(canonical_snapshot) => {
                            let global_nodes = canonical_snapshot.authorized_global_nodes.len();
                            let org_keys = canonical_snapshot.org_key_entries.len();
                            let revoked = canonical_snapshot.revoked_node_ids.len();
                            let intel = canonical_snapshot.threat_intel_ids.len();

                            // Store the raw snapshot for reference.
                            *state.canonical_snapshot.write().await =
                                Some(canonical_snapshot.clone());

                            // Classify snapshot freshness using config-sourced policy.
                            let freshness_policy = {
                                let config_guard = shared_config.read().await;
                                config_guard
                                    .main
                                    .tunnel
                                    .mesh
                                    .as_ref()
                                    .and_then(|mesh| {
                                        // The config crate's AuthorityFreshnessConfig uses a String
                                        // for stale_mode. Round-trip through JSON to convert to the
                                        // mesh crate's typed version with the enum.
                                        let mesh_cfg = serde_json::to_value(&mesh.authority_freshness).ok()?;
                                        let auth_freshness: synvoid_mesh::config::AuthorityFreshnessConfig =
                                            serde_json::from_value(mesh_cfg).ok()?;
                                        Some(synvoid_mesh::canonical::CanonicalSnapshotFreshnessPolicy::from(
                                            &auth_freshness,
                                        ))
                                    })
                                    .unwrap_or_default()
                            };
                            tracing::debug!(
                                "Canonical snapshot freshness policy: fresh_ms={}, stale_grace_ms={}, stale_mode={:?}",
                                freshness_policy.fresh_max_age_ms,
                                freshness_policy.stale_grace_max_age_ms,
                                freshness_policy.stale_mode,
                            );
                            let now = synvoid_utils::safe_unix_timestamp();
                            let freshness_state =
                                synvoid_mesh::canonical::classify_canonical_snapshot(
                                    Some(&canonical_snapshot),
                                    &freshness_policy,
                                    now,
                                );

                            match freshness_state {
                                synvoid_mesh::canonical::CanonicalSnapshotFreshnessState::Fresh { age_ms } => {
                                    tracing::info!(
                                        "Canonical trust snapshot accepted fresh (age_ms={})",
                                        age_ms
                                    );
                                    // Wrap in freshness-bound reader and apply.
                                    let reader = synvoid_mesh::canonical::FreshnessBoundCanonicalReader::new(
                                        canonical_snapshot,
                                        freshness_policy,
                                        now,
                                    );
                                    let canonical_reader: Arc<dyn CanonicalTrustReader> = Arc::new(reader);
                                    let advisory: Option<Arc<dyn AdvisoryRecordSource>> =
                                        state.data_plane.record_store.as_ref().map(|store| {
                                            Arc::new(RecordStoreAdvisorySource::new(store.clone()))
                                                as Arc<dyn AdvisoryRecordSource>
                                        });
                                    state.data_plane.update_threat_intel_policy_context(
                                        Some(canonical_reader),
                                        advisory,
                                    );
                                    tracing::info!(
                                        "Canonical trust snapshot applied and policy context refreshed: {} global nodes, {} org keys, {} revoked, {} intel",
                                        global_nodes, org_keys, revoked, intel,
                                    );
                                }
                                synvoid_mesh::canonical::CanonicalSnapshotFreshnessState::StaleWithinGrace { age_ms } => {
                                    match freshness_policy.stale_mode {
                                        synvoid_mesh::canonical::CanonicalSnapshotStaleMode::AllowStaleWithWarning => {
                                            tracing::warn!(
                                                "Canonical trust snapshot accepted stale under grace (age_ms={}, mode=allow_stale_with_warning)",
                                                age_ms
                                            );
                                            let reader = synvoid_mesh::canonical::FreshnessBoundCanonicalReader::new(
                                                canonical_snapshot,
                                                freshness_policy,
                                                now,
                                            );
                                            let canonical_reader: Arc<dyn CanonicalTrustReader> = Arc::new(reader);
                                            let advisory: Option<Arc<dyn AdvisoryRecordSource>> =
                                                state.data_plane.record_store.as_ref().map(|store| {
                                                    Arc::new(RecordStoreAdvisorySource::new(store.clone()))
                                                        as Arc<dyn AdvisoryRecordSource>
                                                });
                                            state.data_plane.update_threat_intel_policy_context(
                                                Some(canonical_reader),
                                                advisory,
                                            );
                                            tracing::info!(
                                                "Canonical trust snapshot applied (stale) and policy context refreshed: {} global nodes, {} org keys, {} revoked, {} intel",
                                                global_nodes, org_keys, revoked, intel,
                                            );
                                        }
                                        synvoid_mesh::canonical::CanonicalSnapshotStaleMode::FailOpenDefer => {
                                            tracing::warn!(
                                                "Canonical trust snapshot stale, deferring (age_ms={}, mode=fail_open_defer)",
                                                age_ms
                                            );
                                            state.data_plane.update_threat_intel_policy_context(None, None);
                                        }
                                        synvoid_mesh::canonical::CanonicalSnapshotStaleMode::FailClosedNotActionable => {
                                            tracing::warn!(
                                                "Canonical trust snapshot stale, fail-closed (age_ms={}, mode=fail_closed_not_actionable)",
                                                age_ms
                                            );
                                            let reader = synvoid_mesh::canonical::FreshnessBoundCanonicalReader::new(
                                                canonical_snapshot,
                                                freshness_policy,
                                                now,
                                            );
                                            let canonical_reader: Arc<dyn CanonicalTrustReader> = Arc::new(reader);
                                            let advisory: Option<Arc<dyn AdvisoryRecordSource>> =
                                                state.data_plane.record_store.as_ref().map(|store| {
                                                    Arc::new(RecordStoreAdvisorySource::new(store.clone()))
                                                        as Arc<dyn AdvisoryRecordSource>
                                                });
                                            state.data_plane.update_threat_intel_policy_context(
                                                Some(canonical_reader),
                                                advisory,
                                            );
                                        }
                                    }
                                }
                                synvoid_mesh::canonical::CanonicalSnapshotFreshnessState::Expired { age_ms } => {
                                    tracing::warn!(
                                        "Canonical trust snapshot expired, not applying (age_ms={})",
                                        age_ms
                                    );
                                    state.data_plane.update_threat_intel_policy_context(None, None);
                                }
                                synvoid_mesh::canonical::CanonicalSnapshotFreshnessState::Missing
                                | synvoid_mesh::canonical::CanonicalSnapshotFreshnessState::Invalid => {
                                    tracing::error!(
                                        "Canonical trust snapshot invalid/malformed, not applying"
                                    );
                                    state.data_plane.update_threat_intel_policy_context(None, None);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                "Failed to deserialize canonical trust snapshot: {}",
                                e
                            );
                        }
                    }
                }
                Some(Message::RulePatternsUpdate { version, patterns }) => {
                    tracing::info!(
                        "Received rule patterns update v{} from Supervisor ({} categories)",
                        version,
                        patterns.len()
                    );

                    for pattern_data in patterns {
                        crate::waf::rule_feed::update_patterns_for_category(
                            &pattern_data.category,
                            pattern_data.patterns,
                        );
                    }

                    if let Err(e) = state.unified_server.reload_attack_detector() {
                        tracing::error!(
                            "Failed to reload attack detector with new patterns: {}",
                            e
                        );
                    } else {
                        tracing::info!(
                            "Successfully reloaded attack detector with new rule patterns"
                        );
                    }
                }
                #[cfg(feature = "mesh")]
                Some(Message::ThreatFeedUpdate {
                    indicators,
                    version: _,
                    timestamp: _,
                }) => {
                    tracing::debug!(
                        "Received threat feed update with {} indicators from Supervisor",
                        indicators.len()
                    );
                    if let Some(threat_intel) = &state.request_services.threat_intel {
                        for indicator_data in &indicators {
                            let threat_type = match indicator_data.threat_type {
                                crate::process::ipc::ThreatIndicatorType::IpBlock => {
                                    crate::mesh::protocol::ThreatType::IpBlock
                                }
                                crate::process::ipc::ThreatIndicatorType::RateLimitViolation => {
                                    crate::mesh::protocol::ThreatType::RateLimitViolation
                                }
                                crate::process::ipc::ThreatIndicatorType::SuspiciousActivity => {
                                    crate::mesh::protocol::ThreatType::SuspiciousActivity
                                }
                            };
                            let severity = match indicator_data.severity {
                                crate::process::ipc::ThreatSeverityLevel::Low => {
                                    crate::mesh::protocol::ThreatSeverity::Low
                                }
                                crate::process::ipc::ThreatSeverityLevel::Medium => {
                                    crate::mesh::protocol::ThreatSeverity::Medium
                                }
                                crate::process::ipc::ThreatSeverityLevel::High => {
                                    crate::mesh::protocol::ThreatSeverity::High
                                }
                                crate::process::ipc::ThreatSeverityLevel::Critical => {
                                    crate::mesh::protocol::ThreatSeverity::Critical
                                }
                            };
                            let indicator = crate::mesh::protocol::ThreatIndicator {
                                threat_type,
                                indicator_value: indicator_data.indicator_value.clone(),
                                severity,
                                reason: indicator_data.reason.clone(),
                                ttl_seconds: indicator_data.ttl_seconds,
                                source_node_id: indicator_data.source_node_id.clone(),
                                timestamp: indicator_data.timestamp,
                                site_scope: indicator_data.site_scope.clone(),
                                rate_limit_requests: indicator_data.rate_limit_requests,
                                rate_limit_window_secs: indicator_data.rate_limit_window_secs,
                                suspicious_pattern: indicator_data.suspicious_pattern.clone(),
                                signature: Vec::new(),
                                signer_public_key: None,
                            };
                            threat_intel.add_feed_indicator(indicator);
                        }
                        tracing::info!(
                            "Applied {} threat feed indicators from Supervisor",
                            indicators.len()
                        );
                    } else {
                        tracing::warn!("No threat intel manager available to apply feed update");
                    }
                }
                Some(Message::UnifiedServerWorkerDrain {
                    timeout_secs,
                    drain_id: request_drain_id,
                }) => {
                    tracing::info!(
                        "Unified Server Worker {} received drain signal (timeout: {}s, drain_id: {})",
                        state.worker_id,
                        timeout_secs,
                        request_drain_id
                    );

                    if state.draining.is_draining() {
                        let current_drain_id = state.drain_id.load(Ordering::SeqCst);
                        if current_drain_id > 0 && current_drain_id != request_drain_id {
                            tracing::warn!(
                                "Already draining with id {}, ignoring request for id {}",
                                current_drain_id,
                                request_drain_id
                            );
                            continue;
                        }
                    }

                    state.drain_id.store(request_drain_id, Ordering::SeqCst);
                    state.draining.start_drain();

                    state.drain_state.start_drain(request_drain_id).await;

                    let tx_guard = state.stop_accepting_tx.lock().await;
                    if let Some(tx) = tx_guard.as_ref() {
                        let _ = tx.send(());
                    }
                    state.stopped_accepting.start_drain();

                    tracing::info!(
                        "Unified Server Worker {} stopping accepting new connections",
                        state.worker_id
                    );

                    let _remaining = wait_for_drain(
                        &state.drain_state,
                        timeout_secs,
                        &state.worker_id,
                        "drain request",
                    )
                    .await;

                    tracing::info!(
                        "Unified Server Worker {} stopping Granian supervisors",
                        state.worker_id
                    );
                    let app_servers = state.app_servers.read().await;
                    for (site_id, supervisor) in app_servers.iter() {
                        tracing::info!("Stopping granian for site {}", site_id);
                        supervisor.stop().await;
                    }
                    drop(app_servers);

                    let remaining = state.drain_state.get_active_connections();
                    let current_drain_id = state.drain_id.load(Ordering::SeqCst);
                    tracing::info!(
                        "Unified Server Worker {} drain complete, {} remaining connections",
                        state.worker_id,
                        remaining
                    );

                    state.draining.end_drain();
                    state.drain_id.store(0, Ordering::SeqCst);
                    state.stopped_accepting.end_drain();

                    let mut ipc = state.ipc.lock().await;
                    let _ = ipc
                        .send(&Message::UnifiedServerWorkerDrained {
                            id: state.worker_id,
                            remaining_connections: remaining,
                            drain_id: current_drain_id,
                        })
                        .await;
                }
                Some(Message::UnifiedServerWorkerResize { worker_threads }) => {
                    tracing::info!(
                        "Unified Server Worker {} received threadpool resize request to {} threads",
                        state.worker_id,
                        worker_threads
                    );

                    let event = WorkerLifecycleEvent::WorkerResize { worker_threads: worker_threads as usize };
                    let _ = request_lifecycle_transition(&lifecycle_tx, event).await;
                    return Ok(());
                }
                Some(_) | None => {}
            }
        }
    });
    (id, lifecycle_rx)
}

/// Abort and join all tasks in the registry with a bounded timeout.
///
/// Used during partial startup failure to ensure no migrated task
/// survives a failed worker initialization.
pub async fn rollback_started_tasks(
    registry: &mut crate::worker::task_registry::WorkerTaskRegistry,
) {
    registry.shutdown();
    let exits = registry
        .shutdown_and_join(
            std::time::Duration::from_secs(2),
            std::time::Duration::from_secs(1),
        )
        .await;
    if !exits.is_empty() {
        tracing::warn!(
            "Startup rollback: {} tasks did not exit cleanly",
            exits.len()
        );
    }
}

/// Request the blocklist from Supervisor at startup, with a 5s timeout.
pub async fn request_initial_blocklist(
    ipc: &Arc<TokioMutex<crate::process::ipc_transport::IpcStream>>,
    worker_id: crate::process::WorkerId,
    unified_server: &crate::server::UnifiedServer,
) {
    let Some(block_store) = unified_server.get_block_store() else {
        tracing::warn!("BlockStore not initialized, skipping blocklist request");
        return;
    };

    let mut ipc_guard = ipc.lock().await;
    if let Err(e) = ipc_guard
        .send(&Message::BlocklistRequest {
            worker_id: worker_id.as_usize(),
            from_version: 0,
        })
        .await
    {
        tracing::warn!("Failed to send blocklist request: {}", e);
        return;
    }

    let timeout = Duration::from_secs(5);
    let start = Instant::now();
    while start.elapsed() < timeout {
        match ipc_guard.recv_with_timeout::<Message>(100).await {
            Ok(Some(Message::BlocklistResponse {
                blocks,
                mesh_blocks,
                ..
            })) => {
                tracing::info!(
                    "Received blocklist from Supervisor with {} IP entries and {} mesh entries",
                    blocks.len(),
                    mesh_blocks.len()
                );
                for block in blocks {
                    let provenance = ipc_data_to_provenance(
                        block.provenance_kind.as_deref(),
                        block.provenance_source.as_deref(),
                    );
                    if let Ok(ip) = block.ip.parse() {
                        let _ = block_store.block_ip_with_provenance(
                            ip,
                            &block.reason,
                            block.ban_expire_seconds,
                            &block.site_scope,
                            provenance,
                        );
                    }
                }
                for block in mesh_blocks {
                    let provenance = ipc_data_to_provenance(
                        block.provenance_kind.as_deref(),
                        block.provenance_source.as_deref(),
                    );
                    let _ = block_store.block_mesh_id_with_provenance(
                        &block.mesh_id,
                        &block.reason,
                        block.ban_expire_seconds,
                        &block.site_scope,
                        provenance,
                    );
                }
                break;
            }
            Ok(Some(msg)) => {
                tracing::debug!("Received non-blocklist message during startup: {:?}", msg);
            }
            Ok(None) => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(unused_imports)]
    use super::*;
    use crate::worker::task_registry::{TaskExitReason, WorkerTaskRegistry};
    use std::sync::atomic::{AtomicBool, AtomicU64};
    use std::sync::Arc;

    /// Verify that the bandwidth persist task shuts down cleanly
    /// and the registry reports zero active tasks afterward.
    #[tokio::test]
    async fn test_bandwidth_persist_shutdown_cleans_up() {
        let mut registry = WorkerTaskRegistry::new();
        spawn_bandwidth_persist_task(&mut registry);

        assert_eq!(registry.background_count(), 1);

        let exits = registry
            .shutdown_and_join(Duration::from_secs(2), Duration::from_secs(2))
            .await;

        // Bandwidth persist is cooperative; it should exit cleanly.
        // No non-clean exits expected (it breaks on shutdown signal).
        let non_clean: Vec<_> = exits
            .iter()
            .filter(|e| e.reason != TaskExitReason::CleanCompletion)
            .collect();
        assert!(
            non_clean.is_empty(),
            "Expected clean shutdown, got: {:?}",
            non_clean
        );
        assert_eq!(registry.active_count(), 0);
    }

    /// Verify that multiple registry-owned tasks all shut down
    /// within the configured timeout bound.
    #[tokio::test]
    async fn test_registry_shutdown_joins_all_tasks() {
        let mut registry = WorkerTaskRegistry::new();
        let counter = Arc::new(AtomicU64::new(0));

        // Spawn 3 background tasks that spin.
        for _ in 0..3 {
            let c = counter.clone();
            registry.spawn_background("spinner", async move {
                loop {
                    c.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            });
        }

        assert_eq!(registry.background_count(), 3);

        let start = std::time::Instant::now();
        let exits = registry
            .shutdown_and_join(Duration::from_secs(2), Duration::from_secs(2))
            .await;
        let elapsed = start.elapsed();

        // All tasks should have been aborted (they spin forever).
        assert_eq!(exits.len(), 3);
        for exit in &exits {
            assert_eq!(exit.reason, TaskExitReason::Aborted);
        }
        assert_eq!(registry.active_count(), 0);

        // Shutdown should complete well within the timeout bound.
        assert!(
            elapsed < Duration::from_secs(5),
            "Shutdown took {:?}, expected < 5s",
            elapsed
        );

        // Verify tasks actually stopped incrementing.
        let after = counter.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let after_wait = counter.load(Ordering::Relaxed);
        assert!(
            after_wait <= after + 1,
            "Tasks continued after abort: after={}, after_wait={}",
            after,
            after_wait
        );
    }

    /// Verify that rollback_started_tasks cancels all tasks in the registry.
    #[tokio::test]
    async fn test_rollback_cancels_all_tasks() {
        let mut registry = WorkerTaskRegistry::new();
        let alive = Arc::new(AtomicBool::new(true));
        let alive_clone = alive.clone();

        registry.spawn_background("long_task", async move {
            while alive_clone.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });

        assert_eq!(registry.active_count(), 1);

        rollback_started_tasks(&mut registry).await;

        assert_eq!(registry.active_count(), 0);
    }

    /// Verify that the heartbeat task stops on shutdown signal.
    #[tokio::test]
    async fn test_heartbeat_stops_on_shutdown() {
        let mut registry = WorkerTaskRegistry::new();
        let token = registry.child_token();

        // Spawn a simplified heartbeat-like task (without UnifiedServerWorkerState).
        registry.spawn_background("heartbeat_test", async move {
            let mut interval = tokio::time::interval(Duration::from_millis(10));
            let mut shutdown_rx = token;
            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    result = shutdown_rx.changed() => {
                        if result.is_ok() && *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });

        assert_eq!(registry.background_count(), 1);

        let exits = registry
            .shutdown_and_join(Duration::from_secs(2), Duration::from_secs(2))
            .await;

        let non_clean: Vec<_> = exits
            .iter()
            .filter(|e| e.reason != TaskExitReason::CleanCompletion)
            .collect();
        assert!(
            non_clean.is_empty(),
            "Heartbeat should exit cleanly, got: {:?}",
            non_clean
        );
        assert_eq!(registry.active_count(), 0);
    }

    /// Verify that a critical IPC-like task that panics is detected
    /// and reported through the exit channel before shutdown.
    #[tokio::test]
    async fn test_ipc_panic_detected_before_shutdown() {
        let mut registry = WorkerTaskRegistry::new();
        let mut exit_rx = registry.subscribe_exits();

        registry.spawn_critical("ipc_panic_test", async {
            panic!("IPC connection lost");
        });

        // The exit notification should arrive immediately.
        let exit = tokio::time::timeout(Duration::from_secs(2), exit_rx.recv())
            .await
            .expect("Should receive exit notification")
            .expect("Should Ok");

        assert_eq!(exit.name, "ipc_panic_test");
        match &exit.reason {
            TaskExitReason::Panic(msg) => assert!(msg.contains("IPC connection lost")),
            other => panic!("Expected Panic, got {:?}", other),
        }

        // Shutdown should still complete cleanly.
        let _exits = registry
            .shutdown_and_join(Duration::from_secs(2), Duration::from_secs(2))
            .await;
        assert_eq!(registry.active_count(), 0);
    }
}
