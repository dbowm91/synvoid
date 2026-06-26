use crate::supervisor::state::SupervisorState;
use std::sync::Arc;
use synvoid_ipc::ipc_transport::IpcStream as AsyncIpcStream;
use synvoid_ipc::{
    CommandResponse, ProcessManager, StatusStats, SupervisorCommand, SupervisorStatus,
    ThreatSummary,
};

pub async fn handle_supervisor_command(
    ipc: &mut AsyncIpcStream,
    pm: Arc<ProcessManager>,
    state: SupervisorState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Attempt to receive a supervisor command.
    // Since AsyncIpcStream::recv_with_timeout is generic, we can use it here.
    match ipc.recv_with_timeout::<SupervisorCommand>(5000).await {
        Ok(Some(command)) => {
            match command {
                SupervisorCommand::Status => {
                    let pm_stats = pm.get_status();
                    let status = SupervisorStatus {
                        supervisor_pid: std::process::id(),
                        started_at: 0, // TODO: Track start time
                        uptime_secs: 0,
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        workers: pm_stats.workers,
                        stats: StatusStats {
                            total_requests: pm_stats.stats.total_requests,
                            blocked_last_hour: pm_stats.stats.blocked_last_hour,
                            challenged_last_hour: pm_stats.stats.challenged_last_hour,
                            proxied_last_hour: pm_stats.stats.proxied_last_hour,
                            active_blocks: pm_stats.stats.active_blocks,
                            active_violations: 0,
                        },
                        threat_summary: ThreatSummary {
                            critical_ips: 0,
                            elevated_ips: 0,
                            total_blocked_ips: 0,
                        },
                    };
                    ipc.send(&CommandResponse::Status(status)).await?;
                }
                SupervisorCommand::Stop { graceful } => {
                    tracing::info!("Supervisor: Stop command received (graceful: {})", graceful);
                    ipc.send(&CommandResponse::Ok("Shutdown initiated".to_string()))
                        .await?;
                    state.shutdown().await;
                }
                SupervisorCommand::ReloadConfig => {
                    tracing::info!("Supervisor: ReloadConfig command received");
                    {
                        let mut config = state.config.write().await;
                        config.reload_all();
                    }
                    ipc.send(&CommandResponse::Ok("Configuration reloaded".to_string()))
                        .await?;
                }
                SupervisorCommand::HealthCheck => {
                    ipc.send(&CommandResponse::Ok("true".to_string())).await?;
                }
            }
        }
        _ => {
            return Err("Failed to receive or parse supervisor command".into());
        }
    }

    Ok(())
}

pub use crate::supervisor::cli_commands::{
    handle_configtest, handle_generatenewtoken, handle_generatetoken, handle_rehash,
    handle_rehash_data, handle_status, handle_status_data, handle_stop, handle_stop_data,
};
pub use crate::supervisor::ipc::handle_worker_connection_single;

#[cfg(feature = "mesh")]
pub use crate::supervisor::cli_commands::{
    handle_export_threat_feed, handle_export_threat_feed_data,
};
