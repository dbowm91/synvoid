use std::sync::Arc;

use crate::process::{PidFileManager, ProcessManager};

use super::MasterState;

pub fn setup_signal_handlers(master_state: MasterState, process_manager: Arc<ProcessManager>) {
    let state = master_state.clone();
    let pm = process_manager.clone();

    tokio::spawn(async move {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                tracing::info!("Received SIGINT (Ctrl+C), initiating graceful shutdown...");
                state.shutdown().await;
                pm.graceful_shutdown().await;
            }
            Err(e) => {
                tracing::error!("Error in signal handler: {}", e);
            }
        }
    });

    // Unix-specific signal handler for graceful shutdown.
    //
    // Signal handling notes:
    // - This handles SIGTERM (not SIGINT/Ctrl+C which is handled separately above)
    // - On Unix, SIGTERM is the standard signal for graceful shutdown request
    // - On Windows, we rely solely on Ctrl+C (handled by ctrl_c() above)
    // - The SIGTERM handler triggers the same graceful shutdown flow as Ctrl+C
    #[cfg(unix)]
    {
        let state = master_state.clone();
        let pm = process_manager.clone();

        tokio::spawn(async move {
            #[cfg(unix)]
            {
                let mut sigterm =
                    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!("Failed to install SIGTERM handler: {}", e);
                            return;
                        }
                    };

                sigterm.recv().await;
            }

            #[cfg(windows)]
            {
                use tokio::signal::ctrl_c;
                ctrl_c().await.ok();
            }

            tracing::info!("Received shutdown signal, initiating graceful shutdown...");
            state.shutdown().await;
            pm.graceful_shutdown().await;
        });
    }
}

/// Acquires the PID file with atomic check-and-write to avoid TOCTOU race.
/// Returns the PidFileManager on success, or exits the process on failure.
pub fn acquire_pid_file() -> PidFileManager {
    let mut pid_manager = PidFileManager::new();
    let current_pid = std::process::id();
    let version = env!("CARGO_PKG_VERSION");

    match pid_manager.try_acquire(current_pid, version) {
        Ok(true) => pid_manager,
        Ok(false) => {
            eprintln!(
                "RustWAF is already running (PID: {:?})",
                pid_manager.get_pid()
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!(
                "Error acquiring PID file: {}. RustWAF may already be running.",
                e
            );
            std::process::exit(1);
        }
    }
}

/// Daemonize the process on Unix platforms.
/// On non-Unix platforms, logs a warning and runs in foreground.
pub fn daemonize(pid_manager: &PidFileManager) {
    #[cfg(unix)]
    {
        let current_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("/"));

        let result = {
            // SAFETY: daemon.start() must be called before any threads exist.
            // This runs during early initialization before Tokio runtime starts.
            unsafe {
                daemonize2::Daemonize::new()
                    .working_directory(current_dir)
                    .umask(0o077)
                    .pid_file(pid_manager.pid_file_path())
                    .start()
            }
        };
        match result {
            Ok(_) => {}
            Err(e) => {
                tracing::error!("Failed to daemonize: {}", e);
                std::process::exit(1);
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid_manager;
        tracing::warn!("Daemonization is not supported on this platform, running in foreground");
    }
}
