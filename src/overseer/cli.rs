use std::path::PathBuf;

use clap::{Parser, Subcommand};

use super::mode::{detect_upgrade_mode, UpgradeMode};
use super::rollback::RollbackManager;
use super::state::{OverseerState, Persistence};
use super::upgrade::Orchestrator;

#[derive(Parser)]
pub struct OverseerArgs {
    #[command(subcommand)]
    pub command: UpgradeCommand,
}

#[derive(Subcommand, Debug)]
pub enum UpgradeCommand {
    Stage {
        #[arg(help = "Path to the new binary")]
        binary: PathBuf,

        #[arg(long, help = "Path to new config directory")]
        config: Option<PathBuf>,

        #[arg(long, help = "Expected SHA-256 checksum of the binary")]
        checksum: Option<String>,
    },

    Status,

    Apply {
        #[arg(long, help = "Comma-separated list of worker ports")]
        ports: String,

        #[arg(long, default_value = "30", help = "Validation timeout in seconds")]
        timeout: u64,

        #[arg(long, default_value = "30", help = "Drain timeout in seconds")]
        drain_timeout: u64,

        #[arg(long, help = "Force specific upgrade mode")]
        mode: Option<String>,
    },

    Rollback,

    Cancel,

    Recover {
        #[arg(long, help = "Automatically rollback to previous version")]
        rollback: bool,
    },

    Versions {
        #[arg(long, default_value = "5", help = "Number of versions to show")]
        count: usize,
    },
}

pub async fn run_overseer_command(args: OverseerArgs) -> Result<(), Box<dyn std::error::Error>> {
    match args.command {
        UpgradeCommand::Stage { binary, config, checksum } => {
            handle_stage(binary, config, checksum).await
        }
        UpgradeCommand::Status => {
            handle_status().await
        }
        UpgradeCommand::Apply { ports, timeout, drain_timeout, mode } => {
            handle_apply(ports, timeout, drain_timeout, mode).await
        }
        UpgradeCommand::Rollback => {
            handle_rollback().await
        }
        UpgradeCommand::Cancel => {
            handle_cancel().await
        }
        UpgradeCommand::Recover { rollback } => {
            handle_recover(rollback).await
        }
        UpgradeCommand::Versions { count } => {
            handle_versions(count).await
        }
    }
}

async fn handle_stage(binary: PathBuf, config: Option<PathBuf>, checksum: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let persistence = Persistence::new(None);
    let _lock = persistence.acquire_lock()?;

    let orchestrator = Orchestrator::new(None, None, None);

    orchestrator.stage(binary, config, checksum).await?;

    let state = orchestrator.get_state().await;

    println!("✓ Upgrade staged successfully");
    println!("  Version: {}", state.staged_version.as_ref().unwrap());
    println!("  Mode: {}", state.upgrade_mode.as_ref().unwrap().name());
    println!("  State: {}", state.state);
    
    if state.staged_binary_checksum.is_some() {
        println!("  Checksum: verified");
    }

    Ok(())
}

async fn handle_status() -> Result<(), Box<dyn std::error::Error>> {
    let persistence = Persistence::new(None);

    let _lock = match persistence.acquire_lock() {
        Ok(lock) => lock,
        Err(e) => {
            println!("Overseer Status (from file)");
            println!("==========================");
            println!("  Lock: {} (another process may be running)", e);
            let state = persistence.load()?;
            print_state(&state);
            return Ok(());
        }
    };

    let state = persistence.load()?;

    println!("Overseer Status");
    println!("===============");

    let mode = detect_upgrade_mode();
    println!("  Upgrade Mode: {} (detected)", mode.name());
    println!("  SO_REUSEPORT: {}", if mode == UpgradeMode::ReusePort { "supported" } else { "not available" });

    print_state(&state);

    Ok(())
}

fn print_state(state: &OverseerState) {
    println!("  State: {}", state.state);
    println!("  Current Version: {}", state.current_version.as_ref().unwrap_or(&"none".to_string()));
    println!("  Staged Version: {}", state.staged_version.as_ref().unwrap_or(&"none".to_string()));

    if let Some(ref error) = state.last_error {
        println!("  Last Error: {}", error);
    }

    if let Some(timestamp) = state.last_upgrade_timestamp {
        println!("  Last Upgrade: {}", format_timestamp(timestamp));
    }

    if let Some(timestamp) = state.last_rollback_timestamp {
        println!("  Last Rollback: {}", format_timestamp(timestamp));
    }

    if let Some(ref ports) = state.worker_ports {
        println!("  Worker Ports: {:?}", ports);
    }

    if state.previous_version.is_some() {
        println!("  Previous Version: {}", state.previous_version.as_ref().unwrap());
    }
}

async fn handle_apply(
    ports_str: String,
    timeout: u64,
    drain_timeout: u64,
    mode: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let persistence = Persistence::new(None);
    let _lock = persistence.acquire_lock()?;

    let ports: Vec<u16> = ports_str
        .split(',')
        .map(|s| s.trim().parse())
        .collect::<Result<Vec<_>, _>>()?;

    if ports.is_empty() {
        return Err("At least one port must be specified".into());
    }

    let orchestrator = Orchestrator::new(None, None, None);

    println!("Starting upgrade...");
    println!("  Ports: {:?}", ports);
    println!("  Validation timeout: {}s", timeout);
    println!("  Drain timeout: {}s", drain_timeout);

    if let Some(mode_str) = mode {
        println!("  Mode: {}", mode_str);
    }

    match orchestrator.apply(ports.clone(), timeout, drain_timeout).await {
        Ok(result) => {
            println!();
            println!("✓ Upgrade completed successfully");
            println!("  Version: {}", result.version);
            println!("  Mode: {}", result.mode.name());
            println!("  Success rate: {:.1}%", result.metrics.success_rate * 100.0);
            println!("  Old ports: {:?}", result.old_ports);
            println!("  New ports: {:?}", result.new_ports);
            Ok(())
        }
        Err(e) => {
            eprintln!();
            eprintln!("✗ Upgrade failed: {}", e);

            if let Some(state) = get_state_rollback_info(&orchestrator).await {
                if state.can_rollback() {
                    eprintln!();
                    eprintln!("Rollback is available. Run:");
                    eprintln!("  maluwaf upgrade rollback");
                }
            }

            Err(e.into())
        }
    }
}

async fn handle_rollback() -> Result<(), Box<dyn std::error::Error>> {
    let persistence = Persistence::new(None);
    let _lock = persistence.acquire_lock()?;

    let rollback_mgr = RollbackManager::new(None);

    if let Some(target) = rollback_mgr.get_rollback_target().await {
        println!("Rollback Target");
        println!("===============");
        println!("  Version: {}", target.version);
        println!("  Reason: {}", target.reason);
    }

    let orchestrator = Orchestrator::new(None, None, None);
    rollback_mgr.perform_rollback(&orchestrator).await?;

    println!("✓ Rollback completed successfully");

    Ok(())
}

async fn handle_cancel() -> Result<(), Box<dyn std::error::Error>> {
    let persistence = Persistence::new(None);
    let _lock = persistence.acquire_lock()?;

    let orchestrator = Orchestrator::new(None, None, None);
    orchestrator.cancel().await?;

    println!("✓ Staged upgrade cancelled");

    Ok(())
}

async fn handle_recover(rollback: bool) -> Result<(), Box<dyn std::error::Error>> {
    let persistence = Persistence::new(None);
    let _lock = persistence.acquire_lock()?;

    let state = persistence.load()?;
    
    println!("Overseer Recovery");
    println!("================");
    println!("  Current State: {}", state.state);

    if !state.needs_recovery() {
        println!("  Status: No recovery needed");
        return Ok(());
    }

    println!("  Recovery needed: System was in incomplete upgrade state");

    if rollback {
        println!("  Attempting automatic rollback...");
        
        let rollback_mgr = RollbackManager::new(None);
        let orchestrator = Orchestrator::new(None, None, None);
        
        match rollback_mgr.perform_rollback(&orchestrator).await {
            Ok(()) => {
                println!("✓ Rollback completed successfully");
            }
            Err(e) => {
                println!("✗ Rollback failed: {}", e);
                return Err(e.into());
            }
        }
    } else {
        println!();
        println!("To recover, run one of:");
        println!("  maluwaf upgrade rollback   - Rollback to previous version");
        println!("  maluwaf upgrade recover --rollback - Auto rollback to previous version");
    }

    Ok(())
}

async fn handle_versions(count: usize) -> Result<(), Box<dyn std::error::Error>> {
    let rollback_mgr = RollbackManager::new(None);
    let versions = rollback_mgr.get_previous_versions(count).await;

    println!("Previous Versions");
    println!("================");

    if versions.is_empty() {
        println!("  No previous versions found");
    } else {
        for version in versions {
            println!("  {} - {}", version.version, format_timestamp(version.created_at));
        }
    }

    Ok(())
}

async fn get_state_rollback_info(orchestrator: &Orchestrator) -> Option<OverseerState> {
    let state = orchestrator.get_state().await;
    if state.can_rollback() {
        Some(state)
    } else {
        None
    }
}

fn format_timestamp(timestamp: u64) -> String {
    use std::time::{Duration, UNIX_EPOCH};

    let datetime = UNIX_EPOCH + Duration::from_secs(timestamp);

    match datetime.duration_since(UNIX_EPOCH) {
        Ok(d) => {
            let secs = d.as_secs();
            let hours = secs / 3600;
            let mins = (secs % 3600) / 60;
            let secs = secs % 60;

            if hours > 24 {
                let days = hours / 24;
                format!("{}d ago", days)
            } else if hours > 0 {
                format!("{}h{}m ago", hours, mins)
            } else if mins > 0 {
                format!("{}m ago", mins)
            } else {
                format!("{}s ago", secs)
            }
        }
        Err(_) => "unknown".to_string(),
    }
}
