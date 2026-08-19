//! Sandbox module for isolating massive attack surfaces (WASM, Yara).
//!
//! This module implements the "Jail" process model where highly restricted
//! child processes are used to execute potentially dangerous code.

#[allow(unused_imports)]
use std::sync::Arc;

use crate::platform::sandbox::{ProcessSandbox, SandboxLevel, SandboxPaths};

pub fn run_wasm_jail_mode() {
    tracing::info!("Starting WASM plugin execution jail");

    // Apply strict sandbox immediately
    let level = SandboxLevel::Strict;
    let paths = SandboxPaths::new()
        .add_read_path("/usr/lib") // Minimal system libs
        .add_read_path("/lib");

    if let Err(e) = ProcessSandbox::with_paths(level, paths) {
        tracing::error!("Failed to initialize WASM jail sandbox: {}", e);
        std::process::exit(1);
    }

    tracing::error!(
        "WASM jail IPC is not implemented; refusing to run a sandbox with no request listener"
    );
    std::process::exit(1);
}

pub fn run_yara_jail_mode() {
    tracing::info!("Starting YARA rule evaluation jail");

    // Apply strict sandbox immediately
    let level = SandboxLevel::Strict;
    let paths = SandboxPaths::new()
        .add_read_path("/usr/lib")
        .add_read_path("/lib");

    if let Err(e) = ProcessSandbox::with_paths(level, paths) {
        tracing::error!("Failed to initialize YARA jail sandbox: {}", e);
        std::process::exit(1);
    }

    tracing::error!(
        "YARA jail IPC is not implemented; refusing to run a sandbox with no request listener"
    );
    std::process::exit(1);
}
