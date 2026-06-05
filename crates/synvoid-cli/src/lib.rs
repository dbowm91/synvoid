//! CLI argument parsing for SynVoid.
//!
//! Extracts the Clap `Args` struct into a library crate.
//! Command dispatch remains in `src/main.rs` which calls
//! `synvoid_cli::Args::parse()`.

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "synvoid")]
#[command(about = "Multi-Process Web Application Firewall")]
#[command(version)]
pub struct Args {
    #[arg(long, help = "Run as mesh agent process (control plane)")]
    pub mesh_agent: bool,

    #[arg(long, help = "Run as WASM plugin execution jail")]
    pub wasm_jail: bool,

    #[arg(long, help = "Run as YARA rule evaluation jail")]
    pub yara_jail: bool,

    #[arg(long, help = "Run as worker process")]
    pub worker: bool,

    #[arg(long, value_name = "ID", help = "Worker ID (worker mode only)")]
    pub worker_id: Option<usize>,

    #[arg(long, value_name = "PORT", help = "Worker port (worker mode only)")]
    pub port: Option<u16>,

    #[arg(long, value_name = "PATH", help = "Config directory path")]
    pub config_path: Option<PathBuf>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Supervisor IPC socket path (worker mode only)"
    )]
    pub supervisor_socket: Option<PathBuf>,

    #[arg(
        long = "cpu-worker",
        alias = "static-worker",
        help = "Run as CPU offload worker process (compat: --static-worker)"
    )]
    pub cpu_worker: bool,

    #[arg(
        long = "cpu-worker-id",
        alias = "static-worker-id",
        value_name = "ID",
        help = "CPU worker ID"
    )]
    pub cpu_worker_id: Option<usize>,

    #[arg(
        long,
        help = "Run as unified server worker process (handles HTTP/HTTPS/HTTP3)"
    )]
    pub unified_server_worker: bool,

    #[arg(long, value_name = "ID", help = "Unified server worker ID")]
    pub unified_worker_id: Option<usize>,

    #[arg(
        long,
        value_name = "COUNT",
        help = "Number of tokio worker threads (for worker processes)"
    )]
    pub worker_threads: Option<usize>,

    #[arg(long, value_name = "CORE", help = "CPU core to pin this worker to")]
    pub cpu_affinity: Option<usize>,

    #[arg(
        long,
        value_name = "COUNT",
        help = "Total number of workers in the pool"
    )]
    pub total_workers: Option<usize>,

    #[arg(
        long,
        hide = true,
        help = "Enable shared-port startup behavior for internally spawned worker processes"
    )]
    pub reuse_port: bool,

    #[arg(short, long, help = "Run in foreground (don't daemonize)")]
    pub foreground: bool,

    #[arg(long, help = "Validate config files and exit")]
    pub configtest: bool,

    #[arg(long, help = "Show status of running instance")]
    pub status: bool,

    #[arg(long, help = "Stop running instance")]
    pub stop: bool,

    #[arg(long, help = "Restart instance (stop + start)")]
    pub restart: bool,

    #[arg(long, help = "Reload configuration and propagate to workers")]
    pub rehash: bool,

    #[arg(
        long,
        help = "Generate a new admin token and save it to config/main.toml"
    )]
    pub generatenewtoken: bool,

    #[arg(
        long,
        help = "Generate and print an admin token (does not save to config)"
    )]
    pub generatetoken: bool,

    #[arg(
        long,
        value_name = "TOKEN",
        help = "Hash an admin token for use in config (reads token from stdin if not provided)"
    )]
    pub hash_token: Option<Option<String>>,

    #[arg(
        long,
        value_name = "COST",
        help = "Bcrypt cost for token hashing (default: 12, min: 4, max: 31)"
    )]
    pub hash_cost: Option<u32>,

    #[arg(
        long,
        value_name = "MODE",
        help = "Test mode: challenge-off, ratelimit-off, attack-off, bot-off, flood-off, all-off"
    )]
    pub test: Option<Vec<String>>,

    #[arg(
        long,
        value_name = "PATTERN",
        help = "Check if a regex pattern is safe (ReDoS check)"
    )]
    pub checkregex: Option<String>,

    #[arg(
        long,
        help = "Required when using --test all-off to confirm intentional testing"
    )]
    pub force: bool,

    #[arg(
        short,
        long,
        value_name = "LEVEL",
        help = "Log level: trace, debug, info, warn, error (overrides config)"
    )]
    pub log_level: Option<String>,

    #[arg(
        long,
        value_name = "ADDR",
        help = "Address of the Supervisor control API (gRPC)"
    )]
    pub control_addr: Option<String>,

    #[arg(long, help = "Use TLS for Supervisor control API (gRPC)")]
    pub control_api_tls: bool,

    #[arg(long, help = "Export OpenAPI spec as JSON and exit")]
    pub export_openapi: bool,

    #[arg(long, help = "Export API specification (OpenAPI 3.0) as JSON and exit")]
    pub export_api_spec: bool,

    #[arg(long, help = "Export threat feed as JSON")]
    pub export_threat_feed: bool,

    #[arg(
        long,
        value_name = "PATH",
        help = "Path to Ed25519 private key for signing threat feed"
    )]
    pub sign_with: Option<PathBuf>,

    #[arg(long, value_name = "SITE_ID", help = "Filter threat feed by site ID")]
    pub site_id: Option<String>,

    #[arg(long, help = "Generate a new genesis key for first global node setup")]
    pub genesis: bool,

    #[arg(
        long,
        help = "Show current node information (node ID, public key, genesis status)"
    )]
    pub show_node_info: bool,
}
