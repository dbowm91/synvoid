#![allow(clippy::all, unused_variables)]

mod server;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use synvoid::vpn_client::{ReconnectConfig, VpnClient, VpnClientConfig};
use server::start_server;

#[derive(Parser, Debug)]
#[command(name = "synvoid-vpn")]
#[command(about = "SynVoid VPN Client - Connect to WAF as a VPN tunnel")]
#[command(version)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(about = "Connect to a WAF VPN server")]
    Connect {
        #[arg(long, help = "WAF server hostname or IP")]
        server: String,

        #[arg(long, default_value = "51821", help = "WAF server port")]
        port: u16,

        #[arg(long, help = "Client identifier")]
        client_id: String,

        #[arg(long, help = "Authentication token")]
        token: String,

        #[arg(long, help = "TCP port mapping (format: local:remote, e.g., 8080:80)")]
        tcp: Vec<String>,

        #[arg(long, help = "UDP port mapping (format: local:remote, e.g., 53:53)")]
        udp: Vec<String>,

        #[arg(long, help = "Local bind address")]
        bind: Option<String>,

        #[arg(long, help = "Server name for TLS verification")]
        server_name: Option<String>,

        #[arg(long, default_value = "true", help = "Verify server certificate")]
        verify: bool,

        #[arg(long, default_value = "true", help = "Enable auto-reconnect")]
        reconnect: bool,

        #[arg(
            long,
            default_value = "10",
            help = "Maximum reconnect attempts (0 = unlimited)"
        )]
        max_retries: u32,
    },

    #[command(about = "Connect using a configuration file")]
    ConnectConfig {
        #[arg(long, help = "Path to configuration file")]
        config: PathBuf,
    },

    #[command(about = "Generate a sample configuration file")]
    GenerateConfig {
        #[arg(long, help = "Output path for the configuration file")]
        output: PathBuf,
    },

    #[command(about = "Start VPN dashboard HTTP server")]
    Serve {
        #[arg(
            long,
            default_value = "127.0.0.1:8080",
            help = "Dashboard listen address"
        )]
        bind: String,

        #[arg(long, help = "API key for dashboard authentication (optional)")]
        api_key: Option<String>,
    },
}

fn parse_port_mapping(s: &str) -> Result<(u16, u16), String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return Err(format!(
            "Invalid port mapping format: {}. Expected local:remote",
            s
        ));
    }

    let local: u16 = parts[0]
        .parse()
        .map_err(|_| format!("Invalid local port: {}", parts[0]))?;
    let remote: u16 = parts[1]
        .parse()
        .map_err(|_| format!("Invalid remote port: {}", parts[1]))?;

    Ok((local, remote))
}

async fn run_connect(
    server: String,
    port: u16,
    client_id: String,
    token: String,
    tcp_mappings: Vec<String>,
    udp_mappings: Vec<String>,
    bind: Option<String>,
    server_name: Option<String>,
    verify: bool,
    reconnect: bool,
    max_retries: u32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut config = VpnClientConfig::new(&server, port, &client_id, &token)
        .with_verify_server(verify)
        .with_reconnect(ReconnectConfig::new(reconnect, max_retries));

    if let Some(name) = server_name {
        config = config.with_server_name(&name);
    }

    if let Some(bind_addr) = bind {
        config = config.with_local_bind(&bind_addr);
    }

    for mapping in tcp_mappings {
        let (local, remote) =
            parse_port_mapping(&mapping).map_err(|e| format!("Port mapping error: {}", e))?;
        config = config.with_tcp_mapping(local, remote);
    }

    for mapping in udp_mappings {
        let (local, remote) =
            parse_port_mapping(&mapping).map_err(|e| format!("Port mapping error: {}", e))?;
        config = config.with_udp_mapping(local, remote);
    }

    let vpn_client = VpnClient::new(config)?;

    tracing::info!("Connecting to WAF VPN at {}:{}...", server, port);
    tracing::info!("Press Ctrl+C to disconnect");

    vpn_client.run_with_auto_reconnect().await?;

    Ok(())
}

fn generate_sample_config(
    output: &PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sample = r#"# SynVoid VPN Client Configuration
# This file configures the VPN client to connect to a WAF server

enabled = true

# Server configuration
server_host = "waf.example.com"
server_port = 51821
server_name = "waf.example.com"  # Optional: for TLS verification

# Client credentials
client_id = "my-client"
auth_token = "your-secret-token"

# Local bind address for port mappings
local_bind_host = "127.0.0.1"

# TLS settings
verify_server = true
# server_ca = "/path/to/ca.pem"  # Optional: custom CA

# Connection settings
connect_timeout_ms = 10000

# Reconnect settings
[reconnect]
enabled = true
max_attempts = 10
initial_delay_ms = 1000
max_delay_ms = 60000
backoff_multiplier = 2.0

# TCP port mappings
# Each mapping creates a local listener that forwards to the remote port
[[port_mappings]]
local_port = 8080
remote_port = 80
protocol = "tcp"
# upstream_host = "192.168.1.10"  # Optional: target host on WAF network

[[port_mappings]]
local_port = 8443
remote_port = 443
protocol = "tcp"

# UDP port mappings
[[port_mappings]]
local_port = 5353
remote_port = 53
protocol = "udp"
"#;

    std::fs::write(output, sample)?;
    println!("Sample configuration written to: {:?}", output);

    Ok(())
}

fn load_config_from_file(
    path: &PathBuf,
) -> Result<VpnClientConfig, Box<dyn std::error::Error + Send + Sync>> {
    let content = std::fs::read_to_string(path)?;
    let config: VpnClientConfig = toml::from_str(&content)?;
    Ok(config)
}

async fn run_server(
    bind: String,
    api_key: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    start_server(&bind, api_key).await;
    Ok(())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let result: Result<(), Box<dyn std::error::Error + Send + Sync>> = match args.command {
        Commands::Connect {
            server,
            port,
            client_id,
            token,
            tcp,
            udp,
            bind,
            server_name,
            verify,
            reconnect,
            max_retries,
        } => {
            run_connect(
                server,
                port,
                client_id,
                token,
                tcp,
                udp,
                bind,
                server_name,
                verify,
                reconnect,
                max_retries,
            )
            .await
        }
        Commands::ConnectConfig { config } => match load_config_from_file(&config) {
            Ok(vpn_config) => {
                let vpn_client = VpnClient::new(vpn_config).expect("Failed to create VPN client");
                vpn_client.run_with_auto_reconnect().await
            }
            Err(e) => {
                eprintln!("Failed to load config: {}", e);
                std::process::exit(1);
            }
        },
        Commands::GenerateConfig { output } => generate_sample_config(&output),
        Commands::Serve { bind, api_key } => run_server(bind, api_key).await,
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
