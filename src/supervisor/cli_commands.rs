use std::path::PathBuf;
#[cfg(feature = "mesh")]
use std::sync::Arc;

use synvoid_config::MainConfig;
use synvoid_ipc::{CommandClient, PidFileManager, SupervisorCommand};
#[cfg(feature = "mesh")]
use synvoid_mesh::protocol::MeshMessageSigner;
#[cfg(feature = "mesh")]
use synvoid_mesh::threat_intel::ThreatIntelligenceManager;

#[cfg(feature = "mesh")]
use crate::commands::supervisor_control::ThreatFeedExportSummary;
use crate::commands::supervisor_control::{RehashOutcome, StopOutcome, SupervisorStatusDisplay};

pub fn handle_status_data(
    control_addr: Option<String>,
    use_tls: bool,
) -> Result<SupervisorStatusDisplay, Box<dyn std::error::Error>> {
    let pid_manager = PidFileManager::new();

    if let Some(content) = pid_manager.read_pid() {
        if pid_manager.is_running() {
            let client =
                CommandClient::new(Some(pid_manager.socket_file_path()), control_addr, use_tls);

            match client.get_status() {
                Ok(status) => {
                    let mut text = String::new();
                    text.push_str("synvoid Status\n");
                    text.push_str("==============\n");
                    text.push_str(&format!("Supervisor PID: {}\n", status.supervisor_pid));
                    text.push_str(&format!("Version: {}\n", status.version));
                    text.push_str(&format!("Uptime: {} seconds\n", status.uptime_secs));
                    text.push('\n');
                    text.push_str("Workers:\n");
                    text.push_str(&format!(
                        "  {:<4} {:<8} {:<6} {:<10} {:<12} {:<10}\n",
                        "ID", "PID", "Port", "Status", "Requests", "Blocked"
                    ));
                    text.push_str(&format!("  {}\n", "-".repeat(60)));
                    for worker in &status.workers {
                        text.push_str(&format!(
                            "  {:<4} {:<8} {:<6} {:<10} {:<12} {:<10}\n",
                            worker.id,
                            worker.pid,
                            worker.port,
                            worker.status,
                            worker.requests,
                            worker.blocked
                        ));
                    }
                    text.push('\n');
                    text.push_str("Stats (last hour):\n");
                    text.push_str(&format!(
                        "  Total Requests:    {}\n",
                        status.stats.total_requests
                    ));
                    text.push_str(&format!(
                        "  Blocked:           {} ({:.1}%)\n",
                        status.stats.blocked_last_hour,
                        if status.stats.total_requests > 0 {
                            (status.stats.blocked_last_hour as f64
                                / status.stats.total_requests as f64)
                                * 100.0
                        } else {
                            0.0
                        }
                    ));
                    text.push_str(&format!(
                        "  Challenged:        {}\n",
                        status.stats.challenged_last_hour
                    ));
                    text.push_str(&format!(
                        "  Proxied:           {}\n",
                        status.stats.proxied_last_hour
                    ));
                    text.push('\n');
                    text.push_str("Threat Summary:\n");
                    text.push_str(&format!(
                        "  Active Blocks:     {}\n",
                        status.stats.active_blocks
                    ));
                    text.push_str(&format!(
                        "  Critical IPs:      {}\n",
                        status.threat_summary.critical_ips
                    ));
                    text.push_str(&format!(
                        "  Elevated IPs:     {}\n",
                        status.threat_summary.elevated_ips
                    ));

                    return Ok(SupervisorStatusDisplay { text });
                }
                Err(e) => {
                    let text = format!(
                        "synvoid appears to be running but status is unavailable: {}\nPID: {}",
                        e, content.pid
                    );
                    return Ok(SupervisorStatusDisplay { text });
                }
            }
        }
    }

    Ok(SupervisorStatusDisplay {
        text: "synvoid is not running".to_string(),
    })
}

pub fn handle_status(
    control_addr: Option<String>,
    use_tls: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let status = handle_status_data(control_addr, use_tls)?;
    println!("{}", status.text);
    Ok(())
}

pub fn handle_stop_data(
    control_addr: Option<String>,
    use_tls: bool,
) -> Result<StopOutcome, Box<dyn std::error::Error>> {
    let pid_manager = PidFileManager::new();

    if let Some(_content) = pid_manager.read_pid() {
        if pid_manager.is_running() {
            let client =
                CommandClient::new(Some(pid_manager.socket_file_path()), control_addr, use_tls);

            match client.send_command(SupervisorCommand::Stop { graceful: true }) {
                Ok(_msg) => {
                    let mut count = 0;
                    while pid_manager.is_running() && count < 30 {
                        std::thread::sleep(std::time::Duration::from_secs(1));
                        count += 1;
                    }

                    if pid_manager.is_running() {
                        return Ok(StopOutcome {
                            acknowledged: true,
                            shutdown_confirmed: false,
                            timed_out: true,
                        });
                    } else {
                        pid_manager.remove_pid()?;
                        pid_manager.remove_socket()?;
                        return Ok(StopOutcome {
                            acknowledged: true,
                            shutdown_confirmed: true,
                            timed_out: false,
                        });
                    }
                }
                Err(e) => {
                    return Err(format!("Failed to send stop command: {}", e).into());
                }
            }
        }
    }

    Ok(StopOutcome {
        acknowledged: false,
        shutdown_confirmed: false,
        timed_out: false,
    })
}

pub fn handle_stop(
    control_addr: Option<String>,
    use_tls: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let outcome = handle_stop_data(control_addr, use_tls)?;
    if let Some(text) =
        (crate::commands::supervisor_control::SupervisorControlOutcome::Stop(outcome)).display()
    {
        println!("{}", text);
    }
    Ok(())
}

pub fn handle_rehash_data(
    control_addr: Option<String>,
    use_tls: bool,
) -> Result<RehashOutcome, Box<dyn std::error::Error>> {
    let pid_manager = PidFileManager::new();

    if let Some(_content) = pid_manager.read_pid() {
        if pid_manager.is_running() {
            let client =
                CommandClient::new(Some(pid_manager.socket_file_path()), control_addr, use_tls);

            match client.send_command(SupervisorCommand::ReloadConfig) {
                Ok(_msg) => {
                    return Ok(RehashOutcome { acknowledged: true });
                }
                Err(e) => {
                    return Err(format!("Failed to send reload command: {}", e).into());
                }
            }
        }
    }

    Ok(RehashOutcome {
        acknowledged: false,
    })
}

pub fn handle_rehash(
    control_addr: Option<String>,
    use_tls: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let outcome = handle_rehash_data(control_addr, use_tls)?;
    if let Some(text) =
        (crate::commands::supervisor_control::SupervisorControlOutcome::Rehash(outcome)).display()
    {
        println!("{}", text);
    }
    Ok(())
}

pub fn handle_configtest(config_path: &Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let config_dir = config_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("config"));
    let main_config_path = config_dir.join("main.toml");

    println!("Testing configuration files...");

    if !main_config_path.exists() {
        eprintln!("Error: main.toml not found at {:?}", main_config_path);
        std::process::exit(1);
    }

    match MainConfig::from_file(&main_config_path) {
        Ok(_config) => {
            println!("✓ main.toml is valid");

            let sites_dir = config_dir.join("sites");
            if sites_dir.exists() {
                for entry in std::fs::read_dir(&sites_dir)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.extension().map(|e| e == "toml").unwrap_or(false) {
                        match crate::config::site::SiteConfig::from_file(&path) {
                            Ok(_) => {
                                println!(
                                    "✓ {} is valid",
                                    path.file_name().unwrap().to_string_lossy()
                                );
                            }
                            Err(e) => {
                                eprintln!(
                                    "✗ {}: {}",
                                    path.file_name().unwrap().to_string_lossy(),
                                    e
                                );
                                std::process::exit(1);
                            }
                        }
                    }
                }
            }

            println!("\nAll configuration files are valid");
            Ok(())
        }
        Err(e) => {
            eprintln!("✗ main.toml: {}", e);
            std::process::exit(1);
        }
    }
}

pub fn generate_token_hex() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.random()).collect();
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn handle_generatetoken() {
    let token = generate_token_hex();
    println!("{}", token);
}

pub fn handle_generatenewtoken(config_path: &Option<PathBuf>) {
    let token = generate_token_hex();
    println!("{}", token);

    let config_dir = config_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("config"));
    let main_config_path = config_dir.join("main.toml");

    if let Err(e) = std::fs::create_dir_all(&config_dir) {
        eprintln!("Error: Failed to create config directory: {}", e);
        return;
    }

    let content = if main_config_path.exists() {
        match std::fs::read_to_string(&main_config_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error: Failed to read config file: {}", e);
                return;
            }
        }
    } else {
        format!(
            r#"# synvoid Main Configuration
# This file was generated by --generatenewtoken

[server]
host = "0.0.0.0"
port = 8080
trusted_proxies = ["127.0.0.1", "::1"]

[tokio]
worker_threads = "auto"

[http]
header_read_timeout_secs = 10
keep_alive_timeout_secs = 60
max_headers = 128
max_request_line_size = 8192
max_header_size_ingress = 4096
max_header_size_egress = 16384
max_request_size = 1048576
pipeline_limit = 32

[admin]
enabled = true
port = 8081
token = "{}"

[logging]
level = "info"
access_log = true
access_log_format = "json"
retention_days = 5
max_entries_per_file = 50000

[metrics]
enabled = true
port = 9090

[defaults]
[defaults.ratelimit]
mode = "shared"

[defaults.ratelimit.ip]
per_second = 10
per_minute = 60
per_5min = 200
per_10min = 350
per_hour = 500
per_day = 1000
burst = 20

[defaults.ratelimit.global]
per_second = 500
per_minute = 5000
per_5min = 20000
max_connections = 1000

[defaults.blocked]
paths = ["/.env", "/.git", "/wp-login.php"]
use_regex = true
block_methods = ["GET", "POST", "PUT", "DELETE"]

[defaults.worker_pool]
mode = "shared"
workers = 4
worker_port_base = 9000
auto_scale = true
"#,
            token
        )
    };

    let updated_content = if content.contains("[admin]") {
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        let mut in_admin_section = false;
        let mut token_updated = false;

        for line in lines.iter_mut() {
            let trimmed = line.trim();
            if trimmed == "[admin]" {
                in_admin_section = true;
            } else if trimmed.starts_with('[') && trimmed != "[admin]" {
                in_admin_section = false;
            }

            if in_admin_section && trimmed.starts_with("token") && trimmed.contains('=') {
                *line = format!("token = \"{}\"", token);
                token_updated = true;
                break;
            }
        }

        if !token_updated {
            if let Some(pos) = lines.iter().position(|l| l.trim() == "[admin]") {
                lines.insert(pos + 3, format!("token = \"{}\"", token));
            }
        }

        lines.join("\n")
    } else {
        let admin_section = format!(
            "\n[admin]\nenabled = true\nport = 8081\ntoken = \"{}\"\n",
            token
        );
        content + &admin_section
    };

    if let Err(e) = std::fs::write(&main_config_path, &updated_content) {
        eprintln!("Error: Failed to write config file: {}", e);
        return;
    }

    // Restrict permissions on config file since it contains the admin token
    // Note: Token is written before permissions are set, but window is minimal
    // and only affects world-readable during the atomic write operation.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) =
            std::fs::set_permissions(&main_config_path, std::fs::Permissions::from_mode(0o600))
        {
            eprintln!("Warning: Failed to set config file permissions: {}", e);
        }
    }

    tracing::warn!(
        "Admin token is stored in plaintext in the config file. \
         Ensure the file has restricted permissions (0600) and is not world-readable."
    );

    println!("Config file updated: {:?}", main_config_path);
    println!("Admin token has been set in [admin] section");
}

#[cfg(feature = "mesh")]
pub fn handle_export_threat_feed_data(
    sign_with: &Option<PathBuf>,
    site_id: Option<&str>,
) -> Result<ThreatFeedExportSummary, Box<dyn std::error::Error>> {
    let config_dir = PathBuf::from("config");
    let main_config_path = config_dir.join("main.toml");

    if !main_config_path.exists() {
        return Err(format!("Config not found at {:?}", main_config_path).into());
    }

    let main_config = match MainConfig::from_file(&main_config_path) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to load config: {}", e).into()),
    };

    let mesh_config = match main_config.tunnel.mesh {
        Some(m) => m,
        None => return Err("Mesh is not enabled - cannot export threat feed".into()),
    };

    let node_id = mesh_config.node_id();
    let node_role = mesh_config.role;

    let (_signing_key, signer) = if let Some(ref key_path) = sign_with {
        let key_data = std::fs::read(key_path)?;
        if key_data.len() != 32 {
            return Err("Signing key must be 32 bytes (Ed25519)".into());
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_data);
        let signer = MeshMessageSigner::new(key_array);
        (Some(key_array), Some(signer))
    } else if let Some(ref genesis) = mesh_config.genesis_key {
        if let Some(private_key) = &genesis.private_key {
            let signer = MeshMessageSigner::new(*private_key);
            (Some(*private_key), Some(signer))
        } else {
            return Err("No signing key available. Use --sign-with to provide a key file.".into());
        }
    } else if let Some(signing_key_bytes) = mesh_config.signing_key() {
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(signing_key_bytes);
        let signer = MeshMessageSigner::new(key_array);
        (Some(key_array), Some(signer))
    } else {
        return Err("No signing key available. Use --sign-with to provide a key file.".into());
    };

    let threat_intel_config = mesh_config.threat_intel.clone();

    let block_store = Arc::new(crate::block_store::BlockStore::new(
        false,
        None,
        Default::default(),
    ));
    let internal_config: crate::mesh::threat_intel::ThreatIntelligenceConfigInternal =
        serde_json::from_str(&serde_json::to_string(&threat_intel_config).unwrap()).unwrap();

    let node_role_internal: crate::mesh::config::MeshNodeRole =
        serde_json::from_str(&serde_json::to_string(&node_role).unwrap()).unwrap();

    let threat_manager = ThreatIntelligenceManager::new(
        internal_config,
        block_store,
        node_id.clone(),
        node_role_internal,
        signer.as_ref().map(|s| Arc::new(s.clone())),
    );

    let signer = signer.as_ref().expect("Signer was validated above");
    let signer_pk_bytes: [u8; 32] = signer
        .get_public_key_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid public key length")?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&signer_pk_bytes)
        .map_err(|_| "Invalid Ed25519 public key")?;
    let payload = threat_manager.create_signed_feed(site_id, &verifying_key);

    let json = serde_json::to_string_pretty(&payload)?;
    let bytes = json.len();

    Ok(ThreatFeedExportSummary::Written {
        bytes,
        records: None,
    })
}

#[cfg(feature = "mesh")]
pub fn handle_export_threat_feed(
    sign_with: &Option<PathBuf>,
    site_id: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_dir = PathBuf::from("config");
    let main_config_path = config_dir.join("main.toml");

    if !main_config_path.exists() {
        return Err(format!("Config not found at {:?}", main_config_path).into());
    }

    let main_config = match MainConfig::from_file(&main_config_path) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to load config: {}", e).into()),
    };

    let mesh_config = match main_config.tunnel.mesh {
        Some(m) => m,
        None => return Err("Mesh is not enabled - cannot export threat feed".into()),
    };

    let node_id = mesh_config.node_id();
    let node_role = mesh_config.role;

    let (_signing_key, signer) = if let Some(ref key_path) = sign_with {
        let key_data = std::fs::read(key_path)?;
        if key_data.len() != 32 {
            return Err("Signing key must be 32 bytes (Ed25519)".into());
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_data);
        let signer = MeshMessageSigner::new(key_array);
        (Some(key_array), Some(signer))
    } else if let Some(ref genesis) = mesh_config.genesis_key {
        if let Some(private_key) = &genesis.private_key {
            let signer = MeshMessageSigner::new(*private_key);
            (Some(*private_key), Some(signer))
        } else {
            return Err("No signing key available. Use --sign-with to provide a key file.".into());
        }
    } else if let Some(signing_key_bytes) = mesh_config.signing_key() {
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(signing_key_bytes);
        let signer = MeshMessageSigner::new(key_array);
        (Some(key_array), Some(signer))
    } else {
        return Err("No signing key available. Use --sign-with to provide a key file.".into());
    };

    let threat_intel_config = mesh_config.threat_intel.clone();

    let block_store = Arc::new(crate::block_store::BlockStore::new(
        false,
        None,
        Default::default(),
    ));
    let internal_config: crate::mesh::threat_intel::ThreatIntelligenceConfigInternal =
        serde_json::from_str(&serde_json::to_string(&threat_intel_config).unwrap()).unwrap();

    let node_role_internal: crate::mesh::config::MeshNodeRole =
        serde_json::from_str(&serde_json::to_string(&node_role).unwrap()).unwrap();

    let threat_manager = ThreatIntelligenceManager::new(
        internal_config,
        block_store,
        node_id.clone(),
        node_role_internal,
        signer.as_ref().map(|s| Arc::new(s.clone())),
    );

    let signer = signer.as_ref().expect("Signer was validated above");
    let signer_pk_bytes: [u8; 32] = signer
        .get_public_key_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid public key length")?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&signer_pk_bytes)
        .map_err(|_| "Invalid Ed25519 public key")?;
    let payload = threat_manager.create_signed_feed(site_id, &verifying_key);

    let json = serde_json::to_string_pretty(&payload)?;
    println!("{}", json);

    Ok(())
}
