use std::path::PathBuf;

use crate::config::main::MainConfig;
use crate::process::{CommandClient, MasterCommand, PidFileManager};

pub fn handle_status() -> Result<(), Box<dyn std::error::Error>> {
    let pid_manager = PidFileManager::new();

    if let Some(content) = pid_manager.read_pid() {
        if pid_manager.is_running() {
            let client = CommandClient::new(Some(pid_manager.socket_file_path()));

            match client.get_status() {
                Ok(status) => {
                    println!("RustWAF Status");
                    println!("==============");
                    println!("Master PID: {}", status.master_pid);
                    println!("Version: {}", status.version);
                    println!("Uptime: {} seconds", status.uptime_secs);
                    println!("");
                    println!("Workers:");
                    println!(
                        "  {:<4} {:<8} {:<6} {:<10} {:<12} {:<10}",
                        "ID", "PID", "Port", "Status", "Requests", "Blocked"
                    );
                    println!("  {}", "-".repeat(60));
                    for worker in &status.workers {
                        println!(
                            "  {:<4} {:<8} {:<6} {:<10} {:<12} {:<10}",
                            worker.id,
                            worker.pid,
                            worker.port,
                            worker.status,
                            worker.requests,
                            worker.blocked
                        );
                    }
                    println!("");
                    println!("Stats (last hour):");
                    println!("  Total Requests:    {}", status.stats.total_requests);
                    println!(
                        "  Blocked:           {} ({:.1}%)",
                        status.stats.blocked_last_hour,
                        if status.stats.total_requests > 0 {
                            (status.stats.blocked_last_hour as f64
                                / status.stats.total_requests as f64)
                                * 100.0
                        } else {
                            0.0
                        }
                    );
                    println!("  Challenged:        {}", status.stats.challenged_last_hour);
                    println!("  Proxied:           {}", status.stats.proxied_last_hour);
                    println!("");
                    println!("Threat Summary:");
                    println!("  Active Blocks:     {}", status.stats.active_blocks);
                    println!(
                        "  Critical IPs:      {}",
                        status.threat_summary.critical_ips
                    );
                    println!("  Elevated IPs:     {}", status.threat_summary.elevated_ips);

                    return Ok(());
                }
                Err(e) => {
                    println!(
                        "RustWAF appears to be running but status is unavailable: {}",
                        e
                    );
                    println!("PID: {}", content.pid);
                    return Ok(());
                }
            }
        }
    }

    println!("RustWAF is not running");
    Ok(())
}

pub fn handle_stop() -> Result<(), Box<dyn std::error::Error>> {
    let pid_manager = PidFileManager::new();

    if let Some(_content) = pid_manager.read_pid() {
        if pid_manager.is_running() {
            let client = CommandClient::new(Some(pid_manager.socket_file_path()));

            match client.send_command(MasterCommand::Stop { graceful: true }) {
                Ok(msg) => {
                    println!("Stop signal sent: {}", msg);
                    println!("Waiting for shutdown...");

                    let mut count = 0;
                    while pid_manager.is_running() && count < 30 {
                        std::thread::sleep(std::time::Duration::from_secs(1));
                        count += 1;
                    }

                    if pid_manager.is_running() {
                        println!("Warning: Process did not shut down cleanly");
                    } else {
                        println!("RustWAF stopped");
                        pid_manager.remove_pid()?;
                        pid_manager.remove_socket()?;
                    }
                }
                Err(e) => {
                    println!("Failed to send stop command: {}", e);
                }
            }
            return Ok(());
        }
    }

    println!("RustWAF is not running");
    Ok(())
}

pub fn handle_rehash() -> Result<(), Box<dyn std::error::Error>> {
    let pid_manager = PidFileManager::new();

    if let Some(_content) = pid_manager.read_pid() {
        if pid_manager.is_running() {
            let client = CommandClient::new(Some(pid_manager.socket_file_path()));

            match client.send_command(MasterCommand::ReloadConfig) {
                Ok(msg) => {
                    println!("Reload signal sent: {}", msg);
                }
                Err(e) => {
                    println!("Failed to send reload command: {}", e);
                }
            }
            return Ok(());
        }
    }

    println!("RustWAF is not running");
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
        let default_config = r#"# RustWAF Main Configuration
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
token = "TOKEN_PLACEHOLDER"

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
"#;
        default_config.to_string()
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

    println!("Config file updated: {:?}", main_config_path);
    println!("Admin token has been set in [admin] section");
}
