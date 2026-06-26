//! Typed one-shot command outcome and error boundary.
//!
//! This module owns the boundary between CLI command execution and
//! one-shot command handlers. It converts typed one-shot commands
//! into structured outcomes rather than ad-hoc strings or raw exit codes.
//!
//! ## Boundary Model
//!
//! ```text
//! OneShotCommand -> execute_one_shot_command()
//!     -> Result<OneShotOutcome, OneShotError>
//!     -> exit code
//! ```

use std::path::PathBuf;

use super::plan::OneShotCommand;

/// Typed outcome from a successfully executed one-shot command.
///
/// Each variant carries structured data where practical. The `exit_code()`
/// method maps outcomes to process exit codes in one place, and `display()`
/// centralizes CLI formatting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OneShotOutcome {
    /// Config validation passed.
    ConfigValid,
    /// OpenAPI schema exported as JSON.
    OpenApiJson(String),
    /// API specification exported as JSON.
    ApiSpecJson(String),
    /// A genesis key was generated.
    GenesisKeyGenerated {
        /// The formatted display text for the genesis key.
        display: String,
    },
    /// Node information was queried.
    NodeInfo {
        /// The formatted display text for the node information.
        display: String,
    },
    /// A token was generated (hex string).
    TokenGenerated {
        /// The generated token hex string.
        token: String,
    },
    /// A new token was generated and saved to config.
    NewTokenGenerated {
        /// The generated token hex string.
        token: String,
        /// The config path that was updated.
        config_path: String,
    },
    /// A token was hashed with bcrypt.
    TokenHash {
        /// The bcrypt hash string.
        hash: String,
    },
    /// A regex pattern was checked for ReDoS safety.
    RegexCheck {
        /// Whether the pattern is safe.
        safe: bool,
        /// The pattern that was checked.
        pattern: String,
        /// The reason the pattern is unsafe, if applicable.
        reason: Option<String>,
    },
}

impl OneShotOutcome {
    /// Map this outcome to a process exit code.
    ///
    /// All success outcomes return 0. This centralizes exit-code mapping
    /// so the CLI execution layer does not need per-command knowledge.
    pub fn exit_code(&self) -> i32 {
        match self {
            OneShotOutcome::ConfigValid
            | OneShotOutcome::OpenApiJson(_)
            | OneShotOutcome::ApiSpecJson(_)
            | OneShotOutcome::GenesisKeyGenerated { .. }
            | OneShotOutcome::NodeInfo { .. }
            | OneShotOutcome::TokenGenerated { .. }
            | OneShotOutcome::NewTokenGenerated { .. }
            | OneShotOutcome::TokenHash { .. } => 0,
            // Unsafe regex exits non-zero to indicate the pattern is unsafe.
            OneShotOutcome::RegexCheck { safe, .. } => {
                if *safe {
                    0
                } else {
                    1
                }
            }
        }
    }

    /// Format this outcome for user-facing display.
    ///
    /// Centralizes CLI formatting so handlers return data, not side effects.
    /// Returns `Some(text)` when there is user-visible output.
    pub fn display(&self) -> Option<String> {
        match self {
            OneShotOutcome::ConfigValid => Some("All configuration files are valid".to_string()),
            OneShotOutcome::OpenApiJson(json) => Some(json.clone()),
            OneShotOutcome::ApiSpecJson(json) => Some(json.clone()),
            OneShotOutcome::GenesisKeyGenerated { display } => Some(display.clone()),
            OneShotOutcome::NodeInfo { display } => Some(display.clone()),
            OneShotOutcome::TokenGenerated { token } => Some(token.clone()),
            OneShotOutcome::NewTokenGenerated { token, config_path } => {
                let mut text = token.clone();
                text.push_str(&format!("\nConfig file updated: {}", config_path));
                text.push_str("\nAdmin token has been set in [admin] section");
                Some(text)
            }
            OneShotOutcome::TokenHash { hash } => Some(hash.clone()),
            OneShotOutcome::RegexCheck {
                safe,
                pattern,
                reason,
            } => {
                if *safe {
                    Some(format!("✓ Pattern is safe: {}", pattern))
                } else {
                    let mut text = format!("✗ Pattern is UNSAFE: {}", pattern);
                    if let Some(r) = reason {
                        text.push_str(&format!("\n  Reason: {}", r));
                    }
                    Some(text)
                }
            }
        }
    }
}

/// Typed error from a failed one-shot command.
///
/// Each variant classifies the failure mode so the CLI execution layer
/// can produce meaningful messages and consistent exit codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OneShotError {
    /// Config validation failed.
    ConfigInvalid(String),
    /// JSON serialization failed.
    Serialization(String),
    /// A required feature is not enabled.
    UnsupportedFeature(&'static str),
    /// An I/O error occurred.
    Io(String),
    /// Token hashing failed.
    TokenHash(String),
    /// The regex pattern is unsafe.
    RegexUnsafe(String),
    /// An unclassified error occurred.
    Unknown(String),
}

impl std::fmt::Display for OneShotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OneShotError::ConfigInvalid(msg) => write!(f, "Config test failed: {}", msg),
            OneShotError::Serialization(msg) => write!(f, "Serialization error: {}", msg),
            OneShotError::UnsupportedFeature(feature) => {
                write!(
                    f,
                    "This command requires the {} feature to be enabled.",
                    feature
                )
            }
            OneShotError::Io(msg) => write!(f, "I/O error: {}", msg),
            OneShotError::TokenHash(msg) => write!(f, "Error hashing token: {}", msg),
            OneShotError::RegexUnsafe(msg) => write!(f, "Regex check error: {}", msg),
            OneShotError::Unknown(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for OneShotError {}

impl OneShotError {
    /// Map this error to a process exit code.
    ///
    /// All errors return 1 for backwards compatibility. Variant-specific
    /// exit codes may be introduced after a compatibility review.
    pub fn exit_code(&self) -> i32 {
        1
    }
}

/// Execute a one-shot command and return a typed outcome.
///
/// This adapter function dispatches to existing handler functions and
/// wraps their results in structured types. It centralizes the execution
/// boundary for all one-shot commands.
///
/// # Arguments
///
/// * `command` - A typed one-shot command from the planning layer.
///
/// # Returns
///
/// A typed outcome on success, or a typed error on failure.
pub fn execute_one_shot_command(command: OneShotCommand) -> Result<OneShotOutcome, OneShotError> {
    match command {
        OneShotCommand::ConfigTest => execute_config_test(),
        OneShotCommand::ExportOpenApi => execute_export_openapi(),
        OneShotCommand::ExportApiSpec => execute_export_api_spec(),
        OneShotCommand::Genesis => execute_genesis(),
        OneShotCommand::ShowNodeInfo => execute_show_node_info(),
        OneShotCommand::GenerateToken => execute_generate_token(),
        OneShotCommand::GenerateNewToken { config_path } => execute_generate_new_token(config_path),
        OneShotCommand::HashToken { token, cost } => execute_hash_token(token, cost),
        OneShotCommand::CheckRegex { pattern } => execute_check_regex(pattern),
    }
}

fn execute_config_test() -> Result<OneShotOutcome, OneShotError> {
    let config_dir = std::env::current_dir()
        .map_err(|e| OneShotError::Io(format!("Failed to get current directory: {}", e)))?
        .join("config");
    let main_config_path = config_dir.join("main.toml");

    if !main_config_path.exists() {
        return Err(OneShotError::ConfigInvalid(format!(
            "main.toml not found at {:?}",
            main_config_path
        )));
    }

    let _config = synvoid_config::MainConfig::from_file(&main_config_path)
        .map_err(|e| OneShotError::ConfigInvalid(format!("main.toml: {}", e)))?;

    let sites_dir = config_dir.join("sites");
    if sites_dir.exists() {
        let entries: Vec<_> = std::fs::read_dir(&sites_dir)
            .map_err(|e| OneShotError::Io(format!("Failed to read sites dir: {}", e)))?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "toml")
                    .unwrap_or(false)
            })
            .collect();

        for entry in entries {
            let path = entry.path();
            crate::config::site::SiteConfig::from_file(&path).map_err(|e| {
                OneShotError::ConfigInvalid(format!(
                    "{}: {}",
                    path.file_name().unwrap().to_string_lossy(),
                    e
                ))
            })?;
        }
    }

    Ok(OneShotOutcome::ConfigValid)
}

fn execute_export_openapi() -> Result<OneShotOutcome, OneShotError> {
    use crate::config::MainConfig;

    let schema = schemars::schema_for!(MainConfig);
    let json = serde_json::to_string_pretty(&schema)
        .map_err(|e| OneShotError::Serialization(e.to_string()))?;
    Ok(OneShotOutcome::OpenApiJson(json))
}

fn execute_export_api_spec() -> Result<OneShotOutcome, OneShotError> {
    use crate::admin::openapi::synvoidOpenApi;

    let spec = synvoidOpenApi::openapi_json();
    let json = serde_json::to_string_pretty(&spec.0)
        .map_err(|e| OneShotError::Serialization(e.to_string()))?;
    Ok(OneShotOutcome::ApiSpecJson(json))
}

#[cfg(feature = "mesh")]
fn execute_genesis() -> Result<OneShotOutcome, OneShotError> {
    use crate::mesh::config::GenesisKeyConfig;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let genesis = GenesisKeyConfig::generate();
    let private_key = genesis.private_key.ok_or_else(|| {
        OneShotError::Unknown("Genesis key generation did not produce a private key".to_string())
    })?;
    let genesis_b64 = URL_SAFE_NO_PAD.encode(private_key);

    let display = format!(
        "Genesis key generated successfully.\n\
         \n\
         IMPORTANT: This genesis key is the root of trust for your mesh network.\n\
         \t  Store it securely - it will be needed to add additional global nodes.\n\
         \n\
         Genesis key (base64): {}\n\
         \n\
         To use this genesis key, add the following to your config/main.toml:\n\
         \n\
         \t[mesh.node_identity]\n\
         \tgenesis_key_base64 = \"{}\"\n",
        genesis_b64, genesis_b64
    );

    Ok(OneShotOutcome::GenesisKeyGenerated { display })
}

#[cfg(not(feature = "mesh"))]
fn execute_genesis() -> Result<OneShotOutcome, OneShotError> {
    Err(OneShotError::UnsupportedFeature("mesh"))
}

#[cfg(feature = "mesh")]
fn execute_show_node_info() -> Result<OneShotOutcome, OneShotError> {
    use crate::config::MainConfig;

    let config_path = PathBuf::from("config");
    let main_config_path = config_path.join("main.toml");

    if !main_config_path.exists() {
        return Err(OneShotError::Io(format!(
            "No config found at {}. Run with --genesis first to generate genesis key.",
            main_config_path.display()
        )));
    }

    let config = MainConfig::from_file(&main_config_path)
        .map_err(|e| OneShotError::Io(format!("Error loading config: {}", e)))?;

    let mut lines = Vec::new();
    lines.push("Node Information:".to_string());
    lines.push("================".to_string());
    lines.push(String::new());

    if let Some(ref mesh) = config.tunnel.mesh {
        lines.push(format!("Mesh Role: {:?}", mesh.role));
        lines.push(format!("Node ID: {}", mesh.node_id()));
        lines.push(format!("Router ID: {}", mesh.router_id()));

        if let Some(ref genesis) = mesh.genesis_key {
            lines.push(format!(
                "Genesis Key: configured (public: {:?})",
                genesis
                    .get_public_key()
                    .map(|pk| format!("{}...", &pk[..16.min(pk.len())]))
            ));
        } else {
            lines.push("Genesis Key: NOT configured".to_string());
        }

        if mesh.node_identity.genesis_key_base64.is_some() {
            lines.push("Genesis Key Base64: configured in node_identity".to_string());
        }

        if mesh.has_signing_key() {
            if let Some(ref pk) = mesh.signing_public_key() {
                lines.push(format!(
                    "Signing Public Key: {}...",
                    hex::encode(&pk[..16.min(pk.len())])
                ));
            }
        } else {
            lines
                .push("Signing Key: NOT configured (edge/origin node without genesis)".to_string());
        }
    } else {
        lines.push("Mesh: NOT enabled".to_string());
    }

    Ok(OneShotOutcome::NodeInfo {
        display: lines.join("\n"),
    })
}

#[cfg(not(feature = "mesh"))]
fn execute_show_node_info() -> Result<OneShotOutcome, OneShotError> {
    Err(OneShotError::UnsupportedFeature("mesh"))
}

fn execute_generate_token() -> Result<OneShotOutcome, OneShotError> {
    let token = generate_token_hex();
    Ok(OneShotOutcome::TokenGenerated { token })
}

fn execute_generate_new_token(
    config_path: Option<PathBuf>,
) -> Result<OneShotOutcome, OneShotError> {
    let token = generate_token_hex();

    let config_dir = config_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("config"));
    let main_config_path = config_dir.join("main.toml");

    std::fs::create_dir_all(&config_dir)
        .map_err(|e| OneShotError::Io(format!("Failed to create config directory: {}", e)))?;

    let content = if main_config_path.exists() {
        std::fs::read_to_string(&main_config_path)
            .map_err(|e| OneShotError::Io(format!("Failed to read config file: {}", e)))?
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

    std::fs::write(&main_config_path, &updated_content)
        .map_err(|e| OneShotError::Io(format!("Failed to write config file: {}", e)))?;

    // Restrict permissions on config file since it contains the admin token.
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

    Ok(OneShotOutcome::NewTokenGenerated {
        token,
        config_path: main_config_path.display().to_string(),
    })
}

fn execute_hash_token(token: String, cost: u32) -> Result<OneShotOutcome, OneShotError> {
    use crate::admin::hash_admin_token_with_cost;

    let hash = hash_admin_token_with_cost(&token, cost)
        .map_err(|e| OneShotError::TokenHash(e.to_string()))?;
    Ok(OneShotOutcome::TokenHash { hash })
}

fn execute_check_regex(pattern: String) -> Result<OneShotOutcome, OneShotError> {
    use crate::utils::check_regex_complexity;

    let result = check_regex_complexity(&pattern);
    Ok(OneShotOutcome::RegexCheck {
        safe: result.safe,
        pattern,
        reason: result.reason,
    })
}

fn generate_token_hex() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.random()).collect();
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_hash_outcome_prints_hash_only() {
        let outcome = OneShotOutcome::TokenHash {
            hash: "$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12".to_string(),
        };
        let display = outcome.display().unwrap();
        assert_eq!(
            display,
            "$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12"
        );
    }

    #[test]
    fn regex_safe_exits_zero() {
        let outcome = OneShotOutcome::RegexCheck {
            safe: true,
            pattern: r"\d+".to_string(),
            reason: None,
        };
        assert_eq!(outcome.exit_code(), 0);
    }

    #[test]
    fn regex_unsafe_exits_nonzero() {
        let outcome = OneShotOutcome::RegexCheck {
            safe: false,
            pattern: r"(.*+)+".to_string(),
            reason: Some("ReDoS risk".to_string()),
        };
        assert_eq!(outcome.exit_code(), 1);
    }

    #[test]
    fn openapi_outcome_prints_json_payload() {
        let json = r#"{"$schema":"http://json-schema.org/draft-07/schema#"}"#.to_string();
        let outcome = OneShotOutcome::OpenApiJson(json.clone());
        assert_eq!(outcome.display().unwrap(), json);
    }

    #[test]
    fn api_spec_outcome_prints_json_payload() {
        let json = r#"{"openapi":"3.0.0","info":{"title":"SynVoid"}}"#.to_string();
        let outcome = OneShotOutcome::ApiSpecJson(json.clone());
        assert_eq!(outcome.display().unwrap(), json);
    }

    #[test]
    fn token_generated_displays_hex() {
        let outcome = OneShotOutcome::TokenGenerated {
            token: "abcdef0123456789".to_string(),
        };
        assert_eq!(outcome.display().unwrap(), "abcdef0123456789");
    }

    #[test]
    fn new_token_generated_displays_token_and_config() {
        let outcome = OneShotOutcome::NewTokenGenerated {
            token: "abcdef0123456789".to_string(),
            config_path: "config/main.toml".to_string(),
        };
        let display = outcome.display().unwrap();
        assert!(display.contains("abcdef0123456789"));
        assert!(display.contains("config/main.toml"));
        assert!(display.contains("Admin token has been set"));
    }

    #[test]
    fn config_valid_exit_code_is_zero() {
        let outcome = OneShotOutcome::ConfigValid;
        assert_eq!(outcome.exit_code(), 0);
    }

    #[test]
    fn genesis_key_generated_displays_full_text() {
        let outcome = OneShotOutcome::GenesisKeyGenerated {
            display: "Genesis key generated successfully.\nKey: abc123".to_string(),
        };
        let display = outcome.display().unwrap();
        assert!(display.contains("Genesis key generated successfully"));
        assert!(display.contains("Key: abc123"));
    }

    #[test]
    fn node_info_displays_full_text() {
        let outcome = OneShotOutcome::NodeInfo {
            display: "Node Information:\n================\n\nMesh: NOT enabled".to_string(),
        };
        let display = outcome.display().unwrap();
        assert!(display.contains("Node Information"));
        assert!(display.contains("Mesh: NOT enabled"));
    }

    #[test]
    fn errors_exit_nonzero() {
        let errors = [
            OneShotError::ConfigInvalid("test".into()),
            OneShotError::Serialization("test".into()),
            OneShotError::UnsupportedFeature("mesh"),
            OneShotError::Io("test".into()),
            OneShotError::TokenHash("test".into()),
            OneShotError::RegexUnsafe("test".into()),
            OneShotError::Unknown("test".into()),
        ];
        for error in &errors {
            assert_eq!(error.exit_code(), 1, "expected exit code 1 for {:?}", error);
        }
    }

    #[test]
    fn error_display_messages() {
        let err = OneShotError::ConfigInvalid("main.toml: missing key".into());
        assert_eq!(
            err.to_string(),
            "Config test failed: main.toml: missing key"
        );

        let err = OneShotError::Serialization("unexpected token".into());
        assert_eq!(err.to_string(), "Serialization error: unexpected token");

        let err = OneShotError::UnsupportedFeature("mesh");
        assert_eq!(
            err.to_string(),
            "This command requires the mesh feature to be enabled."
        );

        let err = OneShotError::Io("permission denied".into());
        assert_eq!(err.to_string(), "I/O error: permission denied");

        let err = OneShotError::TokenHash("bcrypt failed".into());
        assert_eq!(err.to_string(), "Error hashing token: bcrypt failed");

        let err = OneShotError::RegexUnsafe("pattern too long".into());
        assert_eq!(err.to_string(), "Regex check error: pattern too long");

        let err = OneShotError::Unknown("something happened".into());
        assert_eq!(err.to_string(), "Error: something happened");
    }

    #[test]
    fn regex_safe_display() {
        let outcome = OneShotOutcome::RegexCheck {
            safe: true,
            pattern: r"\d+".to_string(),
            reason: None,
        };
        assert_eq!(outcome.display().unwrap(), "✓ Pattern is safe: \\d+");
    }

    #[test]
    fn regex_unsafe_display_with_reason() {
        let outcome = OneShotOutcome::RegexCheck {
            safe: false,
            pattern: r"(.*+)+".to_string(),
            reason: Some("ReDoS risk: nested quantifiers".to_string()),
        };
        let display = outcome.display().unwrap();
        assert!(display.contains("✗ Pattern is UNSAFE"));
        assert!(display.contains("(.*+)+"));
        assert!(display.contains("ReDoS risk: nested quantifiers"));
    }

    #[test]
    fn all_outcome_variants_are_exhaustive_display() {
        let outcomes: Vec<OneShotOutcome> = vec![
            OneShotOutcome::ConfigValid,
            OneShotOutcome::OpenApiJson("{}".into()),
            OneShotOutcome::ApiSpecJson("{}".into()),
            OneShotOutcome::GenesisKeyGenerated {
                display: "key".into(),
            },
            OneShotOutcome::NodeInfo {
                display: "info".into(),
            },
            OneShotOutcome::TokenGenerated {
                token: "abc".into(),
            },
            OneShotOutcome::NewTokenGenerated {
                token: "abc".into(),
                config_path: "path".into(),
            },
            OneShotOutcome::TokenHash {
                hash: "hash".into(),
            },
            OneShotOutcome::RegexCheck {
                safe: true,
                pattern: "pat".into(),
                reason: None,
            },
        ];
        for o in &outcomes {
            // display must not panic
            let _ = o.display();
            // exit_code must be valid
            let _ = o.exit_code();
        }
    }

    #[test]
    fn all_error_variants_are_exhaustive_display() {
        let errors: Vec<OneShotError> = vec![
            OneShotError::ConfigInvalid("t".into()),
            OneShotError::Serialization("t".into()),
            OneShotError::UnsupportedFeature("t"),
            OneShotError::Io("t".into()),
            OneShotError::TokenHash("t".into()),
            OneShotError::RegexUnsafe("t".into()),
            OneShotError::Unknown("t".into()),
        ];
        for e in &errors {
            // Display must not panic
            let _ = e.to_string();
            // exit_code must be 1
            assert_eq!(e.exit_code(), 1);
        }
    }

    // --- Output contract tests (Iteration 109) ---

    #[test]
    fn openapi_outcome_stdout_is_json_only() {
        let json = r#"{"$schema":"http://json-schema.org/draft-07/schema#","type":"object"}"#;
        let outcome = OneShotOutcome::OpenApiJson(json.to_string());
        let display = outcome.display().unwrap();
        // Must start with JSON structural character
        assert!(
            display.starts_with('{') || display.starts_with('['),
            "OpenAPI output must start with JSON, got: {:?}",
            &display[..20.min(display.len())]
        );
        // Must parse as valid JSON
        assert!(
            serde_json::from_str::<serde_json::Value>(&display).is_ok(),
            "OpenAPI output must be valid JSON"
        );
        // Must not contain human preamble
        assert!(
            !display.contains("OpenAPI schema"),
            "OpenAPI output must not contain human preamble 'OpenAPI schema'"
        );
        assert!(
            !display.contains("Exported"),
            "OpenAPI output must not contain human preamble 'Exported'"
        );
    }

    #[test]
    fn api_spec_outcome_stdout_is_json_only() {
        let json = r#"{"openapi":"3.0.0","info":{"title":"SynVoid","version":"1.0"}}"#;
        let outcome = OneShotOutcome::ApiSpecJson(json.to_string());
        let display = outcome.display().unwrap();
        assert!(
            display.starts_with('{') || display.starts_with('['),
            "API spec output must start with JSON, got: {:?}",
            &display[..20.min(display.len())]
        );
        assert!(
            serde_json::from_str::<serde_json::Value>(&display).is_ok(),
            "API spec output must be valid JSON"
        );
        assert!(
            !display.contains("Schema"),
            "API spec output must not contain human preamble 'Schema'"
        );
    }

    #[test]
    fn hash_token_outcome_stdout_is_hash_only() {
        let hash = "$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12";
        let outcome = OneShotOutcome::TokenHash {
            hash: hash.to_string(),
        };
        let display = outcome.display().unwrap();
        // Exactly one line, no labels
        assert_eq!(display, hash);
        assert!(
            !display.contains("Hash:"),
            "hash output must not be labeled"
        );
        assert!(
            !display.contains("Token:"),
            "hash output must not contain 'Token:'"
        );
        assert!(!display.contains('\n'), "hash output must be a single line");
    }

    #[test]
    fn generated_token_outcome_stdout_is_token_only() {
        let token = "abcdef0123456789abcdef0123456789";
        let outcome = OneShotOutcome::TokenGenerated {
            token: token.to_string(),
        };
        let display = outcome.display().unwrap();
        assert_eq!(display, token);
        assert!(
            !display.contains("Token:"),
            "token output must not be labeled"
        );
        assert!(
            !display.contains('\n'),
            "token output must be a single line"
        );
    }

    #[test]
    fn new_token_generated_first_line_is_token() {
        let token = "abcdef0123456789abcdef0123456789";
        let outcome = OneShotOutcome::NewTokenGenerated {
            token: token.to_string(),
            config_path: "config/main.toml".to_string(),
        };
        let display = outcome.display().unwrap();
        let first_line = display.lines().next().unwrap();
        assert_eq!(
            first_line, token,
            "first line of generatenewtoken output must be the token"
        );
    }

    #[test]
    fn new_token_generated_mentions_config_path() {
        let outcome = OneShotOutcome::NewTokenGenerated {
            token: "abcdef0123456789abcdef0123456789".to_string(),
            config_path: "config/main.toml".to_string(),
        };
        let display = outcome.display().unwrap();
        assert!(
            display.contains("config/main.toml"),
            "generatenewtoken output must mention config path"
        );
    }

    #[test]
    fn new_token_generated_exit_code_zero() {
        let outcome = OneShotOutcome::NewTokenGenerated {
            token: "abcdef0123456789abcdef0123456789".to_string(),
            config_path: "config/main.toml".to_string(),
        };
        assert_eq!(outcome.exit_code(), 0);
    }

    #[test]
    fn config_valid_exit_code_is_zero_and_no_contamination() {
        let outcome = OneShotOutcome::ConfigValid;
        assert_eq!(outcome.exit_code(), 0);
        let display = outcome.display().unwrap();
        assert!(
            !display.contains("Token"),
            "configtest output must not contain token text"
        );
        assert!(
            !display.contains("Hash"),
            "configtest output must not contain hash text"
        );
        assert!(
            !display.starts_with('{'),
            "configtest output must not be JSON"
        );
    }

    #[test]
    fn regex_safe_display_contains_safe_label() {
        let outcome = OneShotOutcome::RegexCheck {
            safe: true,
            pattern: r"\d+".to_string(),
            reason: None,
        };
        let display = outcome.display().unwrap();
        assert!(display.contains("Pattern is safe"));
        assert!(display.contains(r"\d+"));
    }

    #[test]
    fn regex_unsafe_display_contains_unsafe_label() {
        let outcome = OneShotOutcome::RegexCheck {
            safe: false,
            pattern: r"(.*+)+".to_string(),
            reason: Some("nested quantifiers".to_string()),
        };
        let display = outcome.display().unwrap();
        assert!(display.contains("Pattern is UNSAFE"));
        assert!(display.contains("(.*+)+"));
    }

    #[test]
    fn regex_unsafe_with_reason_includes_reason() {
        let outcome = OneShotOutcome::RegexCheck {
            safe: false,
            pattern: r"(.*+)+".to_string(),
            reason: Some("ReDoS risk: nested quantifiers".to_string()),
        };
        let display = outcome.display().unwrap();
        assert!(display.contains("ReDoS risk: nested quantifiers"));
    }

    #[test]
    fn regex_unsafe_without_reason_omits_reason_line() {
        let outcome = OneShotOutcome::RegexCheck {
            safe: false,
            pattern: r"(.*+)+".to_string(),
            reason: None,
        };
        let display = outcome.display().unwrap();
        assert!(display.contains("Pattern is UNSAFE"));
        assert!(
            !display.contains("Reason:"),
            "regex without reason must not print 'Reason:' line"
        );
    }

    #[test]
    fn regex_exit_codes_are_correct() {
        let safe = OneShotOutcome::RegexCheck {
            safe: true,
            pattern: r"\d+".to_string(),
            reason: None,
        };
        let unsafe_outcome = OneShotOutcome::RegexCheck {
            safe: false,
            pattern: r"(.*+)+".to_string(),
            reason: None,
        };
        assert_eq!(safe.exit_code(), 0);
        assert_eq!(unsafe_outcome.exit_code(), 1);
    }

    #[test]
    fn genesis_key_generated_shape() {
        let outcome = OneShotOutcome::GenesisKeyGenerated {
            display: "Genesis key generated successfully.\n\
                      \n\
                      IMPORTANT: This genesis key is the root of trust for your mesh network.\n\
                      \t  Store it securely.\n\
                      \n\
                      Genesis key (base64): abc123def456\n\
                      \n\
                      To use this genesis key, add the following to your config/main.toml:\n\
                      \n\
                      \t[mesh.node_identity]\n\
                      \tgenesis_key_base64 = \"abc123def456\"\n"
                .to_string(),
        };
        let display = outcome.display().unwrap();
        assert!(display.contains("Genesis key generated successfully"));
        assert!(display.contains("genesis_key_base64"));
        assert!(display.contains("abc123def456"));
    }

    #[test]
    fn node_info_shape() {
        let outcome = OneShotOutcome::NodeInfo {
            display: "Node Information:\n\
                      \n\
                      Mesh: NOT enabled"
                .to_string(),
        };
        let display = outcome.display().unwrap();
        assert!(display.contains("Node Information:"));
        assert!(display.contains("Mesh: NOT enabled"));
    }

    #[test]
    fn node_info_with_mesh_enabled_shape() {
        let outcome = OneShotOutcome::NodeInfo {
            display: "Node Information:\n\
                      \n\
                      Mesh Role: Global\n\
                      Node ID: node-1\n\
                      Router ID: router-1"
                .to_string(),
        };
        let display = outcome.display().unwrap();
        assert!(display.contains("Node Information:"));
        assert!(display.contains("Mesh Role:"));
    }
}
