use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::validation::ConfigValidationError;

fn default_ipc_enforce_signing() -> bool {
    true
}

fn default_global_security_headers() -> bool {
    true
}

/// Worker filesystem-sandbox policy (`[security] worker_sandbox`).
///
/// Phase 08 (production-readiness remediation) makes the main data-plane
/// Worker's in-process filesystem confinement an explicit, typed choice
/// instead of an undocumented composition decision.
///
/// The default is `Off`: the worker has not been qualified under Landlock for
/// every deployment shape (child jail/app-server processes, custom static
/// roots, operator-provided YARA/rule directories), so silently enabling it
/// would be a startup-risk regression. `Auto` and `Required` are opt-in and
/// are enforced only when the platform backend can express the requested
/// filesystem guarantees.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema, ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum WorkerSandboxMode {
    /// No in-process filesystem sandbox is applied.
    #[default]
    Off,
    /// Apply the worker filesystem sandbox when the backend fully enforces
    /// the requested filesystem guarantees; otherwise log the enforcement
    /// report and continue without it.
    Auto,
    /// Fail worker startup unless the backend fully enforces the requested
    /// filesystem guarantees.
    Required,
}

impl WorkerSandboxMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Auto => "auto",
            Self::Required => "required",
        }
    }
}

fn default_worker_sandbox() -> WorkerSandboxMode {
    WorkerSandboxMode::default()
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema, ToSchema)]
pub struct MainSecurityConfig {
    #[serde(default)]
    pub more_clear_headers: Vec<String>,
    #[serde(default = "default_sanitize_forwarded")]
    pub sanitize_forwarded_headers: bool,
    #[serde(default = "default_global_security_headers")]
    pub global_security_headers: bool,
    #[serde(default = "default_ipc_enforce_signing")]
    pub ipc_enforce_signing: bool,
    #[serde(default)]
    pub ipc_session_key_env: Option<String>,
    #[serde(default)]
    pub allow_insecure_ipc_key: bool,
    #[serde(default)]
    pub strict_tls_passthrough_policy: bool,
    /// Worker filesystem-sandbox policy. See [`WorkerSandboxMode`].
    #[serde(default = "default_worker_sandbox")]
    pub worker_sandbox: WorkerSandboxMode,
}

impl Default for MainSecurityConfig {
    /// Hand-written so the struct default matches the serde field defaults.
    ///
    /// The derive produced `false` for `ipc_enforce_signing`,
    /// `sanitize_forwarded_headers` and `global_security_headers` where TOML
    /// parsing produced `true` — a fail-open default on an authentication
    /// boundary for any construction path that used `default()` instead of a
    /// parsed file.
    fn default() -> Self {
        Self {
            more_clear_headers: Vec::new(),
            sanitize_forwarded_headers: default_sanitize_forwarded(),
            global_security_headers: default_global_security_headers(),
            ipc_enforce_signing: default_ipc_enforce_signing(),
            ipc_session_key_env: None,
            allow_insecure_ipc_key: false,
            strict_tls_passthrough_policy: false,
            worker_sandbox: default_worker_sandbox(),
        }
    }
}

impl MainSecurityConfig {
    /// Validate the security section.
    ///
    /// `worker_sandbox` is a typed enum, so an unknown TOML value is rejected
    /// by deserialization; the runtime backend probe (not this parser) decides
    /// whether `required` can actually be enforced. Keeping the method here
    /// makes the section part of the top-level validation chain and gives
    /// future security constraints a single home.
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        Ok(())
    }
}

fn default_sanitize_forwarded() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, JsonSchema, ToSchema)]
pub struct MainStaticConfig {
    #[serde(default = "default_static_worker_enabled")]
    pub enabled: Option<bool>,
    #[serde(default = "default_watch_interval_ms")]
    pub watch_interval_ms: Option<u64>,
    #[serde(default = "default_preload_on_startup")]
    pub preload_on_startup: Option<bool>,
    #[serde(default = "default_minified_base_dir")]
    pub minified_base_dir: Option<String>,
}

fn default_static_worker_enabled() -> Option<bool> {
    Some(true)
}

fn default_watch_interval_ms() -> Option<u64> {
    Some(5000)
}

fn default_preload_on_startup() -> Option<bool> {
    Some(true)
}

fn default_minified_base_dir() -> Option<String> {
    Some("/var/cache/synvoid/minified".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_tls_passthrough_policy_default_is_false() {
        assert!(!MainSecurityConfig::default().strict_tls_passthrough_policy);
    }

    #[test]
    fn strict_tls_passthrough_policy_backward_compat_missing_field() {
        let toml_str = r#"
more_clear_headers = ["X-Request-Id"]
sanitize_forwarded_headers = true
"#;
        let config: MainSecurityConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.strict_tls_passthrough_policy);
    }

    #[test]
    fn strict_tls_passthrough_policy_explicit_true() {
        let toml_str = r#"
strict_tls_passthrough_policy = true
"#;
        let config: MainSecurityConfig = toml::from_str(toml_str).unwrap();
        assert!(config.strict_tls_passthrough_policy);
    }

    #[test]
    fn worker_sandbox_default_is_off() {
        assert_eq!(
            MainSecurityConfig::default().worker_sandbox,
            WorkerSandboxMode::Off
        );
        let parsed: MainSecurityConfig = toml::from_str("").unwrap();
        assert_eq!(parsed.worker_sandbox, WorkerSandboxMode::Off);
    }

    #[test]
    fn worker_sandbox_parses_every_documented_mode() {
        for (text, expected) in [
            ("off", WorkerSandboxMode::Off),
            ("auto", WorkerSandboxMode::Auto),
            ("required", WorkerSandboxMode::Required),
        ] {
            let toml_str = format!("worker_sandbox = \"{text}\"");
            let parsed: MainSecurityConfig = toml::from_str(&toml_str)
                .unwrap_or_else(|error| panic!("worker_sandbox = {text} must parse: {error}"));
            assert_eq!(parsed.worker_sandbox, expected);
            assert_eq!(parsed.worker_sandbox.as_str(), text);
        }
    }

    #[test]
    fn worker_sandbox_rejects_unknown_mode() {
        let error = toml::from_str::<MainSecurityConfig>("worker_sandbox = \"sometimes\"")
            .expect_err("unknown worker_sandbox values must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("worker_sandbox") || message.contains("unknown variant"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn worker_sandbox_survives_serialization_round_trip() {
        let config = MainSecurityConfig {
            worker_sandbox: WorkerSandboxMode::Required,
            ..Default::default()
        };
        let serialized = toml::to_string(&config).expect("security config must serialize");
        assert!(serialized.contains("worker_sandbox = \"required\""));
        let reparsed: MainSecurityConfig =
            toml::from_str(&serialized).expect("serialized security config must parse");
        assert_eq!(reparsed.worker_sandbox, WorkerSandboxMode::Required);
    }
}
