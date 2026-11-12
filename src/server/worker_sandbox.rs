//! Worker filesystem-sandbox policy and startup application (Phase 08).
//!
//! The UnifiedServerWorker is the process that parses untrusted HTTP, runs the
//! WAF and terminates TLS. Phase 07 hardened the service account, capabilities
//! and systemd unit; this module adds the in-process filesystem layer that runs
//! before the worker creates its Tokio runtime.
//!
//! Policy comes from `[security] worker_sandbox`:
//!
//! - `off` — explicit: no in-process filesystem confinement is applied.
//! - `auto` — apply the sandbox only when the backend fully enforces the
//!   requested filesystem guarantees; otherwise log the enforcement report and
//!   continue unsandboxed.
//! - `required` — fail startup unless every requested filesystem guarantee is
//!   fully enforced.
//!
//! Only filesystem guarantees are requested. Network and exec denial are not
//! requested: the worker is a proxy and may spawn jail/app-server children.
//! Seccomp/systemd syscall filtering is not implemented by this module and must
//! never be claimed here.

use std::path::{Path, PathBuf};

use synvoid_config::security::WorkerSandboxMode;
use synvoid_config::{ConfigManager, MainConfig};
use synvoid_platform::sandbox::{
    prepare_sandbox, EnforcementReport, EnteredSandbox, Guarantee, GuaranteeStatus, SandboxError,
    SandboxRequest, ThreadScope,
};
use synvoid_platform::PlatformPaths;

/// Guarantees the worker request treats as required. All are filesystem
/// guarantees that Linux Landlock can express; syscall-level guarantees stay
/// out of this request until they are qualified for the worker workload.
pub const WORKER_SANDBOX_GUARANTEES: &[Guarantee] = &[
    Guarantee::AmbientFilesystemDenied,
    Guarantee::FilesystemReadAllowlist,
    Guarantee::FilesystemWriteAllowlist,
    Guarantee::InheritedIpcUsable,
    Guarantee::DescendantsConfined,
];

/// Errors that prevent a worker from starting under its configured policy.
#[derive(Debug, thiserror::Error)]
pub enum WorkerSandboxError {
    #[error("worker sandbox request could not be built: {0}")]
    Request(String),
    #[error("required worker sandbox could not be enforced: {0}")]
    NotEnforced(#[from] SandboxError),
    #[error("required worker sandbox enforcement report is incomplete: {0}")]
    Incomplete(String),
}

/// Resolve the worker sandbox policy from the effective configuration and
/// apply it. The returned witness must be retained by the caller for the whole
/// worker lifetime.
pub fn apply_worker_sandbox_for_config(
    config_dir: &Path,
) -> Result<Option<EnteredSandbox>, WorkerSandboxError> {
    let config = load_worker_config(config_dir);
    apply_worker_sandbox(
        config.security.worker_sandbox,
        &config,
        config_dir,
        &PlatformPaths::new(),
    )
}

/// Apply a resolved worker sandbox policy.
///
/// `paths` is injectable so the request can be tested without touching the
/// host's real `/var/lib`, `/var/log`, `/run` and cache directories.
pub fn apply_worker_sandbox(
    mode: WorkerSandboxMode,
    config: &MainConfig,
    config_dir: &Path,
    paths: &PlatformPaths,
) -> Result<Option<EnteredSandbox>, WorkerSandboxError> {
    tracing::info!(
        "Resolved worker sandbox policy: worker_sandbox = {}",
        mode.as_str()
    );

    if mode == WorkerSandboxMode::Off {
        tracing::info!(
            "Worker sandbox disabled by configuration (worker_sandbox = \"off\"); \
             no in-process filesystem confinement is claimed"
        );
        return Ok(None);
    }

    let request = match build_worker_sandbox_request(config, config_dir, paths) {
        Ok(request) => request,
        Err(error) => {
            return match mode {
                WorkerSandboxMode::Off => Ok(None),
                WorkerSandboxMode::Auto => {
                    tracing::warn!(
                        "Worker sandbox not enforced (auto): request could not be built: {error}"
                    );
                    Ok(None)
                }
                WorkerSandboxMode::Required => Err(error),
            };
        }
    };

    let prepared = match prepare_sandbox(request) {
        Ok(prepared) => prepared,
        Err(error) => {
            return finish_worker_sandbox(mode, Err(error));
        }
    };

    log_enforcement_report("prepared", prepared.projection());

    if let Err(error) = prepared.projection().require_all(WORKER_SANDBOX_GUARANTEES) {
        return match mode {
            WorkerSandboxMode::Off => Ok(None),
            WorkerSandboxMode::Auto => {
                tracing::warn!("Worker sandbox not enforced (auto): {error}");
                Ok(None)
            }
            WorkerSandboxMode::Required => Err(WorkerSandboxError::Incomplete(error.to_string())),
        };
    }

    finish_worker_sandbox(mode, prepared.enter())
}

fn finish_worker_sandbox(
    mode: WorkerSandboxMode,
    result: Result<EnteredSandbox, SandboxError>,
) -> Result<Option<EnteredSandbox>, WorkerSandboxError> {
    match result {
        Ok(guard) => {
            log_enforcement_report("enforced", guard.report());
            Ok(Some(guard))
        }
        Err(error) => match mode {
            WorkerSandboxMode::Off => Ok(None),
            WorkerSandboxMode::Required => Err(WorkerSandboxError::NotEnforced(error)),
            WorkerSandboxMode::Auto if auto_may_continue_without_enforcement(&error) => {
                tracing::warn!("Worker sandbox not enforced (auto): {error}");
                Ok(None)
            }
            WorkerSandboxMode::Auto => Err(WorkerSandboxError::NotEnforced(error)),
        },
    }
}

/// `auto` may continue only when the failure is known to happen before any
/// irreversible mechanism was installed. A partial post-entry failure is
/// reported as startup failure instead of running in an unknown confinement
/// state.
fn auto_may_continue_without_enforcement(error: &SandboxError) -> bool {
    matches!(
        error,
        SandboxError::NotSupported(_)
            | SandboxError::LandlockUnavailable
            | SandboxError::Unsupported(_)
            | SandboxError::InsufficientCapabilities(_)
            | SandboxError::InvalidPath(_)
            | SandboxError::InvalidPolicy(_)
            | SandboxError::BackendConflict(_)
    )
}

fn log_enforcement_report(stage: &str, report: &EnforcementReport) {
    let guarantees = report
        .decisions
        .iter()
        .filter(|decision| decision.status != GuaranteeStatus::NotRequested)
        .map(|decision| format!("{:?}={:?}", decision.guarantee, decision.status))
        .collect::<Vec<_>>()
        .join(", ");
    tracing::info!(
        "Worker sandbox {stage}: backend={}, abi={}, scope={:?}, guarantees=[{}]",
        report.backend,
        report.abi,
        report.scope,
        guarantees
    );
}

/// Load the effective main config for policy resolution.
///
/// A broken/missing `main.toml` keeps the worker's historical fallback to
/// defaults, but a declared `worker_sandbox = "required"` is still honoured so
/// a malformed unrelated field cannot silently downgrade an explicit security
/// request to `off`.
fn load_worker_config(config_dir: &Path) -> MainConfig {
    let main_toml = config_dir.join("main.toml");
    match MainConfig::from_file(&main_toml) {
        Ok(config) => config,
        Err(error) => {
            tracing::warn!(
                "Failed to load main config for worker sandbox policy: {error}; using defaults"
            );
            let mut config = MainConfig::default_config();
            if let Some(mode) = declared_worker_sandbox_mode(&main_toml) {
                config.security.worker_sandbox = mode;
            }
            config
        }
    }
}

fn declared_worker_sandbox_mode(main_toml: &Path) -> Option<WorkerSandboxMode> {
    let text = std::fs::read_to_string(main_toml).ok()?;
    let value: toml::Value = toml::from_str(&text).ok()?;
    let mode = value.get("security")?.get("worker_sandbox")?.as_str()?;
    match mode {
        "off" => Some(WorkerSandboxMode::Off),
        "auto" => Some(WorkerSandboxMode::Auto),
        "required" => Some(WorkerSandboxMode::Required),
        _ => None,
    }
}

/// Build the worker's filesystem policy from the effective configuration and
/// the deployment's runtime paths.
///
/// The allowlist is derived from actual configured paths, never from a blanket
/// `/` or `$HOME` grant. Read roots cover configuration, certificates/ACME,
/// rule/YARA sources, static/admin assets, GeoIP, DNS root hints/trust anchors
/// and system CA/loader files. Write roots cover logs, data, runtime, cache,
/// the admin-writable config directory (only when the admin editor is enabled)
/// and the explicitly configured upload/ACME/rule-feed directories.
pub fn build_worker_sandbox_request(
    config: &MainConfig,
    config_dir: &Path,
    paths: &PlatformPaths,
) -> Result<SandboxRequest, WorkerSandboxError> {
    let mut read_paths = Vec::new();
    let mut write_paths = Vec::new();

    for dir in [
        paths.data_dir(),
        paths.log_dir(),
        paths.cache_dir(),
        paths.runtime_dir(),
    ] {
        ensure_dir(dir).map_err(|error| {
            WorkerSandboxError::Request(format!(
                "cannot prepare worker runtime directory {}: {error}",
                dir.display()
            ))
        })?;
        push_unique(&mut write_paths, dir.to_path_buf());
    }

    if config_dir.is_dir() {
        push_unique(&mut read_paths, config_dir.to_path_buf());
    }
    if config.admin.enabled {
        ensure_dir(config_dir).map_err(|error| {
            WorkerSandboxError::Request(format!(
                "cannot prepare admin-writable config directory {}: {error}",
                config_dir.display()
            ))
        })?;
        push_unique(&mut write_paths, config_dir.to_path_buf());
    }

    if let Some(dir) = config.persistence.data_dir.as_deref() {
        ensure_dir(Path::new(dir)).map_err(|error| {
            WorkerSandboxError::Request(format!(
                "cannot prepare configured data_dir {dir}: {error}"
            ))
        })?;
        push_unique(&mut write_paths, PathBuf::from(dir));
    }

    if let Some(dir) = config.logging.access_log_dir.as_deref() {
        ensure_dir(Path::new(dir)).map_err(|error| {
            WorkerSandboxError::Request(format!(
                "cannot prepare configured access_log_dir {dir}: {error}"
            ))
        })?;
        push_unique(&mut write_paths, PathBuf::from(dir));
    }

    push_read_file(&mut read_paths, config.tls.cert_path.as_deref());
    push_read_file(&mut read_paths, config.tls.key_path.as_deref());
    push_read_dir(&mut read_paths, config.tls.watch_dir.as_deref());
    push_read_file(&mut read_paths, config.tls.ocsp_response_path.as_deref());
    push_read_file(
        &mut read_paths,
        config.tls.client_auth.ca_cert_path.as_deref(),
    );

    if config.tls.acme.enabled {
        if let Some(dir) = config.tls.acme.cache_dir.as_deref() {
            ensure_dir(Path::new(dir)).map_err(|error| {
                WorkerSandboxError::Request(format!("cannot prepare ACME cache_dir {dir}: {error}"))
            })?;
            push_unique(&mut write_paths, PathBuf::from(dir));
        }
    }

    if config.rule_feed.enabled {
        if let Some(dir) = config.rule_feed.storage_dir.as_deref() {
            ensure_dir(Path::new(dir)).map_err(|error| {
                WorkerSandboxError::Request(format!(
                    "cannot prepare rule-feed storage_dir {dir}: {error}"
                ))
            })?;
            push_unique(&mut write_paths, PathBuf::from(dir));
        }
    }

    push_read_dir(
        &mut read_paths,
        config.defaults.upload.yara_rules_dir.as_deref(),
    );
    if config.defaults.upload.enabled {
        for dir in [
            Some(config.defaults.upload.sandbox_dir.as_str()),
            Some(config.defaults.upload.quarantine_dir.as_str()),
        ]
        .into_iter()
        .flatten()
        {
            ensure_dir(Path::new(dir)).map_err(|error| {
                WorkerSandboxError::Request(format!(
                    "cannot prepare upload directory {dir}: {error}"
                ))
            })?;
            push_unique(&mut write_paths, PathBuf::from(dir));
        }
    }

    if let Some(dir) = config
        .static_config
        .as_ref()
        .and_then(|static_config| static_config.minified_base_dir.as_deref())
    {
        ensure_dir(Path::new(dir)).map_err(|error| {
            WorkerSandboxError::Request(format!(
                "cannot prepare minified asset directory {dir}: {error}"
            ))
        })?;
        push_unique(&mut write_paths, PathBuf::from(dir));
    }

    push_read_file(&mut read_paths, config.geoip.database_path.as_deref());

    #[cfg(feature = "dns")]
    if config.dns.enabled {
        push_read_path_candidate(
            &mut read_paths,
            Path::new(&config.dns.recursive.root_hints_path),
            config_dir,
        );
        push_read_path_candidate(
            &mut read_paths,
            Path::new(&config.dns.recursive.trust_anchor_path),
            config_dir,
        );
    }

    if let Ok(key_file) = std::env::var("SYNVOID_IPC_KEY_FILE") {
        push_read_file(&mut read_paths, Some(&key_file));
    }

    // The installation directory holds the worker's sibling jail binaries.
    // Read access here also grants Landlock's Execute right, which the worker
    // needs to spawn them after entry.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            push_read_root(&mut read_paths, dir);
        }
    }

    for root in static_asset_roots(config_dir) {
        push_read_root(&mut read_paths, &root);
    }

    for path in SYSTEM_READ_PATHS {
        push_existing_read(&mut read_paths, Path::new(path));
    }

    let mut request = SandboxRequest::new()
        .scope(ThreadScope::CurrentThreadPlusDescendants)
        .require(Guarantee::AmbientFilesystemDenied)
        .require(Guarantee::FilesystemReadAllowlist)
        .require(Guarantee::FilesystemWriteAllowlist)
        .require(Guarantee::InheritedIpcUsable)
        .require(Guarantee::DescendantsConfined);

    for path in read_paths {
        request = request.read_path(path);
    }
    for path in write_paths {
        request = request.write_path(path);
    }

    request
        .validate()
        .map_err(|error| WorkerSandboxError::Request(error.to_string()))?;
    Ok(request)
}

const SYSTEM_READ_PATHS: &[&str] = &[
    "/usr/lib",
    "/usr/lib64",
    "/lib",
    "/lib64",
    "/dev/random",
    "/dev/urandom",
    "/dev/null",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/localtime",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/ssl",
    "/etc/pki",
    "/etc/ca-certificates",
    "/usr/share/ca-certificates",
    "/proc/self",
    "/proc/meminfo",
    "/proc/cpuinfo",
    "/proc/stat",
];

fn static_asset_roots(config_dir: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            roots.push(dir.to_path_buf());
        }
    }
    if let Some(manifest_dir) = option_env!("CARGO_MANIFEST_DIR") {
        roots.push(PathBuf::from(manifest_dir));
    }
    if let Ok(cwd) = std::env::current_dir() {
        roots.push(cwd);
    }

    let mut asset_roots = Vec::new();
    for root in roots {
        for relative in ["static", "admin-ui/dist"] {
            let path = root.join(relative);
            if path.exists() {
                push_unique(&mut asset_roots, path);
            }
        }
    }

    if config_dir.is_dir() {
        let mut manager = ConfigManager::new(config_dir.to_path_buf());
        for (_site_id, result) in manager.discover_sites() {
            if let Ok(site) = result {
                if let Some(root) = site.r#static.default_root.as_deref() {
                    push_existing_read(&mut asset_roots, Path::new(root));
                }
                for location in &site.r#static.locations {
                    push_existing_read(&mut asset_roots, Path::new(&location.root));
                }
            }
        }
    }

    asset_roots
}

fn ensure_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)
}

fn push_unique(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}

fn push_existing_read(paths: &mut Vec<PathBuf>, path: &Path) {
    if path.exists() {
        push_unique(paths, path.to_path_buf());
    }
}

/// Guard derived roots against accidentally becoming a blanket grant when a
/// binary or asset directory happens to live at `/` or `$HOME`.
fn push_read_root(paths: &mut Vec<PathBuf>, path: &Path) {
    if path == Path::new("/") {
        return;
    }
    if let Some(home) = std::env::var_os("HOME") {
        if path == Path::new(&home) {
            return;
        }
    }
    push_existing_read(paths, path);
}

fn push_read_file(paths: &mut Vec<PathBuf>, path: Option<&str>) {
    if let Some(path) = path {
        let path = Path::new(path);
        if path.is_file() {
            push_unique(paths, path.to_path_buf());
        }
    }
}

fn push_read_dir(paths: &mut Vec<PathBuf>, path: Option<&str>) {
    if let Some(path) = path {
        let path = Path::new(path);
        if path.is_dir() {
            push_unique(paths, path.to_path_buf());
        }
    }
}

#[cfg(feature = "dns")]
fn push_read_path_candidate(paths: &mut Vec<PathBuf>, path: &Path, config_dir: &Path) {
    if path.is_absolute() {
        push_existing_read(paths, path);
        return;
    }
    push_existing_read(paths, path);
    push_existing_read(paths, &config_dir.join(path));
}

#[cfg(test)]
mod tests {
    use super::*;
    use synvoid_config::security::MainSecurityConfig;

    fn temp_paths(base: &Path) -> PlatformPaths {
        PlatformPaths::with_base(base)
    }

    fn test_config() -> MainConfig {
        let mut config = MainConfig::default_config();
        config.defaults.upload.enabled = false;
        config
    }

    #[test]
    fn required_fails_closed_when_the_backend_is_missing() {
        let result = finish_worker_sandbox(
            WorkerSandboxMode::Required,
            Err(SandboxError::LandlockUnavailable),
        );
        assert!(matches!(result, Err(WorkerSandboxError::NotEnforced(_))));
    }

    #[test]
    fn auto_continues_when_the_backend_is_missing() {
        let result = finish_worker_sandbox(
            WorkerSandboxMode::Auto,
            Err(SandboxError::LandlockUnavailable),
        )
        .expect("auto must continue when the backend is unavailable");
        assert!(result.is_none());
    }

    #[test]
    fn auto_fails_when_entry_fails_after_a_partial_application() {
        let result = finish_worker_sandbox(
            WorkerSandboxMode::Auto,
            Err(SandboxError::PartialEnforcement("partial".into())),
        );
        assert!(matches!(result, Err(WorkerSandboxError::NotEnforced(_))));
    }

    #[test]
    fn off_never_installs_a_sandbox() {
        let config = test_config();
        let tmp = tempfile::TempDir::new().unwrap();
        let result = apply_worker_sandbox(
            WorkerSandboxMode::Off,
            &config,
            tmp.path(),
            &temp_paths(tmp.path()),
        )
        .expect("off must be an explicit no-op");
        assert!(result.is_none());
    }

    #[test]
    fn request_requires_only_the_filesystem_guarantees() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config = test_config();
        let request =
            build_worker_sandbox_request(&config, tmp.path(), &temp_paths(tmp.path())).unwrap();

        for guarantee in WORKER_SANDBOX_GUARANTEES {
            assert!(
                request.required.contains(guarantee),
                "missing required guarantee {guarantee:?}"
            );
        }
        assert!(!request.required.contains(&Guarantee::NetworkDenied));
        assert!(!request.required.contains(&Guarantee::ExecDenied));
        assert_eq!(request.scope, ThreadScope::CurrentThreadPlusDescendants);
    }

    #[test]
    fn request_does_not_grant_root_or_home() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config = test_config();
        let request =
            build_worker_sandbox_request(&config, tmp.path(), &temp_paths(tmp.path())).unwrap();

        let root = Path::new("/");
        let home = std::env::var_os("HOME").map(PathBuf::from);
        for path in request.read_paths.iter().chain(request.write_paths.iter()) {
            assert_ne!(path, root, "worker sandbox must not grant /");
            if let Some(home) = home.as_ref() {
                assert_ne!(path, home, "worker sandbox must not grant $HOME");
            }
        }
    }

    #[test]
    fn config_directory_is_writable_only_when_the_admin_editor_is_enabled() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config_dir = tmp.path().join("config");
        std::fs::create_dir_all(&config_dir).unwrap();

        let mut config = test_config();
        config.admin.enabled = false;
        let disabled =
            build_worker_sandbox_request(&config, &config_dir, &temp_paths(tmp.path())).unwrap();
        assert!(
            !disabled.write_paths.iter().any(|path| path == &config_dir),
            "config dir must not be writable without the admin editor"
        );

        config.admin.enabled = true;
        let enabled =
            build_worker_sandbox_request(&config, &config_dir, &temp_paths(tmp.path())).unwrap();
        assert!(
            enabled.write_paths.iter().any(|path| path == &config_dir),
            "config dir must be writable when the admin editor is enabled"
        );
    }

    #[test]
    fn declared_required_mode_survives_a_broken_config() {
        let tmp = tempfile::TempDir::new().unwrap();
        let main_toml = tmp.path().join("main.toml");
        std::fs::write(
            &main_toml,
            "[security]\nworker_sandbox = \"required\"\n[server]\nhost = \"not a host\"\n",
        )
        .unwrap();
        let config = load_worker_config(tmp.path());
        assert_eq!(
            config.security.worker_sandbox,
            WorkerSandboxMode::Required,
            "a malformed unrelated field must not downgrade required to off"
        );
    }

    #[test]
    fn missing_config_defaults_to_off() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config = load_worker_config(tmp.path());
        assert_eq!(
            config.security.worker_sandbox,
            MainSecurityConfig::default().worker_sandbox
        );
        assert_eq!(config.security.worker_sandbox, WorkerSandboxMode::Off);
    }
}
