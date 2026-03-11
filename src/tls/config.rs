use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct InternalTlsConfig {
    pub enabled: bool,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    pub watch_dir: Option<PathBuf>,
    pub prefer_post_quantum: bool,
    pub port: u16,
    pub acme: InternalAcmeConfig,
}

#[derive(Debug, Clone)]
pub struct InternalAcmeConfig {
    pub enabled: bool,
    pub email: Option<String>,
    pub cache_dir: Option<PathBuf>,
    pub staging: bool,
    pub domains: Vec<String>,
}

impl Default for InternalTlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: None,
            key_path: None,
            watch_dir: None,
            prefer_post_quantum: true,
            port: 443,
            acme: InternalAcmeConfig::default(),
        }
    }
}

impl Default for InternalAcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            email: None,
            cache_dir: None,
            staging: false,
            domains: Vec::new(),
        }
    }
}

impl From<crate::config::main::TlsConfig> for InternalTlsConfig {
    fn from(config: crate::config::main::TlsConfig) -> Self {
        Self {
            enabled: config.enabled,
            cert_path: config.cert_path.map(PathBuf::from),
            key_path: config.key_path.map(PathBuf::from),
            watch_dir: config.watch_dir.map(PathBuf::from),
            prefer_post_quantum: config.prefer_post_quantum,
            port: config.port,
            acme: InternalAcmeConfig::from(config.acme),
        }
    }
}

impl From<crate::config::main::AcmeConfig> for InternalAcmeConfig {
    fn from(config: crate::config::main::AcmeConfig) -> Self {
        Self {
            enabled: config.enabled,
            email: config.email,
            cache_dir: config.cache_dir.map(PathBuf::from),
            staging: config.staging,
            domains: config.domains,
        }
    }
}
