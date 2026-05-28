use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct InternalTlsConfig {
    pub enabled: bool,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    pub watch_dir: Option<PathBuf>,
    pub prefer_post_quantum: bool,
    pub tls_1_3_only: bool,
    pub enable_tls_12_fallback: bool,
    pub ocsp_stapling_enabled: bool,
    pub ocsp_response_path: Option<PathBuf>,
    pub port: u16,
    pub acme: InternalAcmeConfig,
    pub client_auth: InternalClientAuthConfig,
}

#[derive(Debug, Clone, Default)]
pub struct InternalAcmeConfig {
    pub enabled: bool,
    pub email: Option<String>,
    pub cache_dir: Option<PathBuf>,
    pub staging: bool,
    pub domains: Vec<String>,
    pub challenge_type: InternalAcmeChallengeType,
    pub terms_of_service_agreed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InternalAcmeChallengeType {
    #[default]
    Http01,
    Dns01,
}

#[derive(Debug, Clone, Default)]
pub struct InternalClientAuthConfig {
    pub enabled: bool,
    pub ca_cert_path: Option<PathBuf>,
}

impl Default for InternalTlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: None,
            key_path: None,
            watch_dir: None,
            prefer_post_quantum: true,
            tls_1_3_only: true,
            enable_tls_12_fallback: false,
            ocsp_stapling_enabled: true,
            ocsp_response_path: None,
            port: 443,
            acme: InternalAcmeConfig::default(),
            client_auth: InternalClientAuthConfig::default(),
        }
    }
}

impl From<crate::config::TlsConfig> for InternalTlsConfig {
    fn from(config: crate::config::TlsConfig) -> Self {
        Self {
            enabled: config.enabled,
            cert_path: config.cert_path.map(PathBuf::from),
            key_path: config.key_path.map(PathBuf::from),
            watch_dir: config.watch_dir.map(PathBuf::from),
            prefer_post_quantum: config.prefer_post_quantum,
            tls_1_3_only: config.tls_1_3_only,
            enable_tls_12_fallback: config.enable_tls_12_fallback,
            ocsp_stapling_enabled: config.ocsp_stapling_enabled,
            ocsp_response_path: config.ocsp_response_path.map(PathBuf::from),
            port: config.port,
            acme: InternalAcmeConfig::from(config.acme),
            client_auth: InternalClientAuthConfig::from(config.client_auth),
        }
    }
}

impl From<InternalTlsConfig> for crate::config::TlsConfig {
    fn from(config: InternalTlsConfig) -> Self {
        Self {
            enabled: config.enabled,
            cert_path: config.cert_path.map(|p| p.to_string_lossy().into_owned()),
            key_path: config.key_path.map(|p| p.to_string_lossy().into_owned()),
            watch_dir: config.watch_dir.map(|p| p.to_string_lossy().into_owned()),
            prefer_post_quantum: config.prefer_post_quantum,
            tls_1_3_only: config.tls_1_3_only,
            enable_tls_12_fallback: config.enable_tls_12_fallback,
            ocsp_stapling_enabled: config.ocsp_stapling_enabled,
            ocsp_response_path: config
                .ocsp_response_path
                .map(|p| p.to_string_lossy().into_owned()),
            port: config.port,
            acme: crate::config::AcmeConfig::from(config.acme),
            client_auth: crate::config::ClientAuthConfig::from(config.client_auth),
            strict_protocol_validation: false,
        }
    }
}

impl From<InternalAcmeConfig> for crate::config::AcmeConfig {
    fn from(config: InternalAcmeConfig) -> Self {
        Self {
            enabled: config.enabled,
            email: config.email,
            cache_dir: config.cache_dir.map(|p| p.to_string_lossy().into_owned()),
            staging: config.staging,
            domains: config.domains,
            challenge_type: match config.challenge_type {
                InternalAcmeChallengeType::Http01 => crate::config::AcmeChallengeType::Http01,
                InternalAcmeChallengeType::Dns01 => crate::config::AcmeChallengeType::Dns01,
            },
            terms_of_service_agreed: config.terms_of_service_agreed,
        }
    }
}

impl From<InternalClientAuthConfig> for crate::config::ClientAuthConfig {
    fn from(config: InternalClientAuthConfig) -> Self {
        Self {
            enabled: config.enabled,
            ca_cert_path: config
                .ca_cert_path
                .map(|p| p.to_string_lossy().into_owned()),
        }
    }
}

impl From<crate::config::ClientAuthConfig> for InternalClientAuthConfig {
    fn from(config: crate::config::ClientAuthConfig) -> Self {
        Self {
            enabled: config.enabled,
            ca_cert_path: config.ca_cert_path.map(PathBuf::from),
        }
    }
}

impl From<crate::config::AcmeConfig> for InternalAcmeConfig {
    fn from(config: crate::config::AcmeConfig) -> Self {
        Self {
            enabled: config.enabled,
            email: config.email,
            cache_dir: config.cache_dir.map(PathBuf::from),
            staging: config.staging,
            domains: config.domains,
            challenge_type: match config.challenge_type {
                crate::config::AcmeChallengeType::Http01 => InternalAcmeChallengeType::Http01,
                crate::config::AcmeChallengeType::Dns01 => InternalAcmeChallengeType::Dns01,
            },
            terms_of_service_agreed: config.terms_of_service_agreed,
        }
    }
}
