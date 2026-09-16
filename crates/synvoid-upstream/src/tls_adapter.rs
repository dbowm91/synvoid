//! SynVoid site-config → egress-TLS adapter (Phase 34).
//!
//! Converts `synvoid_config::site::UpstreamTlsConfig` (deserialized site
//! policy: enable flag, CA path, audited `skip_verify` + reason) into the
//! generic [`UpstreamTlsConfig`] transport policy owned by
//! `synvoid-http-client`.
//!
//! This conversion used to live in `synvoid-http-client/src/tls.rs`, which
//! forced the generic HTTP transport layer to depend on `synvoid-config`.
//! It now lives here — next to upstream selection/health checking — so the
//! transport core only understands neutral TLS policy (verify flag, CA path,
//! hostname-skip reason, plaintext allowance).

pub use synvoid_http_client::UpstreamTlsConfig;

/// Build neutral upstream TLS policy from site config.
///
/// Returns `None` when upstream TLS is disabled for the site, in which case
/// callers fall back to the shared default client.
pub fn upstream_tls_from_site_config(
    config: &synvoid_config::site::UpstreamTlsConfig,
) -> Option<UpstreamTlsConfig> {
    let enabled = config.enabled.unwrap_or(true);
    if !enabled {
        return None;
    }
    let skip_verify = config.skip_verify.unwrap_or(false);
    if skip_verify {
        let reason = config
            .skip_verify_reason
            .as_deref()
            .unwrap_or("none provided");
        tracing::warn!(
            reason,
            "Upstream TLS: skip_verify is ENABLED \u{2014} hostname verification is BYPASSED but chain validation still occurs. Configure skip_verify_reason to document why this is needed."
        );
    }
    Some(UpstreamTlsConfig {
        verify: !skip_verify,
        ca_cert_path: config.ca_cert.clone(),
        server_name: None,
        skip_verify,
        skip_verify_reason: config.skip_verify_reason.clone(),
        allow_plaintext: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_tls_from_site_config_returns_none_when_disabled() {
        let site_cfg = synvoid_config::site::UpstreamTlsConfig {
            enabled: Some(false),
            ..Default::default()
        };
        assert!(upstream_tls_from_site_config(&site_cfg).is_none());
    }

    #[test]
    fn upstream_tls_from_site_config_maps_skip_verify_and_reason() {
        let site_cfg = synvoid_config::site::UpstreamTlsConfig {
            enabled: Some(true),
            skip_verify: Some(true),
            skip_verify_reason: Some("test reason".to_string()),
            ..Default::default()
        };
        let cfg = upstream_tls_from_site_config(&site_cfg).unwrap();
        assert!(cfg.skip_verify);
        assert!(!cfg.verify);
        assert_eq!(cfg.skip_verify_reason.as_deref(), Some("test reason"));
        assert!(cfg.ca_cert_path.is_none());
        assert!(cfg.server_name.is_none());
        assert!(!cfg.allow_plaintext);
    }

    #[test]
    fn upstream_tls_from_site_config_defaults_to_enabled_verify() {
        let site_cfg = synvoid_config::site::UpstreamTlsConfig::default();
        let cfg = upstream_tls_from_site_config(&site_cfg).unwrap();
        assert!(cfg.verify);
        assert!(!cfg.skip_verify);
    }
}
