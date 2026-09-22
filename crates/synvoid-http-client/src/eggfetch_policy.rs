//! Private eggfetch TLS policy translator (Phase 58 qualification).
//!
//! Translates SynVoid's neutral [`UpstreamTlsConfig`] into eggfetch
//! [`eggfetch_core::TlsConfig`] without introducing a second public TLS
//! configuration type. This module is deliberately `pub(crate)`: Phase 58
//! adds no new public contract; Phase 59 promotes this translator to
//! production-quality private code behind the internal transport lane.
//!
//! Policy invariants (must hold in both lanes):
//!
//! - normal verification stays normal verification;
//! - custom CA **augments** the native/WebPKI base store (matches the legacy
//!   [`crate::tls::build_tls_config`] additive behavior), never replaces it;
//! - `server_name` / SNI override travels per-request via
//!   [`eggfetch_core::TransportHints::sni_hostname`], never baked into the
//!   shared [`eggfetch_core::TlsConfig`];
//! - `skip_verify = true` disables **hostname matching only**; chain and
//!   signature verification stay enabled. This is never equivalent to
//!   `danger_accept_invalid_certs(true)`;
//! - `skip_verify_reason` stays SynVoid-side audit/logging state;
//! - `allow_plaintext` stays a routing/policy gate outside TLS config;
//! - every TLS-enabled client receives an explicit aws-lc
//!   [`rustls::crypto::CryptoProvider`]; eggfetch's process-provider
//!   fallback is never relied upon.

use std::sync::Arc;

use anyhow::{Context, Result};

use crate::tls::UpstreamTlsConfig;

/// Centralized Rustls crypto-provider authority for egress transport.
///
/// Both the legacy Hyper lane ([`crate::tls::build_tls_config`]) and the
/// eggfetch qualification lane consume this helper so provider selection
/// cannot diverge between lanes. The provider is explicit aws-lc-rs; it is
/// never installed as the process-global default here (callers that need a
/// process default for legacy `ClientConfig::builder()` paths own that
/// decision separately).
///
/// Cheap to clone/share (`Arc`); provider identity is stable per process so
/// it never fragments connection-pool identity.
pub(crate) fn eggfetch_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    static PROVIDER_LOGGED: std::sync::Once = std::sync::Once::new();
    PROVIDER_LOGGED.call_once(|| {
        tracing::info!(
            "Eggfetch TLS translator initialized with explicit aws-lc-rs provider (PQ support: {})",
            if cfg!(feature = "post-quantum") {
                "enabled"
            } else {
                "not available"
            }
        );
    });
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// Translate neutral SynVoid TLS policy into an eggfetch [`eggfetch_core::TlsConfig`].
///
/// Fail-closed: an unreadable/malformed/empty custom CA file returns `Err`
/// (eggfetch's `additional_ca_certificate_path` enforces this); no silent
/// fallback to defaults occurs.
pub(crate) fn upstream_tls_to_eggfetch(
    cfg: &UpstreamTlsConfig,
) -> Result<eggfetch_core::TlsConfig> {
    let provider = eggfetch_crypto_provider();

    let mut builder = eggfetch_core::TlsConfig::builder().crypto_provider(provider);

    // Custom CA augments the native/WebPKI base store, matching the legacy
    // additive behavior in `crate::tls::build_tls_config`.
    if let Some(ca_path) = cfg.ca_cert_path.as_deref() {
        builder = builder
            .additional_ca_certificate_path(ca_path)
            .with_context(|| format!("eggfetch TLS: failed to load custom CA from {ca_path}"))?;
    }

    if cfg.skip_verify {
        let reason = cfg.skip_verify_reason.as_deref().unwrap_or("not specified");
        tracing::warn!(
            reason,
            "Eggfetch TLS: hostname verification BYPASSED for upstream \
             — chain/signature validation still occurs. Connection is secure \
             against eavesdropping but NOT against impersonation."
        );
        // Hostname-only skip. `verify_certificate` stays true so an
        // untrusted/self-signed chain is still rejected. This is the
        // chain-preserving analogue of `HostnameSkippingVerifier`.
        builder = builder.verify_hostname(false);
    }

    // `server_name` (SNI override) is intentionally NOT baked into the shared
    // TlsConfig. It travels per-request via `TransportHints::sni_hostname`
    // (see `crate::eggfetch_transport`), so one cached client never crosses
    // incompatible SNI policy. SNI itself stays enabled here.
    //
    // `allow_plaintext` is a routing/policy gate owned above transport and
    // must not become a TLS toggle hidden inside eggfetch.

    Ok(builder.build())
}

/// Per-request SNI override for the eggfetch lane.
///
/// Returns the `sni_hostname` hint value for `cfg.server_name`, or `None`
/// when no override is configured. Kept beside the translator so the
/// "SNI travels per-request, never in the shared TlsConfig" rule has one
/// obvious owner.
pub(crate) fn eggfetch_sni_hint(cfg: &UpstreamTlsConfig) -> Option<String> {
    cfg.server_name.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translator_builds_default_policy_with_explicit_provider() {
        let cfg = UpstreamTlsConfig::default();
        let tls = upstream_tls_to_eggfetch(&cfg).expect("default policy must build");
        assert!(
            tls.has_explicit_crypto_provider(),
            "eggfetch TLS config must carry an explicit provider, never process fallback"
        );
        assert!(tls.verify_hostname(), "default must verify hostname");
        assert!(
            tls.verify_certificate(),
            "default must verify certificate chain"
        );
        assert!(tls.sni_enabled(), "SNI must stay enabled");
        assert!(eggfetch_sni_hint(&cfg).is_none());
    }

    #[test]
    fn translator_hostname_skip_keeps_chain_verification() {
        let cfg = UpstreamTlsConfig {
            skip_verify: true,
            skip_verify_reason: Some("test-only".to_string()),
            ..UpstreamTlsConfig::default()
        };
        let tls = upstream_tls_to_eggfetch(&cfg).expect("skip policy must build");
        assert!(
            tls.has_explicit_crypto_provider(),
            "skip mode must still carry the explicit provider"
        );
        assert!(
            !tls.verify_hostname(),
            "skip mode disables hostname matching"
        );
        assert!(
            tls.verify_certificate(),
            "skip mode MUST retain chain/signature verification \
             (never danger_accept_invalid_certs)"
        );
    }

    #[test]
    fn translator_sni_override_travels_per_request() {
        let cfg = UpstreamTlsConfig {
            server_name: Some("sni.example.test".to_string()),
            ..UpstreamTlsConfig::default()
        };
        let tls = upstream_tls_to_eggfetch(&cfg).expect("SNI policy must build");
        // Shared config keeps SNI enabled and full verification; the override
        // itself is a per-request hint, never baked into pool identity.
        assert!(tls.sni_enabled());
        assert!(tls.verify_hostname());
        assert_eq!(eggfetch_sni_hint(&cfg).as_deref(), Some("sni.example.test"));
    }

    #[test]
    fn translator_rejects_missing_ca_file_closed() {
        let cfg = UpstreamTlsConfig {
            ca_cert_path: Some("/nonexistent/definitely-not-a-ca.pem".to_string()),
            ..UpstreamTlsConfig::default()
        };
        assert!(
            upstream_tls_to_eggfetch(&cfg).is_err(),
            "unreadable custom CA must fail closed, never fall back to defaults"
        );
    }

    #[test]
    fn translator_rejects_empty_ca_file_closed() {
        let empty = tempfile::NamedTempFile::new().unwrap();
        // Empty file: no PEM certificates.
        let cfg = UpstreamTlsConfig {
            ca_cert_path: Some(empty.path().to_string_lossy().into_owned()),
            ..UpstreamTlsConfig::default()
        };
        assert!(
            upstream_tls_to_eggfetch(&cfg).is_err(),
            "empty custom CA must fail closed"
        );
    }

    #[test]
    fn translator_rejects_malformed_ca_file_closed() {
        let mut garbage = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write as _;
        writeln!(garbage, "this is not a PEM certificate at all").unwrap();
        let cfg = UpstreamTlsConfig {
            ca_cert_path: Some(garbage.path().to_string_lossy().into_owned()),
            ..UpstreamTlsConfig::default()
        };
        assert!(
            upstream_tls_to_eggfetch(&cfg).is_err(),
            "malformed custom CA must fail closed"
        );
    }

    #[test]
    fn provider_helper_is_stable_and_explicit() {
        // Both lanes share one authority: repeated calls yield equivalent
        // provider capability (aws-lc-rs default provider construction is
        // deterministic for the process).
        let a = eggfetch_crypto_provider();
        let b = eggfetch_crypto_provider();
        assert_eq!(
            format!("{:?}", a.cipher_suites.len()),
            format!("{:?}", b.cipher_suites.len())
        );
    }
}
