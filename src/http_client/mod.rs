pub use synvoid_http_client::*;

pub mod quic_tunnel_dispatch;
pub mod streaming_waf_body;

pub use quic_tunnel_dispatch::{is_quictunnel_url, send_request_via_quic_tunnel};
pub use streaming_waf_body::StreamingWafBody;

pub fn upstream_tls_from_site_config(
    config: &synvoid_config::site::UpstreamTlsConfig,
) -> Option<synvoid_http_client::UpstreamTlsConfig> {
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
    Some(synvoid_http_client::UpstreamTlsConfig {
        verify: !skip_verify,
        ca_cert_path: config.ca_cert.clone(),
        server_name: None,
        skip_verify,
        skip_verify_reason: config.skip_verify_reason.clone(),
        allow_plaintext: false,
    })
}
