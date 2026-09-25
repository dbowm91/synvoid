//! Hyper transport adapter (Phase 74).
//!
//! The only canonical module allowed to name Hyper ingress types
//! (`hyper::body::Incoming`, `hyper::upgrade::OnUpgrade`): it converts a
//! Hyper request into the neutral [`crate::inbound::InboundRequest`] before
//! the request enters policy code, and backs the neutral
//! [`crate::inbound::UpgradeCapability`] with the Hyper handoff.
//!
//! Plaintext H1, TLS-H1, and TLS-H2 all flow through
//! [`adapt_hyper_request`]; the policy pipeline cannot tell which Hyper
//! protocol produced the request.

use crate::headers::is_websocket_upgrade;
use crate::inbound::{
    BoxTunnelIo, InboundBody, InboundRequest, TunnelHandler, UpgradeCapability, UpgradeError,
    UpgradeHandshake, UpgradeRequest,
};

impl InboundBody {
    /// Convert a Hyper ingress body. Transport errors map to
    /// [`InboundBodyError::Transport`] with the message preserved;
    /// DATA/trailers/hints/drop semantics pass through untouched.
    pub fn from_incoming(body: hyper::body::Incoming) -> Self {
        Self::from_body(body)
    }
}

/// Hyper-backed neutral upgrade capability.
pub struct HyperUpgradeCapability {
    request: UpgradeRequest,
    on_upgrade: Option<hyper::upgrade::OnUpgrade>,
}

impl HyperUpgradeCapability {
    fn new(on_upgrade: hyper::upgrade::OnUpgrade) -> Self {
        Self {
            request: UpgradeRequest::websocket(),
            on_upgrade: Some(on_upgrade),
        }
    }
}

impl UpgradeCapability for HyperUpgradeCapability {
    fn request(&self) -> &UpgradeRequest {
        &self.request
    }

    fn accept(
        self: Box<Self>,
        headers: http::HeaderMap,
        handler: TunnelHandler,
    ) -> Result<UpgradeHandshake, UpgradeError> {
        // The application never controls transfer framing: reject framing
        // headers deterministically instead of stripping them silently.
        for name in ["content-length", "transfer-encoding", "trailer"] {
            if headers.contains_key(name) {
                return Err(UpgradeError::ForbiddenHeader(name.to_string()));
            }
        }
        // `connection`/`upgrade` are runtime-owned: strip any supplied values
        // and re-apply the validated protocol below.
        let mut headers = headers;
        headers.remove("connection");
        headers.remove("upgrade");
        headers.insert("upgrade", "websocket".parse().expect("static header value"));
        headers.insert(
            "connection",
            "upgrade".parse().expect("static header value"),
        );

        let this = *self;
        let on_upgrade = this
            .on_upgrade
            .ok_or_else(|| UpgradeError::Gone("hyper upgrade handoff missing".to_string()))?;
        // reason: the post-handshake duplex is owned by the tunnel handler
        // independent of the 101 response path; awaiting it here would stall
        // the response. This mirrors the dispatch spawns this replaces.
        tokio::spawn(async move {
            match on_upgrade.await {
                Ok(upgraded) => {
                    let io: BoxTunnelIo = Box::new(hyper_util::rt::TokioIo::new(upgraded));
                    handler(io).await;
                }
                Err(e) => {
                    tracing::error!("Hyper upgrade handoff failed: {}", e);
                    metrics::counter!("synvoid.websocket.upgrade_failed").increment(1);
                }
            }
        });
        Ok(UpgradeHandshake {
            status: http::StatusCode::SWITCHING_PROTOCOLS,
            headers,
        })
    }
}

/// Convert a Hyper ingress request into the neutral boundary:
///
/// 1. classify WebSocket/upgrade eligibility with the canonical predicate;
/// 2. capture `OnUpgrade` only when required;
/// 3. wrap it in the neutral capability;
/// 4. convert `Incoming` to [`InboundBody`].
pub fn adapt_hyper_request(req: hyper::Request<hyper::body::Incoming>) -> InboundRequest {
    let mut req = req;
    let upgrade: Option<Box<dyn UpgradeCapability>> = if is_websocket_upgrade(req.headers()) {
        Some(Box::new(HyperUpgradeCapability::new(hyper::upgrade::on(
            &mut req,
        ))))
    } else {
        None
    };
    let (parts, body) = req.into_parts();
    InboundRequest {
        parts,
        body: InboundBody::from_incoming(body),
        upgrade,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbound::InboundBodyError;
    use http_body::Body as _;

    #[test]
    fn hyper_upgrade_capability_reports_websocket_intent() {
        // Capability construction needs a live OnUpgrade; intent reporting
        // is covered through `UpgradeRequest` here and live in the
        // integration boundary tests.
        assert_eq!(UpgradeRequest::websocket().protocol, "websocket");
    }

    #[test]
    fn empty_and_fixed_bodies_carry_exact_hints() {
        let empty = InboundBody::empty();
        assert_eq!(empty.size_hint().exact(), Some(0));
        let fixed = InboundBody::from_bytes(bytes::Bytes::from_static(b"abc"));
        assert_eq!(fixed.size_hint().exact(), Some(3));
    }

    #[test]
    fn body_error_variants_render() {
        assert!(InboundBodyError::Transport("x".to_string())
            .to_string()
            .contains('x'));
        assert!(InboundBodyError::Cancelled
            .to_string()
            .contains("cancelled"));
        assert!(InboundBodyError::Protocol("y".to_string())
            .to_string()
            .contains('y'));
        assert!(UpgradeError::ForbiddenHeader("content-length".to_string())
            .to_string()
            .contains("content-length"));
        assert!(UpgradeError::Gone("z".to_string())
            .to_string()
            .contains('z'));
    }
}
