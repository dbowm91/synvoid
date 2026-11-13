//! Mesh multi-upstream service identity and origin authorization.
//!
//! Phase 01/02 contract: the edge sends an explicit, typed service ID ahead of
//! the HTTP bytes; the origin resolves that ID against its operator-configured
//! `local_upstreams` and enforces `peered_wafs` plus the single service policy
//! on both route disclosure and the forwarded request.

use std::sync::Arc;
use std::time::Duration;

use synvoid_mesh::config::MeshConfig;
use synvoid_mesh::service_target::{
    decode_service_preface, encode_service_preface, is_service_preface_start, MAX_SERVICE_ID_BYTES,
};
use synvoid_mesh::topology::{LocalUpstreamAuthorization, MeshTopology};
use synvoid_mesh::transport_peer::read_service_preface;
use tokio::io::AsyncWriteExt;

const IDLE_TIMEOUT: Duration = Duration::from_secs(5);

fn origin_topology() -> MeshTopology {
    let config: MeshConfig = serde_json::from_value(serde_json::json!({
        "node_id": "origin-1",
        "local_upstreams": {
            "blog-public": {
                "upstream_url": "http://127.0.0.1:5000",
                "peered_wafs": [
                    {"node_id": "edge-a", "allowed": true},
                    {"node_id": "edge-b", "allowed": false}
                ]
            },
            "blog-alt": {
                "upstream_url": "http://10.1.2.3:8080"
            },
            "blog-denied": {
                "upstream_url": "http://192.168.1.10:9000"
            }
        },
        "service_policy": {"deny": ["blog-denied"]},
        "routing": {"allow_all_services": true}
    }))
    .expect("valid mesh config fixture");

    MeshTopology::new(Arc::new(config))
}

#[tokio::test]
async fn preface_is_read_before_the_http_request() {
    let encoded = encode_service_preface("blog-public").unwrap();
    let mut wire = encoded.clone();
    wire.extend_from_slice(b"GET / HTTP/1.1\r\nHost: blog.example\r\n\r\n");

    let (mut client, mut server) = tokio::io::duplex(wire.len());
    client.write_all(&wire[1..]).await.unwrap();
    client.shutdown().await.unwrap();

    assert!(is_service_preface_start(wire[0]));
    let service_id = read_service_preface(&mut server, wire[0], IDLE_TIMEOUT)
        .await
        .unwrap();
    assert_eq!(service_id, "blog-public");

    // The stream is positioned exactly at the HTTP request line.
    use tokio::io::AsyncReadExt;
    let mut rest = Vec::new();
    server.read_to_end(&mut rest).await.unwrap();
    assert!(rest.starts_with(b"GET / HTTP/1.1\r\n"));
}

#[tokio::test]
async fn preface_rejects_empty_and_oversized_ids() {
    assert!(encode_service_preface("").is_err());

    let mut wire = vec![0x1f, b'M', b'S', b'V', 1, 0];
    wire.extend_from_slice(&((MAX_SERVICE_ID_BYTES + 1) as u16).to_be_bytes());
    let (mut client, mut server) = tokio::io::duplex(64);
    client.write_all(&wire[1..]).await.unwrap();
    let error = read_service_preface(&mut server, wire[0], IDLE_TIMEOUT).await;
    assert!(error.is_err(), "oversized service ID must be rejected");
}

#[tokio::test]
async fn preface_decode_rejects_control_characters() {
    let mut encoded = encode_service_preface("blog").unwrap();
    encoded[8] = b'\n';
    assert!(decode_service_preface(&encoded).is_err());
}

#[tokio::test]
async fn authorized_peer_reaches_private_configured_upstream() {
    let topology = origin_topology();

    match topology
        .authorize_local_upstream("blog-public", "edge-a")
        .await
    {
        LocalUpstreamAuthorization::Allowed(info) => {
            assert_eq!(info.upstream_url, "http://127.0.0.1:5000");
        }
        other => panic!("expected allowed, got {other:?}"),
    }
}

#[tokio::test]
async fn unauthorized_peer_is_denied_without_disclosing_url() {
    let topology = origin_topology();

    match topology
        .authorize_local_upstream("blog-public", "edge-c")
        .await
    {
        LocalUpstreamAuthorization::PeerNotAuthorized => {}
        other => panic!("expected PeerNotAuthorized, got {other:?}"),
    }

    // An explicitly `allowed = false` peer is excluded too.
    match topology
        .authorize_local_upstream("blog-public", "edge-b")
        .await
    {
        LocalUpstreamAuthorization::PeerNotAuthorized => {}
        other => panic!("expected PeerNotAuthorized for edge-b, got {other:?}"),
    }
}

#[tokio::test]
async fn empty_peered_wafs_keeps_legacy_unrestricted_semantics() {
    let topology = origin_topology();
    match topology
        .authorize_local_upstream("blog-alt", "edge-c")
        .await
    {
        LocalUpstreamAuthorization::Allowed(info) => {
            assert_eq!(info.upstream_url, "http://10.1.2.3:8080");
        }
        other => panic!("expected allowed, got {other:?}"),
    }
}

#[tokio::test]
async fn unknown_service_and_policy_denial_are_distinct() {
    let topology = origin_topology();

    assert!(matches!(
        topology
            .authorize_local_upstream("missing-service", "edge-a")
            .await,
        LocalUpstreamAuthorization::UnknownService
    ));
    assert!(matches!(
        topology
            .authorize_local_upstream("blog-denied", "edge-a")
            .await,
        LocalUpstreamAuthorization::ServiceNotAllowed
    ));
}

#[tokio::test]
async fn routing_allowlist_is_part_of_the_same_policy_decision() {
    let config: MeshConfig = serde_json::from_value(serde_json::json!({
        "node_id": "origin-1",
        "local_upstreams": {
            "blog-public": {"upstream_url": "http://127.0.0.1:5000"}
        },
        "routing": {"allow_all_services": false, "allowed_services": ["blog-other"]}
    }))
    .unwrap();
    let topology = MeshTopology::new(Arc::new(config));

    assert!(matches!(
        topology
            .authorize_local_upstream("blog-public", "edge-a")
            .await,
        LocalUpstreamAuthorization::ServiceNotAllowed
    ));
}
