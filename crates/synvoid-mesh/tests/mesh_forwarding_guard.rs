//! Static regression guards for mesh multi-upstream forwarding.
//!
//! These guards pin the Phase 01/02/04 contracts that unit tests can lose if a
//! future change quietly restores the old behavior:
//!
//! - `BackendType::Mesh` dispatches through the mesh proxy, never an empty
//!   backend pool;
//! - the selected service ID travels in the typed preface (`_target_url` is
//!   not ignored again);
//! - the origin authorizes against `local_upstreams`/`peered_wafs` instead of
//!   deriving the service from `Host` when an explicit ID is present;
//! - route disclosure is authorized on both datagram and stream paths;
//! - per-service body caps drive the body path instead of a silent 64 KiB
//!   default.

use std::path::{Path, PathBuf};

fn crate_file(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn repo_file(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn slice_between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start_index = source
        .find(start)
        .unwrap_or_else(|| panic!("guard anchor not found: {start}"));
    let rest = &source[start_index + start.len()..];
    let end_index = rest
        .find(end)
        .unwrap_or_else(|| panic!("guard end anchor not found: {end}"));
    &rest[..end_index]
}

#[test]
fn http_dispatch_uses_the_mesh_proxy_not_the_backend_pool() {
    let dispatch = repo_file("crates/synvoid-http/src/mesh_backend_dispatch.rs");
    assert!(
        dispatch.contains("MeshProxy"),
        "mesh HTTP dispatch must carry the mesh proxy handle"
    );
    assert!(
        dispatch.contains("route_request(service_id"),
        "mesh HTTP dispatch must forward the selected service ID through MeshProxy::route_request"
    );
    assert!(
        !dispatch.contains("MeshBackendPool"),
        "MeshBackendPool must not return as the HTTP dispatch requirement"
    );
    assert!(
        !dispatch.contains("mesh backend pool not available"),
        "the unpopulated-pool 502 path must stay retired"
    );
    assert!(
        dispatch.contains("CONTENT_LENGTH"),
        "the mesh hop must send the buffered body with fixed-length framing"
    );
    assert!(
        dispatch.contains("TRANSFER_ENCODING"),
        "client chunked framing must not leak past the buffered mesh dispatch"
    );
}

#[test]
fn egress_writes_the_typed_service_preface() {
    let transport = crate_file("src/mesh/transport.rs");
    let proxy_http = slice_between(
        &transport,
        "pub async fn proxy_http_request",
        "fn check_rate_limit(",
    );
    assert!(
        proxy_http.contains("encode_service_preface(service_id)"),
        "proxy_http_request must encode the service ID as a typed preface"
    );
    assert!(
        proxy_http.contains("write_all(&preface)"),
        "the preface must be written before the HTTP request bytes"
    );
    assert!(
        !proxy_http.contains("_target_url"),
        "the service target must not be ignored again"
    );
}

#[test]
fn origin_authorizes_instead_of_deriving_from_host() {
    let peer = crate_file("src/mesh/transport_peer.rs");
    let handler = slice_between(
        &peer,
        "async fn handle_http_proxy_stream(",
        "async fn write_mesh_http_error(",
    );
    assert!(
        handler.contains("service_id: Option<&str>"),
        "the peer HTTP handler must accept the preface service ID"
    );
    assert!(
        handler.contains("authorize_local_upstream("),
        "the origin data path must authorize the local upstream for the peer"
    );
    assert!(
        !handler.contains("get_upstream_info("),
        "the origin data path must not resolve the service without authorization"
    );
    assert!(
        handler.contains("UnknownService"),
        "an unknown explicit service ID must fail closed"
    );
    assert!(
        handler.contains("PeerNotAuthorized"),
        "an unauthorized peer must fail closed"
    );

    let topology = crate_file("src/mesh/topology.rs");
    let authorize = slice_between(
        &topology,
        "pub async fn authorize_local_upstream(",
        "pub async fn get_best_peers_for_query(",
    );
    assert!(
        authorize.contains("can_be_routed_by(peer_node_id)"),
        "authorize_local_upstream must enforce peered_wafs"
    );
    assert!(
        authorize.contains("can_forward_service("),
        "service policy must be part of the same authorization decision"
    );
}

#[test]
fn route_disclosure_is_authorized_on_both_paths() {
    let routing = crate_file("src/mesh/transport_routing.rs");
    let datagram = slice_between(
        &routing,
        "pub(crate) async fn handle_route_query_datagram(",
        "pub(crate) async fn handle_route_response(",
    );
    assert!(
        datagram.contains("route_disclosure_allowed("),
        "datagram route disclosure must authorize the requester"
    );

    let stream = slice_between(
        &routing,
        "pub(crate) async fn handle_route_query(",
        "pub(crate) async fn wait_for_route_event(",
    );
    assert!(
        stream.contains("authorize_local_upstream("),
        "stream route disclosure must authorize the requester"
    );
    assert!(
        stream.contains("write_route_not_found("),
        "denied disclosure must return a typed not-found, not an upstream URL"
    );
}

#[test]
fn proxy_to_peer_sends_the_service_id() {
    let proxy = crate_file("src/mesh/proxy.rs");
    assert!(
        proxy.contains("proxy_http_request(peer_node_id, upstream_id, req)"),
        "proxy_to_peer must send the service ID, not a resolved target URL"
    );
}

#[test]
fn body_path_uses_the_per_service_policy() {
    let peer = crate_file("src/mesh/transport_peer.rs");
    let handler = slice_between(
        &peer,
        "async fn handle_http_proxy_stream(",
        "async fn write_mesh_http_error(",
    );
    for token in [
        "body_policy.request_cap(",
        "body_policy.response_cap(",
        "body_policy.allow_chunked",
        "stream_fixed_http_body(",
        "stream_chunked_http_body(",
        "stream_close_delimited_http_body(",
    ] {
        assert!(
            handler.contains(token),
            "body path must use the per-service policy token: {token}"
        );
    }
}

#[test]
fn config_and_mesh_crates_share_the_service_id_rules() {
    let config = repo_file("crates/synvoid-config/src/site/backend.rs");
    assert!(
        config.contains("pub const MAX_MESH_SERVICE_ID_BYTES: usize = 255;"),
        "config must bound mesh service IDs"
    );
    assert!(
        config.contains("must not contain control characters"),
        "config must reject control characters in mesh service IDs"
    );

    let mesh = crate_file("src/mesh/service_target.rs");
    assert!(
        mesh.contains("pub const MAX_SERVICE_ID_BYTES: usize = 255;"),
        "the wire contract must use the same bound"
    );
}
