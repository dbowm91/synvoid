//! Config-load validation for mesh service IDs and listener overrides.

use std::collections::HashMap;

use synvoid_config::listener::normalize_http_listeners;
use synvoid_config::site::BackendConfig;
use synvoid_config::{HttpListenerConfig, MainConfig, SiteConfig, UpstreamConfig};

fn listener(name: &str, port: u16) -> HttpListenerConfig {
    HttpListenerConfig {
        name: name.to_string(),
        address: "127.0.0.1".to_string(),
        port,
        tls: false,
        http2: false,
        http3: false,
        default_site: None,
        ipv6_only: false,
    }
}

fn mesh_site(listeners: &[&str], service: &str) -> SiteConfig {
    let mut site = SiteConfig::default();
    site.site.domains = vec!["blog.test".to_string()];
    site.site.listeners = listeners.iter().map(|name| name.to_string()).collect();
    site.site.upstream = UpstreamConfig {
        default: "http://127.0.0.1:5000".to_string(),
        ..Default::default()
    };
    site.proxy.backend = Some(BackendConfig::Mesh {
        upstream: service.to_string(),
    });
    site
}

fn main_with(listeners: &[&str]) -> MainConfig {
    let mut main = MainConfig::default_config();
    main.server.host = "127.0.0.1".to_string();
    main.server.port = 18080;
    main.admin.enabled = false;
    main.metrics.enabled = false;
    main.http.listeners = listeners
        .iter()
        .enumerate()
        .map(|(index, name)| listener(name, 18081 + index as u16))
        .collect();
    main
}

#[test]
fn explicit_and_url_like_mesh_service_ids_validate() {
    assert!(mesh_site(&["public"], "blog-public").validate().is_ok());
    assert!(mesh_site(&["public"], "http://blog.example:8082")
        .validate()
        .is_ok());
}

#[test]
fn empty_mesh_service_id_is_rejected_at_config_load() {
    let error = mesh_site(&["public"], "").validate().unwrap_err();
    assert_eq!(error.field, "proxy.backend.upstream");
    assert!(error.message.contains("must not be empty"));
}

#[test]
fn control_characters_in_mesh_service_id_are_rejected() {
    let error = mesh_site(&["public"], "blog\nalt").validate().unwrap_err();
    assert_eq!(error.field, "proxy.backend.upstream");
    assert!(error.message.contains("control character"));
}

#[test]
fn listener_overrides_require_a_mesh_backend() {
    let mut site = mesh_site(&["public"], "blog-default");
    site.proxy.backend = None;
    site.proxy
        .listener_backends
        .insert("public".to_string(), "blog-public".to_string());

    let error = site.validate().unwrap_err();
    assert_eq!(error.field, "proxy.listener_backends");
    assert!(error.message.contains("requires a site-level mesh backend"));
}

#[test]
fn unknown_listener_in_override_is_rejected() {
    let main = main_with(&["public"]);
    let mut site = mesh_site(&["public"], "blog-default");
    site.proxy
        .listener_backends
        .insert("ghost".to_string(), "blog-public".to_string());
    let sites = HashMap::from([(site.site_id(), site)]);

    let error = normalize_http_listeners(&main, &sites).unwrap_err();
    assert_eq!(error.field, "site.proxy.listener_backends");
    assert!(error.message.contains("unknown listener 'ghost'"));
}

#[test]
fn override_for_a_listener_outside_site_membership_is_rejected() {
    let main = main_with(&["public", "public-alt"]);
    let mut site = mesh_site(&["public"], "blog-default");
    site.proxy
        .listener_backends
        .insert("public-alt".to_string(), "blog-alt".to_string());
    let sites = HashMap::from([(site.site_id(), site)]);

    let error = normalize_http_listeners(&main, &sites).unwrap_err();
    assert_eq!(error.field, "site.proxy.listener_backends");
    assert!(error.message.contains("not a member"));
}

#[test]
fn member_listener_override_is_accepted() {
    let main = main_with(&["public", "public-alt"]);
    let mut site = mesh_site(&["public", "public-alt"], "blog-default");
    site.proxy
        .listener_backends
        .insert("public".to_string(), "blog-public".to_string());
    site.proxy
        .listener_backends
        .insert("public-alt".to_string(), "blog-alt".to_string());
    let sites = HashMap::from([(site.site_id(), site)]);

    assert!(normalize_http_listeners(&main, &sites).is_ok());
}

#[test]
fn empty_listener_override_service_id_is_rejected() {
    let mut site = mesh_site(&["public"], "blog-default");
    site.proxy
        .listener_backends
        .insert("public".to_string(), "".to_string());

    let error = site.validate().unwrap_err();
    assert_eq!(error.field, "proxy.listener_backends.public");
}

#[derive(serde::Deserialize)]
struct MeshExample {
    tunnel: MeshTunnel,
}

#[derive(serde::Deserialize)]
struct MeshTunnel {
    mesh: synvoid_config::mesh::MeshConfig,
}

#[test]
fn mesh_example_parses_and_respects_edge_ceilings() {
    let path = format!(
        "{}/../../config/mesh-example.toml",
        env!("CARGO_MANIFEST_DIR")
    );
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"));
    let example: MeshExample = toml::from_str(&content)
        .unwrap_or_else(|error| panic!("mesh example does not match the schema: {error}"));
    let mesh = example.tunnel.mesh;

    assert!(mesh.enabled);
    assert_eq!(mesh.port, 50051);

    let blog = mesh
        .local_upstreams
        .get("blog-public")
        .expect("blog-public service example is missing");
    assert_eq!(blog.upstream_url, "http://10.0.1.10:8080");
    assert!(
        blog.peered_wafs.iter().any(|peer| peer.allowed),
        "the private origin example must name an authorized peer"
    );

    // These are the current edge-side ceilings. The example must not teach an
    // operator to configure caps that cannot be reached end to end.
    assert!(
        blog.body_policy.max_request_body_bytes.unwrap() <= 8 * 1024 * 1024,
        "example request cap exceeds the edge retry replay ceiling"
    );
    assert!(
        blog.body_policy.max_response_body_bytes.unwrap() <= 50 * 1024 * 1024,
        "example response cap exceeds the edge response buffer ceiling"
    );

    assert!(mesh.local_upstreams.contains_key("cdn-assets"));
}
