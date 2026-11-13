#![cfg(feature = "mesh")]

//! Listener-scoped mesh service selection (mesh multi-upstream Phase 03).
//!
//! Listener names stay local: the per-listener routing table resolves the
//! override to a mesh service ID and only that ID reaches `RouteTarget`.

use std::collections::HashMap;

use synvoid_config::site::{BackendConfig, LocationConfig, UpstreamConfig};
use synvoid_config::{HttpListenerConfig, MainConfig, SiteConfig};
use synvoid_proxy::{BackendType, RouteResult, Router};

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

fn mesh_site(domain: &str, base_service: &str, overrides: &[(&str, &str)]) -> SiteConfig {
    let mut site = SiteConfig::default();
    site.site.domains = vec![domain.to_string()];
    site.site.listeners = vec!["public".to_string(), "public-alt".to_string()];
    site.site.upstream = UpstreamConfig {
        default: "http://127.0.0.1:5000".to_string(),
        ..Default::default()
    };
    site.proxy.backend = Some(BackendConfig::Mesh {
        upstream: base_service.to_string(),
    });
    site.proxy.listener_backends = overrides
        .iter()
        .map(|(listener, service)| (listener.to_string(), service.to_string()))
        .collect();
    site
}

fn router(sites: Vec<SiteConfig>, listeners: Vec<HttpListenerConfig>) -> Router {
    let mut main = MainConfig::default_config();
    main.server.host = "127.0.0.1".to_string();
    main.server.port = 18080;
    main.admin.enabled = false;
    main.metrics.enabled = false;
    main.http.listeners = listeners;
    let sites = sites
        .into_iter()
        .map(|site| (site.site_id(), site))
        .collect::<HashMap<_, _>>();
    Router::new(&main, sites)
}

fn mesh_target(result: RouteResult) -> String {
    match result {
        RouteResult::Found(target) => {
            assert!(
                matches!(target.backend_type, BackendType::Mesh),
                "expected a mesh target"
            );
            target.upstream.to_string()
        }
        other => panic!("expected a mesh route, got {other:?}"),
    }
}

#[test]
fn same_site_resolves_per_listener_service_without_mutation() {
    let site = mesh_site(
        "blog.test",
        "blog-default",
        &[("public", "blog-public"), ("public-alt", "blog-alt")],
    );
    let router = router(
        vec![site],
        vec![listener("public", 18081), listener("public-alt", 18082)],
    );

    assert_eq!(
        mesh_target(router.route_with_listener_id("blog.test", "/", Some("public"))),
        "blog-public"
    );
    assert_eq!(
        mesh_target(router.route_with_listener_id("blog.test", "/", Some("public-alt"))),
        "blog-alt"
    );

    // The shared SiteConfig is not mutated: re-reading listener one still
    // selects its own service.
    assert_eq!(
        mesh_target(router.route_with_listener_id("blog.test", "/", Some("public"))),
        "blog-public"
    );
}

#[test]
fn listener_without_override_uses_the_site_default() {
    let site = mesh_site("blog.test", "blog-default", &[("public", "blog-public")]);
    let router = router(
        vec![site],
        vec![listener("public", 18081), listener("public-alt", 18082)],
    );

    assert_eq!(
        mesh_target(router.route_with_listener_id("blog.test", "/", Some("public-alt"))),
        "blog-default"
    );
}

#[test]
fn location_backend_wins_over_listener_override() {
    let mut site = mesh_site("blog.test", "blog-default", &[("public", "blog-public")]);
    site.proxy.locations = vec![LocationConfig {
        path: "/api".to_string(),
        backend: Some(BackendConfig::Mesh {
            upstream: "blog-api".to_string(),
        }),
        fastcgi: None,
        php: None,
        cgi: None,
        proxy: None,
        allowed_methods: None,
        serverless: None,
        spin: None,
    }];
    let router = router(
        vec![site],
        vec![listener("public", 18081), listener("public-alt", 18082)],
    );

    assert_eq!(
        mesh_target(router.route_with_listener_id("blog.test", "/api/items", Some("public"))),
        "blog-api"
    );
    assert_eq!(
        mesh_target(router.route_with_listener_id("blog.test", "/", Some("public"))),
        "blog-public"
    );
}

#[test]
fn default_site_uses_each_listeners_override() {
    let mut site = mesh_site(
        "blog.test",
        "blog-default",
        &[("public", "blog-public"), ("public-alt", "blog-alt")],
    );
    site.site.listeners = vec![];
    let mut public = listener("public", 18081);
    public.default_site = Some("blog.test".to_string());
    let mut public_alt = listener("public-alt", 18082);
    public_alt.default_site = Some("blog.test".to_string());
    let router = router(vec![site], vec![public, public_alt]);

    assert_eq!(
        mesh_target(router.route_with_listener_id("unknown.test", "/", Some("public"))),
        "blog-public"
    );
    assert_eq!(
        mesh_target(router.route_with_listener_id("unknown.test", "/", Some("public-alt"))),
        "blog-alt"
    );
}

#[test]
fn compatibility_url_like_service_id_is_unchanged() {
    let site = mesh_site("blog.test", "http://blog.example:8082", &[]);
    let router = router(
        vec![site],
        vec![listener("public", 18081), listener("public-alt", 18082)],
    );

    assert_eq!(
        mesh_target(router.route_with_listener_id("blog.test", "/", Some("public"))),
        "http://blog.example:8082"
    );
}
