use std::collections::HashMap;

use synvoid_config::site::UpstreamConfig;
use synvoid_config::{HttpListenerConfig, MainConfig, SiteConfig};
use synvoid_proxy::Router;

fn site(domain: &str, upstream: &str, listeners: &[&str]) -> SiteConfig {
    let mut site = SiteConfig::default();
    site.site.domains = vec![domain.to_string()];
    site.site.listeners = listeners.iter().map(|name| name.to_string()).collect();
    site.site.upstream = UpstreamConfig {
        default: upstream.to_string(),
        ..Default::default()
    };
    site
}

fn listener(name: &str, port: u16, default_site: Option<&str>) -> HttpListenerConfig {
    HttpListenerConfig {
        name: name.to_string(),
        address: "127.0.0.1".to_string(),
        port,
        tls: false,
        http2: false,
        http3: false,
        default_site: default_site.map(str::to_string),
        ipv6_only: false,
    }
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

#[test]
fn listeners_with_distinct_default_sites_do_not_leak() {
    let sites = vec![
        site("alpha.test", "http://127.0.0.1:9001", &["one"]),
        site("beta.test", "http://127.0.0.1:9002", &["two"]),
    ];
    let router = router(
        sites,
        vec![
            listener("one", 18081, Some("alpha.test")),
            listener("two", 18082, Some("beta.test")),
        ],
    );

    let alpha = router.route_with_listener_id("missing.test", "/", Some("one"));
    let beta = router.route_with_listener_id("missing.test", "/", Some("two"));
    match (alpha, beta) {
        (synvoid_proxy::RouteResult::Found(a), synvoid_proxy::RouteResult::Found(b)) => {
            assert_eq!(a.site_id.as_ref(), "alpha.test");
            assert_eq!(b.site_id.as_ref(), "beta.test");
        }
        other => panic!("expected both defaults to resolve, got {other:?}"),
    }

    // A Host bound only to listener two falls to listener one's default, not
    // to the other listener's table.
    match router.route_with_listener_id("beta.test", "/", Some("one")) {
        synvoid_proxy::RouteResult::Found(target) => {
            assert_eq!(target.site_id.as_ref(), "alpha.test");
        }
        other => panic!("expected listener one default, got {other:?}"),
    }
}

#[test]
fn unmatched_host_without_default_does_not_leak() {
    let sites = vec![
        site("gamma.test", "http://127.0.0.1:9001", &["one"]),
        site("beta.test", "http://127.0.0.1:9002", &["two"]),
    ];
    let router = router(
        sites,
        vec![listener("one", 18081, None), listener("two", 18082, None)],
    );
    assert!(matches!(
        router.route_with_listener_id("beta.test", "/", Some("one")),
        synvoid_proxy::RouteResult::NotFound(_)
    ));
    assert!(matches!(
        router.route_with_listener_id("gamma.test", "/", Some("two")),
        synvoid_proxy::RouteResult::NotFound(_)
    ));
}

#[test]
fn exact_host_wins_over_default_site() {
    let sites = vec![
        site("alpha.test", "http://127.0.0.1:9001", &["one"]),
        site("beta.test", "http://127.0.0.1:9002", &["one"]),
    ];
    let router = router(sites, vec![listener("one", 18081, Some("alpha.test"))]);
    let result = router.route_with_listener_id("beta.test", "/", Some("one"));
    match result {
        synvoid_proxy::RouteResult::Found(target) => {
            assert_eq!(target.site_id.as_ref(), "beta.test");
        }
        other => panic!("expected exact host match, got {other:?}"),
    }
}

#[test]
fn omitted_membership_is_available_on_every_listener() {
    let sites = vec![site("shared.test", "http://127.0.0.1:9001", &[])];
    let router = router(
        sites,
        vec![listener("one", 18081, None), listener("two", 18082, None)],
    );
    for id in ["one", "two"] {
        match router.route_with_listener_id("shared.test", "/", Some(id)) {
            synvoid_proxy::RouteResult::Found(target) => {
                assert_eq!(target.site_id.as_ref(), "shared.test")
            }
            other => panic!("expected shared site on {id}, got {other:?}"),
        }
    }
}

#[test]
fn unknown_listener_does_not_fall_back_to_global_table() {
    let sites = vec![site("alpha.test", "http://127.0.0.1:9001", &[])];
    let router = router(sites, vec![listener("one", 18081, None)]);
    assert!(matches!(
        router.route_with_listener_id("alpha.test", "/", Some("missing")),
        synvoid_proxy::RouteResult::NotFound(message) if message.contains("missing")
    ));
}
