//! Request routing and domain resolution.
//!
//! Maps incoming requests to site configurations based on the `Host`
//! header, supporting exact domain matching, suffix/wildcard matching,
//! and per-listener default sites. Resolves backend targets (upstream
//! pools, FastCGI, static files, QUIC tunnels) and integrates with
//! the static file handler and minifier.

use crate::config::site::BackendConfig;
use crate::config::site::PhpLocationConfig;
use crate::config::{MainConfig, SiteConfig};
use crate::location_matcher::LocationMatcher;
#[cfg(feature = "mesh")]
use crate::mesh::config::{
    MeshCompressionConfig, MeshImageProtectionConfig, MeshMinificationConfig,
};
use crate::platform::fs::PlatformPaths;
use crate::plugin::PluginManager;
use crate::static_files::{
    client::{AsyncMinifierClient, MinifierClient},
    minifier::MinifierCache,
    StaticFileHandler,
};
use crate::theme::ThemeConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Clone)]
pub struct Router {
    domain_map: HashMap<Arc<str>, Arc<SiteConfig>>,
    suffix_domain_map: Vec<(Arc<str>, Arc<SiteConfig>)>,
    fallback_mode: String,
    fallback_upstream: Option<String>,
    static_handlers: HashMap<String, Arc<StaticFileHandler>>,
    minifier_client: Option<MinifierClient>,
    async_minifier_client: Option<AsyncMinifierClient>,
    listen_map: HashMap<SocketAddr, Vec<String>>,
    default_servers: HashMap<SocketAddr, String>,
    plugin_manager: Option<Arc<PluginManager>>,
    cleaned_site_domains: HashMap<String, Vec<Arc<str>>>,
    cleaned_site_domain_suffixes: HashMap<String, Vec<Arc<str>>>,
    location_matchers: HashMap<String, LocationMatcher>,
    site_map: HashMap<String, Arc<SiteConfig>>,
}

type SiteMaps = (
    HashMap<Arc<str>, Arc<SiteConfig>>,
    Vec<(Arc<str>, Arc<SiteConfig>)>,
    HashMap<String, Vec<Arc<str>>>,
    HashMap<String, Vec<Arc<str>>>,
    HashMap<String, Arc<StaticFileHandler>>,
    HashMap<SocketAddr, Vec<String>>,
    HashMap<SocketAddr, String>,
    HashMap<String, Arc<SiteConfig>>,
);

#[derive(Clone)]
pub enum BackendType {
    Upstream,
    FastCgi,
    Php,
    Cgi,
    AxumDynamic,
    AppServer,
    Static,
    QuicTunnel,
    Serverless,
    Mesh,
    Spin,
}

#[derive(Clone)]
pub struct RouteTarget {
    pub site_id: Arc<str>,
    pub upstream: Arc<str>,
    pub site_config: Arc<SiteConfig>,
    pub static_handler: Option<Arc<StaticFileHandler>>,
    pub backend_type: BackendType,
    pub backend_socket: Option<Arc<str>>,
    pub backend_plugin: Option<Arc<str>>,
    pub tunnel_peer: Option<Arc<str>>,
    pub tunnel_port: Option<u16>,
    pub serverless_function: Option<Arc<str>>,
    pub php_location_config: Option<PhpLocationConfig>,
    pub spin_app_name: Option<Arc<str>>,
}

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum RouteResult {
    Found(RouteTarget),
    NotFound(String),
    Error(String),
}

impl Router {
    pub fn new(main_config: &MainConfig, sites: HashMap<String, SiteConfig>) -> Self {
        let sites_clone = sites.clone();
        let static_worker_socket = Self::resolve_static_worker_socket(main_config);
        let minifier_client = MinifierClient::new(static_worker_socket.clone());
        let async_minifier_client = AsyncMinifierClient::new(static_worker_socket);
        let default_theme_config = ThemeConfig::from(main_config.defaults.theme.clone());

        let location_matchers = Self::build_location_matchers(&sites_clone);

        let (
            domain_map,
            suffix_domain_map,
            cleaned_site_domains,
            cleaned_site_domain_suffixes,
            static_handlers,
            listen_map,
            default_servers,
            site_map,
        ) = Self::build_all_maps(
            main_config,
            sites,
            &minifier_client,
            &async_minifier_client,
            &default_theme_config,
        );

        let router = Router {
            domain_map,
            suffix_domain_map,
            fallback_mode: main_config.fallback.mode.clone(),
            fallback_upstream: main_config.fallback.upstream.clone(),
            static_handlers,
            minifier_client: Some(minifier_client),
            async_minifier_client: Some(async_minifier_client),
            listen_map: listen_map.clone(),
            default_servers,
            plugin_manager: None,
            cleaned_site_domains,
            cleaned_site_domain_suffixes,
            location_matchers,
            site_map,
        };

        Self::log_configuration(&listen_map, &router.default_servers);
        router
    }

    #[inline]
    fn resolve_static_worker_socket(main_config: &MainConfig) -> PathBuf {
        main_config
            .static_config
            .as_ref()
            .and_then(|c| c.minified_base_dir.clone())
            .map(|base| {
                let mut path = PathBuf::from(base);
                path.pop();
                path.join("synvoid-static-worker.sock")
            })
            .unwrap_or_else(|| PlatformPaths::new().static_worker_socket_path())
    }

    fn build_all_maps(
        main_config: &MainConfig,
        sites: HashMap<String, SiteConfig>,
        minifier_client: &MinifierClient,
        async_minifier_client: &AsyncMinifierClient,
        default_theme_config: &ThemeConfig,
    ) -> SiteMaps {
        let mut domain_map = HashMap::new();
        let mut suffix_domain_map: Vec<(Arc<str>, Arc<SiteConfig>)> = Vec::new();
        let mut static_handlers = HashMap::new();
        let mut listen_map: HashMap<SocketAddr, Vec<String>> = HashMap::new();
        let mut default_servers: HashMap<SocketAddr, String> = HashMap::new();
        let mut cleaned_site_domains: HashMap<String, Vec<Arc<str>>> = HashMap::new();
        let mut cleaned_site_domain_suffixes: HashMap<String, Vec<Arc<str>>> = HashMap::new();
        let mut site_map: HashMap<String, Arc<SiteConfig>> = HashMap::new();

        for (_site_id, config) in sites {
            let config_arc = Arc::new(config);
            let site_id = config_arc.site_id();

            site_map.insert(site_id.clone(), config_arc.clone());

            Self::build_domain_map_entry(
                &config_arc,
                &mut domain_map,
                &mut suffix_domain_map,
                &mut cleaned_site_domains,
                &mut cleaned_site_domain_suffixes,
            );

            if config_arc.r#static.enabled.unwrap_or(false) {
                Self::initialize_static_handler(
                    &config_arc,
                    minifier_client,
                    async_minifier_client,
                    default_theme_config,
                    &mut static_handlers,
                );
            }

            if !config_arc.site.listen.is_empty() {
                Self::build_listen_map_entry(
                    &config_arc,
                    main_config,
                    &mut listen_map,
                    &mut default_servers,
                );
            }
        }

        suffix_domain_map.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        (
            domain_map,
            suffix_domain_map,
            cleaned_site_domains,
            cleaned_site_domain_suffixes,
            static_handlers,
            listen_map,
            default_servers,
            site_map,
        )
    }

    fn build_domain_map_entry(
        config_arc: &Arc<SiteConfig>,
        domain_map: &mut HashMap<Arc<str>, Arc<SiteConfig>>,
        suffix_domain_map: &mut Vec<(Arc<str>, Arc<SiteConfig>)>,
        cleaned_site_domains: &mut HashMap<String, Vec<Arc<str>>>,
        cleaned_site_domain_suffixes: &mut HashMap<String, Vec<Arc<str>>>,
    ) {
        let site_id = config_arc.site_id();
        let cleaned: Vec<Arc<str>> = config_arc
            .site
            .domains
            .iter()
            .map(|d| Arc::from(Self::clean_domain(d).as_str()))
            .collect();

        let mut suffixes: Vec<Arc<str>> = Vec::new();
        for clean_domain in &cleaned {
            if clean_domain.starts_with('.') || clean_domain.contains('*') {
                suffix_domain_map.push((clean_domain.clone(), config_arc.clone()));
                suffixes.push(clean_domain.clone());
            } else {
                domain_map.insert(clean_domain.clone(), config_arc.clone());
            }
        }

        cleaned_site_domains.insert(site_id.clone(), cleaned);
        cleaned_site_domain_suffixes.insert(site_id, suffixes);
    }

    fn initialize_static_handler(
        config_arc: &Arc<SiteConfig>,
        minifier_client: &MinifierClient,
        async_minifier_client: &AsyncMinifierClient,
        default_theme_config: &ThemeConfig,
        static_handlers: &mut HashMap<String, Arc<StaticFileHandler>>,
    ) {
        let site_id = config_arc.site_id();
        let minifier_cache = if config_arc.r#static.enable_minification.unwrap_or(true) {
            let min_config = MinifierCache::config_from_site(&site_id, &config_arc.r#static);
            Some(Arc::new(MinifierCache::new(min_config)))
        } else {
            None
        };

        let client = if config_arc.r#static.enable_minification.unwrap_or(true) {
            Some(minifier_client.clone())
        } else {
            None
        };

        let async_client = if config_arc.r#static.enable_minification.unwrap_or(true) {
            Some(async_minifier_client.clone())
        } else {
            None
        };

        let theme_config = config_arc
            .r#static
            .theme
            .as_ref()
            .map(|t| t.to_theme_config(default_theme_config))
            .unwrap_or_else(|| default_theme_config.clone());

        match StaticFileHandler::new_with_minifier(
            config_arc.r#static.clone(),
            site_id.clone(),
            minifier_cache,
            client,
            async_client,
            None,
            None,
            None,
            theme_config,
        ) {
            Ok(handler) => {
                if handler.is_enabled() {
                    static_handlers.insert(site_id, Arc::new(handler));
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to create static handler for site {}: {}",
                    site_id,
                    e
                );
            }
        }
    }

    fn build_listen_map_entry(
        config_arc: &Arc<SiteConfig>,
        main_config: &MainConfig,
        listen_map: &mut HashMap<SocketAddr, Vec<String>>,
        default_servers: &mut HashMap<SocketAddr, String>,
    ) {
        for listen_config in &config_arc.site.listen {
            if let Some(addr) = listen_config.to_socket_addr(main_config.server.port) {
                let http_port = if listen_config.is_ssl() {
                    main_config.tls.port
                } else {
                    main_config.server.port
                };
                let _actual_port = listen_config.port.unwrap_or(http_port);

                let bind_addr = if let Some(p) = listen_config.port {
                    SocketAddr::new(addr.ip(), p)
                } else {
                    addr
                };

                listen_map
                    .entry(bind_addr)
                    .or_default()
                    .push(config_arc.site_id());

                if listen_config.is_default_server() {
                    if let Some(existing) = default_servers.get(&bind_addr) {
                        tracing::error!(
                            "Multiple default servers configured for {}: {} and {}",
                            bind_addr,
                            existing,
                            config_arc.site_id()
                        );
                    } else {
                        default_servers.insert(bind_addr, config_arc.site_id());
                    }
                }
            }
        }
    }

    fn build_location_matchers(
        sites: &HashMap<String, SiteConfig>,
    ) -> HashMap<String, LocationMatcher> {
        let mut location_matchers = HashMap::new();
        for (site_id, config) in sites {
            if !config.proxy.locations.is_empty() {
                let patterns: Vec<String> = config
                    .proxy
                    .locations
                    .iter()
                    .map(|loc| loc.path.clone())
                    .collect();
                location_matchers.insert(site_id.clone(), LocationMatcher::new(patterns));
            }
        }
        location_matchers
    }

    fn log_configuration(
        listen_map: &HashMap<SocketAddr, Vec<String>>,
        default_servers: &HashMap<SocketAddr, String>,
    ) {
        if !listen_map.is_empty() {
            tracing::info!("IP-based virtual hosts configured:");
            for (addr, site_ids) in listen_map {
                tracing::info!("  {} -> {:?}", addr, site_ids);
            }
        }

        if !default_servers.is_empty() {
            tracing::info!("Default servers configured:");
            for (addr, site_id) in default_servers {
                tracing::info!("  {} -> {}", addr, site_id);
            }
        }
    }

    #[inline]
    fn clean_domain(domain: &str) -> String {
        domain.trim_start_matches("www.").to_lowercase()
    }

    pub fn with_plugin_manager(mut self, plugin_manager: Arc<PluginManager>) -> Self {
        self.plugin_manager = Some(plugin_manager);
        self
    }

    pub fn plugin_manager(&self) -> Option<&Arc<PluginManager>> {
        self.plugin_manager.as_ref()
    }

    #[inline]
    fn is_host_valid_for_site(&self, clean_host: &str, site_config: &Arc<SiteConfig>) -> bool {
        if let Some(suffixes) = self
            .cleaned_site_domain_suffixes
            .get(&site_config.site_id())
        {
            for suffix in suffixes {
                if clean_host.ends_with(suffix.as_ref()) {
                    return true;
                }
            }
        }
        if let Some(cleaned) = self.cleaned_site_domains.get(&site_config.site_id()) {
            for clean_domain in cleaned {
                if clean_host == clean_domain.as_ref() {
                    return true;
                }
            }
        }

        false
    }

    #[inline]
    fn parse_quictunnel_url(url: &str) -> Option<(String, u16)> {
        let trimmed = url.trim();
        if !trimmed.starts_with("quictunnel://") && !trimmed.starts_with("quictunnel:") {
            return None;
        }

        let rest = trimmed
            .trim_start_matches("quictunnel://")
            .trim_start_matches("quictunnel:");

        if let Some(colon_pos) = rest.rfind(':') {
            let peer = rest[..colon_pos].to_string();
            let port_str = &rest[colon_pos + 1..];
            if let Ok(port) = port_str.parse::<u16>() {
                return Some((peer, port));
            }
        }

        None
    }

    fn get_location_backend(
        &self,
        site_config: &Arc<SiteConfig>,
        path: &str,
    ) -> Option<RouteResult> {
        let locations = &site_config.proxy.locations;
        if locations.is_empty() {
            return None;
        }

        let site_id = site_config.site_id();
        let matcher = self.location_matchers.get(&site_id)?;

        if let Some((idx, _match_type)) = matcher.match_uri(path) {
            let location = &locations[idx];

            if let Some(ref backend) = location.backend {
                let site_id = site_config.site_id();
                return Some(match backend {
                    BackendConfig::Upstream { url } => {
                        let upstream = url
                            .clone()
                            .unwrap_or_else(|| site_config.site.upstream.get_upstream(path));

                        if let Some((peer, port)) = Self::parse_quictunnel_url(&upstream) {
                            RouteResult::Found(RouteTarget {
                                site_id: Arc::from(site_id.as_str()),
                                upstream: Arc::from(upstream.as_str()),
                                site_config: site_config.clone(),
                                static_handler: None,
                                backend_type: BackendType::QuicTunnel,
                                backend_socket: None,
                                backend_plugin: None,
                                tunnel_peer: Some(Arc::from(peer.as_str())),
                                tunnel_port: Some(port),
                                serverless_function: None,
                                php_location_config: None,
                                spin_app_name: None,
                            })
                        } else {
                            RouteResult::Found(RouteTarget {
                                site_id: Arc::from(site_id.as_str()),
                                upstream: Arc::from(upstream.as_str()),
                                site_config: site_config.clone(),
                                static_handler: None,
                                backend_type: BackendType::Upstream,
                                backend_socket: None,
                                backend_plugin: None,
                                tunnel_peer: None,
                                tunnel_port: None,
                                serverless_function: None,
                                php_location_config: None,
                                spin_app_name: None,
                            })
                        }
                    }
                    BackendConfig::FastCgi { socket } => {
                        let socket = socket
                            .clone()
                            .unwrap_or_else(|| "/run/php-fpm.sock".to_string());
                        RouteResult::Found(RouteTarget {
                            site_id: Arc::from(site_id.as_str()),
                            upstream: Arc::from(format!("fastcgi://{}", socket)),
                            site_config: site_config.clone(),
                            static_handler: None,
                            backend_type: BackendType::FastCgi,
                            backend_socket: Some(Arc::from(socket.as_str())),
                            backend_plugin: None,
                            tunnel_peer: None,
                            tunnel_port: None,
                            serverless_function: None,
                            php_location_config: None,
                            spin_app_name: None,
                        })
                    }
                    BackendConfig::AxumDynamic { socket, plugin } => {
                        let socket = socket
                            .clone()
                            .unwrap_or_else(|| "/run/synvoid/axum.sock".to_string());
                        let plugin = plugin
                            .clone()
                            .unwrap_or_else(|| "/opt/synvoid/plugins/app.so".to_string());
                        RouteResult::Found(RouteTarget {
                            site_id: Arc::from(site_id.as_str()),
                            upstream: Arc::from(format!("http://{}", socket)),
                            site_config: site_config.clone(),
                            static_handler: None,
                            backend_type: BackendType::AxumDynamic,
                            backend_socket: Some(Arc::from(socket.as_str())),
                            backend_plugin: Some(Arc::from(plugin.as_str())),
                            tunnel_peer: None,
                            tunnel_port: None,
                            serverless_function: None,
                            php_location_config: None,
                            spin_app_name: None,
                        })
                    }
                    BackendConfig::AppServer { socket } => {
                        let socket = socket.clone().unwrap_or_else(|| {
                            site_config
                                .app_server
                                .socket_path_for_site(&site_id, 0)
                                .display()
                                .to_string()
                        });
                        RouteResult::Found(RouteTarget {
                            site_id: Arc::from(site_id.as_str()),
                            upstream: Arc::from(format!("http://unix:{}:", socket)),
                            site_config: site_config.clone(),
                            static_handler: None,
                            backend_type: BackendType::AppServer,
                            backend_socket: Some(Arc::from(socket.as_str())),
                            backend_plugin: None,
                            tunnel_peer: None,
                            tunnel_port: None,
                            serverless_function: None,
                            php_location_config: None,
                            spin_app_name: None,
                        })
                    }
                    BackendConfig::Static { enabled } => {
                        if enabled.unwrap_or(false) {
                            let site_id = site_config.site_id();
                            if let Some(handler) = self.static_handlers.get(&site_id) {
                                return Some(RouteResult::Found(RouteTarget {
                                    site_id: Arc::from(site_id.as_str()),
                                    upstream: Arc::from(""),
                                    site_config: site_config.clone(),
                                    static_handler: Some(handler.clone()),
                                    backend_type: BackendType::Static,
                                    backend_socket: None,
                                    backend_plugin: None,
                                    tunnel_peer: None,
                                    tunnel_port: None,
                                    serverless_function: None,
                                    php_location_config: location.php.clone(),
                                    spin_app_name: None,
                                }));
                            }
                        }
                        RouteResult::Error("Static backend not available".to_string())
                    }
                    BackendConfig::Spin { spin_app_name } => {
                        if let Some(ref app_name) = spin_app_name {
                            let site_id = site_config.site_id();
                            return Some(RouteResult::Found(RouteTarget {
                                site_id: Arc::from(site_id.as_str()),
                                upstream: Arc::from(""),
                                site_config: site_config.clone(),
                                static_handler: None,
                                backend_type: BackendType::Spin,
                                backend_socket: None,
                                backend_plugin: None,
                                tunnel_peer: None,
                                tunnel_port: None,
                                serverless_function: None,
                                php_location_config: None,
                                spin_app_name: Some(Arc::from(app_name.clone())),
                            }));
                        }
                        RouteResult::Error("Spin backend missing app name".to_string())
                    }
                    #[cfg(feature = "mesh")]
                    BackendConfig::Mesh { upstream } => {
                        let upstream_id = upstream.clone();
                        RouteResult::Found(RouteTarget {
                            site_id: Arc::from(site_id.as_str()),
                            upstream: Arc::from(upstream_id.as_str()),
                            site_config: site_config.clone(),
                            static_handler: None,
                            backend_type: BackendType::Mesh,
                            backend_socket: None,
                            backend_plugin: None,
                            tunnel_peer: None,
                            tunnel_port: None,
                            serverless_function: None,
                            php_location_config: None,
                            spin_app_name: None,
                        })
                    }
                    #[cfg(not(feature = "mesh"))]
                    BackendConfig::Mesh { .. } => {
                        RouteResult::Error("Mesh backend not available".to_string())
                    }
                });
            }

            if let Some(ref php_config) = location.php {
                if let Some(socket) = php_config.socket.clone().or_else(|| {
                    php_config.host.as_ref().map(|h| {
                        if let Some(port) = php_config.port {
                            format!("{}:{}", h, port)
                        } else {
                            format!("{}:9000", h)
                        }
                    })
                }) {
                    let site_id = site_config.site_id();
                    return Some(RouteResult::Found(RouteTarget {
                        site_id: Arc::from(site_id.as_str()),
                        upstream: Arc::from(format!("php://{}", socket)),
                        site_config: site_config.clone(),
                        static_handler: None,
                        backend_type: BackendType::Php,
                        backend_socket: Some(Arc::from(socket.as_str())),
                        backend_plugin: None,
                        tunnel_peer: None,
                        tunnel_port: None,
                        serverless_function: None,
                        php_location_config: location.php.clone(),
                        spin_app_name: None,
                    }));
                }
            }

            if let Some(ref fastcgi_config) = location.fastcgi {
                if let Some(socket) = fastcgi_config.socket.clone() {
                    let site_id = site_config.site_id();
                    return Some(RouteResult::Found(RouteTarget {
                        site_id: Arc::from(site_id.as_str()),
                        upstream: Arc::from(format!("fastcgi://{}", socket)),
                        site_config: site_config.clone(),
                        static_handler: None,
                        backend_type: BackendType::FastCgi,
                        backend_socket: Some(Arc::from(socket.as_str())),
                        backend_plugin: None,
                        tunnel_peer: None,
                        tunnel_port: None,
                        serverless_function: None,
                        php_location_config: None,
                        spin_app_name: None,
                    }));
                }
            }

            if let Some(ref cgi_config) = location.cgi {
                if let Some(ref root) = cgi_config.root {
                    let site_id = site_config.site_id();
                    return Some(RouteResult::Found(RouteTarget {
                        site_id: Arc::from(site_id.as_str()),
                        upstream: Arc::from(format!("cgi://{}", root)),
                        site_config: site_config.clone(),
                        static_handler: None,
                        backend_type: BackendType::Cgi,
                        backend_socket: Some(Arc::from(root.as_str())),
                        backend_plugin: None,
                        tunnel_peer: None,
                        tunnel_port: None,
                        serverless_function: None,
                        php_location_config: None,
                        spin_app_name: None,
                    }));
                }
            }

            if let Some(ref proxy_config) = location.proxy {
                if let Some(ref upstream) = proxy_config.url {
                    let site_id = site_config.site_id();
                    return Some(RouteResult::Found(RouteTarget {
                        site_id: Arc::from(site_id.as_str()),
                        upstream: Arc::from(upstream.as_str()),
                        site_config: site_config.clone(),
                        static_handler: None,
                        backend_type: BackendType::Upstream,
                        backend_socket: None,
                        backend_plugin: None,
                        tunnel_peer: None,
                        tunnel_port: None,
                        serverless_function: None,
                        php_location_config: None,
                        spin_app_name: None,
                    }));
                }
            }

            if let Some(ref serverless_config) = location.serverless {
                if serverless_config.enabled {
                    if let Some(func) = serverless_config.functions.first() {
                        let site_id = site_config.site_id();
                        return Some(RouteResult::Found(RouteTarget {
                            site_id: Arc::from(site_id.as_str()),
                            upstream: Arc::from(""),
                            site_config: site_config.clone(),
                            static_handler: None,
                            backend_type: BackendType::Serverless,
                            backend_socket: None,
                            backend_plugin: None,
                            tunnel_peer: None,
                            tunnel_port: None,
                            serverless_function: Some(Arc::from(func.name.clone())),
                            php_location_config: None,
                            spin_app_name: None,
                        }));
                    }
                }
            }
        }

        None
    }

    fn route_to_target(
        &self,
        site_config: &Arc<SiteConfig>,
        path: &str,
        clean_host: &str,
    ) -> RouteResult {
        let site_id = site_config.site_id();

        if site_config.security.reject_unknown_hosts.unwrap_or(false)
            && !self.is_host_valid_for_site(clean_host, site_config)
        {
            return RouteResult::NotFound("Host not allowed".to_string());
        }

        if let Some(location_backend) = self.get_location_backend(site_config, path) {
            return location_backend;
        }

        if let Some(ref backend) = site_config.proxy.backend {
            match backend {
                BackendConfig::Upstream { url } => {
                    let upstream = url
                        .clone()
                        .unwrap_or_else(|| site_config.site.upstream.get_upstream(path));

                    if let Some((peer, port)) = Self::parse_quictunnel_url(&upstream) {
                        return RouteResult::Found(RouteTarget {
                            site_id: Arc::from(site_id.as_str()),
                            upstream: Arc::from(upstream.as_str()),
                            site_config: site_config.clone(),
                            static_handler: None,
                            backend_type: BackendType::QuicTunnel,
                            backend_socket: None,
                            backend_plugin: None,
                            tunnel_peer: Some(Arc::from(peer.as_str())),
                            tunnel_port: Some(port),
                            serverless_function: None,
                            php_location_config: None,
                            spin_app_name: None,
                        });
                    }

                    return RouteResult::Found(RouteTarget {
                        site_id: Arc::from(site_id.as_str()),
                        upstream: Arc::from(upstream.as_str()),
                        site_config: site_config.clone(),
                        static_handler: None,
                        backend_type: BackendType::Upstream,
                        backend_socket: None,
                        backend_plugin: None,
                        tunnel_peer: None,
                        tunnel_port: None,
                        serverless_function: None,
                        php_location_config: None,
                        spin_app_name: None,
                    });
                }
                BackendConfig::FastCgi { socket } => {
                    let socket = socket
                        .clone()
                        .unwrap_or_else(|| "/run/php-fpm.sock".to_string());
                    return RouteResult::Found(RouteTarget {
                        site_id: Arc::from(site_id.as_str()),
                        upstream: Arc::from(format!("fastcgi://{}", socket)),
                        site_config: site_config.clone(),
                        static_handler: None,
                        backend_type: BackendType::FastCgi,
                        backend_socket: Some(Arc::from(socket.as_str())),
                        backend_plugin: None,
                        tunnel_peer: None,
                        tunnel_port: None,
                        serverless_function: None,
                        php_location_config: None,
                        spin_app_name: None,
                    });
                }
                BackendConfig::AxumDynamic { socket, plugin } => {
                    let socket = socket
                        .clone()
                        .unwrap_or_else(|| "/run/synvoid/axum.sock".to_string());
                    let plugin = plugin
                        .clone()
                        .unwrap_or_else(|| "/opt/synvoid/plugins/app.so".to_string());
                    return RouteResult::Found(RouteTarget {
                        site_id: Arc::from(site_id.as_str()),
                        upstream: Arc::from(format!("http://{}", socket)),
                        site_config: site_config.clone(),
                        static_handler: None,
                        backend_type: BackendType::AxumDynamic,
                        backend_socket: Some(Arc::from(socket.as_str())),
                        backend_plugin: Some(Arc::from(plugin.as_str())),
                        tunnel_peer: None,
                        tunnel_port: None,
                        serverless_function: None,
                        php_location_config: None,
                        spin_app_name: None,
                    });
                }
                BackendConfig::AppServer { socket } => {
                    let socket = socket.clone().unwrap_or_else(|| {
                        site_config
                            .app_server
                            .socket_path_for_site(&site_id, 0)
                            .display()
                            .to_string()
                    });
                    return RouteResult::Found(RouteTarget {
                        site_id: Arc::from(site_id.as_str()),
                        upstream: Arc::from(format!("http://unix:{}:", socket)),
                        site_config: site_config.clone(),
                        static_handler: None,
                        backend_type: BackendType::AppServer,
                        backend_socket: Some(Arc::from(socket.as_str())),
                        backend_plugin: None,
                        tunnel_peer: None,
                        tunnel_port: None,
                        serverless_function: None,
                        php_location_config: None,
                        spin_app_name: None,
                    });
                }
                BackendConfig::Static { enabled } => {
                    if enabled.unwrap_or(false) {
                        if let Some(handler) = self.static_handlers.get(&site_id) {
                            return RouteResult::Found(RouteTarget {
                                site_id: Arc::from(site_id.as_str()),
                                upstream: Arc::from(""),
                                site_config: site_config.clone(),
                                static_handler: Some(handler.clone()),
                                backend_type: BackendType::Static,
                                backend_socket: None,
                                backend_plugin: None,
                                tunnel_peer: None,
                                tunnel_port: None,
                                serverless_function: None,
                                php_location_config: None,
                                spin_app_name: None,
                            });
                        }
                    }
                }
                BackendConfig::Spin { spin_app_name } => {
                    if let Some(ref app_name) = spin_app_name {
                        return RouteResult::Found(RouteTarget {
                            site_id: Arc::from(site_id.as_str()),
                            upstream: Arc::from(""),
                            site_config: site_config.clone(),
                            static_handler: None,
                            backend_type: BackendType::Spin,
                            backend_socket: None,
                            backend_plugin: None,
                            tunnel_peer: None,
                            tunnel_port: None,
                            serverless_function: None,
                            php_location_config: None,
                            spin_app_name: Some(Arc::from(app_name.clone())),
                        });
                    }
                }
                #[cfg(feature = "mesh")]
                BackendConfig::Mesh { upstream } => {
                    let upstream_id = upstream.clone();
                    return RouteResult::Found(RouteTarget {
                        site_id: Arc::from(site_id.as_str()),
                        upstream: Arc::from(upstream_id.as_str()),
                        site_config: site_config.clone(),
                        static_handler: None,
                        backend_type: BackendType::Mesh,
                        backend_socket: None,
                        backend_plugin: None,
                        tunnel_peer: None,
                        tunnel_port: None,
                        serverless_function: None,
                        php_location_config: None,
                        spin_app_name: None,
                    });
                }
                #[cfg(not(feature = "mesh"))]
                BackendConfig::Mesh { .. } => {}
            }
        }

        if let Some(ref php_config) = site_config.proxy.php {
            if let Some(socket) = php_config.socket.clone().or_else(|| {
                php_config.host.as_ref().map(|h| {
                    if let Some(port) = php_config.port {
                        format!("{}:{}", h, port)
                    } else {
                        format!("{}:9000", h)
                    }
                })
            }) {
                let _root = php_config
                    .root
                    .clone()
                    .unwrap_or_else(|| "/var/www/html".to_string());
                return RouteResult::Found(RouteTarget {
                    site_id: Arc::from(site_id.as_str()),
                    upstream: Arc::from(format!("php://{}", socket)),
                    site_config: site_config.clone(),
                    static_handler: None,
                    backend_type: BackendType::Php,
                    backend_socket: Some(Arc::from(socket.as_str())),
                    backend_plugin: None,
                    tunnel_peer: None,
                    tunnel_port: None,
                    serverless_function: None,
                    php_location_config: None,
                    spin_app_name: None,
                });
            }
        }

        if let Some(ref cgi_config) = site_config.proxy.cgi {
            if let Some(ref root) = cgi_config.root {
                return RouteResult::Found(RouteTarget {
                    site_id: Arc::from(site_id.as_str()),
                    upstream: Arc::from(format!("cgi://{}", root)),
                    site_config: site_config.clone(),
                    static_handler: None,
                    backend_type: BackendType::Cgi,
                    backend_socket: Some(Arc::from(root.as_str())),
                    backend_plugin: None,
                    tunnel_peer: None,
                    tunnel_port: None,
                    serverless_function: None,
                    php_location_config: None,
                    spin_app_name: None,
                });
            }
        }

        if site_config.app_server.enabled.unwrap_or(false) {
            let socket = site_config
                .app_server
                .socket_path_for_site(&site_id, 0)
                .display()
                .to_string();
            return RouteResult::Found(RouteTarget {
                site_id: Arc::from(site_id.as_str()),
                upstream: Arc::from(format!("http://unix:{}:", socket)),
                site_config: site_config.clone(),
                static_handler: None,
                backend_type: BackendType::AppServer,
                backend_socket: Some(Arc::from(socket.as_str())),
                backend_plugin: None,
                tunnel_peer: None,
                tunnel_port: None,
                serverless_function: None,
                php_location_config: None,
                spin_app_name: None,
            });
        }

        let static_handler = self.static_handlers.get(&site_id).cloned();
        if let Some(ref handler) = static_handler {
            if handler.get_matching_location(path).is_some() {
                return RouteResult::Found(RouteTarget {
                    site_id: Arc::from(site_id.as_str()),
                    upstream: Arc::from(""),
                    site_config: site_config.clone(),
                    static_handler: Some(handler.clone()),
                    backend_type: BackendType::Static,
                    backend_socket: None,
                    backend_plugin: None,
                    tunnel_peer: None,
                    tunnel_port: None,
                    serverless_function: None,
                    php_location_config: None,
                    spin_app_name: None,
                });
            }
        }

        let upstream = site_config.site.upstream.get_upstream(path);
        RouteResult::Found(RouteTarget {
            site_id: Arc::from(site_id.as_str()),
            upstream: Arc::from(upstream.as_str()),
            site_config: site_config.clone(),
            static_handler,
            backend_type: BackendType::Upstream,
            backend_socket: None,
            backend_plugin: None,
            tunnel_peer: None,
            tunnel_port: None,
            serverless_function: None,
            php_location_config: None,
            spin_app_name: None,
        })
    }

    pub fn route(&self, host: &str, path: &str) -> RouteResult {
        self.route_with_local_addr(host, path, None)
    }

    pub fn route_with_local_addr(
        &self,
        host: &str,
        path: &str,
        local_addr: Option<SocketAddr>,
    ) -> RouteResult {
        let clean_host = Self::clean_domain(host);
        let clean_host_arc: Arc<str> = Arc::from(clean_host.as_str());

        if let Some(addr) = local_addr {
            if let Some(site_ids) = self.listen_map.get(&addr) {
                for site_id in site_ids {
                    if let Some(site_config) = self.site_map.get(site_id) {
                        if self.is_host_valid_for_site(&clean_host, site_config)
                            || site_config.site.domains.is_empty()
                        {
                            return self.route_to_target(site_config, path, &clean_host);
                        }
                        if let Some(suffixes) = self.cleaned_site_domain_suffixes.get(site_id) {
                            for suffix in suffixes {
                                if clean_host.ends_with(suffix.as_ref()) {
                                    return self.route_to_target(site_config, path, &clean_host);
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Some(site_config) = self.domain_map.get(clean_host_arc.as_ref()) {
            return self.route_to_target(site_config, path, &clean_host);
        }

        for (domain, site_config) in &self.suffix_domain_map {
            if clean_host.ends_with(domain.as_ref()) {
                return self.route_to_target(site_config, path, &clean_host);
            }
        }

        if clean_host.is_empty() || clean_host == "*" {
            if let Some(addr) = local_addr {
                if let Some(default_site_id) = self.default_servers.get(&addr) {
                    if let Some(site_config) = self.site_map.get(default_site_id) {
                        return self.route_to_target(site_config, path, &clean_host);
                    }
                }
            }
            if let Some(default_site_id) = self.default_servers.values().next() {
                if let Some(site_config) = self.site_map.get(default_site_id) {
                    return self.route_to_target(site_config, path, &clean_host);
                }
            }
        }

        match self.fallback_mode.as_str() {
            "return_404" => RouteResult::NotFound(format!("No site configured for host: {}", host)),
            "proxy_to" => {
                if let Some(upstream) = &self.fallback_upstream {
                    let default_site = SiteConfig::default_fallback_site(upstream.clone());
                    let site_id = default_site.site_id();
                    let static_handler = self.static_handlers.get(&site_id).cloned();

                    RouteResult::Found(RouteTarget {
                        site_id: Arc::from(site_id.as_str()),
                        upstream: Arc::from(upstream.as_str()),
                        site_config: Arc::new(default_site),
                        static_handler,
                        backend_type: BackendType::Upstream,
                        backend_socket: None,
                        backend_plugin: None,
                        tunnel_peer: None,
                        tunnel_port: None,
                        serverless_function: None,
                        php_location_config: None,
                        spin_app_name: None,
                    })
                } else {
                    RouteResult::Error(
                        "Fallback mode is 'proxy_to' but no upstream configured".to_string(),
                    )
                }
            }
            _ => RouteResult::NotFound(format!("No site configured for host: {}", host)),
        }
    }

    pub fn update_sites(&mut self, sites: HashMap<String, SiteConfig>) {
        self.domain_map.clear();
        self.suffix_domain_map.clear();
        self.static_handlers.clear();
        self.listen_map.clear();
        self.default_servers.clear();
        self.cleaned_site_domains.clear();
        self.cleaned_site_domain_suffixes.clear();
        self.site_map.clear();

        for (_site_id, config) in sites {
            let config_arc = Arc::new(config);
            let site_id_str = config_arc.site_id();

            self.site_map
                .insert(site_id_str.clone(), config_arc.clone());

            let cleaned: Vec<Arc<str>> = config_arc
                .site
                .domains
                .iter()
                .map(|d| Arc::from(Self::clean_domain(d).as_str()))
                .collect();

            let mut suffixes: Vec<Arc<str>> = Vec::new();
            for clean_domain in &cleaned {
                if clean_domain.starts_with('.') || clean_domain.contains('*') {
                    self.suffix_domain_map
                        .push((clean_domain.clone(), config_arc.clone()));
                    suffixes.push(clean_domain.clone());
                } else {
                    self.domain_map
                        .insert(clean_domain.clone(), config_arc.clone());
                }
            }

            self.cleaned_site_domains
                .insert(site_id_str.clone(), cleaned);
            self.cleaned_site_domain_suffixes
                .insert(site_id_str.clone(), suffixes);

            if config_arc.r#static.enabled.unwrap_or(false) {
                let minifier_cache = if config_arc.r#static.enable_minification.unwrap_or(true) {
                    let min_config =
                        MinifierCache::config_from_site(&site_id_str, &config_arc.r#static);
                    Some(Arc::new(MinifierCache::new(min_config)))
                } else {
                    None
                };

                let client = if config_arc.r#static.enable_minification.unwrap_or(true) {
                    self.minifier_client.clone()
                } else {
                    None
                };

                match StaticFileHandler::new_with_minifier(
                    config_arc.r#static.clone(),
                    site_id_str.clone(),
                    minifier_cache,
                    client,
                    self.async_minifier_client.clone(),
                    None,
                    None,
                    None,
                    ThemeConfig::default(),
                ) {
                    Ok(handler) => {
                        if handler.is_enabled() {
                            self.static_handlers
                                .insert(site_id_str.clone(), Arc::new(handler));
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to create static handler for site {}: {}",
                            site_id_str,
                            e
                        );
                    }
                }
            }

            if !config_arc.site.listen.is_empty() {
                for listen_config in &config_arc.site.listen {
                    if let Some(addr) = listen_config.to_socket_addr(80) {
                        self.listen_map
                            .entry(addr)
                            .or_default()
                            .push(site_id_str.clone());

                        if listen_config.is_default_server() {
                            if let Some(existing) = self.default_servers.get(&addr) {
                                tracing::error!(
                                    "Multiple default servers configured for {}: {} and {}",
                                    addr,
                                    existing,
                                    site_id_str
                                );
                            } else {
                                self.default_servers.insert(addr, site_id_str.clone());
                            }
                        }
                    }
                }
            }
        }

        self.suffix_domain_map
            .sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    }

    #[cfg(feature = "mesh")]
    pub fn update_static_handler_mesh_config(
        &self,
        site_id: &str,
        image_protection: Option<MeshImageProtectionConfig>,
        compression: Option<MeshCompressionConfig>,
        minification: Option<MeshMinificationConfig>,
    ) -> Option<Arc<StaticFileHandler>> {
        self.static_handlers.get(site_id).map(|handler| {
            let new_handler =
                (**handler)
                    .clone()
                    .with_mesh_config(image_protection, compression, minification);
            Arc::new(new_handler)
        })
    }
}

impl Default for Router {
    fn default() -> Self {
        Router {
            domain_map: HashMap::new(),
            suffix_domain_map: Vec::new(),
            fallback_mode: "return_404".to_string(),
            fallback_upstream: None,
            static_handlers: HashMap::new(),
            minifier_client: None,
            async_minifier_client: None,
            listen_map: HashMap::new(),
            default_servers: HashMap::new(),
            plugin_manager: None,
            cleaned_site_domains: HashMap::new(),
            cleaned_site_domain_suffixes: HashMap::new(),
            location_matchers: HashMap::new(),
            site_map: HashMap::new(),
        }
    }
}
