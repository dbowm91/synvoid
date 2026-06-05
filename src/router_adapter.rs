use std::sync::Arc;

use synvoid_core::request::RequestContext;
use synvoid_core::routing::{RouteResolution, RouteTarget as CoreRouteTarget};
use synvoid_proxy::routing::RouteResolver;

use crate::router::{BackendType, RouteResult, RouteTarget, Router};

/// Adapter that implements [`RouteResolver`] for the root [`Router`].
#[derive(Clone)]
pub struct RouterRouteResolver {
    router: Arc<Router>,
}

impl RouterRouteResolver {
    pub fn new(router: Arc<Router>) -> Self {
        Self { router }
    }
}

impl RouteResolver for RouterRouteResolver {
    type Error = RouterResolveError;

    fn resolve(&self, ctx: &RequestContext) -> Result<RouteResolution, Self::Error> {
        let host = ctx.host.as_deref().unwrap_or("");
        let path = ctx.path.as_deref().unwrap_or("/");

        let result = self.router.route(host, path);

        match result {
            RouteResult::Found(target) => Ok(map_route_target(target)),
            RouteResult::NotFound(_reason) => Ok(RouteResolution {
                site_id: None,
                target: CoreRouteTarget::NotFound,
                cache_policy_id: None,
                security_policy_id: None,
            }),
            RouteResult::Error(msg) => Err(RouterResolveError(msg)),
        }
    }
}

#[derive(Debug)]
pub struct RouterResolveError(String);

impl std::fmt::Display for RouterResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "route resolution failed: {}", self.0)
    }
}

impl std::error::Error for RouterResolveError {}

fn map_route_target(target: RouteTarget) -> RouteResolution {
    let site_id = Some(target.site_id.to_string());

    let core_target = match target.backend_type {
        BackendType::Upstream => CoreRouteTarget::ReverseProxy {
            upstream_id: target.upstream.to_string(),
        },
        BackendType::Static => CoreRouteTarget::Static {
            location_id: target.upstream.to_string(),
        },
        BackendType::FastCgi => CoreRouteTarget::FastCgi {
            pool_id: target.upstream.to_string(),
        },
        BackendType::Cgi => CoreRouteTarget::Cgi {
            handler_id: target.upstream.to_string(),
        },
        BackendType::Php => CoreRouteTarget::Php {
            pool_id: target.upstream.to_string(),
        },
        BackendType::Serverless => CoreRouteTarget::Serverless {
            function_id: target
                .serverless_function
                .map(|s| s.to_string())
                .unwrap_or_default(),
        },
        BackendType::Spin => CoreRouteTarget::Plugin {
            plugin_id: target
                .spin_app_name
                .map(|s| s.to_string())
                .unwrap_or_default(),
        },
        BackendType::QuicTunnel => CoreRouteTarget::Tunnel {
            tunnel_id: target
                .tunnel_peer
                .map(|s| s.to_string())
                .unwrap_or_default(),
        },
        BackendType::Mesh => CoreRouteTarget::NotFound,
        BackendType::AxumDynamic | BackendType::AppServer => CoreRouteTarget::NotFound,
    };

    RouteResolution {
        site_id,
        target: core_target,
        cache_policy_id: None,
        security_policy_id: None,
    }
}
