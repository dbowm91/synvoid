use synvoid_core::request::RequestContext;
use synvoid_core::routing::RouteResolution;

pub trait RouteResolver: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    fn resolve(&self, ctx: &RequestContext) -> Result<RouteResolution, Self::Error>;
}
