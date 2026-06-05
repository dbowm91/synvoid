use std::sync::Arc;
use synvoid_core::drain::DrainState;
use synvoid_core::metrics::MetricsSink;
use synvoid_proxy::routing::RouteResolver;
use synvoid_waf::traits::WafProcessor;

/// Bundled runtime dependencies for the HTTP server pipeline.
///
/// This struct allows the HTTP pipeline to depend on trait objects
/// rather than concrete root types for WAF, routing, metrics, and drain.
#[derive(Clone)]
pub struct HttpRuntimeContext<W, R, M, D> {
    pub waf: Arc<W>,
    pub router: Arc<R>,
    pub metrics: Arc<M>,
    pub drain: Arc<D>,
}

impl<W, R, M, D> HttpRuntimeContext<W, R, M, D>
where
    W: WafProcessor,
    R: RouteResolver,
    M: MetricsSink,
    D: DrainState,
{
    pub fn new(waf: Arc<W>, router: Arc<R>, metrics: Arc<M>, drain: Arc<D>) -> Self {
        Self {
            waf,
            router,
            metrics,
            drain,
        }
    }
}
