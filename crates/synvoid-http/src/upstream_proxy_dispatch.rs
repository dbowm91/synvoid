use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use futures::future::BoxFuture;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::Full;

use synvoid_config::MainConfig;
use synvoid_http_client::{send_request_streaming_generic, ErasedBodyImpl};
#[cfg(feature = "mesh")]
use synvoid_mesh::mesh::transport::MeshTransportManager;
use synvoid_metrics::WorkerMetrics;
use synvoid_proxy::RouteTarget;
use synvoid_proxy::Router;

use crate::handle_buffered_upstream_request;
use crate::handle_streaming_upstream_response;
use crate::upstream_proxy_dispatch_plan::UpstreamProxyDispatchPlan;

#[allow(clippy::too_many_arguments)]
pub async fn handle_pass_upstream_proxy_phase<PoisonFn, PoisonFut>(
    target: &RouteTarget,
    router: &Arc<Router>,
    path: &str,
    site_id: &str,
    method: &http::Method,
    parts: &http::request::Parts,
    full_body_arc: &Arc<Bytes>,
    dispatch_plan: UpstreamProxyDispatchPlan,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
    metrics: &Option<Arc<WorkerMetrics>>,
    request_body_size: u64,
    #[cfg(feature = "mesh")] mesh_transport: &Option<Arc<MeshTransportManager>>,
    quictunnel_request: impl Fn(
        http::Method,
        &str,
        Option<&http::HeaderMap>,
        Option<Bytes>,
        Option<std::time::Duration>,
    )
        -> BoxFuture<'static, anyhow::Result<synvoid_http_client::HttpResponse>>,
    on_upstream_success: impl Fn(),
    on_upstream_failure: impl Fn(),
    on_error_egress: impl Fn(u64),
    mark_image_rights: PoisonFn,
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error>
where
    PoisonFn: Fn(
        Bytes,
        String,
        Option<String>,
        Option<synvoid_config::site::SiteImageRightsConfig>,
    ) -> PoisonFut,
    PoisonFut: std::future::Future<Output = Bytes>,
{
    if let Some(streaming) = dispatch_plan.streaming {
        let erased_body = ErasedBodyImpl::from_full(Full::new(full_body_arc.as_ref().clone()));
        let request_result = send_request_streaming_generic(
            streaming.client.as_ref(),
            method.clone(),
            &dispatch_plan.upstream_target.url,
            erased_body,
            streaming.forward_headers,
            Some(dispatch_plan.upstream_target.timeout),
        )
        .await;

        return handle_streaming_upstream_response(
            request_result,
            target,
            site_id,
            request_body_size,
            &dispatch_plan.headers_to_filter,
            dispatch_plan.upstream_target.max_response_size,
            alt_svc,
            main_config,
            metrics,
            on_upstream_success,
            on_upstream_failure,
            on_error_egress,
        )
        .await;
    }

    handle_buffered_upstream_request(
        target,
        router,
        path,
        site_id,
        method,
        parts,
        full_body_arc,
        &dispatch_plan.forwarding_client,
        &dispatch_plan.upstream_target,
        &dispatch_plan.headers_to_filter,
        alt_svc,
        main_config,
        metrics,
        request_body_size,
        #[cfg(feature = "mesh")]
        mesh_transport,
        quictunnel_request,
        on_upstream_success,
        on_upstream_failure,
        on_error_egress,
        mark_image_rights,
    )
    .await
}
