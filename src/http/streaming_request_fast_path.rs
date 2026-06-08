use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;

use crate::config::MainConfig;
use crate::proxy::client_registry::UpstreamClientRegistry;
use crate::proxy::WafDecision;
use crate::router::{RouteTarget, Router};
use crate::waf::WafCore;

pub use synvoid_http::StreamingRequestFastPathOutcome;

#[allow(clippy::too_many_arguments)]
pub async fn maybe_handle_streaming_request_fast_path<DecisionFn, DecisionFut, LogFn>(
    target: &RouteTarget,
    router: &Arc<Router>,
    waf: &Arc<WafCore>,
    skip_waf: bool,
    site_id: &str,
    client_ip: std::net::IpAddr,
    method: &http::Method,
    path: &str,
    query_string: Option<&str>,
    parts: &http::request::Parts,
    user_agent: Option<&str>,
    body: hyper::body::Incoming,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
    upstream_client_registry: &Arc<UpstreamClientRegistry>,
    #[cfg(feature = "mesh")] serverless_manager: &Option<
        Arc<crate::serverless::manager::ServerlessManager>,
    >,
    _on_streaming_serverless_status: LogFn,
    handle_non_pass_decision: DecisionFn,
) -> Result<StreamingRequestFastPathOutcome, hyper::Error>
where
    DecisionFn: FnOnce(WafDecision) -> DecisionFut,
    DecisionFut: Future<Output = Option<Response<BoxBody<Bytes, Infallible>>>>,
    LogFn: FnOnce(u16),
{
    let method_str = method.to_string();

    synvoid_http::maybe_handle_streaming_request_fast_path(
        target,
        router,
        skip_waf,
        parts,
        body,
        || {
            waf.check_request_full(
                Some(site_id),
                client_ip,
                &method_str,
                path,
                query_string,
                &parts.headers,
                None,
                user_agent,
                None,
                Some(&target.site_config.bot),
                None,
            )
        },
        |body| async move {
            let streaming_waf = waf
                .streaming()
                .map(|s| Box::new(s) as Box<dyn synvoid_http::shared_handler::StreamingWafScanner>);
            synvoid_http::handle_streaming_request_pass(
                target,
                path,
                method,
                parts,
                body,
                client_ip,
                streaming_waf,
                alt_svc,
                main_config,
                upstream_client_registry,
                #[cfg(feature = "mesh")]
                serverless_manager,
                _on_streaming_serverless_status,
                || {
                    let body = waf.error_page_manager.render_page_with_theme(
                        403,
                        Some("Forbidden"),
                        target
                            .site_config
                            .error_pages
                            .theme
                            .as_ref()
                            .map(|theme_config| {
                                theme_config.to_theme_config(waf.error_page_manager.theme())
                            })
                            .as_ref(),
                    );
                    crate::http::response_builder::build_response_with_alt_svc(
                        403,
                        body,
                        "text/html",
                        alt_svc,
                        main_config.as_ref(),
                    )
                },
            )
            .await
        },
        handle_non_pass_decision,
    )
    .await
}
