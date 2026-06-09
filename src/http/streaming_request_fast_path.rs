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

use synvoid_http::BufferedRequestWaf;
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
    _alt_svc: &Option<String>,
    _main_config: &Arc<MainConfig>,
    _upstream_client_registry: &Arc<UpstreamClientRegistry>,
    #[cfg(feature = "mesh")] _serverless_manager: &Option<
        Arc<crate::serverless::manager::ServerlessManager>,
    >,
    _on_streaming_serverless_status: LogFn,
    handle_non_pass_decision: DecisionFn,
) -> Result<StreamingRequestFastPathOutcome, hyper::Error>
where
    DecisionFn: FnOnce(WafDecision) -> DecisionFut + Send + 'static,
    DecisionFut: Future<Output = Option<Response<BoxBody<Bytes, Infallible>>>> + Send + 'static,
    LogFn: FnOnce(u16) + Send + 'static,
{
    let method_str = method.to_string();
    let site_id_for_check = site_id.to_string();
    let path_for_check = path.to_string();
    let query_for_check = query_string.map(str::to_string);
    let headers_for_check = parts.headers.clone();
    let user_agent_for_check = user_agent.map(str::to_string);
    let site_bot_config_for_check = target.site_config.bot.clone();
    let waf_for_check = Arc::clone(waf);

    synvoid_http::maybe_handle_streaming_request_fast_path(
        target,
        router,
        skip_waf,
        parts,
        body,
        move || {
            Arc::clone(&waf_for_check).check_request_full_owned(
                Some(site_id_for_check.clone()),
                client_ip,
                method_str.clone(),
                path_for_check.clone(),
                query_for_check.clone(),
                headers_for_check.clone(),
                None,
                user_agent_for_check.clone(),
                None,
                Some(site_bot_config_for_check.clone()),
            )
        },
        move |body| async move { Ok(StreamingRequestFastPathOutcome::Continue(body)) },
        handle_non_pass_decision,
    )
    .await
}
