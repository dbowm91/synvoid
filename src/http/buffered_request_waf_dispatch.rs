use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;

use crate::config::{HttpConfig, MainConfig};
use crate::router::RouteTarget;
use crate::waf::WafCore;

#[allow(clippy::too_many_arguments)]
pub async fn maybe_handle_buffered_request_waf<
    DropFn,
    LogFn,
    BlockedFn,
    BlockedEgressFn,
    ChallengedFn,
    ElapsedFn,
>(
    waf: &Arc<WafCore>,
    target: &RouteTarget,
    skip_waf: bool,
    site_id: &str,
    client_ip: std::net::IpAddr,
    method_str: &str,
    path: &str,
    query_string: Option<&str>,
    headers: &http::HeaderMap,
    body_slice_ref: Option<&[u8]>,
    user_agent: Option<&str>,
    http_config: &HttpConfig,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
    on_drop: DropFn,
    on_log: LogFn,
    on_blocked: BlockedFn,
    on_blocked_egress: BlockedEgressFn,
    on_challenged: ChallengedFn,
    elapsed_ms: ElapsedFn,
) -> Option<Response<BoxBody<Bytes, Infallible>>>
where
    DropFn: FnMut(),
    LogFn: FnMut(u16, u64),
    BlockedFn: FnMut(),
    BlockedEgressFn: FnMut(u64),
    ChallengedFn: FnMut(u64),
    ElapsedFn: FnMut() -> u64,
{
    let site_bot_config = Some(&target.site_config.bot);
    synvoid_http::maybe_handle_buffered_request_waf(
        target.clone(),
        skip_waf,
        site_id.to_string(),
        client_ip,
        method_str.to_string(),
        path.to_string(),
        query_string.map(|s| s.to_string()),
        headers.clone(),
        body_slice_ref.map(|b| Bytes::copy_from_slice(b)),
        user_agent.map(|s| s.to_string()),
        http_config.clone(),
        alt_svc.clone(),
        Arc::clone(main_config),
        || {
            waf.check_request_full(
                Some(site_id),
                client_ip,
                method_str,
                path,
                query_string.as_deref(),
                &headers,
                body_slice_ref.as_deref(),
                user_agent.as_deref(),
                None,
                site_bot_config,
                None,
            )
        },
        on_drop,
        on_log,
        on_blocked,
        on_blocked_egress,
        on_challenged,
        elapsed_ms,
        |status, message| {
            waf.error_page_manager.render_page_with_theme(
                status,
                Some(message),
                target
                    .site_config
                    .error_pages
                    .theme
                    .as_ref()
                    .map(|theme_config| {
                        theme_config.to_theme_config(waf.error_page_manager.theme())
                    })
                    .as_ref(),
            )
        },
        |tar_path| waf.generate_tarpit_response(tar_path),
    )
    .await
}
