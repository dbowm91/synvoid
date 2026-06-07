// Root compatibility shim — canonical implementation is in synvoid-http.
use std::net::IpAddr;
use std::sync::Arc;

use bytes::Bytes;

use crate::config::MainConfig;
use crate::router::{RouteTarget, Router};
use crate::waf::WafCore;

pub fn maybe_handle_wasm_request_filter(
    router: &Arc<Router>,
    target: &RouteTarget,
    path: &str,
    method: &http::Method,
    parts: &http::request::Parts,
    body_slice: &Option<Arc<Bytes>>,
    client_ip: IpAddr,
    waf: &Arc<WafCore>,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
    on_request_log: impl Fn(u16),
) -> Option<
    http::Response<http_body_util::combinators::BoxBody<bytes::Bytes, std::convert::Infallible>>,
> {
    let pm = router
        .plugin_manager()
        .and_then(|pm| pm.downcast_ref::<crate::plugin::PluginManager>());
    synvoid_http::maybe_handle_wasm_request_filter(
        pm.map(|pm| pm as &dyn synvoid_http::WasmFilterBackend),
        target,
        path,
        method,
        parts,
        body_slice,
        client_ip,
        waf.as_ref(),
        alt_svc,
        main_config,
        on_request_log,
    )
}
