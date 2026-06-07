//! SynVoid HTTP server utilities.
//!
//! Provides HTTP/1.1 and HTTP/2 server pipeline components, body helpers,
//! header helpers, and response construction primitives.

pub mod app_server_backend_dispatch;
pub mod axum_dynamic_dispatch;
pub mod backend_dispatch;
pub mod body_policy;
pub mod buffered_request_waf_dispatch;
pub mod cgi_backend_dispatch;
pub mod challenge_paths;
pub mod early_parse;
pub mod fastcgi_php_backend_dispatch;
pub mod headers;
pub mod http3_body;
pub mod http3_buffered_upstream_dispatch;
pub mod http3_request_dispatch;
pub mod http3_request_flow;
pub mod http3_request_prelude;
pub mod http3_route_dispatch;
pub mod http3_streaming_upstream_dispatch;
pub mod http3_terminal;
pub mod http3_waf_dispatch;
pub mod http_request_flow;
pub mod http_request_postlude;
pub mod internal_endpoint_dispatch;
pub mod internal_handlers;
pub mod listener;
pub mod mesh_backend_dispatch;
pub mod request_frontdoor;
pub mod request_parse;
pub mod request_preparation;
pub mod response_builder;
pub mod response_helpers;
pub mod response_transform;
pub mod runtime;
pub mod serverless_backend_dispatch;
pub mod shared_handler;
pub mod special_request_paths;
pub mod spin_backend_dispatch;
pub mod static_backend_dispatch;
pub mod streaming_request_fast_path;
pub mod streaming_request_pass;
pub mod streaming_waf_decision;
pub mod streaming_waf_upstream_dispatch;
pub mod traffic_control;
pub mod upload_validation_dispatch;
pub mod upstream_buffered_dispatch;
pub mod upstream_proxy_dispatch;
pub mod upstream_proxy_dispatch_plan;
pub mod upstream_response_transform;
pub mod upstream_streaming_dispatch;
pub mod validation_helpers;
pub mod waf_decision;
pub mod wasm_filter_dispatch;
pub mod websocket_dispatch;
pub mod websocket_upgrade_dispatch;

pub use app_server_backend_dispatch::maybe_handle_app_server_backend;
pub use axum_dynamic_dispatch::{maybe_handle_axum_dynamic_backend, AxumDynamicRouterLookup};
pub use backend_dispatch::{
    handle_pass_backend_dispatch, BackendDispatchContext, BackendDispatchMetrics,
};
pub use body_policy::{collect_and_scan_request_body, BodyPolicyError, RequestBodyWaf};
pub use buffered_request_waf_dispatch::maybe_handle_buffered_request_waf;
pub use cgi_backend_dispatch::maybe_handle_cgi_backend;
pub use challenge_paths::{maybe_handle_challenge_paths, ChallengePathWaf};
pub use fastcgi_php_backend_dispatch::maybe_handle_fastcgi_or_php_backend;
pub use http3_body::{
    collect_http3_request_body, Http3BodyCollectionOutcome, Http3CollectedBody, Http3RequestStream,
};
pub use http3_buffered_upstream_dispatch::handle_http3_buffered_upstream_pass;
pub use http3_request_dispatch::{handle_http3_request_dispatch, Http3RequestWaf};
pub use http3_request_flow::{
    prepare_http3_request_dispatch, Http3RequestDispatchContext, Http3RequestDispatchOutcome,
    Http3RequestResolver,
};
pub use http3_request_prelude::{
    prepare_http3_request_prelude, Http3RequestPrelude, Http3RequestPreludeOutcome,
};
pub use http3_route_dispatch::handle_http3_found_route;
pub use http3_streaming_upstream_dispatch::handle_http3_streaming_upstream_pass;
pub use http3_terminal::{finalize_http3_request, maybe_handle_http3_terminal_route_result};
pub use http3_waf_dispatch::{maybe_handle_http3_waf_decision, Http3WafDecisionOutcome};
pub use http_request_flow::{prepare_http_request_flow, HttpRequestFlowOutcome};
pub use http_request_postlude::{handle_http_request_postlude, HttpRequestPostludeContext};
pub use internal_endpoint_dispatch::{dispatch_internal_endpoint, InternalEndpointDispatch};
pub use internal_handlers::{
    handle_drain_request, handle_drain_status_request, handle_health_request, handle_ready_request,
    DrainStatusSnapshot, HttpDrainControl,
};
#[cfg(feature = "mesh")]
pub use mesh_backend_dispatch::maybe_handle_mesh_backend;
pub use request_frontdoor::{
    prepare_request_frontdoor, FrontdoorRequest, RequestFrontdoorContext, RequestFrontdoorOutcome,
};
pub use request_parse::{
    classify_internal_endpoint, early_waf_decision, extract_request_metadata, extract_trust_token,
    parse_http01_challenge_token, resolve_client_ip, sanitize_and_resolve_client_ip,
    should_handle_key_exchange_path, should_skip_waf_from_trust_cookie, EarlyWafHooks,
    InternalEndpointAction,
};
pub use request_preparation::{
    finalize_request_preparation, prepare_request_after_preflight, prepare_request_preflight,
    BufferedRequestWaf, PreparedRequest, RequestPreflight, RequestPreflightOutcome,
    RequestPreparationOutcome,
};
pub use response_builder::{
    bad_gateway_bytes, error_body, error_response_bytes, fallback_error_boxed,
    fallback_error_bytes, fallback_error_full, reason_phrase,
};
pub use response_helpers::{
    apply_security_headers, build_websocket_response, format_secure_http_only_cookie,
    BoxBodyResponse,
};
pub use response_transform::{apply_compression, apply_minification, ResponseTransformConfig};
#[cfg(feature = "mesh")]
pub use serverless_backend_dispatch::maybe_handle_serverless_backend;
pub use shared_handler::{
    collect_body_with_chunk_waf, stream_body_with_waf, BodyCollectionProtocol,
    SharedRequestHandler, WafStreamedBody,
};
#[cfg(feature = "mesh")]
pub use special_request_paths::{maybe_handle_special_request_paths, SpecialRequestDispatch};
pub use spin_backend_dispatch::maybe_handle_spin_backend;
pub use static_backend_dispatch::maybe_handle_static_backend;
pub use streaming_request_fast_path::{
    maybe_handle_streaming_request_fast_path, StreamingRequestFastPathOutcome,
};
pub use streaming_request_pass::handle_streaming_request_pass;
pub use streaming_waf_decision::{maybe_handle_streaming_waf_decision, TarpitStream};
pub use streaming_waf_upstream_dispatch::{
    handle_streaming_waf_upstream_pass, StreamingWafUpstreamError,
};
pub use traffic_control::{
    maybe_enforce_http3_site_connection_limits, maybe_enforce_request_traffic_limits,
    ConnectionTokenGuard, TrafficControlOutcome,
};
pub use upload_validation_dispatch::{maybe_handle_upload_validation, UploadValidationWaf};
pub use upstream_buffered_dispatch::handle_buffered_upstream_request;
pub use upstream_proxy_dispatch::handle_pass_upstream_proxy_phase;
pub use upstream_proxy_dispatch_plan::{
    prepare_upstream_proxy_dispatch_plan, StreamingUpstreamDispatchPlan, UpstreamProxyDispatchPlan,
};
pub use upstream_response_transform::{transform_upstream_response, TransformedUpstreamResponse};
pub use upstream_streaming_dispatch::handle_streaming_upstream_response;
pub use waf_decision::{
    full_request_waf_decision, resolve_full_request_waf_decision, should_skip_full_waf,
    FullWafDecisionOutcome,
};
pub use wasm_filter_dispatch::{
    maybe_handle_wasm_request_filter, WafErrorPageRenderer, WasmFilterBackend,
};
pub use websocket_dispatch::{handle_websocket_to_appserver, handle_websocket_tunnel};
pub use websocket_upgrade_dispatch::maybe_handle_websocket_upgrade;
