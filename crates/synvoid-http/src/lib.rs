//! SynVoid HTTP server utilities.
//!
//! Provides HTTP/1.1 and HTTP/2 server pipeline components, body helpers,
//! header helpers, and response construction primitives.

pub mod body_policy;
pub mod buffered_request_waf_dispatch;
pub mod challenge_paths;
pub mod early_parse;
pub mod headers;
pub mod listener;
pub mod request_parse;
pub mod response_builder;
pub mod response_helpers;
pub mod response_transform;
pub mod runtime;
pub mod request_preparation;
pub mod shared_handler;
pub mod static_backend_dispatch;
pub mod streaming_request_fast_path;
pub mod streaming_waf_decision;
pub mod streaming_waf_upstream_dispatch;
pub mod upstream_streaming_dispatch;
pub mod upstream_proxy_dispatch_plan;
pub mod upstream_proxy_dispatch;
pub mod upstream_response_transform;
pub mod upstream_buffered_dispatch;
pub mod validation_helpers;
pub mod waf_decision;
pub mod websocket_upgrade_dispatch;

pub use body_policy::{collect_and_scan_request_body, BodyPolicyError, RequestBodyWaf};
pub use buffered_request_waf_dispatch::maybe_handle_buffered_request_waf;
pub use challenge_paths::{maybe_handle_challenge_paths, ChallengePathWaf};
pub use request_parse::{
    classify_internal_endpoint, early_waf_decision, extract_request_metadata, extract_trust_token,
    parse_http01_challenge_token, should_handle_key_exchange_path,
    should_skip_waf_from_trust_cookie, EarlyWafHooks, InternalEndpointAction,
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
pub use request_preparation::{
    finalize_request_preparation, prepare_request_preflight, PreparedRequest, RequestPreflight,
    RequestPreflightOutcome, RequestPreparationOutcome,
};
pub use shared_handler::{
    collect_body_with_chunk_waf, stream_body_with_waf, BodyCollectionProtocol,
    SharedRequestHandler, WafStreamedBody,
};
pub use static_backend_dispatch::maybe_handle_static_backend;
pub use streaming_request_fast_path::{
    maybe_handle_streaming_request_fast_path, StreamingRequestFastPathOutcome,
};
pub use streaming_waf_decision::{maybe_handle_streaming_waf_decision, TarpitStream};
pub use streaming_waf_upstream_dispatch::{
    handle_streaming_waf_upstream_pass, StreamingWafUpstreamError,
};
pub use upstream_streaming_dispatch::handle_streaming_upstream_response;
pub use upstream_buffered_dispatch::handle_buffered_upstream_request;
pub use upstream_proxy_dispatch_plan::{
    prepare_upstream_proxy_dispatch_plan, StreamingUpstreamDispatchPlan, UpstreamProxyDispatchPlan,
};
pub use upstream_proxy_dispatch::handle_pass_upstream_proxy_phase;
pub use upstream_response_transform::{transform_upstream_response, TransformedUpstreamResponse};
pub use waf_decision::{
    full_request_waf_decision, resolve_full_request_waf_decision, should_skip_full_waf,
    FullWafDecisionOutcome,
};
pub use websocket_upgrade_dispatch::maybe_handle_websocket_upgrade;
