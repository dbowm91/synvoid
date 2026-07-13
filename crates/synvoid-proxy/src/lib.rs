//! Reverse proxy crate for SynVoid.
//!
//! Handles header manipulation, retry logic, memory governance,
//! location matching, proxy execution, and streaming cache tee.

pub mod bidirectional;
pub mod cache;
pub mod client_registry;
pub mod dispatch;
pub mod executor;
pub mod governor;
pub mod headers;
pub mod location_matcher;
pub mod protocol;
pub mod retry;
pub mod router;
pub mod router_adapter;
pub mod routing;
pub mod server;
pub mod streaming;

pub use cache::{
    build_cached_response, filter_cacheable_headers, get_cache_max_age_static,
    has_cache_control_directive, is_safe_for_shared_cache, join_upstream_url,
    should_bypass_shared_cache,
};
pub use client_registry::UpstreamClientRegistry;
pub use dispatch::{dispatch_to_upstream, DispatchParams, UpstreamDispatchError};
pub use executor::{
    apply_response_size_limit, build_upstream_request, PreparedUpstreamTarget, ProxyExecutor,
    ResponseSizeError, UpstreamResponsePolicy,
};
pub use governor::GlobalCacheGovernor;
pub use headers::{
    apply_response_header_transforms, build_forward_headers, build_headers_to_filter,
    build_headers_to_filter_for_site, filter_response_headers, filter_response_headers_buf,
    filter_response_headers_buf_with_str_set, is_hop_by_hop_header, is_hop_by_hop_header_name,
    is_private_ip, sanitize_request_path, validate_and_truncate_xff, ForwardedProtocol,
    HEADERS_TO_STRIP, HOP_BY_HOP_HEADERS, MAX_XFF_CHAIN_LENGTH,
};
pub use location_matcher::{LocationMatch, LocationMatchType, LocationMatcher};
pub use retry::{
    calculate_backoff, is_connection_error, is_idempotent_method, is_retryable_status,
    is_timeout_error, should_retry_request,
};
pub use router::{BackendType, RouteResult, RouteTarget, Router};
pub use router_adapter::RouterRouteResolver;
pub use server::{ProxyResponse, ProxyServer, QuicTunnelSender, WafDecision};
pub use streaming::TeeBody;
