//! Root compatibility shim for the extracted `synvoid-proxy` crate.
//!
//! Keep the root API surface stable while the implementation lives in the
//! dedicated proxy crate.

use synvoid_proxy as proxy_crate;

pub type ProxyServer = proxy_crate::ProxyServer<crate::waf::adapter::RootWafProcessor>;

pub use proxy_crate::bidirectional;
pub use proxy_crate::cache;
pub use proxy_crate::client_registry;
pub use proxy_crate::dispatch;
pub use proxy_crate::executor;
pub use proxy_crate::governor;
pub use proxy_crate::headers;
pub use proxy_crate::location_matcher;
pub use proxy_crate::protocol;
pub use proxy_crate::retry;
pub use proxy_crate::router;
pub use proxy_crate::router_adapter;
pub use proxy_crate::routing;
pub use proxy_crate::streaming;

pub use proxy_crate::apply_response_header_transforms;
pub use proxy_crate::apply_response_size_limit;
pub use proxy_crate::build_cached_response;
pub use proxy_crate::build_forward_headers;
pub use proxy_crate::build_headers_to_filter;
pub use proxy_crate::build_headers_to_filter_for_site;
pub use proxy_crate::build_upstream_request;
pub use proxy_crate::calculate_backoff;
pub use proxy_crate::dispatch_to_upstream;
pub use proxy_crate::filter_cacheable_headers;
pub use proxy_crate::filter_response_headers;
pub use proxy_crate::filter_response_headers_buf;
pub use proxy_crate::filter_response_headers_buf_with_str_set;
pub use proxy_crate::get_cache_max_age_static;
pub use proxy_crate::is_connection_error;
pub use proxy_crate::is_hop_by_hop_header;
pub use proxy_crate::is_hop_by_hop_header_name;
pub use proxy_crate::is_idempotent_method;
pub use proxy_crate::is_private_ip;
pub use proxy_crate::is_retryable_status;
pub use proxy_crate::is_timeout_error;
pub use proxy_crate::join_upstream_url;
pub use proxy_crate::sanitize_request_path;
pub use proxy_crate::should_retry_request;
pub use proxy_crate::validate_and_truncate_xff;
pub use proxy_crate::BackendType;
pub use proxy_crate::DispatchParams;
pub use proxy_crate::ForwardedProtocol;
pub use proxy_crate::GlobalCacheGovernor;
pub use proxy_crate::LocationMatch;
pub use proxy_crate::LocationMatchType;
pub use proxy_crate::LocationMatcher;
pub use proxy_crate::PreparedUpstreamTarget;
pub use proxy_crate::ProxyExecutor;
pub use proxy_crate::ProxyResponse;
pub use proxy_crate::QuicTunnelSender;
pub use proxy_crate::ResponseSizeError;
pub use proxy_crate::RouteResult;
pub use proxy_crate::RouteTarget;
pub use proxy_crate::Router;
pub use proxy_crate::RouterRouteResolver;
pub use proxy_crate::TeeBody;
pub use proxy_crate::UpstreamClientRegistry;
pub use proxy_crate::UpstreamDispatchError;
pub use proxy_crate::UpstreamResponsePolicy;
pub use proxy_crate::WafDecision;
pub use proxy_crate::HEADERS_TO_STRIP;
pub use proxy_crate::HOP_BY_HOP_HEADERS;
pub use proxy_crate::MAX_XFF_CHAIN_LENGTH;
