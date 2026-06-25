//! # SynVoid — Multi-Process Web Application Firewall
//!
//! SynVoid is a high-performance WAF with a multi-process architecture:
//! - **Supervisor**: Single control plane process
//! - **Worker**: Handles HTTP requests via Unix domain sockets
//!
//! ## Key Modules
//!
//! - [`waf`] — Core WAF engine (rate limiting, bot detection, attack detection)
//! - [`proxy`] — Reverse proxy and request forwarding
//! - [`config`] — Configuration loading and validation
//! - [`process`] — IPC communication and process management
//! - [`supervisor`] — Process supervision and worker orchestration
//! - [`mesh`] — Mesh networking and DHT-based peer discovery
//! - [`tls`] — TLS termination, ACME certificate management
//! - [`dns`] — DNS server with DNSSEC support (feature-gated)
//!
//! ## Feature Flags
//!
//! - `dns` — DNS server with DNSSEC signing and recursive resolution
//! - `mesh` — Mesh networking for multi-node deployments
//! - `socket-handoff` — Socket transfer between processes
//! - `post-quantum` — Post-quantum TLS key exchange
//! - `wireguard` — WireGuard VPN tunnel support

#![allow(
    elided_lifetimes_in_paths,
    mismatched_lifetime_syntaxes,
    clippy::too_many_arguments,
    clippy::field_reassign_with_default,
    clippy::unwrap_or_default,
    clippy::collapsible_if,
    clippy::unnecessary_map_or,
    clippy::redundant_locals,
    clippy::never_loop,
    clippy::question_mark,
    clippy::missing_safety_doc,
    clippy::unnecessary_cast
)]

// Root-owned application/runtime composition modules. These coordinate
// processes, workers, supervisor state, sockets, startup, or app-level
// integration. See architecture/root_module_ledger.md.
pub mod commands;
pub mod common;
pub mod drain;
pub mod log_controller;
pub mod sandbox;
pub mod server;
pub mod startup;
pub mod supervisor;
pub mod tcp;
pub mod udp;
pub mod worker;

// Mixed application/domain modules. These still expose root-side implementation
// or adapters and need targeted extraction plans before becoming pure facades.
pub mod admin;
pub mod auth;
pub mod captcha;
pub mod challenge;
pub mod filter;
pub mod http;
pub mod http_client;
pub mod listener;
pub mod logging;
pub mod platform;
pub mod plugin;
pub mod tarpit;
pub mod utils;

// Compatibility facades over dedicated crates. New domain code should import
// the dedicated crate directly; these root paths remain for transitional API
// compatibility while root coupling is reduced.
// See architecture/root_module_ledger.md.
pub mod app_server;
pub mod block_store;
pub mod buffer {
    pub use synvoid_utils::buffer::pool;
    pub use synvoid_utils::buffer::pool::{BufferPool, PooledBuf};
}
pub mod cgi;
pub mod config;
pub mod fastcgi;
pub use synvoid_geoip as geoip;
pub mod honeypot_port;
pub mod http3;
pub use synvoid_integrity as integrity;
pub mod location_matcher;
#[cfg(feature = "mesh")]
pub mod mesh;
pub mod metrics;
pub mod mime;
pub mod php;
pub mod process;
pub mod protocol;
pub mod proxy;
pub use synvoid_proxy_cache as proxy_cache;
pub mod router;
pub mod router_adapter;
pub mod serder;
pub use synvoid_utils::serialization;
pub mod serverless;
pub mod spin;
pub mod static_files;
pub mod streaming;
pub mod theme;
pub mod tls;
pub mod tunnel;
pub mod upload;
pub use synvoid_upstream as upstream;
pub mod vpn_client;
pub mod waf;

#[cfg(feature = "icmp-filter")]
pub mod icmp_filter;

#[cfg(feature = "dns")]
pub mod dns;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

pub use config::ConfigManager;
pub use utils::{errors, urlencoding_decode, DrainFlag, OptionExt, ResultExt, RunningFlag};
pub use waf::{WafCore, WafCoreConfig};
