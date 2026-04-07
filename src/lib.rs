//! # MaluWAF — Multi-Process Web Application Firewall
//!
//! MaluWAF is a high-performance WAF with a multi-process architecture:
//! - **Overseer**: Manages master process lifecycle, upgrades, health monitoring
//! - **Master**: Parent process that spawns/manages workers, handles IPC
//! - **Worker**: Handles HTTP requests via Unix domain sockets
//!
//! ## Key Modules
//!
//! - [`waf`] — Core WAF engine (rate limiting, bot detection, attack detection)
//! - [`proxy`] — Reverse proxy and request forwarding
//! - [`config`] — Configuration loading and validation
//! - [`process`] — IPC communication and process management
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

pub mod admin;
pub mod app_server;
pub mod auth;
pub mod block_store;
pub mod buffer;
pub mod captcha;
pub mod cgi;
pub mod challenge;
pub mod common;
pub mod config;
pub mod drain;
pub mod fastcgi;
pub mod filter;
pub mod geoip;
pub mod honeypot_port;
pub mod http;
pub mod http3;
pub mod http_client;
pub mod integrity;
pub mod listener;
pub mod location_matcher;
pub mod log_controller;
pub mod logging;
pub mod master;
pub mod mesh;
pub mod metrics;
pub mod mime;
pub mod overseer;
pub mod php;
pub mod platform;
pub mod plugin;
pub mod process;
pub mod protocol;
pub mod proxy;
pub mod proxy_cache;
pub mod router;
pub mod serder;
pub mod serialization;
pub mod server;
pub mod serverless;
pub mod startup;
pub mod static_files;
pub mod streaming;
pub mod tarpit;
pub mod tcp;
pub mod theme;
pub mod tls;
pub mod tunnel;
pub mod udp;
pub mod upload;
pub mod upstream;
pub mod utils;
pub mod vpn_client;
pub mod waf;
pub mod worker;
pub mod zero_copy;

#[cfg(feature = "icmp-filter")]
pub mod icmp_filter;

#[cfg(feature = "dns")]
pub mod dns;

pub use config::ConfigManager;
pub use utils::{errors, urlencoding_decode, DrainFlag, OptionExt, ResultExt, RunningFlag};
pub use waf::{WafCore, WafCoreConfig};
