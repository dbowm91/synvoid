#![allow(
    elided_lifetimes_in_paths,
    mismatched_lifetime_syntaxes,
    clippy::too_many_arguments,       // Phase 6: refactor with builder/config structs
    clippy::await_holding_lock,       // Phase 4.5: async mutex standardization
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
pub mod error;
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
pub mod platform;
pub mod plugin;
pub mod process;
pub mod protocol;
pub mod proxy;
pub mod proxy_cache;
pub mod router;
pub mod serder;
pub mod serialization;
pub mod serialization_rkyv;
pub mod server;
pub mod static_files;
pub mod streaming;
pub mod supervisor;
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
