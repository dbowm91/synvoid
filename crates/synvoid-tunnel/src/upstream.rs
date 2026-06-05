#![allow(unused_variables, dead_code)]

//! Tunnel upstream resolution and half-TCP proxy support.
//!
//! # Architecture
//!
//! This module provides tunnel-aware upstream resolution for the proxy layer.
//! The primary routing path is via [`TunnelRouter::resolve_tunnel_backend()`]
//! which returns [`TunnelBackend::Direct`] variants with dynamic host resolution.
//!
//! # TunnelBackend Status
//!
//! The `TunnelBackend` struct has been removed from this file. Active tunnel
//! routing uses [`TunnelRouter::resolve_tunnel_backend()`] which returns
//! [`TunnelBackend::Direct`] and [`TunnelBackend::Tunnel`] variants.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::TunnelManager;

pub struct TunnelUpstreamResolver {
    manager: Arc<TunnelManager>,
    static_mappings: HashMap<String, String>,
}

impl TunnelUpstreamResolver {
    pub fn new(manager: Arc<TunnelManager>, static_mappings: HashMap<String, String>) -> Self {
        Self {
            manager,
            static_mappings,
        }
    }

    pub async fn resolve(&self, upstream: &str) -> Option<TunnelUpstreamTarget> {
        if !upstream.starts_with("tunnel:") && !upstream.starts_with("tunnel://") {
            return None;
        }

        let identifier = upstream
            .trim_start_matches("tunnel:")
            .trim_start_matches("tunnel://");

        if let Some(port) = self.static_mappings.get(identifier) {
            return Some(TunnelUpstreamTarget {
                tunnel_identifier: identifier.to_string(),
                static_port: Some(port.parse().ok()?),
                session_id: None,
            });
        }

        let sessions = self.manager.list_sessions().await;

        for session in sessions {
            if let Some(port) = session.get_local_port(identifier) {
                return Some(TunnelUpstreamTarget {
                    tunnel_identifier: identifier.to_string(),
                    static_port: None,
                    session_id: Some(session.id.clone()),
                });
            }
        }

        None
    }

    pub fn register_static_mapping(&mut self, identifier: String, port: u16) {
        self.static_mappings.insert(identifier, port.to_string());
    }
}

#[derive(Debug, Clone)]
pub struct TunnelUpstreamTarget {
    pub tunnel_identifier: String,
    pub static_port: Option<u16>,
    pub session_id: Option<String>,
}

pub struct TunnelUpstreamPool {
    resolver: Arc<RwLock<TunnelUpstreamResolver>>,
}

impl TunnelUpstreamPool {
    pub fn new(manager: Arc<TunnelManager>, mappings: HashMap<String, u16>) -> Self {
        let string_mappings: HashMap<String, String> = mappings
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect();
        Self {
            resolver: Arc::new(RwLock::new(TunnelUpstreamResolver::new(
                manager,
                string_mappings,
            ))),
        }
    }

    pub async fn get_upstream(&self, identifier: &str) -> Option<String> {
        let resolver = self.resolver.read().await;
        resolver.resolve(identifier).await.map(|target| {
            if let Some(port) = target.static_port {
                format!("tcp:127.0.0.1:{}", port)
            } else if let Some(session_id) = target.session_id {
                format!("tunnel:{}", session_id)
            } else {
                String::new()
            }
        })
    }

    pub async fn add_static_mapping(&self, identifier: String, port: u16) {
        let mut resolver = self.resolver.write().await;
        resolver.register_static_mapping(identifier, port);
    }
}
