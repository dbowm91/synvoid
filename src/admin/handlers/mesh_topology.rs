use super::super::state::AdminState;
use super::common::OptionalAuth;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::mesh::topology::PeerState;

#[derive(Debug, Serialize)]
pub struct TopologyResponse {
    pub version: u64,
    pub total_peers: usize,
    pub global_nodes: Vec<TopologyPeerInfo>,
    pub edge_nodes: Vec<TopologyPeerInfo>,
    pub connections: Vec<ConnectionInfo>,
    pub metrics: TopologyMetrics,
}

#[derive(Debug, Serialize)]
pub struct TopologyPeerInfo {
    pub node_id: String,
    pub role: String,
    pub address: String,
    pub geo: Option<String>,
    pub latency_ms: Option<u32>,
    pub status: String,
    pub is_global: bool,
    pub is_trusted: bool,
    pub quic_port: Option<u32>,
    pub wireguard_port: Option<u32>,
}

impl From<&PeerState> for TopologyPeerInfo {
    fn from(peer: &PeerState) -> Self {
        TopologyPeerInfo {
            node_id: peer.node_id.clone(),
            role: format!("{:?}", peer.role),
            address: peer.address.clone(),
            geo: peer.geo.clone(),
            latency_ms: peer.latency_ms,
            status: format!("{:?}", peer.status),
            is_global: peer.is_global,
            is_trusted: peer.is_trusted,
            quic_port: peer.quic_port,
            wireguard_port: peer.wireguard_port,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ConnectionInfo {
    pub from_node: String,
    pub to_node: String,
    pub latency_ms: u32,
    pub bandwidth_mbps: f64,
    pub connection_status: String,
}

#[derive(Debug, Serialize)]
pub struct TopologyMetrics {
    pub total_requests: u64,
    pub mesh_messages_per_sec: f64,
    pub average_peer_latency_ms: f32,
    pub trust_chain_coverage: f32,
}

#[derive(Debug, Serialize)]
pub struct GraphData {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Debug, Serialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub node_type: String,
    pub x: Option<f64>,
    pub y: Option<f64>,
    pub color: String,
    pub size: f64,
}

#[derive(Debug, Serialize)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    pub weight: f64,
    pub label: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TopologyQuery {
    pub include_connections: Option<bool>,
}

pub async fn get_mesh_topology(
    _auth: OptionalAuth,
    State(state): State<Arc<AdminState>>,
    Query(query): Query<TopologyQuery>,
) -> Result<Json<TopologyResponse>, StatusCode> {
    let topology_opt = state.mesh.mesh_transport.as_ref().map(|t| t.get_topology());

    let topology = match topology_opt {
        Some(t) => t,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let version = topology.get_topology_version().await;
    let all_peers = topology.get_all_peers().await;

    let mut global_nodes: Vec<&PeerState> = Vec::new();
    let mut edge_nodes: Vec<&PeerState> = Vec::new();

    for peer in &all_peers {
        if peer.is_global {
            global_nodes.push(peer);
        } else {
            edge_nodes.push(peer);
        }
    }

    let global_infos: Vec<TopologyPeerInfo> = global_nodes
        .iter()
        .map(|p| TopologyPeerInfo::from(*p))
        .collect();
    let edge_infos: Vec<TopologyPeerInfo> = edge_nodes
        .iter()
        .map(|p| TopologyPeerInfo::from(*p))
        .collect();

    let connections = if query.include_connections.unwrap_or(true) {
        build_connection_graph(&global_nodes, &edge_nodes)
    } else {
        vec![]
    };

    let metrics = TopologyMetrics {
        total_requests: 0,
        mesh_messages_per_sec: 0.0,
        average_peer_latency_ms: calculate_avg_latency(&all_peers),
        trust_chain_coverage: calculate_trust_coverage(&all_peers),
    };

    Ok(Json(TopologyResponse {
        version,
        total_peers: global_nodes.len() + edge_nodes.len(),
        global_nodes: global_infos,
        edge_nodes: edge_infos,
        connections,
        metrics,
    }))
}

pub async fn get_topology_graph(
    _auth: OptionalAuth,
    State(state): State<Arc<AdminState>>,
) -> Result<Json<GraphData>, StatusCode> {
    let topology_opt = state.mesh.mesh_transport.as_ref().map(|t| t.get_topology());

    let topology = match topology_opt {
        Some(t) => t,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let all_peers = topology.get_all_peers().await;

    let mut global_nodes: Vec<&PeerState> = Vec::new();
    let mut edge_nodes: Vec<&PeerState> = Vec::new();

    for peer in &all_peers {
        if peer.is_global {
            global_nodes.push(peer);
        } else {
            edge_nodes.push(peer);
        }
    }

    let nodes: Vec<GraphNode> = global_nodes
        .iter()
        .chain(edge_nodes.iter())
        .map(|p| {
            let (x, y) = if p.is_global {
                (Some(geo_to_x(&p.geo)), Some(geo_to_y(&p.geo)))
            } else {
                (
                    Some(geo_to_x(&p.geo) + 50.0),
                    Some(geo_to_y(&p.geo) + 100.0),
                )
            };

            GraphNode {
                id: p.node_id.clone(),
                label: p.node_id.chars().take(8).collect(),
                node_type: if p.is_global { "global" } else { "edge" }.to_string(),
                x,
                y,
                color: if p.is_global { "#4CAF50" } else { "#2196F3" }.to_string(),
                size: if p.is_global { 20.0 } else { 12.0 },
            }
        })
        .collect();

    let edges: Vec<GraphEdge> = global_nodes
        .iter()
        .flat_map(|g| {
            edge_nodes
                .iter()
                .filter(|e| e.geo == g.geo)
                .map(|e| GraphEdge {
                    source: g.node_id.clone(),
                    target: e.node_id.clone(),
                    weight: 1.0 / (e.latency_ms.unwrap_or(100) as f64).max(1.0),
                    label: e.latency_ms.map(|l| format!("{}ms", l)),
                })
                .collect::<Vec<_>>()
        })
        .collect();

    Ok(Json(GraphData { nodes, edges }))
}

fn build_connection_graph(
    global_nodes: &[&PeerState],
    edge_nodes: &[&PeerState],
) -> Vec<ConnectionInfo> {
    let mut connections = Vec::new();

    for global in global_nodes {
        for other_global in global_nodes {
            if global.node_id != other_global.node_id {
                connections.push(ConnectionInfo {
                    from_node: global.node_id.clone(),
                    to_node: other_global.node_id.clone(),
                    latency_ms: global.latency_ms.unwrap_or(50),
                    bandwidth_mbps: 1000.0,
                    connection_status: "connected".to_string(),
                });
            }
        }
    }

    for edge in edge_nodes {
        if edge.is_trusted {
            if let Some(parent) = global_nodes
                .iter()
                .find(|g| g.is_global && g.geo == edge.geo)
            {
                connections.push(ConnectionInfo {
                    from_node: parent.node_id.clone(),
                    to_node: edge.node_id.clone(),
                    latency_ms: edge.latency_ms.unwrap_or(100),
                    bandwidth_mbps: 100.0,
                    connection_status: "connected".to_string(),
                });
            }
        }
    }

    connections
}

fn geo_to_x(geo: &Option<String>) -> f64 {
    let geo_str = geo.as_deref().unwrap_or("default");
    let hash = Sha256::digest(geo_str.as_bytes());
    let val = u64::from_le_bytes(hash[..8].try_into().unwrap());
    (val as f64 % 1000.0) - 500.0
}

fn geo_to_y(geo: &Option<String>) -> f64 {
    let geo_str = geo.as_deref().unwrap_or("default");
    let hash = Sha256::digest((geo_str.to_string() + "y").as_bytes());
    let val = u64::from_le_bytes(hash[..8].try_into().unwrap());
    (val as f64 % 1000.0) - 500.0
}

fn calculate_avg_latency(all_peers: &[PeerState]) -> f32 {
    if all_peers.is_empty() {
        return 0.0;
    }

    let latencies: Vec<_> = all_peers.iter().filter_map(|n| n.latency_ms).collect();

    if latencies.is_empty() {
        return 0.0;
    }

    latencies.iter().sum::<u32>() as f32 / latencies.len() as f32
}

fn calculate_trust_coverage(all_peers: &[PeerState]) -> f32 {
    if all_peers.is_empty() {
        return 0.0;
    }

    let trusted = all_peers.iter().filter(|p| p.is_trusted).count();
    trusted as f32 / all_peers.len() as f32
}
