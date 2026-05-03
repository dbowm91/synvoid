#[cfg(feature = "mesh")]
pub use crate::mesh::config::{
    default_global_seeds, ConnectionScoreWeights, MeshConfig, MeshConnectionConfig,
    MeshLocalUpstream, MeshNodeRole, MeshPeerConfig, MeshRoutingConfig, MeshSeedNode,
    MeshServicePolicy, MeshTlsConfig, MeshUpstreamConfig, MeshUpstreamPeer, ReconnectionPriority,
};
