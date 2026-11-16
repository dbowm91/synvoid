//! Two-node transport contract: real QUIC transports over loopback, strict
//! mutual TLS, and a live handshake between an ORIGIN and an EDGE.
//!
//! The fixture (`tests/support/fixture.rs`) stops at configuration. This binary
//! takes the next step: it assembles the transport stack per node, binds the
//! origin's UDP endpoint, rewrites the edge's seed with the port the origin
//! actually bound, and requires the handshake to be recorded in both
//! topologies.

mod support;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use support::fixture::{two_node_pair, FixtureNode, TwoNodePair};
use synvoid_mesh::backend::{initialize_mesh_transports, MeshBackendPool};
use synvoid_mesh::config::{MeshConfig, MeshNodeRole};
use synvoid_mesh::lifecycle::{MeshStartupPolicy, MeshStartupReport};
use synvoid_mesh::protocol::MeshMessage;
use synvoid_mesh::proxy::MeshProxy;
use synvoid_mesh::topology::{MeshTopology, PeerState};
use synvoid_mesh::transport::MeshTransport;
use synvoid_mesh::transports::manager::MeshTransportManager;
use synvoid_mesh::transports::quic::QuicMeshTransport;

/// Upper bound for the peer to appear in the other node's topology.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// A node whose transport stack is assembled and whose `start()` succeeded.
struct StartedNode {
    node_id: String,
    /// Port reported by the bound endpoint, read right after `start()`.
    port: u16,
    topology: Arc<MeshTopology>,
    quic: Arc<QuicMeshTransport>,
    /// Startup outcome; carries the seed-bootstrap result on the dialer.
    report: MeshStartupReport,
    stopped: AtomicBool,
}

impl StartedNode {
    fn transport(&self) -> Arc<MeshTransport> {
        self.quic.get_inner()
    }

    /// Stops the transport once. Idempotent, so the panic fallback in `Drop`
    /// cannot double-stop a node that already shut down cleanly.
    async fn stop(&self) {
        if !self.stopped.swap(true, Ordering::SeqCst) {
            self.transport().stop().await;
        }
    }
}

impl Drop for StartedNode {
    fn drop(&mut self) {
        if self.stopped.load(Ordering::SeqCst) {
            return;
        }
        // A failed assertion skips the explicit `stop()` calls. Spawn the
        // shutdown so the endpoint is released deterministically instead of
        // relying on runtime teardown.
        let transport = self.transport();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move { transport.stop().await });
        }
    }
}

/// Installs the process-wide rustls provider exactly once.
///
/// Production calls `install_process_crypto_provider()` from `main.rs` before
/// any TLS builder runs. A test binary has no `main`, and the workspace graph
/// enables more than one provider backend (aws-lc-rs and ring), so rustls
/// cannot pick a default from crate features alone and panics inside the QUIC
/// handshake. Idempotent: `install_default` fails harmlessly when already set.
fn ensure_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Assembles the transport stack for one node and starts it.
///
/// Mirrors the production composition order: config → topology → manager →
/// proxy → backend pool → `initialize_mesh_transports` → `start()`.
async fn start_node(config: MeshConfig) -> StartedNode {
    ensure_crypto_provider();
    let cfg = Arc::new(config);
    let topology = Arc::new(MeshTopology::new(cfg.clone()));
    let manager = Arc::new(MeshTransportManager::new(
        cfg.clone(),
        topology.clone(),
        None,
    ));
    let proxy = Arc::new(MeshProxy::new(cfg.clone(), topology.clone(), None));
    let pool = Arc::new(MeshBackendPool::new(proxy, topology.clone()));

    initialize_mesh_transports(&cfg, manager.clone(), pool, None, None, true)
        .await
        .expect("mesh transports initialize");

    let quic = manager
        .get_quic_transport()
        .expect("initialization must register the QUIC transport");

    // `start()` binds the endpoint (the runtime binds in its accept loop), so
    // the actual port is only known afterwards. `start_with_policy` is the same
    // default-policy startup as `start()`, but keeps the report: a test binary
    // has no tracing subscriber, so the report is the only failure diagnostic.
    let report = quic
        .get_inner()
        .start_with_policy(MeshStartupPolicy::default())
        .await
        .expect("mesh transport must start");

    let port = quic
        .get_inner()
        .get_actual_quic_port()
        .await
        .expect("a started transport must report its bound port");

    StartedNode {
        node_id: cfg.node_id(),
        port,
        topology,
        quic,
        report,
        stopped: AtomicBool::new(false),
    }
}

/// Rewrites the edge's placeholder seed with the endpoint the origin bound.
///
/// Called before the edge config is wrapped in `Arc` (the transport clones it
/// at initialization), and after the origin has bound its real port.
///
/// `public_key` stays `None`: the seed dial does not pin a key. The origin is
/// authenticated by its CA-signed leaf (strict mTLS), by binding its claimed
/// node id to the key in its `HelloAck`, and by the role the edge's
/// `peered_wafs` entry grants it (`role = "origin"` in the fixture).
fn point_edge_at_origin(config: &mut MeshConfig, port: u16, origin_id: &str) {
    assert!(
        !config.seeds.is_empty(),
        "edge fixture must carry a seed to rewrite"
    );
    let seed = &mut config.seeds[0];
    seed.address = format!("127.0.0.1:{port}");
    seed.public_key = None;
    seed.node_id = Some(origin_id.to_string());
}

/// Polls `from`'s topology until it records `peer_id`, or panics with the
/// peers it did see.
async fn wait_for_peer(from: &StartedNode, peer_id: &str) -> PeerState {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    loop {
        if let Some(peer) = from.topology.get_peer(peer_id).await {
            return peer;
        }
        assert!(
            Instant::now() < deadline,
            "{} did not record peer {} within {:?}; known peers: {:?}",
            from.node_id,
            peer_id,
            HANDSHAKE_TIMEOUT,
            from.topology.get_peer_ids().await
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Preconditions the assembly relies on: strict TLS needs real files on disk.
fn assert_transport_inputs(node: &FixtureNode) {
    assert!(node.config.enabled);
    assert!(
        node.identity_path.starts_with(node.dir.path()),
        "identity {} escapes its node dir",
        node.identity_path.display()
    );
    for path in [&node.cert_path, &node.key_path, &node.ca_path] {
        assert!(path.is_file(), "missing transport input {}", path.display());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn origin_binds_and_reports_its_port() {
    let TwoNodePair { origin, .. } = two_node_pair();
    assert_transport_inputs(&origin);

    let started = start_node(origin.config).await;
    assert!(
        started.node_id.starts_with("node-"),
        "origin must expose its realized node id, got {}",
        started.node_id
    );
    assert_ne!(
        started.port, 0,
        "origin bound port 0 as its actual port instead of an ephemeral port"
    );

    // The listener still owns the port after startup: reading it again yields
    // the same non-zero value.
    let reported = started
        .quic
        .get_inner()
        .get_actual_quic_port()
        .await
        .expect("bound endpoint keeps reporting its port");
    assert_eq!(reported, started.port);

    started.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handshake_establishes_and_records_peer() {
    let TwoNodePair { origin, edge } = two_node_pair();
    assert_transport_inputs(&origin);
    assert_transport_inputs(&edge);

    // Capture the origin's identity before its config is consumed: the edge's
    // placeholder seed needs the origin's bound port and realized id.
    let origin_id = origin.node_id.clone();
    let origin = start_node(origin.config).await;

    let mut edge_config = edge.config.clone();
    point_edge_at_origin(&mut edge_config, origin.port, &origin_id);
    let edge = start_node(edge_config).await;

    // The seed dial is part of startup, not of the later polling: a zero count
    // means the edge never reached the origin, whatever the topology says.
    assert_eq!(
        edge.report.connected_seed_count, 1,
        "edge seed bootstrap failed; degraded: {:?}",
        edge.report.degraded_reasons
    );

    let edge_view = wait_for_peer(&edge, &origin.node_id).await;
    let origin_view = wait_for_peer(&origin, &edge.node_id).await;

    assert_eq!(
        edge_view.role,
        MeshNodeRole::ORIGIN,
        "edge recorded {} with the wrong role",
        origin.node_id
    );
    assert_eq!(
        origin_view.role,
        MeshNodeRole::EDGE,
        "origin recorded {} with the wrong role",
        edge.node_id
    );

    edge.stop().await;
    origin.stop().await;
}

/// Starts an origin and an edge dialling it, and returns both once the edge's
/// seed bootstrap reported a connection.
///
/// The origin's identity is captured before its config is consumed: the edge's
/// placeholder seed needs the origin's bound port and realized id.
async fn start_pair() -> (StartedNode, StartedNode, String) {
    let TwoNodePair { origin, edge } = two_node_pair();
    assert_transport_inputs(&origin);
    assert_transport_inputs(&edge);

    let origin_id = origin.node_id.clone();
    let origin = start_node(origin.config).await;

    let mut edge_config = edge.config.clone();
    point_edge_at_origin(&mut edge_config, origin.port, &origin_id);
    let edge = start_node(edge_config).await;

    assert_eq!(
        edge.report.connected_seed_count, 1,
        "edge seed bootstrap failed; degraded: {:?}",
        edge.report.degraded_reasons
    );

    (origin, edge, origin_id)
}

/// Polls the node-keyed registry (not topology) until it lists `peer_id`.
async fn wait_for_registered_peer(from: &StartedNode, peer_id: &str) {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    loop {
        if from
            .transport()
            .connected_peer_ids()
            .iter()
            .any(|id| id == peer_id)
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{} did not register a session for {} within {:?}; registered: {:?}",
            from.node_id,
            peer_id,
            HANDSHAKE_TIMEOUT,
            from.transport().connected_peer_ids()
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_lookup_by_node_id() {
    let (origin, edge, origin_id) = start_pair().await;

    wait_for_registered_peer(&edge, &origin_id).await;

    let mut first = edge.transport().connected_peer_ids();
    first.sort();
    assert!(
        first.contains(&origin_id),
        "registry keyed by node id must list {}, got {:?}",
        origin_id,
        first
    );
    assert_eq!(
        edge.transport().peer_count(),
        first.len(),
        "peer_count must agree with the node ids"
    );

    let mut second = edge.transport().connected_peer_ids();
    second.sort();
    assert_eq!(
        first, second,
        "repeated lookups must return the same node ids"
    );

    edge.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_stream_messages_succeed() {
    let (origin, edge, origin_id) = start_pair().await;
    let transport = edge.transport();
    wait_for_registered_peer(&edge, &origin_id).await;

    // The receiver handles exactly one exchange per stream and drops it, so the
    // second send can only succeed if every exchange opens a fresh stream.
    for attempt in 1..=2 {
        transport
            .send_message_to_peer(&origin_id, &MeshMessage::KeepAlive)
            .await
            .unwrap_or_else(|error| panic!("stream message {attempt} failed: {error:?}"));
    }

    edge.stop().await;
    origin.stop().await;
}
