//! Control-plane delivery and startup truth (Phase 05).
//!
//! Site configuration is state-bearing: the sender must get an ack from every
//! origin, a stale version must never overwrite a newer one, and an oversized
//! config must fail with a typed cause instead of a silent datagram loss.
//! Startup must report `connected_peers` from the registry, never from the
//! configured seed list.
//!
//! The two-node assembly mirrors `mesh_two_node_contract.rs`: the fixture stops
//! at configuration, this binary binds the endpoint and runs the handshake.

mod support;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use support::fixture::{two_node_pair, FixtureNode, TwoNodePair, SERVICE_ID};
use synvoid_mesh::backend::{initialize_mesh_transports, MeshBackendPool};
use synvoid_mesh::config::{MeshConfig, MeshNodeRole};
use synvoid_mesh::lifecycle::{MeshStartupPolicy, MeshStartupReport};
use synvoid_mesh::protocol::{MeshMessage, MeshMessageSigner};
use synvoid_mesh::proxy::MeshProxy;
use synvoid_mesh::topology::MeshTopology;
use synvoid_mesh::transport::{MeshTransport, MeshTransportError, MAX_MESSAGE_SIZE};
use synvoid_mesh::transports::manager::MeshTransportManager;
use synvoid_mesh::transports::quic::QuicMeshTransport;

/// Upper bound for the peer to appear in the registry.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// A node whose transport stack is assembled and whose `start` succeeded.
struct StartedNode {
    node_id: String,
    port: u16,
    quic: Arc<QuicMeshTransport>,
    report: MeshStartupReport,
    stopped: AtomicBool,
}

impl StartedNode {
    fn transport(&self) -> Arc<MeshTransport> {
        self.quic.get_inner()
    }

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
        let transport = self.transport();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move { transport.stop().await });
        }
    }
}

/// Installs the process-wide rustls provider exactly once; the test binary has
/// no `main` to do it. Idempotent.
fn ensure_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Transport stack assembled for one node, before `start` runs.
struct AssembledNode {
    node_id: String,
    quic: Arc<QuicMeshTransport>,
}

async fn assemble_node(
    config: MeshConfig,
    signer: Option<Arc<MeshMessageSigner>>,
) -> AssembledNode {
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

    initialize_mesh_transports(&cfg, manager.clone(), pool, None, signer, true)
        .await
        .expect("mesh transports initialize");

    let quic = manager
        .get_quic_transport()
        .expect("initialization must register the QUIC transport");

    AssembledNode {
        node_id: cfg.node_id(),
        quic,
    }
}

/// Starts an assembled node and keeps its report.
async fn start_node_with_policy(
    config: MeshConfig,
    signer: Option<Arc<MeshMessageSigner>>,
    policy: MeshStartupPolicy,
) -> Result<StartedNode, MeshTransportError> {
    let AssembledNode { node_id, quic } = assemble_node(config, signer).await;

    let report = quic.get_inner().start_with_policy(policy).await?;

    let port = quic
        .get_inner()
        .get_actual_quic_port()
        .await
        .expect("a started transport must report its bound port");

    Ok(StartedNode {
        node_id,
        port,
        quic,
        report,
        stopped: AtomicBool::new(false),
    })
}

async fn start_node(config: MeshConfig, signer: Option<Arc<MeshMessageSigner>>) -> StartedNode {
    start_node_with_policy(config, signer, MeshStartupPolicy::default())
        .await
        .expect("mesh transport must start under the lenient policy")
}

/// Rewrites the edge's placeholder seed with the origin's bound port.
fn point_edge_at_origin(config: &mut MeshConfig, port: u16, origin_id: &str) {
    assert!(!config.seeds.is_empty(), "edge fixture must carry a seed");
    let seed = &mut config.seeds[0];
    seed.address = format!("127.0.0.1:{port}");
    seed.public_key = None;
    seed.node_id = Some(origin_id.to_string());
}

/// Polls the node-keyed registry until it lists `peer_id`.
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

fn assert_transport_inputs(node: &FixtureNode) {
    assert!(
        node.identity_path.starts_with(node.dir.path()),
        "identity {} escapes its node dir",
        node.identity_path.display()
    );
    for path in [&node.cert_path, &node.key_path, &node.ca_path] {
        assert!(path.is_file(), "missing transport input {}", path.display());
    }
}

/// Origin + edge with a live handshake and a signer installed on the edge.
///
/// The signer is what `broadcast_site_config_to_origins` uses; installing it
/// here keeps the synthetic `SiteConfigSync` shaped exactly like production.
async fn start_pair_with_signer() -> (StartedNode, StartedNode, Arc<MeshMessageSigner>) {
    let TwoNodePair { origin, edge } = two_node_pair();
    assert_transport_inputs(&origin);
    assert_transport_inputs(&edge);

    let origin_id = origin.node_id.clone();
    let origin = start_node(origin.config, None).await;

    let mut edge_config = edge.config.clone();
    point_edge_at_origin(&mut edge_config, origin.port, &origin_id);
    let signer = Arc::new(MeshMessageSigner::new([7u8; 32]));
    let edge = start_node(edge_config, Some(signer.clone())).await;

    wait_for_registered_peer(&edge, &origin_id).await;
    wait_for_registered_peer(&origin, &edge.node_id).await;

    (origin, edge, signer)
}

/// Builds a `SiteConfigSync` with the production signing shape.
///
/// `source_node_id` is the site's owner as recorded in the receiving node's
/// topology: in this two-node fixture the origin owns `SERVICE_ID` on itself,
/// and the origin gate authorizes by site ownership. Binding the signer to the
/// physical peer is Phase 04's concern.
fn signed_site_config(
    signer: &MeshMessageSigner,
    site_id: &str,
    version: u64,
    config_json: &str,
    source_node_id: &str,
) -> MeshMessage {
    let timestamp = MeshMessage::generate_timestamp();
    let sign_data = format!(
        "{}:{}:{}:{}",
        site_id,
        version,
        config_json.len(),
        timestamp
    );
    MeshMessage::SiteConfigSync {
        request_id: MeshMessage::generate_nonce(),
        site_id: site_id.into(),
        config_version: version,
        config_json: config_json.into(),
        timestamp,
        source_node_id: source_node_id.into(),
        signature: signer.sign(sign_data.as_bytes()),
        signer_public_key: Some(signer.get_public_key()),
        proxy_cache_preferences: None,
    }
}

/// Sends a sync over a stream and decodes the ack written on that stream.
async fn send_sync_and_read_ack(
    edge: &StartedNode,
    origin_id: &str,
    message: &MeshMessage,
) -> MeshMessage {
    let request_id = message.message_id().map(|id| id.to_string());
    let response = edge
        .transport()
        .send_message_to_peer_with_response(origin_id, message)
        .await
        .expect("origin must answer on the same stream");
    let ack = MeshMessage::decode(&response).expect("ack must decode");
    match &ack {
        MeshMessage::SiteConfigAck {
            request_id: acked, ..
        } => assert_eq!(request_id.as_deref(), Some(acked.as_str())),
        other => panic!("expected SiteConfigAck, got {other:?}"),
    }
    ack
}

/// Registers the origin-side apply callback and returns a handle to the
/// applied payloads. Without it the origin rejects as `no_callback`.
fn register_site_config_sink(
    origin: &StartedNode,
) -> Arc<tokio::sync::Mutex<Vec<(String, String)>>> {
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    origin.transport().set_site_config_sync_callback(tx);
    let applied = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let sink = applied.clone();
    tokio::spawn(async move {
        while let Some((site_id, config_json, _prefs)) = rx.recv().await {
            sink.lock().await.push((site_id, config_json));
        }
    });
    applied
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn site_config_ack_round_trip() {
    let (origin, edge, signer) = start_pair_with_signer().await;
    let applied = register_site_config_sink(&origin);

    let site_id = SERVICE_ID;
    let body = "[site]\ndomains = [\"blog.example\"]\n";
    let message = signed_site_config(&signer, site_id, 7, body, &origin.node_id);

    let ack = send_sync_and_read_ack(&edge, &origin.node_id, &message).await;

    match ack {
        MeshMessage::SiteConfigAck {
            site_id: acked_site,
            accepted,
            applied_version,
            reason,
            ..
        } => {
            assert!(accepted, "origin rejected the config: {reason}");
            assert!(reason.is_empty(), "accepted ack carries reason {reason}");
            assert_eq!(&*acked_site, site_id);
            assert_eq!(
                applied_version,
                Some(7),
                "ack must carry the version the origin applied"
            );
        }
        other => panic!("expected SiteConfigAck, got {other:?}"),
    }

    // The ack means "applied", not "received": the callback must have seen the
    // exact body exactly once.
    let applied = applied.lock().await;
    assert_eq!(applied.len(), 1, "config must be applied exactly once");
    assert_eq!(applied[0].0, site_id);
    assert_eq!(applied[0].1, body);

    assert_eq!(
        origin.transport().applied_site_config_version(site_id),
        Some(7)
    );

    edge.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_site_config_is_rejected() {
    let (origin, edge, signer) = start_pair_with_signer().await;
    let applied = register_site_config_sink(&origin);

    let site_id = SERVICE_ID;
    let newer = signed_site_config(
        &signer,
        site_id,
        2,
        "[site]\nversion = 2\n",
        &origin.node_id,
    );
    let ack = send_sync_and_read_ack(&edge, &origin.node_id, &newer).await;
    assert!(
        matches!(
            ack,
            MeshMessage::SiteConfigAck {
                accepted: true,
                applied_version: Some(2),
                ..
            }
        ),
        "newer version must be accepted, got {ack:?}"
    );

    let older = signed_site_config(
        &signer,
        site_id,
        1,
        "[site]\nversion = 1\n",
        &origin.node_id,
    );
    let ack = send_sync_and_read_ack(&edge, &origin.node_id, &older).await;

    match ack {
        MeshMessage::SiteConfigAck {
            accepted,
            applied_version,
            reason,
            ..
        } => {
            assert!(!accepted, "older version must be rejected");
            assert!(
                reason.contains("stale"),
                "rejection reason must name staleness, got {reason}"
            );
            assert_eq!(
                applied_version,
                Some(2),
                "a stale ack reports the version still live"
            );
        }
        other => panic!("expected SiteConfigAck, got {other:?}"),
    }

    // The rejected config never reached the apply callback.
    assert_eq!(applied.lock().await.len(), 1);
    assert_eq!(
        origin.transport().applied_site_config_version(site_id),
        Some(2)
    );

    edge.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_site_config_is_rejected() {
    let TwoNodePair { origin, .. } = two_node_pair();
    let origin = start_node(origin.config, None).await;

    let oversized = "x".repeat(MAX_MESSAGE_SIZE + 1);
    let error = origin
        .transport()
        .broadcast_site_config_to_origins(SERVICE_ID, &oversized, 1, None)
        .await
        .expect_err("an oversized config must not be sent");

    match error {
        MeshTransportError::SiteConfigTooLarge { size, max } => {
            assert_eq!(size, MAX_MESSAGE_SIZE + 1);
            assert_eq!(max, MAX_MESSAGE_SIZE);
        }
        other => panic!("expected SiteConfigTooLarge, got {other:?}"),
    }

    origin.stop().await;
}

/// Rewrites the edge's only seed with an endpoint that can never accept.
///
/// Port 0 is rejected by the QUIC client immediately, so seed bootstrap fails
/// fast instead of waiting for an idle timeout.
fn point_edge_at_unreachable_seed(config: &mut MeshConfig) {
    assert!(!config.seeds.is_empty(), "edge fixture must carry a seed");
    config.seeds[0].address = "127.0.0.1:0".to_string();
    config.seeds[0].public_key = None;
    config.seeds[0].node_id = None;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zero_peer_startup_is_reported() {
    // 1. The production policy must fail instead of reporting success.
    let TwoNodePair { edge, .. } = two_node_pair();
    let mut edge_config = edge.config.clone();
    point_edge_at_unreachable_seed(&mut edge_config);

    let assembled = assemble_node(edge_config, None).await;
    let transport = assembled.quic.get_inner();

    let started = Instant::now();
    let error = match transport
        .start_with_policy(MeshStartupPolicy::require_peers(2))
        .await
    {
        Ok(_) => panic!("zero-peer startup must fail under require_peers(2)"),
        Err(error) => error,
    };
    let elapsed = started.elapsed();

    assert!(
        matches!(error, MeshTransportError::NoPeerConnected),
        "expected NoPeerConnected, got {error:?}"
    );
    assert!(
        elapsed < Duration::from_secs(12),
        "startup must fail within the bound, took {elapsed:?}"
    );
    assert_eq!(
        transport.peer_count(),
        0,
        "a failed zero-peer startup must leave no registered peers"
    );

    // 2. The lenient default keeps starting but reports the truth: zero
    //    connected peers comes from the registry, and the reason is visible.
    let TwoNodePair { edge, .. } = two_node_pair();
    let mut edge_config = edge.config.clone();
    point_edge_at_unreachable_seed(&mut edge_config);

    let node = start_node(edge_config, None).await;
    assert_eq!(
        node.report.connected_peer_count, 0,
        "connected_peer_count must come from the registry"
    );
    assert_eq!(node.transport().peer_count(), 0);
    assert!(
        node.report
            .degraded_reasons
            .iter()
            .any(|reason| reason.contains("no connected peer")),
        "zero-peer startup must be reported as degraded, got {:?}",
        node.report.degraded_reasons
    );

    node.stop().await;
}

/// Guards the role mapping used by status output: the origin fixture really is
/// an ORIGIN and the edge really is an EDGE.
#[test]
fn fixture_roles_are_distinct() {
    let TwoNodePair { origin, edge } = two_node_pair();
    assert_eq!(origin.config.role, MeshNodeRole::ORIGIN);
    assert_eq!(edge.config.role, MeshNodeRole::EDGE);
}
