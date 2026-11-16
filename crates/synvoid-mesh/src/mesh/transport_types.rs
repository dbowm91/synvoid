use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use parking_lot::RwLock;
use quinn::Connection;

use synvoid_rate_limit::{AtomicSlidingWindow, WindowClock};

use crate::protocol::ReplayProtection;

/// How long a closed node keeps its replay state.
///
/// Matches the DHT timestamp window: a record that is still acceptable to the
/// protocol must still be recognised as a replay after the session that
/// delivered it has gone away, so a peer cannot clear the nonce cache by
/// reconnecting first.
pub(crate) const DEFAULT_REPLAY_STATE_RETENTION: Duration = Duration::from_secs(300);

/// Which side opened the QUIC connection a session rides on.
///
/// Both peers must reach the same answer when a dial and an accept race for one
/// node: the connection initiated by the lexicographically smaller node id
/// survives. Each side only knows its own direction, so the rule needs this tag
/// rather than an arrival order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionDirection {
    /// The peer dialled us; we accepted the connection.
    Inbound,
    /// We dialled the peer.
    Outbound,
}

pub struct MeshGlobalRateLimiter {
    per_second: AtomicSlidingWindow,
    per_minute: AtomicSlidingWindow,
    clock: WindowClock,
    limit_per_second: u64,
    limit_per_minute: u64,
}

impl MeshGlobalRateLimiter {
    pub fn new(messages_per_second: usize, messages_per_minute: usize) -> Self {
        Self {
            per_second: AtomicSlidingWindow::new(1, 10),
            per_minute: AtomicSlidingWindow::new(60, 60),
            clock: WindowClock::new(),
            limit_per_second: messages_per_second.max(1) as u64,
            limit_per_minute: messages_per_minute.max(1) as u64,
        }
    }

    pub(crate) fn check(&self) -> GlobalRateLimitCheck {
        let current_per_second = self.per_second.count_now(&self.clock);
        let current_per_minute = self.per_minute.count_now(&self.clock);
        GlobalRateLimitCheck {
            current_per_second,
            current_per_minute,
            exceeded_per_second: current_per_second > self.limit_per_second,
            exceeded_per_minute: current_per_minute > self.limit_per_minute,
        }
    }

    pub fn record(&self) {
        self.per_second.increment_now(&self.clock);
        self.per_minute.increment_now(&self.clock);
    }
}

#[allow(dead_code)]
pub(crate) struct GlobalRateLimitCheck {
    pub current_per_second: u64,
    pub current_per_minute: u64,
    pub exceeded_per_second: bool,
    pub exceeded_per_minute: bool,
}

/// One live QUIC session with a peer node.
///
/// A stream belongs to a single exchange (the receiver handles exactly one
/// message or one HTTP request per bidirectional stream), so a session holds
/// no streams: every send opens a fresh one.
pub struct MeshPeerConnection {
    pub node_id: String,
    pub address: String,
    pub connection: Connection,
    pub session_id: String,
    pub connected_at: Instant,
    pub(crate) last_seen: RwLock<Instant>,
    pub role: crate::config::MeshNodeRole,
    pub upstreams: Vec<String>,
    pub is_trusted: bool,
    /// The Ed25519 key the handshake bound to `node_id`.
    ///
    /// Copied from the `Hello`/`HelloAck` the peer signed its identity with, so
    /// message signatures can be checked against the same key the id derives
    /// from. A session without a key is never registered.
    pub(crate) public_key: Vec<u8>,
    /// Which side opened this connection.
    pub(crate) direction: SessionDirection,
    /// Per-node counter, incremented every time a session becomes current for
    /// its node. Diagnostics for takeover races.
    pub(crate) generation: u64,
}

impl MeshPeerConnection {
    /// Records that the session peer sent something. Called from every receive
    /// path, so it must not allocate or await.
    pub(crate) fn touch_last_seen(&self) {
        *self.last_seen.write() = Instant::now();
    }

    pub(crate) fn last_seen(&self) -> Instant {
        *self.last_seen.read()
    }
}

/// What `MeshPeerRegistry::register` did with the session it was given.
pub(crate) enum RegisterOutcome {
    /// The node had no session; this one is now current.
    Inserted,
    /// The node already had a session and this is the one that lost.
    ///
    /// The caller closes `connection` with the duplicate-session application
    /// code. It must not update topology or emit a disconnect event for it: the
    /// node is still connected through the winning session.
    Replaced(Arc<MeshPeerConnection>),
}

/// Node-keyed session registry with a session-id reverse index.
///
/// Every accessor that takes an id takes a **node** id except
/// [`session_owner`](Self::session_owner) and
/// [`remove_if_current`](Self::remove_if_current), which take a session id. The
/// fields are private so the compiler, not a grep, proves no caller mixes the
/// two.
pub(crate) struct MeshPeerRegistry {
    /// This node's id, used to break dial/accept races deterministically.
    local_node_id: String,
    by_node: DashMap<String, Arc<MeshPeerConnection>>,
    by_session: DashMap<String, String>,
}

impl MeshPeerRegistry {
    pub(crate) fn new(local_node_id: impl Into<String>) -> Self {
        Self {
            local_node_id: local_node_id.into(),
            by_node: DashMap::new(),
            by_session: DashMap::new(),
        }
    }

    /// Makes `incoming` the node's session, or reports it as the loser.
    ///
    /// A node has at most one session. When two sessions exist, the winner is
    /// chosen so both peers agree on the same physical connection:
    ///
    /// * different directions: the connection initiated by the lexicographically
    ///   smaller node id wins;
    /// * same direction (or a node id equal to ours, which is a
    ///   misconfiguration): the newer `connected_at` wins.
    pub(crate) fn register(&self, incoming: Arc<MeshPeerConnection>) -> RegisterOutcome {
        let node_id = incoming.node_id.clone();
        let session_id = incoming.session_id.clone();

        match self.by_node.entry(node_id.clone()) {
            Entry::Vacant(slot) => {
                slot.insert(restamped(&incoming, 1));
                self.by_session.insert(session_id, node_id);
                RegisterOutcome::Inserted
            }
            Entry::Occupied(mut slot) => {
                let existing = Arc::clone(slot.get());
                let generation = existing.generation.saturating_add(1);
                if !self.incoming_wins(&existing, &incoming) {
                    // The incumbent stays current; `by_session` never learns
                    // about the rejected session.
                    return RegisterOutcome::Replaced(incoming);
                }
                let previous = slot.insert(restamped(&incoming, generation));
                self.by_session.insert(session_id, node_id);
                self.by_session.remove(&previous.session_id);
                RegisterOutcome::Replaced(previous)
            }
        }
    }

    fn incoming_wins(&self, existing: &MeshPeerConnection, incoming: &MeshPeerConnection) -> bool {
        if existing.direction != incoming.direction && self.local_node_id != incoming.node_id {
            // Both peers run this rule locally; only the direction each of
            // them sees differs, so they converge on one connection.
            let local_is_smaller = self.local_node_id.as_str() < incoming.node_id.as_str();
            if local_is_smaller {
                incoming.direction == SessionDirection::Outbound
            } else {
                incoming.direction == SessionDirection::Inbound
            }
        } else {
            // Same direction (or self-peering): newest connection wins.
            incoming.connected_at >= existing.connected_at
        }
    }

    pub(crate) fn get(&self, node_id: &str) -> Option<Arc<MeshPeerConnection>> {
        self.by_node.get(node_id).map(|e| Arc::clone(e.value()))
    }

    /// The key the handshake bound to `node_id`, if it has a live session.
    ///
    /// `None` means "no key known for this node", never "skip verification":
    /// callers must treat it as a verification failure unless another
    /// authoritative source supplies the key.
    pub(crate) fn public_key(&self, node_id: &str) -> Option<Vec<u8>> {
        self.by_node
            .get(node_id)
            .map(|e| e.value().public_key.clone())
            .filter(|key| !key.is_empty())
    }

    /// Node that owns `session_id`, if that session is still indexed.
    pub(crate) fn session_owner(&self, session_id: &str) -> Option<String> {
        self.by_session.get(session_id).map(|e| e.value().clone())
    }

    /// Removes the node's session only when it is still `session_id`.
    ///
    /// This is the only removal path that session teardown may use: a slow
    /// cleanup from a replaced session must not evict the session that
    /// replaced it.
    pub(crate) fn remove_if_current(&self, session_id: &str) -> Option<Arc<MeshPeerConnection>> {
        // Copy the owner out and drop the reverse-index guard before touching
        // `by_node`: `register` takes the two maps in the other order.
        let node_id = self.by_session.get(session_id).map(|o| o.value().clone())?;

        let removed = self
            .by_node
            .remove_if(&node_id, |_, session| session.session_id == session_id)
            .map(|(_, session)| session);

        if removed.is_some() && self.session_owner(session_id).as_deref() == Some(node_id.as_str())
        {
            self.by_session.remove(session_id);
        }

        removed
    }

    /// Borrowing iterator. `DashMap` guards stay alive for the duration of an
    /// item, so never await inside a loop over this; use
    /// [`snapshot`](Self::snapshot) instead.
    pub(crate) fn iter(&self) -> impl Iterator<Item = Arc<MeshPeerConnection>> + '_ {
        self.by_node.iter().map(|e| Arc::clone(e.value()))
    }

    /// Owned copy, safe to hold across awaits.
    pub(crate) fn snapshot(&self) -> Vec<Arc<MeshPeerConnection>> {
        self.iter().collect()
    }

    pub(crate) fn node_ids(&self) -> Vec<String> {
        self.by_node.iter().map(|e| e.key().clone()).collect()
    }

    pub(crate) fn len(&self) -> usize {
        self.by_node.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.by_node.is_empty()
    }

    pub(crate) fn clear(&self) {
        self.by_node.clear();
        self.by_session.clear();
    }
}

/// Copies a session with the generation this registration assigned.
///
/// The registry stores `Arc<MeshPeerConnection>`, so the counter cannot be
/// mutated in place; re-stamping keeps `generation` a plain `u64` and keeps the
/// value unique to the registry.
fn restamped(session: &MeshPeerConnection, generation: u64) -> Arc<MeshPeerConnection> {
    Arc::new(MeshPeerConnection {
        node_id: session.node_id.clone(),
        address: session.address.clone(),
        connection: session.connection.clone(),
        session_id: session.session_id.clone(),
        connected_at: session.connected_at,
        last_seen: RwLock::new(session.last_seen()),
        role: session.role,
        upstreams: session.upstreams.clone(),
        is_trusted: session.is_trusted,
        public_key: session.public_key.clone(),
        direction: session.direction,
        generation,
    })
}

/// Replay state per node, independent of the session lifetime.
///
/// A peer that reconnects keeps the nonces it already used: the state is
/// retained for a per-node window after the session closes so a pushed record
/// cannot be replayed by dropping and re-establishing the connection.
pub(crate) struct ReplayStateRegistry {
    states: DashMap<String, Arc<tokio::sync::RwLock<ReplayProtection>>>,
    /// Node -> (when its last session closed, how long to keep its state).
    retained: DashMap<String, (Instant, Duration)>,
}

impl ReplayStateRegistry {
    pub(crate) fn new() -> Self {
        Self {
            states: DashMap::new(),
            retained: DashMap::new(),
        }
    }

    /// State for `node_id`, created on first use.
    ///
    /// This is intentionally not an `Option`: a connected peer always has
    /// replay state, and a caller that cannot prove the peer is connected must
    /// reject instead of skipping the check.
    pub(crate) fn state_for(&self, node_id: &str) -> Arc<tokio::sync::RwLock<ReplayProtection>> {
        if let Some(existing) = self.states.get(node_id) {
            return Arc::clone(existing.value());
        }
        let created = Arc::new(tokio::sync::RwLock::new(ReplayProtection::new()));
        let stored = Arc::clone(
            self.states
                .entry(node_id.to_string())
                .or_insert_with(|| Arc::clone(&created))
                .value(),
        );
        self.retained.remove(node_id);
        stored
    }

    /// State already known for `node_id`, without creating one.
    pub(crate) fn get(&self, node_id: &str) -> Option<Arc<tokio::sync::RwLock<ReplayProtection>>> {
        self.states.get(node_id).map(|e| Arc::clone(e.value()))
    }

    /// Marks the state as closeable `retention` after now.
    ///
    /// Called when a node's last session goes away. Until the window expires
    /// the state stays usable, so an inbound record from a reconnecting peer is
    /// still checked against the nonces it used before.
    pub(crate) fn retain_after_close(&self, node_id: &str, retention: Duration) {
        if self.states.contains_key(node_id) {
            self.retained
                .insert(node_id.to_string(), (Instant::now(), retention));
        }
    }

    /// Drops states whose retention window has expired. Returns how many.
    pub(crate) fn sweep(&self) -> usize {
        let now = Instant::now();
        let expired: Vec<String> = self
            .retained
            .iter()
            .filter(|e| {
                let (closed_at, retention) = *e.value();
                now.saturating_duration_since(closed_at) >= retention
            })
            .map(|e| e.key().clone())
            .collect();

        let mut removed = 0;
        for node_id in expired {
            self.retained.remove(&node_id);
            if self.states.remove(&node_id).is_some() {
                removed += 1;
            }
        }
        removed
    }

    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.states.len()
    }
}

impl Default for ReplayStateRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use quinn::{ClientConfig, Endpoint, ServerConfig};
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    /// A live loopback QUIC connection plus the endpoints that keep it open.
    ///
    /// The registry only stores the handle, so the tests never open a stream;
    /// the endpoints are returned because dropping them tears the connection
    /// down.
    struct Loopback {
        connection: Connection,
        _server: Endpoint,
        _client: Endpoint,
    }

    async fn loopback() -> Loopback {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("self-signed certificate");
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let cert = CertificateDer::from(certified.cert.der().to_vec());
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));

        let server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("server protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .expect("server certificate");
        let server_crypto: quinn::crypto::rustls::QuicServerConfig =
            quinn::crypto::rustls::QuicServerConfig::try_from(server_tls)
                .expect("server crypto config");
        let server = Endpoint::server(
            ServerConfig::with_crypto(Arc::new(server_crypto)),
            (Ipv4Addr::LOCALHOST, 0).into(),
        )
        .expect("server endpoint");
        let server_addr = server.local_addr().expect("server address");

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).expect("trust the test certificate");
        let client_tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("client protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        let client_crypto: quinn::crypto::rustls::QuicClientConfig =
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls)
                .expect("client crypto config");
        let mut client =
            Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint");
        client.set_default_client_config(ClientConfig::new(Arc::new(client_crypto)));

        let dialing = client
            .connect(server_addr, "localhost")
            .expect("dial loopback");
        // `Incoming` only drives the handshake once awaited, so both halves run
        // as futures in the same join.
        let accepting = async {
            let incoming = server.accept().await.expect("server accepted the dial");
            incoming.await.expect("server handshake")
        };
        let (_server_connection, connection) = tokio::join!(accepting, dialing);
        let connection = connection.expect("client handshake");

        Loopback {
            connection,
            _server: server,
            _client: client,
        }
    }

    fn session(
        connection: &Connection,
        node_id: &str,
        session_id: &str,
        direction: SessionDirection,
        connected_at: Instant,
    ) -> Arc<MeshPeerConnection> {
        session_with_key(
            connection,
            node_id,
            session_id,
            direction,
            connected_at,
            Vec::new(),
        )
    }

    fn session_with_key(
        connection: &Connection,
        node_id: &str,
        session_id: &str,
        direction: SessionDirection,
        connected_at: Instant,
        public_key: Vec<u8>,
    ) -> Arc<MeshPeerConnection> {
        Arc::new(MeshPeerConnection {
            node_id: node_id.to_string(),
            address: "127.0.0.1:0".to_string(),
            connection: connection.clone(),
            session_id: session_id.to_string(),
            connected_at,
            last_seen: RwLock::new(connected_at),
            role: crate::config::MeshNodeRole::EDGE,
            upstreams: Vec::new(),
            is_trusted: false,
            public_key,
            direction,
            generation: 0,
        })
    }

    #[tokio::test]
    async fn register_indexes_by_node_and_session() {
        let loopback = loopback().await;
        let now = Instant::now();
        let registry = MeshPeerRegistry::new("node-local");

        assert!(matches!(
            registry.register(session(
                &loopback.connection,
                "node-a",
                "session-1",
                SessionDirection::Inbound,
                now
            )),
            RegisterOutcome::Inserted
        ));

        let stored = registry.get("node-a").expect("node key is the node id");
        assert_eq!(stored.session_id, "session-1");
        assert_eq!(stored.generation, 1);
        assert!(registry.get("session-1").is_none(), "session is not a node");
        assert_eq!(
            registry.session_owner("session-1").as_deref(),
            Some("node-a")
        );
        assert_eq!(registry.len(), 1);
    }

    #[tokio::test]
    async fn registered_session_publishes_the_bound_key() {
        let loopback = loopback().await;
        let now = Instant::now();
        let registry = MeshPeerRegistry::new("node-local");
        let key =
            crate::protocol::MeshMessageSigner::from_secret([0x31; 32]).get_public_key_bytes();

        registry.register(session_with_key(
            &loopback.connection,
            "node-a",
            "session-1",
            SessionDirection::Inbound,
            now,
            key.clone(),
        ));

        assert_eq!(
            registry.public_key("node-a"),
            Some(key),
            "the session must publish the key the handshake bound"
        );
        assert!(
            registry.public_key("node-unknown").is_none(),
            "an unknown node has no key"
        );

        // A session registered without a key stays unverifiable; it must not
        // surface an empty key as if it were usable.
        registry.register(session(
            &loopback.connection,
            "node-b",
            "session-2",
            SessionDirection::Inbound,
            now,
        ));
        assert!(registry.public_key("node-b").is_none());
    }

    #[tokio::test]
    async fn remove_if_current_rejects_stale_session() {
        let loopback = loopback().await;
        let now = Instant::now();
        let registry = MeshPeerRegistry::new("node-local");

        registry.register(session(
            &loopback.connection,
            "node-a",
            "session-old",
            SessionDirection::Inbound,
            now,
        ));
        let outcome = registry.register(session(
            &loopback.connection,
            "node-a",
            "session-new",
            SessionDirection::Inbound,
            now + Duration::from_secs(1),
        ));
        match outcome {
            RegisterOutcome::Replaced(loser) => assert_eq!(loser.session_id, "session-old"),
            RegisterOutcome::Inserted => panic!("same node must replace, not insert"),
        }

        assert!(
            registry.remove_if_current("session-old").is_none(),
            "a replaced session must not remove anything"
        );
        assert_eq!(
            registry.get("node-a").map(|s| s.session_id.clone()),
            Some("session-new".to_string())
        );

        let removed = registry
            .remove_if_current("session-new")
            .expect("current session is removable");
        assert_eq!(removed.session_id, "session-new");
        assert!(registry.get("node-a").is_none());
        assert!(registry.session_owner("session-new").is_none());
        assert!(registry.is_empty());
    }

    #[tokio::test]
    async fn stale_cleanup_cannot_evict_replacement() {
        let loopback = loopback().await;
        let now = Instant::now();
        let registry = MeshPeerRegistry::new("node-local");

        registry.register(session(
            &loopback.connection,
            "node-a",
            "session-old",
            SessionDirection::Inbound,
            now,
        ));
        registry.register(session(
            &loopback.connection,
            "node-a",
            "session-new",
            SessionDirection::Inbound,
            now + Duration::from_secs(1),
        ));

        for _ in 0..3 {
            assert!(registry.remove_if_current("session-old").is_none());
        }
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.node_ids(), vec!["node-a".to_string()]);
        assert_eq!(
            registry.get("node-a").map(|s| s.generation),
            Some(2),
            "the replacement is still current after the stale cleanup"
        );
    }

    #[tokio::test]
    async fn cross_direction_takeover_prefers_smaller_node_id() {
        let loopback = loopback().await;
        let now = Instant::now();

        // The same two physical connections, seen from each end:
        //   "a-out" == "b-in" (dialled by node-a, the smaller id)
        //   "b-out" == "a-in" (dialled by node-b)
        // node-a must keep its outbound, node-b must keep its inbound, in any
        // arrival order.
        for reverse in [false, true] {
            let a = MeshPeerRegistry::new("node-a");
            let b = MeshPeerRegistry::new("node-b");

            let a_out = || {
                session(
                    &loopback.connection,
                    "node-b",
                    "a-out",
                    SessionDirection::Outbound,
                    now,
                )
            };
            let a_in = || {
                session(
                    &loopback.connection,
                    "node-b",
                    "a-in",
                    SessionDirection::Inbound,
                    now + Duration::from_secs(1),
                )
            };
            let b_in = || {
                session(
                    &loopback.connection,
                    "node-a",
                    "b-in",
                    SessionDirection::Inbound,
                    now,
                )
            };
            let b_out = || {
                session(
                    &loopback.connection,
                    "node-a",
                    "b-out",
                    SessionDirection::Outbound,
                    now + Duration::from_secs(1),
                )
            };

            if reverse {
                a.register(a_in());
                a.register(a_out());
                b.register(b_out());
                b.register(b_in());
            } else {
                a.register(a_out());
                a.register(a_in());
                b.register(b_in());
                b.register(b_out());
            }

            assert_eq!(
                a.get("node-b").map(|s| s.session_id.clone()),
                Some("a-out".to_string()),
                "node-a keeps the connection it initiated (smaller id)"
            );
            assert_eq!(
                b.get("node-a").map(|s| s.session_id.clone()),
                Some("b-in".to_string()),
                "node-b keeps the inbound connection from the smaller id"
            );
        }
    }

    #[tokio::test]
    async fn same_direction_keeps_newer_connected_at() {
        let loopback = loopback().await;
        let now = Instant::now();
        let registry = MeshPeerRegistry::new("node-local");

        registry.register(session(
            &loopback.connection,
            "node-a",
            "session-late",
            SessionDirection::Outbound,
            now + Duration::from_secs(5),
        ));
        let outcome = registry.register(session(
            &loopback.connection,
            "node-a",
            "session-early",
            SessionDirection::Outbound,
            now,
        ));
        match outcome {
            RegisterOutcome::Replaced(loser) => assert_eq!(loser.session_id, "session-early"),
            RegisterOutcome::Inserted => panic!("same node must replace, not insert"),
        }
        assert_eq!(
            registry.get("node-a").map(|s| s.session_id.clone()),
            Some("session-late".to_string())
        );

        // Equal timestamps: the newly registered session is the tie-break.
        registry.register(session(
            &loopback.connection,
            "node-a",
            "session-tie",
            SessionDirection::Outbound,
            now + Duration::from_secs(5),
        ));
        assert_eq!(
            registry.get("node-a").map(|s| s.session_id.clone()),
            Some("session-tie".to_string())
        );
    }

    #[tokio::test]
    async fn node_ids_and_len_track_sessions() {
        let loopback = loopback().await;
        let now = Instant::now();
        let registry = MeshPeerRegistry::new("node-local");

        registry.register(session(
            &loopback.connection,
            "node-a",
            "session-a",
            SessionDirection::Inbound,
            now,
        ));
        registry.register(session(
            &loopback.connection,
            "node-b",
            "session-b",
            SessionDirection::Outbound,
            now,
        ));

        let mut ids = registry.node_ids();
        ids.sort();
        assert_eq!(ids, vec!["node-a".to_string(), "node-b".to_string()]);
        assert_eq!(registry.len(), 2);
        assert!(!registry.is_empty());

        registry.clear();
        assert!(registry.is_empty());
        assert!(registry.node_ids().is_empty());
    }

    #[tokio::test]
    async fn replay_state_survives_a_reconnect() {
        let registry = ReplayStateRegistry::new();
        let now = synvoid_utils::safe_unix_timestamp();

        let state = registry.state_for("node-a");
        let first = state.write().await.check_and_add_at("nonce-1", now, now);
        assert!(matches!(first, crate::protocol::ReplayResult::Valid));

        // Session closes; state is retained, so the same nonce still fails.
        registry.retain_after_close("node-a", DEFAULT_REPLAY_STATE_RETENTION);
        assert_eq!(registry.sweep(), 0, "retained state is not swept early");

        let reconnected = registry.state_for("node-a");
        let replay = reconnected
            .write()
            .await
            .check_and_add_at("nonce-1", now, now);
        assert!(matches!(
            replay,
            crate::protocol::ReplayResult::ReplayDetected
        ));
    }

    #[tokio::test]
    async fn replay_state_is_swept_after_retention() {
        let registry = ReplayStateRegistry::new();
        registry.state_for("node-a");
        registry.retain_after_close("node-a", Duration::ZERO);

        assert_eq!(registry.sweep(), 1);
        assert!(registry.get("node-a").is_none());
        assert_eq!(registry.len(), 0);
    }
}
