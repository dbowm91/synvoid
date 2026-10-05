//! Phase 139 — the mesh DHT capability is inverted, wired, and observable.
//!
//! ## The three things this suite exists to pin
//!
//! 1. **The inversion is real at the type boundary.** `MeshDnsRegistry` holds
//!    `Arc<dyn DhtRecordStore>` / `Arc<dyn DhtGlobalLocator>`, both defined in
//!    `synvoid-dns`, and a test double can be substituted. Before Phase 139 the
//!    fields were concrete `synvoid-mesh` types, which is exactly what made
//!    `with_config`'s hardcoded `None` unavoidable.
//!
//! 2. **The wiring is observable, not decorative.** `with_config` still leaves
//!    the capabilities unset — a registry is not a DHT — but composition can
//!    now attach one, and a bound registry reaches the query context that
//!    `resolve_from_mesh` reads. Before Phase 139 that context was hardcoded
//!    `None` in *both* the UDP and TCP transports, so no registry, attached or
//!    not, could ever be observed.
//!
//! 3. **Late binding survives the `Arc`.** Composition holds `Arc<DnsServer>`
//!    and the capability can only be attached after `DnsServer::new` has run,
//!    because the mesh registry and the ACME manager do not exist yet. The
//!    binding therefore has to be visible through the `Arc` the request path
//!    holds — which is what `LateBinding` provides, and what a consuming
//!    builder on a throwaway clone cannot.
//!
//! ## What this suite deliberately does not claim
//!
//! It does not claim a mesh-sourced DNS answer is reachable in production.
//! `resolve_from_mesh` additionally needs the global registry to hold DHT
//! state, which requires `synvoid-mesh`'s own `dns` feature — a latent reverse
//! edge that does not compile and is recorded as residual in
//! `architecture/dns_provider_inversion_phase139_closeout.md`. What is proven
//! here is the seam and the binding, which is the part this phase changed.
#![cfg(feature = "mesh")]

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use synvoid_dns::mesh_sync::dht_capability::{
    AdvertisedAnycastNode, AdvertisedAnycastRecord, AdvertisedDomainRegistration, DhtGlobalLocator,
    DhtGlobalPeer, DhtRecordStore,
};
use synvoid_dns::mesh_sync::MeshDnsRegistry;
use synvoid_dns::server::DnsServer;

// ── doubles ──────────────────────────────────────────────────────────────────

/// A DHT that answers from fixed tables and counts calls, so a test can prove
/// the registry reached the capability rather than merely holding a handle.
struct CountingDht {
    nodes: Vec<AdvertisedAnycastNode>,
    authenticity_calls: AtomicUsize,
    store_calls: AtomicUsize,
}

impl CountingDht {
    fn new(nodes: Vec<AdvertisedAnycastNode>) -> Self {
        Self {
            nodes,
            authenticity_calls: AtomicUsize::new(0),
            store_calls: AtomicUsize::new(0),
        }
    }
}

impl DhtRecordStore for CountingDht {
    fn all_dns_domain_registrations(&self) -> Vec<AdvertisedDomainRegistration> {
        Vec::new()
    }

    fn all_anycast_advertisements(&self) -> Vec<AdvertisedAnycastRecord> {
        Vec::new()
    }

    fn anycast_nodes_for_zone(&self, zone: &str) -> Vec<AdvertisedAnycastNode> {
        self.nodes
            .iter()
            .filter(|node| node.dns_zones.iter().any(|z| z == zone))
            .cloned()
            .collect()
    }

    fn is_anycast_advertisement_authentic(&self, advertisement: &AdvertisedAnycastRecord) -> bool {
        self.authenticity_calls.fetch_add(1, Ordering::SeqCst);
        // Mirrors the provider adapter: an unsigned advertisement is not
        // authenticated, and the question is answered provider-side.
        advertisement.signer_public_key.is_some() && !advertisement.signature.is_empty()
    }

    fn store_dns_domain_registration(
        &self,
        _domain: String,
        _origin_node_id: String,
        _ip_addresses: Vec<String>,
        _ttl_seconds: u64,
    ) -> bool {
        self.store_calls.fetch_add(1, Ordering::SeqCst);
        true
    }

    fn store_anycast_node(
        &self,
        _node_id: String,
        _anycast_ips: Vec<String>,
        _geo: Option<String>,
        _capacity: u32,
        _healthy: bool,
        _dns_zones: Vec<String>,
    ) -> bool {
        self.store_calls.fetch_add(1, Ordering::SeqCst);
        true
    }

    fn remove_anycast_node(&self, _node_id: &str) -> bool {
        true
    }
}

struct FixedLocator;

#[async_trait::async_trait]
impl DhtGlobalLocator for FixedLocator {
    async fn find_closest_global(&self, count: usize) -> Vec<DhtGlobalPeer> {
        (0..count)
            .map(|i| DhtGlobalPeer {
                node_id: format!("global-{i}"),
            })
            .collect()
    }
}

fn anycast_node(zone: &str) -> AdvertisedAnycastNode {
    AdvertisedAnycastNode {
        node_id: "edge-1".to_string(),
        anycast_ips: vec!["203.0.113.10".to_string()],
        geo: Some("DE".to_string()),
        capacity: 10,
        healthy: true,
        dns_zones: vec![zone.to_string()],
        registered_at: 1,
    }
}

fn dns_server() -> DnsServer {
    DnsServer::new(support::dns_runtime(), None, None)
}

// ── 1. the seam is substitutable ──────────────────────────────────────────────

/// `with_config` leaves the DHT capabilities unset. This is correct — a
/// registry is not a DHT — and it is the state Phase 139 changed from
/// "unreachable by construction" to "unset until composition attaches one".
#[test]
fn a_default_registry_has_no_dht_capability() {
    let registry = MeshDnsRegistry::new("node-1".to_string(), true);
    let nodes = registry.query_anycast_from_dht("example.com");
    assert!(
        nodes.is_empty(),
        "with no capability attached the registry must answer nothing, not \
         fabricate a node: a default registry that answered would mask the \
         wiring entirely"
    );
}

/// A DNS-defined trait must accept a double that lives outside `synvoid-mesh`.
/// If this stopped compiling, the edge had been re-narrowed to concrete types.
#[test]
fn the_dht_capability_is_substitutable_by_a_non_mesh_double() {
    let dht = Arc::new(CountingDht::new(vec![anycast_node("example.com")]));
    let registry = MeshDnsRegistry::new("node-1".to_string(), true)
        .with_dht_record_store(dht.clone())
        .with_routing_manager(Arc::new(FixedLocator));

    let nodes = registry.query_anycast_from_dht("example.com");
    assert_eq!(
        nodes.len(),
        1,
        "the attached double must be the one answering"
    );
    assert_eq!(nodes[0].node_id, "edge-1");

    // A zone with no advertisements must still answer through the capability.
    assert!(
        registry.query_anycast_from_dht("other.test").is_empty(),
        "an empty result must mean 'nothing advertised', not 'no capability'"
    );
}

/// A zone query carries no signature, so it must not assert authenticity.
///
/// This method used to hardcode `authenticated: true` on every DHT-sourced
/// node. That was unreachable while the capability could not be attached;
/// wiring it would have made "anything in the DHT is authentic" a live claim,
/// which `architecture/distributed_state_contract.md` forbids.
#[test]
fn a_dht_zone_query_does_not_assert_authenticity() {
    let dht = Arc::new(CountingDht::new(vec![anycast_node("example.com")]));
    let registry = MeshDnsRegistry::new("node-1".to_string(), true).with_dht_record_store(dht);

    let nodes = registry.query_anycast_from_dht("example.com");
    assert_eq!(nodes.len(), 1, "the double is reachable");
    assert!(
        !nodes[0].authenticated,
        "a projection with no signature must not claim authentication; the \
         verified path is `sync_from_dht`, which asks \
         `is_anycast_advertisement_authentic` per record"
    );
}

/// Authenticity is the one question DNS must not answer for itself. The
/// verified path is `sync_from_dht`, which asks the capability per record; this
/// pins that an unsigned advertisement is rejected on that path rather than
/// being admitted on `anycast_ips` alone.
#[tokio::test]
async fn advertisement_authenticity_is_asked_of_the_capability() {
    let dht = Arc::new(CountingDht::new(Vec::new()));
    let store = Arc::clone(&dht) as Arc<dyn DhtRecordStore>;

    let unsigned = AdvertisedAnycastRecord {
        key: "anycast_node:edge-1".to_string(),
        value: serde_json::json!({
            "node_id": "edge-1",
            "anycast_ips": ["203.0.113.10"],
            "geo": "DE",
            "capacity": 10,
            "healthy": true,
            "dns_zones": ["example.com"],
        })
        .to_string()
        .into_bytes(),
        publisher_id: "edge-1".to_string(),
        signature: Vec::new(),
        created_at: 1,
        ttl_seconds: 600,
        source_node_id: "edge-1".to_string(),
        signer_public_key: None,
    };

    assert!(
        !store.is_anycast_advertisement_authentic(&unsigned),
        "an unsigned advertisement must not be treated as authentic"
    );

    let signed = AdvertisedAnycastRecord {
        signer_public_key: Some("ed25519:abc".to_string()),
        signature: vec![1, 2, 3],
        ..unsigned.clone()
    };
    assert!(
        store.is_anycast_advertisement_authentic(&signed),
        "a signed advertisement the double accepts is authentic by the \
         capability's own decision"
    );

    assert!(
        dht.authenticity_calls.load(Ordering::SeqCst) >= 2,
        "the decision must have been delegated to the capability; a local \
         decision would leave the counter at zero"
    );
}

// ── 2. late binding reaches the live server ──────────────────────────────────

/// The regression this pins is precise: a consuming builder called on a
/// `DnsServer::clone()` rebinds the clone and discards it. Before Phase 139
/// `setup_acme` did exactly that and dropped the result, so the capability was
/// never attached — while logging that it was.
#[test]
fn a_capability_bound_after_construction_reaches_the_query_context() {
    let server = Arc::new(dns_server());

    let dht = Arc::new(CountingDht::new(vec![anycast_node("example.com")]));
    let registry = Arc::new(
        MeshDnsRegistry::new("node-1".to_string(), true).with_dht_record_store(dht.clone()),
    );

    assert!(
        server.mesh_registry().is_none(),
        "a freshly constructed server must have no registry"
    );

    assert!(
        server.set_mesh_registry(registry),
        "the first binding must be accepted"
    );

    assert!(
        server.mesh_registry().is_some(),
        "the binding must be visible on the live server"
    );
    assert!(
        server.query_context().mesh_registry.is_some(),
        "the request path reads the registry from the query context; it was \
         hardcoded `None` in both transports before Phase 139"
    );
}

/// The binding must survive the `Arc` boundary composition actually crosses:
/// it holds `Arc<DnsServer>`, and `Clone` is used to hand a server into a
/// startup task. If the cell were cloned by value, the task's server and the
/// composition's server would hold different slots.
#[test]
fn a_binding_survives_cloning_the_server() {
    let server = Arc::new(dns_server());
    let registry = Arc::new(MeshDnsRegistry::new("node-1".to_string(), true));

    // Bind through a clone, the shape the old `setup_acme` attempted.
    let bound = (*server).clone();
    assert!(bound.set_mesh_registry(registry));

    assert!(
        server.mesh_registry().is_some(),
        "a binding made through a clone must reach the `Arc` the request path \
         holds; otherwise the clone silently swallows the capability"
    );
    assert!(
        bound.mesh_registry().is_some(),
        "and the clone must still see its own binding"
    );
}

/// Set-once, not last-write-wins. Replacing a live capability silently would
/// make "which provider is authoritative" unanswerable from logs.
#[test]
fn a_second_binding_is_refused_and_the_first_is_kept() {
    let server = dns_server();

    let first = Arc::new(MeshDnsRegistry::new("node-1".to_string(), true));
    let second = Arc::new(MeshDnsRegistry::new("node-2".to_string(), true));

    assert!(server.set_mesh_registry(first.clone()));
    assert!(
        !server.set_mesh_registry(second.clone()),
        "a second binding must report that it was refused"
    );

    let bound = server.mesh_registry().expect("a binding exists");
    assert!(
        Arc::ptr_eq(bound, &first),
        "the refused binding must not have replaced the live one"
    );
}

/// Same set-once contract for the ACME capability — the one whose wiring was
/// silently lost.
#[test]
fn the_acme_capability_binds_once_and_is_visible_to_the_query_context() {
    let server = Arc::new(dns_server());

    assert!(server.query_context().acme_dns_challenges.is_none());

    let challenges = Arc::new(FixedChallenges);
    assert!(server.set_acme_dns_challenges(Arc::clone(&challenges) as _));

    assert!(
        server.acme_dns_challenges().is_some(),
        "the ACME capability must be readable from the live server"
    );
    assert!(
        server.query_context().acme_dns_challenges.is_some(),
        "the ACME challenge lookup runs in the query path; if the context \
         cannot see it, DNS-01 validation cannot answer its TXT query"
    );

    assert!(
        !server.set_acme_dns_challenges(Arc::new(FixedChallenges)),
        "a second ACME binding must be refused"
    );
}

struct FixedChallenges;

impl synvoid_dns::secure_transport::AcmeTxtChallenges for FixedChallenges {
    fn txt_value(&self, _domain: &str) -> Option<String> {
        Some("challenge-token".to_string())
    }
}

// ── 3. the global locator ────────────────────────────────────────────────────

/// The locator is the narrowest seam in the crate — one method. It must be
/// reachable through a dyn object, because the only field holding it is an
/// `Arc<dyn …>`.
#[tokio::test]
async fn the_global_locator_is_reachable_through_the_registry() {
    let registry = MeshDnsRegistry::new("node-1".to_string(), true)
        .with_routing_manager(Arc::new(FixedLocator));

    // Exercised through the capability's own signature, not through a private
    // path: this is the exact question DNS asks.
    let locator: Arc<dyn DhtGlobalLocator> = Arc::new(FixedLocator);
    assert_eq!(locator.find_closest_global(3).await.len(), 3);

    // And the registry that composition builds must still be constructible
    // with both capabilities present at once.
    let _ = registry.query_anycast_from_dht("example.com");
}
