//! The mesh DHT capability double, shared by the mesh suites.
//!
//! Phase 139 introduced `CountingDht` inside `mesh_capability_wiring.rs` to
//! prove the DNS-owned `DhtRecordStore` seam is substitutable outside
//! `synvoid-mesh`. Phase 08 extends it with the domain-registration half:
//!
//! * a mutable registration table, so a test can add a registration after
//!   startup and let the periodic sync loop pick it up;
//! * a **real Ed25519 verifier** over the registration fields, so the DNS
//!   trust boundary is exercised end to end rather than against a hardcoded
//!   boolean;
//! * an org-key domain-claim set, which is the only place a claim enters the
//!   DNS decision today.
//!
//! It lives in `support/` because two integration-test binaries now need the
//! same double. Keeping two copies would let the seam drift in one suite while
//! the other stayed green.

// The two consumers exercise different halves of this double; a method unused in
// one test binary is still part of the shared capability surface.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use parking_lot::RwLock;

use synvoid_dns::mesh_sync::dht_capability::{
    AdvertisedAnycastNode, AdvertisedAnycastRecord, AdvertisedDomainRegistration, DhtRecordStore,
};

/// The bytes a publisher signs for a domain registration.
///
/// `publisher_id` is deliberately **not** part of the message: the provider
/// chooses the verification key from it, so the message models "what this
/// publisher advertised". A registration signed by a node other than the
/// claimed origin therefore verifies and must be rejected by the DNS-side
/// publisher-binding check, not by a broken signature.
pub fn registration_message(registration: &AdvertisedDomainRegistration) -> Vec<u8> {
    format!(
        "dns-domain-registration-v1|{}|{}|{}|{}|{}",
        registration.domain,
        registration.origin_node_id,
        registration.ip_addresses.join(","),
        registration.created_at,
        registration.ttl_seconds,
    )
    .into_bytes()
}

/// A DHT that answers from fixed tables and counts calls, so a test can prove
/// the registry reached the capability rather than merely holding a handle.
pub struct CountingDht {
    nodes: Vec<AdvertisedAnycastNode>,
    registrations: RwLock<Vec<AdvertisedDomainRegistration>>,
    /// Node id → the key that node signs with.
    publisher_keys: HashMap<String, SigningKey>,
    /// Domains a peer's org-key claim authorizes. Empty by default.
    claimed_domains: RwLock<HashSet<String>>,
    authenticity_calls: AtomicUsize,
    domain_authenticity_calls: AtomicUsize,
    store_calls: AtomicUsize,
}

impl CountingDht {
    pub fn new(nodes: Vec<AdvertisedAnycastNode>) -> Self {
        Self {
            nodes,
            registrations: RwLock::new(Vec::new()),
            publisher_keys: HashMap::new(),
            claimed_domains: RwLock::new(HashSet::new()),
            authenticity_calls: AtomicUsize::new(0),
            domain_authenticity_calls: AtomicUsize::new(0),
            store_calls: AtomicUsize::new(0),
        }
    }

    /// Give each publisher deterministic Ed25519 key material.
    ///
    /// Deterministic seeds keep a failing signature reproducible; the keys are
    /// never used outside a test process.
    pub fn with_publishers(mut self, publishers: &[&str]) -> Self {
        for publisher in publishers {
            let mut seed = [0u8; 32];
            for (index, byte) in publisher.as_bytes().iter().enumerate() {
                seed[index % 32] ^= *byte;
            }
            self.publisher_keys
                .insert((*publisher).to_string(), SigningKey::from_bytes(&seed));
        }
        self
    }

    pub fn add_registration(&self, registration: AdvertisedDomainRegistration) {
        self.registrations.write().push(registration);
    }

    pub fn claim_domain(&self, domain: &str) {
        self.claimed_domains.write().insert(domain.to_string());
    }

    /// Sign `registration` as its `publisher_id`.
    pub fn sign(
        &self,
        mut registration: AdvertisedDomainRegistration,
    ) -> AdvertisedDomainRegistration {
        let key = self
            .publisher_keys
            .get(&registration.publisher_id)
            .unwrap_or_else(|| panic!("no key for publisher {}", registration.publisher_id));
        registration.signature = key
            .sign(&registration_message(&registration))
            .to_bytes()
            .to_vec();
        registration
    }

    /// Anycast authenticity calls, including the zone-query path.
    pub fn authenticity_calls(&self) -> usize {
        self.authenticity_calls.load(Ordering::SeqCst)
    }

    /// Domain-registration authenticity calls.
    pub fn domain_authenticity_calls(&self) -> usize {
        self.domain_authenticity_calls.load(Ordering::SeqCst)
    }

    /// Calls that attempted to write through the capability.
    pub fn store_calls(&self) -> usize {
        self.store_calls.load(Ordering::SeqCst)
    }
}

impl DhtRecordStore for CountingDht {
    fn all_dns_domain_registrations(&self) -> Vec<AdvertisedDomainRegistration> {
        self.registrations.read().clone()
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

    /// Real Ed25519 verification over the registration fields.
    ///
    /// The signing key is selected by `publisher_id`, which is what makes the
    /// "signed by the wrong node" case verifiable: the signature is genuine for
    /// its publisher, and the DNS layer still has to reject it because the
    /// publisher is not the claimed origin.
    fn is_domain_registration_authentic(
        &self,
        registration: &AdvertisedDomainRegistration,
    ) -> bool {
        self.domain_authenticity_calls
            .fetch_add(1, Ordering::SeqCst);

        if registration.signature.is_empty() {
            return false;
        }
        let Some(key) = self.publisher_keys.get(&registration.publisher_id) else {
            return false;
        };
        let Ok(signature_bytes): Result<[u8; 64], _> = registration.signature.as_slice().try_into()
        else {
            return false;
        };
        let signature = Signature::from_bytes(&signature_bytes);
        key.verifying_key()
            .verify(&registration_message(registration), &signature)
            .is_ok()
    }

    fn has_domain_authorization_claim(&self, registration: &AdvertisedDomainRegistration) -> bool {
        self.claimed_domains.read().contains(&registration.domain)
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

/// A store handle that also exposes the counters.
pub fn store(dht: &Arc<CountingDht>) -> Arc<dyn DhtRecordStore> {
    Arc::clone(dht) as Arc<dyn DhtRecordStore>
}
