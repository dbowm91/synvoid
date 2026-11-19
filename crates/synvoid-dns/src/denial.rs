//! Denial of existence, derived from the zone instead of synthesized per query.
//!
//! Phase 05 (D5, D6, D38, L5): a signed zone's NSEC/NSEC3 records are a
//! property of the zone. This module builds them once, from a canonical owner
//! index, and the query path only **selects** the proof that covers the
//! question — it never assembles a record at query time.
//!
//! The index is ordered by RFC 4034 §6.1: names are compared label by label
//! starting at the root, ASCII case-folded, so `example.com` sorts before
//! `a.example.com` (an ancestor before its descendants) and `*.example.com`
//! sorts where the `*` label places it — not by `String` ordering (L5).
//!
//! Two chains are kept:
//!
//! - **NSEC**: one record per owner, in canonical order, `next` wrapping to
//!   the apex. The bitmap is derived from the RRsets present at the owner plus
//!   `NSEC` and `RRSIG`; `DS` is kept only at a delegation (NS present, no
//!   SOA), because a DS bit at any other name, or an absent DS bit at a
//!   delegation, would assert something the zone does not contain.
//! - **NSEC3**: hashed owner names in hash order (RFC 5155 §7.1). Empty
//!   non-terminals get a record with an empty bitmap; a name below a
//!   delegation (glue) is not authoritative and gets none; with Opt-Out an
//!   insecure delegation is omitted and the covering record carries the flag.
//!   The `next` field is the next hash **bytes**, not a re-hash (D38).
//!
//! `Zone` stores the index behind an [`Arc`], and the served zone itself is an
//! `Arc<Zone>` in `ShardedZoneStore` (phase 09 R3): a query clones one pointer
//! and reads the same index every other query reads.
//!
//! [`Zone::rebuild_denial`](crate::server::Zone::rebuild_denial) is called by
//! [`Zone::commit_records`](crate::server::Zone::commit_records), the single
//! writer for zone state (phase 09 R2). Load, reload, `add_record`, the update
//! commit, mesh apply and `ShardedZoneStore::insert`/`update_zone` all go
//! through that writer, so no path can publish a stale chain.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use crate::dnssec::{
    canonical_name, create_nsec3_owner_name, create_nsec3_record, create_nsec_record,
    hash_name_nsec3, Nsec3Config,
};
use crate::server::{DnsZoneRecord, RecordType};

/// `DS`, which only has meaning at a delegation in the parent zone.
const TYPE_DS: u16 = 43;
/// `NS`, which marks a delegation when the owner has no SOA.
const TYPE_NS: u16 = 2;
/// `RRSIG`, present at every signed owner.
const TYPE_RRSIG: u16 = 46;
/// `NSEC`, present at every NSEC owner.
const TYPE_NSEC: u16 = 47;
/// `NSEC3`, never listed in its own type bitmap (RFC 5155 §7.1).
const TYPE_NSEC3: u16 = 50;
/// `SOA`, which marks the apex (and therefore not a delegation).
const TYPE_SOA: u16 = 6;

/// Which denial chain a zone publishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenialMode {
    Nsec,
    Nsec3,
}

/// The answer shape whose proof is being selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenialKind {
    /// The owner exists (or is an empty non-terminal) but the type does not.
    NoData,
    /// Neither the name nor a wildcard match exists.
    NxDomain,
    /// The answer is a wildcard expansion; the next closer name must be proven
    /// absent (RFC 4035 §3.1.3.3, RFC 5155 §7.2.6).
    WildcardAnswer,
    /// The wildcard exists but not the requested type.
    WildcardNoData,
}

/// The canonical owner index and denial chains of one zone.
///
/// Built only by [`ZoneDenial::build`]; the query path reads it.
#[derive(Debug, Default)]
pub struct ZoneDenial {
    /// Normalized origin (lowercase, no trailing dot).
    origin: String,
    /// Every owner in RFC 4034 §6.1 canonical order: canonical wire name and
    /// the display name (`www.example.com`).
    owners: Vec<(Vec<u8>, String)>,
    /// Owner display name -> NSEC record.
    nsec: HashMap<String, Arc<DnsZoneRecord>>,
    /// Hash-ordered NSEC3 chain, when the zone publishes NSEC3.
    nsec3: Option<Nsec3Chain>,
    /// Empty non-terminals: names that own no RRset but have a descendant that
    /// does. They exist for closest-encloser purposes and need an NSEC3.
    empty_non_terminals: BTreeSet<String>,
    /// Delegations without a DS RRset, i.e. the names Opt-Out may omit.
    insecure_delegations: BTreeSet<String>,
}

/// The NSEC3 chain of one zone, in hash order.
#[derive(Debug)]
pub struct Nsec3Chain {
    origin: String,
    /// Sanitized parameters: exactly what the served RDATA carries.
    param: Nsec3Config,
    /// Hash -> NSEC3 record, ordered by the raw hash octets (hash order).
    by_hash: BTreeMap<[u8; 20], Arc<DnsZoneRecord>>,
    /// Original owner display name -> hash, for the names present in the chain.
    owner_hashes: BTreeMap<String, [u8; 20]>,
}

impl ZoneDenial {
    /// Build the index and both chains from the zone's records.
    ///
    /// `nsec3param` comes from the zone configuration; `None` means the zone
    /// does not publish NSEC3. `ttl` applies to every generated record (the
    /// zone's DNSKEY TTL is the existing denial TTL).
    pub fn build(
        origin: &str,
        records: &HashMap<(String, RecordType), Vec<DnsZoneRecord>>,
        nsec3param: Option<&Nsec3Config>,
        ttl: u32,
    ) -> Self {
        let origin = normalize_origin(origin);

        // Owner -> the RR types that actually exist there.
        let mut owner_types: BTreeMap<String, BTreeSet<u16>> = BTreeMap::new();
        for ((name, record_type), values) in records {
            if values.is_empty() {
                continue;
            }
            owner_types
                .entry(display_name(&origin, name))
                .or_default()
                .insert(u16::from(*record_type));
        }

        // Glue below a zone cut is not authoritative data: it is neither
        // signed nor part of the NSEC/NSEC3 chain (RFC 4035 §2.3, RFC 5155
        // §7.1). Keeping it in the index would assert, in a denial proof,
        // that this server is authoritative for a name it only forwards.
        let mut delegation_names: Vec<&String> = owner_types
            .iter()
            .filter(|(_, types)| is_delegation(types))
            .map(|(name, _)| name)
            .collect();
        delegation_names.sort();
        let is_glue = |name: &str| {
            delegation_names
                .iter()
                .any(|delegation| is_strict_descendant(name, delegation.as_str()))
        };
        let authoritative: BTreeMap<String, BTreeSet<u16>> = owner_types
            .iter()
            .filter(|(name, _)| !is_glue(name))
            .map(|(name, types)| (name.clone(), types.clone()))
            .collect();

        let mut owners: Vec<(Vec<u8>, String)> = Vec::with_capacity(authoritative.len());
        for owner in authoritative.keys() {
            match canonical_wire(owner) {
                Some(wire) => owners.push((wire, owner.clone())),
                None => tracing::error!(
                    owner_name = %owner,
                    "DNS denial: unencodable owner name; excluding it from the canonical index"
                ),
            }
        }
        owners.sort_by(|a, b| canonical_cmp(&a.0, &b.0));

        let mut empty_non_terminals = BTreeSet::new();
        let owner_names: BTreeSet<String> = authoritative.keys().cloned().collect();
        for owner in authoritative.keys() {
            for ancestor in ancestors(&origin, owner) {
                if ancestor != origin && !owner_names.contains(&ancestor) {
                    empty_non_terminals.insert(ancestor);
                }
            }
        }

        let mut insecure_delegations = BTreeSet::new();
        for (name, types) in &authoritative {
            if is_delegation(types) && !types.contains(&TYPE_DS) {
                insecure_delegations.insert(name.clone());
            }
        }

        let nsec = build_nsec_map(&owners, &authoritative, ttl);
        let nsec3 = nsec3param.map(|param| {
            build_nsec3_chain(
                &origin,
                &authoritative,
                &empty_non_terminals,
                &insecure_delegations,
                param,
                ttl,
            )
        });

        Self {
            origin,
            owners,
            nsec,
            nsec3: nsec3.flatten(),
            empty_non_terminals,
            insecure_delegations,
        }
    }

    /// True when the zone has no owners (an empty index has no proofs).
    pub fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }

    /// The normalized zone origin.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Owners in canonical order: `(canonical wire name, display name)`.
    pub fn owners(&self) -> &[(Vec<u8>, String)] {
        &self.owners
    }

    /// The NSEC3 chain, when the zone publishes one.
    pub fn nsec3(&self) -> Option<&Nsec3Chain> {
        self.nsec3.as_ref()
    }

    /// True when `name` is an owner (an RRset exists at it).
    pub fn is_owner(&self, name: &str) -> bool {
        let display = display_name(&self.origin, name);
        self.nsec.contains_key(&display)
    }

    /// True when `name` is an empty non-terminal.
    pub fn is_empty_non_terminal(&self, name: &str) -> bool {
        let display = display_name(&self.origin, name);
        self.empty_non_terminals.contains(&display)
    }

    /// True when `name` exists: an owner or an empty non-terminal.
    pub fn exists(&self, name: &str) -> bool {
        self.is_owner(name) || self.is_empty_non_terminal(name)
    }

    /// The NSEC record at an existing owner.
    pub fn nsec_at(&self, name: &str) -> Option<Arc<DnsZoneRecord>> {
        let display = display_name(&self.origin, name);
        self.nsec.get(&display).cloned()
    }

    /// The canonical successor of `name`, wrapping to the apex.
    ///
    /// This replaces the `String` ordering of `find_next_name_in_zone` (L5).
    pub fn successor(&self, name: &str) -> Option<&str> {
        let wire = canonical_wire(&display_name(&self.origin, name))?;
        let index = self
            .owners
            .partition_point(|(candidate, _)| canonical_cmp(candidate, &wire).is_le());
        let owner = self.owners.get(index).or_else(|| self.owners.first())?;
        Some(owner.1.as_str())
    }

    /// The NSEC whose interval strictly contains `name`.
    ///
    /// The owner is the canonical predecessor; the last owner wraps to the
    /// apex. `None` when `name` is itself an owner (it needs no coverage
    /// proof), when the index is empty, or when the name cannot be encoded.
    pub fn nsec_covering(&self, name: &str) -> Option<Arc<DnsZoneRecord>> {
        let wire = canonical_wire(&display_name(&self.origin, name))?;
        let index = self
            .owners
            .partition_point(|(candidate, _)| canonical_cmp(candidate, &wire).is_lt());
        if index < self.owners.len() && canonical_cmp(&self.owners[index].0, &wire).is_eq() {
            return None;
        }
        let owner = if index == 0 {
            self.owners.last()?
        } else {
            &self.owners[index - 1]
        };
        self.nsec.get(&owner.1).cloned()
    }

    /// Select the denial proof for an answer shape.
    ///
    /// Returns the records the authority section must carry, in a
    /// deterministic order, or `None` when the zone cannot prove the answer.
    /// `None` is never papered over: a signed zone that cannot prove a
    /// negative answer must answer SERVFAIL rather than emit an unprovable one.
    pub fn proof(
        &self,
        mode: DenialMode,
        kind: DenialKind,
        qname: &str,
    ) -> Option<Vec<Arc<DnsZoneRecord>>> {
        match mode {
            DenialMode::Nsec => self.nsec_proof(kind, qname),
            DenialMode::Nsec3 => self.nsec3_proof(kind, qname),
        }
    }

    fn nsec_proof(&self, kind: DenialKind, qname: &str) -> Option<Vec<Arc<DnsZoneRecord>>> {
        if self.nsec.is_empty() {
            return None;
        }
        let qname = display_name(&self.origin, qname);
        match kind {
            DenialKind::NoData => Some(vec![self.nsec_at(&qname)?]),
            DenialKind::NxDomain => {
                // A name error for an owner is not a name error at all.
                if self.is_owner(&qname) {
                    return None;
                }
                let mut proof = vec![self.nsec_covering(&qname)?];
                let encloser = self.closest_encloser(&qname)?;
                let wildcard = format!("*.{encloser}");
                if self.exists(&wildcard) {
                    // The wildcard should have matched; this zone cannot prove
                    // that the name does not exist. Phase 09 implements the
                    // wildcard answer that belongs here.
                    return None;
                }
                if let Some(wildcard_cover) = self.nsec_covering(&wildcard) {
                    push_unique(&mut proof, wildcard_cover);
                }
                Some(proof)
            }
            DenialKind::WildcardAnswer => {
                let encloser = self.closest_encloser(&qname)?;
                let next_closer = next_closer(&qname, &encloser)?;
                Some(vec![self.nsec_covering(&next_closer)?])
            }
            DenialKind::WildcardNoData => {
                let encloser = self.closest_encloser(&qname)?;
                let next_closer = next_closer(&qname, &encloser)?;
                let mut proof = vec![self.nsec_covering(&next_closer)?];
                push_unique(&mut proof, self.nsec_at(&format!("*.{encloser}"))?);
                Some(proof)
            }
        }
    }

    fn nsec3_proof(&self, kind: DenialKind, qname: &str) -> Option<Vec<Arc<DnsZoneRecord>>> {
        let chain = self.nsec3.as_ref()?;
        let qname = display_name(&self.origin, qname);
        match kind {
            DenialKind::NoData => {
                if let Some(hash) = chain.hash_of(&qname) {
                    return Some(vec![chain.record_for_hash(&hash)?]);
                }
                // Opt-Out: an insecure delegation has no NSEC3 of its own; the
                // covering record with the Opt-Out flag proves it is unsigned
                // (RFC 5155 §7.2.4).
                if chain.opt_out() && self.insecure_delegations.contains(&qname) {
                    let hash = chain.hash_bytes(&qname)?;
                    return Some(vec![chain.covering_hash(&hash)?]);
                }
                None
            }
            DenialKind::NxDomain => {
                // An owner or an empty non-terminal exists, so a name error
                // is not provable (RFC 5155 §7.2.2/§7.2.3).
                if self.exists(&qname) {
                    return None;
                }
                let encloser = self.closest_provable_encloser(&qname, chain)?;
                let next_closer = next_closer(&qname, &encloser)?;
                let encloser_hash = chain.hash_of(&encloser)?;
                let mut proof = vec![
                    chain.record_for_hash(&encloser_hash)?,
                    chain.covering_hash(&chain.hash_bytes(&next_closer)?)?,
                ];
                let wildcard = format!("*.{encloser}");
                if chain.hash_of(&wildcard).is_some() {
                    // The wildcard should have matched (phase 09).
                    return None;
                }
                let wildcard_cover = chain.covering_hash(&chain.hash_bytes(&wildcard)?)?;
                push_unique(&mut proof, wildcard_cover);
                Some(proof)
            }
            DenialKind::WildcardAnswer => {
                let encloser = self.closest_provable_encloser(&qname, chain)?;
                let next_closer = next_closer(&qname, &encloser)?;
                Some(vec![chain.covering_hash(&chain.hash_bytes(&next_closer)?)?])
            }
            DenialKind::WildcardNoData => {
                let encloser = self.closest_provable_encloser(&qname, chain)?;
                let next_closer = next_closer(&qname, &encloser)?;
                let mut proof = Vec::new();
                if let Some(hash) = chain.hash_of(&encloser) {
                    push_unique(&mut proof, chain.record_for_hash(&hash)?);
                }
                push_unique(
                    &mut proof,
                    chain.covering_hash(&chain.hash_bytes(&next_closer)?)?,
                );
                let wildcard = format!("*.{encloser}");
                let wildcard_hash = chain.hash_bytes(&wildcard)?;
                push_unique(
                    &mut proof,
                    chain
                        .record_for_hash(&wildcard_hash)
                        .or_else(|| chain.covering_hash(&wildcard_hash))?,
                );
                Some(proof)
            }
        }
    }

    /// The longest existing ancestor of `name` (owners and empty
    /// non-terminals both exist).
    fn closest_encloser(&self, name: &str) -> Option<String> {
        let labels = labels(name);
        for start in 1..labels.len() {
            let candidate = labels[start..].join(".");
            if self.exists(&candidate) {
                return Some(candidate);
            }
        }
        if self.exists(&self.origin) {
            Some(self.origin.clone())
        } else {
            None
        }
    }

    /// The longest ancestor with a matching NSEC3 (Opt-Out can hide a
    /// delegation from the chain, making the closest *provable* encloser the
    /// parent — RFC 5155 §7.2.8/§8.3).
    fn closest_provable_encloser(&self, name: &str, chain: &Nsec3Chain) -> Option<String> {
        let labels = labels(name);
        for start in 1..labels.len() {
            let candidate = labels[start..].join(".");
            if chain.hash_of(&candidate).is_some() {
                return Some(candidate);
            }
        }
        if chain.hash_of(&self.origin).is_some() {
            Some(self.origin.clone())
        } else {
            None
        }
    }
}

impl Nsec3Chain {
    /// The parameters as published.
    pub fn param(&self) -> &Nsec3Config {
        &self.param
    }

    /// The normalized origin.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// True when the chain sets the Opt-Out flag.
    pub fn opt_out(&self) -> bool {
        self.param.flags & 0x01 != 0
    }

    /// Number of hashed owner names in the chain.
    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    /// True when the chain has no entries.
    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    /// The hash of a name that is present in the chain.
    pub fn hash_of(&self, name: &str) -> Option<[u8; 20]> {
        let display = display_name(&self.origin, name);
        self.owner_hashes.get(&display).copied()
    }

    /// The NSEC3 record matching `name`, when it is in the chain.
    pub fn record_for_name(&self, name: &str) -> Option<Arc<DnsZoneRecord>> {
        let hash = self.hash_of(name)?;
        self.record_for_hash(&hash)
    }

    /// The NSEC3 record with this hashed owner name.
    pub fn record_for_hash(&self, hash: &[u8; 20]) -> Option<Arc<DnsZoneRecord>> {
        self.by_hash.get(hash).cloned()
    }

    /// The NSEC3 whose interval strictly contains `hash`.
    pub fn covering_hash(&self, hash: &[u8; 20]) -> Option<Arc<DnsZoneRecord>> {
        if self.by_hash.contains_key(hash) {
            return None;
        }
        let owner = match self.by_hash.range(..*hash).next_back() {
            Some((_, record)) => record,
            None => self.by_hash.iter().next_back()?.1,
        };
        Some(Arc::clone(owner))
    }

    /// Hash `name` with the chain's parameters, whether or not it is a member.
    pub fn hash_bytes(&self, name: &str) -> Option<[u8; 20]> {
        let display = display_name(&self.origin, name);
        let hash = hash_name_nsec3(&display, &self.param);
        <[u8; 20]>::try_from(hash.as_slice()).ok()
    }

    /// The hashes in hash order, paired with their records.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8; 20], &Arc<DnsZoneRecord>)> {
        self.by_hash.iter()
    }
}

fn build_nsec_map(
    owners: &[(Vec<u8>, String)],
    owner_types: &BTreeMap<String, BTreeSet<u16>>,
    ttl: u32,
) -> HashMap<String, Arc<DnsZoneRecord>> {
    let mut nsec = HashMap::with_capacity(owners.len());
    if owners.is_empty() {
        return nsec;
    }
    for index in 0..owners.len() {
        let (_, display) = &owners[index];
        let next = &owners[(index + 1) % owners.len()].1;

        let mut types = owner_types.get(display).cloned().unwrap_or_default();
        types.insert(TYPE_NSEC);
        types.insert(TYPE_RRSIG);
        normalize_ds_bit(&mut types);

        let bitmap: Vec<u16> = types.into_iter().collect();
        let rdata = create_nsec_record(display, next, &bitmap);
        nsec.insert(
            display.clone(),
            Arc::new(DnsZoneRecord {
                name: display.clone(),
                record_type: RecordType::NSEC,
                value: hex::encode(rdata),
                ttl,
                priority: None,
            }),
        );
    }
    nsec
}

fn build_nsec3_chain(
    origin: &str,
    owner_types: &BTreeMap<String, BTreeSet<u16>>,
    empty_non_terminals: &BTreeSet<String>,
    insecure_delegations: &BTreeSet<String>,
    param: &Nsec3Config,
    ttl: u32,
) -> Option<Nsec3Chain> {
    let param = match param.sanitized() {
        Some(param) => param,
        None => {
            tracing::error!(
                "DNS denial: NSEC3 salt is longer than 255 octets; refusing to build a chain"
            );
            return None;
        }
    };
    if param.algorithm != 1 {
        // The chain key is the 20-octet SHA-1 hash. A chain that cannot be
        // keyed by its published hashes must not be served.
        tracing::error!(
            algorithm = param.algorithm,
            "DNS denial: unsupported NSEC3 hash algorithm; refusing to build a chain"
        );
        return None;
    }

    let mut delegations: Vec<&String> = owner_types
        .iter()
        .filter(|(_, types)| is_delegation(types))
        .map(|(name, _)| name)
        .collect();
    delegations.sort();
    let is_glue = |name: &str| {
        delegations
            .iter()
            .any(|delegation| is_strict_descendant(name, delegation.as_str()))
    };

    // Owner name -> the types that exist there (an empty set is an ENT).
    let mut entries: BTreeMap<String, BTreeSet<u16>> = BTreeMap::new();
    for (name, types) in owner_types {
        // Glue below a zone cut is not authoritative data (RFC 5155 §7.1).
        if is_glue(name) {
            continue;
        }
        // Opt-Out omits insecure delegations; the covering NSEC3 carries the
        // flag instead.
        if param.flags & 0x01 != 0 && insecure_delegations.contains(name) {
            continue;
        }
        entries.insert(name.clone(), types.clone());
    }
    for name in empty_non_terminals {
        if !is_glue(name) {
            entries.entry(name.clone()).or_default();
        }
    }

    // Hash -> bitmap; a hash collision merges the types (RFC 5155 §C.2.1 says
    // to rotate the salt, which is an operator action, not a query-time one).
    let mut hashed: BTreeMap<[u8; 20], BTreeSet<u16>> = BTreeMap::new();
    let mut owner_hashes: BTreeMap<String, [u8; 20]> = BTreeMap::new();
    for (name, types) in &entries {
        let raw = hash_name_nsec3(name, &param);
        let Ok(hash) = <[u8; 20]>::try_from(raw.as_slice()) else {
            tracing::error!(
                owner = %name,
                "DNS denial: NSEC3 hash is not 20 octets; excluding the owner"
            );
            continue;
        };
        if !types.is_empty() {
            let mut bitmap = types.clone();
            bitmap.insert(TYPE_RRSIG);
            // RFC 5155 §7.1: the NSEC3 type itself is never in the bitmap.
            bitmap.remove(&TYPE_NSEC3);
            normalize_ds_bit(&mut bitmap);
            hashed.entry(hash).or_default().extend(bitmap);
        } else {
            // An empty non-terminal has an empty bitmap (RFC 5155 Appendix A
            // publishes `y.w.example` and `w.example` exactly this way).
            hashed.entry(hash).or_default();
        }
        owner_hashes.insert(name.clone(), hash);
    }

    if hashed.is_empty() {
        return None;
    }

    let hashes: Vec<[u8; 20]> = hashed.keys().copied().collect();
    let mut by_hash: BTreeMap<[u8; 20], Arc<DnsZoneRecord>> = BTreeMap::new();
    for (index, hash) in hashes.iter().enumerate() {
        let next = hashes[(index + 1) % hashes.len()];
        let bitmap: Vec<u16> = hashed[hash].iter().copied().collect();
        let rdata = create_nsec3_record(&param, &next, &bitmap);
        by_hash.insert(
            *hash,
            Arc::new(DnsZoneRecord {
                name: create_nsec3_owner_name(origin, hash),
                record_type: RecordType::NSEC3,
                value: hex::encode(rdata),
                ttl,
                priority: None,
            }),
        );
    }

    Some(Nsec3Chain {
        origin: origin.to_string(),
        param,
        by_hash,
        owner_hashes,
    })
}

/// Remove DS from a bitmap unless the owner is a delegation.
///
/// A DS RRset only exists on the parent side of a zone cut: NS present and no
/// SOA. Keeping a stray DS bit at any other name — or inventing one at an
/// insecure delegation — would assert an RRset the zone does not serve.
fn normalize_ds_bit(types: &mut BTreeSet<u16>) {
    if !is_delegation(types) {
        types.remove(&TYPE_DS);
    }
}

fn is_delegation(types: &BTreeSet<u16>) -> bool {
    types.contains(&TYPE_NS) && !types.contains(&TYPE_SOA)
}

fn push_unique(proof: &mut Vec<Arc<DnsZoneRecord>>, record: Arc<DnsZoneRecord>) {
    if proof.iter().any(|existing| existing.name == record.name) {
        return;
    }
    proof.push(record);
}

/// Normalize a zone origin: lowercase, no trailing dot.
fn normalize_origin(origin: &str) -> String {
    origin.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Resolve a record key (`@`, `www`, `a.b`, or an FQDN inside the zone) to the
/// absolute display name the zone index uses.
pub(crate) fn display_name(origin: &str, name: &str) -> String {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name == "@" || name == origin {
        return origin.to_string();
    }
    if origin.is_empty() {
        return name;
    }
    if name.len() > origin.len() && name.ends_with(&format!(".{origin}")) {
        return name;
    }
    format!("{name}.{origin}")
}

/// The labels of a display name.
fn labels(name: &str) -> Vec<&str> {
    name.split('.').filter(|label| !label.is_empty()).collect()
}

/// Ancestors strictly above `name` and strictly below `origin`, longest first.
fn ancestors(origin: &str, name: &str) -> Vec<String> {
    let name_labels = labels(name);
    let origin_len = labels(origin).len();
    let mut out = Vec::new();
    for start in 1..name_labels.len().saturating_sub(origin_len) {
        out.push(name_labels[start..].join("."));
    }
    out
}

fn is_strict_descendant(name: &str, ancestor: &str) -> bool {
    name.len() > ancestor.len() + 1
        && name.ends_with(ancestor)
        && name.as_bytes()[name.len() - ancestor.len() - 1] == b'.'
}

/// The child of `encloser` on the path to `name` (one label longer).
fn next_closer(name: &str, encloser: &str) -> Option<String> {
    let name_labels = labels(name);
    let encloser_labels = labels(encloser);
    if name_labels.len() <= encloser_labels.len() {
        return None;
    }
    Some(name_labels[name_labels.len() - encloser_labels.len() - 1..].join("."))
}

/// Canonical wire form (lowercase, uncompressed, absolute) of a display name.
fn canonical_wire(display: &str) -> Option<Vec<u8>> {
    let mut fqdn = display.trim().trim_end_matches('.').to_ascii_lowercase();
    if fqdn.is_empty() {
        return Some(vec![0]);
    }
    fqdn.push('.');
    canonical_name(&fqdn).ok()
}

/// The labels of a canonical wire name, without the root label.
fn wire_labels(wire: &[u8]) -> Vec<&[u8]> {
    let mut labels = Vec::new();
    let mut offset = 0;
    while offset < wire.len() {
        let len = wire[offset] as usize;
        if len == 0 {
            break;
        }
        if offset + 1 + len > wire.len() {
            break;
        }
        labels.push(&wire[offset + 1..offset + 1 + len]);
        offset += 1 + len;
    }
    labels
}

/// RFC 4034 §6.1 canonical order: compare label sequences starting at the root,
/// ASCII case-folded.
fn canonical_cmp(a: &[u8], b: &[u8]) -> Ordering {
    wire_labels(a).iter().rev().cmp(wire_labels(b).iter().rev())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(
        records: &[(&str, RecordType)],
    ) -> HashMap<(String, RecordType), Vec<DnsZoneRecord>> {
        let mut map = HashMap::new();
        for (name, record_type) in records {
            map.insert(
                (name.to_string(), *record_type),
                vec![DnsZoneRecord {
                    name: name.to_string(),
                    record_type: *record_type,
                    value: String::new(),
                    ttl: 300,
                    priority: None,
                }],
            );
        }
        map
    }

    /// Glue below a zone cut is not authoritative: it must not appear in the
    /// canonical index, so no NSEC/NSEC3 proof can assert that this server
    /// owns it (RFC 4035 §2.3, RFC 5155 §7.1).
    #[test]
    fn glue_below_a_delegation_is_not_in_any_denial_chain() {
        let zone = request(&[
            ("@", RecordType::SOA),
            ("@", RecordType::NS),
            ("www", RecordType::A),
            ("child", RecordType::NS),
            ("ns.child", RecordType::A),
        ]);

        let nsec_only = ZoneDenial::build("example.com", &zone, None, 300);
        let owners: Vec<&str> = nsec_only
            .owners()
            .iter()
            .map(|(_, name)| name.as_str())
            .collect();
        assert!(
            owners.contains(&"child.example.com"),
            "the delegation point is authoritative and must be covered: {owners:?}"
        );
        assert!(
            !owners.contains(&"ns.child.example.com"),
            "glue must not be asserted by an NSEC record: {owners:?}"
        );
        assert!(nsec_only.nsec_at("ns.child.example.com").is_none());

        let param = Nsec3Config::new(0, vec![0xab, 0xcd]);
        let nsec3 = ZoneDenial::build("example.com", &zone, Some(&param), 300);
        let chain = nsec3.nsec3().expect("NSEC3 chain");
        assert!(chain.hash_of("child.example.com").is_some());
        assert!(
            chain.hash_of("ns.child.example.com").is_none(),
            "glue must not get an NSEC3 record"
        );
    }

    fn bitmap_of(record: &DnsZoneRecord) -> BTreeSet<u16> {
        let rdata = hex::decode(&record.value).unwrap();
        let mut offset = 0;
        while offset < rdata.len() && rdata[offset] != 0 {
            offset += 1 + rdata[offset] as usize;
        }
        offset += 1;
        let mut types = BTreeSet::new();
        while offset + 2 <= rdata.len() {
            let window = rdata[offset] as u16;
            let len = rdata[offset + 1] as usize;
            for byte in 0..len {
                for bit in 0..8 {
                    if rdata[offset + 2 + byte] & (0x80 >> bit) != 0 {
                        types.insert(window * 256 + (byte as u16) * 8 + bit as u16);
                    }
                }
            }
            offset += 2 + len;
        }
        types
    }

    #[test]
    fn canonical_order_puts_an_ancestor_before_its_descendants() {
        let records = request(&[
            ("www", RecordType::A),
            ("@", RecordType::SOA),
            ("a.www", RecordType::A),
            ("z", RecordType::A),
        ]);
        let denial = ZoneDenial::build("example.com", &records, None, 300);
        let displays: Vec<&str> = denial.owners().iter().map(|(_, d)| d.as_str()).collect();
        assert_eq!(
            displays,
            vec![
                "example.com",
                "www.example.com",
                "a.www.example.com",
                "z.example.com"
            ],
            "a descendant sorts after its ancestor, not by String order"
        );
    }

    #[test]
    fn nsec_bitmap_keeps_ds_only_at_a_delegation() {
        let records = request(&[
            ("@", RecordType::SOA),
            ("@", RecordType::NS),
            ("child", RecordType::NS),
            ("secure", RecordType::NS),
            ("secure", RecordType::DS),
        ]);
        let denial = ZoneDenial::build("example.com", &records, None, 300);
        let bitmap = |name: &str| bitmap_of(&denial.nsec_at(name).unwrap());

        assert!(
            !bitmap("@").contains(&TYPE_DS),
            "the apex is not a delegation, DS must not be asserted there"
        );
        assert!(
            !bitmap("child").contains(&TYPE_DS),
            "an insecure delegation must not claim a DS RRset"
        );
        assert!(
            bitmap("secure").contains(&TYPE_DS),
            "a secure delegation publishes DS in its NSEC bitmap"
        );
    }

    #[test]
    fn next_closer_is_one_label_below_the_encloser() {
        assert_eq!(
            next_closer("a.c.x.w.example", "x.w.example").as_deref(),
            Some("c.x.w.example")
        );
        assert_eq!(
            next_closer("a.b.example", "example").as_deref(),
            Some("b.example")
        );
    }
}
