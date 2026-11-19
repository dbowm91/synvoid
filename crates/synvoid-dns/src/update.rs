use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use super::server::{DnsZoneRecord, RecordType, Zone};
use super::tsig::{parse_tsig_from_query, TsigVerifier};
use super::wire;
use crate::server::{SerialPolicy, ShardedZoneStore};

/// RDATA-bearing types an UPDATE may add or delete.
///
/// RFC 2136 §3.4.1.2 makes an unrecognized type a FORMERR. This list is the
/// set the record store can also serve: a type accepted here but unencodable
/// on the wire would turn a successful UPDATE into a SERVFAIL answer.
fn update_supported_type(rtype: u16) -> bool {
    matches!(rtype, 1 | 2 | 5 | 6 | 12 | 15 | 16 | 28 | 43 | 257)
}

/// DNSSEC record types a dynamic UPDATE must not rewrite.
///
/// A DNSKEY/RRSIG/NSEC/NSEC3 write would let an UPDATE author forge the
/// zone's signed state. They are refused unless the handler is built with the
/// explicit `allow_dnssec_writes` policy.
fn dnssec_record_type(rtype: u16) -> bool {
    matches!(rtype, 46 | 47 | 48 | 50 | 51 | 59 | 60)
}

/// A metatype that cannot appear in the update section (RFC 2136 §3.4.1.2).
fn query_metatype(rtype: u16) -> bool {
    matches!(rtype, 251..=255)
}

const CLASS_IN: u16 = 1;
const CLASS_NONE: u16 = 254;
const CLASS_ANY: u16 = 255;
const TYPE_ANY: u16 = 255;
const TYPE_AXFR: u16 = 252;
const TYPE_SOA: u16 = 6;
const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;

#[derive(Debug, Clone)]
pub struct UpdateZone {
    pub name: String,
    pub class: u16,
}

/// One prerequisite RR, kept in wire terms so the metavalue table can be
/// applied at check time (RFC 2136 §3.2.4).
#[derive(Debug, Clone)]
pub struct UpdatePrerequisite {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct UpdateRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

#[derive(Debug)]
pub struct DynamicUpdate {
    pub zone: Option<UpdateZone>,
    pub prerequisites: Vec<UpdatePrerequisite>,
    pub updates: Vec<UpdateRecord>,
}

impl DynamicUpdate {
    /// Parse an RFC 2136 UPDATE message.
    ///
    /// The zone section must hold exactly one SOA entry; prerequisites are
    /// decoded from the answer section and updates from the authority and
    /// additional sections. A TSIG (type 250) or OPT (type 41) record in the
    /// additional section is not an update and is skipped.
    pub fn parse(query: &[u8]) -> Result<Self, String> {
        if query.len() < 12 {
            return Err("Query too small".to_string());
        }

        let flags = wire::get_message_flags(query).ok_or("Invalid DNS header")?;

        if flags.opcode != wire::OPCODE_UPDATE {
            return Err("Not an UPDATE message".to_string());
        }

        let qdcount = u16::from_be_bytes([query[4], query[5]]);
        let ancount = u16::from_be_bytes([query[6], query[7]]);
        let nscount = u16::from_be_bytes([query[8], query[9]]);
        let arcount = u16::from_be_bytes([query[10], query[11]]);

        // RFC 2136 §3.1.2: exactly one zone entry, and it is an SOA. The
        // zone name is the authority for everything that follows, so a
        // missing or repeated entry is a format error rather than a guess.
        if qdcount != 1 {
            return Err(format!(
                "UPDATE zone section must contain exactly one entry, got {qdcount}"
            ));
        }

        let mut pos = 12;
        let (name, ztype, zclass) = Self::parse_zone_entry(query, pos)?;
        if ztype != TYPE_SOA {
            return Err(format!("UPDATE zone section type must be SOA, got {ztype}"));
        }
        pos = Self::skip_question(query, pos);
        let zone = Some(UpdateZone {
            name,
            class: zclass,
        });

        let mut prerequisites = Vec::new();
        for _ in 0..ancount {
            let (name, rtype, rclass, ttl, rdata) = Self::parse_rr_full(query, pos)?;
            prerequisites.push(UpdatePrerequisite {
                name,
                rtype,
                rclass,
                ttl,
                rdata,
            });
            pos = Self::skip_rr_full(query, pos);
        }

        let mut updates = Vec::new();
        let total_updates = nscount as u32 + arcount as u32;
        for _ in 0..total_updates {
            let (name, rtype, rclass, ttl, rdata) = Self::parse_rr_full(query, pos)?;
            // TSIG and OPT are envelope records, never update records.
            if rtype == 250 || rtype == 41 {
                pos = Self::skip_rr_full(query, pos);
                continue;
            }
            updates.push(UpdateRecord {
                name,
                rtype,
                rclass,
                ttl,
                rdata,
            });
            pos = Self::skip_rr_full(query, pos);
        }

        Ok(Self {
            zone,
            prerequisites,
            updates,
        })
    }

    /// Read the zone entry: NAME, ZTYPE, ZCLASS (a question, not an RR).
    fn parse_zone_entry(query: &[u8], pos: usize) -> Result<(String, u16, u16), String> {
        let (name, end_pos) = Self::parse_name(query, pos)
            .map_err(|_| format!("malformed zone name at offset {pos}"))?;
        if end_pos + 4 > query.len() {
            return Err("Incomplete zone section".to_string());
        }
        let ztype = u16::from_be_bytes([query[end_pos], query[end_pos + 1]]);
        let zclass = u16::from_be_bytes([query[end_pos + 2], query[end_pos + 3]]);
        Ok((name, ztype, zclass))
    }

    /// Read one full RR: NAME, TYPE, CLASS, TTL, RDLENGTH, RDATA.
    fn parse_rr_full(query: &[u8], pos: usize) -> Result<(String, u16, u16, u32, Vec<u8>), String> {
        let (name, end_pos) = Self::parse_name(query, pos)
            .map_err(|_| format!("malformed owner name at offset {pos}"))?;
        if end_pos + 10 > query.len() {
            return Err("Incomplete RR".to_string());
        }
        let rtype = u16::from_be_bytes([query[end_pos], query[end_pos + 1]]);
        let rclass = u16::from_be_bytes([query[end_pos + 2], query[end_pos + 3]]);
        let ttl = u32::from_be_bytes([
            query[end_pos + 4],
            query[end_pos + 5],
            query[end_pos + 6],
            query[end_pos + 7],
        ]);
        let rdlen = u16::from_be_bytes([query[end_pos + 8], query[end_pos + 9]]) as usize;

        let rdata_start = end_pos + 10;
        let rdata_end = rdata_start
            .checked_add(rdlen)
            .ok_or_else(|| "RDATA length overflow".to_string())?;
        if rdata_end > query.len() {
            return Err("Incomplete RDATA".to_string());
        }
        let rdata = query[rdata_start..rdata_end].to_vec();

        Ok((name, rtype, rclass, ttl, rdata))
    }

    /// Decode a (possibly compressed) domain name to presentation form.
    fn parse_name(query: &[u8], mut pos: usize) -> Result<(String, usize), String> {
        let mut name = String::new();
        let mut jumps = 0;

        while pos < query.len() {
            let len = query[pos] as usize;

            if len == 0 {
                pos += 1;
                return Ok((name, pos));
            }

            if (len & 0xC0) == 0xC0 {
                jumps += 1;
                if jumps > 10 {
                    return Err("Too many compression pointers".to_string());
                }
                let second = *query.get(pos + 1).ok_or("Truncated compression pointer")?;
                let offset = ((len & 0x3F) << 8) | second as usize;
                if offset >= pos {
                    return Err("Compression pointer does not point backwards".to_string());
                }
                pos = offset;
                continue;
            }

            if len > 63 {
                return Err("Label too long".to_string());
            }

            let label_start = pos + 1;
            let label_end = label_start + len;
            if label_end > query.len() {
                return Err("Name extends past message".to_string());
            }
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(&String::from_utf8_lossy(&query[label_start..label_end]));
            pos = label_end;
        }

        Err("Name runs past the message".to_string())
    }

    /// Skip one question entry (NAME + QTYPE + QCLASS).
    pub(crate) fn skip_question(query: &[u8], pos: usize) -> usize {
        match Self::parse_name(query, pos) {
            Ok((_, end_pos)) => end_pos.saturating_add(4),
            Err(_) => query.len(),
        }
    }

    pub(crate) fn skip_rr_full(query: &[u8], pos: usize) -> usize {
        match Self::parse_name(query, pos) {
            Ok((_, end_pos)) => {
                if end_pos + 10 > query.len() {
                    return query.len();
                }
                let rdlen = u16::from_be_bytes([query[end_pos + 8], query[end_pos + 9]]) as usize;
                end_pos.saturating_add(10).saturating_add(rdlen)
            }
            Err(_) => query.len(),
        }
    }
}

/// A pre-protocol refusal: the response rcode travels with the reason so the
/// dispatcher answers instead of silently dropping the message.
#[derive(Debug, Clone)]
pub struct UpdateDenied {
    pub rcode: u8,
    pub message: String,
}

impl UpdateDenied {
    pub fn new(rcode: u8, message: impl Into<String>) -> Self {
        Self {
            rcode,
            message: message.into(),
        }
    }

    pub fn refused(message: impl Into<String>) -> Self {
        Self::new(wire::UPDATE_RCODE_REFUSED, message)
    }

    pub fn formerr(message: impl Into<String>) -> Self {
        Self::new(wire::UPDATE_RCODE_FORMERR, message)
    }
}

impl fmt::Display for UpdateDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for UpdateDenied {}

/// The result of applying one UPDATE to one zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UpdateOutcome {
    rcode: u8,
    changed: bool,
}

pub struct DynamicUpdateHandler {
    zones: Arc<ShardedZoneStore>,
    enabled: bool,
    allow_any: bool,
    require_tsig: bool,
    tsig_verifier: Option<Arc<TsigVerifier>>,
    /// Permit DNSKEY/RRSIG/NSEC/NSEC3 writes. Off by default: a dynamic
    /// update must not be able to forge the zone's signed state.
    allow_dnssec_writes: bool,
    allowed_ips: Vec<String>,
    cache: Option<Arc<crate::DnsCache>>,
    /// Maximum size in bytes for an UPDATE message. Prevents abuse.
    max_update_size: usize,
    /// Counter for updates received.
    updates_received: AtomicU64,
    /// Counter for updates accepted.
    updates_accepted: AtomicU64,
    /// Counter for updates rejected.
    updates_rejected: AtomicU64,
    #[cfg(feature = "mesh")]
    zone_sync: Option<Arc<crate::anycast_sync::AnycastZoneSync>>,
}

impl Clone for DynamicUpdateHandler {
    fn clone(&self) -> Self {
        Self {
            zones: self.zones.clone(),
            enabled: self.enabled,
            allow_any: self.allow_any,
            require_tsig: self.require_tsig,
            tsig_verifier: self.tsig_verifier.clone(),
            allow_dnssec_writes: self.allow_dnssec_writes,
            allowed_ips: self.allowed_ips.clone(),
            cache: self.cache.clone(),
            max_update_size: self.max_update_size,
            updates_received: AtomicU64::new(self.updates_received.load(Ordering::Relaxed)),
            updates_accepted: AtomicU64::new(self.updates_accepted.load(Ordering::Relaxed)),
            updates_rejected: AtomicU64::new(self.updates_rejected.load(Ordering::Relaxed)),
            #[cfg(feature = "mesh")]
            zone_sync: self.zone_sync.clone(),
        }
    }
}

impl DynamicUpdateHandler {
    pub fn new(zones: Arc<ShardedZoneStore>) -> Self {
        Self {
            zones,
            enabled: false,
            allow_any: false,
            require_tsig: true,
            tsig_verifier: None,
            allow_dnssec_writes: false,
            allowed_ips: Vec::new(),
            cache: None,
            max_update_size: 4096,
            updates_received: AtomicU64::new(0),
            updates_accepted: AtomicU64::new(0),
            updates_rejected: AtomicU64::new(0),
            #[cfg(feature = "mesh")]
            zone_sync: None,
        }
    }

    /// Enable the handler.
    ///
    /// `require_tsig` without a verifier would accept any client that sends a
    /// TSIG-shaped header (D19), so the combination is refused at
    /// construction. Attach the verifier first with [`Self::with_tsig_verifier`]
    /// or use [`Self::with_security_config`].
    pub fn with_config(
        mut self,
        enabled: bool,
        allow_any: bool,
        require_tsig: bool,
    ) -> Result<Self, String> {
        if require_tsig && self.tsig_verifier.is_none() {
            return Err(
                "dynamic update requires TSIG but no TSIG verifier is configured; \
                 refusing to construct a handler that cannot authenticate"
                    .to_string(),
            );
        }
        self.enabled = enabled;
        self.allow_any = allow_any;
        self.require_tsig = require_tsig;
        Ok(self)
    }

    /// Full construction: policy plus the verifier it depends on.
    pub fn with_security_config(
        self,
        enabled: bool,
        allow_any: bool,
        require_tsig: bool,
        verifier: Option<Arc<TsigVerifier>>,
    ) -> Result<Self, String> {
        let mut handler = self;
        if let Some(verifier) = verifier {
            handler.tsig_verifier = Some(verifier);
        }
        handler.with_config(enabled, allow_any, require_tsig)
    }

    pub fn with_tsig_verifier(mut self, verifier: Arc<TsigVerifier>) -> Self {
        self.tsig_verifier = Some(verifier);
        self
    }

    /// Explicitly allow DNSKEY/RRSIG/NSEC/NSEC3 writes in dynamic updates.
    pub fn with_dnssec_writes(mut self, allow: bool) -> Self {
        self.allow_dnssec_writes = allow;
        self
    }

    pub fn with_allowed_ips(mut self, allowed_ips: Vec<String>) -> Self {
        self.allowed_ips = allowed_ips;
        self
    }

    pub fn with_cache(mut self, cache: Arc<crate::DnsCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    pub fn with_max_update_size(mut self, max_size: usize) -> Self {
        self.max_update_size = max_size;
        self
    }

    #[cfg(feature = "mesh")]
    pub fn with_zone_sync(mut self, zone_sync: crate::anycast_sync::AnycastZoneSync) -> Self {
        self.zone_sync = Some(Arc::new(zone_sync));
        self
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn updates_received(&self) -> u64 {
        self.updates_received.load(Ordering::Relaxed)
    }

    pub fn updates_accepted(&self) -> u64 {
        self.updates_accepted.load(Ordering::Relaxed)
    }

    pub fn updates_rejected(&self) -> u64 {
        self.updates_rejected.load(Ordering::Relaxed)
    }

    fn is_ip_allowed(&self, client_ip: std::net::IpAddr) -> bool {
        if self.allowed_ips.is_empty() {
            return false;
        }

        for allowed in &self.allowed_ips {
            if allowed == "*" {
                return true;
            }
            if let Ok(cidr) = allowed.parse::<ipnetwork::IpNetwork>() {
                if cidr.contains(client_ip) {
                    return true;
                }
            }
        }

        false
    }

    /// Byte offset where the additional section begins.
    ///
    /// Every step is bounded by the message length: a declared count that
    /// walks past the packet is a malformed UPDATE, not an empty additional
    /// section. Returning an error here is what stops a truncated message
    /// from looking like an unsigned one.
    fn compute_additional_section_offset(
        &self,
        query: &[u8],
        qdcount: u16,
        ancount: u16,
        nscount: u16,
    ) -> Result<usize, String> {
        let mut pos = 12;
        for _ in 0..qdcount {
            if pos >= query.len() {
                return Err("UPDATE zone section runs past the message".to_string());
            }
            pos = super::DynamicUpdate::skip_question(query, pos);
            if pos > query.len() {
                return Err("UPDATE zone section runs past the message".to_string());
            }
        }
        for _ in 0..(ancount as u32 + nscount as u32) {
            if pos >= query.len() {
                return Err("UPDATE sections run past the message".to_string());
            }
            pos = super::DynamicUpdate::skip_rr_full(query, pos);
            if pos > query.len() {
                return Err("UPDATE sections run past the message".to_string());
            }
        }
        Ok(pos)
    }

    pub fn handle_update(
        &self,
        query: &[u8],
        client_ip: std::net::IpAddr,
    ) -> Result<Vec<u8>, UpdateDenied> {
        self.updates_received.fetch_add(1, Ordering::Relaxed);

        if !self.enabled {
            self.updates_rejected.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(client_ip = %client_ip, "UPDATE denied: not enabled");
            return Err(UpdateDenied::new(
                wire::UPDATE_RCODE_NOTIMP,
                "Dynamic updates not enabled",
            ));
        }

        if query.len() > self.max_update_size {
            self.updates_rejected.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                client_ip = %client_ip,
                message_size = %query.len(),
                max_size = %self.max_update_size,
                "UPDATE denied: message too large"
            );
            return Err(UpdateDenied::formerr("Update message too large"));
        }

        // Cheap authorization before any parsing or HMAC work.
        if !self.allow_any && !self.is_ip_allowed(client_ip) {
            self.updates_rejected.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                client_ip = %client_ip,
                "UPDATE denied: client IP not in allowed list"
            );
            return Err(UpdateDenied::refused(
                "Dynamic updates not allowed from this IP",
            ));
        }

        let qdcount = u16::from_be_bytes([query[4], query[5]]);
        let ancount = u16::from_be_bytes([query[6], query[7]]);
        let nscount = u16::from_be_bytes([query[8], query[9]]);

        let additional_offset = self
            .compute_additional_section_offset(query, qdcount, ancount, nscount)
            .map_err(|e| {
                self.updates_rejected.fetch_add(1, Ordering::Relaxed);
                UpdateDenied::formerr(e)
            })?;

        // Presence implies verification: a TSIG that is present is verified
        // even when `require_tsig` is false, and a verification failure is
        // REFUSED rather than an unsigned fallback.
        let tsig = parse_tsig_from_query(query, additional_offset).map_err(|e| {
            self.updates_rejected.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(client_ip = %client_ip, error = %e, "UPDATE denied: malformed TSIG");
            UpdateDenied::formerr(format!("Malformed TSIG: {e}"))
        })?;

        match tsig {
            Some(tsig) => {
                let verifier = self.tsig_verifier.as_ref().ok_or_else(|| {
                    self.updates_rejected.fetch_add(1, Ordering::Relaxed);
                    UpdateDenied::refused(
                        "TSIG is present but no verifier is configured; refusing to \
                         treat presence as authentication",
                    )
                })?;
                if let Err(e) = verifier.verify(query, &tsig) {
                    self.updates_rejected.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        client_ip = %client_ip,
                        error = %e,
                        "UPDATE denied: TSIG verification failed"
                    );
                    return Err(UpdateDenied::refused(format!(
                        "TSIG verification failed: {e}"
                    )));
                }
            }
            None if self.require_tsig => {
                self.updates_rejected.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    client_ip = %client_ip,
                    "UPDATE denied: TSIG required but not present"
                );
                return Err(UpdateDenied::refused(
                    "Dynamic updates require TSIG authentication",
                ));
            }
            None => {}
        }

        let update = DynamicUpdate::parse(query).map_err(|e| {
            self.updates_rejected.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(client_ip = %client_ip, error = %e, "UPDATE rejected: malformed message");
            UpdateDenied::formerr(e)
        })?;

        let zone = update
            .zone
            .as_ref()
            .ok_or_else(|| UpdateDenied::formerr("No zone in UPDATE"))?;

        let zone_origin = zone.name.trim_end_matches('.').to_ascii_lowercase();

        // RFC 2136 §3.1: a non-IN zone class is not an authoritative zone
        // this server can update.
        if zone.class != CLASS_IN {
            self.updates_rejected.fetch_add(1, Ordering::Relaxed);
            return Ok(self.build_response(query, wire::UPDATE_RCODE_NOTAUTH));
        }

        if !self.zones.contains_key(&zone_origin) {
            self.updates_rejected.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                zone = %zone_origin,
                client_ip = %client_ip,
                "UPDATE rejected: zone not found"
            );
            return Ok(self.build_response(query, wire::UPDATE_RCODE_NOTAUTH));
        }

        tracing::info!(
            zone = %zone_origin,
            client_ip = %client_ip,
            prerequisite_count = %update.prerequisites.len(),
            update_count = %update.updates.len(),
            "UPDATE request received"
        );

        // Prerequisites, mutation, validation, and the commit all happen
        // under the zone's write lock: two concurrent updates serialize on
        // the zone writer instead of last-write-wins on a clone (R5).
        let mut outcome: Option<Result<UpdateOutcome, UpdateDenied>> = None;
        self.zones.update_zone(&zone_origin, |live| {
            outcome = Some(Self::apply_update(
                live,
                &update,
                &zone_origin,
                zone.class,
                query,
                self.allow_dnssec_writes,
            ));
        });

        let outcome = match outcome {
            Some(result) => result?,
            None => {
                // The zone disappeared between the existence check and the
                // writer.
                self.updates_rejected.fetch_add(1, Ordering::Relaxed);
                return Ok(self.build_response(query, wire::UPDATE_RCODE_NOTAUTH));
            }
        };

        if outcome.rcode != wire::UPDATE_RCODE_NOERROR {
            self.updates_rejected.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                zone = %zone_origin,
                client_ip = %client_ip,
                rcode = %outcome.rcode,
                "UPDATE rejected"
            );
            return Ok(self.build_response(query, outcome.rcode));
        }

        if outcome.changed {
            // The committed zone is already rebuilt and validated inside the
            // writer. Cache invalidation follows so no pre-update answer
            // survives the commit.
            if let Some(ref cache) = self.cache {
                cache.invalidate_zone(
                    &zone_origin,
                    crate::cache::InvalidationReason::DynamicUpdate,
                );
            }

            #[cfg(feature = "mesh")]
            if let Some(ref sync) = self.zone_sync {
                let zone_origin_for_sync = zone_origin.clone();
                let sync_clone = sync.clone();
                tokio::spawn(async move {
                    if let Err(e) = sync_clone
                        .trigger_sync(
                            &zone_origin_for_sync,
                            crate::anycast_sync::ZoneSyncReason::DynamicUpdate,
                        )
                        .await
                    {
                        tracing::warn!(zone = %zone_origin_for_sync, error = %e, "Zone sync after UPDATE failed");
                    }
                });
            }
        }

        self.updates_accepted.fetch_add(1, Ordering::Relaxed);
        tracing::info!(
            zone = %zone_origin,
            client_ip = %client_ip,
            prerequisite_count = %update.prerequisites.len(),
            update_count = %update.updates.len(),
            "UPDATE accepted"
        );
        Ok(self.build_response(query, wire::UPDATE_RCODE_NOERROR))
    }

    /// Apply prerequisites and updates to one zone.
    ///
    /// Runs under the zone write lock. All work happens on a clone; `live` is
    /// assigned only after the whole transaction validates, so a failure at
    /// any point leaves the zone byte-for-byte unchanged.
    fn apply_update(
        live: &mut Zone,
        update: &DynamicUpdate,
        origin: &str,
        zone_class: u16,
        message: &[u8],
        allow_dnssec_writes: bool,
    ) -> Result<UpdateOutcome, UpdateDenied> {
        let mut updated = live.clone();

        match Self::check_prerequisites(&updated, update, origin, zone_class, message)? {
            None => {}
            Some(rcode) => {
                return Ok(UpdateOutcome {
                    rcode,
                    changed: false,
                })
            }
        }

        let mut changed = false;
        let mut soa_serial: Option<u32> = None;

        for record in &update.updates {
            let owner = super::server::DnsServer::normalize_record_name(origin, &record.name)
                .map_err(|e| UpdateDenied::new(wire::UPDATE_RCODE_NOTZONE, e))?;

            // Prescan (RFC 2136 §3.4.1.2).
            match record.rclass {
                CLASS_IN => {
                    if query_metatype(record.rtype) {
                        return Err(UpdateDenied::formerr(
                            "Add RR with a query metatype is not allowed",
                        ));
                    }
                    if dnssec_record_type(record.rtype) && !allow_dnssec_writes {
                        return Err(UpdateDenied::refused(
                            "Dynamic updates may not rewrite DNSSEC records",
                        ));
                    }
                    if !update_supported_type(record.rtype) {
                        return Err(UpdateDenied::formerr(
                            "RDATA type cannot be stored by this server",
                        ));
                    }
                }
                CLASS_ANY => {
                    if record.ttl != 0 || !record.rdata.is_empty() || record.rtype == TYPE_AXFR {
                        return Err(UpdateDenied::formerr(
                            "Delete RRset requires TTL 0 and empty RDATA",
                        ));
                    }
                }
                CLASS_NONE => {
                    if record.ttl != 0
                        || record.rtype == TYPE_ANY
                        || query_metatype(record.rtype)
                        || !update_supported_type(record.rtype)
                    {
                        return Err(UpdateDenied::formerr(
                            "Delete RR requires TTL 0 and a concrete supported type",
                        ));
                    }
                    if dnssec_record_type(record.rtype) && !allow_dnssec_writes {
                        return Err(UpdateDenied::refused(
                            "Dynamic updates may not rewrite DNSSEC records",
                        ));
                    }
                }
                _ => {
                    return Err(UpdateDenied::formerr(
                        "Update RR class must be the zone class, ANY, or NONE",
                    ))
                }
            }

            let record_type = RecordType::from(record.rtype);

            match record.rclass {
                CLASS_IN => {
                    let Some((value, priority)) =
                        Self::present_value(record.rtype, &record.rdata, message)
                    else {
                        return Err(UpdateDenied::formerr(
                            "Update RDATA could not be decoded for its type",
                        ));
                    };

                    // RFC 2136 §3.4.2.2: CNAME and other data do not coexist.
                    // The conflicting update RR is ignored, not the request.
                    if record.rtype == TYPE_CNAME {
                        if updated
                            .records
                            .keys()
                            .any(|(name, rtype)| name == &owner && *rtype != RecordType::CNAME)
                        {
                            continue;
                        }
                    } else if updated
                        .records
                        .contains_key(&(owner.clone(), RecordType::CNAME))
                    {
                        continue;
                    }

                    // RFC 2136 §3.4.2.2: an SOA add with serial <= the
                    // current zone serial is ignored.
                    if record.rtype == TYPE_SOA {
                        if owner != "@" {
                            continue;
                        }
                        let Some(new_serial) = Self::soa_serial(&value) else {
                            return Err(UpdateDenied::formerr("SOA RDATA is malformed"));
                        };
                        if !Zone::serial_is_more_recent(new_serial, updated.serial) {
                            continue;
                        }
                        soa_serial = Some(new_serial);
                    }

                    let new_record = DnsZoneRecord {
                        name: owner.clone(),
                        record_type,
                        value,
                        ttl: record.ttl,
                        priority,
                    };

                    let rdata = super::server::rdata_wire(&new_record)
                        .map_err(|_| UpdateDenied::formerr("Update RDATA could not be encoded"))?;
                    let rrset = updated
                        .records
                        .entry((owner.clone(), record_type))
                        .or_default();
                    match rrset.iter().position(|existing| {
                        super::server::rdata_wire(existing)
                            .map(|bytes| bytes == rdata)
                            .unwrap_or(false)
                    }) {
                        Some(index) => rrset[index] = new_record,
                        None => {
                            if record.rtype == TYPE_SOA {
                                rrset.clear();
                            }
                            rrset.push(new_record);
                        }
                    }
                    changed = true;
                }
                CLASS_ANY => {
                    if record.rtype == TYPE_ANY {
                        // Delete all RRsets from a name. At the apex, SOA and
                        // NS survive (RFC 2136 §3.4.2.3).
                        let keys: Vec<(String, RecordType)> = updated
                            .records
                            .keys()
                            .filter(|(name, rtype)| {
                                name == &owner
                                    && !(owner == "@"
                                        && matches!(*rtype, RecordType::SOA | RecordType::NS))
                            })
                            .cloned()
                            .collect();
                        for key in keys {
                            updated.records.remove(&key);
                            changed = true;
                        }
                    } else {
                        if owner == "@" && matches!(record_type, RecordType::SOA | RecordType::NS) {
                            continue;
                        }
                        if updated
                            .records
                            .remove(&(owner.clone(), record_type))
                            .is_some()
                        {
                            changed = true;
                        }
                    }
                }
                CLASS_NONE => {
                    let key = (owner.clone(), record_type);
                    let Some(rrset) = updated.records.get_mut(&key) else {
                        continue;
                    };
                    let target = Self::canonical_rdata(record.rtype, &record.rdata, message)
                        .ok_or_else(|| {
                            UpdateDenied::formerr("Delete RDATA could not be decoded")
                        })?;
                    let position = rrset.iter().position(|existing| {
                        super::server::rdata_wire(existing)
                            .map(|bytes| bytes == target)
                            .unwrap_or(false)
                    });
                    let Some(index) = position else {
                        continue;
                    };
                    // RFC 2136 §3.4.2.4: the apex SOA and the last apex NS
                    // survive.
                    if owner == "@" {
                        if record.rtype == TYPE_SOA {
                            continue;
                        }
                        if record.rtype == TYPE_NS && rrset.len() <= 1 {
                            continue;
                        }
                    }
                    rrset.remove(index);
                    if rrset.is_empty() {
                        updated.records.remove(&key);
                    }
                    changed = true;
                }
                _ => unreachable!("class validated above"),
            }
        }

        if !changed {
            return Ok(UpdateOutcome {
                rcode: wire::UPDATE_RCODE_NOERROR,
                changed: false,
            });
        }

        // One commit through the single zone-state writer (phase 09 R2):
        // normalize, deduplicate, journal the pre-update snapshot, bump the
        // serial, write it into the SOA, and rebuild the owner index and
        // denial chains. A client-supplied SOA serial wins (RFC 2136 §3.4.1).
        let records = std::mem::take(&mut updated.records);
        if let Err(reason) = updated.commit_records(records, SerialPolicy::Bump) {
            tracing::error!(
                zone = %origin,
                reason = %reason,
                "UPDATE commit rejected: the record set is invalid"
            );
            return Ok(UpdateOutcome {
                rcode: wire::UPDATE_RCODE_NOTAUTH,
                changed: false,
            });
        }
        if let Some(serial) = soa_serial {
            updated.set_serial_and_sync_soa(serial);
        }

        if let Err(e) = updated.validate_zone_for_activation() {
            tracing::error!(
                zone = %origin,
                error = %e,
                "UPDATE post-mutation validation failed"
            );
            return Ok(UpdateOutcome {
                rcode: wire::UPDATE_RCODE_NOTAUTH,
                changed: false,
            });
        }

        *live = updated;
        Ok(UpdateOutcome {
            rcode: wire::UPDATE_RCODE_NOERROR,
            changed: true,
        })
    }

    /// Evaluate the prerequisite section against the current zone.
    ///
    /// `None` means every prerequisite held; `Some(rcode)` is the RFC 2136
    /// §3.2.5 failure code.
    fn check_prerequisites(
        zone: &Zone,
        update: &DynamicUpdate,
        origin: &str,
        zone_class: u16,
        message: &[u8],
    ) -> Result<Option<u8>, UpdateDenied> {
        let mut value_dependent: HashMap<(String, u16), BTreeSet<Vec<u8>>> = HashMap::new();

        for prerequisite in &update.prerequisites {
            let owner = super::server::DnsServer::normalize_record_name(origin, &prerequisite.name)
                .map_err(|e| UpdateDenied::new(wire::UPDATE_RCODE_NOTZONE, e))?;

            // RFC 2136 §3.2.5: every prerequisite carries TTL 0.
            if prerequisite.ttl != 0 {
                return Err(UpdateDenied::formerr("Prerequisite TTL must be zero"));
            }

            match prerequisite.rclass {
                CLASS_ANY => {
                    if !prerequisite.rdata.is_empty() {
                        return Err(UpdateDenied::formerr(
                            "Value-independent prerequisite must have empty RDATA",
                        ));
                    }
                    if prerequisite.rtype == TYPE_ANY {
                        if !Self::name_in_use(zone, &owner) {
                            return Ok(Some(wire::UPDATE_RCODE_NXDOMAIN));
                        }
                    } else if !zone
                        .records
                        .contains_key(&(owner, RecordType::from(prerequisite.rtype)))
                    {
                        return Ok(Some(wire::UPDATE_RCODE_NXRRSET));
                    }
                }
                CLASS_NONE => {
                    if !prerequisite.rdata.is_empty() {
                        return Err(UpdateDenied::formerr(
                            "Value-independent prerequisite must have empty RDATA",
                        ));
                    }
                    if prerequisite.rtype == TYPE_ANY {
                        if Self::name_in_use(zone, &owner) {
                            return Ok(Some(wire::UPDATE_RCODE_YXDOMAIN));
                        }
                    } else if zone
                        .records
                        .contains_key(&(owner, RecordType::from(prerequisite.rtype)))
                    {
                        return Ok(Some(wire::UPDATE_RCODE_YXRRSET));
                    }
                }
                class if class == zone_class => {
                    if prerequisite.rtype == TYPE_ANY {
                        return Err(UpdateDenied::formerr(
                            "Value-dependent prerequisite must name a concrete type",
                        ));
                    }
                    let canonical =
                        Self::canonical_rdata(prerequisite.rtype, &prerequisite.rdata, message)
                            .ok_or_else(|| {
                                UpdateDenied::formerr(
                                    "Prerequisite RDATA could not be decoded for its type",
                                )
                            })?;
                    value_dependent
                        .entry((owner, prerequisite.rtype))
                        .or_default()
                        .insert(canonical);
                }
                _ => {
                    return Err(UpdateDenied::formerr(
                        "Prerequisite class must be ANY, NONE, or the zone class",
                    ))
                }
            }
        }

        // RFC 2136 §3.2.3: the prerequisite RRset must equal the zone RRset
        // exactly (same members, no more, no less), compared on canonical
        // wire RDATA with TTL ignored.
        for ((owner, rtype), expected) in value_dependent {
            let mut actual = BTreeSet::new();
            if let Some(records) = zone.records.get(&(owner, RecordType::from(rtype))) {
                for record in records {
                    if let Ok(bytes) = super::server::rdata_wire(record) {
                        actual.insert(bytes);
                    }
                }
            }
            if actual != expected {
                return Ok(Some(wire::UPDATE_RCODE_NXRRSET));
            }
        }

        Ok(None)
    }

    fn name_in_use(zone: &Zone, owner: &str) -> bool {
        zone.records
            .iter()
            .any(|((name, _), records)| name == owner && !records.is_empty())
    }

    fn soa_serial(value: &str) -> Option<u32> {
        value.split_whitespace().nth(2)?.parse().ok()
    }

    /// RFC 2136 §3.4.2.4 compares RDATA bytes; compression does not change
    /// meaning, so the request's RDATA is normalised to the canonical wire
    /// form the store serves.
    fn canonical_rdata(rtype: u16, rdata: &[u8], message: &[u8]) -> Option<Vec<u8>> {
        match rtype {
            2 | 5 | 12 => Self::canonical_name_rdata(rdata, message),
            15 => {
                if rdata.len() < 3 {
                    return None;
                }
                let priority = &rdata[..2];
                let name = Self::canonical_name_rdata(&rdata[2..], message)?;
                let mut out = priority.to_vec();
                out.extend_from_slice(&name);
                Some(out)
            }
            6 => {
                let (mname, used) = Self::decode_name(rdata, 0, message)?;
                let (rname, rname_used) = Self::decode_name(rdata, used, message)?;
                let tail_start = rname_used;
                if rdata.len() < tail_start + 20 {
                    return None;
                }
                let mut out = super::tsig::encode_canonical_name(&mname)?;
                out.extend_from_slice(&super::tsig::encode_canonical_name(&rname)?);
                out.extend_from_slice(&rdata[tail_start..tail_start + 20]);
                Some(out)
            }
            _ => Some(rdata.to_vec()),
        }
    }

    fn canonical_name_rdata(rdata: &[u8], message: &[u8]) -> Option<Vec<u8>> {
        let (name, _) = Self::decode_name(rdata, 0, message)?;
        super::tsig::encode_canonical_name(&name)
    }

    /// Decode one (possibly compressed) name inside `rdata`.
    ///
    /// Returns the presentation-form name and the offset just past it in
    /// `rdata`. Compression pointers are resolved against `message`.
    fn decode_name(rdata: &[u8], start: usize, message: &[u8]) -> Option<(String, usize)> {
        let mut name = String::new();
        let mut pos = start;
        let mut end_in_rdata: Option<usize> = None;
        let mut base = rdata;
        let mut jumps = 0;

        loop {
            let len = *base.get(pos)? as usize;
            if len == 0 {
                pos += 1;
                if end_in_rdata.is_none() {
                    end_in_rdata = Some(pos);
                }
                return Some((name, end_in_rdata.unwrap_or(pos)));
            }
            if (len & 0xC0) == 0xC0 {
                jumps += 1;
                if jumps > 10 {
                    return None;
                }
                let second = *base.get(pos + 1)? as usize;
                let offset = ((len & 0x3F) << 8) | second;
                if end_in_rdata.is_none() {
                    end_in_rdata = Some(pos + 2);
                }
                if offset >= message.len() {
                    return None;
                }
                base = message;
                pos = offset;
                continue;
            }
            if len > 63 {
                return None;
            }
            let label_start = pos + 1;
            let label_end = label_start.checked_add(len)?;
            let label = base.get(label_start..label_end)?;
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(&String::from_utf8_lossy(label));
            pos = label_end;
        }
    }

    /// Presentation-form `(value, priority)` for an RDATA body the store can
    /// serve. `None` means the type or its bytes are unsupported.
    fn present_value(rtype: u16, rdata: &[u8], message: &[u8]) -> Option<(String, Option<u32>)> {
        match rtype {
            1 => {
                if rdata.len() != 4 {
                    return None;
                }
                Some((
                    format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3]),
                    None,
                ))
            }
            28 => {
                if rdata.len() != 16 {
                    return None;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                Some((std::net::Ipv6Addr::from(octets).to_string(), None))
            }
            2 | 5 | 12 => {
                let (name, _) = Self::decode_name(rdata, 0, message)?;
                Some((name.to_ascii_lowercase(), None))
            }
            16 => {
                let mut value = String::new();
                let mut pos = 0;
                while pos < rdata.len() {
                    let len = rdata[pos] as usize;
                    pos += 1;
                    let chunk = rdata.get(pos..pos + len)?;
                    value.push_str(&String::from_utf8_lossy(chunk));
                    pos += len;
                }
                Some((value, None))
            }
            15 => {
                if rdata.len() < 3 {
                    return None;
                }
                let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
                let (name, _) = Self::decode_name(&rdata[2..], 0, message)?;
                Some((name.to_ascii_lowercase(), Some(u32::from(priority))))
            }
            6 => {
                let (mname, used) = Self::decode_name(rdata, 0, message)?;
                let (rname, rname_used) = Self::decode_name(rdata, used, message)?;
                if rdata.len() < rname_used + 20 {
                    return None;
                }
                let mut tail = rname_used;
                let mut numbers = Vec::with_capacity(5);
                for _ in 0..5 {
                    let bytes = rdata.get(tail..tail + 4)?;
                    numbers.push(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
                    tail += 4;
                }
                Some((
                    format!(
                        "{} {} {} {} {} {} {}",
                        mname, rname, numbers[0], numbers[1], numbers[2], numbers[3], numbers[4]
                    ),
                    None,
                ))
            }
            43 => Some((hex::encode(rdata), None)),
            257 => {
                if rdata.len() < 2 {
                    return None;
                }
                let flags = rdata[0];
                let tag_len = rdata[1] as usize;
                let tag = rdata.get(2..2 + tag_len)?;
                let value = rdata.get(2 + tag_len..)?;
                if !tag.is_ascii() || std::str::from_utf8(value).is_err() {
                    return None;
                }
                Some((
                    format!(
                        "{} {} {}",
                        flags,
                        String::from_utf8_lossy(tag),
                        String::from_utf8_lossy(value)
                    ),
                    None,
                ))
            }
            _ => None,
        }
    }

    fn build_response(&self, query: &[u8], rcode: u8) -> Vec<u8> {
        let parsed = match crate::parsed_query::ParsedDnsQuery::parse(query) {
            Ok(p) => p,
            Err(_) => return Vec::new(),
        };

        let id = parsed.id;

        // UPDATE responses: QR=1, AA=1, RA=0, opcode=UPDATE
        let flags = crate::parsed_query::build_response_flags_from_query(
            &parsed, true,  // authoritative
            false, // truncated
            false, // recursion_available
            false, // authentic_data
            rcode,
        );

        let mut response = Vec::with_capacity(12);
        response.extend_from_slice(&id.to_be_bytes());
        response.extend_from_slice(&flags.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT
        response.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_opcode_constants() {
        assert_eq!(wire::OPCODE_UPDATE, 5);
        assert_eq!(wire::UPDATE_RCODE_YXDOMAIN, 6);
        assert_eq!(wire::UPDATE_RCODE_YXRRSET, 7);
    }

    #[test]
    fn test_update_handler_metrics_initial() {
        let zones = Arc::new(ShardedZoneStore::new());
        let handler = DynamicUpdateHandler::new(zones);
        assert_eq!(handler.updates_received(), 0);
        assert_eq!(handler.updates_accepted(), 0);
        assert_eq!(handler.updates_rejected(), 0);
    }

    #[test]
    fn test_update_handler_disabled_rejects() {
        let zones = Arc::new(ShardedZoneStore::new());
        let handler = DynamicUpdateHandler::new(zones);
        // handler is disabled by default
        let result = handler.handle_update(&[0u8; 12], "127.0.0.1".parse().unwrap());
        assert!(result.is_err());
        assert_eq!(handler.updates_received(), 1);
        assert_eq!(handler.updates_rejected(), 1);
        assert_eq!(handler.updates_accepted(), 0);
    }

    #[test]
    fn test_update_handler_max_size_rejects() {
        let zones = Arc::new(ShardedZoneStore::new());
        let handler = DynamicUpdateHandler::new(zones)
            .with_config(true, true, false)
            .expect("no TSIG required")
            .with_max_update_size(100);
        // Create a query larger than 100 bytes
        let big_query = vec![0u8; 200];
        let result = handler.handle_update(&big_query, "127.0.0.1".parse().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
        assert_eq!(handler.updates_received(), 1);
        assert_eq!(handler.updates_rejected(), 1);
    }

    #[test]
    fn test_update_handler_ip_not_allowed() {
        let zones = Arc::new(ShardedZoneStore::new());
        let handler = DynamicUpdateHandler::new(zones)
            .with_config(true, false, false)
            .expect("no TSIG required")
            .with_allowed_ips(vec!["10.0.0.1".to_string()]);
        let result = handler.handle_update(&[0u8; 12], "127.0.0.1".parse().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not allowed"));
        assert_eq!(handler.updates_rejected(), 1);
    }

    #[test]
    fn require_tsig_without_a_verifier_fails_construction() {
        let zones = Arc::new(ShardedZoneStore::new());
        let result = DynamicUpdateHandler::new(zones).with_config(true, true, true);
        let error = result
            .err()
            .expect("require_tsig without a verifier must not construct");
        assert!(error.contains("TSIG"));
    }
}
