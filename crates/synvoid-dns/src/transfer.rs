use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use crate::parsed_query::build_response_flags;
use crate::server::{DnsZoneRecord, RecordType, RecordTypeExt, ShardedZoneStore, Zone};
use crate::tsig::{SignedTsig, TsigParseResult, TsigVerifier};
use crate::wire;

use crate::cache::InvalidationReason;

pub const AXFR_QUERY_TYPE: u16 = 252;
pub const IXFR_QUERY_TYPE: u16 = 251;

/// Default ceiling on the bytes one transfer may put on the wire.
///
/// A transfer is built from memory and written to one connection, so an
/// unbounded zone is an unbounded allocation and an unbounded write. The cap
/// applies per zone (what one request may serialize) and per connection (the
/// signed messages actually written).
pub const DEFAULT_MAX_TRANSFER_BYTES: usize = 16 * 1024 * 1024;

/// RFC 1982 serial arithmetic: returns true when `a` is strictly newer than
/// `b`, accounting for u32 wraparound. Differences >= 2^31 are ambiguous and
/// treated as "not newer".
fn serial_is_newer(a: u32, b: u32) -> bool {
    let delta = a.wrapping_sub(b);
    delta != 0 && delta < 0x8000_0000
}

/// Per-zone transfer authorization.
///
/// A client is authorized when a CIDR matches its address **and** a zone
/// entry matches the requested origin **and** the configured key (if any)
/// matches the verified TSIG key. The three are joint conditions: an IP entry
/// alone no longer authorizes every zone, and a zone entry alone no longer
/// authorizes every client (D20).
///
/// An empty `zones` list means "all zones"; an empty `cidrs` list means
/// "no client" (fail closed), because a transfer without a network match has
/// no one to authorize.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransferAcl {
    pub cidrs: Vec<ipnetwork::IpNetwork>,
    pub zones: Vec<String>,
    pub key: Option<String>,
    /// A `"*"` entry was configured. Whether that is honoured is the separate
    /// `allow_wildcard_transfer` policy bit.
    pub wildcard: bool,
}

impl TransferAcl {
    pub fn new(cidrs: Vec<ipnetwork::IpNetwork>, zones: Vec<String>, key: Option<String>) -> Self {
        Self {
            cidrs,
            zones,
            key,
            wildcard: false,
        }
    }

    pub fn with_wildcard(mut self, wildcard: bool) -> Self {
        self.wildcard = wildcard;
        self
    }

    /// Build from the flat `dns.settings.allow_transfer` entry list.
    ///
    /// The persisted surface is one list, so each entry is classified once:
    /// `*` requests the wildcard, anything that parses as an address/network
    /// is a CIDR, and everything else is a zone name. A zone entry is a zone
    /// name, never a synonym for "any client in any zone".
    pub fn from_entries(entries: &[String]) -> Self {
        let mut acl = Self::default();
        for entry in entries {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            if entry == "*" {
                acl.wildcard = true;
                continue;
            }
            if let Ok(network) = entry.parse::<ipnetwork::IpNetwork>() {
                acl.cidrs.push(network);
                continue;
            }
            acl.zones
                .push(entry.trim_end_matches('.').to_ascii_lowercase());
        }
        acl
    }

    /// True when the client's address is covered by a configured network.
    pub fn network_matches(&self, client_ip: IpAddr) -> bool {
        self.cidrs.iter().any(|cidr| cidr.contains(client_ip))
    }

    /// True when the origin is covered by the zone list (empty = all zones).
    pub fn zone_matches(&self, origin: &str) -> bool {
        if self.zones.is_empty() {
            return true;
        }
        let origin = origin.trim_end_matches('.').to_ascii_lowercase();
        self.zones.contains(&origin)
    }

    /// True when the verified key satisfies the key binding.
    pub fn key_matches(&self, verified_key: Option<&str>) -> bool {
        match &self.key {
            None => true,
            Some(required) => {
                verified_key.is_some_and(|key| key.eq_ignore_ascii_case(required.as_str()))
            }
        }
    }

    /// Joint authorization: network, zone, and key must all match.
    pub fn authorizes(&self, client_ip: IpAddr, origin: &str, verified_key: Option<&str>) -> bool {
        self.network_matches(client_ip)
            && self.zone_matches(origin)
            && self.key_matches(verified_key)
    }
}

/// A refused or failed transfer, with the RCODE the client must receive.
///
/// A handler that returns a bare string cannot tell the dispatcher whether to
/// answer REFUSED, NOTAUTH, or FORMERR, so the dispatcher used to drop the
/// connection instead. The rcode travels with the reason now.
#[derive(Debug, Clone)]
pub struct TransferError {
    pub rcode: u8,
    pub message: String,
}

impl TransferError {
    pub fn new(rcode: u8, message: impl Into<String>) -> Self {
        Self {
            rcode,
            message: message.into(),
        }
    }

    pub fn refused(message: impl Into<String>) -> Self {
        Self::new(wire::RCODE_REFUSED, message)
    }

    pub fn notauth(message: impl Into<String>) -> Self {
        Self::new(wire::UPDATE_RCODE_NOTAUTH, message)
    }

    pub fn servfail(message: impl Into<String>) -> Self {
        Self::new(wire::RCODE_SERVFAIL, message)
    }
}

impl fmt::Display for TransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for TransferError {}

pub struct ZoneTransfer {
    zones: Arc<ShardedZoneStore>,
    acl: TransferAcl,
    tsig_verifier: Option<Arc<TsigVerifier>>,
    allow_wildcard_transfer: bool,
    wildcard_transfer_requires_tsig: bool,
    require_tsig: bool,
    ixfr_enabled: bool,
    ixfr_fallback_to_axfr: bool,
    /// AXFR is disabled by default for security.
    axfr_enabled: bool,
    /// AXFR requires TCP transport.
    tcp_only: bool,
    /// Maximum number of IXFR history entries per zone.
    max_history_size: usize,
    /// Bytes one request may serialize.
    max_zone_transfer_bytes: usize,
    /// Bytes one connection may carry.
    max_transfer_bytes: usize,
    cache: Option<Arc<crate::DnsCache>>,
}

impl ZoneTransfer {
    pub fn new(
        zones: Arc<ShardedZoneStore>,
        allowed_transfers: Vec<String>,
        tsig_verifier: Option<Arc<TsigVerifier>>,
    ) -> Self {
        Self {
            zones,
            acl: TransferAcl::from_entries(&allowed_transfers),
            tsig_verifier,
            allow_wildcard_transfer: false,
            wildcard_transfer_requires_tsig: true,
            require_tsig: true,
            ixfr_enabled: true,
            ixfr_fallback_to_axfr: true,
            axfr_enabled: false,
            tcp_only: true,
            max_history_size: 200,
            max_zone_transfer_bytes: DEFAULT_MAX_TRANSFER_BYTES,
            max_transfer_bytes: DEFAULT_MAX_TRANSFER_BYTES,
            cache: None,
        }
    }

    /// Build a transfer handler, refusing a configuration that cannot
    /// authenticate what it claims to.
    ///
    /// `require_tsig` without a verifier would accept any client that could
    /// forge a TSIG header (D19), so it is rejected here rather than at
    /// request time: the composition layer must fail startup.
    #[allow(clippy::too_many_arguments)]
    pub fn with_security_config(
        zones: Arc<ShardedZoneStore>,
        acl: TransferAcl,
        tsig_verifier: Option<Arc<TsigVerifier>>,
        allow_wildcard_transfer: bool,
        wildcard_transfer_requires_tsig: bool,
        ixfr_enabled: bool,
        ixfr_fallback_to_axfr: bool,
        require_tsig: bool,
        axfr_enabled: bool,
        tcp_only: bool,
    ) -> Result<Self, String> {
        if require_tsig && tsig_verifier.is_none() {
            return Err(
                "zone transfer requires TSIG but no TSIG verifier is configured; \
                 refusing to construct a handler that cannot authenticate"
                    .to_string(),
            );
        }

        if acl.wildcard && !allow_wildcard_transfer {
            tracing::warn!(
                "Zone transfer configuration contains wildcard which is disabled by default"
            );
        }

        if acl.wildcard && wildcard_transfer_requires_tsig {
            tracing::warn!("Zone transfer wildcard requires TSIG authentication");
        }

        Ok(Self {
            zones,
            acl,
            tsig_verifier,
            allow_wildcard_transfer,
            wildcard_transfer_requires_tsig,
            require_tsig,
            ixfr_enabled,
            ixfr_fallback_to_axfr,
            axfr_enabled,
            tcp_only,
            max_history_size: 200,
            max_zone_transfer_bytes: DEFAULT_MAX_TRANSFER_BYTES,
            max_transfer_bytes: DEFAULT_MAX_TRANSFER_BYTES,
            cache: None,
        })
    }

    pub fn with_cache(mut self, cache: Arc<crate::DnsCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    fn is_wildcard_allowed(&self) -> bool {
        self.allow_wildcard_transfer
    }

    fn wildcard_requires_tsig(&self) -> bool {
        self.wildcard_transfer_requires_tsig
    }

    pub fn is_axfr_enabled(&self) -> bool {
        self.axfr_enabled
    }

    /// Whether this handler will answer IXFR.
    ///
    /// Used by `/health` to report realization: a handler whose IXFR path is
    /// disabled must not be claimed as serving IXFR.
    pub fn is_ixfr_enabled(&self) -> bool {
        self.ixfr_enabled
    }

    pub fn is_tcp_only(&self) -> bool {
        self.tcp_only
    }

    pub fn with_max_history_size(mut self, max_size: usize) -> Self {
        self.max_history_size = max_size;
        self
    }

    /// Cap both the per-zone serialization and the per-connection write.
    pub fn with_max_transfer_bytes(mut self, max_bytes: usize) -> Self {
        self.max_zone_transfer_bytes = max_bytes;
        self.max_transfer_bytes = max_bytes;
        self
    }

    /// The cheap half of authorization: network and zone only.
    ///
    /// This runs before any TSIG parsing so a client that is not entitled to
    /// the zone never costs a HMAC (phase 03 R3, phase 07 R2).
    pub fn network_and_zone_allowed(&self, client_ip: IpAddr, origin: &str) -> bool {
        if self.acl.wildcard {
            return self.is_wildcard_allowed();
        }
        self.acl.network_matches(client_ip) && self.acl.zone_matches(origin)
    }

    /// Full authorization, including the verified key binding.
    ///
    /// `is_transfer_allowed` is the two-argument convenience for callers that
    /// have no TSIG (and is therefore false for an ACL that names a key).
    pub fn is_transfer_allowed(&self, client_ip: IpAddr, origin: &str) -> bool {
        self.is_transfer_allowed_with_key(client_ip, origin, None)
    }

    pub fn is_transfer_allowed_with_key(
        &self,
        client_ip: IpAddr,
        origin: &str,
        verified_key: Option<&str>,
    ) -> bool {
        if !self.network_and_zone_allowed(client_ip, origin) {
            return false;
        }
        self.acl.key_matches(verified_key)
    }

    pub fn is_wildcard_transfer(&self, _origin: &str) -> bool {
        self.acl.wildcard
    }

    pub fn acl(&self) -> &TransferAcl {
        &self.acl
    }

    /// Verify a request's TSIG.
    ///
    /// A message with a TSIG is always verified, even when `require_tsig` is
    /// false: accepting a signature without checking it is worse than not
    /// signing at all.
    pub fn verify_tsig(&self, tsig: &TsigParseResult, message: &[u8]) -> Result<(), TransferError> {
        let verifier = self.tsig_verifier.as_ref().ok_or_else(|| {
            TransferError::refused(
                "TSIG is present but no TSIG verifier is configured; refusing to \
                 treat presence as authentication",
            )
        })?;

        verifier.verify(message, tsig).map_err(|e| {
            tracing::warn!(error = %e, "TSIG verification failed");
            TransferError::refused(format!("TSIG verification failed: {e}"))
        })
    }

    /// Sign one response message, carrying `request_mac` (the request MAC for
    /// the first message, the previous message's MAC afterwards).
    pub fn sign_response(
        &self,
        key_name: &str,
        message: &[u8],
        request_mac: Option<&[u8]>,
    ) -> Result<SignedTsig, TransferError> {
        let verifier = self
            .tsig_verifier
            .as_ref()
            .ok_or_else(|| TransferError::refused("TSIG not configured"))?;

        verifier
            .sign_response(key_name, message, request_mac, 0)
            .map_err(|e| TransferError::servfail(format!("TSIG signing failed: {e}")))
    }

    /// Append the complete TSIG RR to a message and count it once.
    fn append_tsig_to_response(
        &self,
        mut response: Vec<u8>,
        key_name: &str,
        request_mac: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>), TransferError> {
        if response.len() < 12 {
            return Err(TransferError::servfail("Response too short for TSIG"));
        }

        let signed = self.sign_response(key_name, &response, request_mac)?;

        let arcount = u16::from_be_bytes([response[10], response[11]]);
        let new_arcount = arcount
            .checked_add(1)
            .ok_or_else(|| TransferError::servfail("TSIG ARCOUNT overflow"))?;
        response[10] = (new_arcount >> 8) as u8;
        response[11] = (new_arcount & 0xff) as u8;

        response.extend_from_slice(&signed.rr);
        Ok((response, signed.mac))
    }

    /// Sign a multi-message transfer.
    ///
    /// RFC 8945 §5.3.1: the first message is signed like any response (the
    /// request MAC is in the digest); every message after the first carries
    /// the previous message's MAC instead.
    fn sign_transfer_messages(
        &self,
        responses: Vec<Vec<u8>>,
        key_name: &str,
        request_mac: &[u8],
    ) -> Result<Vec<Vec<u8>>, TransferError> {
        let mut previous_mac = request_mac.to_vec();
        let mut signed_messages = Vec::with_capacity(responses.len());
        let mut total = 0usize;

        for response in responses {
            let (message, mac) =
                self.append_tsig_to_response(response, key_name, Some(&previous_mac))?;
            previous_mac = mac;
            total = total.saturating_add(message.len());
            if total > self.max_transfer_bytes {
                return Err(TransferError::servfail(
                    "transfer exceeds the per-connection byte limit",
                ));
            }
            signed_messages.push(message);
        }

        Ok(signed_messages)
    }

    fn check_zone_bytes(&self, messages: &[Vec<u8>]) -> Result<(), TransferError> {
        let total: usize = messages.iter().map(Vec::len).sum();
        if total > self.max_zone_transfer_bytes {
            return Err(TransferError::servfail(
                "zone exceeds the per-zone transfer byte limit",
            ));
        }
        if total > self.max_transfer_bytes {
            return Err(TransferError::servfail(
                "transfer exceeds the per-connection byte limit",
            ));
        }
        Ok(())
    }

    pub fn handle_axfr_request(
        &self,
        qname: &str,
        client_ip: IpAddr,
        tsig: Option<&TsigParseResult>,
        message_id: u16,
        message: &[u8],
        is_tcp: bool,
    ) -> Result<Vec<u8>, TransferError> {
        let messages =
            self.handle_axfr_request_impl(qname, client_ip, tsig, message_id, message, is_tcp)?;

        let mut combined = Vec::new();
        for resp in messages {
            combined.extend_from_slice(&resp);
        }

        Ok(combined)
    }

    pub fn handle_axfr_request_messages(
        &self,
        qname: &str,
        client_ip: IpAddr,
        tsig: Option<&TsigParseResult>,
        message_id: u16,
        message: &[u8],
        is_tcp: bool,
    ) -> Result<Vec<Vec<u8>>, TransferError> {
        self.handle_axfr_request_impl(qname, client_ip, tsig, message_id, message, is_tcp)
    }

    fn handle_axfr_request_impl(
        &self,
        qname: &str,
        client_ip: IpAddr,
        tsig: Option<&TsigParseResult>,
        message_id: u16,
        message: &[u8],
        is_tcp: bool,
    ) -> Result<Vec<Vec<u8>>, TransferError> {
        // AXFR disabled by default for security
        if !self.axfr_enabled {
            tracing::debug!(
                zone = %qname,
                client_ip = %client_ip,
                "AXFR request denied: AXFR not enabled"
            );
            return Err(TransferError::refused("AXFR not enabled"));
        }

        // AXFR requires TCP per RFC 5936 §2
        if self.tcp_only && !is_tcp {
            tracing::warn!(
                zone = %qname,
                client_ip = %client_ip,
                "AXFR request denied: TCP required"
            );
            return Err(TransferError::refused("AXFR requires TCP transport"));
        }

        let origin = qname.trim_end_matches('.');

        // Cheap ACL rejection before any TSIG work (phase 03 R3).
        if !self.network_and_zone_allowed(client_ip, origin) {
            tracing::warn!(
                zone = %origin,
                client_ip = %client_ip,
                "AXFR request denied: not in allowed list"
            );
            return Err(TransferError::refused("Zone transfer not allowed"));
        }

        if self.acl.wildcard && self.wildcard_requires_tsig() && tsig.is_none() {
            tracing::warn!(
                zone = %origin,
                client_ip = %client_ip,
                "AXFR request denied: wildcard requires TSIG"
            );
            return Err(TransferError::refused(
                "Zone transfer requires TSIG authentication",
            ));
        }

        let verified_key = self.verify_request_tsig(origin, client_ip, tsig, message)?;

        if !self.acl.key_matches(verified_key.as_deref()) {
            tracing::warn!(
                zone = %origin,
                client_ip = %client_ip,
                "AXFR request denied: TSIG key not authorized"
            );
            return Err(TransferError::refused(
                "Zone transfer not allowed for this TSIG key",
            ));
        }

        tracing::info!(
            zone = %origin,
            client_ip = %client_ip,
            tsig_status = if verified_key.is_some() { "TSIG secured" } else { "unsecured" },
            "AXFR transfer started"
        );

        // A single-response API cannot carry a multi-message transfer; the
        // client must retry over TCP (RFC 5936 §2).
        if !is_tcp {
            return Ok(vec![Self::build_truncated_transfer_response(
                qname,
                AXFR_QUERY_TYPE,
                message_id,
            )]);
        }

        let zone = self
            .zones
            .get(origin)
            .ok_or_else(|| TransferError::notauth("Zone not found"))?;

        let mut responses = Vec::new();

        let soa_record = self.find_soa_record(&zone);
        if let Some(ref soa) = soa_record {
            responses.push(self.build_axfr_first_message(
                qname,
                std::slice::from_ref(soa),
                message_id,
            ));
        }

        for ((name, record_type), records) in &zone.records {
            if *record_type != RecordType::SOA {
                let full_name = if name == "@" || name.is_empty() {
                    origin.to_string()
                } else {
                    format!("{}.{}", name, origin)
                };
                responses.push(self.build_axfr_record(
                    &full_name,
                    record_type,
                    records,
                    message_id,
                ));
            }
        }

        if let Some(ref soa) = soa_record {
            responses.push(self.build_axfr_last_message(
                qname,
                std::slice::from_ref(soa),
                message_id,
            ));
        }

        self.check_zone_bytes(&responses)?;

        tracing::info!(
            zone = %origin,
            client_ip = %client_ip,
            messages = %responses.len(),
            "AXFR transfer completed"
        );

        if let Some(ref cache) = self.cache {
            cache.invalidate_zone(origin, InvalidationReason::ZoneTransferAxfr);
        }

        match (verified_key.as_deref(), tsig) {
            (Some(key_name), Some(request)) => {
                self.sign_transfer_messages(responses, key_name, &request.mac)
            }
            _ => Ok(responses),
        }
    }

    /// Presence implies verification: a request with a TSIG is verified even
    /// when `require_tsig` is false, and a request without one is refused when
    /// it is true. Returns the verified key name, if any.
    fn verify_request_tsig(
        &self,
        origin: &str,
        client_ip: IpAddr,
        tsig: Option<&TsigParseResult>,
        message: &[u8],
    ) -> Result<Option<String>, TransferError> {
        match tsig {
            Some(tsig) => {
                if let Err(e) = self.verify_tsig(tsig, message) {
                    tracing::warn!(
                        zone = %origin,
                        client_ip = %client_ip,
                        error = %e,
                        "TSIG verification failed"
                    );
                    return Err(e);
                }
                Ok(Some(tsig.key_name.clone()))
            }
            None if self.require_tsig => {
                tracing::warn!(
                    zone = %origin,
                    client_ip = %client_ip,
                    "transfer denied: TSIG required"
                );
                Err(TransferError::refused(
                    "Zone transfer requires TSIG authentication",
                ))
            }
            None => Ok(None),
        }
    }

    fn build_truncated_transfer_response(qname: &str, qtype: u16, message_id: u16) -> Vec<u8> {
        let qname_wire = wire::encode_name(qname).unwrap_or_else(|_| vec![0u8]);
        let mut response = Vec::with_capacity(12 + qname_wire.len() + 4);
        response.extend_from_slice(&message_id.to_be_bytes());
        response.extend_from_slice(
            &build_response_flags(true, true, false, false, false, 0).to_be_bytes(),
        );
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&qname_wire);
        response.extend_from_slice(&qtype.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response
    }

    #[allow(clippy::too_many_arguments)]
    pub fn handle_ixfr_request(
        &self,
        qname: &str,
        client_ip: IpAddr,
        serial: Option<u32>,
        tsig: Option<&TsigParseResult>,
        message_id: u16,
        message: &[u8],
        is_tcp: bool,
    ) -> Result<Vec<u8>, TransferError> {
        let messages = self.handle_ixfr_request_impl(
            qname, client_ip, serial, tsig, message_id, message, is_tcp,
        )?;

        let mut combined = Vec::new();
        for resp in messages {
            combined.extend_from_slice(&resp);
        }

        Ok(combined)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn handle_ixfr_request_messages(
        &self,
        qname: &str,
        client_ip: IpAddr,
        serial: Option<u32>,
        tsig: Option<&TsigParseResult>,
        message_id: u16,
        message: &[u8],
        is_tcp: bool,
    ) -> Result<Vec<Vec<u8>>, TransferError> {
        self.handle_ixfr_request_impl(qname, client_ip, serial, tsig, message_id, message, is_tcp)
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_ixfr_request_impl(
        &self,
        qname: &str,
        client_ip: IpAddr,
        serial: Option<u32>,
        tsig: Option<&TsigParseResult>,
        message_id: u16,
        message: &[u8],
        is_tcp: bool,
    ) -> Result<Vec<Vec<u8>>, TransferError> {
        if !self.ixfr_enabled {
            tracing::debug!(zone = %qname, client_ip = %client_ip, "IXFR request denied: IXFR not enabled");
            return Err(TransferError::refused("IXFR not enabled"));
        }

        let origin = qname.trim_end_matches('.');

        // IXFR obeys the same authorization as AXFR (D21).
        if !self.network_and_zone_allowed(client_ip, origin) {
            tracing::warn!(
                zone = %origin,
                client_ip = %client_ip,
                "IXFR request denied: not in allowed list"
            );
            return Err(TransferError::refused("Zone transfer not allowed"));
        }

        if self.acl.wildcard && self.wildcard_requires_tsig() && tsig.is_none() {
            tracing::warn!(
                zone = %origin,
                client_ip = %client_ip,
                "IXFR request denied: wildcard requires TSIG"
            );
            return Err(TransferError::refused(
                "Zone transfer requires TSIG authentication",
            ));
        }

        let verified_key = self.verify_request_tsig(origin, client_ip, tsig, message)?;

        if !self.acl.key_matches(verified_key.as_deref()) {
            tracing::warn!(
                zone = %origin,
                client_ip = %client_ip,
                "IXFR request denied: TSIG key not authorized"
            );
            return Err(TransferError::refused(
                "Zone transfer not allowed for this TSIG key",
            ));
        }

        tracing::info!(
            zone = %origin,
            client_ip = %client_ip,
            serial = ?serial,
            tsig_status = if verified_key.is_some() { "TSIG secured" } else { "unsecured" },
            "IXFR transfer started"
        );

        // RFC 1995 §2: IXFR over UDP is attempted once; a response that does
        // not fit is truncated and the client retries over TCP. Concatenating
        // the whole transfer into one datagram is not an option.
        if !is_tcp {
            return Ok(vec![Self::build_truncated_transfer_response(
                qname,
                IXFR_QUERY_TYPE,
                message_id,
            )]);
        }

        let zone = self
            .zones
            .get(origin)
            .ok_or_else(|| TransferError::notauth("Zone not found"))?;
        let current_serial = zone.serial;
        let client_serial = serial.unwrap_or(0);

        let responses = if client_serial == current_serial {
            vec![self.build_ixfr_current_response(qname, &zone, message_id)?]
        } else if client_serial == 0 || serial_is_newer(client_serial, current_serial) {
            if self.ixfr_fallback_to_axfr {
                self.require_axfr_for_fallback()?;
                self.build_ixfr_full_response_messages(qname, &zone, message_id)?
            } else {
                return Err(TransferError::refused(
                    "IXFR cannot proceed: client has newer serial",
                ));
            }
        } else if let Some(old_version) = zone.get_previous_version(client_serial) {
            self.build_ixfr_incremental_response_messages(
                qname,
                &zone,
                &old_version.records,
                message_id,
            )?
        } else if self.ixfr_fallback_to_axfr {
            self.require_axfr_for_fallback()?;
            self.build_ixfr_full_response_messages(qname, &zone, message_id)?
        } else {
            return Err(TransferError::refused(
                "IXFR cannot proceed: no history available",
            ));
        };

        self.check_zone_bytes(&responses)?;

        tracing::info!(
            zone = %origin,
            client_ip = %client_ip,
            messages = %responses.len(),
            "IXFR transfer completed"
        );

        if let Some(ref cache) = self.cache {
            cache.invalidate_zone(origin, InvalidationReason::ZoneTransferIxfr);
        }

        match (verified_key.as_deref(), tsig) {
            (Some(key_name), Some(request)) => {
                self.sign_transfer_messages(responses, key_name, &request.mac)
            }
            _ => Ok(responses),
        }
    }

    /// An IXFR fallback is an AXFR. It must be enabled explicitly, or the
    /// handler would serve a full zone dump through a path the operator never
    /// turned on (D21).
    fn require_axfr_for_fallback(&self) -> Result<(), TransferError> {
        if self.axfr_enabled {
            Ok(())
        } else {
            Err(TransferError::refused(
                "IXFR fallback requires AXFR to be enabled",
            ))
        }
    }

    fn build_ixfr_full_response_messages(
        &self,
        qname: &str,
        zone: &Zone,
        message_id: u16,
    ) -> Result<Vec<Vec<u8>>, TransferError> {
        let mut responses = Vec::new();

        let soa_record = self
            .find_soa_record(zone)
            .ok_or_else(|| TransferError::servfail("Zone has no SOA record"))?;
        responses.push(self.build_axfr_first_message(
            qname,
            std::slice::from_ref(&soa_record),
            message_id,
        ));

        for ((name, record_type), records) in &zone.records {
            if *record_type != RecordType::SOA {
                let full_name = if name == "@" || name.is_empty() {
                    zone.origin.clone()
                } else {
                    format!("{}.{}", name, zone.origin)
                };
                responses.push(self.build_axfr_record(
                    &full_name,
                    record_type,
                    records,
                    message_id,
                ));
            }
        }

        responses.push(self.build_axfr_last_message(
            qname,
            std::slice::from_ref(&soa_record),
            message_id,
        ));

        tracing::debug!(zone = %qname, messages = %responses.len(), "IXFR full response built");
        Ok(responses)
    }

    fn build_ixfr_incremental_response_messages(
        &self,
        qname: &str,
        zone: &Zone,
        old_records: &std::collections::HashMap<(String, RecordType), Vec<DnsZoneRecord>>,
        message_id: u16,
    ) -> Result<Vec<Vec<u8>>, TransferError> {
        let current_soa = self
            .find_soa_record(zone)
            .ok_or_else(|| TransferError::servfail("Zone has no SOA record"))?
            .clone();

        let old_soa = old_records
            .get(&("@".to_string(), RecordType::SOA))
            .and_then(|v| v.first())
            .cloned();

        let mut all_keys = std::collections::HashSet::new();
        for key in old_records.keys() {
            all_keys.insert(key.clone());
        }
        for key in zone.records.keys() {
            all_keys.insert(key.clone());
        }

        let mut to_delete = Vec::new();
        let mut to_add = Vec::new();

        for key in &all_keys {
            let old_recs = old_records.get(key);
            let new_recs = zone.records.get(key);
            match (old_recs, new_recs) {
                (Some(old), None) => to_delete.push((key.clone(), old.clone())),
                (None, Some(new)) => to_add.push((key.clone(), new.clone())),
                (Some(old), Some(new))
                    if old.len() != new.len()
                        || old
                            .iter()
                            .zip(new.iter())
                            .any(|(a, b)| a.value != b.value || a.ttl != b.ttl) =>
                {
                    to_delete.push((key.clone(), old.clone()));
                    to_add.push((key.clone(), new.clone()));
                }
                _ => {}
            }
        }

        let mut responses = Vec::new();

        let first_ancount = (1 + to_delete.len()) as u16;
        responses.push(self.build_ixfr_message(
            qname,
            old_soa.as_ref(),
            &to_delete,
            first_ancount,
            message_id,
        ));

        let second_ancount = (to_add.len() + 1) as u16;
        responses.push(self.build_ixfr_message(
            qname,
            Some(&current_soa),
            &to_add,
            second_ancount,
            message_id,
        ));

        tracing::debug!(zone = %qname, messages = %responses.len(), "IXFR incremental response built");
        Ok(responses)
    }

    fn build_ixfr_message(
        &self,
        qname: &str,
        soa: Option<&DnsZoneRecord>,
        records: &[((String, RecordType), Vec<DnsZoneRecord>)],
        ancount: u16,
        message_id: u16,
    ) -> Vec<u8> {
        // The question name is an absolute name; a malformed one can only come
        // from a query the parser already accepted, so fall back to the root.
        let qname_wire = wire::encode_name(qname).unwrap_or_else(|_| vec![0u8]);
        let mut response = Vec::new();

        response.extend_from_slice(&message_id.to_be_bytes());
        response.extend_from_slice(
            &build_response_flags(true, false, true, false, false, 0).to_be_bytes(),
        );
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&ancount.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());

        response.extend_from_slice(&qname_wire);
        response.extend_from_slice(&IXFR_QUERY_TYPE.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());

        if let Some(soa_record) = soa {
            response.extend_from_slice(&qname_wire);
            response.extend_from_slice(&6u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&soa_record.ttl.to_be_bytes());

            let soa_data = Self::build_soa_rdata(&soa_record.value);
            response.extend_from_slice(&(soa_data.len() as u16).to_be_bytes());
            response.extend_from_slice(&soa_data);
        }

        for ((name, _), recs) in records {
            let full_name = if name == "@" || name.is_empty() {
                qname.to_string()
            } else {
                format!("{}.{}", name, qname)
            };
            for record in recs {
                let rr = self.build_axfr_record(
                    &full_name,
                    &record.record_type,
                    std::slice::from_ref(record),
                    message_id,
                );
                response.extend_from_slice(&rr[12..]);
            }
        }

        response
    }

    fn build_ixfr_current_response(
        &self,
        qname: &str,
        zone: &Zone,
        message_id: u16,
    ) -> Result<Vec<u8>, TransferError> {
        let soa = self
            .find_soa_record(zone)
            .ok_or_else(|| TransferError::servfail("Zone has no SOA record"))?;
        let qname_wire = wire::encode_name(qname).unwrap_or_else(|_| vec![0u8]);

        let mut response = Vec::new();
        response.extend_from_slice(&message_id.to_be_bytes());
        response.extend_from_slice(
            &build_response_flags(true, false, true, false, false, 0).to_be_bytes(),
        );
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());

        response.extend_from_slice(&qname_wire);
        response.extend_from_slice(&IXFR_QUERY_TYPE.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());

        response.extend_from_slice(&qname_wire);
        response.extend_from_slice(&6u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&soa.ttl.to_be_bytes());

        let soa_data = Self::build_soa_rdata(&soa.value);
        response.extend_from_slice(&(soa_data.len() as u16).to_be_bytes());
        response.extend_from_slice(&soa_data);

        tracing::debug!(zone = %qname, serial = %zone.serial, "IXFR sending current SOA");

        Ok(response)
    }

    fn build_soa_rdata(soa_value: &str) -> Vec<u8> {
        let parts: Vec<&str> = soa_value.split_whitespace().collect();
        if parts.len() < 7 {
            return Vec::new();
        }

        let mut rdata = Vec::new();

        let mname = parts[0];
        for part in mname.split('.') {
            if !part.is_empty() {
                rdata.push(part.len() as u8);
                rdata.extend_from_slice(part.as_bytes());
            }
        }
        rdata.push(0);

        let rname = parts[1];
        for part in rname.split('.') {
            if !part.is_empty() {
                rdata.push(part.len() as u8);
                rdata.extend_from_slice(part.as_bytes());
            }
        }
        rdata.push(0);

        if let Ok(serial) = parts[2].parse::<u32>() {
            rdata.extend_from_slice(&serial.to_be_bytes());
        } else {
            rdata.extend_from_slice(&1u32.to_be_bytes());
        }

        if let Ok(refresh) = parts[3].parse::<u32>() {
            rdata.extend_from_slice(&refresh.to_be_bytes());
        } else {
            rdata.extend_from_slice(&3600u32.to_be_bytes());
        }

        if let Ok(retry) = parts[4].parse::<u32>() {
            rdata.extend_from_slice(&retry.to_be_bytes());
        } else {
            rdata.extend_from_slice(&600u32.to_be_bytes());
        }

        if let Ok(expire) = parts[5].parse::<u32>() {
            rdata.extend_from_slice(&expire.to_be_bytes());
        } else {
            rdata.extend_from_slice(&86400u32.to_be_bytes());
        }

        if let Ok(minimum) = parts[6].parse::<u32>() {
            rdata.extend_from_slice(&minimum.to_be_bytes());
        } else {
            rdata.extend_from_slice(&3600u32.to_be_bytes());
        }

        rdata
    }

    fn find_soa_record(&self, zone: &Zone) -> Option<DnsZoneRecord> {
        let soa_key = ("@".to_string(), RecordType::SOA);
        zone.records
            .get(&soa_key)
            .and_then(|records| records.first().cloned())
    }

    fn build_axfr_first_message(
        &self,
        qname: &str,
        records: &[DnsZoneRecord],
        message_id: u16,
    ) -> Vec<u8> {
        self.build_axfr_record(qname, &RecordType::SOA, records, message_id)
    }

    fn build_axfr_last_message(
        &self,
        qname: &str,
        records: &[DnsZoneRecord],
        message_id: u16,
    ) -> Vec<u8> {
        self.build_axfr_record(qname, &RecordType::SOA, records, message_id)
    }

    fn build_axfr_record(
        &self,
        qname: &str,
        record_type: &RecordType,
        records: &[DnsZoneRecord],
        message_id: u16,
    ) -> Vec<u8> {
        let qname_wire = wire::encode_name(qname).unwrap_or_else(|_| vec![0u8]);
        let mut response = Vec::new();

        response.extend_from_slice(&message_id.to_be_bytes());

        let flags = if record_type == &RecordType::SOA {
            build_response_flags(true, false, true, false, false, 0)
        } else {
            build_response_flags(false, false, true, false, false, 0)
        };
        response.extend_from_slice(&flags.to_be_bytes());

        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&(records.len() as u16).to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());

        response.extend_from_slice(&qname_wire);

        response.extend_from_slice(&record_type.to_u16().to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());

        for record in records {
            response.extend_from_slice(&qname_wire);

            response.extend_from_slice(&record.record_type.to_u16().to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&record.ttl.to_be_bytes());

            match record.record_type {
                RecordType::A => {
                    if let Ok(ip) = record.value.parse::<std::net::Ipv4Addr>() {
                        // RDLENGTH is the RDATA length: four octets, not the
                        // address family number. A short length here made the
                        // following record start inside this one.
                        response.extend_from_slice(&4u16.to_be_bytes());
                        response.extend_from_slice(&ip.octets());
                    }
                }
                RecordType::AAAA => {
                    if let Ok(ip) = record.value.parse::<std::net::Ipv6Addr>() {
                        response.extend_from_slice(&16u16.to_be_bytes());
                        response.extend_from_slice(&ip.octets());
                    }
                }
                RecordType::SOA => {
                    // An SOA RDATA is two names plus five 32-bit fields.
                    // Encoding it through the single-name branch produced a
                    // record no secondary could parse.
                    let rdata = Self::build_soa_rdata(&record.value);
                    response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                    response.extend_from_slice(&rdata);
                }
                RecordType::CNAME | RecordType::NS => {
                    let mut target_parts: Vec<&str> =
                        record.value.split('.').filter(|s| !s.is_empty()).collect();
                    if target_parts.is_empty() {
                        target_parts.push("");
                    }
                    let mut total_len = 1; // root label
                    for part in &target_parts {
                        total_len += 1 + part.len();
                    }
                    response.extend_from_slice(&(total_len as u16).to_be_bytes());
                    for part in &target_parts {
                        response.push((*part).len() as u8);
                        response.extend_from_slice(part.as_bytes());
                    }
                    response.push(0);
                }
                RecordType::TXT => {
                    let txt = record.value.as_bytes();
                    let mut rdata = Vec::with_capacity(txt.len() + txt.len().div_ceil(255));
                    if txt.is_empty() {
                        rdata.push(0);
                    } else {
                        for chunk in txt.chunks(255) {
                            rdata.push(chunk.len() as u8);
                            rdata.extend_from_slice(chunk);
                        }
                    }
                    response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                    response.extend_from_slice(&rdata);
                }
                RecordType::MX => {
                    let priority = record.priority.unwrap_or(10);
                    let mut rdata = Vec::new();
                    rdata.extend_from_slice(&priority.to_be_bytes());
                    let mut target_parts: Vec<&str> =
                        record.value.split('.').filter(|s| !s.is_empty()).collect();
                    if target_parts.is_empty() {
                        target_parts.push("");
                    }
                    for part in &target_parts {
                        rdata.push((*part).len() as u8);
                        rdata.extend_from_slice(part.as_bytes());
                    }
                    rdata.push(0);
                    response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                    response.extend_from_slice(&rdata);
                }
                RecordType::SRV => {
                    let parts: Vec<&str> = record.value.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let priority: u16 = parts[0].parse().unwrap_or(0);
                        let weight: u16 = parts[1].parse().unwrap_or(0);
                        let port: u16 = parts[2].parse().unwrap_or(0);
                        let mut rdata = Vec::new();
                        rdata.extend_from_slice(&priority.to_be_bytes());
                        rdata.extend_from_slice(&weight.to_be_bytes());
                        rdata.extend_from_slice(&port.to_be_bytes());
                        let target = parts[3];
                        let mut target_parts: Vec<&str> =
                            target.split('.').filter(|s| !s.is_empty()).collect();
                        if target_parts.is_empty() {
                            target_parts.push("");
                        }
                        for part in &target_parts {
                            rdata.push((*part).len() as u8);
                            rdata.extend_from_slice(part.as_bytes());
                        }
                        rdata.push(0);
                        response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                        response.extend_from_slice(&rdata);
                    }
                }
                RecordType::PTR => {
                    let mut target_parts: Vec<&str> =
                        record.value.split('.').filter(|s| !s.is_empty()).collect();
                    if target_parts.is_empty() {
                        target_parts.push("");
                    }
                    let mut total_len = 1; // root label
                    for part in &target_parts {
                        total_len += 1 + part.len();
                    }
                    response.extend_from_slice(&(total_len as u16).to_be_bytes());
                    for part in &target_parts {
                        response.push((*part).len() as u8);
                        response.extend_from_slice(part.as_bytes());
                    }
                    response.push(0);
                }
                RecordType::DNSKEY => {
                    if let Ok(key_bytes) = hex::decode(&record.value) {
                        response.extend_from_slice(&(key_bytes.len() as u16).to_be_bytes());
                        response.extend_from_slice(&key_bytes);
                    }
                }
                RecordType::RRSIG => {
                    if let Ok(rrsig_bytes) = hex::decode(&record.value) {
                        response.extend_from_slice(&(rrsig_bytes.len() as u16).to_be_bytes());
                        response.extend_from_slice(&rrsig_bytes);
                    }
                }
                RecordType::NSEC => {
                    let parts: Vec<&str> = record.value.split_whitespace().collect();
                    if !parts.is_empty() {
                        let next_domain = parts[0];
                        let mut target_parts: Vec<&str> =
                            next_domain.split('.').filter(|s| !s.is_empty()).collect();
                        if target_parts.is_empty() {
                            target_parts.push("");
                        }
                        let mut _total_len = 0;
                        for part in &target_parts {
                            _total_len += 1 + part.len();
                        }
                        let mut nsec_data = Vec::new();
                        for part in &target_parts {
                            nsec_data.push((*part).len() as u8);
                            nsec_data.extend_from_slice(part.as_bytes());
                        }
                        if parts.len() > 1 {
                            let mut bitmap = Vec::new();
                            let mut current_window = 0u8;
                            let mut block_bits = Vec::new();
                            for type_str in &parts[1..] {
                                let type_val: u16 = match type_str.to_uppercase().as_str() {
                                    "A" => 1,
                                    "AAAA" => 28,
                                    "CNAME" => 5,
                                    "NS" => 2,
                                    "SOA" => 6,
                                    "TXT" => 16,
                                    "MX" => 15,
                                    "SRV" => 33,
                                    "PTR" => 12,
                                    "DNSKEY" => 48,
                                    "RRSIG" => 46,
                                    "NSEC" => 47,
                                    "NSEC3" => 50,
                                    "DS" => 43,
                                    "CAA" => 257,
                                    _ => continue,
                                };
                                let window_byte = (type_val >> 8) as u8;
                                let bitmap_bit = type_val & 0xFF;
                                if window_byte != current_window {
                                    if !block_bits.is_empty() {
                                        bitmap.push(current_window);
                                        bitmap.push(block_bits.len() as u8);
                                        bitmap.extend_from_slice(&block_bits);
                                    }
                                    current_window = window_byte;
                                    block_bits = vec![0u8; (bitmap_bit / 8) as usize + 1];
                                }
                                let byte_idx = (bitmap_bit / 8) as usize;
                                let bit_idx = bitmap_bit % 8;
                                if byte_idx < block_bits.len() {
                                    block_bits[byte_idx] |= 1 << (7 - bit_idx);
                                }
                            }
                            if !block_bits.is_empty() {
                                bitmap.push(current_window);
                                bitmap.push(block_bits.len() as u8);
                                bitmap.extend_from_slice(&block_bits);
                            }
                            nsec_data.extend_from_slice(&bitmap);
                        } else {
                            nsec_data.push(0);
                        }
                        response.extend_from_slice(&(nsec_data.len() as u16).to_be_bytes());
                        response.extend_from_slice(&nsec_data);
                    }
                }
                RecordType::NSEC3 => {
                    if let Ok(nsec3_bytes) = hex::decode(&record.value) {
                        response.extend_from_slice(&(nsec3_bytes.len() as u16).to_be_bytes());
                        response.extend_from_slice(&nsec3_bytes);
                    }
                }
                RecordType::DS => {
                    if let Ok(ds_bytes) = hex::decode(&record.value) {
                        response.extend_from_slice(&(ds_bytes.len() as u16).to_be_bytes());
                        response.extend_from_slice(&ds_bytes);
                    }
                }
                RecordType::CAA => {
                    let parts: Vec<&str> = record.value.splitn(3, ' ').collect();
                    let mut data = Vec::new();
                    if parts.len() >= 3 {
                        let flags: u8 = parts[0].parse().unwrap_or(0);
                        let tag = parts[1].as_bytes();
                        let value = parts[2].trim_matches('"').as_bytes();
                        data.push(flags);
                        data.push(tag.len() as u8);
                        data.extend_from_slice(tag);
                        data.extend_from_slice(value);
                    } else {
                        data.push(0);
                        data.push(record.value.len() as u8);
                        data.extend_from_slice(record.value.as_bytes());
                    }
                    response.extend_from_slice(&(data.len() as u16).to_be_bytes());
                    response.extend_from_slice(&data);
                }
                _ => continue,
            };
        }

        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_axfr_disabled_by_default() {
        let zones = Arc::new(ShardedZoneStore::new());
        let transfer = ZoneTransfer::new(zones, vec![], None);
        assert!(!transfer.is_axfr_enabled());
    }

    #[test]
    fn test_axfr_tcp_only_default() {
        let zones = Arc::new(ShardedZoneStore::new());
        let transfer = ZoneTransfer::new(zones, vec![], None);
        assert!(transfer.is_tcp_only());
    }

    #[test]
    fn test_axfr_disabled_returns_error() {
        let zones = Arc::new(ShardedZoneStore::new());
        let transfer = ZoneTransfer::new(zones, vec![], None);
        let result = transfer.handle_axfr_request(
            "example.com",
            "192.168.1.1".parse().unwrap(),
            None,
            0x1234,
            &[],
            false,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not enabled"));
    }

    #[test]
    fn test_axfr_tcp_only_rejects_udp() {
        let zones = Arc::new(ShardedZoneStore::new());
        let transfer = ZoneTransfer::with_security_config(
            zones,
            TransferAcl::from_entries(&["*".to_string()]),
            None,
            true,
            true,
            true,
            true,
            false,
            true, // axfr_enabled
            true, // tcp_only
        )
        .expect("a handler without require_tsig may be constructed without a verifier");
        let result = transfer.handle_axfr_request(
            "example.com",
            "192.168.1.1".parse().unwrap(),
            None,
            0x1234,
            &[],
            false, // not TCP
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("TCP transport"));
    }

    #[test]
    fn test_ixfr_enabled_by_default() {
        let zones = Arc::new(ShardedZoneStore::new());
        let transfer = ZoneTransfer::new(zones, vec![], None);
        assert!(transfer.ixfr_enabled);
    }

    #[test]
    fn test_max_history_size_default() {
        let zones = Arc::new(ShardedZoneStore::new());
        let transfer = ZoneTransfer::new(zones, vec![], None);
        assert_eq!(transfer.max_history_size, 200);
    }

    #[test]
    fn test_with_cache_builder() {
        let zones = Arc::new(ShardedZoneStore::new());
        let transfer = ZoneTransfer::new(zones, vec![], None);
        assert!(transfer.cache.is_none());
    }

    #[test]
    fn test_serial_is_newer_rfc1982() {
        assert!(serial_is_newer(2, 1));
        assert!(!serial_is_newer(1, 2));
        assert!(!serial_is_newer(5, 5));

        assert!(serial_is_newer(1, u32::MAX));
        assert!(serial_is_newer(0x0000_0010, 0xFFFFFFF0));
        assert!(serial_is_newer(u32::MAX, u32::MAX - 1));
        assert!(!serial_is_newer(u32::MAX - 1, u32::MAX));
    }
}
