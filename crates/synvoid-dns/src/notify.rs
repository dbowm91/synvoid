use parking_lot::RwLock;
use rand::random;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use super::wire;
use crate::cache::DnsCache;
use crate::parsed_query::{build_response_flags_from_query, ParsedDnsQuery};
use crate::server::ShardedZoneStore;

#[derive(Clone, Debug, Default)]
pub struct NotifyConfig {
    pub enabled: bool,
    pub also_notify: Vec<String>,
}

#[derive(Clone)]
pub struct NotifyHandler {
    zones: Arc<ShardedZoneStore>,
    config: NotifyConfig,
    notified_secondaries: Arc<RwLock<HashMap<String, u32>>>,
    cache: Option<Arc<DnsCache>>,
    /// Source IP allowlist for incoming NOTIFY. Empty = deny all: a NOTIFY
    /// owner must be named explicitly (R6).
    source_allowlist: Vec<String>,
    /// Require TSIG for incoming NOTIFY.
    require_tsig: bool,
    tsig_verifier: Option<Arc<crate::tsig::TsigVerifier>>,
    /// Rate limiter for incoming NOTIFY: (zone, last_time).
    notify_timestamps: Arc<RwLock<HashMap<String, std::time::Instant>>>,
    /// Minimum interval between NOTIFY for same zone.
    min_notify_interval: std::time::Duration,
}

impl NotifyHandler {
    pub fn new(zones: Arc<ShardedZoneStore>, config: NotifyConfig) -> Self {
        Self {
            zones,
            config,
            notified_secondaries: Arc::new(RwLock::new(HashMap::new())),
            cache: None,
            source_allowlist: Vec::new(),
            require_tsig: false,
            tsig_verifier: None,
            notify_timestamps: Arc::new(RwLock::new(HashMap::new())),
            min_notify_interval: std::time::Duration::from_secs(5),
        }
    }

    pub fn with_cache(mut self, cache: Arc<DnsCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    pub fn with_source_allowlist(mut self, allowlist: Vec<String>) -> Self {
        self.source_allowlist = allowlist;
        self
    }

    pub fn with_require_tsig(mut self, require: bool) -> Self {
        self.require_tsig = require;
        self
    }

    pub fn with_tsig_verifier(mut self, verifier: Arc<crate::tsig::TsigVerifier>) -> Self {
        self.tsig_verifier = Some(verifier);
        self
    }

    pub fn with_min_notify_interval(mut self, interval: std::time::Duration) -> Self {
        self.min_notify_interval = interval;
        self
    }

    fn is_source_allowed(&self, client_ip: std::net::IpAddr) -> bool {
        // Deny-all by default: a NOTIFY is an unauthenticated instruction to
        // discard cached data, so "nobody configured an allowlist" must not
        // read as "everyone is a primary".
        if self.source_allowlist.is_empty() {
            return false;
        }
        for allowed in &self.source_allowlist {
            if allowed == "*" {
                return true;
            }
            if let Ok(cidr) = allowed.parse::<ipnetwork::IpNetwork>() {
                if cidr.contains(client_ip) {
                    return true;
                }
            }
            if let Ok(ip) = allowed.parse::<std::net::IpAddr>() {
                if ip == client_ip {
                    return true;
                }
            }
        }
        false
    }

    fn is_rate_limited(&self, zone_origin: &str) -> bool {
        let now = std::time::Instant::now();
        let mut timestamps = self.notify_timestamps.write();
        if let Some(last_time) = timestamps.get(zone_origin) {
            if now.duration_since(*last_time) < self.min_notify_interval {
                return true;
            }
        }
        timestamps.insert(zone_origin.to_string(), now);
        false
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn trigger_zone_change(&self, zone_origin: &str) {
        if !self.config.enabled {
            return;
        }

        if let Some(zone) = self.zones.get(zone_origin) {
            let serial = zone.serial;
            self.notify_secondaries(zone_origin, serial);
        }
    }

    pub fn handle_notify(&self, query: &[u8], client_ip: IpAddr) -> Option<Vec<u8>> {
        if !self.config.enabled {
            return None;
        }

        // Structural checks and the source allowlist are cheap and run before
        // the TSIG parser sees the packet.
        let parsed = ParsedDnsQuery::parse(query).ok()?;
        if !parsed.is_notify() || parsed.flags.is_response {
            return None;
        }

        if !self.is_source_allowed(client_ip) {
            tracing::warn!(
                client_ip = %client_ip,
                "NOTIFY denied: source not in allowlist"
            );
            return None;
        }

        // Presence implies verification: a TSIG that is present is verified
        // even when `require_tsig` is false. A NOTIFY that cannot be
        // authenticated is answered NOTAUTH (RFC 8945 §5.2).
        let tsig = match crate::tsig::parse_tsig_from_query(query, parsed.question_end) {
            Ok(tsig) => tsig,
            Err(e) => {
                tracing::warn!(client_ip = %client_ip, error = %e, "NOTIFY denied: malformed TSIG");
                return Some(build_notify_response(query, wire::UPDATE_RCODE_NOTAUTH));
            }
        };

        match tsig {
            Some(tsig) => match self.tsig_verifier.as_ref() {
                Some(verifier) => {
                    if let Err(e) = verifier.verify(query, &tsig) {
                        tracing::warn!(
                            client_ip = %client_ip,
                            error = %e,
                            "NOTIFY denied: TSIG verification failed"
                        );
                        return Some(build_notify_response(query, wire::UPDATE_RCODE_NOTAUTH));
                    }
                }
                None => {
                    tracing::warn!(
                        client_ip = %client_ip,
                        "NOTIFY denied: TSIG present but no verifier configured"
                    );
                    return Some(build_notify_response(query, wire::UPDATE_RCODE_NOTAUTH));
                }
            },
            None if self.require_tsig => {
                tracing::warn!(
                    client_ip = %client_ip,
                    "NOTIFY denied: TSIG required but not present"
                );
                return None;
            }
            None => {}
        }

        let zone_name = &parsed.qname;

        let zone_origin = if zone_name.ends_with('.') {
            zone_name[..zone_name.len() - 1].to_string()
        } else {
            zone_name.clone()
        };

        // An unknown zone is not this server's authority: NOTAUTH, and the
        // cache is not touched (there is nothing to invalidate).
        if !self.zones.contains_key(&zone_origin) {
            tracing::debug!(
                zone = %zone_origin,
                client_ip = %client_ip,
                "NOTIFY for unknown zone"
            );
            return Some(build_notify_response(query, wire::UPDATE_RCODE_NOTAUTH));
        }

        if self.is_rate_limited(&zone_origin) {
            tracing::debug!(
                zone = %zone_origin,
                client_ip = %client_ip,
                "NOTIFY rate limited, skipping"
            );
            return Some(build_notify_response(query, wire::RCODE_NOERROR));
        }

        if let Some(ref cache) = self.cache {
            cache.invalidate_zone(
                &zone_origin,
                crate::cache::InvalidationReason::NotifyReceived,
            );
        }

        Some(build_notify_response(query, wire::RCODE_NOERROR))
    }

    pub fn notify_secondaries(&self, zone_origin: &str, new_serial: u32) {
        if !self.config.enabled {
            return;
        }

        {
            let notified = self.notified_secondaries.read();
            if let Some(last_serial) = notified.get(zone_origin) {
                if *last_serial == new_serial {
                    tracing::debug!(zone = %zone_origin, serial = %new_serial, "NOTIFY skipped: serial unchanged");
                    return;
                }
            }
        }

        {
            let mut notified = self.notified_secondaries.write();
            notified.insert(zone_origin.to_string(), new_serial);
        }

        if let Some(zone) = self.zones.get(zone_origin) {
            let soa = zone
                .records
                .get(&(zone_origin.to_string(), super::server::RecordType::SOA));

            for secondary in &self.config.also_notify {
                let notify_result =
                    self.send_notify_to_secondary(secondary, zone_origin, soa, new_serial);

                match notify_result {
                    Ok(_) => {
                        tracing::info!(
                            zone = %zone_origin,
                            target = %secondary,
                            serial = %new_serial,
                            "NOTIFY sent"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            zone = %zone_origin,
                            target = %secondary,
                            error = %e,
                            "NOTIFY send failed"
                        );
                    }
                }
            }
        }
    }

    fn send_notify_to_secondary(
        &self,
        secondary: &str,
        zone_origin: &str,
        _soa: Option<&Vec<super::server::DnsZoneRecord>>,
        _serial: u32,
    ) -> Result<(), String> {
        let ip: IpAddr = secondary
            .parse()
            .map_err(|e| format!("Invalid IP address: {}", e))?;

        let port = 53;

        let socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("Failed to bind socket: {}", e))?;

        socket
            .set_nonblocking(true)
            .map_err(|e| format!("Failed to set non-blocking: {}", e))?;

        let transaction_id: u16 = random();

        let mut notify_query = Vec::new();

        notify_query.extend_from_slice(&transaction_id.to_be_bytes());

        notify_query.extend_from_slice(&0x2800u16.to_be_bytes());

        notify_query.extend_from_slice(&1u16.to_be_bytes());

        notify_query.extend_from_slice(&0u16.to_be_bytes());
        notify_query.extend_from_slice(&0u16.to_be_bytes());
        notify_query.extend_from_slice(&0u16.to_be_bytes());

        let name_parts: Vec<&str> = zone_origin.split('.').collect::<Vec<_>>();
        for part in name_parts.clone() {
            if part.is_empty() {
                continue;
            }
            notify_query.push(part.len() as u8);
            notify_query.extend_from_slice(part.as_bytes());
        }
        notify_query.push(0);

        notify_query.extend_from_slice(&6u16.to_be_bytes());

        notify_query.extend_from_slice(&1u16.to_be_bytes());

        let _timeout = std::time::Duration::from_secs(5);

        match socket.send_to(&notify_query, format!("{}:{}", ip, port)) {
            Ok(_) => {
                tracing::debug!(zone = %zone_origin, target = %ip, "NOTIFY packet sent");
                Ok(())
            }
            Err(e) => Err(format!("Send error: {}", e)),
        }
    }
}

pub fn build_notify_response(query: &[u8], rcode: u8) -> Vec<u8> {
    let parsed = match ParsedDnsQuery::parse(query) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };

    let id = parsed.id;

    let flags = build_response_flags_from_query(
        &parsed, true,  // authoritative
        false, // truncated
        false, // recursion_available (authoritative-only)
        false, // authentic_data
        rcode,
    );

    let mut response = Vec::with_capacity(12 + parsed.question_end - 12);
    response.extend_from_slice(&id.to_be_bytes());
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Copy entire question section from raw query
    response.extend_from_slice(&parsed.raw[12..parsed.question_end]);

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notify_opcode() {
        assert_eq!(wire::OPCODE_NOTIFY, 4);
    }

    #[test]
    fn test_build_notify_response() {
        let mut query = vec![0u8; 28];
        query[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
        // NOTIFY query: opcode=4 (bits 11-14), QR=0
        query[2..4].copy_from_slice(&0x2000u16.to_be_bytes());
        query[4..6].copy_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(b"\x07example\x03com\x00");
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());

        let response = build_notify_response(&query, wire::RCODE_NOERROR);
        assert!(!response.is_empty());

        let flags = u16::from_be_bytes([response[2], response[3]]);
        let opcode = (flags & 0x7800) >> 11;
        assert_eq!(opcode, 4);

        let response_code = flags & 0x000F;
        assert_eq!(response_code, 0);
    }

    #[test]
    fn test_notify_source_allowlist_empty_denies_all() {
        let zones = Arc::new(ShardedZoneStore::new());
        let config = NotifyConfig {
            enabled: true,
            also_notify: vec![],
        };
        let handler = NotifyHandler::new(zones, config);
        // Empty allowlist = deny all (R6): a primary must be named.
        assert!(!handler.is_source_allowed("192.168.1.1".parse().unwrap()));
        assert!(!handler.is_source_allowed("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_notify_source_allowlist_specific_ips() {
        let zones = Arc::new(ShardedZoneStore::new());
        let config = NotifyConfig {
            enabled: true,
            also_notify: vec![],
        };
        let handler = NotifyHandler::new(zones, config)
            .with_source_allowlist(vec!["192.168.1.1".to_string(), "10.0.0.0/8".to_string()]);
        assert!(handler.is_source_allowed("192.168.1.1".parse().unwrap()));
        assert!(handler.is_source_allowed("10.0.0.1".parse().unwrap()));
        assert!(!handler.is_source_allowed("172.16.0.1".parse().unwrap()));
    }

    #[test]
    fn test_notify_source_allowlist_wildcard() {
        let zones = Arc::new(ShardedZoneStore::new());
        let config = NotifyConfig {
            enabled: true,
            also_notify: vec![],
        };
        let handler =
            NotifyHandler::new(zones, config).with_source_allowlist(vec!["*".to_string()]);
        assert!(handler.is_source_allowed("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_notify_disabled_rejects() {
        let zones = Arc::new(ShardedZoneStore::new());
        let config = NotifyConfig {
            enabled: false,
            also_notify: vec![],
        };
        let handler = NotifyHandler::new(zones, config);
        let result = handler.handle_notify(&[0u8; 12], "192.168.1.1".parse().unwrap());
        assert!(result.is_none());
    }

    #[test]
    fn test_notify_rate_limiting() {
        let zones = Arc::new(ShardedZoneStore::new());
        let config = NotifyConfig {
            enabled: true,
            also_notify: vec![],
        };
        let handler = NotifyHandler::new(zones, config)
            .with_min_notify_interval(std::time::Duration::from_secs(60));
        // First check should not be rate-limited
        assert!(!handler.is_rate_limited("example.com"));
        // Second check immediately should be rate-limited
        assert!(handler.is_rate_limited("example.com"));
        // Different zone should not be rate-limited
        assert!(!handler.is_rate_limited("other.com"));
    }
}
