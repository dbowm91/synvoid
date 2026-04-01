use parking_lot::RwLock;
use rand::random;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use super::wire;
use crate::dns::server::ShardedZoneStore;

#[derive(Clone, Debug, Default)]
pub struct NotifyConfig {
    pub enabled: bool,
    pub also_notify: Vec<String>,
}

impl From<&crate::config::dns::NotifyConfig> for NotifyConfig {
    fn from(config: &crate::config::dns::NotifyConfig) -> Self {
        Self {
            enabled: config.enabled,
            also_notify: config.also_notify.clone(),
        }
    }
}

#[derive(Clone)]
pub struct NotifyHandler {
    zones: Arc<ShardedZoneStore>,
    config: NotifyConfig,
    notified_secondaries: Arc<RwLock<HashMap<String, u32>>>,
}

impl NotifyHandler {
    pub fn new(zones: Arc<ShardedZoneStore>, config: NotifyConfig) -> Self {
        Self {
            zones,
            config,
            notified_secondaries: Arc::new(RwLock::new(HashMap::new())),
        }
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

    pub fn handle_notify(&self, query: &[u8], _client_ip: IpAddr) -> Option<Vec<u8>> {
        if !self.config.enabled {
            return None;
        }

        if query.len() < 12 {
            return None;
        }

        let flags = wire::get_message_flags(query)?;
        if flags.opcode != wire::OPCODE_NOTIFY {
            return None;
        }

        if flags.is_response {
            return None;
        }

        let qdcount = u16::from_be_bytes([query[4], query[5]]);
        if qdcount == 0 {
            return None;
        }

        let zone_name = parse_notify_zone_name(query, 12)?;

        let zone_origin = if zone_name.ends_with('.') {
            zone_name[..zone_name.len() - 1].to_string()
        } else {
            zone_name.clone()
        };

        let zone = self.zones.get(&zone_origin);

        let rcode = if zone.is_some() {
            wire::RCODE_NOERROR
        } else {
            wire::RCODE_NXDOMAIN
        };

        Some(build_notify_response(query, rcode))
    }

    pub fn notify_secondaries(&self, zone_origin: &str, new_serial: u32) {
        if !self.config.enabled {
            return;
        }

        {
            let notified = self.notified_secondaries.read();
            if let Some(last_serial) = notified.get(zone_origin) {
                if *last_serial == new_serial {
                    tracing::debug!("Serial unchanged for {}, skipping NOTIFY", zone_origin);
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
                            "Sent NOTIFY to {} for zone {} (serial {})",
                            secondary,
                            zone_origin,
                            new_serial
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to send NOTIFY to {} for zone {}: {}",
                            secondary,
                            zone_origin,
                            e
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
                tracing::debug!("NOTIFY packet sent to {}:{}", ip, port);
                Ok(())
            }
            Err(e) => Err(format!("Send error: {}", e)),
        }
    }
}

fn parse_notify_zone_name(query: &[u8], mut pos: usize) -> Option<String> {
    let mut name = String::new();
    let mut jumps = 0;

    while pos < query.len() {
        let len = query[pos] as usize;

        if len == 0 {
            pos += 1;
            break;
        }

        if (len & 0xC0) == 0xC0 {
            if jumps > 10 {
                return None;
            }
            jumps += 1;
            let offset = (len & 0x3F) << 8 | query[pos + 1] as usize;
            pos = offset;
            continue;
        }

        if !name.is_empty() {
            name.push('.');
        }

        pos += 1;
        if pos + len > query.len() {
            return None;
        }

        name.push_str(&String::from_utf8_lossy(&query[pos..pos + len]));
        pos += len;
    }
    let _ = pos;

    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

pub fn build_notify_response(query: &[u8], rcode: u8) -> Vec<u8> {
    if query.len() < 12 {
        return Vec::new();
    }

    let id = u16::from_be_bytes([query[0], query[1]]);

    let flags = wire::MessageFlags {
        is_response: true,
        opcode: wire::OPCODE_NOTIFY,
        authoritative: true,
        truncated: false,
        recursion_desired: false,
        recursion_available: false,
        authentic_data: false,
        response_code: rcode,
    };

    let response = wire::build_response_header(id, flags, 1, 0, 0, 0);

    let mut full_response = response;

    let mut pos = 12;
    let mut question_section = Vec::new();
    while pos < query.len() {
        let len = query[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if pos + 1 + len > query.len() {
            break;
        }
        question_section.push(query[pos]);
        question_section.extend_from_slice(&query[pos + 1..pos + 1 + len]);
        pos += 1 + len;
    }
    question_section.push(0);

    if pos + 4 <= query.len() {
        question_section.extend_from_slice(&query[pos..pos + 4]);
    }

    full_response.extend_from_slice(&question_section);

    full_response
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
        query[2..4].copy_from_slice(&(0x0400u16).to_be_bytes());
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
}
