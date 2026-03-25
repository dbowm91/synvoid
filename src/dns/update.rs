use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

use super::server::{DnsZoneRecord, RecordType, Zone};
use super::wire;

#[derive(Debug, Clone)]
pub struct UpdateZone {
    pub name: String,
    pub class: u16,
}

#[derive(Debug, Clone)]
pub struct UpdatePrerequisite {
    pub name: String,
    pub rtype: u16,
    pub rdata: Vec<u8>,
    pub condition: PrerequisiteCondition,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PrerequisiteCondition {
    Exists,
    NotExists,
    ExistsRRset,
    NotExistsRRset,
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

        let mut pos = 12;

        let zone = if qdcount > 0 {
            let (name, class) = Self::parse_rr(query, pos)?;
            pos = Self::skip_rr(query, pos);
            Some(UpdateZone { name, class })
        } else {
            None
        };

        let mut prerequisites = Vec::new();
        for _ in 0..ancount {
            let (name, rtype, rclass, rdata) = Self::parse_rr_with_rdata(query, pos)?;
            let condition = match rclass {
                1 => PrerequisiteCondition::Exists,
                2 => PrerequisiteCondition::NotExists,
                3 => PrerequisiteCondition::ExistsRRset,
                4 => PrerequisiteCondition::NotExistsRRset,
                _ => PrerequisiteCondition::Exists,
            };
            prerequisites.push(UpdatePrerequisite {
                name,
                rtype,
                rdata,
                condition,
            });
            pos = Self::skip_rr_with_rdata(query, pos);
        }

        let mut updates = Vec::new();
        let total_updates = nscount + arcount;
        for _ in 0..total_updates {
            let (name, rtype, rclass, ttl, rdata) = Self::parse_rr_full(query, pos)?;
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

    fn parse_rr(query: &[u8], pos: usize) -> Result<(String, u16), String> {
        let (name, end_pos) = Self::parse_name(query, pos)?;
        if end_pos + 4 > query.len() {
            return Err("Incomplete RR".to_string());
        }
        let _rtype = u16::from_be_bytes([query[end_pos], query[end_pos + 1]]);
        let zclass = u16::from_be_bytes([query[end_pos + 2], query[end_pos + 3]]);
        Ok((name, zclass))
    }

    fn parse_rr_with_rdata(
        query: &[u8],
        pos: usize,
    ) -> Result<(String, u16, u16, Vec<u8>), String> {
        let (name, end_pos) = Self::parse_name(query, pos)?;
        if end_pos + 6 > query.len() {
            return Err("Incomplete RR".to_string());
        }
        let rtype = u16::from_be_bytes([query[end_pos], query[end_pos + 1]]);
        let rclass = u16::from_be_bytes([query[end_pos + 2], query[end_pos + 3]]);

        let rdata_start = end_pos + 4;
        let rdata = query[rdata_start..].to_vec();

        Ok((name, rtype, rclass, rdata))
    }

    fn parse_rr_full(query: &[u8], pos: usize) -> Result<(String, u16, u16, u32, Vec<u8>), String> {
        let (name, end_pos) = Self::parse_name(query, pos)?;
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
        let rdlen = u16::from_be_bytes([query[end_pos + 8], query[end_pos + 9]]);

        let rdata_start = end_pos + 10;
        let rdata_end = rdata_start + rdlen as usize;
        if rdata_end > query.len() {
            return Err("Incomplete RDATA".to_string());
        }
        let rdata = query[rdata_start..rdata_end].to_vec();

        Ok((name, rtype, rclass, ttl, rdata))
    }

    fn parse_name(query: &[u8], mut pos: usize) -> Result<(String, usize), String> {
        let mut name = String::new();
        let mut jumped = false;
        let mut jumps = 0;

        while pos < query.len() {
            let len = query[pos] as usize;

            if len == 0 {
                pos += 1;
                break;
            }

            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    jumped = true;
                }
                jumps += 1;
                if jumps > 10 {
                    return Err("Too many jumps".to_string());
                }
                let offset = (len & 0x3F) << 8 | query[pos + 1] as usize;
                pos = offset;
                continue;
            }

            if !name.is_empty() {
                name.push('.');
            }

            pos += 1;
            if pos + len > query.len() {
                return Err("Name extends past query".to_string());
            }

            name.push_str(&String::from_utf8_lossy(&query[pos..pos + len]));
            pos += len;
        }

        Ok((name, pos))
    }

    fn skip_rr(query: &[u8], pos: usize) -> usize {
        let (_name, end_pos) = Self::parse_name(query, pos).unwrap_or((String::new(), pos));
        end_pos + 4
    }

    fn skip_rr_with_rdata(query: &[u8], pos: usize) -> usize {
        let (_name, end_pos) = Self::parse_name(query, pos).unwrap_or((String::new(), pos));
        end_pos + 4
    }

    fn skip_rr_full(query: &[u8], pos: usize) -> usize {
        let (_name, end_pos) = Self::parse_name(query, pos).unwrap_or((String::new(), pos));
        if end_pos + 10 > query.len() {
            return query.len();
        }
        let rdlen = u16::from_be_bytes([query[end_pos + 8], query[end_pos + 9]]) as usize;
        end_pos + 10 + rdlen
    }
}

#[derive(Clone)]
pub struct DynamicUpdateHandler {
    zones: Arc<RwLock<HashMap<String, Zone>>>,
    enabled: bool,
    allow_any: bool,
    require_tsig: bool,
    zone_sync: Option<Arc<super::anycast_sync::AnycastZoneSync>>,
}

impl DynamicUpdateHandler {
    pub fn new(zones: Arc<RwLock<HashMap<String, Zone>>>) -> Self {
        Self {
            zones,
            enabled: false,
            allow_any: false,
            require_tsig: false,
            zone_sync: None,
        }
    }

    pub fn with_config(mut self, enabled: bool, allow_any: bool, require_tsig: bool) -> Self {
        self.enabled = enabled;
        self.allow_any = allow_any;
        self.require_tsig = require_tsig;
        self
    }

    pub fn with_zone_sync(mut self, zone_sync: super::anycast_sync::AnycastZoneSync) -> Self {
        self.zone_sync = Some(Arc::new(zone_sync));
        self
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn handle_update(
        &self,
        query: &[u8],
        _client_ip: std::net::IpAddr,
    ) -> Result<Vec<u8>, String> {
        if !self.enabled {
            return Err("Dynamic updates not enabled".to_string());
        }

        let update = DynamicUpdate::parse(query)?;

        let zone = update.zone.ok_or("No zone in UPDATE")?;

        let zone_origin = if zone.name.ends_with('.') {
            zone.name[..zone.name.len() - 1].to_string()
        } else {
            zone.name.clone()
        };

        let mut updated_zone: Zone = {
            let zones = self.zones.read();
            let zone_data = zones.get(&zone_origin).ok_or("Zone not found")?;
            zone_data.clone()
        };

        for prereq in &update.prerequisites {
            if !self.check_prerequisite(&updated_zone, prereq)? {
                return Ok(self.build_response(query, wire::UPDATE_RCODE_YXDOMAIN));
            }
        }

        for update_record in &update.updates {
            match update_record.rclass {
                1 => {
                    updated_zone.records.insert(
                        (
                            update_record.name.clone(),
                            RecordType::from(update_record.rtype),
                        ),
                        vec![DnsZoneRecord {
                            name: update_record.name.clone(),
                            record_type: RecordType::from(update_record.rtype),
                            value: format!("{:?}", update_record.rdata),
                            ttl: update_record.ttl,
                            priority: None,
                        }],
                    );
                }
                2 => {
                    updated_zone.records.remove(&(
                        update_record.name.clone(),
                        RecordType::from(update_record.rtype),
                    ));
                }
                _ => {}
            }
        }

        updated_zone.increment_serial();

        let zone_key = zone_origin.clone();
        let zone_value = updated_zone;
        self.zones.write().insert(zone_key.clone(), zone_value);

        if let Some(ref sync) = self.zone_sync {
            let zone_origin_for_sync = zone_origin.clone();
            let sync_clone = sync.clone();
            tokio::spawn(async move {
                if let Err(e) = sync_clone.trigger_sync(&zone_origin_for_sync, super::anycast_sync::ZoneSyncReason::DynamicUpdate).await {
                    tracing::warn!("Failed to trigger zone sync after dynamic update: {}", e);
                }
            });
        }

        Ok(self.build_response(query, wire::UPDATE_RCODE_NOERROR))
    }

    fn check_prerequisite(&self, zone: &Zone, prereq: &UpdatePrerequisite) -> Result<bool, String> {
        match prereq.condition {
            PrerequisiteCondition::Exists => {
                let records = zone
                    .records
                    .get(&(prereq.name.clone(), RecordType::from(prereq.rtype)));
                Ok(records.is_some() && !records.unwrap().is_empty())
            }
            PrerequisiteCondition::NotExists => {
                let records = zone
                    .records
                    .get(&(prereq.name.clone(), RecordType::from(prereq.rtype)));
                Ok(records.is_none() || records.unwrap().is_empty())
            }
            PrerequisiteCondition::ExistsRRset => {
                let records = zone
                    .records
                    .get(&(prereq.name.clone(), RecordType::from(prereq.rtype)));
                Ok(records.is_some() && !records.unwrap().is_empty())
            }
            PrerequisiteCondition::NotExistsRRset => {
                let records = zone
                    .records
                    .get(&(prereq.name.clone(), RecordType::from(prereq.rtype)));
                Ok(records.is_none() || records.unwrap().is_empty())
            }
        }
    }

    fn build_response(&self, query: &[u8], rcode: u8) -> Vec<u8> {
        if query.len() < 12 {
            return Vec::new();
        }

        let id = u16::from_be_bytes([query[0], query[1]]);

        let flags = wire::MessageFlags {
            is_response: true,
            opcode: wire::OPCODE_UPDATE,
            authoritative: true,
            truncated: false,
            recursion_desired: false,
            recursion_available: false,
            authentic_data: false,
            response_code: rcode,
        };

        wire::build_response_header(id, flags, 0, 0, 0, 0)
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
}
