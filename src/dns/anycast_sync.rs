use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use metrics::counter;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

use crate::dns::server::{DnsZoneRecord, RecordType, ShardedZoneStore, Zone, ZoneHistory};
use crate::mesh::transport::MeshTransport;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SerialComparison {
    RemoteIsNewer,
    LocalIsNewer,
    Equal,
    WrapAround,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ZoneSyncDecision {
    Accept,
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct ZoneSyncMetadata {
    pub zone_origin: String,
    pub serial: u32,
    pub record_count: usize,
    pub timestamp: u64,
    pub source_node_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct SerializedZoneVersion {
    pub serial: u32,
    pub records: Vec<SerializedRecord>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct SerializedZoneData {
    pub origin: String,
    pub serial: u32,
    pub records: Vec<SerializedRecord>,
    pub history: Vec<SerializedZoneVersion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct SerializedIxfrData {
    pub origin: String,
    pub serial: u32,
    pub previous_serial: u32,
    pub changes: Vec<ZoneChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct ZoneChange {
    pub change_type: String,
    pub name: String,
    pub record_type: String,
    pub ttl: u32,
    pub value: Vec<String>,
    pub priority: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct SerializedRecord {
    pub name: String,
    pub record_type: String,
    pub ttl: u32,
    pub value: String,
    pub priority: Option<u32>,
}

pub struct AnycastZoneSync {
    mesh_transport: Option<Arc<MeshTransport>>,
    local_zones: Arc<ShardedZoneStore>,
    node_id: String,
    sync_interval_secs: u64,
    notify_handler: Option<super::notify::NotifyHandler>,
}

#[derive(Debug, Clone)]
pub struct ZoneSyncTrigger {
    pub zone_origin: String,
    pub reason: ZoneSyncReason,
}

#[derive(Debug, Clone)]
pub enum ZoneSyncReason {
    ZoneUpdate,
    DynamicUpdate,
    Axfr,
    Ixfr,
    Manual,
}

impl AnycastZoneSync {
    pub fn new(node_id: String, local_zones: Arc<ShardedZoneStore>) -> Self {
        Self {
            mesh_transport: None,
            local_zones,
            node_id,
            sync_interval_secs: 300,
            notify_handler: None,
        }
    }

    pub fn with_notify_handler(mut self, handler: super::notify::NotifyHandler) -> Self {
        self.notify_handler = Some(handler);
        self
    }

    pub fn with_mesh_transport(mut self, transport: Arc<MeshTransport>) -> Self {
        self.mesh_transport = Some(transport);
        self
    }

    pub fn with_sync_interval(mut self, interval_secs: u64) -> Self {
        self.sync_interval_secs = interval_secs;
        self
    }

    pub async fn trigger_sync(
        &self,
        zone_origin: &str,
        reason: ZoneSyncReason,
    ) -> Result<(), String> {
        let mesh_transport = match &self.mesh_transport {
            Some(t) => t,
            None => return Err("Mesh transport not configured".to_string()),
        };

        let (serial, _record_count) = {
            match self.local_zones.get(zone_origin) {
                Some(zone) => (zone.serial, zone.records.len()),
                None => return Err(format!("Zone {} not found", zone_origin)),
            }
        };

        tracing::info!(
            "Triggering immediate zone sync for {} (serial: {}, reason: {:?})",
            zone_origin,
            serial,
            reason
        );

        let timestamp = crate::utils::safe_unix_timestamp();

        let msg = crate::mesh::protocol::MeshMessage::ZoneSyncRequest {
            request_id: format!("{}-{}-trigger-{}", self.node_id, zone_origin, timestamp).into(),
            zone_origin: zone_origin.into(),
            serial,
            requesting_node_id: self.node_id.clone().into(),
            timestamp,
        };

        let _ = mesh_transport
            .broadcast_to_random_peers(msg, 0.5, Some(crate::mesh::config::MeshNodeRole::GLOBAL))
            .await;

        Ok(())
    }

    pub async fn start_sync_loop(&self) {
        let mesh_transport = self.mesh_transport.clone();
        let local_zones = self.local_zones.clone();
        let node_id = self.node_id.clone();
        let interval = self.sync_interval_secs;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(interval));

            loop {
                interval.tick().await;

                if let Some(ref transport) = mesh_transport {
                    if let Err(e) =
                        Self::broadcast_zone_availability(transport, &local_zones, &node_id).await
                    {
                        tracing::warn!("Zone broadcast failed: {}", e);
                    }
                }
            }
        });
    }

    pub async fn broadcast_single_zone(
        transport: &Arc<MeshTransport>,
        local_zones: &Arc<ShardedZoneStore>,
        node_id: &str,
        zone_origin: &str,
    ) -> Result<(), String> {
        let (serial, _record_count) = {
            match local_zones.get(zone_origin) {
                Some(zone) => (zone.serial, zone.records.len()),
                None => return Err(format!("Zone {} not found", zone_origin)),
            }
        };

        tracing::debug!(
            "Immediately broadcasting zone {} (serial: {}) from node {}",
            zone_origin,
            serial,
            node_id
        );

        let timestamp = crate::utils::safe_unix_timestamp();

        let msg = crate::mesh::protocol::MeshMessage::ZoneSyncRequest {
            request_id: format!("{}-{}-immediate-{}", node_id, zone_origin, timestamp).into(),
            zone_origin: zone_origin.into(),
            serial,
            requesting_node_id: node_id.into(),
            timestamp,
        };

        let _ = transport
            .broadcast_to_random_peers(msg, 0.8, Some(crate::mesh::config::MeshNodeRole::GLOBAL))
            .await;

        Ok(())
    }

    async fn broadcast_zone_availability(
        transport: &Arc<MeshTransport>,
        local_zones: &Arc<ShardedZoneStore>,
        node_id: &str,
    ) -> Result<(), String> {
        let zones: Vec<String> = local_zones.keys();

        if zones.is_empty() {
            return Ok(());
        }

        tracing::debug!(
            "Broadcasting zone availability for {:?} from node {}",
            zones,
            node_id
        );

        for zone_origin in zones {
            let (serial, _record_count) = {
                if let Some(zone) = local_zones.get(&zone_origin) {
                    (zone.serial, zone.records.len())
                } else {
                    continue;
                }
            };

            let timestamp = crate::utils::safe_unix_timestamp();

            let msg = crate::mesh::protocol::MeshMessage::ZoneSyncRequest {
                request_id: format!("{}-{}", node_id, timestamp).into(),
                zone_origin: zone_origin.clone().into(),
                serial,
                requesting_node_id: node_id.into(),
                timestamp,
            };

            let _ = transport
                .broadcast_to_random_peers(
                    msg,
                    0.3,
                    Some(crate::mesh::config::MeshNodeRole::GLOBAL),
                )
                .await;
        }

        Ok(())
    }

    pub fn serialize_zone(&self, zone_origin: &str) -> Option<SerializedZoneData> {
        let zone = self.local_zones.get(zone_origin)?;

        let records: Vec<SerializedRecord> = zone
            .records
            .iter()
            .flat_map(|((name, record_type), records)| {
                records
                    .iter()
                    .map(|r| SerializedRecord {
                        name: name.clone(),
                        record_type: record_type.to_string(),
                        ttl: r.ttl,
                        value: r.value.clone(),
                        priority: r.priority,
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        let history: Vec<SerializedZoneVersion> = zone
            .history
            .iter()
            .map(|h| {
                let records: Vec<SerializedRecord> = h
                    .records
                    .iter()
                    .flat_map(|((name, record_type), records)| {
                        records
                            .iter()
                            .map(|r| SerializedRecord {
                                name: name.clone(),
                                record_type: record_type.to_string(),
                                ttl: r.ttl,
                                value: r.value.clone(),
                                priority: r.priority,
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect();

                SerializedZoneVersion {
                    serial: h.serial,
                    records,
                    timestamp: h.timestamp,
                }
            })
            .collect();

        Some(SerializedZoneData {
            origin: zone.origin.clone(),
            serial: zone.serial,
            records,
            history,
        })
    }

    pub fn serialize_zone_to_json(&self, zone_origin: &str) -> Option<String> {
        self.serialize_zone(zone_origin)
            .and_then(|data| serde_json::to_string(&data).ok())
    }

    pub fn serialize_ixfr_diff(
        &self,
        zone_origin: &str,
        previous_serial: u32,
    ) -> Option<SerializedIxfrData> {
        let zone = self.local_zones.get(zone_origin)?;

        if zone.serial <= previous_serial {
            return None;
        }

        let old_records: HashMap<(String, RecordType), Vec<DnsZoneRecord>> = zone
            .history
            .iter()
            .find(|h| h.serial == previous_serial)
            .map(|h| h.records.clone())
            .unwrap_or_default();

        let mut old_record_map: HashMap<(String, RecordType), Vec<DnsZoneRecord>> = HashMap::new();
        for (key, records) in &old_records {
            for record in records {
                old_record_map
                    .entry(key.clone())
                    .or_default()
                    .push(record.clone());
            }
        }

        let mut changes = Vec::new();
        let mut all_keys: HashSet<(String, RecordType)> = HashSet::new();
        for key in old_record_map.keys() {
            all_keys.insert(key.clone());
        }
        for key in zone.records.keys() {
            all_keys.insert(key.clone());
        }

        for (name, record_type) in all_keys {
            let old_recs = old_record_map.get(&(name.clone(), record_type));
            let new_recs = zone.records.get(&(name.clone(), record_type));

            match (old_recs, new_recs) {
                (Some(old), None) => {
                    for r in old {
                        changes.push(ZoneChange {
                            change_type: "delete".to_string(),
                            name: name.clone(),
                            record_type: record_type.to_string(),
                            ttl: r.ttl,
                            value: vec![r.value.clone()],
                            priority: r.priority,
                        });
                    }
                }
                (None, Some(new)) => {
                    for r in new {
                        changes.push(ZoneChange {
                            change_type: "add".to_string(),
                            name: name.clone(),
                            record_type: record_type.to_string(),
                            ttl: r.ttl,
                            value: vec![r.value.clone()],
                            priority: r.priority,
                        });
                    }
                }
                (Some(old), Some(new)) => {
                    let old_values: Vec<_> = old.iter().map(|r| r.value.clone()).collect();
                    let new_values: Vec<_> = new.iter().map(|r| r.value.clone()).collect();
                    if old_values != new_values || old.len() != new.len() {
                        for r in old {
                            changes.push(ZoneChange {
                                change_type: "delete".to_string(),
                                name: name.clone(),
                                record_type: record_type.to_string(),
                                ttl: r.ttl,
                                value: vec![r.value.clone()],
                                priority: r.priority,
                            });
                        }
                        for r in new {
                            changes.push(ZoneChange {
                                change_type: "add".to_string(),
                                name: name.clone(),
                                record_type: record_type.to_string(),
                                ttl: r.ttl,
                                value: vec![r.value.clone()],
                                priority: r.priority,
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        Some(SerializedIxfrData {
            origin: zone_origin.to_string(),
            serial: zone.serial,
            previous_serial,
            changes,
        })
    }

    pub fn serialize_ixfr_diff_to_json(
        &self,
        zone_origin: &str,
        previous_serial: u32,
    ) -> Option<String> {
        self.serialize_ixfr_diff(zone_origin, previous_serial)
            .and_then(|data| serde_json::to_string(&data).ok())
    }

    pub fn get_zone_version(
        &self,
        zone_origin: &str,
        serial: u32,
    ) -> Option<SerializedZoneVersion> {
        let zone = self.local_zones.get(zone_origin)?;

        if zone.serial == serial {
            let records: Vec<SerializedRecord> = zone
                .records
                .iter()
                .flat_map(|((name, record_type), records)| {
                    records
                        .iter()
                        .map(|r| SerializedRecord {
                            name: name.clone(),
                            record_type: record_type.to_string(),
                            ttl: r.ttl,
                            value: r.value.clone(),
                            priority: r.priority,
                        })
                        .collect::<Vec<_>>()
                })
                .collect();

            return Some(SerializedZoneVersion {
                serial: zone.serial,
                records,
                timestamp: crate::utils::safe_unix_timestamp(),
            });
        }

        zone.history.iter().find(|h| h.serial == serial).map(|h| {
            let records: Vec<SerializedRecord> = h
                .records
                .iter()
                .flat_map(|((name, record_type), records)| {
                    records
                        .iter()
                        .map(|r| SerializedRecord {
                            name: name.clone(),
                            record_type: record_type.to_string(),
                            ttl: r.ttl,
                            value: r.value.clone(),
                            priority: r.priority,
                        })
                        .collect::<Vec<_>>()
                })
                .collect();

            SerializedZoneVersion {
                serial: h.serial,
                records,
                timestamp: h.timestamp,
            }
        })
    }

    pub fn deserialize_zone(&self, json_data: &str) -> Result<Zone, String> {
        let data: SerializedZoneData = serde_json::from_str(json_data)
            .map_err(|e| format!("Failed to parse zone data: {}", e))?;

        let mut records: HashMap<(String, RecordType), Vec<DnsZoneRecord>> = HashMap::new();

        for record in data.records {
            let record_type = match record.record_type.to_uppercase().as_str() {
                "A" => RecordType::A,
                "AAAA" => RecordType::AAAA,
                "CNAME" => RecordType::CNAME,
                "MX" => RecordType::MX,
                "TXT" => RecordType::TXT,
                "NS" => RecordType::NS,
                "SOA" => RecordType::SOA,
                "PTR" => RecordType::PTR,
                "SRV" => RecordType::SRV,
                "DNSKEY" => RecordType::DNSKEY,
                "RRSIG" => RecordType::RRSIG,
                "NSEC" => RecordType::NSEC,
                "NSEC3" => RecordType::NSEC3,
                "DS" => RecordType::DS,
                "CAA" => RecordType::CAA,
                _ => continue,
            };

            let entry = records
                .entry((record.name.clone(), record_type))
                .or_default();
            entry.push(DnsZoneRecord {
                name: record.name,
                record_type,
                ttl: record.ttl,
                value: record.value,
                priority: record.priority,
            });
        }

        let history: Vec<ZoneHistory> = data
            .history
            .iter()
            .map(|hv| {
                let mut hrecords: HashMap<(String, RecordType), Vec<DnsZoneRecord>> =
                    HashMap::new();
                for record in &hv.records {
                    let record_type = match record.record_type.to_uppercase().as_str() {
                        "A" => RecordType::A,
                        "AAAA" => RecordType::AAAA,
                        "CNAME" => RecordType::CNAME,
                        "MX" => RecordType::MX,
                        "TXT" => RecordType::TXT,
                        "NS" => RecordType::NS,
                        "SOA" => RecordType::SOA,
                        "PTR" => RecordType::PTR,
                        "SRV" => RecordType::SRV,
                        "DNSKEY" => RecordType::DNSKEY,
                        "RRSIG" => RecordType::RRSIG,
                        "NSEC" => RecordType::NSEC,
                        "NSEC3" => RecordType::NSEC3,
                        "DS" => RecordType::DS,
                        "CAA" => RecordType::CAA,
                        _ => continue,
                    };
                    let entry = hrecords
                        .entry((record.name.clone(), record_type))
                        .or_default();
                    entry.push(DnsZoneRecord {
                        name: record.name.clone(),
                        record_type,
                        ttl: record.ttl,
                        value: record.value.clone(),
                        priority: record.priority,
                    });
                }
                ZoneHistory {
                    serial: hv.serial,
                    records: hrecords,
                    timestamp: hv.timestamp,
                }
            })
            .collect();

        Ok(Zone {
            origin: data.origin,
            records,
            serial: data.serial,
            ksk_key: None,
            zsk_key: None,
            dnskey_ttl: None,
            nsec3_enabled: false,
            nsec_enabled: false,
            nsec3param: None,
            history,
        })
    }

    pub fn should_accept_zone_update(local_serial: u32, remote_serial: u32) -> ZoneSyncDecision {
        let serial_cmp = Self::compare_serials(local_serial, remote_serial);

        match serial_cmp {
            SerialComparison::RemoteIsNewer => {
                tracing::debug!(
                    "Remote zone is newer (local={}, remote={}), accepting",
                    local_serial,
                    remote_serial
                );
                ZoneSyncDecision::Accept
            }
            SerialComparison::LocalIsNewer => {
                tracing::debug!(
                    "Local zone is newer (local={}, remote={}), rejecting",
                    local_serial,
                    remote_serial
                );
                ZoneSyncDecision::Reject
            }
            SerialComparison::Equal | SerialComparison::WrapAround => {
                tracing::debug!(
                    "Serial comparison: local={}, remote={}, rejecting",
                    local_serial,
                    remote_serial
                );
                ZoneSyncDecision::Reject
            }
        }
    }

    pub fn compare_serials(local: u32, remote: u32) -> SerialComparison {
        const HALF_U32: u32 = u32::MAX / 2;
        let diff = remote.wrapping_sub(local);

        if diff == 0 {
            SerialComparison::Equal
        } else if diff <= HALF_U32 {
            SerialComparison::RemoteIsNewer
        } else if local.wrapping_sub(remote) <= HALF_U32 {
            SerialComparison::LocalIsNewer
        } else {
            SerialComparison::WrapAround
        }
    }

    pub fn apply_remote_zone(
        &self,
        remote_zone: Zone,
        source_node_id: &str,
    ) -> Result<bool, String> {
        let zone_origin = remote_zone.origin.clone();
        let remote_serial = remote_zone.serial;

        let should_accept = {
            if let Some(local_zone) = self.local_zones.get(&zone_origin) {
                let local_serial = local_zone.serial;

                let decision = Self::compare_and_decide(local_serial, remote_serial);

                match decision {
                    ZoneSyncDecision::Accept => {
                        counter!("dns_zone_sync_accepted_total").increment(1);
                        true
                    }
                    ZoneSyncDecision::Reject => {
                        counter!("dns_zone_sync_rejected_total").increment(1);
                        false
                    }
                }
            } else {
                counter!("dns_zone_sync_new_zone_total").increment(1);
                true
            }
        };

        if should_accept {
            self.local_zones.insert(zone_origin.clone(), remote_zone);
            tracing::info!(
                "Accepted remote zone {} (serial: {}) from node {}",
                zone_origin,
                remote_serial,
                source_node_id
            );
            Ok(true)
        } else {
            tracing::debug!(
                "Rejected zone {} update from {} (local serial: {} >= remote: {})",
                zone_origin,
                source_node_id,
                self.get_zone_serial(&zone_origin).unwrap_or(0),
                remote_serial
            );
            Ok(false)
        }
    }

    pub fn apply_remote_zone_from_json(
        &self,
        json_data: &str,
        source_node_id: &str,
    ) -> Result<bool, String> {
        let remote_zone = self.deserialize_zone(json_data)?;
        self.apply_remote_zone(remote_zone, source_node_id)
    }

    fn compare_and_decide(local_serial: u32, remote_serial: u32) -> ZoneSyncDecision {
        let cmp = Self::compare_serials(local_serial, remote_serial);
        match cmp {
            SerialComparison::RemoteIsNewer => ZoneSyncDecision::Accept,
            SerialComparison::LocalIsNewer => ZoneSyncDecision::Reject,
            SerialComparison::Equal => ZoneSyncDecision::Reject,
            SerialComparison::WrapAround => ZoneSyncDecision::Reject,
        }
    }

    pub fn get_zone_serial(&self, zone_origin: &str) -> Option<u32> {
        self.local_zones.get_serial(zone_origin)
    }

    pub fn get_origin_for_zone(&self, zone_origin: &str) -> Option<String> {
        self.local_zones.get_origin(zone_origin)
    }

    pub async fn request_zone_from_peers(&self, zone_origin: &str) -> Result<Option<Zone>, String> {
        let Some(ref transport) = self.mesh_transport else {
            return Err("Mesh transport not configured".to_string());
        };

        tracing::info!("Requesting zone {} from mesh peers", zone_origin);

        let request_id = format!(
            "{}-{}-{}",
            zone_origin,
            self.node_id,
            chrono::Utc::now().timestamp()
        );
        let current_serial = self.get_zone_serial(zone_origin).unwrap_or(0);

        let message = crate::mesh::protocol::MeshMessage::ZoneSyncRequest {
            request_id: request_id.into(),
            zone_origin: zone_origin.into(),
            serial: current_serial,
            requesting_node_id: self.node_id.clone().into(),
            timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
        };

        let (_sent, failed) = transport
            .broadcast_to_random_peers(
                message,
                0.3,
                Some(crate::mesh::config::MeshNodeRole::GLOBAL),
            )
            .await;
        if failed > 0 {
            tracing::warn!("Failed to send zone sync request to {} peers", failed);
        }

        Ok(None)
    }

    pub async fn request_ixfr_from_peer(
        &self,
        zone_origin: &str,
        target_node_id: &str,
        client_serial: u32,
    ) -> Result<Option<SerializedIxfrData>, String> {
        let Some(ref transport) = self.mesh_transport else {
            return Err("Mesh transport not configured".to_string());
        };

        tracing::info!(
            "Requesting IXFR for {} from peer {} (client serial: {})",
            zone_origin,
            target_node_id,
            client_serial
        );

        let request_id = format!(
            "{}-{}-ixfr-{}",
            zone_origin,
            self.node_id,
            chrono::Utc::now().timestamp()
        );

        let message = crate::mesh::protocol::MeshMessage::ZoneSyncRequest {
            request_id: request_id.into(),
            zone_origin: zone_origin.into(),
            serial: client_serial,
            requesting_node_id: self.node_id.clone().into(),
            timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
        };

        let _ = transport
            .send_datagram_to_peer(target_node_id, &message)
            .await;

        Ok(None)
    }

    pub fn get_ixfr_data_for_peer(
        &self,
        zone_origin: &str,
        requesting_serial: u32,
    ) -> Option<SerializedIxfrData> {
        let current_serial = self.get_zone_serial(zone_origin)?;

        if current_serial == requesting_serial {
            tracing::debug!("Peer has current serial {}, no IXFR needed", current_serial);
            return None;
        }

        if requesting_serial == 0 {
            tracing::debug!("Peer has serial 0, full zone transfer needed");
            return None;
        }

        self.serialize_ixfr_diff(zone_origin, requesting_serial)
    }

    pub fn should_send_full_zone(&self, zone_origin: &str, requesting_serial: u32) -> bool {
        let current_serial = match self.get_zone_serial(zone_origin) {
            Some(s) => s,
            None => return true,
        };

        if requesting_serial == 0 {
            return true;
        }

        if requesting_serial >= current_serial {
            return true;
        }

        if self
            .serialize_ixfr_diff(zone_origin, requesting_serial)
            .is_none()
        {
            return true;
        }

        false
    }

    pub fn get_local_zone(&self, zone_origin: &str) -> Option<Zone> {
        self.local_zones.get(zone_origin)
    }

    pub fn get_all_local_zones(&self) -> Vec<String> {
        self.local_zones.keys()
    }

    pub fn update_local_zone(&self, zone: Zone) -> Result<(), String> {
        let origin = zone.origin.clone();

        self.local_zones.insert(origin.clone(), zone);

        tracing::info!("Updated local zone: {}", origin);

        if let Some(ref notify_handler) = self.notify_handler {
            notify_handler.trigger_zone_change(&origin);
        }

        Ok(())
    }

    pub fn remove_local_zone(&self, zone_origin: &str) -> bool {
        self.local_zones.remove(zone_origin).is_some()
    }

    pub fn get_zone_count(&self) -> usize {
        self.local_zones.len()
    }

    pub fn create_zone_sync_handler(
        &self,
    ) -> impl Fn(
        String,
        String,
        u32,
        String,
    ) -> futures::future::BoxFuture<'static, (String, String, u32, bool)>
           + Send
           + Sync
           + 'static {
        move |_zone_origin: String,
              _requesting_node_id: String,
              _serial: u32,
              _peer_id: String|
              -> futures::future::BoxFuture<'static, (String, String, u32, bool)> {
            async move {
                (
                    "{\"error\": \"Zone sync handler needs full integration\"}".to_string(),
                    "".to_string(),
                    0,
                    false,
                )
            }
            .boxed()
        }
    }
}
