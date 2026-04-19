#![allow(dead_code)]
// SAFETY_REASON: Reserved for future DNS mesh protocol handling

use crate::mesh::transport::MeshTransport;
use crate::utils::current_timestamp;
use base64::Engine;
use flate2::read::ZlibDecoder as ReadZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;

#[cfg(feature = "dns")]
use crate::dns::server::Zone as DnsZone;

use metrics::{counter, gauge};

use crate::mesh::protocol::MeshMessage;

impl MeshTransport {
    pub(crate) async fn handle_anycast_registration(
        &self,
        _from_peer: &str,
        _request_id: &str,
        registration: crate::dns::messages::DnsAnycastNodeRegistration,
    ) {
        tracing::debug!(
            "Received anycast node registration for node: {}",
            registration.node_id
        );

        if !self
            .config
            .role
            .contains(crate::mesh::config::MeshNodeRole::GLOBAL)
        {
            tracing::warn!("Received anycast registration on non-global node");
            return;
        }

        let dns_registry = match &self.dns_registry {
            Some(r) => r,
            None => {
                tracing::warn!("DNS registry not available for anycast registration");
                return;
            }
        };

        if let Err(e) = dns_registry
            .register_anycast_node(registration.clone())
            .await
        {
            tracing::error!("Failed to register anycast node: {}", e);
            return;
        }

        self.broadcast_anycast_node_registration(&registration)
            .await;

        tracing::info!(
            "Anycast node {} registered successfully",
            registration.node_id
        );
    }

    pub(crate) async fn broadcast_anycast_node_registration(
        &self,
        registration: &crate::dns::messages::DnsAnycastNodeRegistration,
    ) {
        use crate::mesh::protocol::ArcStr;

        let global_nodes = self.topology.get_global_nodes().await;

        let message = MeshMessage::AnycastNodeRegistration {
            request_id: ArcStr::new(format!(
                "{}-broadcast-{}",
                registration.node_id,
                chrono::Utc::now().timestamp()
            )),
            node_id: ArcStr::new(registration.node_id.clone()),
            anycast_ips: registration.anycast_ips.clone(),
            geo: registration.geo.as_ref().map(|g| ArcStr::new(g.clone())),
            capacity: registration.capacity,
            healthy: registration.healthy,
            dns_zones: registration.dns_zones.clone(),
            certificate_fingerprint: registration
                .certificate_fingerprint
                .as_ref()
                .map(|c| ArcStr::new(c.clone())),
            timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
        };

        for node_id in global_nodes {
            if node_id == self.config.node_id() {
                continue;
            }

            if let Err(e) = self.send_datagram_to_peer(&node_id, &message).await {
                tracing::debug!(
                    "Failed to broadcast anycast registration to {}: {}",
                    node_id,
                    e
                );
            }
        }
    }

    pub(crate) async fn handle_anycast_health_update(
        &self,
        _peer_id: &str,
        node_id: &str,
        anycast_ips: Vec<String>,
        healthy: bool,
        latency_ms: Option<u32>,
        load_percent: Option<u8>,
    ) {
        tracing::debug!(
            "Received anycast health update from {}: healthy={}",
            node_id,
            healthy
        );

        counter!("dns_anycast_health_updates_total").increment(1);

        if let Some(latency) = latency_ms {
            gauge!("dns_anycast_node_latency_ms").set(latency as f64);
        }
        if let Some(load) = load_percent {
            gauge!("dns_anycast_node_load_percent").set(load as f64);
        }

        if !self
            .config
            .role
            .contains(crate::mesh::config::MeshNodeRole::GLOBAL)
        {
            return;
        }

        let dns_registry = match &self.dns_registry {
            Some(r) => r,
            None => return,
        };

        let update = crate::dns::messages::DnsAnycastHealthUpdate {
            node_id: node_id.to_string(),
            anycast_ips,
            healthy,
            latency_ms,
            load_percent,
            timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
        };

        if let Err(e) = dns_registry.update_anycast_health(update).await {
            tracing::error!("Failed to update anycast health: {}", e);
            counter!("dns_anycast_health_update_errors_total").increment(1);
        }
    }

    pub(crate) async fn handle_zone_sync_request(
        &self,
        peer_id: &str,
        request_id: &str,
        zone_origin: &str,
        client_serial: u32,
        requesting_node_id: &str,
    ) {
        tracing::debug!(
            "Received zone sync request for zone: {} from node: {} (client serial: {})",
            zone_origin,
            requesting_node_id,
            client_serial
        );

        let (records_json, response_serial, complete, previous_serial) = if let Some(
            ref dns_registry,
        ) = self.dns_registry
        {
            let nodes = dns_registry.get_all_healthy_origin_nodes();

            let is_origin = nodes.iter().any(|node| {
                node.domains.contains(&zone_origin.to_string())
                    && node.node_id == self.config.node_id()
            });

            if is_origin {
                let zone_opt = if let Some(ref zones) = *self.dns_zones.read() {
                    zones.get(zone_origin)
                } else {
                    None
                };

                if let Some(zone) = zone_opt {
                    let current_serial = zone.serial;

                    if client_serial == current_serial {
                        // Client has latest
                        (
                            serde_json::json!({
                                "status": "up_to_date",
                                "serial": current_serial
                            })
                            .to_string(),
                            current_serial,
                            true,
                            client_serial,
                        )
                    } else if client_serial == 0 || client_serial > current_serial {
                        // Client needs full transfer
                        let records: Vec<crate::dns::anycast_sync::SerializedRecord> = zone
                            .records
                            .iter()
                            .flat_map(|((name, rt), records)| {
                                records
                                    .iter()
                                    .map(|r| crate::dns::anycast_sync::SerializedRecord {
                                        name: name.clone(),
                                        record_type: rt.to_string(),
                                        ttl: r.ttl,
                                        value: r.value.clone(),
                                        priority: r.priority,
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .collect();

                        let json =
                            serde_json::to_string(&crate::dns::anycast_sync::SerializedZoneData {
                                origin: zone.origin.clone(),
                                serial: zone.serial,
                                records,
                                history: vec![],
                            })
                            .unwrap_or_else(|_| "{}".to_string());

                        (json, zone.serial, true, client_serial)
                    } else {
                        // Client has older version - try IXFR from history
                        tracing::info!(
                            "Zone {} updated from serial {} to {}, attempting IXFR",
                            zone_origin,
                            client_serial,
                            current_serial
                        );

                        // Try to get the client's version from history
                        let old_records = zone
                            .get_previous_version(client_serial)
                            .map(|old_version| old_version.records.clone());

                        if let Some(old_records) = old_records {
                            // Compute IXFR: find additions and deletions
                            let mut changes = Vec::new();

                            let all_keys: std::collections::HashSet<_> =
                                zone.records.keys().chain(old_records.keys()).collect();

                            for key in all_keys {
                                let new_recs = zone.records.get(key);
                                let old_recs = old_records.get(key);

                                match (new_recs, old_recs) {
                                    (Some(new), Some(old)) => {
                                        // Check if records differ
                                        let changed = new.len() != old.len()
                                            || new
                                                .iter()
                                                .zip(old.iter())
                                                .any(|(a, b)| a.value != b.value || a.ttl != b.ttl);

                                        if changed {
                                            // Changed - treat as delete + add
                                            changes.push(crate::dns::anycast_sync::ZoneChange {
                                                change_type: "delete".to_string(),
                                                name: key.0.clone(),
                                                record_type: key.1.to_string(),
                                                ttl: old.iter().map(|r| r.ttl).next().unwrap_or(0),
                                                value: old
                                                    .iter()
                                                    .map(|r| r.value.clone())
                                                    .collect::<Vec<_>>(),
                                                priority: old
                                                    .iter()
                                                    .map(|r| r.priority)
                                                    .next()
                                                    .flatten(),
                                            });
                                            changes.push(crate::dns::anycast_sync::ZoneChange {
                                                change_type: "add".to_string(),
                                                name: key.0.clone(),
                                                record_type: key.1.to_string(),
                                                ttl: new.iter().map(|r| r.ttl).next().unwrap_or(0),
                                                value: new
                                                    .iter()
                                                    .map(|r| r.value.clone())
                                                    .collect::<Vec<_>>(),
                                                priority: new
                                                    .iter()
                                                    .map(|r| r.priority)
                                                    .next()
                                                    .flatten(),
                                            });
                                        }
                                    }
                                    (Some(new), None) => {
                                        // Added
                                        changes.push(crate::dns::anycast_sync::ZoneChange {
                                            change_type: "add".to_string(),
                                            name: key.0.clone(),
                                            record_type: key.1.to_string(),
                                            ttl: new.iter().map(|r| r.ttl).next().unwrap_or(0),
                                            value: new
                                                .iter()
                                                .map(|r| r.value.clone())
                                                .collect::<Vec<_>>(),
                                            priority: new
                                                .iter()
                                                .map(|r| r.priority)
                                                .next()
                                                .flatten(),
                                        });
                                    }
                                    (None, Some(old)) => {
                                        // Deleted
                                        changes.push(crate::dns::anycast_sync::ZoneChange {
                                            change_type: "delete".to_string(),
                                            name: key.0.clone(),
                                            record_type: key.1.to_string(),
                                            ttl: old.iter().map(|r| r.ttl).next().unwrap_or(0),
                                            value: old
                                                .iter()
                                                .map(|r| r.value.clone())
                                                .collect::<Vec<_>>(),
                                            priority: old
                                                .iter()
                                                .map(|r| r.priority)
                                                .next()
                                                .flatten(),
                                        });
                                    }
                                    _ => {}
                                }
                            }

                            let json = serde_json::to_string(
                                &crate::dns::anycast_sync::SerializedIxfrData {
                                    origin: zone.origin.clone(),
                                    serial: zone.serial,
                                    previous_serial: client_serial,
                                    changes,
                                },
                            )
                            .unwrap_or_else(|_| "{}".to_string());

                            (json, zone.serial, true, client_serial)
                        } else {
                            // No history available - send full AXFR
                            tracing::warn!(
                                "No history for serial {}, sending full AXFR",
                                client_serial
                            );

                            let records: Vec<crate::dns::anycast_sync::SerializedRecord> = zone
                                .records
                                .iter()
                                .flat_map(|((name, rt), records)| {
                                    records
                                        .iter()
                                        .map(|r| crate::dns::anycast_sync::SerializedRecord {
                                            name: name.clone(),
                                            record_type: rt.to_string(),
                                            ttl: r.ttl,
                                            value: r.value.clone(),
                                            priority: r.priority,
                                        })
                                        .collect::<Vec<_>>()
                                })
                                .collect();

                            let json = serde_json::to_string(
                                &crate::dns::anycast_sync::SerializedZoneData {
                                    origin: zone.origin.clone(),
                                    serial: zone.serial,
                                    records,
                                    history: vec![],
                                },
                            )
                            .unwrap_or_else(|_| "{}".to_string());

                            (json, zone.serial, true, client_serial)
                        }
                    }
                } else {
                    (
                        serde_json::json!({
                            "error": "Zone not found in local storage",
                            "zone": zone_origin
                        })
                        .to_string(),
                        0,
                        false,
                        0,
                    )
                }
            } else {
                (serde_json::json!({
                    "error": "Not origin node for zone",
                    "zone": zone_origin,
                    "available_origins": nodes.iter().filter(|n| n.domains.contains(&zone_origin.to_string())).map(|n| &n.node_id).collect::<Vec<_>>()
                }).to_string(), 0, false, 0)
            }
        } else {
            (
                serde_json::json!({
                    "error": "No DNS registry available"
                })
                .to_string(),
                0,
                false,
                0,
            )
        };

        let (compressed, final_json) = if records_json.len() > 1024 {
            use std::io::Write;
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            if encoder.write_all(records_json.as_bytes()).is_ok() {
                match encoder.finish() {
                    Ok(compressed) => {
                        let encoded = base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            &compressed,
                        );
                        tracing::debug!(
                            "Compressed zone {} from {} to {} bytes",
                            zone_origin,
                            records_json.len(),
                            encoded.len()
                        );
                        (true, encoded)
                    }
                    Err(_) => (false, records_json),
                }
            } else {
                (false, records_json)
            }
        } else {
            (false, records_json)
        };

        let (origin_signature, origin_pubkey) = if let Some(ref signer) = self.origin_ed25519_signer
        {
            let sign_data = format!("{}|{}|{}", zone_origin, final_json, response_serial);
            let sig = signer.sign(&sign_data);
            (
                sig.into_bytes(),
                self.config
                    .origin_signing_key
                    .as_ref()
                    .and_then(|k| k.public_key_base64.clone()),
            )
        } else {
            (Vec::new(), None)
        };

        let response = crate::mesh::protocol::MeshMessage::ZoneSyncResponse {
            request_id: request_id.into(),
            zone_origin: zone_origin.into(),
            records_json: final_json.into(),
            serial: response_serial,
            complete,
            timestamp: crate::mesh::protocol::MeshMessage::generate_timestamp(),
            origin_signature,
            origin_pubkey,
            previous_serial,
            compressed,
        };

        if let Err(e) = self.send_datagram_to_peer(peer_id, &response).await {
            tracing::warn!("Failed to send zone sync response to {}: {}", peer_id, e);
        }
    }

    pub(crate) async fn handle_zone_sync_response(
        &self,
        peer_id: &str,
        _request_id: &str,
        zone_origin: &str,
        records_json: &str,
        serial: u32,
        complete: bool,
        origin_signature: &[u8],
        origin_pubkey: Option<&str>,
        previous_serial: u32,
        compressed: bool,
    ) {
        if !self.config.role.is_global() {
            tracing::debug!("Ignoring zone sync response on non-global node");
            return;
        }

        tracing::debug!("Received zone sync response for zone: {} (serial: {}, complete: {}, prev_serial: {}, compressed: {})", 
            zone_origin, serial, complete, previous_serial, compressed);

        let final_json = if compressed {
            match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, records_json) {
                Ok(compressed_data) => {
                    use std::io::Read;
                    let mut decoder = ReadZlibDecoder::new(compressed_data.as_slice());
                    let mut decompressed = String::new();
                    match decoder.read_to_string(&mut decompressed) {
                        Ok(_) => {
                            tracing::debug!(
                                "Decompressed zone {} from {} to {} bytes",
                                zone_origin,
                                records_json.len(),
                                decompressed.len()
                            );
                            decompressed
                        }
                        Err(e) => {
                            tracing::warn!("Failed to decompress zone {}: {}", zone_origin, e);
                            records_json.to_string()
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to decode base64 for zone {}: {}", zone_origin, e);
                    records_json.to_string()
                }
            }
        } else {
            records_json.to_string()
        };

        let verified = if !origin_signature.is_empty() && origin_pubkey.is_some() {
            let sign_data = format!("{}|{}|{}", zone_origin, final_json, serial);
            if let Some(pubkey_str) = origin_pubkey {
                if let Ok(pubkey_bytes) =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, pubkey_str)
                {
                    crate::integrity::signing::verify_ed25519_raw(
                        &pubkey_bytes,
                        &sign_data,
                        origin_signature,
                    )
                } else {
                    tracing::warn!("Failed to decode public key for zone sync verification");
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        if verified {
            tracing::info!(
                "Zone {} signature verified (serial: {})",
                zone_origin,
                serial
            );
            counter!("dns_zone_sync_signature_verified_total").increment(1);
        } else if !origin_signature.is_empty() {
            tracing::warn!("Zone {} signature verification FAILED", zone_origin);
            counter!("dns_zone_sync_signature_failed_total").increment(1);
        }

        if complete {
            let should_accept = {
                let zones_guard = self.dns_zones.read();
                if let Some(ref zones) = *zones_guard {
                    if let Some(local_zone) = zones.get(zone_origin) {
                        let local_serial = local_zone.serial;
                        let remote_newer = serial.wrapping_sub(local_serial) <= (u32::MAX / 2);
                        if remote_newer {
                            counter!("dns_zone_sync_accepted_total").increment(1);
                            true
                        } else {
                            counter!("dns_zone_sync_rejected_total").increment(1);
                            tracing::debug!(
                                "Rejecting zone {} sync: local serial {} >= remote {}",
                                zone_origin,
                                local_serial,
                                serial
                            );
                            false
                        }
                    } else {
                        counter!("dns_zone_sync_new_zone_total").increment(1);
                        true
                    }
                } else {
                    false
                }
            };

            if should_accept {
                if let Ok(data) = serde_json::from_str::<serde_json::Value>(&final_json) {
                    tracing::debug!("Zone sync data for {}: {:?}", zone_origin, data);
                }

                if let Some(ref zones) = *self.dns_zones.read() {
                    if let Ok(zone) = Self::parse_zone_from_json(zone_origin, &final_json, serial) {
                        zones.insert(zone_origin.to_string(), zone);
                        tracing::info!(
                            "Applied zone {} from peer {} (serial: {})",
                            zone_origin,
                            peer_id,
                            serial
                        );
                    } else {
                        tracing::warn!("Failed to parse zone {} from sync response", zone_origin);
                    }
                }
            }

            tracing::info!("Zone {} sync completed with serial {}", zone_origin, serial);
            counter!("dns_zone_sync_completed_total").increment(1);

            let bytes = records_json.len() as u64;
            counter!("dns_zone_sync_bytes_total").increment(bytes);

            if compressed {
                counter!("dns_zone_sync_compressed_total").increment(1);
            }

            if previous_serial > 0 && previous_serial != serial {
                counter!("dns_zone_sync_ixfr_total").increment(1);
            } else {
                counter!("dns_zone_sync_axfr_total").increment(1);
            }
        }
    }

    pub(crate) async fn handle_zone_sync_ack(
        &self,
        _peer_id: &str,
        _request_id: &str,
        zone_origin: &str,
        serial: u64,
    ) {
        if !self.config.role.is_global() {
            tracing::debug!("Ignoring zone sync ACK on non-global node");
            return;
        }

        tracing::debug!(
            "Received zone sync ACK for zone: {} serial: {}",
            zone_origin,
            serial
        );
    }

    pub(crate) fn parse_zone_from_json(
        origin: &str,
        json_data: &str,
        serial: u32,
    ) -> Result<DnsZone, String> {
        use crate::dns::RecordType;

        let data: serde_json::Value = serde_json::from_str(json_data)
            .map_err(|e| format!("Failed to parse zone JSON: {}", e))?;

        let mut records: std::collections::HashMap<
            (String, RecordType),
            Vec<crate::dns::DnsZoneRecord>,
        > = std::collections::HashMap::new();

        if let Some(records_arr) = data.get("records").and_then(|r| r.as_array()) {
            for rec in records_arr {
                let name = rec
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("@")
                    .to_string();
                let record_type_str = rec
                    .get("record_type")
                    .and_then(|t| t.as_str())
                    .unwrap_or("A");
                let value = rec
                    .get("value")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let ttl = rec.get("ttl").and_then(|t| t.as_u64()).unwrap_or(3600) as u32;
                let priority = rec
                    .get("priority")
                    .and_then(|p| p.as_u64())
                    .map(|p| p as u32);

                let record_type = match record_type_str.to_uppercase().as_str() {
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
                    _ => continue,
                };

                let key = (name.clone(), record_type);
                records
                    .entry(key)
                    .or_default()
                    .push(crate::dns::DnsZoneRecord {
                        name,
                        record_type,
                        value,
                        ttl,
                        priority,
                    });
            }
        }

        let mut zone = DnsZone::new(origin.to_string());
        zone.serial = serial;
        zone.records = records;

        Ok(zone)
    }

    pub(crate) async fn handle_node_shutdown(
        &self,
        _from_peer: &str,
        node_id: &str,
        role: crate::mesh::config::MeshNodeRole,
        domains: &[std::sync::Arc<str>],
        graceful: bool,
        shutdown_at: u64,
        timestamp: u64,
    ) {
        if !self.config.role.is_global() {
            tracing::debug!("Ignoring node shutdown on non-global node");
            return;
        }

        let now = current_timestamp();
        let time_until_shutdown = shutdown_at.saturating_sub(now);

        tracing::info!(
            "Node {} announced graceful shutdown in {}s for domains: {:?}",
            node_id,
            time_until_shutdown,
            domains
        );

        if graceful && time_until_shutdown > 0 {
            if let Some(dns_registry) = &self.dns_registry {
                let shutdown_msg = crate::dns::messages::DnsNodeShutdown {
                    node_id: node_id.to_string(),
                    role: if role.is_edge() {
                        crate::dns::messages::DnsNodeRole::Edge
                    } else {
                        crate::dns::messages::DnsNodeRole::Origin
                    },
                    domains: domains.iter().map(|d| d.to_string()).collect(),
                    graceful,
                    shutdown_at,
                    timestamp,
                };

                let _ = dns_registry.handle_node_shutdown(shutdown_msg).await;
            }
        }

        self.topology.remove_peer(node_id).await;
    }

    pub(crate) async fn handle_dns_domain_register_request(
        &self,
        from_peer: &str,
        request_id: &str,
        domain: &str,
        origin_node_id: &str,
        challenge_token: &str,
        geo: Option<&str>,
        capacity: u32,
        timestamp: u64,
        _signature: &[u8],
    ) {
        tracing::info!(
            "Received DNS domain register request: {} from {} for domain {}",
            request_id,
            origin_node_id,
            domain
        );

        if !self
            .config
            .role
            .contains(crate::mesh::config::MeshNodeRole::GLOBAL)
        {
            tracing::warn!("Received DNS domain register request on non-global node");
            return;
        }

        let dns_registry = match &self.dns_registry {
            Some(r) => r,
            None => {
                tracing::warn!("DNS registry not available");
                return;
            }
        };

        let now = current_timestamp();
        if now.saturating_sub(timestamp) > 300 {
            tracing::warn!("DNS domain register request timestamp too old");
            return;
        }

        let verified = self
            .verify_domain_challenge(domain, challenge_token, origin_node_id)
            .await;

        let reason = if verified {
            "Domain verified successfully".to_string()
        } else {
            "Domain verification failed".to_string()
        };

        let ttl_seconds: u64 = 300;
        let expires_at = now + ttl_seconds;

        let response = MeshMessage::DnsDomainRegisterResponse {
            request_id: request_id.into(),
            domain: domain.into(),
            origin_node_id: origin_node_id.into(),
            verified,
            reason: reason.clone().into(),
            timestamp: now,
            signature: vec![],
        };

        if let Err(e) = self.send_datagram_to_peer(from_peer, &response).await {
            tracing::warn!("Failed to send DNS domain register response: {}", e);
            return;
        }

        if verified {
            let registration = crate::dns::messages::DnsRegistration {
                node_id: origin_node_id.to_string(),
                domain: domain.to_string(),
                ip_addresses: vec![],
                geo: geo.map(String::from),
                capacity,
                healthy: true,
                latency_ms: None,
                certificate_fingerprint: None,
                role: crate::dns::messages::DnsNodeRole::Origin,
                edge_node_id: None,
                edge_node_geo: None,
                certificate_chain: Vec::new(),
            };

            if let Err(e) = dns_registry.register_origin_node(registration).await {
                tracing::error!("Failed to register origin node in DNS registry: {}", e);
                return;
            }

            self.broadcast_dns_domain_registered(
                domain,
                origin_node_id,
                &self.config.node_id(),
                geo,
                capacity,
                now,
                expires_at,
            )
            .await;

            tracing::info!("Domain {} registered for origin {}", domain, origin_node_id);
        }
    }

    pub(crate) async fn handle_dns_domain_register_response(
        &self,
        _from_peer: &str,
        _request_id: &str,
        domain: &str,
        _origin_node_id: &str,
        verified: bool,
        reason: &str,
        _timestamp: u64,
    ) {
        if !self.config.role.is_global() {
            tracing::debug!("Ignoring DNS domain register response on non-global node");
            return;
        }

        tracing::info!(
            "Received DNS domain register response for {}: verified={}, reason={}",
            domain,
            verified,
            reason
        );
    }

    pub(crate) async fn handle_dns_domain_deregister_request(
        &self,
        _from_peer: &str,
        request_id: &str,
        domain: &str,
        origin_node_id: &str,
        reason: &str,
        _timestamp: u64,
    ) {
        tracing::info!(
            "Received DNS domain deregister request: {} from {} for domain {}",
            request_id,
            origin_node_id,
            domain
        );

        if !self
            .config
            .role
            .contains(crate::mesh::config::MeshNodeRole::GLOBAL)
        {
            tracing::warn!("Received DNS domain deregister request on non-global node");
            return;
        }

        let dns_registry = match &self.dns_registry {
            Some(r) => r,
            None => {
                tracing::warn!("DNS registry not available");
                return;
            }
        };

        let now = current_timestamp();

        let registered_origins = dns_registry.get_registered_origin_nodes();
        let origin_exists = registered_origins
            .values()
            .any(|o| o.node_id == origin_node_id && o.domains.contains(&domain.to_string()));

        if !origin_exists {
            tracing::warn!(
                "Origin {} not registered for domain {}",
                origin_node_id,
                domain
            );
            return;
        }

        self.broadcast_dns_domain_deregistered(
            domain,
            origin_node_id,
            &self.config.node_id(),
            reason,
            now,
        )
        .await;

        tracing::info!(
            "Domain {} deregistered for origin {}",
            domain,
            origin_node_id
        );
    }

    pub(crate) async fn handle_dns_domain_registered(
        &self,
        _from_peer: &str,
        domain: &str,
        origin_node_id: &str,
        verified_by_global_node: &str,
        geo: Option<&str>,
        capacity: u32,
        _registered_at: u64,
        _expires_at: u64,
    ) {
        if !self.config.role.is_global() {
            tracing::debug!("Ignoring DNS domain registered on non-global node");
            return;
        }

        tracing::info!(
            "Received DnsDomainRegistered: domain={} origin={} verified_by={}",
            domain,
            origin_node_id,
            verified_by_global_node
        );

        if !self
            .config
            .role
            .contains(crate::mesh::config::MeshNodeRole::GLOBAL)
        {
            return;
        }

        let dns_registry = match &self.dns_registry {
            Some(r) => r,
            None => return,
        };

        let registration = crate::dns::messages::DnsRegistration {
            node_id: origin_node_id.to_string(),
            domain: domain.to_string(),
            ip_addresses: vec![],
            geo: geo.map(String::from),
            capacity,
            healthy: true,
            latency_ms: None,
            certificate_fingerprint: None,
            role: crate::dns::messages::DnsNodeRole::Origin,
            edge_node_id: None,
            edge_node_geo: None,
            certificate_chain: Vec::new(),
        };

        if let Err(e) = dns_registry.register_origin_node(registration).await {
            tracing::error!("Failed to register origin from broadcast: {}", e);
        }
    }

    pub(crate) async fn handle_dns_domain_deregistered(
        &self,
        _from_peer: &str,
        domain: &str,
        origin_node_id: &str,
        deregistered_by_global_node: &str,
        reason: &str,
        _deregistered_at: u64,
    ) {
        if !self.config.role.is_global() {
            tracing::debug!("Ignoring DNS domain deregistered on non-global node");
            return;
        }

        tracing::info!(
            "Received DnsDomainDeregistered: domain={} origin={} by={} reason={}",
            domain,
            origin_node_id,
            deregistered_by_global_node,
            reason
        );

        let dns_registry = match &self.dns_registry {
            Some(r) => r,
            None => return,
        };

        if let Err(e) = dns_registry.remove_origin(origin_node_id, domain) {
            tracing::warn!("Failed to remove origin from DNS registry: {}", e);
        }
    }

    pub(crate) async fn verify_domain_challenge(
        &self,
        domain: &str,
        challenge_token: &str,
        origin_node_id: &str,
    ) -> bool {
        if challenge_token.is_empty() {
            tracing::warn!("Empty challenge token for domain {}", domain);
            return false;
        }

        if let Some(expected_token) = challenge_token.strip_prefix("txt:") {
            return self.verify_txt_challenge(domain, expected_token).await;
        }

        if challenge_token.starts_with("oauth:") {
            let oauth_config = &challenge_token[7..];
            return self
                .verify_oauth_challenge(domain, origin_node_id, oauth_config)
                .await;
        }

        if let Some(signature_hex) = challenge_token.strip_prefix("signed:") {
            return self
                .verify_signed_challenge(domain, origin_node_id, signature_hex)
                .await;
        }

        tracing::warn!("Unknown challenge token format for domain {}", domain);
        false
    }

    pub(crate) async fn verify_txt_challenge(&self, domain: &str, expected_token: &str) -> bool {
        tracing::debug!(
            "Verifying TXT record challenge for {}: expected={}",
            domain,
            expected_token
        );

        let txt_query = format!("_maluwaf-challenge.{}", domain);

        match &self.dns_resolver {
            Some(resolver) => match resolver.lookup_txt(&txt_query).await {
                Ok(txt_record) => {
                    for value in &txt_record.values {
                        if value.contains(expected_token) {
                            tracing::info!(
                                "TXT challenge verified for domain {}: token found in TXT record",
                                domain
                            );
                            return true;
                        }
                    }
                    tracing::warn!(
                            "TXT challenge verification failed for {}: token not found in TXT records: {:?}",
                            domain,
                            txt_record.values
                        );
                    false
                }
                Err(e) => {
                    tracing::warn!("TXT lookup failed for {}: {}", txt_query, e);
                    false
                }
            },
            None => {
                tracing::warn!(
                    "DNS resolver not available - cannot verify TXT challenge for domain {}",
                    domain
                );
                false
            }
        }
    }

    pub(crate) async fn verify_oauth_challenge(
        &self,
        domain: &str,
        origin_node_id: &str,
        oauth_config: &str,
    ) -> bool {
        tracing::debug!(
            "Verifying OAuth/DNS-OAUTH challenge for {} with node {}",
            domain,
            origin_node_id
        );

        let challenge_record = format!("_oauth-challenge.{}", domain.trim_start_matches('_'));

        let records = self.resolve_txt_record(&challenge_record).await;
        if records.is_empty() {
            tracing::debug!("No OAuth challenge record found for {}", challenge_record);
            return false;
        }

        for record in records {
            if record.contains(oauth_config) {
                tracing::info!(
                    "OAuth challenge verified for {} using config {}",
                    domain,
                    oauth_config
                );
                return true;
            }
        }

        tracing::warn!(
            "OAuth challenge verification failed for {}: no matching config",
            domain
        );
        false
    }

    async fn resolve_txt_record(&self, _name: &str) -> Vec<String> {
        Vec::new()
    }

    pub(crate) async fn verify_signed_challenge(
        &self,
        domain: &str,
        origin_node_id: &str,
        signature_hex: &str,
    ) -> bool {
        tracing::debug!(
            "Verifying signed challenge for {} from {}",
            domain,
            origin_node_id
        );

        if signature_hex.is_empty() {
            tracing::warn!("Empty signature for signed challenge");
            return false;
        }

        let signature_bytes = match hex::decode(signature_hex) {
            Ok(bytes) if bytes.len() == 64 => bytes,
            Ok(bytes) => {
                tracing::warn!(
                    "Invalid signature length for domain {}: expected 64, got {}",
                    domain,
                    bytes.len()
                );
                return false;
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to decode signature hex for domain {}: {}",
                    domain,
                    e
                );
                return false;
            }
        };

        let public_key_b64 = match self
            .config
            .global_node
            .known_origin_keys
            .get(origin_node_id)
        {
            Some(key) => key.clone(),
            None => {
                tracing::warn!(
                    "No known public key for origin node {} when verifying challenge for {}",
                    origin_node_id,
                    domain
                );
                return false;
            }
        };

        let public_key_bytes: Vec<u8> =
            match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&public_key_b64) {
                Ok(bytes) if bytes.len() == 32 => bytes,
                Ok(bytes) => {
                    tracing::warn!(
                        "Invalid public key length for origin node {}: expected 32, got {}",
                        origin_node_id,
                        bytes.len()
                    );
                    return false;
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to decode public key for origin node {}: {}",
                        origin_node_id,
                        e
                    );
                    return false;
                }
            };

        let challenge_content = format!("{}:{}", domain, origin_node_id);

        if crate::integrity::signing::verify_ed25519_raw(
            &public_key_bytes,
            &challenge_content,
            &signature_bytes,
        ) {
            tracing::info!(
                "Signed challenge verified for domain {} from node {}",
                domain,
                origin_node_id
            );
            true
        } else {
            tracing::warn!(
                "Signed challenge verification failed for domain {} from node {}",
                domain,
                origin_node_id
            );
            false
        }
    }

    pub(crate) async fn broadcast_dns_domain_registered(
        &self,
        domain: &str,
        origin_node_id: &str,
        verified_by_global_node: &str,
        geo: Option<&str>,
        capacity: u32,
        registered_at: u64,
        expires_at: u64,
    ) {
        let global_nodes = self.topology.get_global_nodes().await;

        let message = MeshMessage::DnsDomainRegistered {
            domain: domain.into(),
            origin_node_id: origin_node_id.into(),
            verified_by_global_node: verified_by_global_node.into(),
            geo: geo.map(|s| s.into()),
            capacity,
            registered_at,
            expires_at,
            signature: vec![],
        };

        for node_id in global_nodes {
            if node_id == self.config.node_id() {
                continue;
            }

            if let Err(e) = self.send_datagram_to_peer(&node_id, &message).await {
                tracing::warn!(
                    "Failed to broadcast DnsDomainRegistered to {}: {}",
                    node_id,
                    e
                );
            }
        }
    }

    pub(crate) async fn broadcast_dns_domain_deregistered(
        &self,
        domain: &str,
        origin_node_id: &str,
        deregistered_by_global_node: &str,
        reason: &str,
        deregistered_at: u64,
    ) {
        let global_nodes = self.topology.get_global_nodes().await;

        let message = MeshMessage::DnsDomainDeregistered {
            domain: domain.into(),
            origin_node_id: origin_node_id.into(),
            deregistered_by_global_node: deregistered_by_global_node.into(),
            reason: reason.into(),
            deregistered_at,
            signature: vec![],
        };

        for node_id in global_nodes {
            if node_id == self.config.node_id() {
                continue;
            }

            if let Err(e) = self.send_datagram_to_peer(&node_id, &message).await {
                tracing::warn!(
                    "Failed to broadcast DnsDomainDeregistered to {}: {}",
                    node_id,
                    e
                );
            }
        }
    }
}
