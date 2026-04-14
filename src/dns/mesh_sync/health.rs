use super::*;
use metrics::gauge;

impl MeshDnsRegistry {
    pub async fn update_anycast_health(
        &self,
        update: DnsAnycastHealthUpdate,
    ) -> Result<(), String> {
        if !self.is_global {
            tracing::debug!("Ignoring anycast health update on non-global node");
            return Ok(());
        }

        let (geo, capacity, dns_zones, was_healthy) = {
            let mut anycast_nodes = self.anycast_nodes.write();
            if let Some(node) = anycast_nodes.get_mut(&update.node_id) {
                let was_healthy = node.healthy;
                node.healthy = update.healthy;
                node.latency_ms = update.latency_ms;
                node.load_percent = update.load_percent;
                node.last_update = chrono::Utc::now().timestamp() as u64;

                if let Some(latency) = update.latency_ms {
                    gauge!("dns_anycast_node_latency_ms").set(latency as f64);
                }
                if let Some(load) = update.load_percent {
                    gauge!("dns_anycast_node_load_percent").set(load as f64);
                }

                (
                    node.geo.clone(),
                    node.capacity,
                    node.dns_zones.clone(),
                    was_healthy,
                )
            } else {
                return Ok(());
            }
        };

        if update.healthy != was_healthy {
            gauge!("dns_anycast_node_healthy").set(if update.healthy { 1.0 } else { 0.0 });
        }

        let healthy_count = {
            let nodes = self.anycast_nodes.read();
            nodes.values().filter(|n| n.healthy).count()
        };
        gauge!("dns_anycast_healthy_nodes").set(healthy_count as f64);

        if let Some(ref dht_store) = self.dht_record_store {
            dht_store.store_anycast_node(
                update.node_id.clone(),
                update.anycast_ips.clone(),
                geo.as_ref().map(|g| g.to_string()),
                capacity,
                update.healthy,
                dns_zones,
            );
            tracing::debug!("Updated anycast node {} health in DHT", update.node_id);
        }

        Ok(())
    }

    pub fn get_healthy_anycast_nodes(&self) -> Vec<RegisteredAnycastNode> {
        let nodes = self.anycast_nodes.read();
        nodes.values().filter(|n| n.healthy).cloned().collect()
    }

    pub fn get_healthy_anycast_for_zone(&self, zone: &str) -> Vec<RegisteredAnycastNode> {
        let nodes = self.anycast_nodes.read();
        let mapping = self.domain_to_anycast_mapping.read();

        if let Some(node_ids) = mapping.get(zone) {
            node_ids
                .iter()
                .filter_map(|id| nodes.get(id).cloned())
                .filter(|n| n.healthy)
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn query_anycast_from_dht(&self, zone: &str) -> Vec<RegisteredAnycastNode> {
        if !self.is_global {
            return Vec::new();
        }

        if let Some(ref dht_store) = self.dht_record_store {
            let nodes = dht_store.get_anycast_nodes_for_zone(zone);
            nodes
                .into_iter()
                .filter_map(|value| {
                    let node_id = value.get("node_id")?.as_str()?;
                    let anycast_ips: Vec<String> = value
                        .get("anycast_ips")?
                        .as_array()?
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    let geo = value.get("geo").and_then(|v| v.as_str()).map(String::from);
                    let capacity = value.get("capacity")?.as_u64()? as u32;
                    let healthy = value.get("healthy")?.as_bool()?;
                    let dns_zones: Vec<String> = value
                        .get("dns_zones")?
                        .as_array()?
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();

                    Some(RegisteredAnycastNode {
                        node_id: node_id.to_string(),
                        anycast_ips,
                        geo,
                        healthy,
                        capacity,
                        latency_ms: None,
                        load_percent: None,
                        last_update: chrono::Utc::now().timestamp() as u64,
                        authenticated: false,
                        dns_zones,
                    })
                })
                .filter(|n| n.healthy)
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn has_anycast_for_zone(&self, zone: &str) -> bool {
        let nodes = self.anycast_nodes.read();
        nodes
            .values()
            .any(|n| n.dns_zones.iter().any(|z| z == zone) && n.healthy)
    }

    pub async fn remove_anycast_node(&self, node_id: &str) -> Result<(), String> {
        let zones = {
            let mut nodes = self.anycast_nodes.write();

            if let Some(node) = nodes.remove(node_id) {
                let mut mapping = self.domain_to_anycast_mapping.write();
                for zone in &node.dns_zones {
                    if let Some(node_ids) = mapping.get_mut(zone) {
                        node_ids.retain(|id| id != node_id);
                        if node_ids.is_empty() {
                            mapping.remove(zone);
                        }
                    }
                }
                tracing::info!("Removed anycast node {}", node_id);
                node.dns_zones
            } else {
                Vec::new()
            }
        };

        if !zones.is_empty() {
            if let Some(ref dht_store) = self.dht_record_store {
                dht_store.remove_anycast_node(node_id);
                tracing::debug!("Removed anycast node {} from DHT", node_id);
            }
        }

        Ok(())
    }

    pub fn get_best_anycast_for_zone(
        &self,
        zone: &str,
        client_geo: Option<&str>,
    ) -> Option<RegisteredAnycastNode> {
        let all_nodes = self.get_healthy_anycast_for_zone(zone);

        if all_nodes.is_empty() {
            return None;
        }

        let Some(client_geo) = client_geo else {
            return all_nodes.into_iter().next();
        };

        let mut scored_nodes: Vec<(RegisteredAnycastNode, f64)> = all_nodes
            .into_iter()
            .map(|node| {
                let score = self.calculate_anycast_score(&node, Some(client_geo));
                (node, score)
            })
            .collect();

        scored_nodes.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        scored_nodes.into_iter().next().map(|(node, _)| node)
    }

    fn calculate_anycast_score(
        &self,
        node: &RegisteredAnycastNode,
        client_geo: Option<&str>,
    ) -> f64 {
        let mut score = 100.0;

        if let Some(geo) = client_geo {
            if let Some(ref node_geo) = node.geo {
                let node_geo_parts: Vec<&str> = node_geo.split(',').collect();
                let client_geo_parts: Vec<&str> = geo.split(',').collect();

                if let Some(node_country) = node_geo_parts.first() {
                    if let Some(client_country) = client_geo_parts.first() {
                        if node_country.eq_ignore_ascii_case(client_country) {
                            score += 50.0;
                        }
                    }
                }

                if node_geo_parts.len() > 1 && client_geo_parts.len() > 1 {
                    if let Some(node_region) = node_geo_parts.get(1) {
                        if let Some(client_region) = client_geo_parts.get(1) {
                            if node_region.eq_ignore_ascii_case(client_region) {
                                score += 30.0;
                            }
                        }
                    }
                }

                if node_geo.eq_ignore_ascii_case(geo) {
                    score += 20.0;
                }
            }
        }

        if let Some(latency) = node.latency_ms {
            score -= (latency as f64) * 0.1;
        }

        if let Some(load) = node.load_percent {
            score -= (load as f64) * 0.5;
        }

        let now = chrono::Utc::now().timestamp() as u64;
        if node.last_update > 0 && now > node.last_update {
            let age_secs = now - node.last_update;
            if age_secs > 300 {
                score -= ((age_secs - 300) / 60) as f64 * 1.0;
            }
        }

        score
    }

    pub async fn update_origin_health(&self, update: DnsHealthUpdate) -> Result<(), String> {
        if !self.is_global {
            if let Some(ref tx) = self.health_tx {
                tx.send(update.clone())
                    .await
                    .map_err(|e| format!("Failed to send health update: {}", e))?;
            }
        }

        let mut origins = self.origin_nodes.write();
        if let Some(node) = origins.get_mut(&update.node_id) {
            node.healthy = update.healthy;
            node.latency_ms = update.latency_ms;
            node.load_percent = update.load_percent;
            node.last_update = chrono::Utc::now().timestamp() as u64;
        }

        Ok(())
    }

    pub async fn update_edge_health(&self, report: DnsEdgeHealthReport) -> Result<(), String> {
        let mut edges = self.edge_nodes.write();

        if let Some(edge) = edges.get_mut(&report.edge_node_id) {
            edge.last_update = chrono::Utc::now().timestamp() as u64;

            if report.healthy {
                edge.consecutive_failures = 0;
                edge.last_failure_reason = None;
            } else {
                edge.consecutive_failures += 1;
                edge.last_failure_reason = report.last_failure_reason.clone();
            }

            if edge.consecutive_failures >= self.config.failure_threshold_for_removal {
                tracing::warn!(
                    "Edge node {} exceeded failure threshold, marking unhealthy",
                    report.edge_node_id
                );
                edge.healthy = false;
            } else if edge.consecutive_failures >= self.config.failure_threshold_for_demotion {
                tracing::warn!(
                    "Edge node {} exceeded demotion threshold, reducing priority",
                    report.edge_node_id
                );
            }
        }

        Ok(())
    }

    pub async fn handle_node_shutdown(&self, shutdown: DnsNodeShutdown) -> Result<(), String> {
        if !self.is_global {
            if let Some(ref tx) = self.shutdown_tx {
                tx.send(shutdown.clone())
                    .await
                    .map_err(|e| format!("Failed to send shutdown: {}", e))?;
            }
        }

        let now = chrono::Utc::now().timestamp() as u64;

        if shutdown.graceful {
            let lead_time = self.config.graceful_shutdown_lead_time_secs;
            let effective_shutdown_at = shutdown.shutdown_at.saturating_sub(lead_time);

            if effective_shutdown_at > now {
                tracing::info!(
                    "Node {} announcing graceful shutdown at {}, removing from DNS at {}",
                    shutdown.node_id,
                    shutdown.shutdown_at,
                    effective_shutdown_at
                );
            }
        }

        match shutdown.role {
            DnsNodeRole::Edge => {
                let mut edges = self.edge_nodes.write();
                for domain in &shutdown.domains {
                    tracing::info!(
                        "Removing edge node {} from DNS for domain {} due to shutdown",
                        shutdown.node_id,
                        domain
                    );
                }
                edges.remove(&shutdown.node_id);
            }
            DnsNodeRole::Origin => {
                let mut origins = self.origin_nodes.write();
                let mut mapping = self.domain_to_origin_mapping.write();

                for domain in &shutdown.domains {
                    if let Some(origin_ids) = mapping.get_mut(domain) {
                        origin_ids.retain(|id| id != &shutdown.node_id);
                    }
                    tracing::info!(
                        "Removing origin node {} from DNS for domain {} due to shutdown",
                        shutdown.node_id,
                        domain
                    );
                }
                origins.remove(&shutdown.node_id);
            }
        }

        Ok(())
    }

    pub fn remove_origin(&self, node_id: &str, domain: &str) -> Result<(), String> {
        let mut origins = self.origin_nodes.write();
        let mut mapping = self.domain_to_origin_mapping.write();

        if let Some(origin) = origins.get_mut(node_id) {
            origin.domains.retain(|d| d != domain);
            if origin.domains.is_empty() {
                origins.remove(node_id);
            }
        }

        if let Some(origin_ids) = mapping.get_mut(domain) {
            origin_ids.retain(|id| id != node_id);
            if origin_ids.is_empty() {
                mapping.remove(domain);
            }
        }

        tracing::info!(
            "Removed origin {} for domain {} from DNS registry",
            node_id,
            domain
        );
        Ok(())
    }
}
