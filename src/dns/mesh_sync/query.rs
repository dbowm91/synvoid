use super::*;

impl MeshDnsRegistry {
    pub fn get_edge_nodes_for_domain(&self, domain: &str) -> Vec<RegisteredEdgeNode> {
        let edges = self.edge_nodes.read();

        edges
            .values()
            .filter(|n| n.domains.iter().any(|d| d == domain))
            .filter(|n| n.healthy)
            .filter(|n| n.consecutive_failures < self.config.failure_threshold_for_removal)
            .cloned()
            .collect()
    }

    pub fn get_origin_nodes_for_domain(&self, domain: &str) -> Vec<RegisteredOriginNode> {
        let origins = self.origin_nodes.read();

        origins
            .values()
            .filter(|n| n.domains.iter().any(|d| d == domain))
            .filter(|n| n.healthy)
            .cloned()
            .collect()
    }

    pub fn get_edge_nodes_for_domain_geo(
        &self,
        domain: &str,
        client_geo: Option<&str>,
    ) -> Vec<RegisteredEdgeNode> {
        let all_nodes = self.get_edge_nodes_for_domain(domain);

        let Some(client_geo) = client_geo else {
            return all_nodes;
        };

        let mut scored_nodes: Vec<(RegisteredEdgeNode, f64)> = all_nodes
            .into_iter()
            .map(|node| {
                let score = self.calculate_geo_score_for_edge(&node, client_geo);
                (node, score)
            })
            .collect();

        scored_nodes.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        scored_nodes.into_iter().map(|(node, _)| node).collect()
    }

    pub fn get_origin_nodes_for_domain_geo(
        &self,
        domain: &str,
        client_geo: Option<&str>,
    ) -> Vec<RegisteredOriginNode> {
        let all_nodes = self.get_origin_nodes_for_domain(domain);

        let Some(client_geo) = client_geo else {
            return all_nodes;
        };

        let mut scored_nodes: Vec<(RegisteredOriginNode, f64)> = all_nodes
            .into_iter()
            .map(|node| {
                let score = self.calculate_geo_score_for_origin(&node, client_geo);
                (node, score)
            })
            .collect();

        scored_nodes.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        scored_nodes.into_iter().map(|(node, _)| node).collect()
    }

    pub fn get_best_edge_for_client(
        &self,
        domain: &str,
        _client_ip: Option<std::net::IpAddr>,
        client_geo: Option<&str>,
    ) -> Option<RegisteredEdgeNode> {
        let nodes = self.get_edge_nodes_for_domain_geo(domain, client_geo);

        if nodes.is_empty() {
            return None;
        }

        if nodes.len() == 1 {
            return Some(nodes[0].clone());
        }

        let mut best_node = None;
        let mut best_score = f64::MIN;

        for node in nodes {
            let score = self.calculate_edge_score(&node, client_geo);
            if score > best_score {
                best_score = score;
                best_node = Some(node);
            }
        }

        best_node
    }

    pub fn get_best_origin_for_edge(
        &self,
        domain: &str,
        edge_node_id: &str,
        client_geo: Option<&str>,
    ) -> Option<RegisteredOriginNode> {
        let edges = self.edge_nodes.read();
        let edge = edges.get(edge_node_id);

        let origins = self.get_origin_nodes_for_domain_geo(domain, client_geo);

        let filtered: Vec<RegisteredOriginNode> = origins
            .into_iter()
            .filter(|origin| {
                if let Some(edge) = edge {
                    origin.edge_node_id.as_ref() == Some(&edge.node_id)
                        || origin.edge_node_id.is_none()
                } else {
                    true
                }
            })
            .collect();

        if filtered.is_empty() {
            return None;
        }

        let mut best_node = None;
        let mut best_score = f64::MIN;

        for node in filtered {
            let score = self.calculate_origin_score(&node, client_geo);
            if score > best_score {
                best_score = score;
                best_node = Some(node);
            }
        }

        best_node
    }

    pub(super) fn calculate_geo_score_for_edge(
        &self,
        node: &RegisteredEdgeNode,
        client_geo: &str,
    ) -> f64 {
        let mut score = 0.0;

        if let Some(ref node_geo) = node.geo {
            let node_geo_parts: Vec<&str> = node_geo.split(',').collect();
            let client_geo_parts: Vec<&str> = client_geo.split(',').collect();

            if let Some(node_country) = node_geo_parts.first() {
                if let Some(client_country) = client_geo_parts.first() {
                    if node_country.eq_ignore_ascii_case(client_country) {
                        score += 100.0;
                    }
                }
            }

            if node_geo_parts.len() > 1 && client_geo_parts.len() > 1 {
                if let Some(node_region) = node_geo_parts.get(1) {
                    if let Some(client_region) = client_geo_parts.get(1) {
                        if node_region.eq_ignore_ascii_case(client_region) {
                            score += 50.0;
                        }
                    }
                }
            }

            if node_geo.eq_ignore_ascii_case(client_geo) {
                score += 25.0;
            }
        }

        score
    }

    pub(super) fn calculate_geo_score_for_origin(
        &self,
        node: &RegisteredOriginNode,
        client_geo: &str,
    ) -> f64 {
        let mut score = 0.0;

        if let Some(ref node_geo) = node.geo {
            let node_geo_parts: Vec<&str> = node_geo.split(',').collect();
            let client_geo_parts: Vec<&str> = client_geo.split(',').collect();

            if let Some(node_country) = node_geo_parts.first() {
                if let Some(client_country) = client_geo_parts.first() {
                    if node_country.eq_ignore_ascii_case(client_country) {
                        score += 100.0;
                    }
                }
            }

            if node_geo_parts.len() > 1 && client_geo_parts.len() > 1 {
                if let Some(node_region) = node_geo_parts.get(1) {
                    if let Some(client_region) = client_geo_parts.get(1) {
                        if node_region.eq_ignore_ascii_case(client_region) {
                            score += 50.0;
                        }
                    }
                }
            }

            if node_geo.eq_ignore_ascii_case(client_geo) {
                score += 25.0;
            }
        }

        score
    }

    fn calculate_edge_score(&self, node: &RegisteredEdgeNode, client_geo: Option<&str>) -> f64 {
        let mut score = 100.0;

        if let Some(geo) = client_geo {
            score += self.calculate_geo_score_for_edge(node, geo);
        }

        if let Some(latency) = node.latency_ms {
            score -= (latency as f64) * 0.1;
        }

        if let Some(load) = node.load_percent {
            score -= (load as f64) * 0.5;
        }

        if node.consecutive_failures > 0 {
            score -= (node.consecutive_failures as f64) * 10.0;
        }

        let now = chrono::Utc::now().timestamp() as u64;
        if node.last_update > 0 && now > node.last_update {
            let age_secs = now - node.last_update;
            if age_secs > 300 {
                score -= ((age_secs - 300) / 60) as f64 * 1.0;
            }
        }

        if !node.authenticated {
            score -= 50.0;
        }

        score
    }

    fn calculate_origin_score(&self, node: &RegisteredOriginNode, client_geo: Option<&str>) -> f64 {
        let mut score = 100.0;

        if let Some(geo) = client_geo {
            score += self.calculate_geo_score_for_origin(node, geo);
        }

        if let Some(latency) = node.latency_ms {
            score -= (latency as f64) * 0.1;
        }

        if let Some(load) = node.load_percent {
            score -= (load as f64) * 0.5;
        }

        if node.capacity > 0 {
            score += (node.capacity as f64) * 0.01;
        }

        let now = chrono::Utc::now().timestamp() as u64;
        if node.last_update > 0 && now > node.last_update {
            let age_secs = now - node.last_update;
            if age_secs > 300 {
                score -= ((age_secs - 300) / 60) as f64 * 1.0;
            }
        }

        if !node.authenticated {
            score -= 50.0;
        }

        score
    }

    pub fn get_all_healthy_edge_nodes(&self) -> Vec<RegisteredEdgeNode> {
        let edges = self.edge_nodes.read();

        edges
            .values()
            .filter(|n| n.healthy)
            .filter(|n| n.consecutive_failures < self.config.failure_threshold_for_removal)
            .cloned()
            .collect()
    }

    pub fn get_all_healthy_origin_nodes(&self) -> Vec<RegisteredOriginNode> {
        let origins = self.origin_nodes.read();

        origins.values().filter(|n| n.healthy).cloned().collect()
    }

    pub fn get_registered_edge_nodes(&self) -> HashMap<String, RegisteredEdgeNode> {
        self.edge_nodes.read().clone()
    }

    pub fn get_registered_origin_nodes(&self) -> HashMap<String, RegisteredOriginNode> {
        self.origin_nodes.read().clone()
    }

    pub fn cleanup_stale_edge_nodes(&self, max_age_secs: u64) {
        let now = chrono::Utc::now().timestamp() as u64;
        let mut edges = self.edge_nodes.write();

        edges.retain(|_, node| now - node.last_update < max_age_secs);
    }

    pub fn cleanup_stale_origin_nodes(&self, max_age_secs: u64) {
        let now = chrono::Utc::now().timestamp() as u64;
        let mut origins = self.origin_nodes.write();

        origins.retain(|_, node| now - node.last_update < max_age_secs);
    }

    pub fn has_origin_for_domain(&self, domain: &str) -> bool {
        let origins = self.origin_nodes.read();
        origins
            .values()
            .any(|n| n.domains.iter().any(|d| d == domain) && n.healthy)
    }

    pub fn has_edge_for_domain(&self, domain: &str) -> bool {
        let edges = self.edge_nodes.read();
        edges.values().any(|n| {
            n.domains.iter().any(|d| d == domain)
                && n.healthy
                && n.consecutive_failures < self.config.failure_threshold_for_removal
        })
    }
}
