use super::*;
use crate::cache::TransportClass;
use crate::parsed_query::ParsedDnsQuery;

/// Parse and validate the bind address from config.
/// Returns `Err` immediately on invalid address instead of silently falling back.
pub(crate) fn configured_bind_addr(config: &DnsConfig) -> Result<SocketAddr, String> {
    let bind_ip: std::net::IpAddr = config
        .bind_address
        .parse()
        .map_err(|e| format!("Invalid DNS bind_address '{}': {}", config.bind_address, e))?;
    if config.port == 0 {
        return Err("DNS port cannot be zero".to_string());
    }
    Ok(SocketAddr::from((bind_ip, config.port)))
}

impl DnsServer {
    fn build_handler_state(&self) -> DnsHandlerState {
        DnsHandlerState {
            zones: self.zones.clone(),
            zone_trie: self.zone_trie.clone(),
            zone_index: self.zone_index.clone(),
            rate_limiter: self.rate_limiter.clone(),
            query_validator: self.query_validator.clone(),
            firewall: self.firewall.clone(),
            connection_limits: self.connection_limits.clone(),
            min_geo_ttl: self.config.settings.min_geo_ttl,
            negative_cache_ttl: self.config.settings.negative_cache_ttl,
            cache: self.cache.clone(),
            dnssec: self.dnssec.clone(),
            signer_name: self.signer_name.clone(),
            rrl_enabled: self.rrl_enabled,
            zone_transfer: self.zone_transfer.clone(),
            ecs_filter_config: self.ecs_filter_config.clone(),
            update_handler: self.update_handler.clone(),
            notify_handler: self.notify_handler.clone(),
            query_coalescer: self.query_coalescer.clone(),
            acme_dns_challenges: self.acme_dns_challenges.clone(),
            cookie_server: self.cookie_server.clone(),
        }
    }

    pub fn with_anycast(mut self, manager: crate::anycast::AnycastSocketManager) -> Self {
        self.anycast_manager = Some(Arc::new(manager));
        self
    }

    pub async fn start(&mut self) -> Result<(), String> {
        if self.config.dnssec.enabled {
            if let Err(e) = self.initialize_dnssec() {
                tracing::warn!("Failed to initialize DNSSEC: {}", e);
                self.health.set_dnssec_signing_enabled(false);
            } else {
                tracing::info!("DNSSEC initialized successfully");
                self.health.set_dnssec_signing_enabled(true);
                Self::start_key_rotation_task(self.dnssec.clone(), 86400);
            }
        }

        if self.config.recursive.enabled {
            if let Err(e) = self.start_recursive_server().await {
                // Recursive init failed — server still functions as
                // authoritative, but recursive subsystem is degraded.
                self.health.set_recursive_degraded();
                return Err(e);
            }
        }

        let (shutdown_watcher_tx, shutdown_watcher_rx) = tokio::sync::watch::channel(false);
        self.shutdown_watcher_tx = Some(shutdown_watcher_tx);

        if let Some(ref coalescer) = self.query_coalescer {
            Self::start_coalescer_cleanup_task(
                Some(coalescer),
                self.config.settings.query_coalescing.cleanup_interval_secs,
                shutdown_watcher_rx,
            );
        }

        if self.config.anycast.enabled {
            return Err(
                "Anycast requires mesh feature (not available in extracted dns crate)".to_string(),
            );
        } else {
            self.start_standard_mode().await?;
        }

        Ok(())
    }

    /// Initiate graceful shutdown of the DNS runtime. Idempotent — safe to call multiple times.
    pub fn shutdown_runtime(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            tracing::info!("DNS server shutdown requested");
            let _ = tx.send(());
        }
        if let Some(watcher) = self.shutdown_watcher_tx.take() {
            let _ = watcher.send(true);
        }
        self.connection_limits.initiate_graceful_shutdown();
        // Liveness is no longer Healthy — listener is no longer bound.
        self.health.set_listener_bound(false);
    }

    async fn start_recursive_server(&mut self) -> Result<(), String> {
        tracing::info!(
            "Starting recursive DNS server on {}:{}",
            self.config.recursive.bind_address,
            self.config.recursive.port
        );

        let rate_limiter = self.rate_limiter.clone();
        let metrics = None;

        let recursive_server = crate::recursive::RecursiveDnsServer::new(
            self.config.recursive.clone(),
            rate_limiter,
            None,
            metrics,
        )
        .await
        .map_err(|e| format!("Failed to create recursive DNS server: {}", e))?;

        let server = Arc::new(recursive_server);
        let server_clone = server.clone();
        server_clone
            .start()
            .await
            .map_err(|e| format!("Failed to start recursive DNS server: {}", e))?;

        self.recursive_server = Some(server);
        // Recursive server reached steady state — report healthy. Subsequent
        // circuit-breaker trips will transition to Degraded via the setter
        // in the recursive path.
        self.health.set_recursive_healthy();
        self.health.set_circuit_breaker_open(false);

        Ok(())
    }

    async fn start_standard_mode(&mut self) -> Result<(), String> {
        let bind_addr = configured_bind_addr(&self.config)?;

        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| format!("Failed to bind DNS UDP socket: {}", e))?;

        let tcp_listener = tokio::net::TcpListener::bind(bind_addr)
            .await
            .map_err(|e| format!("Failed to bind DNS TCP socket: {}", e))?;

        tracing::info!("DNS server listening on {} (UDP + TCP)", bind_addr);

        // Listener is bound — liveness is now Healthy.
        self.health.set_listener_bound(true);

        let state = self.build_handler_state();
        let geoip_lookup = self.geoip_lookup.clone();
        let udp_buffer_size = self.config.limits.udp_buffer_size;

        let (tx_udp, mut rx_udp) = tokio::sync::oneshot::channel::<()>();
        let (tx_tcp, mut rx_tcp) = tokio::sync::oneshot::channel::<()>();
        let tx = tx_udp;
        self.shutdown_tx = Some(tx);

        let udp_state = state.clone();
        let geoip_lookup_udp = geoip_lookup.clone();
        let acme_dns_challenges_udp = self.acme_dns_challenges.clone();
        let _cookie_server_udp = self.cookie_server.clone();
        let dns64_translator_udp = self.dns64_translator.clone();

        tokio::spawn(async move {
            let DnsHandlerState {
                zones: zones_udp,
                zone_trie: zone_trie_udp,
                zone_index: _zone_index_udp,
                rate_limiter: rate_limiter_udp,
                query_validator: query_validator_udp,
                firewall: firewall_udp,
                connection_limits: _connection_limits_udp,
                min_geo_ttl,
                negative_cache_ttl,
                cache: cache_udp,
                dnssec: dnssec_udp,
                signer_name: signer_name_udp,
                rrl_enabled: rrl_enabled_udp,
                zone_transfer: zone_transfer_udp,
                ecs_filter_config: ecs_filter_config_udp,
                update_handler: update_handler_udp,
                notify_handler: notify_handler_udp,
                query_coalescer: query_coalescer_udp,
                acme_dns_challenges: _acme_dns_challenges_udp,
                cookie_server: cookie_server_udp,
            } = udp_state;
            let ctx = QueryContext {
                zones: &zones_udp,
                zone_trie: &zone_trie_udp,
                geoip_lookup: geoip_lookup_udp.as_ref(),
                min_geo_ttl,
                negative_cache_ttl,
                cache: cache_udp.as_ref(),
                dnssec: dnssec_udp.as_ref(),
                signer_name: signer_name_udp.as_ref(),
                query_validator: query_validator_udp.as_ref(),
                firewall: firewall_udp.as_ref(),
                connection_limits: None,
                max_idle_time: None,
                zone_transfer: zone_transfer_udp.as_ref(),
                ecs_filter_config: &ecs_filter_config_udp,
                rate_limiter: rate_limiter_udp.as_ref(),
                rrl_enabled: rrl_enabled_udp,
                update_handler: update_handler_udp.as_ref(),
                notify_handler: notify_handler_udp.as_ref(),
                query_coalescer: query_coalescer_udp.as_ref(),
                dns64_translator: dns64_translator_udp.as_ref(),
                acme_dns_challenges: acme_dns_challenges_udp.as_ref(),
                cookie_server: cookie_server_udp.as_ref(),
                #[cfg(feature = "mesh")]
                mesh_registry: None,
            };
            let mut buf = vec![0u8; udp_buffer_size];

            loop {
                tokio::select! {
                    result = socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, src)) => {
                                let client_ip = src.ip();

                                let allowed = if let Some(rl) = &rate_limiter_udp {
                                    rl.check_ip(client_ip).is_ok()
                                } else {
                                    true
                                };

                                if !allowed {
                                    tracing::debug!(
                                        transport = "udp",
                                        client = %client_ip,
                                        "DNS query rate limited"
                                    );
                                    continue;
                                }

                                // Validate query structure
                                let query_validator = query_validator_udp.as_ref();
                                if let Some(validator) = query_validator {
                                    if let Err(resp) = validator.validate_query_with_response(&buf[..len]) {
                                        if let Some(response) = resp {
                                            if let Err(e) = socket.send_to(&response, &src).await {
                                                tracing::debug!("Failed to send error response: {}", e);
                                            }
                                        }
                                        continue;
                                    }
                                }

                                // Parse once for firewall, coalescing, and downstream
                                let parsed = ParsedDnsQuery::parse(&buf[..len]);
                                let query_name = parsed
                                    .as_ref()
                                    .map(|p| p.qname.clone())
                                    .unwrap_or_else(|_| "unknown".to_string());

                                // Firewall check
                                if let Some(fw) = firewall_udp.as_ref() {
                                    if let Ok(ref parsed_q) = parsed {
                                        let firewall = fw.read();
                                        match firewall.evaluate_query(parsed_q, client_ip, &query_name) {
                                            Ok(decision) => {
                                                if decision.action == crate::firewall::DnsFirewallAction::Block {
                                                    tracing::warn!(
                                                        "DNS query blocked by firewall: rule={} client={} qname={}",
                                                        decision.rule_id,
                                                        client_ip,
                                                        query_name
                                                    );
                                                    continue;
                                                }
                                            }
                                            Err(e) => {
                                                tracing::warn!("Firewall evaluation error: {}", e);
                                            }
                                        }
                                    }
                                }

                                let skip_coalesce = parsed
                                    .as_ref()
                                    .map(|pq| crate::query_coalesce::should_skip_coalescing(pq.qtype, pq.flags.opcode))
                                    .unwrap_or(false);

                                // Derive transport class from EDNS for cache keying
                                let transport_class = if let Ok(ref parsed_q) = parsed {
                                    if parsed_q.has_edns {
                                        // Extract UDP payload size from OPT record class field
                                        let opt_offset = parsed_q.question_end;
                                        if opt_offset + 4 <= buf.len() {
                                            let udp_payload_size = u16::from_be_bytes(
                                                [buf[opt_offset + 3], buf[opt_offset + 4]],
                                            );
                                            TransportClass::UdpEdns(udp_payload_size)
                                        } else {
                                            TransportClass::UdpEdns(1232)
                                        }
                                    } else {
                                        TransportClass::Udp512
                                    }
                                } else {
                                    TransportClass::Udp512
                                };

                                let query_key = if skip_coalesce {
                                    None
                                } else if let Ok(ref parsed_q) = parsed {
                                    crate::query_coalesce::QueryKey::from_parsed(parsed_q, Some(client_ip), &buf[..len], Some(transport_class))
                                } else {
                                    crate::query_coalesce::QueryKey::from_query(&buf[..len], Some(client_ip), Some(transport_class))
                                };

                                let _dnssec = dnssec_udp.clone();
                                let _signer_name = signer_name_udp.clone();
                                let rate_limiter = rate_limiter_udp.clone();
                                let rrl_enabled = rrl_enabled_udp;

                                let response = if let Some(coalescer) = &ctx.query_coalescer {

                                    if let Some(key) = query_key {
                                        match coalescer.get_or_wait(key.clone()).await {
                                            Some(crate::query_coalesce::CoalesceResult::Response(resp)) => {
                                                Some(resp)
                                            }
                                            Some(crate::query_coalesce::CoalesceResult::NewQuery(_tx)) => {
                                                let resp = if let (Some(c), Ok(ref parsed_q)) = (&ctx.cache, &parsed) {
                                                    Self::handle_parsed_query_with_cache(&ctx, parsed_q, &buf[..len], c, transport_class, Some(client_ip))
                                                } else if let Some(c) = &ctx.cache {
                                                    Self::handle_query_with_cache(&ctx, &buf[..len], c, transport_class, Some(client_ip))
                                                } else if let Ok(ref parsed_q) = &parsed {
                                                    Self::handle_parsed_query(&ctx, parsed_q, &buf[..len], Some(client_ip))
                                                } else {
                                                    Self::handle_query(&ctx, &buf[..len], Some(client_ip))
                                                };

                                                if let Some(ref r) = resp {
                                                    coalescer.broadcast_response(key.clone(), r.clone());
                                                } else {
                                                    coalescer.cancel_in_flight(&key);
                                                }

                                                resp
                                            }
                                            None => {
                                                if let (Some(c), Ok(ref parsed_q)) = (&ctx.cache, &parsed) {
                                                    Self::handle_parsed_query_with_cache(&ctx, parsed_q, &buf[..len], c, transport_class, Some(client_ip))
                                                } else if let Some(c) = &ctx.cache {
                                                    Self::handle_query_with_cache(&ctx, &buf[..len], c, transport_class, Some(client_ip))
                                                } else if let Ok(ref parsed_q) = &parsed {
                                                    Self::handle_parsed_query(&ctx, parsed_q, &buf[..len], Some(client_ip))
                                                } else {
                                                    Self::handle_query(&ctx, &buf[..len], Some(client_ip))
                                                }
                                            }
                                            _ => {
                                                if let (Some(c), Ok(ref parsed_q)) = (&ctx.cache, &parsed) {
                                                    Self::handle_parsed_query_with_cache(&ctx, parsed_q, &buf[..len], c, transport_class, Some(client_ip))
                                                } else if let Some(c) = &ctx.cache {
                                                    Self::handle_query_with_cache(&ctx, &buf[..len], c, transport_class, Some(client_ip))
                                                } else if let Ok(ref parsed_q) = &parsed {
                                                    Self::handle_parsed_query(&ctx, parsed_q, &buf[..len], Some(client_ip))
                                                } else {
                                                    Self::handle_query(&ctx, &buf[..len], Some(client_ip))
                                                }
                                            }
                                        }
                                    } else if let (Some(c), Ok(ref parsed_q)) = (&ctx.cache, &parsed) {
                                        Self::handle_parsed_query_with_cache(&ctx, parsed_q, &buf[..len], c, transport_class, Some(client_ip))
                                    } else if let Some(c) = &ctx.cache {
                                        Self::handle_query_with_cache(&ctx, &buf[..len], c, transport_class, Some(client_ip))
                                    } else if let Ok(ref parsed_q) = &parsed {
                                        Self::handle_parsed_query(&ctx, parsed_q, &buf[..len], Some(client_ip))
                                    } else {
                                        Self::handle_query(&ctx, &buf[..len], Some(client_ip))
                                    }
                                } else if let (Some(c), Ok(ref parsed_q)) = (&ctx.cache, &parsed) {
                                    Self::handle_parsed_query_with_cache(&ctx, parsed_q, &buf[..len], c, transport_class, Some(client_ip))
                                } else if let Some(c) = &ctx.cache {
                                    Self::handle_query_with_cache(&ctx, &buf[..len], c, transport_class, Some(client_ip))
                                } else if let Ok(ref parsed_q) = &parsed {
                                    Self::handle_parsed_query(&ctx, parsed_q, &buf[..len], Some(client_ip))
                                } else {
                                    Self::handle_query(&ctx, &buf[..len], Some(client_ip))
                                };

                                if let Some(ref resp) = response {
                                    if rrl_enabled {
                                        if let Some(rl) = rate_limiter.as_ref() {
                                            if !rl.should_respond(client_ip) {
                                                tracing::debug!(
                                                    transport = "udp",
                                                    client = %client_ip,
                                                    "RRL dropping response"
                                                );
                                                continue;
                                            }
                                        }
                                    }

                                    tracing::trace!(
                                        transport = "udp",
                                        client = %client_ip,
                                        response_len = resp.len(),
                                        "DNS response sent"
                                    );
                                    let _ = socket.send_to(resp, src).await;
                                }
                            }
                            Err(e) => {
                                tracing::error!("DNS recv error: {}", e);
                            }
                        }
                    }
                    _ = &mut rx_udp => {
                        tracing::info!("DNS server shutting down (UDP)");
                        let _ = tx_tcp.send(());
                        break;
                    }
                }
            }
        });

        let tcp_state = state;
        let geoip_lookup_tcp = geoip_lookup;
        let tcp_buffer_size = self.config.limits.udp_buffer_size;
        let acme_dns_challenges_tcp = self.acme_dns_challenges.clone();
        let cookie_server_tcp = self.cookie_server.clone();
        let dns64_translator_tcp = self.dns64_translator.clone();

        tokio::spawn(async move {
            let DnsHandlerState {
                zones: zones_tcp,
                zone_trie: zone_trie_tcp,
                zone_index: zone_index_tcp,
                rate_limiter: rate_limiter_tcp,
                query_validator: query_validator_tcp,
                firewall: firewall_tcp,
                connection_limits: connection_limits_tcp,
                min_geo_ttl,
                negative_cache_ttl,
                cache: cache_tcp,
                dnssec: dnssec_tcp,
                signer_name: signer_name_tcp,
                rrl_enabled: rrl_enabled_tcp,
                zone_transfer: zone_transfer_tcp,
                ecs_filter_config: ecs_filter_config_tcp,
                update_handler: update_handler_tcp,
                notify_handler: notify_handler_tcp,
                query_coalescer: query_coalescer_tcp,
                acme_dns_challenges: _acme_dns_challenges_tcp,
                cookie_server: _cookie_server_tcp,
            } = tcp_state;
            let _buf = vec![0u8; tcp_buffer_size];

            loop {
                tokio::select! {
                    result = tcp_listener.accept() => {
                        match result {
                            Ok((stream, _src)) => {
                                let client_ip = stream.peer_addr().map(|a| a.ip()).unwrap_or_else(|_| IpAddr::from([0,0,0,0]));

                                let allowed = if let Some(rl) = &rate_limiter_tcp {
                                    rl.check_ip(client_ip).is_ok()
                                } else {
                                    true
                                };

                                if !allowed {
                                    tracing::debug!(
                                        transport = "tcp",
                                        client = %client_ip,
                                        "DNS TCP query rate limited"
                                    );
                                    continue;
                                }

                                let zones_clone = zones_tcp.clone();
                                let zone_trie_clone = zone_trie_tcp.clone();
                                let _zone_index_clone = zone_index_tcp.clone();
                                let geoip_lookup_clone = geoip_lookup_tcp.clone();
                                let cache_clone = cache_tcp.clone();
                                let dnssec_clone = dnssec_tcp.clone();
                                let signer_name_clone = signer_name_tcp.clone();
                                let query_validator_clone = query_validator_tcp.clone();
                                let firewall_clone = firewall_tcp.clone();
                                let zone_transfer_clone = zone_transfer_tcp.clone();
                                let ecs_filter_clone = ecs_filter_config_tcp.clone();
                                let rate_limiter_clone = rate_limiter_tcp.clone();
                                let update_handler_clone = update_handler_tcp.clone();
                                let notify_handler_clone = notify_handler_tcp.clone();
                                let query_coalescer_clone = query_coalescer_tcp.clone();
                                let acme_dns_challenges_clone = acme_dns_challenges_tcp.clone();
                                let cookie_server_clone = cookie_server_tcp.clone();
                                let connection_limits_clone = connection_limits_tcp.clone();
                                let dns64_clone = dns64_translator_tcp.clone();

                                tokio::spawn(async move {
                                    let _connection_guard = match connection_limits_clone.try_acquire_connection() {
                                        Ok(guard) => {
                                            metrics::counter!("dns_tcp_connections_total").increment(1);
                                            metrics::gauge!("dns_active_tcp_connections").increment(1.0);
                                            guard
                                        },
                                        Err(e) => {
                                            tracing::warn!(
                                                transport = "tcp",
                                                client = %client_ip,
                                                "Connection rejected by limits: {}", e
                                            );
                                            return;
                                        }
                                    };
                                    let max_idle_time = Some(std::time::Duration::from_secs(
                                        connection_limits_clone.max_tcp_idle_time().as_secs()
                                    ));
                                    let ctx = QueryContext {
                                        zones: &zones_clone,
                                        zone_trie: &zone_trie_clone,
                                        geoip_lookup: geoip_lookup_clone.as_ref(),
                                        min_geo_ttl,
                                        negative_cache_ttl,
                                        cache: cache_clone.as_ref(),
                                        dnssec: dnssec_clone.as_ref(),
                                        signer_name: signer_name_clone.as_ref(),
                                        query_validator: query_validator_clone.as_ref(),
                                        firewall: firewall_clone.as_ref(),
                                        connection_limits: Some(&connection_limits_clone),
                                        max_idle_time,
                                        zone_transfer: zone_transfer_clone.as_ref(),
                                        ecs_filter_config: &ecs_filter_clone,
                                        rate_limiter: rate_limiter_clone.as_ref(),
                                        rrl_enabled: rrl_enabled_tcp,
                                        update_handler: update_handler_clone.as_ref(),
                                        notify_handler: notify_handler_clone.as_ref(),
                                        query_coalescer: query_coalescer_clone.as_ref(),
                                        dns64_translator: dns64_clone.as_ref(),
                                        acme_dns_challenges: acme_dns_challenges_clone.as_ref(),
                                        cookie_server: cookie_server_clone.as_ref(),
                                        #[cfg(feature = "mesh")]
                                        mesh_registry: None,
                                    };
                                    if let Err(e) = Self::handle_tcp_query(stream, ctx).await {
                                        tracing::debug!(
                                            transport = "tcp",
                                            client = %client_ip,
                                            "TCP DNS error: {}", e
                                        );
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::error!("DNS TCP accept error: {}", e);
                            }
                        }
                    }
                    _ = &mut rx_tcp => {
                        tracing::info!("DNS server shutting down (TCP)");
                        break;
                    }
                }
            }
        });

        if self.config.dot.enabled {
            let mut dot = DotServer::new(self.config.dot.clone(), self.cert_resolver.clone());
            dot.set_dns_server(self.clone());
            if let Err(e) = dot.start().await {
                tracing::warn!("Failed to start DoT server: {}", e);
                self.health.set_cert_valid(false);
            } else {
                tracing::info!("DoT server started on port {}", self.config.dot.port);
                self.health.set_cert_valid(true);
            }
            self.dot_server = Some(dot);
        }

        if self.config.doh.enabled {
            let mut doh = DohServer::new(self.config.doh.clone(), self.cert_resolver.clone());
            doh.set_dns_server(self.clone());
            if let Err(e) = doh.start().await {
                tracing::warn!("Failed to start DoH server: {}", e);
                self.health.set_cert_valid(false);
            } else {
                tracing::info!("DoH server started on port {}", self.config.doh.port);
                self.health.set_cert_valid(true);
            }
            self.doh_server = Some(doh);
        }

        if self.config.doq.enabled {
            let mut doq = DoqServer::new(self.config.doq.clone(), self.cert_resolver.clone());
            doq.set_dns_server(self.clone());
            if let Err(e) = doq.start().await {
                tracing::warn!("Failed to start DoQ server: {}", e);
                self.health.set_cert_valid(false);
            } else {
                tracing::info!("DoQ server started on port {}", self.config.doq.port);
                self.health.set_cert_valid(true);
            }
            self.doq_server = Some(doq);
        }

        Ok(())
    }

    pub fn start_coalescer_cleanup_task(
        coalescer: Option<&Arc<crate::query_coalesce::QueryCoalescer>>,
        interval_secs: u64,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) {
        if let Some(coalescer) = coalescer {
            let coalescer = coalescer.clone();

            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));

                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            let count_before = coalescer.in_flight_count();
                            coalescer.cleanup_stale();
                            let count_after = coalescer.in_flight_count();

                            if count_before != count_after {
                                tracing::debug!(
                                    "Query coalescer cleanup: {} -> {} entries",
                                    count_before,
                                    count_after
                                );
                            }
                        }
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                tracing::info!("Query coalescer cleanup task shutting down");
                                break;
                            }
                        }
                    }
                }
            });

            tracing::info!(
                "Query coalescer cleanup task started with interval {}s",
                interval_secs
            );
        }
    }

    pub fn get_coalescer_metrics(&self) -> Option<crate::query_coalesce::QueryCoalescerMetrics> {
        self.query_coalescer.as_ref().map(|c| c.metrics())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn make_config(bind: &str, port: u16) -> DnsConfig {
        let mut c = DnsConfig::default();
        c.bind_address = bind.to_string();
        c.port = port;
        c
    }

    #[test]
    fn configured_bind_addr_ipv4() {
        let config = make_config("127.0.0.1", 5353);
        let addr = configured_bind_addr(&config).unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(addr.port(), 5353);
    }

    #[test]
    fn configured_bind_addr_ipv6() {
        let config = make_config("::1", 5353);
        let addr = configured_bind_addr(&config).unwrap();
        assert_eq!(addr.ip(), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
        assert_eq!(addr.port(), 5353);
    }

    #[test]
    fn configured_bind_addr_wildcard() {
        let config = make_config("0.0.0.0", 53);
        let addr = configured_bind_addr(&config).unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(addr.port(), 53);
    }

    #[test]
    fn configured_bind_addr_invalid_fails_fast() {
        let config = make_config("not-an-ip", 53);
        let result = configured_bind_addr(&config);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("Invalid DNS bind_address"),
            "Error should mention bind_address: {}",
            err
        );
    }

    #[test]
    fn configured_bind_addr_port_zero_fails() {
        let config = make_config("0.0.0.0", 0);
        let result = configured_bind_addr(&config);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("port cannot be zero"),
            "Error should mention port: {}",
            err
        );
    }

    #[test]
    fn shutdown_runtime_is_idempotent() {
        let mut config = DnsConfig::default();
        config.bind_address = "127.0.0.1".to_string();
        config.port = 5353;
        let mut server = DnsServer::new(config, None);
        // First call should send the signal
        server.shutdown_runtime();
        // Second call should not panic
        server.shutdown_runtime();
    }
}
