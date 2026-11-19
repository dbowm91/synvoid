use super::*;
/// Validate the authoritative bind socket from runtime configuration.
///
/// The address is already parsed by the application-owned adapter, so the only
/// remaining fail-fast condition is a zero port (which cannot reach a
/// listener). Startup returns `Err` instead of silently falling back.
pub(crate) fn configured_bind_addr(
    config: &crate::runtime_config::AuthoritativeRuntimeConfig,
) -> Result<SocketAddr, String> {
    if config.bind_address.port() == 0 {
        return Err("DNS port cannot be zero".to_string());
    }
    Ok(config.bind_address)
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
            min_geo_ttl: self.authoritative.ttl.min_geo_ttl,
            negative_cache_ttl: self.authoritative.ttl.negative_cache_ttl,
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
            #[cfg(feature = "mesh")]
            mesh_registry: self.mesh_registry.clone(),
        }
    }

    pub fn with_anycast(mut self, manager: crate::anycast::AnycastSocketManager) -> Self {
        self.anycast_manager = Some(Arc::new(manager));
        self
    }

    pub async fn start(&mut self) -> Result<(), String> {
        // R3: the realized flags are set where the thing is realized. The
        // handlers are attached by composition before `start()`, so this is the
        // first point that can see them; `init_health_state` records only what
        // configuration requested.
        self.health.set_axfr_enabled(
            self.zone_transfer
                .as_ref()
                .is_some_and(|transfer| transfer.is_axfr_enabled()),
        );
        self.health.set_ixfr_enabled(
            self.zone_transfer
                .as_ref()
                .is_some_and(|transfer| transfer.is_ixfr_enabled()),
        );
        self.health
            .set_update_enabled(self.update_handler.is_some());
        self.health
            .set_notify_enabled(self.notify_handler.is_some());

        if self.dnssec_runtime.enabled {
            // A configured signed zone that cannot be signed is a startup
            // error, not a degraded mode: serving it unsigned would be a
            // silent downgrade of every RRset the zone claims to sign (R3).
            self.initialize_dnssec().map_err(|e| {
                tracing::error!("Failed to initialize DNSSEC: {}", e);
                self.health.set_dnssec_signing_enabled(false);
                format!("DNSSEC initialization failed: {e}")
            })?;
            tracing::info!("DNSSEC initialized successfully");
            // Keys existing in the manager is not signing: at least one loaded
            // zone must hold a ZSK handle for the health claim to be true.
            self.health
                .set_dnssec_signing_enabled(self.has_signing_zone());
            // Phase 05 R4: there is no runtime key-rotation task. Rotation is
            // a manual runbook operation (docs/dns-dnssec-architecture.md):
            // the served zone's key handles are reload-only, so rotating the
            // keystore while the server runs would change the validator's key
            // without changing the published DNSKEY.
        }

        if self.recursive.enabled {
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
                self.authoritative
                    .query_coalescing
                    .cleanup_interval
                    .as_secs(),
                shutdown_watcher_rx,
            );
        }

        if self.authoritative.anycast.enabled {
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
            "Starting recursive DNS server on {}",
            self.recursive.bind_address
        );

        let rate_limiter = self.rate_limiter.clone();
        let metrics = None;

        // `dns.recursive.firewall` is policy, not decoration: build it here and
        // fail startup if it cannot be built, rather than binding a listener
        // that ignores it (the recursive port had `firewall: None`).
        let firewall = if self.recursive.firewall.enabled {
            let firewall = crate::firewall::DnsFirewall::from_runtime(&self.recursive.firewall)
                .map_err(|e| format!("Failed to build recursive DNS firewall: {}", e))?;
            Some(Arc::new(RwLock::new(firewall)))
        } else {
            None
        };

        let recursive_server = crate::recursive::RecursiveDnsServer::new(
            (*self.recursive).clone(),
            rate_limiter,
            firewall,
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
        let bind_addr = configured_bind_addr(&self.authoritative)?;

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
        let udp_buffer_size = self.authoritative.limits.udp_buffer_size;

        let (tx_udp, mut rx_udp) = tokio::sync::oneshot::channel::<()>();
        let (tx_tcp, mut rx_tcp) = tokio::sync::oneshot::channel::<()>();
        let tx = tx_udp;
        self.shutdown_tx = Some(tx);

        let udp_state = state.clone();
        let geoip_lookup_udp = geoip_lookup.clone();
        let acme_dns_challenges_udp = self.acme_dns_challenges.clone();
        let _cookie_server_udp = self.cookie_server.clone();
        let dns64_translator_udp = self.dns64_translator.clone();
        #[cfg(feature = "mesh")]
        let mesh_registry_udp = self.mesh_registry.clone();

        tokio::spawn(async move {
            let DnsHandlerState {
                zones: zones_udp,
                zone_trie: zone_trie_udp,
                zone_index: _zone_index_udp,
                rate_limiter: rate_limiter_udp,
                query_validator: query_validator_udp,
                firewall: firewall_udp,
                connection_limits: connection_limits_udp,
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
                #[cfg(feature = "mesh")]
                    mesh_registry: _mesh_registry_udp,
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
                connection_limits: Some(&connection_limits_udp),
                max_idle_time: None,
                zone_transfer: zone_transfer_udp.as_ref(),
                ecs_filter_config: &ecs_filter_config_udp,
                rate_limiter: rate_limiter_udp.as_ref(),
                rrl_enabled: rrl_enabled_udp,
                update_handler: update_handler_udp.as_ref(),
                notify_handler: notify_handler_udp.as_ref(),
                query_coalescer: query_coalescer_udp.as_ref(),
                dns64_translator: dns64_translator_udp.as_ref(),
                acme_dns_challenges: acme_dns_challenges_udp.get(),
                cookie_server: cookie_server_udp.as_ref(),
                #[cfg(feature = "mesh")]
                mesh_registry: mesh_registry_udp.get(),
            };
            let mut buf = vec![0u8; udp_buffer_size];

            loop {
                tokio::select! {
                    result = socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, src)) => {
                                let client_ip = src.ip();

                                // One gate for every transport: size, header,
                                // QR, opcode, QDCOUNT, question structure,
                                // QCLASS, EDNS, firewall, rate limit.
                                let admitted = match crate::server::admit(
                                    &buf[..len],
                                    client_ip,
                                    crate::server::TransportKind::Udp,
                                    &ctx,
                                ) {
                                    crate::server::Admission::Allow(admitted) => admitted,
                                    crate::server::Admission::Reply(response) => {
                                        let _ = socket.send_to(&response, &src).await;
                                        continue;
                                    }
                                    crate::server::Admission::Drop => continue,
                                };

                                let rate_limiter = rate_limiter_udp.clone();
                                let rrl_enabled = rrl_enabled_udp;

                                let response = Self::serve_admitted(
                                    &ctx,
                                    &admitted,
                                    &buf[..len],
                                    Some(client_ip),
                                )
                                .await;

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
        let tcp_buffer_size = self.authoritative.limits.udp_buffer_size;
        let acme_dns_challenges_tcp = self.acme_dns_challenges.clone();
        let cookie_server_tcp = self.cookie_server.clone();
        let dns64_translator_tcp = self.dns64_translator.clone();
        #[cfg(feature = "mesh")]
        let mesh_registry_tcp = self.mesh_registry.clone();

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
                #[cfg(feature = "mesh")]
                    mesh_registry: _mesh_registry_tcp,
            } = tcp_state;
            let _buf = vec![0u8; tcp_buffer_size];

            loop {
                tokio::select! {
                    result = tcp_listener.accept() => {
                        match result {
                            Ok((stream, _src)) => {
                                let client_ip = stream.peer_addr().map(|a| a.ip()).unwrap_or_else(|_| IpAddr::from([0,0,0,0]));

                                // Rate limiting runs in `admit`, per query.
                                // A pre-check here would charge the token before
                                // the listener knows whether the connection
                                // carries a query at all, and would silently
                                // drop the connection instead of returning the
                                // same REFUSED as every other transport.
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
                                #[cfg(feature = "mesh")]
                                let mesh_registry_clone = mesh_registry_tcp.clone();
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
                                        acme_dns_challenges: acme_dns_challenges_clone.get(),
                                        cookie_server: cookie_server_clone.as_ref(),
                                        #[cfg(feature = "mesh")]
                                        mesh_registry: mesh_registry_clone.get(),
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

        if self.authoritative.dot.enabled {
            let bind = self.authoritative.dot.bind_address;
            let mut dot = DotServer::new(self.authoritative.dot, self.cert_resolver.clone());
            dot.set_dns_server(self.clone());
            if let Err(e) = dot.start().await {
                tracing::warn!("Failed to start DoT server: {}", e);
                self.health.set_cert_valid(false);
                // Configured, but no listener: /health must say so.
                self.health.set_dot_enabled(false);
            } else {
                tracing::info!(
                    "DoT server started on {}",
                    bind.map(|a| a.port()).unwrap_or_default()
                );
                self.health.set_cert_valid(true);
                self.health.set_dot_enabled(true);
            }
            self.dot_server = Some(dot);
        } else {
            self.health.set_dot_enabled(false);
        }

        if self.authoritative.doh.enabled {
            let bind = self.authoritative.doh.bind_address;
            let mut doh = DohServer::new(self.authoritative.doh, self.cert_resolver.clone());
            doh.set_dns_server(self.clone());
            if let Err(e) = doh.start().await {
                tracing::warn!("Failed to start DoH server: {}", e);
                self.health.set_cert_valid(false);
                self.health.set_doh_enabled(false);
            } else {
                tracing::info!(
                    "DoH server started on {}",
                    bind.map(|a| a.port()).unwrap_or_default()
                );
                self.health.set_cert_valid(true);
                self.health.set_doh_enabled(true);
            }
            self.doh_server = Some(doh);
        } else {
            self.health.set_doh_enabled(false);
        }

        if self.authoritative.doq.enabled {
            let bind = self.authoritative.doq.bind_address;
            let mut doq = DoqServer::new(self.authoritative.doq, self.cert_resolver.clone());
            doq.set_dns_server(self.clone());
            if let Err(e) = doq.start().await {
                tracing::warn!("Failed to start DoQ server: {}", e);
                self.health.set_cert_valid(false);
                self.health.set_doq_enabled(false);
            } else {
                tracing::info!(
                    "DoQ server started on {}",
                    bind.map(|a| a.port()).unwrap_or_default()
                );
                self.health.set_cert_valid(true);
                self.health.set_doq_enabled(true);
            }
            self.doq_server = Some(doq);
        } else {
            self.health.set_doq_enabled(false);
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
    use crate::runtime_config::{test_fixtures::dns_runtime, AuthoritativeRuntimeConfig};
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Minimal DNS-owned authoritative runtime for a loopback bind.
    ///
    /// The bind address arrives already parsed, so `make_config` only has to
    /// assemble it. An unparseable literal is represented as an unreachable
    /// case because the application adapter rejects it before construction.
    fn make_config(bind: &str, port: u16) -> AuthoritativeRuntimeConfig {
        dns_runtime(bind, port).authoritative
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

    /// The adapter rejects an unparseable literal before any server exists, so
    /// `configured_bind_addr` only has to guard the zero port.
    #[test]
    fn configured_bind_addr_rejects_unparseable_literal_upstream() {
        assert!(crate::runtime_config::parse_bind_address("not-an-ip", 53).is_none());
        assert!(crate::runtime_config::parse_bind_address("127.0.0.1", 5353).is_some());
        assert!(crate::runtime_config::parse_bind_address("::1", 5353).is_some());
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
        let mut server = DnsServer::new(dns_runtime("127.0.0.1", 5353), None, None);
        // First call should send the signal
        server.shutdown_runtime();
        // Second call should not panic
        server.shutdown_runtime();
    }
}
