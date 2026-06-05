use super::*;

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
            } else {
                tracing::info!("DNSSEC initialized successfully");

                Self::start_key_rotation_task(self.dnssec.clone(), 86400);
            }
        }

        if self.config.recursive.enabled {
            self.start_recursive_server().await?;
        }

        if let Some(ref coalescer) = self.query_coalescer {
            Self::start_coalescer_cleanup_task(
                Some(coalescer),
                self.config.settings.query_coalescing.cleanup_interval_secs,
            );
        }

        if self.config.anycast.enabled {
            return Err("Anycast requires mesh feature (not available in extracted dns crate)".to_string());
        } else {
            self.start_standard_mode().await?;
        }

        Ok(())
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

        Ok(())
    }

    async fn start_standard_mode(&mut self) -> Result<(), String> {
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], self.config.port));

        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| format!("Failed to bind DNS UDP socket: {}", e))?;

        let tcp_listener = tokio::net::TcpListener::bind(bind_addr)
            .await
            .map_err(|e| format!("Failed to bind DNS TCP socket: {}", e))?;

        tracing::info!("DNS server listening on {} (UDP + TCP)", bind_addr);

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
        let cookie_server_udp = self.cookie_server.clone();

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
                dns64_translator: None,
                acme_dns_challenges: acme_dns_challenges_udp.as_ref(),
                cookie_server: cookie_server_udp.as_ref(),
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
                                    tracing::debug!("DNS query rate limited for {}", client_ip);
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

                                // Extract query name once for firewall and RRL checks
                                let query_name = Self::extract_query_name(&buf[..len]);

                                // Firewall check
                                if let Some(fw) = firewall_udp.as_ref() {
                                    let firewall = fw.read();
                                    match firewall.evaluate_query(&buf[..len], client_ip, &query_name) {
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

                                let query_key = crate::query_coalesce::QueryKey::from_query(&buf[..len], Some(client_ip));
                                let cache_key = if let Some(ref key) = query_key {
                                    CacheKey::new(key.name.clone(), RecordType::from(key.qtype), Some(client_ip))
                                } else {
                                    CacheKey::new(String::new(), RecordType::NULL, Some(client_ip))
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
                                            Some(crate::query_coalesce::CoalesceResult::NewQuery(_)) => {
                                                if let Some(c) = &ctx.cache {
                                                    Self::handle_query_with_cache(&ctx, &buf[..len], c, cache_key, Some(client_ip))
                                                } else {
                                                    Self::handle_query(&ctx, &buf[..len], Some(client_ip))
                                                }
                                            }
                                            None => {
                                                if let Some(c) = &ctx.cache {
                                                    Self::handle_query_with_cache(&ctx, &buf[..len], c, cache_key, Some(client_ip))
                                                } else {
                                                    Self::handle_query(&ctx, &buf[..len], Some(client_ip))
                                                }
                                            }
                                            _ => {
                                                if let Some(c) = &ctx.cache {
                                                    Self::handle_query_with_cache(&ctx, &buf[..len], c, cache_key, Some(client_ip))
                                                } else {
                                                    Self::handle_query(&ctx, &buf[..len], Some(client_ip))
                                                }
                                            }
                                        }
                                    } else if let Some(c) = &ctx.cache {
                                        Self::handle_query_with_cache(&ctx, &buf[..len], c, cache_key, Some(client_ip))
                                    } else {
                                        Self::handle_query(&ctx, &buf[..len], Some(client_ip))
                                    }
                                } else if let Some(c) = &ctx.cache {
                                    Self::handle_query_with_cache(&ctx, &buf[..len], c, cache_key, Some(client_ip))
                                } else {
                                    Self::handle_query(&ctx, &buf[..len], Some(client_ip))
                                };

                                if let Some(ref resp) = response {
                                    if rrl_enabled {
                                        if let Some(rl) = rate_limiter.as_ref() {
                                            if !rl.should_respond(client_ip) {
                                                tracing::debug!("RRL dropping response to {}", client_ip);
                                                continue;
                                            }
                                        }
                                    }

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
                                    tracing::debug!("DNS TCP query rate limited for {}", client_ip);
                                    continue;
                                }

                                let connection_limits = connection_limits_tcp.clone();
                                match connection_limits.try_acquire_connection() {
                                    Ok(_guard) => {}
                                    Err(e) => {
                                        tracing::warn!("Connection rejected by limits: {}", e);
                                        continue;
                                    }
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

                                tokio::spawn(async move {
                                    let max_idle_time = Some(std::time::Duration::from_secs(
                                        connection_limits.max_tcp_idle_time().as_secs()
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
                                        connection_limits: Some(&connection_limits),
                                        max_idle_time,
                                        zone_transfer: zone_transfer_clone.as_ref(),
                                        ecs_filter_config: &ecs_filter_clone,
                                        rate_limiter: rate_limiter_clone.as_ref(),
                                        rrl_enabled: rrl_enabled_tcp,
                                        update_handler: update_handler_clone.as_ref(),
                                        notify_handler: notify_handler_clone.as_ref(),
                                        query_coalescer: query_coalescer_clone.as_ref(),
                                        dns64_translator: None,
                                        acme_dns_challenges: acme_dns_challenges_clone.as_ref(),
                                        cookie_server: cookie_server_clone.as_ref(),
                                    };
                                    if let Err(e) = Self::handle_tcp_query(stream, ctx).await {
                                        tracing::debug!("TCP DNS error: {}", e);
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
            } else {
                tracing::info!("DoT server started on port {}", self.config.dot.port);
            }
            self.dot_server = Some(dot);
        }

        if self.config.doh.enabled {
            let mut doh = DohServer::new(self.config.doh.clone(), self.cert_resolver.clone());
            doh.set_dns_server(self.clone());
            if let Err(e) = doh.start().await {
                tracing::warn!("Failed to start DoH server: {}", e);
            } else {
                tracing::info!("DoH server started on port {}", self.config.doh.port);
            }
            self.doh_server = Some(doh);
        }

        if self.config.doq.enabled {
            let mut doq = DoqServer::new(self.config.doq.clone(), self.cert_resolver.clone());
            doq.set_dns_server(self.clone());
            if let Err(e) = doq
                .start(
                    std::net::SocketAddr::from(([0, 0, 0, 0], self.config.doq.port)),
                    self.clone(),
                )
                .await
            {
                tracing::warn!("Failed to start DoQ server: {}", e);
            } else {
                tracing::info!("DoQ server started on port {}", self.config.doq.port);
            }
            self.doq_server = Some(doq);
        }

        Ok(())
    }

    pub(crate) fn start_coalescer_cleanup_task(
        coalescer: Option<&Arc<crate::query_coalesce::QueryCoalescer>>,
        interval_secs: u64,
    ) {
        if let Some(coalescer) = coalescer {
            let coalescer = coalescer.clone();

            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));

                loop {
                    interval.tick().await;

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
            });

            tracing::info!(
                "Query coalescer cleanup task started with interval {}s",
                interval_secs
            );
        }
    }

    pub fn get_coalescer_metrics(
        &self,
    ) -> Option<crate::query_coalesce::QueryCoalescerMetrics> {
        self.query_coalescer.as_ref().map(|c| c.metrics())
    }
}
