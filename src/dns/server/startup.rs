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
            #[cfg(feature = "dns")]
            acme_dns_challenges: self.acme_dns_challenges.clone(),
        }
    }

    pub fn with_anycast(mut self, manager: crate::dns::anycast::AnycastSocketManager) -> Self {
        self.anycast_manager = Some(Arc::new(manager));
        self
    }

    #[cfg(feature = "mesh")]
    pub fn with_mesh_transport(
        mut self,
        transport: Arc<crate::mesh::transport::MeshTransport>,
    ) -> Self {
        self.mesh_transport = Some(transport);
        self
    }

    #[cfg(feature = "mesh")]
    pub fn with_zone_sync(mut self, zone_sync: crate::dns::anycast_sync::AnycastZoneSync) -> Self {
        self.zone_sync = Some(Arc::new(zone_sync));
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
            #[cfg(feature = "mesh")]
            self.start_anycast_mode().await?;
            #[cfg(not(feature = "mesh"))]
            return Err("Anycast requires mesh feature".to_string());
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

        let recursive_server = crate::dns::recursive::RecursiveDnsServer::new(
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

    #[cfg(feature = "mesh")]
    async fn start_anycast_mode(&mut self) -> Result<(), String> {
        let platform = crate::dns::platform::create_platform();

        let mut manager =
            crate::dns::anycast::AnycastSocketManager::new(&self.config.anycast, platform).await?;

        let node_id = if let Some(ref mesh_registry) = self.mesh_registry {
            mesh_registry.node_id().to_string()
        } else {
            "unknown".to_string()
        };

        let geo = self.config.anycast.geo.clone();

        let zones_list = self.zones.keys();

        if let Some(ref mesh_registry) = self.mesh_registry {
            let anycast_ips = manager.get_bound_ips();
            let registration = crate::dns::messages::DnsAnycastNodeRegistration {
                node_id: node_id.clone(),
                anycast_ips: anycast_ips.iter().map(|ip| ip.to_string()).collect(),
                geo,
                capacity: self.config.anycast.capacity,
                healthy: true,
                dns_zones: zones_list.clone(),
                certificate_fingerprint: None,
            };
            mesh_registry.register_anycast_node(registration).await?;
        }

        let (health_tx, mut health_rx) =
            tokio::sync::mpsc::channel::<crate::dns::anycast::AnycastHealthUpdate>(100);
        manager.set_health_sender(health_tx);

        let mesh_registry_for_health = self.mesh_registry.clone();
        let node_id_for_health = node_id.clone();
        tokio::spawn(async move {
            while let Some(update) = health_rx.recv().await {
                if let Some(ref registry) = mesh_registry_for_health {
                    let health_update = crate::dns::messages::DnsAnycastHealthUpdate {
                        node_id: node_id_for_health.clone(),
                        anycast_ips: vec![update.ip.to_string()],
                        healthy: update.healthy,
                        latency_ms: update.latency_ms.map(|v| v as u32),
                        load_percent: update
                            .error_count
                            .checked_div(update.query_count.max(1))
                            .map(|v| v as u8),
                        timestamp: crate::utils::safe_unix_timestamp(),
                    };
                    let _ = registry.update_anycast_health(health_update).await;
                }
            }
        });

        if self.config.anycast.health_check_interval_secs > 0 {
            let interval = self.config.anycast.health_check_interval_secs;
            manager.start_health_monitor(interval).await;
        }

        let zones_for_sync = self.zones.clone();
        let mut zone_sync =
            crate::dns::anycast_sync::AnycastZoneSync::new(node_id.clone(), zones_for_sync);

        if let Some(ref transport) = self.mesh_transport {
            zone_sync = zone_sync.with_mesh_transport(transport.clone());

            // Set DNS zones on transport for zone sync
            transport.set_dns_zones(self.zones.clone());
        }

        if self.config.anycast.mesh_based_sync {
            let sync_interval = self.config.anycast.sync_interval_secs;
            zone_sync = zone_sync.with_sync_interval(sync_interval);
            zone_sync.start_sync_loop().await;
        }

        self.zone_sync = Some(Arc::new(zone_sync));

        self.anycast_manager = Some(Arc::new(manager));

        self.start_listeners_with_anycast().await?;

        Ok(())
    }

    #[cfg(feature = "mesh")]
    async fn start_listeners_with_anycast(&mut self) -> Result<(), String> {
        let anycast_manager = self
            .anycast_manager
            .as_ref()
            .ok_or("Anycast manager not initialized")?;

        let bound_addresses = anycast_manager.get_bound_addresses();

        tracing::info!("Starting anycast DNS on {:?}", bound_addresses);

        let state = self.build_handler_state();
        #[cfg(feature = "mesh")]
        let mesh_registry = self.mesh_registry.clone();
        let geoip_lookup = self.geoip_lookup.clone();
        let anycast_mgr = anycast_manager.clone();
        let config = self.config.clone();

        let (tx_udp, mut rx_udp) = tokio::sync::oneshot::channel::<()>();
        let (tx_tcp, mut rx_tcp) = tokio::sync::oneshot::channel::<()>();
        let tx = tx_udp;
        self.shutdown_tx = Some(tx);

        let udp_state = state.clone();
        #[cfg(feature = "mesh")]
        let mesh_registry_udp = mesh_registry.clone();
        let geoip_lookup_udp = geoip_lookup.clone();
        let anycast_udp = anycast_mgr.clone();
        let udp_buffer_size = config.limits.udp_buffer_size;
        #[cfg(feature = "dns")]
        let acme_dns_challenges_udp = self.acme_dns_challenges.clone();

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
                #[cfg(feature = "dns")]
                    acme_dns_challenges: _acme_dns_challenges_udp,
            } = udp_state;
            let ctx = QueryContext {
                zones: &zones_udp,
                zone_trie: &zone_trie_udp,
                #[cfg(feature = "mesh")]
                mesh_registry: mesh_registry_udp.as_ref(),
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
                #[cfg(feature = "dns")]
                acme_dns_challenges: acme_dns_challenges_udp.as_ref(),
            };
            let mut buf = vec![0u8; udp_buffer_size];

            loop {
                tokio::select! {
                    result = anycast_udp.recv_from(&mut buf) => {
                        match result {
                            Ok((len, src, dest_ip)) => {
                                let client_ip = src.ip();


                                let allowed = if let Some(rl) = &rate_limiter_udp {
                                    rl.check_ip(client_ip).is_ok()
                                } else {
                                    true
                                };

                                if !allowed {
                                    tracing::debug!("Anycast DNS query rate limited for {}", client_ip);
                                    continue;
                                }

                                let query_validator = query_validator_udp.as_ref();
                                if let Some(validator) = query_validator {
                                    if let Err(resp) = validator.validate_query_with_response(&buf[..len]) {
                                        if let Some(response) = resp {
                                            if let Err(e) = anycast_udp.send_to(&response, src, dest_ip).await {
                                                tracing::debug!("Failed to send error response: {}", e);
                                            }
                                        }
                                        continue;
                                    }
                                }

                                let query_name = Self::extract_query_name(&buf[..len]);

                                if let Some(fw) = firewall_udp.as_ref() {
                                    let firewall = fw.read();
                                    match firewall.evaluate_query(&buf[..len], client_ip, &query_name) {
                                        Ok(decision) => {
                                            if decision.action == crate::dns::firewall::DnsFirewallAction::Block {
                                                tracing::warn!(
                                                    "Anycast DNS query blocked by firewall: rule={} client={} qname={}",
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

                                let query_key = crate::dns::query_coalesce::QueryKey::from_query(&buf[..len], Some(client_ip));
                                let cache_key = if let Some(ref key) = query_key {
                                    CacheKey::new(key.name.clone(), RecordType::from(key.qtype), Some(client_ip))
                                } else {
                                    CacheKey::new(String::new(), RecordType::NULL, Some(client_ip))
                                };

                                let _dnssec = dnssec_udp.clone();
                                let _signer_name = signer_name_udp.clone();

                                let response = if let Some(coalescer) = &ctx.query_coalescer {

                                    if let Some(key) = query_key {
                                        match coalescer.get_or_wait(key.clone()) {
                                            Some(crate::dns::query_coalesce::CoalesceResult::Response(resp)) => {
                                                Some(resp)
                                            }
                                            Some(crate::dns::query_coalesce::CoalesceResult::NewQuery(_)) => {
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
                                    if rrl_enabled_udp {
                                        if let Some(rl) = rate_limiter_udp.as_ref() {
                                            if !rl.should_respond(client_ip) {
                                                tracing::debug!("Anycast RRL dropping response to {}", client_ip);
                                                continue;
                                            }
                                        }
                                    }

                                    if let Err(e) = anycast_udp.send_to(resp, src, dest_ip).await {
                                        tracing::debug!("Anycast DNS send error: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!("Anycast recv error: {}", e);
                            }
                        }
                    }
                    _ = &mut rx_udp => {
                        tracing::info!("Anycast DNS server shutting down (UDP)");
                        let _ = tx_tcp.send(());
                        break;
                    }
                }
            }
        });

        tracing::info!("Anycast DNS UDP server started on {:?}", bound_addresses);

        let anycast_mgr_tcp = anycast_manager.clone();
        #[cfg(feature = "dns")]
        let acme_dns_challenges_tcp = self.acme_dns_challenges.clone();

        let tcp_state = state;
        let mesh_registry_tcp = mesh_registry;
        let geoip_lookup_tcp = geoip_lookup;

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
                #[cfg(feature = "dns")]
                    acme_dns_challenges: _acme_dns_challenges_tcp,
            } = tcp_state;
            loop {
                tokio::select! {
                    result = anycast_mgr_tcp.accept_tcp() => {
                        match result {
                            Ok(conn) => {
                                let client_ip = conn.peer_addr.ip();
                                let dest_ip = conn.dest_ip;

                                let allowed = if let Some(rl) = &rate_limiter_tcp {
                                    rl.check_ip(client_ip).is_ok()
                                } else {
                                    true
                                };

                                if !allowed {
                                    tracing::debug!("Anycast DNS TCP query rate limited for {}", client_ip);
                                    continue;
                                }

                                let connection_limits = connection_limits_tcp.clone();
                                match connection_limits.try_acquire_connection() {
                                    Ok(_guard) => {}
                                    Err(e) => {
                                        tracing::warn!("Anycast TCP connection rejected by limits: {}", e);
                                        continue;
                                    }
                                }

                                let zones_clone = zones_tcp.clone();
                                let zone_trie_clone = zone_trie_tcp.clone();
                                let _zone_index_clone = zone_index_tcp.clone();
                                #[cfg(feature = "mesh")]
                                let mesh_registry_clone = mesh_registry_tcp.clone();
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
                                #[cfg(feature = "dns")]
                                let acme_dns_challenges_clone = acme_dns_challenges_tcp.clone();

                                tokio::spawn(async move {
                                    let max_idle_time = Some(std::time::Duration::from_secs(
                                        connection_limits.max_tcp_idle_time().as_secs()
                                    ));
                                    tracing::debug!("TCP connection from {} to anycast IP {}", client_ip, dest_ip);
                                    let ctx = QueryContext {
                                        zones: &zones_clone,
                                        zone_trie: &zone_trie_clone,
                                        #[cfg(feature = "mesh")]
                                        mesh_registry: mesh_registry_clone.as_ref(),
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
                                        #[cfg(feature = "dns")]
                                        acme_dns_challenges: acme_dns_challenges_clone.as_ref(),
                                    };
                                    if let Err(e) = Self::handle_tcp_query(conn.stream, ctx).await {
                                        tracing::debug!("Anycast TCP DNS error: {}", e);
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::error!("Anycast DNS TCP accept error: {}", e);
                            }
                        }
                    }
                    _ = &mut rx_tcp => {
                        tracing::info!("Anycast DNS TCP server shutting down");
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    async fn start_standard_mode(&mut self) -> Result<(), String> {
        // C3: Check dns_mesh_mode_only enforcement
        // If dns_mesh_mode_only is set and this node is not global, skip DNS binding
        #[cfg(feature = "mesh")]
        let should_skip_binding = if let Some(ref transport) = self.mesh_transport {
            let cfg = transport.get_mesh_config();
            if let Some(ref dht_cfg) = cfg.dht {
                dht_cfg.dns_mesh_mode_only && !cfg.role.is_global()
            } else {
                false
            }
        } else {
            false
        };

        #[cfg(not(feature = "mesh"))]
        let should_skip_binding = false;

        if should_skip_binding {
            tracing::info!(
                "Skipping DNS socket binding: dns_mesh_mode_only=true and node is not global"
            );
            return Ok(());
        }

        let bind_addr = SocketAddr::from(([0, 0, 0, 0], self.config.port));

        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| format!("Failed to bind DNS UDP socket: {}", e))?;

        let tcp_listener = tokio::net::TcpListener::bind(bind_addr)
            .await
            .map_err(|e| format!("Failed to bind DNS TCP socket: {}", e))?;

        tracing::info!("DNS server listening on {} (UDP + TCP)", bind_addr);

        let state = self.build_handler_state();
        #[cfg(feature = "mesh")]
        let mesh_registry = self.mesh_registry.clone();
        let geoip_lookup = self.geoip_lookup.clone();
        let udp_buffer_size = self.config.limits.udp_buffer_size;

        let (tx_udp, mut rx_udp) = tokio::sync::oneshot::channel::<()>();
        let (tx_tcp, mut rx_tcp) = tokio::sync::oneshot::channel::<()>();
        let tx = tx_udp;
        self.shutdown_tx = Some(tx);

        let udp_state = state.clone();
        #[cfg(feature = "mesh")]
        let mesh_registry_udp = mesh_registry.clone();
        let geoip_lookup_udp = geoip_lookup.clone();
        #[cfg(feature = "dns")]
        let acme_dns_challenges_udp = self.acme_dns_challenges.clone();

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
                #[cfg(feature = "dns")]
                    acme_dns_challenges: _acme_dns_challenges_udp,
            } = udp_state;
            let ctx = QueryContext {
                zones: &zones_udp,
                zone_trie: &zone_trie_udp,
                #[cfg(feature = "mesh")]
                mesh_registry: mesh_registry_udp.as_ref(),
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
                #[cfg(feature = "dns")]
                acme_dns_challenges: acme_dns_challenges_udp.as_ref(),
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
                                            if decision.action == crate::dns::firewall::DnsFirewallAction::Block {
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

                                let query_key = crate::dns::query_coalesce::QueryKey::from_query(&buf[..len], Some(client_ip));
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
                                        match coalescer.get_or_wait(key.clone()) {
                                            Some(crate::dns::query_coalesce::CoalesceResult::Response(resp)) => {
                                                Some(resp)
                                            }
                                            Some(crate::dns::query_coalesce::CoalesceResult::NewQuery(_)) => {
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
        #[cfg(feature = "mesh")]
        let mesh_registry_tcp = mesh_registry;
        let geoip_lookup_tcp = geoip_lookup;
        let tcp_buffer_size = self.config.limits.udp_buffer_size;
        #[cfg(feature = "dns")]
        let acme_dns_challenges_tcp = self.acme_dns_challenges.clone();

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
                #[cfg(feature = "dns")]
                    acme_dns_challenges: _acme_dns_challenges_tcp,
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
                                #[cfg(feature = "mesh")]
                                let mesh_registry_clone = mesh_registry_tcp.clone();
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
                                #[cfg(feature = "dns")]
                                let acme_dns_challenges_clone = acme_dns_challenges_tcp.clone();

                                tokio::spawn(async move {
                                    let max_idle_time = Some(std::time::Duration::from_secs(
                                        connection_limits.max_tcp_idle_time().as_secs()
                                    ));
                                    let ctx = QueryContext {
                                        zones: &zones_clone,
                                        zone_trie: &zone_trie_clone,
                                        #[cfg(feature = "mesh")]
                                        mesh_registry: mesh_registry_clone.as_ref(),
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
                                        #[cfg(feature = "dns")]
                                        acme_dns_challenges: acme_dns_challenges_clone.as_ref(),
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
        coalescer: Option<&Arc<crate::dns::query_coalesce::QueryCoalescer>>,
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
    ) -> Option<crate::dns::query_coalesce::QueryCoalescerMetrics> {
        self.query_coalescer.as_ref().map(|c| c.metrics())
    }
}
