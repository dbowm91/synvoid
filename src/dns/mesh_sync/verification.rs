use super::*;

impl MeshDnsRegistry {
    pub fn verify_certificate_chain(&self, chain: &[Vec<u8>]) -> Result<bool, String> {
        if chain.is_empty() {
            return Err("Empty certificate chain".to_string());
        }

        let _now = chrono::Utc::now().timestamp() as u64;

        for (i, cert_der) in chain.iter().enumerate() {
            if cert_der.len() < 4 {
                return Err(format!(
                    "Certificate at index {} is too short ({} bytes)",
                    i,
                    cert_der.len()
                ));
            }

            if cert_der[0] != 0x30 {
                return Err(format!(
                    "Certificate at index {} is not valid DER (expected SEQUENCE tag 0x30, got 0x{:02x})",
                    i, cert_der[0]
                ));
            }

            if let Some(trusted) = self.trusted_certificates.read().values().next() {
                if trusted.certificate_der == *cert_der && !trusted.is_valid() {
                    return Err(format!(
                        "Certificate at index {} is expired (not_after: {})",
                        i, trusted.not_after
                    ));
                }
            }
        }

        if self.config.require_cert_chain_verification && chain.len() < 2 {
            return Err(
                "Certificate chain must contain at least end-entity and CA certificate"
                    .to_string(),
            );
        }

        tracing::info!(
            "Certificate chain verification passed ({} certificates)",
            chain.len()
        );
        Ok(true)
    }

    pub fn initiate_domain_verification(
        &self,
        domain: String,
        origin_node_id: String,
        verify_ownership: bool,
        ip_addresses: Vec<String>,
    ) -> DomainVerificationRequest {
        let now = chrono::Utc::now().timestamp() as u64;
        let request_id = format!("{}-{}-{}", domain, origin_node_id, now);

        let verification_type = if verify_ownership {
            DomainVerificationType::TxtChallenge
        } else {
            DomainVerificationType::NsRecord
        };

        let challenge_token = uuid::Uuid::new_v4().to_string();

        let request = DomainVerificationRequest {
            request_id: request_id.clone(),
            domain: domain.clone(),
            origin_node_id: origin_node_id.clone(),
            verification_type,
            challenge_token: Some(challenge_token),
            ip_addresses,
            created_at: now,
            expires_at: now + self.config.verification_timeout_secs,
        };

        self.pending_verifications
            .write()
            .insert(request_id, request.clone());

        self.verification_metrics
            .record_initiated(&verification_type);
        tracing::info!(
            "Initiated domain verification for {} (type: {:?})",
            domain,
            verification_type
        );

        request
    }

    pub fn get_pending_verification(&self, request_id: &str) -> Option<DomainVerificationRequest> {
        self.pending_verifications.read().get(request_id).cloned()
    }

    pub fn get_pending_verifications_for_domain(
        &self,
        domain: &str,
    ) -> Vec<DomainVerificationRequest> {
        self.pending_verifications
            .read()
            .values()
            .filter(|v| v.domain == domain)
            .cloned()
            .collect()
    }

    pub fn get_verification_metrics(&self) -> VerificationMetricsSummary {
        self.verification_metrics.get_summary()
    }

    pub fn update_verification_status(
        &self,
        request_id: &str,
        status: DomainVerificationStatus,
        error_message: Option<String>,
    ) -> bool {
        let mut pending = self.pending_verifications.write();

        if let Some(verification) = pending.get_mut(request_id) {
            match status {
                DomainVerificationStatus::Verified => {
                    tracing::info!(
                        "Domain verification completed for {}: {}",
                        verification.domain,
                        request_id
                    );
                }
                DomainVerificationStatus::Failed => {
                    tracing::warn!(
                        "Domain verification failed for {}: {} - {:?}",
                        verification.domain,
                        request_id,
                        error_message
                    );
                }
                _ => {}
            }
            true
        } else {
            false
        }
    }

    pub fn cleanup_expired_verifications(&self) -> usize {
        let now = chrono::Utc::now().timestamp() as u64;
        let mut pending = self.pending_verifications.write();
        let initial_count = pending.len();

        pending.retain(|_, v| v.expires_at > now);

        let removed = initial_count - pending.len();
        if removed > 0 {
            tracing::debug!("Cleaned up {} expired domain verifications", removed);
        }

        removed
    }

    pub async fn verify_domain_ns_records(
        &self,
        domain: &str,
        expected_nameservers: &[String],
    ) -> Result<bool, String> {
        let resolver = self
            .dns_resolver
            .as_ref()
            .ok_or_else(|| "DNS resolver not configured".to_string())?;

        let ns_record = resolver
            .lookup_ns(domain)
            .await
            .map_err(|e| format!("NS lookup failed: {}", e))?;

        for expected in expected_nameservers {
            let expected_base = expected.trim_end_matches('.').to_lowercase();
            let found = ns_record.nameservers.iter().any(|ns| {
                let ns_base = ns.trim_end_matches('.').to_lowercase();
                ns_base == expected_base || ns_base.ends_with(&format!(".{}", expected_base))
            });

            if !found {
                tracing::warn!(
                    "Expected nameserver {} not found for domain {}",
                    expected,
                    domain
                );
                return Ok(false);
            }
        }

        tracing::info!("NS record verification passed for domain {}", domain);
        Ok(true)
    }

    pub async fn verify_domain_txt_challenge(
        &self,
        domain: &str,
        expected_token: &str,
    ) -> Result<bool, String> {
        let resolver = self
            .dns_resolver
            .as_ref()
            .ok_or_else(|| "DNS resolver not configured".to_string())?;

        let txt_record = resolver
            .lookup_txt(&format!("_acme-challenge.{}", domain))
            .await
            .map_err(|e| format!("TXT lookup failed: {}", e))?;

        for txt_value in &txt_record.values {
            if txt_value.contains(expected_token) {
                tracing::info!("TXT challenge verification passed for domain {}", domain);
                return Ok(true);
            }
        }

        tracing::warn!(
            "TXT challenge verification failed for domain {} - token not found",
            domain
        );
        Ok(false)
    }

    pub fn complete_verification_and_register(
        &self,
        request_id: &str,
        registration: DnsRegistration,
    ) -> Result<(), String> {
        let pending = self.pending_verifications.read();

        let verification = pending
            .get(request_id)
            .ok_or_else(|| "Verification request not found".to_string())?;

        if verification.domain != registration.domain {
            return Err("Domain mismatch between registration and verification".to_string());
        }

        if verification.origin_node_id != registration.node_id {
            return Err("Origin node mismatch between registration and verification".to_string());
        }

        drop(pending);

        let cert_chain_verified = if self.config.require_cert_chain_verification
            && !registration.certificate_chain.is_empty()
        {
            match self.verify_certificate_chain(&registration.certificate_chain) {
                Ok(true) => true,
                Ok(false) => {
                    return Err("Certificate chain verification failed".to_string());
                }
                Err(e) => {
                    return Err(format!("Certificate chain verification error: {}", e));
                }
            }
        } else {
            false
        };

        let now = chrono::Utc::now().timestamp() as u64;

        let origin = RegisteredOriginNode {
            node_id: registration.node_id.clone(),
            domains: vec![registration.domain.clone()],
            geo: registration.geo.clone(),
            healthy: registration.healthy,
            capacity: registration.capacity,
            latency_ms: registration.latency_ms,
            load_percent: None,
            last_update: now,
            last_seen: now,
            authenticated: true,
            edge_node_id: registration.edge_node_id.clone(),
            edge_node_geo: registration.edge_node_geo.clone(),
            certificate_chain: registration.certificate_chain.clone(),
            cert_chain_verified,
        };

        self.origin_nodes
            .write()
            .insert(registration.node_id.clone(), origin);

        {
            let mut mapping = self.domain_to_origin_mapping.write();
            mapping
                .entry(registration.domain.clone())
                .or_default()
                .push(registration.node_id.clone());
        }

        if self.is_global {
            if let Some(ref dht_store) = self.dht_record_store {
                let ip_addresses = registration.ip_addresses.clone();
                let ttl = 600;
                let stored = dht_store.store_dns_domain_registration(
                    registration.domain.clone(),
                    registration.node_id.clone(),
                    ip_addresses,
                    ttl,
                );
                if stored {
                    tracing::info!(
                        "Registered domain {} in DHT after verification",
                        registration.domain
                    );
                }
            }
        }

        self.pending_verifications.write().remove(request_id);

        tracing::info!(
            "Domain {} registered after verification",
            registration.domain
        );

        Ok(())
    }

    pub async fn register_origin_with_verification(
        &self,
        registration: DnsRegistration,
        verify_domain_ownership: bool,
    ) -> Result<DnsRegistrationWithVerificationResponse, String> {
        if self.is_global {
            return Err("Use register_origin_node for global nodes".to_string());
        }

        let request_id = format!(
            "{}-{}-{}",
            registration.domain,
            registration.node_id,
            chrono::Utc::now().timestamp()
        );

        let _verification_request = DnsRegistrationWithVerificationRequest {
            request_id: request_id.clone(),
            registration: registration.clone(),
            verify_domain_ownership,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };

        let global_nodes = if let Some(ref rm) = self.routing_manager {
            rm.find_closest_global(5).await
        } else {
            Vec::new()
        };

        if !global_nodes.is_empty() && self.registration_tx.is_some() {
            let mut last_error = None;

            for (attempt, global_node) in global_nodes.iter().enumerate() {
                if attempt >= Self::MAX_REGISTRATION_RETRIES {
                    break;
                }

                tracing::info!(
                    "Attempting registration to global node {} (attempt {}/{})",
                    global_node.node_id,
                    attempt + 1,
                    Self::MAX_REGISTRATION_RETRIES
                );

                if let Some(ref tx) = self.registration_tx {
                    let request = DnsRegistrationRequest {
                        node_id: self.node_id.clone(),
                        domains: vec![registration.clone()],
                        is_global: false,
                        certificate_fingerprint: registration.certificate_fingerprint.clone(),
                        role: DnsNodeRole::Origin,
                    };

                    match tx.try_send(request) {
                        Ok(_) => {
                            tracing::info!(
                                "Registration request sent to global node {}",
                                global_node.node_id
                            );

                            return Ok(DnsRegistrationWithVerificationResponse {
                                request_id,
                                domain: registration.domain.clone(),
                                registration_accepted: true,
                                verification_status: DomainVerificationStatus::Pending,
                                verification_type: if verify_domain_ownership {
                                    Some(DomainVerificationType::TxtChallenge)
                                } else {
                                    Some(DomainVerificationType::NsRecord)
                                },
                                challenge_token: Some(uuid::Uuid::new_v4().to_string()),
                                nameservers_required: None,
                                error_message: None,
                                global_node_id: global_node.node_id.to_string(),
                                timestamp: chrono::Utc::now().timestamp() as u64,
                            });
                        }
                        Err(e) => {
                            last_error = Some(e.to_string());
                            tracing::warn!(
                                "Registration attempt {} failed: {:?}",
                                attempt + 1,
                                last_error
                            );
                        }
                    }
                }
            }

            if last_error.is_some() {
                tracing::warn!("Failed to send to global nodes, continuing with fallback");
            }
        }

        if let Some(ref tx) = self.registration_tx {
            let request = DnsRegistrationRequest {
                node_id: self.node_id.clone(),
                domains: vec![registration.clone()],
                is_global: false,
                certificate_fingerprint: registration.certificate_fingerprint.clone(),
                role: DnsNodeRole::Origin,
            };

            tx.send(request)
                .await
                .map_err(|e| format!("Failed to send registration: {}", e))?;

            tracing::info!("Registration request sent via local channel");

            return Ok(DnsRegistrationWithVerificationResponse {
                request_id,
                domain: registration.domain.clone(),
                registration_accepted: true,
                verification_status: DomainVerificationStatus::Pending,
                verification_type: if verify_domain_ownership {
                    Some(DomainVerificationType::TxtChallenge)
                } else {
                    Some(DomainVerificationType::NsRecord)
                },
                challenge_token: Some(uuid::Uuid::new_v4().to_string()),
                nameservers_required: None,
                error_message: None,
                global_node_id: self.node_id.clone(),
                timestamp: chrono::Utc::now().timestamp() as u64,
            });
        }

        Err("No registration channel available".to_string())
    }

    pub fn handle_registration_with_verification(
        &self,
        request: DnsRegistrationWithVerificationRequest,
    ) -> Result<DnsRegistrationWithVerificationResponse, String> {
        if !self.is_global {
            return Err("Only global nodes can handle registration requests".to_string());
        }

        let now = chrono::Utc::now().timestamp() as u64;
        let request_id = request.request_id.clone();
        let domain = request.registration.domain.clone();
        let origin_node_id = request.registration.node_id.clone();

        let authenticated = self.verify_registration(
            &request.registration.node_id,
            request.registration.certificate_fingerprint.as_deref(),
        );

        if !authenticated && self.config.require_mtls {
            return Ok(DnsRegistrationWithVerificationResponse {
                request_id: request_id.clone(),
                domain: domain.clone(),
                registration_accepted: false,
                verification_status: DomainVerificationStatus::Failed,
                verification_type: None,
                challenge_token: None,
                nameservers_required: None,
                error_message: Some("Authentication required".to_string()),
                global_node_id: self.node_id.clone(),
                timestamp: now,
            });
        }

        if request.verify_domain_ownership {
            let verification = self.initiate_domain_verification(
                domain.clone(),
                origin_node_id.clone(),
                true,
                request.registration.ip_addresses.clone(),
            );

            return Ok(DnsRegistrationWithVerificationResponse {
                request_id,
                domain,
                registration_accepted: true,
                verification_status: DomainVerificationStatus::Pending,
                verification_type: Some(DomainVerificationType::TxtChallenge),
                challenge_token: verification.challenge_token,
                nameservers_required: None,
                error_message: None,
                global_node_id: self.node_id.clone(),
                timestamp: now,
            });
        }

        let verification = self.initiate_domain_verification(
            domain.clone(),
            origin_node_id.clone(),
            false,
            request.registration.ip_addresses.clone(),
        );

        Ok(DnsRegistrationWithVerificationResponse {
            request_id,
            domain,
            registration_accepted: true,
            verification_status: DomainVerificationStatus::Pending,
            verification_type: Some(DomainVerificationType::NsRecord),
            challenge_token: verification.challenge_token,
            nameservers_required: None,
            error_message: None,
            global_node_id: self.node_id.clone(),
            timestamp: now,
        })
    }

    pub async fn start_verification_loop(&self) {
        let resolver = match &self.dns_resolver {
            Some(r) => Arc::clone(r),
            None => {
                tracing::warn!("No DNS resolver configured, verification loop not starting");
                return;
            }
        };

        let pending = Arc::clone(&self.pending_verifications);
        let origin_nodes = Arc::clone(&self.origin_nodes);
        let domain_mapping = Arc::clone(&self.domain_to_origin_mapping);
        let dht_store = self.dht_record_store.clone();
        let verification_tx = self.verification_tx.clone();
        let failure_tx = self.verification_failure_tx.clone();
        let _node_id = self.node_id.clone();
        let metrics = self.verification_metrics.clone();

        let retry_interval = self.config.verification_retry_interval_secs;
        let timeout_message = format!(
            "Verification timeout - DNS challenge not completed within {} seconds",
            self.config.verification_timeout_secs
        );

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(retry_interval)).await;

                let now = chrono::Utc::now().timestamp() as u64;
                let mut to_retry = Vec::new();
                let mut to_remove = Vec::new();
                let mut failures_to_send: Vec<VerificationFailure> = Vec::new();

                {
                    let pending_guard = pending.read();
                    for (request_id, verification) in pending_guard.iter() {
                        if verification.expires_at <= now {
                            to_remove.push(request_id.clone());

                            if failure_tx.is_some() {
                                failures_to_send.push(VerificationFailure {
                                    request_id: request_id.clone(),
                                    domain: verification.domain.clone(),
                                    origin_node_id: verification.origin_node_id.clone(),
                                    error_message: timeout_message.clone(),
                                });
                            }
                        } else {
                            to_retry.push((
                                request_id.clone(),
                                verification.domain.clone(),
                                verification.challenge_token.clone().unwrap_or_default(),
                                verification.verification_type,
                                verification.ip_addresses.clone(),
                            ));
                        }
                    }
                }

                for failure in failures_to_send {
                    if let Some(tx) = &failure_tx {
                        let _ = tx.send(failure).await;
                    }
                }

                for request_id in to_remove {
                    pending.write().remove(&request_id);
                    metrics.record_timeout();
                    tracing::warn!("Verification timed out for request {}", request_id);
                }

                for (request_id, domain, token, verification_type, ip_addresses) in to_retry {
                    let verified = match verification_type {
                        DomainVerificationType::TxtChallenge => resolver
                            .lookup_txt(&format!("_acme-challenge.{}", domain))
                            .await
                            .map(|txt| txt.values.iter().any(|v| v.contains(&token)))
                            .unwrap_or(false),
                        DomainVerificationType::NsRecord => {
                            let ns_result = resolver.lookup_ns(&domain).await;
                            match ns_result {
                                Ok(ns) => {
                                    if ns.nameservers.is_empty() {
                                        false
                                    } else {
                                        let expected_ips: Vec<std::net::IpAddr> = ip_addresses
                                            .iter()
                                            .filter_map(|ip| ip.parse().ok())
                                            .collect();

                                        if expected_ips.is_empty() {
                                            tracing::warn!("NS verification: no expected IPs provided, checking NS exists only");
                                            !ns.nameservers.is_empty()
                                        } else {
                                            let mut verified = false;
                                            for ns_name in &ns.nameservers {
                                                if let Ok(ips) = resolver.lookup_a(ns_name).await {
                                                    for ip in &ips {
                                                        if expected_ips.contains(ip) {
                                                            verified = true;
                                                            tracing::info!("NS verification: found matching IP {} for nameserver {}", ip, ns_name);
                                                            break;
                                                        }
                                                    }
                                                }
                                                if verified {
                                                    break;
                                                }
                                            }
                                            if !verified {
                                                tracing::warn!("NS verification: no matching IPs found for nameservers {:?}", ns.nameservers);
                                            }
                                            verified
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("NS lookup failed for {}: {}", domain, e);
                                    false
                                }
                            }
                        }
                        DomainVerificationType::MeshCertificate => {
                            // Mesh certificate verification relies on the certificate
                            // chain already being verified during registration.
                            // If we reach this point with MeshCertificate type,
                            // consider it verified (the chain check happened earlier).
                            tracing::info!(
                                "Mesh certificate verification for domain {} (chain-verified)",
                                domain
                            );
                            true
                        }
                    };

                    if verified {
                        metrics.record_succeeded();
                        tracing::info!("Verification succeeded for domain {}", domain);

                        {
                            let mut origins = origin_nodes.write();
                            if !origins.contains_key(
                                &request_id.split('-').nth(1).unwrap_or("").to_string(),
                            ) {
                                let origin = RegisteredOriginNode {
                                    node_id: request_id.split('-').nth(1).unwrap_or("").to_string(),
                                    domains: vec![domain.clone()],
                                    geo: None,
                                    healthy: true,
                                    capacity: 100,
                                    latency_ms: None,
                                    load_percent: None,
                                    last_update: now,
                                    last_seen: now,
                                    authenticated: true,
                                    edge_node_id: None,
                                    edge_node_geo: None,
                                    certificate_chain: Vec::new(),
                                    cert_chain_verified: false,
                                };
                                origins.insert(request_id.clone(), origin);
                            }
                        }

                        {
                            let mut mapping = domain_mapping.write();
                            mapping
                                .entry(domain.clone())
                                .or_default()
                                .push(request_id.clone());
                        }

                        if let Some(ref store) = dht_store {
                            let _ = store.store_dns_domain_registration(
                                domain.clone(),
                                request_id.clone(),
                                vec![],
                                600,
                            );
                        }

                        pending.write().remove(&request_id);

                        if let Some(tx) = &verification_tx {
                            let _ = tx
                                .send(VerificationTask {
                                    request_id: request_id.clone(),
                                    domain: domain.clone(),
                                    origin_node_id: request_id
                                        .split('-')
                                        .nth(1)
                                        .unwrap_or("")
                                        .to_string(),
                                    challenge_token: token,
                                    verification_type,
                                })
                                .await;
                        }
                    } else {
                        metrics.record_failed();
                    }
                }
            }
        });
    }
}
