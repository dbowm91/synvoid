use super::*;

#[cfg(feature = "mesh")]
use crate::mesh_sync::MeshDnsRegistry;

use crate::parsed_query::ParsedDnsQuery;

impl DnsServer {
    pub(super) fn build_simple_nxdomain_response(
        parsed: &ParsedDnsQuery<'_>,
    ) -> Option<Arc<Vec<u8>>> {
        use crate::parsed_query::build_response_flags_full;

        // RFC 2308: NXDOMAIN responses MUST include SOA in authority section.
        // Build SOA record before header so we know the authority count.
        let mut soa_rdata = Vec::new();
        // MNAME: root label (.)
        soa_rdata.push(0);
        // RNAME: root label (.)
        soa_rdata.push(0);
        // SERIAL
        soa_rdata.extend_from_slice(&0u32.to_be_bytes());
        // REFRESH
        soa_rdata.extend_from_slice(&3600u32.to_be_bytes());
        // RETRY
        soa_rdata.extend_from_slice(&600u32.to_be_bytes());
        // EXPIRE
        soa_rdata.extend_from_slice(&604800u32.to_be_bytes());
        // MINIMUM
        soa_rdata.extend_from_slice(&60u32.to_be_bytes());

        let flags = build_response_flags_full(true, false, false, false, false, false, 3); // NXDOMAIN

        // Build header with 1 question, 0 answer, 1 authority (SOA), 0 additional
        let mut response = Vec::with_capacity(12 + 64 + soa_rdata.len());
        response.extend_from_slice(&parsed.id.to_be_bytes());
        response.extend_from_slice(&flags.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        response.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        response.extend_from_slice(&1u16.to_be_bytes()); // NSCOUNT (SOA in authority)
        response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // Copy entire question section from raw query
        response.extend_from_slice(&parsed.raw[12..parsed.question_end]);

        // Append SOA record in authority section (owner = question name)
        response.extend_from_slice(&parsed.raw[12..parsed.qname_end]); // SOA owner name
        response.extend_from_slice(&6u16.to_be_bytes()); // type: SOA
        response.extend_from_slice(&1u16.to_be_bytes()); // class: IN
        response.extend_from_slice(&0u32.to_be_bytes()); // TTL: 0
        response.extend_from_slice(&(soa_rdata.len() as u16).to_be_bytes()); // RDLENGTH
        response.extend_from_slice(&soa_rdata);

        Some(Arc::new(response))
    }

    pub(super) async fn handle_tcp_query(
        mut stream: tokio::net::TcpStream,
        ctx: QueryContext<'_>,
    ) -> Result<(), String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        let client_ip = stream
            .peer_addr()
            .map(|a| a.ip())
            .unwrap_or_else(|_| IpAddr::from([0, 0, 0, 0]));

        let idle_timeout = ctx.max_idle_time.unwrap_or(Duration::from_secs(30));

        let mut length_buf = [0u8; 2];
        let read_result = timeout(idle_timeout, stream.read_exact(&mut length_buf)).await;

        match read_result {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(format!("TCP read error: {}", e)),
            Err(_) => {
                tracing::debug!("TCP connection idle timeout for {}", client_ip);
                return Err("Connection idle timeout".to_string());
            }
        }

        let len = u16::from_be_bytes([length_buf[0], length_buf[1]]) as usize;

        let mut query = vec![0u8; len];

        let read_result = timeout(idle_timeout, stream.read_exact(&mut query)).await;

        match read_result {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(format!("TCP read error: {}", e)),
            Err(_) => {
                tracing::debug!("TCP query read timeout for {}", client_ip);
                return Err("Query read timeout".to_string());
            }
        }

        // Validate query structure
        if let Some(validator) = ctx.query_validator {
            if let Err(resp) = validator.validate_query_with_response(&query) {
                if let Some(response) = resp {
                    let len = response.len() as u16;
                    let mut response_buf = len.to_be_bytes().to_vec();
                    response_buf.extend_from_slice(&response);
                    if let Err(e) = stream.write_all(&response_buf).await {
                        tracing::debug!("Failed to send error response: {}", e);
                    }
                }
                tracing::debug!(
                    "Invalid DNS TCP query from {}: validation failed",
                    client_ip
                );
                return Err("Invalid query".to_string());
            }
        }

        // Parse once — pass parsed state to firewall and downstream
        let parsed_tcp = ParsedDnsQuery::parse(&query);

        // Firewall check
        if let Some(fw) = ctx.firewall.as_ref() {
            let qname = match &parsed_tcp {
                Ok(p) => p.qname.clone(),
                Err(_) => Self::extract_query_name(&query),
            };
            let fw_read = fw.read();
            match fw_read.evaluate_query(&query, client_ip, &qname) {
                Ok(decision) => {
                    if decision.action == crate::firewall::DnsFirewallAction::Block {
                        tracing::warn!(
                            "DNS TCP query blocked by firewall: rule={} client={} qname={}",
                            decision.rule_id,
                            client_ip,
                            qname
                        );
                        return Err("Blocked by firewall".to_string());
                    }
                }
                Err(e) => {
                    tracing::warn!("TCP Firewall evaluation error: {}", e);
                }
            }
        }

        let cache_key = CacheKey::new(String::new(), RecordType::NULL, Some(client_ip));

        let response = if let Some(coalescer) = ctx.query_coalescer {
            let query_key = crate::query_coalesce::QueryKey::from_query(&query, Some(client_ip));

            if let Some(key) = query_key {
                match coalescer.get_or_wait(key.clone()).await {
                    Some(crate::query_coalesce::CoalesceResult::Response(resp)) => Some(resp),
                    Some(crate::query_coalesce::CoalesceResult::NewQuery(_)) => {
                        if let Some(c) = ctx.cache {
                            Self::handle_query_with_cache(
                                &ctx,
                                &query,
                                c,
                                cache_key,
                                Some(client_ip),
                            )
                        } else {
                            Self::handle_query(&ctx, &query, Some(client_ip))
                        }
                    }
                    None => {
                        if let Some(c) = ctx.cache {
                            Self::handle_query_with_cache(
                                &ctx,
                                &query,
                                c,
                                cache_key,
                                Some(client_ip),
                            )
                        } else {
                            Self::handle_query(&ctx, &query, Some(client_ip))
                        }
                    }
                    _ => {
                        if let Some(c) = ctx.cache {
                            Self::handle_query_with_cache(
                                &ctx,
                                &query,
                                c,
                                cache_key,
                                Some(client_ip),
                            )
                        } else {
                            Self::handle_query(&ctx, &query, Some(client_ip))
                        }
                    }
                }
            } else if let Some(c) = ctx.cache {
                Self::handle_query_with_cache(&ctx, &query, c, cache_key, Some(client_ip))
            } else {
                Self::handle_query(&ctx, &query, Some(client_ip))
            }
        } else if let Some(c) = ctx.cache {
            Self::handle_query_with_cache(&ctx, &query, c, cache_key, Some(client_ip))
        } else {
            Self::handle_query(&ctx, &query, Some(client_ip))
        };

        if let Some(resp) = response {
            // Check if this is a zone transfer (AXFR/IXFR) - need special multi-message handling for TCP
            if let Some(zt) = ctx.zone_transfer {
                let parsed_zt = ParsedDnsQuery::parse(&query);
                if let Ok(parsed_zt) = &parsed_zt {
                    if parsed_zt.is_axfr() {
                        let tsig =
                            crate::tsig::parse_tsig_from_query(&query, parsed_zt.question_end);
                        match zt.handle_axfr_request_messages(
                            &parsed_zt.qname,
                            client_ip,
                            tsig.as_ref(),
                            parsed_zt.id,
                            &query,
                        ) {
                            Ok(messages) => {
                                for msg in messages {
                                    let len = msg.len() as u16;
                                    let mut buf = len.to_be_bytes().to_vec();
                                    buf.extend_from_slice(&msg);
                                    stream.write_all(&buf).await.map_err(|e| e.to_string())?;
                                }
                                return Ok(());
                            }
                            Err(e) => {
                                tracing::warn!("AXFR multi-message failed: {}", e);
                                return Err(format!("AXFR failed: {}", e));
                            }
                        }
                    }

                    if parsed_zt.is_ixfr() {
                        let serial = Self::extract_ixfr_serial(&query);
                        let tsig =
                            crate::tsig::parse_tsig_from_query(&query, parsed_zt.question_end);
                        match zt.handle_ixfr_request_messages(
                            &parsed_zt.qname,
                            client_ip,
                            serial,
                            tsig.as_ref(),
                            parsed_zt.id,
                            &query,
                        ) {
                            Ok(messages) => {
                                for msg in messages {
                                    let len = msg.len() as u16;
                                    let mut buf = len.to_be_bytes().to_vec();
                                    buf.extend_from_slice(&msg);
                                    stream.write_all(&buf).await.map_err(|e| e.to_string())?;
                                }
                                return Ok(());
                            }
                            Err(e) => {
                                tracing::warn!("IXFR multi-message failed: {}", e);
                                return Err(format!("IXFR failed: {}", e));
                            }
                        }
                    }
                }
            }

            // Apply RRL for TCP queries if enabled
            if ctx.rrl_enabled {
                if let Some(rl) = ctx.rate_limiter {
                    if !rl.should_respond(client_ip) {
                        tracing::debug!("RRL dropping TCP response to {}", client_ip);
                        return Ok(());
                    }
                }
            }

            if let Some(limits) = ctx.connection_limits {
                if let Err(e) = limits.validate_response_size(resp.len()) {
                    tracing::warn!("Response size {} exceeds limit: {}", resp.len(), e);
                }
            }
            let len = resp.len() as u16;
            let mut response_buf = len.to_be_bytes().to_vec();
            response_buf.extend_from_slice(&resp);
            stream
                .write_all(&response_buf)
                .await
                .map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    pub(crate) fn handle_query_with_cache(
        ctx: &QueryContext,
        query: &[u8],
        cache: &Arc<DnsCache>,
        mut cache_key: CacheKey,
        client_ip: Option<std::net::IpAddr>,
    ) -> Option<Arc<Vec<u8>>> {
        let parsed = ParsedDnsQuery::parse(query).ok()?;

        if parsed.is_notify() {
            if let Some(handler) = ctx.notify_handler {
                if let Some(ip) = client_ip {
                    return handler.handle_notify(query, ip).map(Arc::new);
                }
            }
            return None;
        }

        if parsed.is_update() {
            if let Some(handler) = ctx.update_handler {
                if let Some(ip) = client_ip {
                    match handler.handle_update(query, ip) {
                        Ok(response) => return Some(Arc::new(response)),
                        Err(_) => return None,
                    }
                }
            }
            return None;
        }

        if parsed.is_axfr() {
            if let (Some(zt), Some(ip)) = (ctx.zone_transfer, client_ip) {
                let tsig = crate::tsig::parse_tsig_from_query(query, parsed.question_end);
                let message_id = u16::from_be_bytes([query[0], query[1]]);
                match zt.handle_axfr_request(&parsed.qname, ip, tsig.as_ref(), message_id, query) {
                    Ok(response) => return Some(Arc::new(response)),
                    Err(e) => {
                        tracing::warn!("AXFR failed: {}", e);
                        return None;
                    }
                }
            }
            return None;
        }

        if parsed.is_ixfr() {
            if let (Some(zt), Some(ip)) = (ctx.zone_transfer, client_ip) {
                let serial = Self::extract_ixfr_serial(query);
                let tsig = crate::tsig::parse_tsig_from_query(query, parsed.question_end);
                let message_id = u16::from_be_bytes([query[0], query[1]]);
                match zt.handle_ixfr_request(
                    &parsed.qname,
                    ip,
                    serial,
                    tsig.as_ref(),
                    message_id,
                    query,
                ) {
                    Ok(response) => return Some(Arc::new(response)),
                    Err(e) => {
                        tracing::warn!("IXFR failed: {}", e);
                        return None;
                    }
                }
            }
            return None;
        }

        let record_type = RecordType::from(parsed.qtype);

        cache_key.qname = parsed.qname.clone();
        use crate::server::RecordTypeExt;
        cache_key.qtype = record_type.to_u16();

        if let Some(cached) = cache.get(&cache_key) {
            return Some(cached);
        }

        let result = Self::handle_query(ctx, query, client_ip);

        if let Some(ref data) = result {
            let ttl = Self::extract_ttl_from_response(data.as_ref(), ctx.negative_cache_ttl);
            if ttl > 0 {
                cache.insert(cache_key, data.as_ref().clone(), ttl);
            }
        }

        result
    }

    pub(super) fn extract_ttl_from_response(response: &[u8], negative_cache_ttl: u32) -> u32 {
        if response.len() < 12 {
            return 0;
        }

        let flags = u16::from_be_bytes([response[2], response[3]]);
        let rcode = flags & 0x000F;
        let ancount = u16::from_be_bytes([response[6], response[7]]);

        if ancount == 0 {
            if rcode == 3 {
                return negative_cache_ttl;
            }
            return 0;
        }

        let mut pos = 12;
        while pos < response.len() {
            let len = response[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            pos += 1 + len;
        }
        pos += 4;

        if pos + 10 > response.len() {
            return 0;
        }

        let record_type = u16::from_be_bytes([response[pos], response[pos + 1]]);
        if record_type != 1
            && record_type != 28
            && record_type != 5
            && record_type != 15
            && record_type != 16
            && record_type != 2
            && record_type != 6
            && record_type != 33
        {
            return 0;
        }
        pos += 2;
        pos += 2;

        u32::from_be_bytes([
            response[pos],
            response[pos + 1],
            response[pos + 2],
            response[pos + 3],
        ])
    }

    pub(super) fn extract_ixfr_serial(query: &[u8]) -> Option<u32> {
        if query.len() < 16 {
            return None;
        }

        let parsed = ParsedDnsQuery::parse(query).ok()?;

        if parsed.qtype != crate::transfer::IXFR_QUERY_TYPE {
            return None;
        }

        // Skip past the SOA owner name in the authority section to find the serial.
        // The SOA owner name starts at question_end (after the question section).
        let after_soa_owner = ParsedDnsQuery::skip_wire_name(query, parsed.question_end)?;

        if after_soa_owner + 4 <= query.len() {
            Some(u32::from_be_bytes([
                query[after_soa_owner],
                query[after_soa_owner + 1],
                query[after_soa_owner + 2],
                query[after_soa_owner + 3],
            ]))
        } else {
            None
        }
    }

    #[cfg(feature = "mesh")]
    pub(super) fn resolve_from_mesh(
        mesh_registry: &Arc<MeshDnsRegistry>,
        qname: &str,
        client_ip: std::net::IpAddr,
        geoip_lookup: Option<&Arc<synvoid_geoip::GeoIpManager>>,
        qtype: u16,
    ) -> Option<Vec<DnsZoneRecord>> {
        let domain = qname.trim_end_matches('.');

        if !mesh_registry.has_origin_for_domain(domain) {
            tracing::debug!("No origin nodes registered for domain {}", domain);
            return None;
        }

        let client_geo = if let Some(geoip) = geoip_lookup {
            geoip.get_country_info(client_ip).map(|c| c.code.clone())
        } else {
            None
        };

        let best_edge =
            mesh_registry.get_best_edge_for_client(domain, Some(client_ip), client_geo.as_deref());

        best_edge.map(|edge| {
            let record_type = match qtype {
                1 => RecordType::A,
                28 => RecordType::AAAA,
                _ => RecordType::A,
            };

            edge.ip_addresses
                .iter()
                .filter_map(|ip| {
                    let matches_query = match record_type {
                        RecordType::A => ip.parse::<std::net::Ipv4Addr>().is_ok(),
                        RecordType::AAAA => ip.parse::<std::net::Ipv6Addr>().is_ok(),
                        _ => true,
                    };
                    if matches_query {
                        Some(DnsZoneRecord {
                            name: "@".to_string(),
                            record_type,
                            value: ip.clone(),
                            ttl: 60,
                            priority: None,
                        })
                    } else {
                        None
                    }
                })
                .collect()
        })
    }

    pub fn handle_query(
        ctx: &QueryContext,
        query: &[u8],
        client_ip: Option<std::net::IpAddr>,
    ) -> Option<Arc<Vec<u8>>> {
        use crate::server::RecordTypeExt;

        let parsed = ParsedDnsQuery::parse(query).ok()?;
        let query_id = parsed.id;

        if parsed.is_notify() {
            if let Some(handler) = ctx.notify_handler {
                if let Some(ip) = client_ip {
                    return handler.handle_notify(query, ip).map(Arc::new);
                }
            }
            return None;
        }

        if parsed.is_update() {
            if let Some(handler) = ctx.update_handler {
                if let Some(ip) = client_ip {
                    match handler.handle_update(query, ip) {
                        Ok(response) => return Some(Arc::new(response)),
                        Err(_) => return None,
                    }
                }
            }
            return None;
        }

        let mut edns_options = parse_edns_options(query);

        if let Some(ref mut edns) = edns_options {
            crate::edns::filter_ecs(edns, ctx.ecs_filter_config);
        }

        let dnssec_ok = edns_options.as_ref().map(|e| e.dnssec_ok).unwrap_or(false);

        let mut cookie_valid = false;
        let mut cookie_absent = false;
        let client_ip_for_log = client_ip.unwrap_or(IpAddr::from([127, 0, 0, 1]));
        if let (Some(cs), Some(edns)) = (ctx.cookie_server, &edns_options) {
            if let Some(ref cookie) = edns.cookie {
                if cookie.server_cookie.is_some() {
                    cookie_valid = cs.validate_cookie(
                        client_ip_for_log,
                        &cookie.client_cookie,
                        cookie.server_cookie.as_ref().unwrap(),
                    );
                } else {
                    cookie_absent = true;
                }
            } else {
                cookie_absent = true;
            }
            if !cookie_valid && !cookie_absent {
                tracing::debug!("Invalid DNS cookie from {}", client_ip_for_log);
            }
        }

        let qname_lower = parsed.qname.to_lowercase();
        if qname_lower.ends_with(".example") || qname_lower == "example" {
            return Self::build_simple_nxdomain_response(&parsed);
        }

        if parsed.qtype == 16 {
            // TXT record query - check for ACME DNS-01 challenge
            if qname_lower.starts_with("_acme-challenge.") {
                if let Some(acme_challenges) = ctx.acme_dns_challenges {
                    let domain = qname_lower
                        .strip_prefix("_acme-challenge.")
                        .unwrap_or(&qname_lower);
                    if let Some(txt_value) = acme_challenges.get_txt_value(domain) {
                        tracing::debug!(
                            "Serving ACME DNS-01 challenge for {}: {}",
                            domain,
                            txt_value
                        );
                        return Some(Self::build_acme_txt_response(
                            query_id,
                            &parsed.qname,
                            &txt_value,
                            edns_options.as_ref(),
                        ));
                    }
                }
            }
        }

        let record_type = RecordType::from(parsed.qtype);

        let trie_guard = ctx.zone_trie.read();

        // Use the trie for efficient zone lookup
        let best_match = trie_guard.find_zone(&qname_lower);

        let (origin_str, zone) = match best_match {
            Some(origin) => match ctx.zones.get(&origin) {
                Some(zone) => (origin.clone(), zone),
                None => return None,
            },
            None => return None,
        };

        let origin_canonical = origin_str.clone();
        let origin_lower_for_strip = origin_canonical.trim_end_matches('.').to_lowercase();

        // Reuse qname_lower instead of calling to_lowercase again
        let qname_lower_trimmed = qname_lower.trim_end_matches('.').to_string();
        let lookup_name = if qname_lower_trimmed == origin_lower_for_strip
            || parsed.qname.is_empty()
            || parsed.qname == "@"
        {
            "@".to_string()
        } else {
            let suffix = format!(".{}", origin_lower_for_strip);
            match qname_lower_trimmed.strip_suffix(&suffix) {
                Some(s) => s.to_string(),
                None => qname_lower_trimmed.clone(),
            }
        };

        let key = (lookup_name.clone(), record_type);
        if let Some(records) = zone.records.get(&key) {
            return Some(Self::build_response(
                query_id,
                &parsed.qname,
                parsed.qtype,
                records,
                dnssec_ok,
                edns_options.as_ref(),
                zone.zsk_key.as_ref(),
                &origin_canonical,
            ));
        }

        if record_type == RecordTypeExt::UNKNOWN || record_type == RecordType::A {
            let cname_key = (lookup_name.clone(), RecordType::CNAME);
            if let Some(cname_records) = zone.records.get(&cname_key) {
                if let Some(cname) = cname_records.first() {
                    let cname_target = cname.value.trim_end_matches('.');
                    let qname_stripped = parsed.qname.trim_end_matches('.');
                    if cname_target.eq_ignore_ascii_case(qname_stripped) {
                        tracing::warn!("CNAME loop detected for {}", parsed.qname);
                        return None;
                    }
                }
                return Some(Self::build_response(
                    query_id,
                    &parsed.qname,
                    parsed.qtype,
                    cname_records,
                    dnssec_ok,
                    edns_options.as_ref(),
                    zone.zsk_key.as_ref(),
                    &origin_canonical,
                ));
            }
        }

        if parsed.qtype == 255 {
            let mut all_records = Vec::new();
            let mut seen_cname = false;
            let lookup_name_for_qtype = lookup_name.clone();

            for ((name, _rt), records) in &zone.records {
                if name == &lookup_name_for_qtype
                    || (name == "@" && lookup_name_for_qtype.is_empty())
                {
                    for record in records {
                        if record.record_type == RecordType::CNAME {
                            if !seen_cname {
                                all_records.push(record.clone());
                                seen_cname = true;
                            }
                        } else if record.record_type != RecordType::SOA
                            && record.record_type != RecordType::NS
                            && record.record_type != RecordType::DNSKEY
                            && record.record_type != RecordType::DS
                            && record.record_type != RecordType::RRSIG
                            && record.record_type != RecordType::NSEC
                            && record.record_type != RecordType::NSEC3
                            && record.record_type != RecordType::NSEC3PARAM
                        {
                            all_records.push(record.clone());
                        }
                    }
                }
            }

            if !all_records.is_empty() {
                return Some(Self::build_response(
                    query_id,
                    &parsed.qname,
                    parsed.qtype,
                    &all_records,
                    dnssec_ok,
                    edns_options.as_ref(),
                    zone.zsk_key.as_ref(),
                    &origin_canonical,
                ));
            }

            if record_type == RecordType::DNSKEY && qname_lower_trimmed == origin_lower_for_strip {
                let dnskey_records = Self::build_dnskey_records(&zone);
                return Some(Self::build_response(
                    query_id,
                    &parsed.qname,
                    parsed.qtype,
                    &dnskey_records,
                    dnssec_ok,
                    edns_options.as_ref(),
                    zone.ksk_key.as_ref(),
                    &origin_canonical,
                ));
            }

            if parsed.qtype == 59 && qname_lower_trimmed == origin_lower_for_strip {
                if let Some(ksk) = &zone.ksk_key {
                    let cds_records = Self::build_cds_records(ksk);
                    return Some(Self::build_response(
                        query_id,
                        &parsed.qname,
                        parsed.qtype,
                        &cds_records,
                        dnssec_ok,
                        edns_options.as_ref(),
                        zone.ksk_key.as_ref(),
                        &origin_canonical,
                    ));
                }
            }

            if parsed.qtype == 60 && qname_lower_trimmed == origin_lower_for_strip {
                let cdnskey_records = Self::build_cdnskey_records(&zone);
                return Some(Self::build_response(
                    query_id,
                    &parsed.qname,
                    parsed.qtype,
                    &cdnskey_records,
                    dnssec_ok,
                    edns_options.as_ref(),
                    zone.ksk_key.as_ref(),
                    &origin_canonical,
                ));
            }

            if record_type == RecordType::DS && qname_lower_trimmed == origin_lower_for_strip {
                if let Some(ksk) = &zone.ksk_key {
                    let ds_records = Self::build_ds_records(ksk);
                    return Some(Self::build_response(
                        query_id,
                        &parsed.qname,
                        parsed.qtype,
                        &ds_records,
                        dnssec_ok,
                        edns_options.as_ref(),
                        zone.ksk_key.as_ref(),
                        &origin_canonical,
                    ));
                }
            }

            if record_type == RecordType::NSEC3PARAM
                && qname_lower_trimmed == origin_lower_for_strip
            {
                if let Some(nsec3param_record) = Self::build_nsec3param_record(&zone) {
                    return Some(Self::build_response(
                        query_id,
                        &parsed.qname,
                        parsed.qtype,
                        &[nsec3param_record],
                        dnssec_ok,
                        edns_options.as_ref(),
                        zone.zsk_key.as_ref(),
                        &origin_canonical,
                    ));
                }
            }
        }

        #[cfg(feature = "mesh")]
        if let (Some(registry), Some(ip)) = (ctx.mesh_registry, client_ip) {
            if let Some(mesh_records) =
                Self::resolve_from_mesh(registry, &parsed.qname, ip, ctx.geoip_lookup, parsed.qtype)
            {
                if !mesh_records.is_empty() {
                    tracing::debug!("Resolved {} from mesh network", parsed.qname);
                    let mesh_zone = ctx.zones.find_by_suffix(&parsed.qname);
                    let zsk = mesh_zone.as_ref().and_then(|zone| zone.zsk_key.as_ref());
                    return Some(Self::build_response(
                        query_id,
                        &parsed.qname,
                        parsed.qtype,
                        &mesh_records,
                        dnssec_ok,
                        edns_options.as_ref(),
                        zsk,
                        &parsed.qname,
                    ));
                }
            }
        }

        // DNS64 synthesis: if AAAA query found no records, try synthesizing from A records
        if parsed.qtype == 28 {
            if let Some(translator) = ctx.dns64_translator {
                if translator.should_synthesize(28, client_ip) {
                    if let Some(zone) = ctx.zones.find_by_suffix(&parsed.qname) {
                        let a_key = (lookup_name.clone(), RecordType::A);
                        if let Some(a_records) = zone.records.get(&a_key) {
                            let aaaa_records: Vec<DnsZoneRecord> = a_records
                                .iter()
                                .filter_map(|rec| {
                                    rec.value.parse::<std::net::Ipv4Addr>().ok().map(|ipv4| {
                                        let synth = translator.config().synthesize_aaaa(ipv4);
                                        DnsZoneRecord {
                                            name: rec.name.clone(),
                                            record_type: RecordType::AAAA,
                                            value: synth.to_string(),
                                            ttl: rec.ttl,
                                            priority: None,
                                        }
                                    })
                                })
                                .collect();
                            if !aaaa_records.is_empty() {
                                tracing::debug!(
                                    "DNS64: Synthesized {} AAAA records from A records for {}",
                                    aaaa_records.len(),
                                    parsed.qname
                                );
                                let origin = qname_lower
                                    .split_once('.')
                                    .map(|(_, suffix)| format!(".{}", suffix))
                                    .unwrap_or_else(|| qname_lower.clone());
                                return Some(Self::build_response(
                                    query_id,
                                    &parsed.qname,
                                    parsed.qtype,
                                    &aaaa_records,
                                    dnssec_ok,
                                    edns_options.as_ref(),
                                    None,
                                    &origin,
                                ));
                            }
                        }
                    }
                }
            }
        }

        if dnssec_ok {
            // Check for NODATA: name exists but requested type does not
            // Use suffix index for O(k) lookup instead of O(n) full scan
            if let Some(zone) = ctx.zones.find_by_suffix_with_filter(&parsed.qname, |zone| {
                (zone.nsec_enabled || zone.nsec3_enabled)
                    && Self::is_nodata(zone, &parsed.qname, record_type)
            }) {
                let origin = zone.origin.clone();
                let soa_record = zone
                    .records
                    .get(&("@".to_string(), RecordType::SOA))
                    .and_then(|records| records.first().cloned());
                if zone.nsec3_enabled {
                    let nsec3_records = Self::build_nsec3_nodata(&zone, &parsed.qname, record_type);
                    let zsk = zone.zsk_key.as_ref();
                    return Some(Self::build_nodata_response(
                        parsed.id,
                        &parsed.qname,
                        parsed.qtype,
                        &nsec3_records,
                        50,
                        dnssec_ok,
                        edns_options.as_ref(),
                        zsk,
                        origin.as_str(),
                        soa_record.as_ref(),
                    ));
                } else if zone.nsec_enabled {
                    let nsec_records = Self::build_nsec_records(&zone, &parsed.qname, record_type);
                    let zsk = zone.zsk_key.as_ref();
                    return Some(Self::build_nodata_response(
                        parsed.id,
                        &parsed.qname,
                        parsed.qtype,
                        &nsec_records,
                        47,
                        dnssec_ok,
                        edns_options.as_ref(),
                        zsk,
                        origin.as_str(),
                        soa_record.as_ref(),
                    ));
                }
            }

            // NXDOMAIN NSEC/NSEC3 proof
            // Use suffix index for O(k) lookup instead of O(n) full scan
            if let Some(zone) = ctx.zones.find_by_suffix_with_filter(&parsed.qname, |zone| {
                zone.nsec_enabled || zone.nsec3_enabled
            }) {
                let origin = zone.origin.clone();
                if zone.nsec_enabled {
                    let nsec_records = Self::build_nsec_records(&zone, &parsed.qname, record_type);
                    if !nsec_records.is_empty() {
                        let zsk = zone.zsk_key.as_ref();
                        return Some(Self::build_nxdomain_response(
                            parsed.id,
                            &parsed.qname,
                            parsed.qtype,
                            &nsec_records,
                            47,
                            dnssec_ok,
                            edns_options.as_ref(),
                            zsk,
                            origin.as_str(),
                        ));
                    }
                } else if zone.nsec3_enabled {
                    let nsec3_records =
                        Self::build_nsec3_records(&zone, &parsed.qname, record_type);
                    if !nsec3_records.is_empty() {
                        let zsk = zone.zsk_key.as_ref();
                        return Some(Self::build_nxdomain_response(
                            parsed.id,
                            &parsed.qname,
                            parsed.qtype,
                            &nsec3_records,
                            50,
                            dnssec_ok,
                            edns_options.as_ref(),
                            zsk,
                            origin.as_str(),
                        ));
                    }
                }
            }
        }

        None
    }

    pub(super) fn build_nxdomain_response(
        response_id: u16,
        qname: &str,
        qtype: u16,
        nsec_records: &[DnsZoneRecord],
        nsec_record_type: u16,
        dnssec_ok: bool,
        edns_options: Option<&EdnsOptions>,
        zsk: Option<&crate::dnssec::ZoneSigningKey>,
        signer_name: &str,
    ) -> Arc<Vec<u8>> {
        let mut response = Vec::new();

        response.extend_from_slice(&response_id.to_be_bytes());

        let mut flags =
            crate::parsed_query::build_response_flags(true, false, true, true, false, 3);
        // AD flag: only set when NSEC/NSEC3 proof records are present
        if dnssec_ok && !nsec_records.is_empty() {
            flags |= 0x0020;
        }
        response.extend_from_slice(&flags.to_be_bytes());

        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&(nsec_records.len() as u16).to_be_bytes());

        let name_parts: Vec<&str> = if qname.is_empty() || qname == "@" {
            vec![""]
        } else {
            qname.split('.').collect()
        };

        for part in &name_parts {
            if !part.is_empty() {
                response.push((*part).len() as u8);
                response.extend_from_slice(part.as_bytes());
            }
        }
        response.push(0);

        response.extend_from_slice(&qtype.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());

        for nsec_record in nsec_records {
            let nsec_name_parts: Vec<&str> = nsec_record.name.split('.').collect();

            for part in &nsec_name_parts {
                if !part.is_empty() {
                    response.push((*part).len() as u8);
                    response.extend_from_slice(part.as_bytes());
                }
            }
            response.push(0);

            response.extend_from_slice(&nsec_record_type.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&nsec_record.ttl.to_be_bytes());

            if let Ok(nsec_data) = hex::decode(&nsec_record.value) {
                response.extend_from_slice(&(nsec_data.len() as u16).to_be_bytes());
                response.extend_from_slice(&nsec_data);
            }
        }

        if dnssec_ok && !nsec_records.is_empty() {
            if let Some(key) = zsk {
                for nsec_record in nsec_records {
                    let rrsig = Self::create_signed_rrsig(nsec_record, signer_name, key);
                    if !rrsig.is_empty() {
                        let nsec_name_parts: Vec<&str> = nsec_record.name.split('.').collect();
                        for part in &nsec_name_parts {
                            if !part.is_empty() {
                                response.push((*part).len() as u8);
                                response.extend_from_slice(part.as_bytes());
                            }
                        }
                        response.push(0);
                        response.extend_from_slice(&46u16.to_be_bytes());
                        response.extend_from_slice(&1u16.to_be_bytes());
                        response.extend_from_slice(&nsec_record.ttl.to_be_bytes());
                        response.extend_from_slice(&(rrsig.len() as u16).to_be_bytes());
                        response.extend_from_slice(&rrsig);
                    }
                }
            }
        }

        if let Some(edns) = edns_options {
            let opt_record =
                crate::edns::EdnsOptions::build_opt_record(edns.udp_payload_size, dnssec_ok);
            response.extend_from_slice(&[0]);
            response.extend_from_slice(&41u16.to_be_bytes());
            response.extend_from_slice(&(opt_record.len() as u16).to_be_bytes());
            response.extend_from_slice(&opt_record);
        } else if dnssec_ok {
            let opt_record = crate::edns::EdnsOptions::build_opt_record(4096, dnssec_ok);
            response.extend_from_slice(&[0]);
            response.extend_from_slice(&41u16.to_be_bytes());
            response.extend_from_slice(&(opt_record.len() as u16).to_be_bytes());
            response.extend_from_slice(&opt_record);
        }

        Arc::new(response)
    }

    pub(super) fn build_nodata_response(
        response_id: u16,
        qname: &str,
        qtype: u16,
        nsec_records: &[DnsZoneRecord],
        nsec_record_type: u16,
        dnssec_ok: bool,
        edns_options: Option<&EdnsOptions>,
        zsk: Option<&crate::dnssec::ZoneSigningKey>,
        signer_name: &str,
        soa_record: Option<&DnsZoneRecord>,
    ) -> Arc<Vec<u8>> {
        let mut response = Vec::new();

        response.extend_from_slice(&response_id.to_be_bytes());

        // NODATA: RCODE 0 (NOERROR), authoritative answer
        let mut flags =
            crate::parsed_query::build_response_flags(true, false, true, true, false, 0);
        // AD flag: set when NSEC3 proof records are present
        if dnssec_ok && !nsec_records.is_empty() {
            flags |= 0x0020;
        }
        response.extend_from_slice(&flags.to_be_bytes());

        response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        response.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT (empty for NODATA)
        response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT placeholder
        let nscount_offset = response.len() - 2;
        response.extend_from_slice(&(nsec_records.len() as u16).to_be_bytes()); // ARCOUNT placeholder

        let name_parts: Vec<&str> = if qname.is_empty() || qname == "@" {
            vec![""]
        } else {
            qname.split('.').collect()
        };

        for part in &name_parts {
            if !part.is_empty() {
                response.push((*part).len() as u8);
                response.extend_from_slice(part.as_bytes());
            }
        }
        response.push(0);

        response.extend_from_slice(&qtype.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());

        let mut nscount: u16 = 0;

        // Add SOA record to authority section (RFC 2308)
        if let Some(soa) = soa_record {
            let soa_name_parts: Vec<&str> = if qname.is_empty() || qname == "@" {
                vec![""]
            } else {
                qname.split('.').collect()
            };

            for part in &soa_name_parts {
                if !part.is_empty() {
                    response.push((*part).len() as u8);
                    response.extend_from_slice(part.as_bytes());
                }
            }
            response.push(0);

            response.extend_from_slice(&RecordType::SOA.to_u16().to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&soa.ttl.to_be_bytes());

            // SOA record value as wire format
            let soa_value = soa.value.as_bytes();
            response.extend_from_slice(&(soa_value.len() as u16).to_be_bytes());
            response.extend_from_slice(soa_value);
            nscount += 1;
        }

        for nsec_record in nsec_records {
            let nsec_name_parts: Vec<&str> = nsec_record.name.split('.').collect();

            for part in &nsec_name_parts {
                if !part.is_empty() {
                    response.push((*part).len() as u8);
                    response.extend_from_slice(part.as_bytes());
                }
            }
            response.push(0);

            response.extend_from_slice(&nsec_record_type.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&nsec_record.ttl.to_be_bytes());

            if let Ok(nsec_data) = hex::decode(&nsec_record.value) {
                response.extend_from_slice(&(nsec_data.len() as u16).to_be_bytes());
                response.extend_from_slice(&nsec_data);
            }
            nscount += 1;
        }

        if dnssec_ok && !nsec_records.is_empty() {
            if let Some(key) = zsk {
                for nsec_record in nsec_records {
                    let rrsig = Self::create_signed_rrsig(nsec_record, signer_name, key);
                    if !rrsig.is_empty() {
                        let nsec_name_parts: Vec<&str> = nsec_record.name.split('.').collect();
                        for part in &nsec_name_parts {
                            if !part.is_empty() {
                                response.push((*part).len() as u8);
                                response.extend_from_slice(part.as_bytes());
                            }
                        }
                        response.push(0);
                        response.extend_from_slice(&46u16.to_be_bytes());
                        response.extend_from_slice(&1u16.to_be_bytes());
                        response.extend_from_slice(&nsec_record.ttl.to_be_bytes());
                        response.extend_from_slice(&(rrsig.len() as u16).to_be_bytes());
                        response.extend_from_slice(&rrsig);
                        nscount += 1;
                    }
                }
            }
        }

        // Update NSCOUNT
        response[nscount_offset..nscount_offset + 2].copy_from_slice(&nscount.to_be_bytes());

        if let Some(edns) = edns_options {
            let opt_record =
                crate::edns::EdnsOptions::build_opt_record(edns.udp_payload_size, dnssec_ok);
            response.extend_from_slice(&[0]);
            response.extend_from_slice(&41u16.to_be_bytes());
            response.extend_from_slice(&(opt_record.len() as u16).to_be_bytes());
            response.extend_from_slice(&opt_record);
        } else if dnssec_ok {
            let opt_record = crate::edns::EdnsOptions::build_opt_record(4096, dnssec_ok);
            response.extend_from_slice(&[0]);
            response.extend_from_slice(&41u16.to_be_bytes());
            response.extend_from_slice(&(opt_record.len() as u16).to_be_bytes());
            response.extend_from_slice(&opt_record);
        }

        Arc::new(response)
    }

    #[deprecated(note = "Use ParsedDnsQuery::parse instead; retained for fallback paths only")]
    pub(super) fn extract_query_name(query: &[u8]) -> String {
        wire::parse_query_name(query, 12).unwrap_or_else(|| "unknown".to_string())
    }
}
