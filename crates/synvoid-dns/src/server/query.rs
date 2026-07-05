use super::*;

#[cfg(feature = "mesh")]
use crate::mesh_sync::MeshDnsRegistry;

use crate::cache::TransportClass;
use crate::parsed_query::ParsedDnsQuery;

#[derive(Debug)]
enum TtlParseError {
    Truncated,
    MalformedLabel,
}

impl DnsServer {
    #[cfg(test)]
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

    /// Handle a single DNS query over TCP.
    ///
    /// # One-query-per-connection policy
    ///
    /// TCP mode is **one-query-per-connection** (RFC 7766 §4). The server reads
    /// the 2-byte length prefix, processes exactly one query, writes the response,
    /// and closes the connection. This matches the common DNS-over-TCP behavior
    /// where clients open a new connection per query.
    ///
    /// This design is intentionally conservative: the server never reads a second
    /// length-prefixed frame from the same TCP stream. The connection is dropped
    /// after sending the single response (or error), which signals EOF to the
    /// client.
    ///
    /// # AXFR/IXFR exception
    ///
    /// AXFR/IXFR transfers send multiple length-prefixed messages over the same
    /// connection, but the connection still closes after the transfer completes.
    /// This is handled as a special case before the one-query return.
    ///
    /// # Deferred: persistent TCP
    ///
    /// Persistent TCP connections (pipelining, multiplexing, connection reuse
    /// across multiple queries) are **not implemented** in this milestone. They
    /// require additional framing state, idle timeout management per query, and
    /// connection pool accounting. This is deferred to a future milestone.
    pub(super) async fn handle_tcp_query(
        mut stream: tokio::net::TcpStream,
        ctx: QueryContext<'_>,
    ) -> Result<(), String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        // ── One-query-per-connection ────────────────────────────────────
        // This handler reads exactly ONE length-prefixed DNS message,
        // processes it, writes the response, and returns. The TcpStream
        // is dropped on return, closing the connection. We never loop
        // to read a second query from the same stream.

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

        // Firewall check — skip if parse fails (malformed query → FORMERR anyway)
        if let (Some(fw), Ok(ref parsed_q)) = (ctx.firewall.as_ref(), &parsed_tcp) {
            let fw_read = fw.read();
            match fw_read.evaluate_query(parsed_q, client_ip, &parsed_q.qname) {
                Ok(decision) => {
                    if decision.action == crate::firewall::DnsFirewallAction::Block {
                        tracing::warn!(
                            "DNS TCP query blocked by firewall: rule={} client={} qname={}",
                            decision.rule_id,
                            client_ip,
                            parsed_q.qname
                        );
                        return Err("Blocked by firewall".to_string());
                    }
                }
                Err(e) => {
                    tracing::warn!("TCP Firewall evaluation error: {}", e);
                }
            }
        }

        let skip_coalesce = parsed_tcp
            .as_ref()
            .map(|pq| crate::query_coalesce::should_skip_coalescing(pq.qtype, pq.flags.opcode))
            .unwrap_or(false);

        let response = if let Some(coalescer) = ctx.query_coalescer {
            let query_key = if skip_coalesce {
                None
            } else if let Ok(ref parsed_q) = parsed_tcp {
                crate::query_coalesce::QueryKey::from_parsed(
                    parsed_q,
                    Some(client_ip),
                    &query,
                    Some(TransportClass::Tcp),
                )
            } else {
                crate::query_coalesce::QueryKey::from_query(
                    &query,
                    Some(client_ip),
                    Some(TransportClass::Tcp),
                )
            };

            if let Some(key) = query_key {
                match coalescer.get_or_wait(key.clone()).await {
                    Some(crate::query_coalesce::CoalesceResult::Response(resp)) => Some(resp),
                    Some(crate::query_coalesce::CoalesceResult::NewQuery(_tx)) => {
                        let resp = if let (Some(c), Ok(ref parsed_q)) = (ctx.cache, &parsed_tcp) {
                            Self::handle_parsed_query_with_cache(
                                &ctx,
                                parsed_q,
                                &query,
                                c,
                                TransportClass::Tcp,
                                Some(client_ip),
                            )
                        } else if let Some(c) = ctx.cache {
                            Self::handle_query_with_cache(
                                &ctx,
                                &query,
                                c,
                                TransportClass::Tcp,
                                Some(client_ip),
                            )
                        } else if let Ok(ref parsed_q) = parsed_tcp {
                            Self::handle_parsed_query(&ctx, parsed_q, &query, Some(client_ip))
                        } else {
                            Self::handle_query(&ctx, &query, Some(client_ip))
                        };

                        if let Some(ref r) = resp {
                            coalescer.broadcast_response(key.clone(), r.clone());
                        } else {
                            coalescer.cancel_in_flight(&key);
                        }

                        resp
                    }
                    None => {
                        if let (Some(c), Ok(ref parsed_q)) = (ctx.cache, &parsed_tcp) {
                            Self::handle_parsed_query_with_cache(
                                &ctx,
                                parsed_q,
                                &query,
                                c,
                                TransportClass::Tcp,
                                Some(client_ip),
                            )
                        } else if let Some(c) = ctx.cache {
                            Self::handle_query_with_cache(
                                &ctx,
                                &query,
                                c,
                                TransportClass::Tcp,
                                Some(client_ip),
                            )
                        } else if let Ok(ref parsed_q) = parsed_tcp {
                            Self::handle_parsed_query(&ctx, parsed_q, &query, Some(client_ip))
                        } else {
                            Self::handle_query(&ctx, &query, Some(client_ip))
                        }
                    }
                    _ => {
                        if let (Some(c), Ok(ref parsed_q)) = (ctx.cache, &parsed_tcp) {
                            Self::handle_parsed_query_with_cache(
                                &ctx,
                                parsed_q,
                                &query,
                                c,
                                TransportClass::Tcp,
                                Some(client_ip),
                            )
                        } else if let Some(c) = ctx.cache {
                            Self::handle_query_with_cache(
                                &ctx,
                                &query,
                                c,
                                TransportClass::Tcp,
                                Some(client_ip),
                            )
                        } else if let Ok(ref parsed_q) = parsed_tcp {
                            Self::handle_parsed_query(&ctx, parsed_q, &query, Some(client_ip))
                        } else {
                            Self::handle_query(&ctx, &query, Some(client_ip))
                        }
                    }
                }
            } else if let (Some(c), Ok(ref parsed_q)) = (ctx.cache, &parsed_tcp) {
                Self::handle_parsed_query_with_cache(
                    &ctx,
                    parsed_q,
                    &query,
                    c,
                    TransportClass::Tcp,
                    Some(client_ip),
                )
            } else if let Some(c) = ctx.cache {
                Self::handle_query_with_cache(&ctx, &query, c, TransportClass::Tcp, Some(client_ip))
            } else if let Ok(ref parsed_q) = parsed_tcp {
                Self::handle_parsed_query(&ctx, parsed_q, &query, Some(client_ip))
            } else {
                Self::handle_query(&ctx, &query, Some(client_ip))
            }
        } else if let (Some(c), Ok(ref parsed_q)) = (ctx.cache, &parsed_tcp) {
            Self::handle_parsed_query_with_cache(
                &ctx,
                parsed_q,
                &query,
                c,
                TransportClass::Tcp,
                Some(client_ip),
            )
        } else if let Some(c) = ctx.cache {
            Self::handle_query_with_cache(&ctx, &query, c, TransportClass::Tcp, Some(client_ip))
        } else if let Ok(ref parsed_q) = parsed_tcp {
            Self::handle_parsed_query(&ctx, parsed_q, &query, Some(client_ip))
        } else {
            Self::handle_query(&ctx, &query, Some(client_ip))
        };

        if let Some(resp) = response {
            if let Some(zt) = ctx.zone_transfer {
                if let Ok(ref parsed_zt) = parsed_tcp {
                    if parsed_zt.is_axfr() {
                        let tsig =
                            crate::tsig::parse_tsig_from_query(&query, parsed_zt.question_end);
                        match zt.handle_axfr_request_messages(
                            &parsed_zt.qname,
                            client_ip,
                            tsig.as_ref(),
                            parsed_zt.id,
                            &query,
                            true, // TCP path
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
                    tracing::warn!(
                        transport = "tcp",
                        client = %client_ip,
                        response_size = resp.len(),
                        "{}", e
                    );

                    // Build a SERVFAIL that echoes the original question section
                    // when the query was successfully parsed (RFC 1035 §4.1.1).
                    //
                    // When parsing succeeds, we capture query ID, RD bit, and the
                    // full question section (QNAME wire + QTYPE + QCLASS) from the
                    // parsed query to construct a standards-compliant SERVFAIL.
                    //
                    // When parsing fails (malformed query), we extract what we can
                    // from the raw header bytes and emit a minimal SERVFAIL with
                    // no question section (QDCOUNT=0).
                    let (query_id, rd, question_bytes) = if let Ok(ref parsed_q) = parsed_tcp {
                        // Question section: QNAME (wire) + QTYPE (2) + QCLASS (2)
                        let q = &query[12..parsed_q.question_end];
                        (
                            parsed_q.id,
                            parsed_q.flags.recursion_desired,
                            Some(q.to_vec()),
                        )
                    } else if query.len() >= 4 {
                        let qid = u16::from_be_bytes([query[0], query[1]]);
                        let flags = u16::from_be_bytes([query[2], query[3]]);
                        let rd = (flags & 0x0100) != 0;
                        (qid, rd, None)
                    } else {
                        (0u16, false, None)
                    };

                    // QR=1, AA=0, TC=0, RD=echoed, RA=0, AD=0, RCODE=2 (SERVFAIL)
                    //
                    // RA=0: We are returning SERVFAIL, not claiming recursion is
                    // available. A SERVFAIL with RA=1 could mislead clients into
                    // retrying via recursion when the real issue is response size.
                    //
                    // AD=0: We have not validated anything for this response, so
                    // the Authentic Data bit must not be set.
                    //
                    // AA=0: We do not know whether this query is for an
                    // authoritative zone at this point in the TCP handler, so we
                    // omit the Authoritative Answer bit. A future enhancement
                    // could check zone context and set AA=true for authoritative
                    // SERVFAIL responses.
                    let flags = crate::parsed_query::build_response_flags(
                        false, false, rd, false, false, 2,
                    );

                    let qdcount: u16 = if question_bytes.is_some() { 1 } else { 0 };

                    let mut servfail =
                        Vec::with_capacity(12 + question_bytes.as_ref().map_or(0, |q| q.len()));
                    servfail.extend_from_slice(&query_id.to_be_bytes());
                    servfail.extend_from_slice(&flags.to_be_bytes());
                    servfail.extend_from_slice(&qdcount.to_be_bytes());
                    servfail.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
                    servfail.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
                    servfail.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
                    if let Some(q) = question_bytes {
                        servfail.extend_from_slice(&q);
                    }

                    // Verify the SERVFAIL itself fits within the TCP hard limit.
                    // The SERVFAIL is at most ~271 bytes (12 header + 259 max question),
                    // so this should always pass for any reasonable limit, but we
                    // enforce it defensively.
                    if let Some(limits) = ctx.connection_limits {
                        if let Err(e) = limits.validate_response_size(servfail.len()) {
                            tracing::warn!(
                                transport = "tcp",
                                client = %client_ip,
                                servfail_size = servfail.len(),
                                "SERVFAIL itself exceeds hard limit: {}. Closing connection.",
                                e
                            );
                            return Ok(());
                        }
                    }

                    let len = servfail.len() as u16;
                    let mut response_buf = len.to_be_bytes().to_vec();
                    response_buf.extend_from_slice(&servfail);
                    let _ = stream.write_all(&response_buf).await;
                    return Ok(());
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
        transport_class: TransportClass,
        client_ip: Option<std::net::IpAddr>,
    ) -> Option<Arc<Vec<u8>>> {
        let parsed = ParsedDnsQuery::parse(query).ok()?;
        Self::handle_parsed_query_with_cache(ctx, &parsed, query, cache, transport_class, client_ip)
    }

    pub(super) fn handle_parsed_query_with_cache(
        ctx: &QueryContext,
        parsed: &ParsedDnsQuery<'_>,
        query: &[u8],
        cache: &Arc<DnsCache>,
        transport_class: TransportClass,
        client_ip: Option<std::net::IpAddr>,
    ) -> Option<Arc<Vec<u8>>> {
        if parsed.is_notify() {
            if let Some(handler) = ctx.notify_handler {
                if let Some(ip) = client_ip {
                    return handler.handle_notify(query, ip).map(Arc::new);
                }
            }
            return wire::build_error_response(query, wire::RCODE_NOTIMP).map(Arc::new);
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
            return wire::build_error_response(query, wire::RCODE_NOTIMP).map(Arc::new);
        }

        if parsed.is_axfr() {
            if let (Some(zt), Some(ip)) = (ctx.zone_transfer, client_ip) {
                let tsig = crate::tsig::parse_tsig_from_query(query, parsed.question_end);
                let message_id = u16::from_be_bytes([query[0], query[1]]);
                match zt.handle_axfr_request(
                    &parsed.qname,
                    ip,
                    tsig.as_ref(),
                    message_id,
                    query,
                    transport_class == TransportClass::Tcp,
                ) {
                    Ok(response) => return Some(Arc::new(response)),
                    Err(e) => {
                        tracing::warn!("AXFR failed: {}", e);
                        return None;
                    }
                }
            }
            return wire::build_error_response(query, wire::RCODE_NOTIMP).map(Arc::new);
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
            return wire::build_error_response(query, wire::RCODE_NOTIMP).map(Arc::new);
        }

        let cache_key = if let Some(ip) = client_ip {
            CacheKey::from_parsed_authoritative(parsed, ip, transport_class)
        } else {
            CacheKey::from_parsed_authoritative(
                parsed,
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                transport_class,
            )
        };

        if let Some(cached) = cache.get(&cache_key) {
            return Some(cached);
        }

        let result = Self::handle_parsed_query(ctx, parsed, query, client_ip);

        if let Some(ref data) = result {
            let ttl = Self::extract_ttl_from_response(data.as_ref(), ctx.negative_cache_ttl);
            if ttl > 0 {
                cache.insert(cache_key, data.as_ref().clone(), ttl);
            }
        }

        result
    }

    /// Skip a DNS name in a packet, handling compression pointers.
    fn skip_dns_name(buf: &[u8], pos: usize) -> Result<usize, TtlParseError> {
        if pos >= buf.len() {
            return Err(TtlParseError::Truncated);
        }
        let mut p = pos;
        loop {
            if p >= buf.len() {
                return Err(TtlParseError::Truncated);
            }
            let len = buf[p];
            if len == 0 {
                return Ok(p + 1);
            }
            if (len & 0xC0) == 0xC0 {
                if p + 2 > buf.len() {
                    return Err(TtlParseError::Truncated);
                }
                return Ok(p + 2);
            }
            if len > 63 {
                return Err(TtlParseError::MalformedLabel);
            }
            p += 1 + len as usize;
        }
    }

    /// Skip the header (12 bytes) and all question entries.
    fn skip_header_and_question(buf: &[u8]) -> Result<usize, TtlParseError> {
        if buf.len() < 12 {
            return Err(TtlParseError::Truncated);
        }
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let mut pos = 12;
        for _ in 0..qdcount {
            pos = Self::skip_dns_name(buf, pos)?;
            pos += 4; // QTYPE + QCLASS
        }
        Ok(pos)
    }

    /// Skip a single RR (name + type + class + ttl + rdlength + rdata).
    fn skip_rr_safe(buf: &[u8], pos: usize) -> Result<usize, TtlParseError> {
        let name_end = Self::skip_dns_name(buf, pos)?;
        if name_end + 10 > buf.len() {
            return Err(TtlParseError::Truncated);
        }
        let rdlength = u16::from_be_bytes([buf[name_end + 8], buf[name_end + 9]]) as usize;
        Ok(name_end + 10 + rdlength)
    }

    /// Extract the minimum TTL from all answer RRs.
    fn first_answer_ttl(buf: &[u8]) -> Result<Option<u32>, TtlParseError> {
        let mut pos = Self::skip_header_and_question(buf)?;
        let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
        if ancount == 0 {
            return Ok(None);
        }
        let mut min_ttl = u32::MAX;
        for _ in 0..ancount {
            let name_end = Self::skip_dns_name(buf, pos)?;
            if name_end + 10 > buf.len() {
                return Err(TtlParseError::Truncated);
            }
            // After name: type(2) + class(2) + TTL(4) + rdlength(2)
            let ttl = u32::from_be_bytes([
                buf[name_end + 4],
                buf[name_end + 5],
                buf[name_end + 6],
                buf[name_end + 7],
            ]);
            min_ttl = min_ttl.min(ttl);
            pos = Self::skip_rr_safe(buf, pos)?;
        }
        Ok(Some(min_ttl))
    }

    /// Extract negative TTL from SOA authority record.
    fn negative_soa_ttl(buf: &[u8]) -> Result<Option<u32>, TtlParseError> {
        let answer_end = {
            let mut pos = Self::skip_header_and_question(buf)?;
            let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
            for _ in 0..ancount {
                pos = Self::skip_rr_safe(buf, pos)?;
            }
            pos
        };
        let nscount = u16::from_be_bytes([buf[8], buf[9]]) as usize;
        let mut pos = answer_end;
        for _ in 0..nscount {
            let name_end = Self::skip_dns_name(buf, pos)?;
            if name_end + 10 > buf.len() {
                return Err(TtlParseError::Truncated);
            }
            let rtype = u16::from_be_bytes([buf[name_end], buf[name_end + 1]]);
            let ttl = u32::from_be_bytes([
                buf[name_end + 4],
                buf[name_end + 5],
                buf[name_end + 6],
                buf[name_end + 7],
            ]);
            let rdlength = u16::from_be_bytes([buf[name_end + 8], buf[name_end + 9]]) as usize;
            if rtype == 6 && rdlength >= 20 {
                // SOA MINIMUM is the last 4 bytes of RDATA
                let rdstart = name_end + 10;
                let minimum_pos = rdstart + rdlength - 4;
                if minimum_pos + 4 > buf.len() {
                    return Err(TtlParseError::Truncated);
                }
                let soa_minimum = u32::from_be_bytes([
                    buf[minimum_pos],
                    buf[minimum_pos + 1],
                    buf[minimum_pos + 2],
                    buf[minimum_pos + 3],
                ]);
                return Ok(Some(ttl.min(soa_minimum)));
            }
            pos = name_end + 10 + rdlength;
        }
        Ok(None)
    }

    pub(super) fn extract_ttl_from_response(response: &[u8], negative_cache_ttl: u32) -> u32 {
        if response.len() < 12 {
            return 0;
        }

        let flags = u16::from_be_bytes([response[2], response[3]]);
        let rcode = flags & 0x000F;
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        let nscount = u16::from_be_bytes([response[8], response[9]]);

        // SERVFAIL (2) and REFUSED (5) are transient — never cache.
        if rcode == 2 || rcode == 5 {
            return 0;
        }

        // Positive response: extract TTL from answer RRs.
        if ancount > 0 {
            if let Ok(Some(ttl)) = Self::first_answer_ttl(response) {
                return ttl;
            }
            return 0;
        }

        // NXDOMAIN (3) or NODATA (0 with no answers): try SOA negative TTL.
        if rcode == 3 || nscount > 0 {
            if let Ok(Some(soa_min_ttl)) = Self::negative_soa_ttl(response) {
                return soa_min_ttl.min(negative_cache_ttl);
            }
        }

        // No SOA found — for NXDOMAIN still apply negative cache.
        if rcode == 3 {
            return negative_cache_ttl;
        }

        0
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
        let parsed = ParsedDnsQuery::parse(query).ok()?;
        Self::handle_parsed_query(ctx, &parsed, query, client_ip)
    }

    pub(super) fn handle_parsed_query(
        ctx: &QueryContext,
        parsed: &ParsedDnsQuery<'_>,
        query: &[u8],
        client_ip: Option<std::net::IpAddr>,
    ) -> Option<Arc<Vec<u8>>> {
        use crate::server::RecordTypeExt;

        let query_id = parsed.id;
        let rd = parsed.flags.recursion_desired;

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
                        let (resp, _report) = Self::build_acme_txt_response(
                            query_id,
                            &parsed.qname,
                            &txt_value,
                            edns_options.as_ref(),
                        );
                        return Some(resp);
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
                None => {
                    let (resp, _report) = Self::build_refused(
                        parsed.id,
                        &parsed.qname,
                        parsed.qtype,
                        edns_options.as_ref(),
                    );
                    return Some(resp);
                }
            },
            None => {
                let (resp, _report) = Self::build_refused(
                    parsed.id,
                    &parsed.qname,
                    parsed.qtype,
                    edns_options.as_ref(),
                );
                return Some(resp);
            }
        };

        // Defense-in-depth: SERVFAIL if the zone somehow lacks a SOA record.
        // Zone loader validates SOA presence, but a zone loaded from persistence
        // or a race condition could bypass that check.
        if zone.get_soa().is_none() {
            tracing::error!(
                zone = %origin_str,
                qname = %parsed.qname,
                "Zone has no SOA record, returning SERVFAIL"
            );
            let flags = crate::parsed_query::build_response_flags(true, false, rd, false, false, 2);
            let question = super::wire::build_question(&parsed.qname, parsed.qtype, 1);
            let has_opt = edns_options.is_some();
            let arcount: u16 = if has_opt { 1 } else { 0 };
            let mut packet = Vec::with_capacity(12 + question.len() + 16);
            packet.extend_from_slice(&parsed.id.to_be_bytes());
            packet.extend_from_slice(&flags.to_be_bytes());
            packet.extend_from_slice(&1u16.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes());
            packet.extend_from_slice(&arcount.to_be_bytes());
            packet.extend_from_slice(&question);
            if let Some(edns) = edns_options {
                let opt =
                    super::response_encoder::build_opt_encoded_record(edns.udp_payload_size, false);
                packet.extend_from_slice(&opt.bytes);
            }
            return Some(Arc::new(packet));
        }

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
            let (resp, _report) = Self::build_response(
                query_id,
                &parsed.qname,
                parsed.qtype,
                records,
                dnssec_ok,
                edns_options.as_ref(),
                zone.zsk_key.as_ref(),
                &origin_canonical,
                rd,
            );
            return Some(resp);
        }

        if record_type == RecordTypeExt::UNKNOWN || record_type == RecordType::A {
            let cname_key = (lookup_name.clone(), RecordType::CNAME);
            if let Some(cname_records) = zone.records.get(&cname_key) {
                if let Some(cname) = cname_records.first() {
                    let cname_target = cname.value.trim_end_matches('.');
                    let qname_stripped = parsed.qname.trim_end_matches('.');
                    if cname_target.eq_ignore_ascii_case(qname_stripped) {
                        tracing::warn!("CNAME loop detected for {}", parsed.qname);
                        let (resp, _report) = Self::build_refused(
                            parsed.id,
                            &parsed.qname,
                            parsed.qtype,
                            edns_options.as_ref(),
                        );
                        return Some(resp);
                    }
                }
                let (resp, _report) = Self::build_response(
                    query_id,
                    &parsed.qname,
                    parsed.qtype,
                    cname_records,
                    dnssec_ok,
                    edns_options.as_ref(),
                    zone.zsk_key.as_ref(),
                    &origin_canonical,
                    rd,
                );
                return Some(resp);
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
                let (resp, _report) = Self::build_response(
                    query_id,
                    &parsed.qname,
                    parsed.qtype,
                    &all_records,
                    dnssec_ok,
                    edns_options.as_ref(),
                    zone.zsk_key.as_ref(),
                    &origin_canonical,
                    rd,
                );
                return Some(resp);
            }

            if record_type == RecordType::DNSKEY && qname_lower_trimmed == origin_lower_for_strip {
                let dnskey_records = Self::build_dnskey_records(&zone);
                let (resp, _report) = Self::build_response(
                    query_id,
                    &parsed.qname,
                    parsed.qtype,
                    &dnskey_records,
                    dnssec_ok,
                    edns_options.as_ref(),
                    zone.ksk_key.as_ref(),
                    &origin_canonical,
                    rd,
                );
                return Some(resp);
            }

            if parsed.qtype == 59 && qname_lower_trimmed == origin_lower_for_strip {
                if let Some(ksk) = &zone.ksk_key {
                    let cds_records = Self::build_cds_records(ksk);
                    let (resp, _report) = Self::build_response(
                        query_id,
                        &parsed.qname,
                        parsed.qtype,
                        &cds_records,
                        dnssec_ok,
                        edns_options.as_ref(),
                        zone.ksk_key.as_ref(),
                        &origin_canonical,
                        rd,
                    );
                    return Some(resp);
                }
            }

            if parsed.qtype == 60 && qname_lower_trimmed == origin_lower_for_strip {
                let cdnskey_records = Self::build_cdnskey_records(&zone);
                let (resp, _report) = Self::build_response(
                    query_id,
                    &parsed.qname,
                    parsed.qtype,
                    &cdnskey_records,
                    dnssec_ok,
                    edns_options.as_ref(),
                    zone.ksk_key.as_ref(),
                    &origin_canonical,
                    rd,
                );
                return Some(resp);
            }

            if record_type == RecordType::DS && qname_lower_trimmed == origin_lower_for_strip {
                if let Some(ksk) = &zone.ksk_key {
                    let ds_records = Self::build_ds_records(ksk);
                    let (resp, _report) = Self::build_response(
                        query_id,
                        &parsed.qname,
                        parsed.qtype,
                        &ds_records,
                        dnssec_ok,
                        edns_options.as_ref(),
                        zone.ksk_key.as_ref(),
                        &origin_canonical,
                        rd,
                    );
                    return Some(resp);
                }
            }

            if record_type == RecordType::NSEC3PARAM
                && qname_lower_trimmed == origin_lower_for_strip
            {
                if let Some(nsec3param_record) = Self::build_nsec3param_record(&zone) {
                    let (resp, _report) = Self::build_response(
                        query_id,
                        &parsed.qname,
                        parsed.qtype,
                        &[nsec3param_record],
                        dnssec_ok,
                        edns_options.as_ref(),
                        zone.zsk_key.as_ref(),
                        &origin_canonical,
                        rd,
                    );
                    return Some(resp);
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
                    let (resp, _report) = Self::build_response(
                        query_id,
                        &parsed.qname,
                        parsed.qtype,
                        &mesh_records,
                        dnssec_ok,
                        edns_options.as_ref(),
                        zsk,
                        &parsed.qname,
                        rd,
                    );
                    return Some(resp);
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
                                let (resp, _report) = Self::build_response(
                                    query_id,
                                    &parsed.qname,
                                    parsed.qtype,
                                    &aaaa_records,
                                    dnssec_ok,
                                    edns_options.as_ref(),
                                    None,
                                    &origin,
                                    rd,
                                );
                                return Some(resp);
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
                        rd,
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
                        rd,
                    ));
                }
            }

            // NXDOMAIN NSEC/NSEC3 proof
            // Use suffix index for O(k) lookup instead of O(n) full scan
            if let Some(zone) = ctx.zones.find_by_suffix_with_filter(&parsed.qname, |zone| {
                zone.nsec_enabled || zone.nsec3_enabled
            }) {
                let origin = zone.origin.clone();
                let soa_record = zone
                    .records
                    .get(&("@".to_string(), RecordType::SOA))
                    .and_then(|records| records.first().cloned());
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
                            soa_record.as_ref(),
                            rd,
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
                            soa_record.as_ref(),
                            rd,
                        ));
                    }
                }
            }
        }

        let outcome = zone.lookup_authoritative(&lookup_name, parsed.qtype);
        match outcome {
            AuthoritativeLookupOutcome::NoData { soa, .. } => {
                let (resp, _report) = Self::build_unsigned_nodata(
                    parsed.id,
                    &parsed.qname,
                    parsed.qtype,
                    soa.as_ref(),
                    edns_options.as_ref(),
                    ctx.negative_cache_ttl,
                    rd,
                );
                Some(resp)
            }
            AuthoritativeLookupOutcome::NxDomain { soa, .. } => {
                let (resp, _report) = Self::build_unsigned_nxdomain(
                    parsed.id,
                    &parsed.qname,
                    parsed.qtype,
                    soa.as_ref(),
                    edns_options.as_ref(),
                    ctx.negative_cache_ttl,
                    rd,
                );
                Some(resp)
            }
            _ => None,
        }
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
        soa_record: Option<&DnsZoneRecord>,
        rd: bool,
    ) -> Arc<Vec<u8>> {
        let _ = nsec_record_type;
        use super::response_encoder::{
            assemble_packet, build_opt_encoded_record, build_response_flags, encode_rr, DnsSection,
            ResponseEnvelope,
        };

        let mut envelope = ResponseEnvelope::default();

        // Fail-closed: missing SOA is an internal invariant violation.
        // The zone SOA check in handle_parsed_query should catch this earlier,
        // but we enforce it here as defense-in-depth.
        let Some(soa) = soa_record else {
            tracing::error!(
                qname = %qname,
                "Missing SOA record for signed NXDOMAIN response (internal invariant violation), returning SERVFAIL"
            );
            let flags = build_response_flags(true, false, rd, false, false, 2);
            let question = super::wire::build_question(qname, qtype, 1);
            let has_opt = edns_options.is_some();
            let arcount: u16 = if has_opt { 1 } else { 0 };
            let mut packet = Vec::with_capacity(12 + question.len() + 16);
            packet.extend_from_slice(&response_id.to_be_bytes());
            packet.extend_from_slice(&flags.to_be_bytes());
            packet.extend_from_slice(&1u16.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes());
            packet.extend_from_slice(&arcount.to_be_bytes());
            packet.extend_from_slice(&question);
            if let Some(edns) = edns_options {
                let opt = build_opt_encoded_record(edns.udp_payload_size, false);
                packet.extend_from_slice(&opt.bytes);
            }
            return Arc::new(packet);
        };

        // Authority section: SOA record (RFC 2308)
        match encode_rr(soa, None) {
            Ok(mut rec) => {
                rec.section = DnsSection::Authority;
                envelope.authority_records.push(rec);
            }
            Err(reason) => {
                tracing::error!(
                    qname = %qname,
                    reason = %reason,
                    "DNS encode: SOA record failed for NXDOMAIN response, returning SERVFAIL"
                );
                let flags = build_response_flags(true, false, rd, false, false, 2);
                let question = super::wire::build_question(qname, qtype, 1);
                let has_opt = edns_options.is_some();
                let arcount: u16 = if has_opt { 1 } else { 0 };
                let mut packet = Vec::with_capacity(12 + question.len() + 16);
                packet.extend_from_slice(&response_id.to_be_bytes());
                packet.extend_from_slice(&flags.to_be_bytes());
                packet.extend_from_slice(&1u16.to_be_bytes());
                packet.extend_from_slice(&0u16.to_be_bytes());
                packet.extend_from_slice(&0u16.to_be_bytes());
                packet.extend_from_slice(&arcount.to_be_bytes());
                packet.extend_from_slice(&question);
                if let Some(edns) = edns_options {
                    let opt = build_opt_encoded_record(edns.udp_payload_size, false);
                    packet.extend_from_slice(&opt.bytes);
                }
                return Arc::new(packet);
            }
        }

        // Authority section: NSEC/NSEC3 denial proof records
        for nsec_record in nsec_records {
            let encoded = DnsZoneRecord {
                name: nsec_record.name.clone(),
                record_type: nsec_record.record_type,
                value: nsec_record.value.clone(),
                ttl: nsec_record.ttl,
                priority: None,
            };
            match encode_rr(&encoded, None) {
                Ok(mut rec) => {
                    rec.section = DnsSection::Authority;
                    envelope.authority_records.push(rec);
                }
                Err(reason) => {
                    tracing::error!(
                        qname = %qname,
                        reason = %reason,
                        "DNS encode: NSEC/NSEC3 record failed for NXDOMAIN response"
                    );
                }
            }

            // RRSIG for the denial proof record
            if dnssec_ok {
                if let Some(key) = zsk {
                    let rrsig = Self::create_signed_rrsig(nsec_record, signer_name, key);
                    if !rrsig.is_empty() {
                        let rrsig_record = DnsZoneRecord {
                            name: nsec_record.name.clone(),
                            record_type: RecordType::RRSIG,
                            value: hex::encode(&rrsig),
                            ttl: nsec_record.ttl,
                            priority: None,
                        };
                        match encode_rr(&rrsig_record, None) {
                            Ok(mut rec) => {
                                rec.section = DnsSection::Authority;
                                envelope.authority_records.push(rec);
                            }
                            Err(reason) => {
                                tracing::error!(
                                    qname = %qname,
                                    reason = %reason,
                                    "DNS encode: RRSIG record failed for NXDOMAIN response"
                                );
                            }
                        }
                    }
                }
            }
        }

        // Additional section: OPT record
        if let Some(edns) = edns_options {
            envelope
                .additional_records
                .push(build_opt_encoded_record(edns.udp_payload_size, dnssec_ok));
        } else if dnssec_ok {
            envelope
                .additional_records
                .push(build_opt_encoded_record(4096, dnssec_ok));
        }

        // Authoritative servers never set AD — AD is a recursive validation signal.
        let flags = build_response_flags(true, false, rd, false, false, 3);
        let packet = assemble_packet(&envelope, response_id, flags, qname, qtype);
        Arc::new(packet)
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
        rd: bool,
    ) -> Arc<Vec<u8>> {
        let _ = nsec_record_type;
        use super::response_encoder::{
            assemble_packet, build_opt_encoded_record, build_response_flags, encode_rr, DnsSection,
            ResponseEnvelope,
        };

        let mut envelope = ResponseEnvelope::default();

        // Fail-closed: missing SOA is an internal invariant violation.
        // The zone SOA check in handle_parsed_query should catch this earlier,
        // but we enforce it here as defense-in-depth.
        let Some(soa) = soa_record else {
            tracing::error!(
                qname = %qname,
                "Missing SOA record for signed NODATA response (internal invariant violation), returning SERVFAIL"
            );
            let flags = build_response_flags(true, false, rd, false, false, 2);
            let question = super::wire::build_question(qname, qtype, 1);
            let has_opt = edns_options.is_some();
            let arcount: u16 = if has_opt { 1 } else { 0 };
            let mut packet = Vec::with_capacity(12 + question.len() + 16);
            packet.extend_from_slice(&response_id.to_be_bytes());
            packet.extend_from_slice(&flags.to_be_bytes());
            packet.extend_from_slice(&1u16.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes());
            packet.extend_from_slice(&arcount.to_be_bytes());
            packet.extend_from_slice(&question);
            if let Some(edns) = edns_options {
                let opt = build_opt_encoded_record(edns.udp_payload_size, false);
                packet.extend_from_slice(&opt.bytes);
            }
            return Arc::new(packet);
        };

        // Authority section: SOA record (RFC 2308)
        match encode_rr(soa, None) {
            Ok(mut rec) => {
                rec.section = DnsSection::Authority;
                envelope.authority_records.push(rec);
            }
            Err(reason) => {
                tracing::error!(
                    qname = %qname,
                    reason = %reason,
                    "DNS encode: SOA record failed for NODATA response, returning SERVFAIL"
                );
                let flags = build_response_flags(true, false, rd, false, false, 2);
                let question = super::wire::build_question(qname, qtype, 1);
                let has_opt = edns_options.is_some();
                let arcount: u16 = if has_opt { 1 } else { 0 };
                let mut packet = Vec::with_capacity(12 + question.len() + 16);
                packet.extend_from_slice(&response_id.to_be_bytes());
                packet.extend_from_slice(&flags.to_be_bytes());
                packet.extend_from_slice(&1u16.to_be_bytes());
                packet.extend_from_slice(&0u16.to_be_bytes());
                packet.extend_from_slice(&0u16.to_be_bytes());
                packet.extend_from_slice(&arcount.to_be_bytes());
                packet.extend_from_slice(&question);
                if let Some(edns) = edns_options {
                    let opt = build_opt_encoded_record(edns.udp_payload_size, false);
                    packet.extend_from_slice(&opt.bytes);
                }
                return Arc::new(packet);
            }
        }

        // Authority section: NSEC/NSEC3 denial proof records
        for nsec_record in nsec_records {
            let encoded = DnsZoneRecord {
                name: nsec_record.name.clone(),
                record_type: nsec_record.record_type,
                value: nsec_record.value.clone(),
                ttl: nsec_record.ttl,
                priority: None,
            };
            match encode_rr(&encoded, None) {
                Ok(mut rec) => {
                    rec.section = DnsSection::Authority;
                    envelope.authority_records.push(rec);
                }
                Err(reason) => {
                    tracing::error!(
                        qname = %qname,
                        reason = %reason,
                        "DNS encode: NSEC/NSEC3 record failed for NODATA response"
                    );
                }
            }

            // RRSIG for the denial proof record
            if dnssec_ok {
                if let Some(key) = zsk {
                    let rrsig = Self::create_signed_rrsig(nsec_record, signer_name, key);
                    if !rrsig.is_empty() {
                        let rrsig_record = DnsZoneRecord {
                            name: nsec_record.name.clone(),
                            record_type: RecordType::RRSIG,
                            value: hex::encode(&rrsig),
                            ttl: nsec_record.ttl,
                            priority: None,
                        };
                        match encode_rr(&rrsig_record, None) {
                            Ok(mut rec) => {
                                rec.section = DnsSection::Authority;
                                envelope.authority_records.push(rec);
                            }
                            Err(reason) => {
                                tracing::error!(
                                    qname = %qname,
                                    reason = %reason,
                                    "DNS encode: RRSIG record failed for NODATA response"
                                );
                            }
                        }
                    }
                }
            }
        }

        // Additional section: OPT record
        if let Some(edns) = edns_options {
            envelope
                .additional_records
                .push(build_opt_encoded_record(edns.udp_payload_size, dnssec_ok));
        } else if dnssec_ok {
            envelope
                .additional_records
                .push(build_opt_encoded_record(4096, dnssec_ok));
        }

        // NODATA: RCODE 0 (NOERROR), authoritative answer
        // Authoritative servers never set AD — AD is a recursive validation signal.
        let flags = build_response_flags(true, false, rd, false, false, 0);
        let packet = assemble_packet(&envelope, response_id, flags, qname, qtype);
        Arc::new(packet)
    }
}

#[cfg(test)]
mod servfail_response_tests {
    use super::*;

    fn build_query_with_flags(id: u16, flags: u16, name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&flags.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&qclass.to_be_bytes());
        q
    }

    #[test]
    fn test_servfail_echoes_question_section() {
        let query = build_query_with_flags(0xABCD, 0x0100, "example.com", 1, 1);
        let parsed = ParsedDnsQuery::parse(&query).unwrap();

        let query_id = parsed.id;
        let rd = parsed.flags.recursion_desired;
        let question_bytes = Some(query[12..parsed.question_end].to_vec());

        // RA=false: we are returning SERVFAIL, not claiming recursion is available
        let flags = crate::parsed_query::build_response_flags(false, false, rd, false, false, 2);
        let qdcount: u16 = if question_bytes.is_some() { 1 } else { 0 };

        let mut servfail = Vec::with_capacity(12 + question_bytes.as_ref().map_or(0, |q| q.len()));
        servfail.extend_from_slice(&query_id.to_be_bytes());
        servfail.extend_from_slice(&flags.to_be_bytes());
        servfail.extend_from_slice(&qdcount.to_be_bytes());
        servfail.extend_from_slice(&0u16.to_be_bytes());
        servfail.extend_from_slice(&0u16.to_be_bytes());
        servfail.extend_from_slice(&0u16.to_be_bytes());
        if let Some(q) = question_bytes {
            servfail.extend_from_slice(&q);
        }

        assert_eq!(servfail[0], 0xAB);
        assert_eq!(servfail[1], 0xCD);

        let resp_flags = u16::from_be_bytes([servfail[2], servfail[3]]);
        assert_ne!(resp_flags & 0x8000, 0, "QR=1");
        assert_eq!(resp_flags & 0x0400, 0, "AA=0");
        assert_eq!(resp_flags & 0x0200, 0, "TC=0");
        assert_ne!(resp_flags & 0x0100, 0, "RD echoed");
        assert_eq!(resp_flags & 0x0080, 0, "RA=0");
        assert_eq!(resp_flags & 0x0020, 0, "AD=0");
        assert_eq!(resp_flags & 0x000F, 2, "RCODE=SERVFAIL");

        assert_eq!(
            u16::from_be_bytes([servfail[4], servfail[5]]),
            1,
            "QDCOUNT=1"
        );
        assert!(servfail.len() > 12);
        assert_eq!(&servfail[12..], &query[12..parsed.question_end]);
    }

    #[test]
    fn test_servfail_rd_zero_when_query_rd_zero() {
        let query = build_query_with_flags(0x1234, 0x0000, "test.local", 28, 1);
        let parsed = ParsedDnsQuery::parse(&query).unwrap();
        let flags = crate::parsed_query::build_response_flags(
            false,
            false,
            parsed.flags.recursion_desired,
            false,
            false,
            2,
        );
        assert_eq!(flags & 0x0100, 0);
    }

    #[test]
    fn test_servfail_rd_one_when_query_rd_one() {
        let query = build_query_with_flags(0x5678, 0x0100, "test.local", 15, 1);
        let parsed = ParsedDnsQuery::parse(&query).unwrap();
        let flags = crate::parsed_query::build_response_flags(
            false,
            false,
            parsed.flags.recursion_desired,
            false,
            false,
            2,
        );
        assert_ne!(flags & 0x0100, 0);
    }

    #[test]
    fn test_servfail_flags_bit_layout() {
        // QR=1, AA=0, TC=0, RD=1, RA=0, AD=0, RCODE=2
        let flags = crate::parsed_query::build_response_flags(false, false, true, false, false, 2);
        assert_eq!(flags, 0x8102);
    }

    #[test]
    fn test_servfail_fallback_without_parsed_query() {
        let query = build_query_with_flags(0xDEAD, 0x0100, "bad", 1, 1);
        let short_query = &query[..8];
        let qid = u16::from_be_bytes([short_query[0], short_query[1]]);
        let flags_raw = u16::from_be_bytes([short_query[2], short_query[3]]);
        let rd = (flags_raw & 0x0100) != 0;
        let flags = crate::parsed_query::build_response_flags(false, false, rd, false, false, 2);

        let mut servfail = Vec::with_capacity(12);
        servfail.extend_from_slice(&qid.to_be_bytes());
        servfail.extend_from_slice(&flags.to_be_bytes());
        servfail.extend_from_slice(&0u16.to_be_bytes());
        servfail.extend_from_slice(&0u16.to_be_bytes());
        servfail.extend_from_slice(&0u16.to_be_bytes());
        servfail.extend_from_slice(&0u16.to_be_bytes());

        assert_eq!(servfail.len(), 12);
        assert_eq!(u16::from_be_bytes([servfail[0], servfail[1]]), 0xDEAD);
    }

    // --- TTL parsing helper tests ---

    fn build_positive_response(id: u16, answer_ttl: u32) -> Vec<u8> {
        let flags = crate::parsed_query::build_response_flags(true, true, false, true, false, 0);
        let mut r = Vec::new();
        r.extend_from_slice(&id.to_be_bytes());
        r.extend_from_slice(&flags.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        r.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        r.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        r.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
                                                  // question: example.com IN A
        r.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        r.extend_from_slice(&[3, b'c', b'o', b'm']);
        r.push(0);
        r.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        r.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
                                                  // answer: example.com IN A 300
        r.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        r.extend_from_slice(&[3, b'c', b'o', b'm']);
        r.push(0);
        r.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        r.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        r.extend_from_slice(&answer_ttl.to_be_bytes()); // TTL
        r.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        r.extend_from_slice(&[93, 184, 216, 34]); // RDATA
        r
    }

    fn build_nxdomain_response_with_soa(id: u16) -> Vec<u8> {
        let flags = crate::parsed_query::build_response_flags(true, true, false, true, false, 3);
        let mut r = Vec::new();
        r.extend_from_slice(&id.to_be_bytes());
        r.extend_from_slice(&flags.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        r.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        r.extend_from_slice(&1u16.to_be_bytes()); // NSCOUNT (SOA)
        r.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
                                                  // question
        r.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        r.extend_from_slice(&[3, b'c', b'o', b'm']);
        r.push(0);
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        // authority: SOA record
        r.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        r.extend_from_slice(&[3, b'c', b'o', b'm']);
        r.push(0);
        r.extend_from_slice(&6u16.to_be_bytes()); // TYPE SOA
        r.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        r.extend_from_slice(&120u32.to_be_bytes()); // SOA TTL
        let soa_rdata: Vec<u8> = [
            0, // MNAME root
            0, // RNAME root
        ]
        .iter()
        .copied()
        .chain(0u32.to_be_bytes().iter().copied())
        .chain(3600u32.to_be_bytes().iter().copied())
        .chain(600u32.to_be_bytes().iter().copied())
        .chain(604800u32.to_be_bytes().iter().copied())
        .chain(300u32.to_be_bytes().iter().copied()) // MINIMUM = 300
        .collect();
        r.extend_from_slice(&(soa_rdata.len() as u16).to_be_bytes());
        r.extend_from_slice(&soa_rdata);
        r
    }

    fn build_response_with_rcode(id: u16, rcode: u8) -> Vec<u8> {
        let flags =
            crate::parsed_query::build_response_flags(true, false, false, true, false, rcode);
        let mut r = Vec::new();
        r.extend_from_slice(&id.to_be_bytes());
        r.extend_from_slice(&flags.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r
    }

    #[test]
    fn test_extract_ttl_positive_response() {
        let resp = build_positive_response(0x1234, 300);
        let ttl = super::DnsServer::extract_ttl_from_response(&resp, 60);
        assert_eq!(ttl, 300);
    }

    #[test]
    fn test_extract_ttl_servfail_returns_zero() {
        let resp = build_response_with_rcode(0x1234, 2u8); // SERVFAIL
        let ttl = super::DnsServer::extract_ttl_from_response(&resp, 60);
        assert_eq!(ttl, 0, "SERVFAIL must not be cached");
    }

    #[test]
    fn test_extract_ttl_refused_returns_zero() {
        let resp = build_response_with_rcode(0x1234, 5u8); // REFUSED
        let ttl = super::DnsServer::extract_ttl_from_response(&resp, 60);
        assert_eq!(ttl, 0, "REFUSED must not be cached");
    }

    #[test]
    fn test_extract_ttl_nxdomain_with_soa() {
        let resp = build_nxdomain_response_with_soa(0x1234);
        let ttl = super::DnsServer::extract_ttl_from_response(&resp, 60);
        // SOA minimum = 300, negative_cache_ttl = 60, min(300, 60) = 60
        assert_eq!(ttl, 60);
    }

    #[test]
    fn test_extract_ttl_nxdomain_no_soa_uses_negative_cache() {
        // NXDOMAIN with no authority section
        let flags = crate::parsed_query::build_response_flags(true, true, false, true, false, 3);
        let mut resp = Vec::new();
        resp.extend_from_slice(&0x1234u16.to_be_bytes());
        resp.extend_from_slice(&flags.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        resp.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        resp.extend_from_slice(&[3, b'c', b'o', b'm']);
        resp.push(0);
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        let ttl = super::DnsServer::extract_ttl_from_response(&resp, 90);
        assert_eq!(
            ttl, 90,
            "NXDOMAIN without SOA should use negative_cache_ttl"
        );
    }

    #[test]
    fn test_first_answer_ttl_basic() {
        let resp = build_positive_response(0xABCD, 600);
        let ttl = super::DnsServer::first_answer_ttl(&resp).unwrap();
        assert_eq!(ttl, Some(600));
    }

    #[test]
    fn test_first_answer_ttl_empty_answers() {
        let flags = crate::parsed_query::build_response_flags(true, true, false, true, false, 0);
        let mut r = Vec::new();
        r.extend_from_slice(&0xABCDu16.to_be_bytes());
        r.extend_from_slice(&flags.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT=0
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&[3, b'f', b'o', b'o']);
        r.push(0);
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        let ttl = super::DnsServer::first_answer_ttl(&r).unwrap();
        assert_eq!(ttl, None);
    }

    #[test]
    fn test_skip_dns_name_simple() {
        let mut buf = Vec::new();
        // example.com
        buf.extend_from_slice(&[7]);
        buf.extend_from_slice(b"example");
        buf.extend_from_slice(&[3]);
        buf.extend_from_slice(b"com");
        buf.push(0);
        let end = super::DnsServer::skip_dns_name(&buf, 0).unwrap();
        assert_eq!(end, 13); // 1+7 + 1+3 + 1 = 13
    }

    #[test]
    fn test_skip_dns_name_compression_pointer() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[7]);
        buf.extend_from_slice(b"example");
        buf.extend_from_slice(&[3]);
        buf.extend_from_slice(b"com");
        buf.push(0);
        // pointer to offset 0
        buf.extend_from_slice(&[0xC0, 0x00]);
        // Position 12 is the null terminator; the pointer is at position 13
        let end = super::DnsServer::skip_dns_name(&buf, 13).unwrap();
        assert_eq!(end, 15);
    }

    #[test]
    fn test_skip_dns_name_truncated() {
        let buf = &[0xFF]; // truncated label
        assert!(super::DnsServer::skip_dns_name(buf, 0).is_err());
    }

    #[test]
    fn test_negative_soa_ttl_basic() {
        let resp = build_nxdomain_response_with_soa(0x1234);
        let ttl = super::DnsServer::negative_soa_ttl(&resp).unwrap();
        // SOA record TTL = 120, SOA MINIMUM = 300, min = 120
        assert_eq!(ttl, Some(120));
    }

    #[test]
    fn test_negative_soa_ttl_no_answer() {
        let flags = crate::parsed_query::build_response_flags(true, true, false, true, false, 0);
        let mut r = Vec::new();
        r.extend_from_slice(&0x1234u16.to_be_bytes());
        r.extend_from_slice(&flags.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&[3, b'f', b'o', b'o']);
        r.push(0);
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        let ttl = super::DnsServer::negative_soa_ttl(&r).unwrap();
        assert_eq!(ttl, None);
    }

    #[test]
    fn test_first_answer_ttl_chooses_minimum() {
        // Build a response with ANCOUNT=2, TTLs 100 and 300
        let flags = crate::parsed_query::build_response_flags(true, true, false, true, false, 0);
        let mut r = Vec::new();
        r.extend_from_slice(&0xABCDu16.to_be_bytes());
        r.extend_from_slice(&flags.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        r.extend_from_slice(&2u16.to_be_bytes()); // ANCOUNT=2
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        // question
        r.extend_from_slice(&[3, b'f', b'o', b'o']);
        r.push(0);
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        // answer 1: foo A TTL=100
        r.extend_from_slice(&[3, b'f', b'o', b'o']);
        r.push(0);
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&100u32.to_be_bytes());
        r.extend_from_slice(&4u16.to_be_bytes());
        r.extend_from_slice(&[1, 2, 3, 4]);
        // answer 2: foo A TTL=300
        r.extend_from_slice(&[3, b'f', b'o', b'o']);
        r.push(0);
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&300u32.to_be_bytes());
        r.extend_from_slice(&4u16.to_be_bytes());
        r.extend_from_slice(&[5, 6, 7, 8]);
        let ttl = super::DnsServer::first_answer_ttl(&r).unwrap();
        assert_eq!(ttl, Some(100), "should choose minimum TTL across answers");
    }

    #[test]
    fn test_skip_dns_name_pointer_beyond_buffer() {
        // Compression pointer at offset 0 — the pointer itself is in bounds (2 bytes),
        // so skip_dns_name succeeds (it skips the name without following the pointer).
        let buf = &[0xC0, 0xFF];
        let result = super::DnsServer::skip_dns_name(buf, 0);
        assert_eq!(result.unwrap(), 2, "should advance past the 2-byte pointer");
    }

    #[test]
    fn test_negative_soa_ttl_malformed_rdata() {
        // Build NXDOMAIN response with SOA authority where rdlength < 20
        let flags = crate::parsed_query::build_response_flags(true, true, false, true, false, 3);
        let mut r = Vec::new();
        r.extend_from_slice(&0x1234u16.to_be_bytes());
        r.extend_from_slice(&flags.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        r.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        r.extend_from_slice(&1u16.to_be_bytes()); // NSCOUNT (SOA)
        r.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
                                                  // question
        r.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        r.extend_from_slice(&[3, b'c', b'o', b'm']);
        r.push(0);
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        // authority: SOA with rdlength=10 (too short for SOA rdata which needs >= 20)
        r.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        r.extend_from_slice(&[3, b'c', b'o', b'm']);
        r.push(0);
        r.extend_from_slice(&6u16.to_be_bytes()); // TYPE SOA
        r.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        r.extend_from_slice(&120u32.to_be_bytes()); // TTL
        r.extend_from_slice(&10u16.to_be_bytes()); // RDLENGTH (too short)
        r.extend_from_slice(&[0u8; 10]); // only 10 bytes of rdata
        let ttl = super::DnsServer::negative_soa_ttl(&r).unwrap();
        assert_eq!(ttl, None, "malformed SOA rdata should return None");
    }

    // ── TCP hard-limit SERVFAIL tests ──────────────────────────────────

    /// Build a SERVFAIL using the same logic as the TCP hard-limit handler.
    /// Returns (wire_response, raw_query).
    fn build_tcp_hardlimit_servfail(
        id: u16,
        flags_raw: u16,
        name: &str,
        qtype: u16,
        qclass: u16,
    ) -> (Vec<u8>, Vec<u8>) {
        let query = build_query_with_flags(id, flags_raw, name, qtype, qclass);
        let parsed = ParsedDnsQuery::parse(&query).unwrap();
        let rd = parsed.flags.recursion_desired;
        let question_bytes = Some(query[12..parsed.question_end].to_vec());

        // RA=false, AD=false (matching the updated hard-limit handler)
        let flags = crate::parsed_query::build_response_flags(false, false, rd, false, false, 2);
        let qdcount: u16 = if question_bytes.is_some() { 1 } else { 0 };

        let mut servfail = Vec::with_capacity(12 + question_bytes.as_ref().map_or(0, |q| q.len()));
        servfail.extend_from_slice(&id.to_be_bytes());
        servfail.extend_from_slice(&flags.to_be_bytes());
        servfail.extend_from_slice(&qdcount.to_be_bytes());
        servfail.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        servfail.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        servfail.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        if let Some(q) = question_bytes {
            servfail.extend_from_slice(&q);
        }

        (servfail, query)
    }

    #[test]
    fn test_hardlimit_servfail_preserves_query_id() {
        let (servfail, _) = build_tcp_hardlimit_servfail(0xBEEF, 0x0100, "example.com", 1, 1);
        assert_eq!(u16::from_be_bytes([servfail[0], servfail[1]]), 0xBEEF);
    }

    #[test]
    fn test_hardlimit_servfail_preserves_rd_bit() {
        // RD=1 query → SERVFAIL should echo RD=1
        let (servfail, _) = build_tcp_hardlimit_servfail(0x0001, 0x0100, "a.b", 1, 1);
        let flags = u16::from_be_bytes([servfail[2], servfail[3]]);
        assert_ne!(flags & 0x0100, 0, "RD should be echoed");

        // RD=0 query → SERVFAIL should echo RD=0
        let (servfail2, _) = build_tcp_hardlimit_servfail(0x0002, 0x0000, "a.b", 1, 1);
        let flags2 = u16::from_be_bytes([servfail2[2], servfail2[3]]);
        assert_eq!(flags2 & 0x0100, 0, "RD=0 should be echoed");
    }

    #[test]
    fn test_hardlimit_servfail_ra_false() {
        let (servfail, _) = build_tcp_hardlimit_servfail(0x0003, 0x0100, "example.com", 1, 1);
        let flags = u16::from_be_bytes([servfail[2], servfail[3]]);
        assert_eq!(flags & 0x0080, 0, "RA must be 0 in hard-limit SERVFAIL");
    }

    #[test]
    fn test_hardlimit_servfail_ad_false() {
        let (servfail, _) = build_tcp_hardlimit_servfail(0x0004, 0x0100, "example.com", 1, 1);
        let flags = u16::from_be_bytes([servfail[2], servfail[3]]);
        assert_eq!(flags & 0x0020, 0, "AD must be 0 in hard-limit SERVFAIL");
    }

    #[test]
    fn test_hardlimit_servfail_echoes_question_section() {
        let (servfail, query) = build_tcp_hardlimit_servfail(0xABCD, 0x0100, "example.com", 1, 1);
        let parsed = ParsedDnsQuery::parse(&query).unwrap();
        let qdcount = u16::from_be_bytes([servfail[4], servfail[5]]);
        assert_eq!(qdcount, 1, "QDCOUNT=1 when question is echoed");
        assert_eq!(
            &servfail[12..],
            &query[12..parsed.question_end],
            "question section must be echoed verbatim"
        );
    }

    #[test]
    fn test_hardlimit_servfail_echoes_qtype_and_qclass() {
        let (servfail, query) = build_tcp_hardlimit_servfail(0xABCD, 0x0100, "example.com", 28, 1);
        let parsed = ParsedDnsQuery::parse(&query).unwrap();
        // QTYPE and QCLASS are the last 4 bytes of the question section
        let q_section = &query[12..parsed.question_end];
        let qtype_bytes = &q_section[q_section.len() - 4..q_section.len() - 2];
        let qclass_bytes = &q_section[q_section.len() - 2..];
        assert_eq!(
            u16::from_be_bytes([qtype_bytes[0], qtype_bytes[1]]),
            28,
            "QTYPE=AAAA"
        );
        assert_eq!(
            u16::from_be_bytes([qclass_bytes[0], qclass_bytes[1]]),
            1,
            "QCLASS=IN"
        );
        // Verify they appear in the SERVFAIL
        let sf_q_section = &servfail[12..];
        assert_eq!(sf_q_section, q_section);
    }

    #[test]
    fn test_hardlimit_servfail_is_within_size_limits() {
        // SERVFAIL with question section: 12 + question_len
        // For "example.com" the question is 17 bytes (7+example + 3+com + 0 + 2+2)
        let (servfail, _) = build_tcp_hardlimit_servfail(0x0001, 0x0100, "example.com", 1, 1);
        assert!(servfail.len() <= 512, "SERVFAIL must fit in 512 bytes");
        assert!(servfail.len() > 12, "SERVFAIL must have question section");
    }

    #[test]
    fn test_hardlimit_servfail_no_partial_oversized_response() {
        // The SERVFAIL itself should be well under any reasonable limit.
        // This test verifies the SERVFAIL is never truncated.
        let (servfail, _) = build_tcp_hardlimit_servfail(0xBEEF, 0x0100, "example.com", 1, 1);
        let flags = u16::from_be_bytes([servfail[2], servfail[3]]);
        assert_eq!(flags & 0x0200, 0, "TC=0: SERVFAIL must not be truncated");
    }

    #[test]
    fn test_hardlimit_servfail_fallback_without_parsed_query() {
        // When parsing fails (query too short), SERVFAIL has QDCOUNT=0
        let query = build_query_with_flags(0xDEAD, 0x0100, "bad", 1, 1);
        let short_query = &query[..8];
        let qid = u16::from_be_bytes([short_query[0], short_query[1]]);
        let flags_raw = u16::from_be_bytes([short_query[2], short_query[3]]);
        let rd = (flags_raw & 0x0100) != 0;
        let flags = crate::parsed_query::build_response_flags(false, false, rd, false, false, 2);

        let mut servfail = Vec::with_capacity(12);
        servfail.extend_from_slice(&qid.to_be_bytes());
        servfail.extend_from_slice(&flags.to_be_bytes());
        servfail.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT=0
        servfail.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        servfail.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        servfail.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        assert_eq!(servfail.len(), 12);
        assert_eq!(u16::from_be_bytes([servfail[0], servfail[1]]), 0xDEAD);
        assert_eq!(
            u16::from_be_bytes([servfail[4], servfail[5]]),
            0,
            "QDCOUNT=0 when parsing failed"
        );
    }
}

// ── TCP one-query-per-connection lifecycle tests ──────────────────────

#[cfg(test)]
mod tcp_lifecycle_tests {
    use super::*;
    use crate::edns::EcsFilterConfig;
    use crate::limits::ConnectionLimits;
    use crate::server::DnsZoneRecord;
    use crate::server::RecordType;
    use crate::server::Zone;
    use crate::zone_trie::ZoneTrie;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Build a raw DNS query in wire format.
    fn build_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
        let mut q = Vec::with_capacity(12 + 256 + 4);
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
        q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        if qname.is_empty() || qname == "." {
            q.push(0);
        } else {
            for label in qname.split('.').filter(|s| !s.is_empty()) {
                q.push(label.len() as u8);
                q.extend_from_slice(label.as_bytes());
            }
            q.push(0);
        }

        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        q
    }

    /// Wrap a DNS message with a 2-byte TCP length prefix.
    fn wrap_tcp(msg: &[u8]) -> Vec<u8> {
        let len = msg.len() as u16;
        let mut buf = len.to_be_bytes().to_vec();
        buf.extend_from_slice(msg);
        buf
    }

    /// Build a test zone with records that produce a response large enough
    /// to exceed a small hard limit. The TXT record wire encoding is ~50 bytes.
    fn build_test_zone() -> Zone {
        let mut zone = Zone::new("test.local".to_string());
        zone.serial = 2026070301;
        zone.nsec_enabled = false;
        zone.nsec3_enabled = false;

        zone.records.insert(
            ("@".to_string(), RecordType::SOA),
            vec![DnsZoneRecord {
                name: "@".to_string(),
                record_type: RecordType::SOA,
                value: "ns1.test.local. admin.test.local. 2026070301 3600 600 604800 300"
                    .to_string(),
                ttl: 300,
                priority: None,
            }],
        );

        zone.records.insert(
            ("www".to_string(), RecordType::A),
            vec![DnsZoneRecord {
                name: "www".to_string(),
                record_type: RecordType::A,
                value: "192.0.2.10".to_string(),
                ttl: 300,
                priority: None,
            }],
        );

        zone.records.insert(
            ("txt".to_string(), RecordType::TXT),
            vec![DnsZoneRecord {
                name: "txt".to_string(),
                record_type: RecordType::TXT,
                value: "a-long-enough-txt-record-to-make-the-response-exceed-thirty-bytes"
                    .to_string(),
                ttl: 300,
                priority: None,
            }],
        );

        zone
    }

    /// Start a DNS server on a random port with an optional zone and connection limits.
    async fn start_test_server_with_zone(
        zone: Option<Zone>,
        connection_limits: Option<Arc<ConnectionLimits>>,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let zones = Arc::new(ShardedZoneStore::new());
            let mut trie = ZoneTrie::new();

            if let Some(z) = zone {
                let origin = z.origin.clone();
                zones.insert(origin.clone(), z);
                trie.insert(&origin);
            }

            let zone_trie = Arc::new(RwLock::new(trie));
            let ecs_config = EcsFilterConfig::default();
            let limits = connection_limits.unwrap_or_else(|| {
                Arc::new(ConnectionLimits::new(
                    100, 1000, 65535, 65535, 1000, 300, 30, false,
                ))
            });
            let ctx = QueryContext {
                zones: &zones,
                zone_trie: &zone_trie,
                geoip_lookup: None,
                min_geo_ttl: 0,
                negative_cache_ttl: 300,
                cache: None,
                dnssec: None,
                signer_name: None,
                query_validator: None,
                firewall: None,
                connection_limits: Some(&limits),
                max_idle_time: Some(std::time::Duration::from_secs(5)),
                zone_transfer: None,
                ecs_filter_config: &ecs_config,
                rate_limiter: None,
                rrl_enabled: false,
                update_handler: None,
                notify_handler: None,
                query_coalescer: None,
                dns64_translator: None,
                acme_dns_challenges: None,
                cookie_server: None,
                #[cfg(feature = "mesh")]
                mesh_registry: None,
            };
            let _ = DnsServer::handle_tcp_query(stream, ctx).await;
        });

        addr
    }

    #[tokio::test]
    async fn test_tcp_one_query_then_connection_closed() {
        // Use a zone so we get a real response instead of REFUSED
        let zone = build_test_zone();
        let addr = start_test_server_with_zone(Some(zone), None).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        // Send a valid DNS query over TCP (length-prefixed)
        let query = build_query(0x1234, "www.test.local", 1);
        let tcp_msg = wrap_tcp(&query);
        stream.write_all(&tcp_msg).await.unwrap();

        // Read the response
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await.unwrap();

        // Response should be a valid DNS message
        assert!(resp_buf.len() >= 12);
        let resp_flags = u16::from_be_bytes([resp_buf[2], resp_buf[3]]);
        assert_ne!(resp_flags & 0x8000, 0, "QR=1 in response");
        // NOERROR (0) since the zone has the record
        assert_eq!(
            resp_flags & 0x000F,
            0,
            "RCODE=NOERROR (zone has the record)"
        );

        // Connection should be closed by the server after one response.
        // Attempting to read should return 0 bytes (EOF) or an error.
        let read_result = stream.read(&mut [0u8; 1]).await;
        match read_result {
            Ok(0) => {} // EOF — connection closed by server
            Ok(_) => {
                panic!(
                    "Expected connection closed (EOF), but got additional data. \
                     The server is not enforcing one-query-per-connection."
                );
            }
            Err(_) => {} // Connection reset — also acceptable
        }
    }

    #[tokio::test]
    async fn test_tcp_second_query_not_processed() {
        let zone = build_test_zone();
        let addr = start_test_server_with_zone(Some(zone), None).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        // Send first query
        let query1 = build_query(0x1111, "www.test.local", 1);
        stream.write_all(&wrap_tcp(&query1)).await.unwrap();

        // Read first response
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await.unwrap();
        assert_eq!(
            u16::from_be_bytes([resp_buf[2], resp_buf[3]]) & 0x000F,
            0,
            "First query returns NOERROR"
        );

        // Server should have closed the connection. Verify by trying to send
        // a second query — this should fail or produce no response.
        let query2 = build_query(0x2222, "www.test.local", 1);
        let write_result = stream.write_all(&wrap_tcp(&query2)).await;

        // Either the write fails (broken pipe) or we get EOF on read
        if write_result.is_ok() {
            let read_result = stream.read(&mut [0u8; 1]).await;
            match read_result {
                Ok(0) => {} // EOF — correct
                Ok(_) => {
                    panic!(
                        "Server processed a second query on the same TCP connection. \
                         One-query-per-connection policy is violated."
                    );
                }
                Err(_) => {} // Connection reset — acceptable
            }
        }
    }

    #[tokio::test]
    async fn test_tcp_hardlimit_returns_servfail() {
        // Set up a zone with a TXT record that produces a response > 40 bytes.
        // The SERVFAIL with question section is ~32 bytes for "txt.test.local",
        // so max_response_size=40 rejects the real response but allows the SERVFAIL.
        let zone = build_test_zone();

        let limits = Arc::new(ConnectionLimits::new(
            100,   // max_tcp_connections
            1000,  // max_concurrent_queries
            65535, // max_query_size
            40,    // max_response_size — rejects real responses (~48+ bytes)
            // but allows SERVFAIL (~32 bytes)
            1000, // max_records_per_response
            300,  // max_tcp_idle_time_secs
            30,   // max_tcp_query_time_secs
            false,
        ));
        let addr = start_test_server_with_zone(Some(zone), Some(limits)).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        // Query for the TXT record which should produce a large response
        let query = build_query(0xFACE, "txt.test.local", 16);
        stream.write_all(&wrap_tcp(&query)).await.unwrap();

        // Read the length prefix
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await.unwrap();

        // Should be a SERVFAIL
        assert!(resp_buf.len() >= 12);
        let resp_flags = u16::from_be_bytes([resp_buf[2], resp_buf[3]]);
        assert_eq!(
            resp_flags & 0x000F,
            2,
            "RCODE must be SERVFAIL (2) when response exceeds hard limit"
        );
        // RA must be 0
        assert_eq!(
            resp_flags & 0x0080,
            0,
            "RA must be 0 in hard-limit SERVFAIL"
        );
        // AD must be 0
        assert_eq!(
            resp_flags & 0x0020,
            0,
            "AD must be 0 in hard-limit SERVFAIL"
        );
    }

    #[tokio::test]
    async fn test_tcp_hardlimit_servfail_preserves_id() {
        let zone = build_test_zone();
        let limits = Arc::new(ConnectionLimits::new(
            100, 1000, 65535, 40, 1000, 300, 30, false,
        ));
        let addr = start_test_server_with_zone(Some(zone), Some(limits)).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        let query = build_query(0xCAFE, "txt.test.local", 16);
        stream.write_all(&wrap_tcp(&query)).await.unwrap();

        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await.unwrap();

        // Query ID must be preserved in the SERVFAIL
        let resp_id = u16::from_be_bytes([resp_buf[0], resp_buf[1]]);
        assert_eq!(resp_id, 0xCAFE, "SERVFAIL must preserve query ID");
    }

    #[tokio::test]
    async fn test_tcp_hardlimit_servfail_echoes_question() {
        let zone = build_test_zone();
        let limits = Arc::new(ConnectionLimits::new(
            100, 1000, 65535, 40, 1000, 300, 30, false,
        ));
        let addr = start_test_server_with_zone(Some(zone), Some(limits)).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        let query = build_query(0xBEEF, "txt.test.local", 16);
        stream.write_all(&wrap_tcp(&query)).await.unwrap();

        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await.unwrap();

        // Parse the question section from the original query
        let parsed = ParsedDnsQuery::parse(&query).unwrap();
        let question = &query[12..parsed.question_end];

        // SERVFAIL should have QDCOUNT=1 and echo the question section
        let qdcount = u16::from_be_bytes([resp_buf[4], resp_buf[5]]);
        assert_eq!(qdcount, 1, "SERVFAIL must have QDCOUNT=1");
        assert_eq!(
            &resp_buf[12..],
            question,
            "SERVFAIL must echo the full question section"
        );
    }
}
