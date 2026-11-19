use super::*;

#[cfg(feature = "mesh")]
use crate::mesh_sync::MeshDnsRegistry;

use crate::cache::TransportClass;
use crate::denial::{DenialKind, DenialMode};
use crate::parsed_query::ParsedDnsQuery;

// Only `resolve_from_mesh` takes the country lookup, and that is mesh-gated.
#[cfg(feature = "mesh")]
use crate::geo::CountryLookup;

#[derive(Debug)]
enum TtlParseError {
    Truncated,
    MalformedLabel,
}

/// What the DNS-cookie policy decided for one query.
enum CookiePolicy {
    /// The query may be answered; `refresh` is a fresh COOKIE option to attach
    /// to the response when a valid cookie was presented.
    Pass { refresh: Option<Vec<u8>> },
    /// The query must not reach the answer path.
    Answer(Arc<Vec<u8>>),
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
    /// Sequential persistent DNS-over-TCP (RFC 7766 §4 connection reuse).
    ///
    /// The connection serves multiple length-prefixed queries sequentially on
    /// the same stream: at most one outstanding query at a time. Request
    /// pipelining / multiplexed response reordering is explicitly NOT
    /// supported — a client must wait for each response before sending the
    /// next query. AXFR/IXFR transfers send multiple length-prefixed messages
    /// over the same connection and then return to the query loop.
    ///
    /// Bounding policy (abuse resistance):
    /// - maximum message size is enforced BEFORE allocation from
    ///   `dns.limits.max_query_size` (capped at the 16-bit framing maximum);
    /// - per-read idle timeout from `dns.limits.max_tcp_idle_time_secs`;
    /// - per-query body timeout from `dns.limits.max_tcp_query_time_secs`;
    /// - at most `MAX_TCP_QUERIES_PER_CONNECTION` queries per connection;
    /// - the caller's TCP connection permit is held for the full connection
    ///   lifetime (acquired in `startup.rs` before this call);
    /// - graceful shutdown drains the loop at the next query boundary.
    ///
    /// A clean client close (EOF) or idle timeout ends the loop normally
    /// (`Ok`); framing violations and I/O errors end it with `Err`.
    /// Write one length-prefixed error response on a TCP connection.
    async fn write_tcp_error(
        stream: &mut tokio::net::TcpStream,
        query: &[u8],
        rcode: u8,
    ) -> Result<(), String> {
        use tokio::io::AsyncWriteExt;

        let Some(error) = wire::build_error_response(query, rcode) else {
            return Ok(());
        };
        let len = error.len() as u16;
        let mut buf = len.to_be_bytes().to_vec();
        buf.extend_from_slice(&error);
        stream.write_all(&buf).await.map_err(|e| e.to_string())
    }

    pub(super) async fn handle_tcp_query(
        mut stream: tokio::net::TcpStream,
        ctx: QueryContext<'_>,
    ) -> Result<(), String> {
        use crate::limits::MAX_TCP_QUERIES_PER_CONNECTION;
        use std::io::ErrorKind;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        let client_ip = stream
            .peer_addr()
            .map(|a| a.ip())
            .unwrap_or_else(|_| IpAddr::from([0, 0, 0, 0]));

        let idle_timeout = ctx.max_idle_time.unwrap_or(Duration::from_secs(30));
        let query_timeout = ctx
            .connection_limits
            .map(|l| l.max_tcp_query_time())
            .unwrap_or(Duration::from_secs(30));
        // Enforced BEFORE allocating the query buffer (fail-closed framing).
        let max_frame = ctx
            .connection_limits
            .map(|l| l.max_query_size().min(u16::MAX as usize))
            .unwrap_or(u16::MAX as usize);

        let mut queries_served = 0usize;

        loop {
            if ctx
                .connection_limits
                .map(|l| l.is_in_graceful_shutdown())
                .unwrap_or(false)
            {
                tracing::debug!(
                    transport = "tcp",
                    client = %client_ip,
                    "TCP connection draining for graceful shutdown"
                );
                break;
            }

            if queries_served >= MAX_TCP_QUERIES_PER_CONNECTION {
                tracing::debug!(
                    transport = "tcp",
                    client = %client_ip,
                    queries = queries_served,
                    "TCP connection reached per-connection query bound; closing"
                );
                break;
            }

            let mut length_buf = [0u8; 2];
            match timeout(idle_timeout, stream.read_exact(&mut length_buf)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) if e.kind() == ErrorKind::UnexpectedEof => {
                    tracing::debug!(
                        transport = "tcp",
                        client = %client_ip,
                        "TCP connection closed by client"
                    );
                    break;
                }
                Ok(Err(e)) => return Err(format!("TCP read error: {}", e)),
                Err(_) => {
                    tracing::debug!("TCP connection idle timeout for {}", client_ip);
                    break;
                }
            }

            let len = u16::from_be_bytes([length_buf[0], length_buf[1]]) as usize;

            if len == 0 || len > max_frame {
                return Err(format!(
                    "Invalid TCP query length {} (allowed 1..={})",
                    len, max_frame
                ));
            }

            let mut query = vec![0u8; len];

            match timeout(query_timeout, stream.read_exact(&mut query)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) if e.kind() == ErrorKind::UnexpectedEof => {
                    tracing::debug!(
                        transport = "tcp",
                        client = %client_ip,
                        "TCP connection closed mid-query by client"
                    );
                    break;
                }
                Ok(Err(e)) => return Err(format!("TCP read error: {}", e)),
                Err(_) => {
                    tracing::debug!("TCP query read timeout for {}", client_ip);
                    break;
                }
            }

            queries_served += 1;

            // One gate for every transport. A refusal is written as a DNS
            // error response; a drop (QR=1 or a packet too short to answer)
            // closes this connection without a response, which is the only
            // safe action for a response message (D14).
            let admitted = match crate::server::admit(
                &query,
                client_ip,
                crate::server::TransportKind::Tcp,
                &ctx,
            ) {
                crate::server::Admission::Allow(admitted) => admitted,
                crate::server::Admission::Reply(response) => {
                    let len = response.len() as u16;
                    let mut response_buf = len.to_be_bytes().to_vec();
                    response_buf.extend_from_slice(&response);
                    if let Err(e) = stream.write_all(&response_buf).await {
                        tracing::debug!("Failed to send error response: {}", e);
                    }
                    continue;
                }
                crate::server::Admission::Drop => break,
            };

            // AXFR/IXFR are multi-message protocols, so the TCP framing layer
            // owns them and dispatches them here exactly once. Routing them
            // through `serve_admitted` as well would verify the request TSIG
            // twice, and the second verification of an authentic MAC is a
            // replay.
            {
                let parsed_query = admitted.parsed();
                if parsed_query.is_axfr() || parsed_query.is_ixfr() {
                    if let Some(zt) = ctx.zone_transfer {
                        // Cheap ACL rejection before the TSIG parser sees the
                        // packet (phase 03 R3 / phase 07 R2).
                        let origin = parsed_query.qname.trim_end_matches('.');
                        if !zt.network_and_zone_allowed(client_ip, origin) {
                            Self::write_tcp_error(&mut stream, &query, wire::RCODE_REFUSED).await?;
                            continue;
                        }

                        let tsig = match crate::tsig::parse_tsig_from_query(
                            &query,
                            parsed_query.question_end,
                        ) {
                            Ok(tsig) => tsig,
                            Err(e) => {
                                tracing::warn!("Transfer refused: malformed TSIG: {}", e);
                                Self::write_tcp_error(&mut stream, &query, wire::RCODE_FORMERR)
                                    .await?;
                                continue;
                            }
                        };

                        let outcome = if parsed_query.is_axfr() {
                            zt.handle_axfr_request_messages(
                                &parsed_query.qname,
                                client_ip,
                                tsig.as_ref(),
                                parsed_query.id,
                                &query,
                                true, // TCP path
                            )
                        } else {
                            let serial = Self::extract_ixfr_serial(&query);
                            zt.handle_ixfr_request_messages(
                                &parsed_query.qname,
                                client_ip,
                                serial,
                                tsig.as_ref(),
                                parsed_query.id,
                                &query,
                                true, // TCP path
                            )
                        };

                        match outcome {
                            Ok(messages) => {
                                for msg in messages {
                                    let len = msg.len() as u16;
                                    let mut buf = len.to_be_bytes().to_vec();
                                    buf.extend_from_slice(&msg);
                                    stream.write_all(&buf).await.map_err(|e| e.to_string())?;
                                }
                                continue;
                            }
                            Err(e) => {
                                tracing::warn!("Transfer failed: {} (rcode {})", e, e.rcode);
                                Self::write_tcp_error(&mut stream, &query, e.rcode).await?;
                                continue;
                            }
                        }
                    }
                }
            }

            let response = Self::serve_admitted(&ctx, &admitted, &query, Some(client_ip)).await;

            if let Some(resp) = response {
                // Apply RRL for TCP queries if enabled
                if ctx.rrl_enabled {
                    if let Some(rl) = ctx.rate_limiter {
                        if !rl.should_respond(client_ip) {
                            tracing::debug!("RRL dropping TCP response to {}", client_ip);
                            continue;
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

                        // Build a SERVFAIL that echoes the original question
                        // section (RFC 1035 §4.1.1). Admission guarantees the
                        // query parsed, so the question is always available.
                        let parsed_q = admitted.parsed();
                        let question = &query[12..parsed_q.question_end];
                        let (query_id, rd, question_bytes) = (
                            parsed_q.id,
                            parsed_q.flags.recursion_desired,
                            Some(question.to_vec()),
                        );

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
                                break;
                            }
                        }

                        let len = servfail.len() as u16;
                        let mut response_buf = len.to_be_bytes().to_vec();
                        response_buf.extend_from_slice(&servfail);
                        if let Err(e) = stream.write_all(&response_buf).await {
                            tracing::warn!("Failed to send SERVFAIL response: {}", e);
                            break;
                        }
                        continue;
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
        }

        Ok(())
    }
    pub(super) fn handle_parsed_query_with_cache(
        ctx: &QueryContext,
        parsed: &ParsedDnsQuery<'_>,
        query: &[u8],
        cache: &Arc<DnsCache>,
        transport_class: TransportClass,
        client_ip: Option<std::net::IpAddr>,
    ) -> Option<Arc<Vec<u8>>> {
        // EDNS envelope errors are answered before anything is cached or
        // dispatched: BADVERS must not answer the question, and a duplicate
        // OPT is a FORMERR regardless of opcode.
        if let Some(response) = Self::edns_protocol_error(parsed) {
            return Some(response);
        }

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
                    return match handler.handle_update(query, ip) {
                        Ok(response) => Some(Arc::new(response)),
                        // A refused UPDATE is answered, not dropped: a client
                        // that never receives a reply cannot tell a policy
                        // refusal from a lost packet.
                        Err(e) => {
                            tracing::warn!("UPDATE failed: {} (rcode {})", e, e.rcode);
                            wire::build_error_response(query, e.rcode).map(Arc::new)
                        }
                    };
                }
            }
            return wire::build_error_response(query, wire::RCODE_NOTIMP).map(Arc::new);
        }

        if parsed.is_axfr() {
            if let (Some(zt), Some(ip)) = (ctx.zone_transfer, client_ip) {
                // Cheap ACL rejection before the TSIG parser runs.
                let origin = parsed.qname.trim_end_matches('.');
                if !zt.network_and_zone_allowed(ip, origin) {
                    return wire::build_error_response(query, wire::RCODE_REFUSED).map(Arc::new);
                }

                let tsig = match crate::tsig::parse_tsig_from_query(query, parsed.question_end) {
                    Ok(tsig) => tsig,
                    Err(e) => {
                        tracing::warn!("AXFR refused: malformed TSIG: {}", e);
                        return wire::build_error_response(query, wire::RCODE_FORMERR)
                            .map(Arc::new);
                    }
                };
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
                        tracing::warn!("AXFR failed: {} (rcode {})", e, e.rcode);
                        return wire::build_error_response(query, e.rcode).map(Arc::new);
                    }
                }
            }
            return wire::build_error_response(query, wire::RCODE_NOTIMP).map(Arc::new);
        }

        if parsed.is_ixfr() {
            if let (Some(zt), Some(ip)) = (ctx.zone_transfer, client_ip) {
                let origin = parsed.qname.trim_end_matches('.');
                if !zt.network_and_zone_allowed(ip, origin) {
                    return wire::build_error_response(query, wire::RCODE_REFUSED).map(Arc::new);
                }

                let serial = Self::extract_ixfr_serial(query);
                let tsig = match crate::tsig::parse_tsig_from_query(query, parsed.question_end) {
                    Ok(tsig) => tsig,
                    Err(e) => {
                        tracing::warn!("IXFR refused: malformed TSIG: {}", e);
                        return wire::build_error_response(query, wire::RCODE_FORMERR)
                            .map(Arc::new);
                    }
                };
                let message_id = u16::from_be_bytes([query[0], query[1]]);
                match zt.handle_ixfr_request(
                    &parsed.qname,
                    ip,
                    serial,
                    tsig.as_ref(),
                    message_id,
                    query,
                    transport_class == TransportClass::Tcp,
                ) {
                    Ok(response) => return Some(Arc::new(response)),
                    Err(e) => {
                        tracing::warn!("IXFR failed: {} (rcode {})", e, e.rcode);
                        return wire::build_error_response(query, e.rcode).map(Arc::new);
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
            // The cache stores a complete response, including the transaction
            // ID of the query that produced it. A new query carries a new ID;
            // returning the cached bytes unchanged makes every client but the
            // first discard the datagram as a mismatched response. The key
            // binds qname (case included), qtype, qclass, DO, transport class
            // and client, so the ID is the only field that differs.
            let mut response = cached.as_ref().clone();
            if response.len() >= 2 && query.len() >= 2 {
                response[0..2].copy_from_slice(&query[0..2]);
            }
            return Some(Arc::new(response));
        }

        let result = Self::handle_parsed_query(ctx, parsed, query, client_ip, transport_class);

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
        geoip_lookup: Option<&Arc<dyn CountryLookup>>,
        qtype: u16,
    ) -> Option<Vec<DnsZoneRecord>> {
        let domain = qname.trim_end_matches('.');

        if !mesh_registry.has_origin_for_domain(domain) {
            tracing::debug!("No origin nodes registered for domain {}", domain);
            return None;
        }

        // R1: authenticity is a precondition for answering, not a score
        // penalty. A registration that slipped into the map without the
        // capability's verdict — or one admitted by any future path that skips
        // `sync_from_dht` — must not answer. `calculate_origin_score` still
        // penalizes unauthenticated nodes by 50 points; that is a tie-break,
        // never an admission decision.
        let origins = mesh_registry.get_origin_nodes_for_domain(domain);
        if !origins.iter().any(|origin| origin.authenticated) {
            tracing::warn!(
                domain = %domain,
                "Mesh origin registry holds no authenticated origin for the domain; refusing"
            );
            return None;
        }

        let client_geo = geoip_lookup
            .and_then(|lookup| lookup.country_info(client_ip))
            .map(|c| c.code);

        let best_edge =
            mesh_registry.get_best_edge_for_client(domain, Some(client_ip), client_geo.as_deref());

        // An edge is the preferred answer when one serves the domain. Without
        // one, an authenticated origin answers with the addresses it
        // advertised: that is the DHT-registration path, and before this it
        // produced no records at all because the IPs were discarded.
        let answer_ips = match best_edge {
            Some(edge) => edge.ip_addresses,
            None => {
                let mut authenticated_origins =
                    origins.into_iter().filter(|origin| origin.authenticated);
                let origin = authenticated_origins.next()?;
                authenticated_origins
                    .fold(origin, |best, candidate| {
                        if candidate.capacity > best.capacity
                            || (candidate.capacity == best.capacity
                                && candidate.node_id < best.node_id)
                        {
                            candidate
                        } else {
                            best
                        }
                    })
                    .ip_addresses
            }
        };

        let record_type = match qtype {
            1 => RecordType::A,
            28 => RecordType::AAAA,
            _ => RecordType::A,
        };

        let records = answer_ips
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
            .collect();

        Some(records)
    }

    /// Largest response a transport can carry, given the client's EDNS state.
    ///
    /// This is the single place a response budget is decided; every builder
    /// receives the result explicitly instead of re-deriving it from EDNS.
    ///
    /// * `Udp512` (no EDNS): 512 bytes (RFC 1035 §4.2.1).
    /// * `UdpEdns(advertised)`: the advertised CLASS clamped to
    ///   `[EDNS_MIN_UDP_PAYLOAD, EDNS_MAX_UDP_PAYLOAD]` (RFC 6891 §6.2.5). A
    ///   client that asks for less than 4096 is never sent more, and a client
    ///   that asks for 64 KiB is never sent a fragmented 64 KiB datagram.
    /// * `Tcp`/`Http`/`Quic`: 65535. Stream transports are length-prefixed and
    ///   must not inherit the UDP budget.
    pub(super) fn response_size_limit(transport: TransportClass) -> usize {
        match transport {
            TransportClass::Tcp | TransportClass::Http | TransportClass::Quic => {
                usize::from(u16::MAX)
            }
            TransportClass::Udp512 => usize::from(crate::edns::EDNS_MIN_UDP_PAYLOAD),
            TransportClass::UdpEdns(advertised) => usize::from(advertised.clamp(
                crate::edns::EDNS_MIN_UDP_PAYLOAD,
                crate::edns::EDNS_MAX_UDP_PAYLOAD,
            )),
        }
    }

    /// Answer an EDNS protocol error (BADVERS or a duplicate OPT) using the
    /// query's own question section and EDNS state.
    pub(super) fn build_edns_error_response(
        parsed: &ParsedDnsQuery<'_>,
        rcode: u8,
        extended_rcode: u16,
    ) -> Option<Arc<Vec<u8>>> {
        let opt = parsed.edns.as_ref().map(|edns| {
            super::response_encoder::build_opt_encoded_record(
                edns.udp_payload_size,
                edns.dnssec_ok,
                extended_rcode,
            )
            .bytes
        });
        wire::build_error_response_with_opt(parsed.raw, rcode, opt.as_deref()).map(Arc::new)
    }

    /// Reject a query whose EDNS envelope cannot be answered normally.
    ///
    /// RFC 6891 §6.1.1: more than one OPT record is a FORMERR.
    /// RFC 6891 §6.1.3: an unsupported EDNS version is answered with BADVERS
    /// (extended RCODE 16) and the question is not answered.
    fn edns_protocol_error(parsed: &ParsedDnsQuery<'_>) -> Option<Arc<Vec<u8>>> {
        if parsed.duplicate_opt || parsed.malformed_edns {
            return Self::build_edns_error_response(
                parsed,
                wire::RCODE_FORMERR,
                crate::edns::EXTENDED_RCODE_NONE,
            );
        }
        let edns = parsed.edns.as_ref()?;
        if edns.version != crate::edns::EDNS_VERSION {
            return Self::build_edns_error_response(parsed, 0, crate::edns::EXTENDED_RCODE_BADVERS);
        }
        None
    }

    /// Unadmitted dispatch entry: **not** for listeners.
    ///
    /// Phase 03 moved every listener onto [`crate::server::admit`] followed by
    /// [`Self::serve_admitted`], which is the only dispatch entry that has
    /// admission's token. This function remains for tests and embedded callers
    /// that already hold a query they trust; it performs no size, firewall, or
    /// rate-limit check.
    ///
    /// It applies the **stream** budget of 65535 bytes. Callers that need the
    /// UDP budget use [`Self::handle_query_with_transport`] with a
    /// `TransportClass::Udp*` value.
    pub fn handle_query(
        ctx: &QueryContext,
        query: &[u8],
        client_ip: Option<std::net::IpAddr>,
    ) -> Option<Arc<Vec<u8>>> {
        Self::handle_query_with_transport(ctx, query, client_ip, TransportClass::Tcp)
    }

    /// Transport-aware entry point.
    ///
    /// `transport_class` decides the response budget once, in
    /// [`Self::response_size_limit`], and is threaded through the builders.
    pub fn handle_query_with_transport(
        ctx: &QueryContext,
        query: &[u8],
        client_ip: Option<std::net::IpAddr>,
        transport_class: TransportClass,
    ) -> Option<Arc<Vec<u8>>> {
        let parsed = ParsedDnsQuery::parse(query).ok()?;
        Self::handle_parsed_query(ctx, &parsed, query, client_ip, transport_class)
    }

    /// RFC 7873 server-cookie enforcement for UDP.
    ///
    /// DoH/DoT/DoQ are exempt: a spoofed source cannot complete the
    /// handshake, so cookies add nothing there. On UDP, when
    /// `dns.settings.require_cookie` is on:
    ///
    /// - no OPT record: the cookie cannot be returned, so REFUSED;
    /// - no valid server cookie: BADCOOKIE (extended RCODE 23) with a fresh
    ///   server cookie;
    /// - a valid cookie: the query proceeds and the response carries a
    ///   refreshed cookie.
    fn cookie_policy(
        ctx: &QueryContext,
        parsed: &ParsedDnsQuery<'_>,
        transport_class: TransportClass,
        client_ip: Option<IpAddr>,
    ) -> CookiePolicy {
        // Control-plane messages are authenticated by their own path.
        if parsed.is_notify() || parsed.is_update() {
            return CookiePolicy::Pass { refresh: None };
        }

        if !matches!(
            transport_class,
            TransportClass::Udp512 | TransportClass::UdpEdns(_)
        ) {
            return CookiePolicy::Pass { refresh: None };
        }

        let Some(server) = ctx.cookie_server else {
            return CookiePolicy::Pass { refresh: None };
        };
        if !server.require_cookie() {
            return CookiePolicy::Pass { refresh: None };
        }

        let client_ip = client_ip.unwrap_or(IpAddr::from([127, 0, 0, 1]));

        let Some(edns) = parsed.edns.as_ref() else {
            // RFC 7873 §5.2.3 requires the fresh cookie to travel in an OPT
            // record. Without EDNS there is no way to return one, and
            // answering silently would defeat the control.
            tracing::debug!(
                client = %client_ip,
                "Cookie required but the query carried no EDNS; refusing"
            );
            return CookiePolicy::Answer(
                wire::build_error_response(parsed.raw, wire::RCODE_REFUSED)
                    .map(Arc::new)
                    .unwrap_or_default(),
            );
        };

        let client_cookie = edns
            .cookie
            .as_ref()
            .map(|cookie| cookie.client_cookie.clone())
            .filter(|cookie| cookie.len() >= 8);
        let server_cookie = edns
            .cookie
            .as_ref()
            .and_then(|cookie| cookie.server_cookie.as_ref())
            .filter(|cookie| !cookie.is_empty());

        if let (Some(client_cookie), Some(server_cookie)) = (&client_cookie, server_cookie) {
            if server.validate_cookie(client_ip, client_cookie, server_cookie) {
                let fresh = server.generate_server_cookie(client_ip, client_cookie);
                return CookiePolicy::Pass {
                    refresh: Some(crate::edns::EdnsOptions::build_cookie_option(
                        client_cookie,
                        &fresh,
                    )),
                };
            }
        }

        let (client_cookie, server_cookie) = match client_cookie {
            // Echo the client's cookie and pair it with a fresh server
            // cookie, so a client that merely lost ours can recover.
            Some(client_cookie) => {
                let server_cookie = server.generate_server_cookie(client_ip, &client_cookie);
                (client_cookie, server_cookie)
            }
            None => match server.create_response_cookie(client_ip) {
                Ok(mut cookies) => {
                    let server_cookie = cookies.split_off(8);
                    (cookies, server_cookie)
                }
                Err(e) => {
                    tracing::error!(error = %e, "Cookie RNG failed; refusing the query");
                    return CookiePolicy::Answer(
                        wire::build_error_response(parsed.raw, wire::RCODE_SERVFAIL)
                            .map(Arc::new)
                            .unwrap_or_default(),
                    );
                }
            },
        };

        let option = crate::edns::EdnsOptions::build_cookie_option(&client_cookie, &server_cookie);
        match Self::build_badcookie_response(parsed, edns.udp_payload_size, edns.dnssec_ok, &option)
        {
            Some(response) => CookiePolicy::Answer(response),
            None => CookiePolicy::Answer(
                wire::build_error_response(parsed.raw, wire::RCODE_REFUSED)
                    .map(Arc::new)
                    .unwrap_or_default(),
            ),
        }
    }

    /// BADCOOKIE (extended RCODE 23) with the supplied COOKIE option.
    fn build_badcookie_response(
        parsed: &ParsedDnsQuery<'_>,
        udp_payload_size: u16,
        dnssec_ok: bool,
        cookie_option: &[u8],
    ) -> Option<Arc<Vec<u8>>> {
        let payload = udp_payload_size.clamp(
            crate::edns::EDNS_MIN_UDP_PAYLOAD,
            crate::edns::EDNS_MAX_UDP_PAYLOAD,
        );

        let mut opt = Vec::with_capacity(11 + cookie_option.len());
        opt.push(0); // NAME: root
        opt.extend_from_slice(&41u16.to_be_bytes()); // TYPE: OPT
        opt.extend_from_slice(&payload.to_be_bytes()); // CLASS: advertised payload
        let mut ttl = u32::from((crate::edns::EXTENDED_RCODE_BADCOOKIE >> 4) as u8) << 24;
        if dnssec_ok {
            ttl |= 0x8000;
        }
        opt.extend_from_slice(&ttl.to_be_bytes());
        opt.extend_from_slice(&(cookie_option.len() as u16).to_be_bytes());
        opt.extend_from_slice(cookie_option);

        // The low four bits of BADCOOKIE live in the header RCODE; the OPT
        // TTL carries the upper eight (RFC 6891 §6.1.3).
        let header_rcode = (crate::edns::EXTENDED_RCODE_BADCOOKIE & 0x0F) as u8;
        wire::build_error_response_with_opt(parsed.raw, header_rcode, Some(&opt)).map(Arc::new)
    }

    /// Append a COOKIE option to the response's OPT record.
    ///
    /// Every response builder emits the OPT last with an empty RDLENGTH, so
    /// the option is appended there and the length is set once.
    fn attach_cookie_option(mut response: Vec<u8>, cookie_option: &[u8]) -> Vec<u8> {
        if response.len() < 12 || cookie_option.is_empty() {
            return response;
        }
        let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;
        let total = u16::from_be_bytes([response[6], response[7]]) as usize
            + u16::from_be_bytes([response[8], response[9]]) as usize
            + u16::from_be_bytes([response[10], response[11]]) as usize;

        let mut pos = 12;
        for _ in 0..qdcount {
            let Ok(next) = Self::skip_dns_name(&response, pos) else {
                return response;
            };
            pos = next + 4;
            if pos > response.len() {
                return response;
            }
        }

        for index in 0..total {
            let Ok(next) = Self::skip_dns_name(&response, pos) else {
                return response;
            };
            if next + 10 > response.len() {
                return response;
            }
            let rtype = u16::from_be_bytes([response[next], response[next + 1]]);
            let rdlen = u16::from_be_bytes([response[next + 8], response[next + 9]]) as usize;
            let rd_start = next + 10;
            if rd_start + rdlen > response.len() {
                return response;
            }
            if rtype == 41 && rdlen == 0 && index + 1 == total {
                response[next + 8..next + 10]
                    .copy_from_slice(&(cookie_option.len() as u16).to_be_bytes());
                response.extend_from_slice(cookie_option);
                return response;
            }
            pos = rd_start + rdlen;
        }

        response
    }

    /// Dispatch one parsed query.
    ///
    /// The DNS-cookie gate runs here, once, for every transport and before
    /// the answer cache: a BADCOOKIE challenge is per-client state and must
    /// never be served from, or written to, a shared cache entry.
    pub(super) fn handle_parsed_query(
        ctx: &QueryContext,
        parsed: &ParsedDnsQuery<'_>,
        query: &[u8],
        client_ip: Option<std::net::IpAddr>,
        transport_class: TransportClass,
    ) -> Option<Arc<Vec<u8>>> {
        match Self::cookie_policy(ctx, parsed, transport_class, client_ip) {
            CookiePolicy::Answer(response) => Some(response),
            CookiePolicy::Pass { refresh: None } => {
                Self::handle_parsed_query_inner(ctx, parsed, query, client_ip, transport_class)
            }
            CookiePolicy::Pass {
                refresh: Some(cookie_option),
            } => Self::handle_parsed_query_inner(ctx, parsed, query, client_ip, transport_class)
                .map(|response| {
                    let refreshed = Self::attach_cookie_option((*response).clone(), &cookie_option);
                    let budget = Self::response_size_limit(transport_class);
                    if refreshed.len() <= budget {
                        Arc::new(refreshed)
                    } else {
                        // The refreshed cookie does not fit the client's
                        // advertised budget. The answer is still valid; the
                        // refresh is advisory (RFC 7873 §5.2.3).
                        response
                    }
                }),
        }
    }

    fn handle_parsed_query_inner(
        ctx: &QueryContext,
        parsed: &ParsedDnsQuery<'_>,
        query: &[u8],
        client_ip: Option<std::net::IpAddr>,
        transport_class: TransportClass,
    ) -> Option<Arc<Vec<u8>>> {
        if let Some(response) = Self::edns_protocol_error(parsed) {
            return Some(response);
        }

        let query_id = parsed.id;
        let rd = parsed.flags.recursion_desired;
        // The client's question section, echoed verbatim into every response.
        let question_bytes = &parsed.raw[12..parsed.question_end];
        let max_size = Self::response_size_limit(transport_class);

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
                    return match handler.handle_update(query, ip) {
                        Ok(response) => Some(Arc::new(response)),
                        // Answer the refusal: a dropped UPDATE is
                        // indistinguishable from a lost packet.
                        Err(e) => {
                            tracing::warn!("UPDATE failed: {} (rcode {})", e, e.rcode);
                            wire::build_error_response(query, e.rcode).map(Arc::new)
                        }
                    };
                }
            }
            return None;
        }

        // The OPT record was parsed once, when the query was parsed. No
        // positional sniffing here: a second parse is a second assumption.
        let mut edns_options = parsed.edns.clone();

        if let Some(ref mut edns) = edns_options {
            crate::edns::filter_ecs(edns, ctx.ecs_filter_config);
        }

        let dnssec_ok = edns_options.as_ref().map(|e| e.dnssec_ok).unwrap_or(false);

        let qname_lower = parsed.qname.to_lowercase();

        if parsed.qtype == 16 {
            // TXT record query - check for ACME DNS-01 challenge
            if qname_lower.starts_with("_acme-challenge.") {
                if let Some(acme_challenges) = ctx.acme_dns_challenges {
                    let domain = qname_lower
                        .strip_prefix("_acme-challenge.")
                        .unwrap_or(&qname_lower);
                    if let Some(txt_value) = acme_challenges.txt_value(domain) {
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
                            max_size,
                            question_bytes,
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
                        question_bytes,
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
                    question_bytes,
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
            let has_opt = edns_options.is_some();
            let arcount: u16 = if has_opt { 1 } else { 0 };
            let mut packet = Vec::with_capacity(12 + question_bytes.len() + 16);
            packet.extend_from_slice(&parsed.id.to_be_bytes());
            packet.extend_from_slice(&flags.to_be_bytes());
            packet.extend_from_slice(&1u16.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes());
            packet.extend_from_slice(&0u16.to_be_bytes());
            packet.extend_from_slice(&arcount.to_be_bytes());
            packet.extend_from_slice(question_bytes);
            if let Some(edns) = edns_options {
                let opt = super::response_encoder::build_opt_encoded_record(
                    edns.udp_payload_size,
                    edns.dnssec_ok,
                    crate::edns::EXTENDED_RCODE_NONE,
                );
                packet.extend_from_slice(&opt.bytes);
            }
            return Some(Arc::new(packet));
        }

        // RFC 4035 §2.2: a zone signs with both keys or not at all. Startup
        // rejects a half-configured signed zone; this is the query-path
        // defense for a zone that bypassed it — fail closed, do not serve a
        // mix of signed and unsigned RRsets.
        let signing = match Self::signing_keys_for_zone(
            &zone,
            query_id,
            &parsed.qname,
            rd,
            edns_options.as_ref(),
            question_bytes,
        ) {
            Ok(signing) => signing,
            Err(resp) => return Some(resp),
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

        // ── R1: one authoritative lookup, used by the signed and the
        // unsigned path. The outcome describes what the zone holds; response
        // construction, signing and phase-05 proof selection happen below.
        let outcome = zone.lookup(&parsed.qname, record_type);

        // ANY is answered from every RRset at the owner, which is not an
        // ordinary single-type lookup; it runs before the negative branches.
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
                    max_size,
                    signing.as_ref(),
                    &origin_canonical,
                    rd,
                    question_bytes,
                );
                return Some(resp);
            }
        }

        match &outcome {
            LookupOutcome::Answer { records, .. } => {
                let (resp, _report) = Self::build_response(
                    query_id,
                    &parsed.qname,
                    parsed.qtype,
                    records,
                    dnssec_ok,
                    edns_options.as_ref(),
                    max_size,
                    signing.as_ref(),
                    &origin_canonical,
                    rd,
                    question_bytes,
                );
                return Some(resp);
            }
            LookupOutcome::Cname { records } => {
                let (resp, _report) = Self::build_response(
                    query_id,
                    &parsed.qname,
                    parsed.qtype,
                    records,
                    dnssec_ok,
                    edns_options.as_ref(),
                    max_size,
                    signing.as_ref(),
                    &origin_canonical,
                    rd,
                    question_bytes,
                );
                return Some(resp);
            }
            LookupOutcome::WildcardAnswer { wildcard, records } => {
                // RFC 4035 §3.1.3.3: a wildcard expansion carries the
                // next-closer non-existence proof. A signed zone that cannot
                // select it must not answer.
                let proof = if dnssec_ok && (zone.nsec_enabled || zone.nsec3_enabled) {
                    let mode = if zone.nsec3_enabled {
                        DenialMode::Nsec3
                    } else {
                        DenialMode::Nsec
                    };
                    zone.denial()
                        .proof(mode, DenialKind::WildcardAnswer, &parsed.qname)
                } else {
                    None
                };
                if proof.is_none() && signing.is_some() && dnssec_ok {
                    tracing::error!(
                        qname = %parsed.qname,
                        zone = %zone.origin,
                        wildcard = %wildcard,
                        "DNSSEC: signed zone cannot select the wildcard next-closer proof; returning SERVFAIL"
                    );
                    metrics::counter!("dns_dnssec_denial_failure_total").increment(1);
                    return Some(Self::servfail_packet(
                        parsed.id,
                        rd,
                        edns_options.as_ref(),
                        question_bytes,
                    ));
                }
                let empty: Vec<Arc<DnsZoneRecord>> = Vec::new();
                let resp = Self::build_wildcard_response(
                    query_id,
                    &parsed.qname,
                    parsed.qtype,
                    wildcard,
                    records,
                    proof.as_ref().unwrap_or(&empty),
                    dnssec_ok,
                    edns_options.as_ref(),
                    max_size,
                    signing.as_ref(),
                    &origin_canonical,
                    rd,
                    question_bytes,
                );
                return Some(resp);
            }
            LookupOutcome::Dname { answer } => {
                // RFC 6672 §3.1/§5.3.1: the DNAME is signed, the synthesized
                // CNAME is not, and both are in the answer section.
                let resp = Self::build_dname_response(
                    query_id,
                    &parsed.qname,
                    parsed.qtype,
                    answer,
                    dnssec_ok,
                    edns_options.as_ref(),
                    max_size,
                    signing.as_ref(),
                    &origin_canonical,
                    rd,
                    question_bytes,
                );
                return Some(resp);
            }
            LookupOutcome::Referral {
                delegation,
                authority,
                additional,
            } => {
                // RFC 4035 §3.1.4.1: a secure delegation carries its DS RRset;
                // an insecure one carries the proof that no DS exists.
                let mut proof: Vec<DnsZoneRecord> = Vec::new();
                match zone.rrset(delegation, RecordType::DS) {
                    Some(ds) if !ds.is_empty() => proof.extend(ds.iter().cloned()),
                    _ => {
                        if dnssec_ok && (zone.nsec_enabled || zone.nsec3_enabled) {
                            let mode = if zone.nsec3_enabled {
                                DenialMode::Nsec3
                            } else {
                                DenialMode::Nsec
                            };
                            match zone.denial().proof(mode, DenialKind::NoData, delegation) {
                                Some(records) => proof
                                    .extend(records.iter().map(|record| record.as_ref().clone())),
                                None if signing.is_some() => {
                                    tracing::error!(
                                        zone = %zone.origin,
                                        delegation = %delegation,
                                        "DNSSEC: no proof of the delegation's DS state; returning SERVFAIL"
                                    );
                                    metrics::counter!("dns_dnssec_denial_failure_total")
                                        .increment(1);
                                    return Some(Self::servfail_packet(
                                        parsed.id,
                                        rd,
                                        edns_options.as_ref(),
                                        question_bytes,
                                    ));
                                }
                                None => {}
                            }
                        }
                    }
                }
                let resp = Self::build_referral_response(
                    query_id,
                    &parsed.qname,
                    parsed.qtype,
                    authority,
                    additional,
                    &proof,
                    dnssec_ok,
                    edns_options.as_ref(),
                    max_size,
                    signing.as_ref(),
                    &origin_canonical,
                    rd,
                    question_bytes,
                );
                return Some(resp);
            }
            LookupOutcome::Loop => {
                tracing::warn!("CNAME loop detected for {}", parsed.qname);
                let (resp, _report) = Self::build_refused(
                    parsed.id,
                    &parsed.qname,
                    parsed.qtype,
                    edns_options.as_ref(),
                    question_bytes,
                );
                return Some(resp);
            }
            LookupOutcome::DnameOverflow => {
                // RFC 6672 §3.2: a substitution that overflows the legal name
                // length is YXDOMAIN, not a truncated name.
                return Some(Self::build_rcode_response(
                    query_id,
                    &parsed.qname,
                    parsed.qtype,
                    crate::wire::UPDATE_RCODE_YXDOMAIN,
                    edns_options.as_ref(),
                    max_size,
                    rd,
                    question_bytes,
                ));
            }
            // Negative outcomes are answered below, after the synthetic apex
            // RRsets and the mesh/DNS64 fallbacks.
            LookupOutcome::NoData
            | LookupOutcome::EmptyNonTerminal
            | LookupOutcome::WildcardNoData { .. }
            | LookupOutcome::NxDomain => {}
        }

        // DNSSEC key material at the zone apex is built from the zone's key
        // handles rather than looked up in `records`, so these branches must
        // run for their own qtype — not only inside the ANY (255) block.
        if record_type == RecordType::DNSKEY && qname_lower_trimmed == origin_lower_for_strip {
            let dnskey_records = Self::build_dnskey_records(&zone);
            let (resp, _report) = Self::build_response(
                query_id,
                &parsed.qname,
                parsed.qtype,
                &dnskey_records,
                dnssec_ok,
                edns_options.as_ref(),
                max_size,
                signing.as_ref(),
                &origin_canonical,
                rd,
                question_bytes,
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
                    max_size,
                    signing.as_ref(),
                    &origin_canonical,
                    rd,
                    question_bytes,
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
                max_size,
                signing.as_ref(),
                &origin_canonical,
                rd,
                question_bytes,
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
                    max_size,
                    signing.as_ref(),
                    &origin_canonical,
                    rd,
                    question_bytes,
                );
                return Some(resp);
            }
        }

        if record_type == RecordType::NSEC3PARAM && qname_lower_trimmed == origin_lower_for_strip {
            if let Some(nsec3param_record) = Self::build_nsec3param_record(&zone) {
                let (resp, _report) = Self::build_response(
                    query_id,
                    &parsed.qname,
                    parsed.qtype,
                    &[nsec3param_record],
                    dnssec_ok,
                    edns_options.as_ref(),
                    max_size,
                    signing.as_ref(),
                    &origin_canonical,
                    rd,
                    question_bytes,
                );
                return Some(resp);
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
                    // Mesh records are synthesized under the queried name, so
                    // the signer name is the covering zone's apex when there is
                    // one; without a zone the answer is not signable.
                    let (mesh_signing, mesh_origin) = match mesh_zone.as_ref() {
                        Some(zone) => (
                            ZoneSigningKeys::from_zone(zone).ok().flatten(),
                            zone.origin.clone(),
                        ),
                        None => (None, parsed.qname.clone()),
                    };
                    let (resp, _report) = Self::build_response(
                        query_id,
                        &parsed.qname,
                        parsed.qtype,
                        &mesh_records,
                        dnssec_ok,
                        edns_options.as_ref(),
                        max_size,
                        mesh_signing.as_ref(),
                        &mesh_origin,
                        rd,
                        question_bytes,
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
                        if let Some(a_records) = zone.rrset(&parsed.qname, RecordType::A) {
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
                                // The owner is built from (record.name, zone origin);
                                // a suffix of the qname is not the origin.
                                let origin = zone.origin.clone();
                                let (resp, _report) = Self::build_response(
                                    query_id,
                                    &parsed.qname,
                                    parsed.qtype,
                                    &aaaa_records,
                                    dnssec_ok,
                                    edns_options.as_ref(),
                                    max_size,
                                    None,
                                    &origin,
                                    rd,
                                    question_bytes,
                                );
                                return Some(resp);
                            }
                        }
                    }
                }
            }
        }

        // Only a negative outcome reaches this point. The proof kind is a
        // property of the lookup outcome, not a second guess at the data:
        // an owner (or empty non-terminal) is NODATA, a matched wildcard with
        // no RRset of the qtype is wildcard NODATA, everything else is a name
        // error.
        if dnssec_ok && (zone.nsec_enabled || zone.nsec3_enabled) {
            let mode = if zone.nsec3_enabled {
                DenialMode::Nsec3
            } else {
                DenialMode::Nsec
            };
            let kind = match &outcome {
                LookupOutcome::NoData => DenialKind::NoData,
                // An empty non-terminal has no NSEC of its own, so RFC 4035
                // §3.1.3.2 proves its NODATA with the name-error form; RFC
                // 5155 §7.2.3 gives every ENT its own empty-bitmap NSEC3, so
                // there it is ordinary NODATA.
                LookupOutcome::EmptyNonTerminal => {
                    if mode == DenialMode::Nsec3 {
                        DenialKind::NoData
                    } else {
                        DenialKind::NxDomain
                    }
                }
                LookupOutcome::WildcardNoData { .. } => DenialKind::WildcardNoData,
                _ => DenialKind::NxDomain,
            };

            if let Some(proof) = zone.denial().proof(mode, kind, &parsed.qname) {
                if !proof.is_empty() {
                    let origin = zone.origin.clone();
                    let soa_record = zone.get_soa();
                    return Some(
                        if matches!(kind, DenialKind::NoData | DenialKind::WildcardNoData) {
                            Self::build_nodata_response(
                                parsed.id,
                                &parsed.qname,
                                parsed.qtype,
                                &proof,
                                dnssec_ok,
                                edns_options.as_ref(),
                                max_size,
                                signing.as_ref(),
                                origin.as_str(),
                                soa_record.as_ref(),
                                rd,
                                question_bytes,
                            )
                        } else {
                            Self::build_nxdomain_response(
                                parsed.id,
                                &parsed.qname,
                                parsed.qtype,
                                &proof,
                                dnssec_ok,
                                edns_options.as_ref(),
                                max_size,
                                signing.as_ref(),
                                origin.as_str(),
                                soa_record.as_ref(),
                                rd,
                                question_bytes,
                            )
                        },
                    );
                }
            }

            if signing.is_some() {
                tracing::error!(
                    qname = %parsed.qname,
                    zone = %zone.origin,
                    mode = ?mode,
                    kind = ?kind,
                    "DNSSEC: signed zone cannot select a denial proof; returning SERVFAIL"
                );
                metrics::counter!("dns_dnssec_denial_failure_total").increment(1);
                return Some(Self::servfail_packet(
                    parsed.id,
                    rd,
                    edns_options.as_ref(),
                    question_bytes,
                ));
            }
        }

        let soa = zone.get_soa();
        let is_nxdomain = matches!(outcome, LookupOutcome::NxDomain);
        Some(if is_nxdomain {
            let (resp, _report) = Self::build_unsigned_nxdomain(
                parsed.id,
                &parsed.qname,
                parsed.qtype,
                soa.as_ref(),
                edns_options.as_ref(),
                max_size,
                ctx.negative_cache_ttl,
                rd,
                origin_str.as_str(),
                question_bytes,
            );
            resp
        } else {
            let (resp, _report) = Self::build_unsigned_nodata(
                parsed.id,
                &parsed.qname,
                parsed.qtype,
                soa.as_ref(),
                edns_options.as_ref(),
                max_size,
                ctx.negative_cache_ttl,
                rd,
                origin_str.as_str(),
                question_bytes,
            );
            resp
        })
    }

    /// Append one authority-section RRset, followed by its RRSIG when the
    /// zone is signed.
    ///
    /// Returns `false` if the record, its signature, or the RRSIG's encoding
    /// fails. The caller must then answer SERVFAIL: an RRset served without
    /// its RRSIG (or an RRSIG without its RRset) is not a truthful negative
    /// answer (RFC 4035 §3.1.3, finding L4).
    pub(super) fn push_authority_rrset(
        envelope: &mut super::response_encoder::ResponseEnvelope,
        record: &DnsZoneRecord,
        origin: &str,
        signing: Option<&ZoneSigningKeys<'_>>,
    ) -> bool {
        use super::response_encoder::{encode_rr, DnsSection};

        let Ok(mut encoded) = encode_rr(record, origin, None) else {
            tracing::error!(
                owner = %record.name,
                record_type = ?record.record_type,
                "DNS encode: authority record failed; returning SERVFAIL"
            );
            return false;
        };
        encoded.section = DnsSection::Authority;
        envelope.authority_records.push(encoded);

        let Some(keys) = signing else {
            return true;
        };

        let Ok(rrsig) = Self::create_signed_rrsig(&[record], origin, keys) else {
            return false;
        };
        let rrsig_record = DnsZoneRecord {
            name: record.name.clone(),
            record_type: RecordType::RRSIG,
            value: hex::encode(&rrsig),
            ttl: record.ttl,
            priority: None,
        };
        let Ok(mut encoded) = encode_rr(&rrsig_record, origin, None) else {
            tracing::error!(
                owner = %record.name,
                "DNS encode: RRSIG failed; refusing to serve the unsigned RRset"
            );
            return false;
        };
        encoded.section = DnsSection::Authority;
        envelope.authority_records.push(encoded);
        true
    }

    /// Build an authoritative NXDOMAIN with its NSEC/NSEC3 proof.
    ///
    /// A signed zone answers with the SOA **and its RRSIG** (RFC 4035
    /// §3.1.3), then the denial proof and its RRSIG; the SOA and the proof are
    /// signed with the ZSK by [`ZoneSigningKeys::signing_key_for`].
    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_nxdomain_response(
        response_id: u16,
        qname: &str,
        qtype: u16,
        proof: &[Arc<DnsZoneRecord>],
        dnssec_ok: bool,
        edns_options: Option<&EdnsOptions>,
        max_size: usize,
        signing: Option<&ZoneSigningKeys<'_>>,
        origin: &str,
        soa_record: Option<&DnsZoneRecord>,
        rd: bool,
        question: &[u8],
    ) -> Arc<Vec<u8>> {
        use super::response_encoder::{
            assemble_packet, build_opt_encoded_record, build_response_flags, ResponseEnvelope,
        };

        let signing = if dnssec_ok { signing } else { None };
        let mut envelope = ResponseEnvelope::default();

        // Fail-closed: missing SOA is an internal invariant violation.
        // The zone SOA check in handle_parsed_query should catch this earlier,
        // but we enforce it here as defense-in-depth.
        let Some(soa) = soa_record else {
            tracing::error!(
                qname = %qname,
                "Missing SOA record for signed NXDOMAIN response (internal invariant violation), returning SERVFAIL"
            );
            return Self::servfail_packet(response_id, rd, edns_options, question);
        };

        // Authority section: SOA (RFC 2308) followed by its RRSIG.
        if !Self::push_authority_rrset(&mut envelope, soa, origin, signing) {
            tracing::error!(
                qname = %qname,
                "DNS encode: SOA or its RRSIG failed for NXDOMAIN response, returning SERVFAIL"
            );
            return Self::servfail_packet(response_id, rd, edns_options, question);
        }

        // Authority section: the selected NSEC/NSEC3 denial proof records,
        // each followed by its RRSIG.
        for proof_record in proof {
            if !Self::push_authority_rrset(&mut envelope, proof_record.as_ref(), origin, signing) {
                tracing::error!(
                    qname = %qname,
                    "DNS encode: denial proof or its RRSIG failed for NXDOMAIN response, returning SERVFAIL"
                );
                return Self::servfail_packet(response_id, rd, edns_options, question);
            }
        }

        // Additional section: OPT record
        if let Some(edns) = edns_options {
            envelope.additional_records.push(build_opt_encoded_record(
                edns.udp_payload_size,
                dnssec_ok,
                crate::edns::EXTENDED_RCODE_NONE,
            ));
        } else if dnssec_ok {
            envelope.additional_records.push(build_opt_encoded_record(
                crate::edns::EDNS_MAX_UDP_PAYLOAD,
                dnssec_ok,
                crate::edns::EXTENDED_RCODE_NONE,
            ));
        }

        // Authoritative servers never set AD — AD is a recursive validation signal.
        let flags = build_response_flags(true, false, rd, false, false, 3);
        let packet = assemble_packet(&envelope, response_id, flags, question);
        Self::fit_to_transport(
            response_id,
            packet,
            qname,
            qtype,
            edns_options,
            max_size,
            rd,
            question,
        )
    }

    /// Build an authoritative NODATA answer with its NSEC/NSEC3 proof.
    ///
    /// Same rule as NXDOMAIN: the SOA is signed and its RRSIG follows it, and
    /// the denial proof keeps its signature.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_nodata_response(
        response_id: u16,
        qname: &str,
        qtype: u16,
        proof: &[Arc<DnsZoneRecord>],
        dnssec_ok: bool,
        edns_options: Option<&EdnsOptions>,
        max_size: usize,
        signing: Option<&ZoneSigningKeys<'_>>,
        origin: &str,
        soa_record: Option<&DnsZoneRecord>,
        rd: bool,
        question: &[u8],
    ) -> Arc<Vec<u8>> {
        use super::response_encoder::{
            assemble_packet, build_opt_encoded_record, build_response_flags, ResponseEnvelope,
        };

        let signing = if dnssec_ok { signing } else { None };
        let mut envelope = ResponseEnvelope::default();

        // Fail-closed: missing SOA is an internal invariant violation.
        // The zone SOA check in handle_parsed_query should catch this earlier,
        // but we enforce it here as defense-in-depth.
        let Some(soa) = soa_record else {
            tracing::error!(
                qname = %qname,
                "Missing SOA record for signed NODATA response (internal invariant violation), returning SERVFAIL"
            );
            return Self::servfail_packet(response_id, rd, edns_options, question);
        };

        // Authority section: SOA (RFC 2308) followed by its RRSIG.
        if !Self::push_authority_rrset(&mut envelope, soa, origin, signing) {
            tracing::error!(
                qname = %qname,
                "DNS encode: SOA or its RRSIG failed for NODATA response, returning SERVFAIL"
            );
            return Self::servfail_packet(response_id, rd, edns_options, question);
        }

        // Authority section: the selected NSEC/NSEC3 denial proof records,
        // each followed by its RRSIG.
        for proof_record in proof {
            if !Self::push_authority_rrset(&mut envelope, proof_record.as_ref(), origin, signing) {
                tracing::error!(
                    qname = %qname,
                    "DNS encode: denial proof or its RRSIG failed for NODATA response, returning SERVFAIL"
                );
                return Self::servfail_packet(response_id, rd, edns_options, question);
            }
        }

        // Additional section: OPT record
        if let Some(edns) = edns_options {
            envelope.additional_records.push(build_opt_encoded_record(
                edns.udp_payload_size,
                dnssec_ok,
                crate::edns::EXTENDED_RCODE_NONE,
            ));
        } else if dnssec_ok {
            envelope.additional_records.push(build_opt_encoded_record(
                crate::edns::EDNS_MAX_UDP_PAYLOAD,
                dnssec_ok,
                crate::edns::EXTENDED_RCODE_NONE,
            ));
        }

        // NODATA: RCODE 0 (NOERROR), authoritative answer
        // Authoritative servers never set AD — AD is a recursive validation signal.
        let flags = build_response_flags(true, false, rd, false, false, 0);
        let packet = assemble_packet(&envelope, response_id, flags, question);
        Self::fit_to_transport(
            response_id,
            packet,
            qname,
            qtype,
            edns_options,
            max_size,
            rd,
            question,
        )
    }

    /// Enforce the transport's response budget and degrade to a TC=1 empty
    /// response when the assembled answer does not fit.
    ///
    /// `max_size` is computed once per request by
    /// [`Self::response_size_limit`]: the client's EDNS advertisement clamped
    /// to `[512, 4096]` on UDP, or 65535 on a stream transport. There is no
    /// second notion of transport here.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn fit_to_transport(
        response_id: u16,
        packet: Vec<u8>,
        qname: &str,
        qtype: u16,
        edns_options: Option<&EdnsOptions>,
        max_size: usize,
        rd: bool,
        question: &[u8],
    ) -> Arc<Vec<u8>> {
        if packet.len() > max_size {
            tracing::debug!(
                qname = %qname,
                response_len = packet.len(),
                max_size = max_size,
                "DNS authoritative response truncated for its transport"
            );
            return Self::build_truncated_tc_response(
                response_id,
                qname,
                qtype,
                rd,
                edns_options,
                question,
            )
            .0;
        }
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

// ── TCP persistent-connection lifecycle tests (Phase 45) ──────────────

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

    /// Phase 45 (Workstream D): the connection stays open after one response
    /// and serves a second sequential query on the same stream (RFC 7766
    /// connection reuse; no pipelining — one outstanding query at a time).
    #[tokio::test]
    async fn test_tcp_connection_reused_for_second_query() {
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

        // Connection must still be open: a second query on the same stream
        // gets a second response with its own ID.
        let query2 = build_query(0x5678, "www.test.local", 1);
        stream.write_all(&wrap_tcp(&query2)).await.unwrap();
        stream.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await.unwrap();
        assert_eq!(
            u16::from_be_bytes([resp_buf[0], resp_buf[1]]),
            0x5678,
            "second response must echo the second query ID"
        );
    }

    /// Phase 45 (Workstream D): service continues after an error response —
    /// a query for a missing name does not poison the connection.
    #[tokio::test]
    async fn test_tcp_connection_survives_error_response() {
        let zone = build_test_zone();
        let addr = start_test_server_with_zone(Some(zone), None).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        // Send first query for a name that does not exist in the zone.
        let query1 = build_query(0x1111, "missing.test.local", 1);
        stream.write_all(&wrap_tcp(&query1)).await.unwrap();

        // Read first response (NXDOMAIN or similar — must still be framed).
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await.unwrap();
        assert_eq!(
            u16::from_be_bytes([resp_buf[0], resp_buf[1]]),
            0x1111,
            "error response must echo the query ID"
        );

        // A second query on the same connection is still served.
        let query2 = build_query(0x2222, "www.test.local", 1);
        stream.write_all(&wrap_tcp(&query2)).await.unwrap();
        stream.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await.unwrap();
        assert_eq!(
            u16::from_be_bytes([resp_buf[0], resp_buf[1]]),
            0x2222,
            "connection must keep serving after an error response"
        );
        assert_eq!(
            u16::from_be_bytes([resp_buf[2], resp_buf[3]]) & 0x000F,
            0,
            "second query returns NOERROR"
        );
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
