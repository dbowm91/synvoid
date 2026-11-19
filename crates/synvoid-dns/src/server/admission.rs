//! One admission gate for every DNS transport.
//!
//! Before phase 03 the packet checks were copied into the UDP and TCP loops and
//! the encrypted listeners (DoT/DoH/DoQ) called `DnsServer::handle_query*`
//! directly, so switching port bypassed the query validator, the DNS firewall,
//! and the per-IP rate limiter (audit D12b). This module makes the ordered
//! decision once and gives the listeners a value they can only obtain by
//! asking for it.
//!
//! # Order
//!
//! Cheapest first, and identical on every transport:
//!
//! 1. size bound (the configured limits runtime)
//! 2. 12-byte header (a shorter packet cannot be answered)
//! 3. `QR=1` → **drop**, never answer (D14)
//! 4. opcode: QUERY/NOTIFY/UPDATE; anything else NOTIMP
//! 5. QDCOUNT: 0 FORMERR, more than 1 NOTIMP
//! 6. question structure and declared-record framing → FORMERR
//! 7. QCLASS (IN only) → NOTIMP
//! 8. EDNS envelope: duplicate OPT/malformed options FORMERR, version BADVERS
//! 9. firewall → REFUSED
//! 10. per-IP rate limit → REFUSED
//! 11. [`Admission::Allow`]
//!
//! The firewall deliberately runs before the cache lookup (the listener never
//! reaches one on a refusal) and after EDNS: a packet the server cannot
//! interpret is a protocol error regardless of policy.
//!
//! # Why a token type
//!
//! [`Admission::Allow`] carries an [`Admitted`] value whose `_permit` field is
//! a private zero-sized type with no constructor outside this module. The
//! dispatch entry ([`DnsServer::serve_admitted`]) accepts only `&Admitted`, so
//! a listener cannot reach the cache or the handler without first calling
//! [`admit`]: there is no public way to build the argument. This is stronger
//! than a `debug_assert` (which a release build drops) and needs no `cfg(test)`
//! counter to notice a bypass.

use std::net::IpAddr;
use std::sync::Arc;

use crate::cache::TransportClass;
use crate::firewall::DnsFirewallAction;
use crate::parsed_query::ParsedDnsQuery;
use crate::query_coalesce::CoalesceResult;
use crate::wire;

use super::{DnsServer, QueryContext};

/// The transport a packet arrived on.
///
/// Kept distinct from [`TransportClass`] because the class is a *response
/// budget*: a UDP query's class depends on its own EDNS OPT record, which
/// admission only knows after parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Udp,
    Tcp,
    Https,
    Quic,
}

impl TransportKind {
    /// The cache namespace / response budget for this transport and query.
    pub fn response_class(self, parsed: &ParsedDnsQuery<'_>) -> TransportClass {
        match self {
            // The query's own OPT CLASS is the client's advertised payload;
            // ARCOUNT=0 means legacy 512-byte UDP even if OPT-shaped bytes
            // trail the question.
            TransportKind::Udp => match parsed.edns.as_ref() {
                Some(edns) => TransportClass::UdpEdns(edns.udp_payload_size),
                None => TransportClass::Udp512,
            },
            TransportKind::Tcp => TransportClass::Tcp,
            TransportKind::Https => TransportClass::Http,
            TransportKind::Quic => TransportClass::Quic,
        }
    }
}

/// A query that passed admission.
///
/// The private `_permit` field is the admission token: see the module docs.
pub struct Admitted<'a> {
    parsed: ParsedDnsQuery<'a>,
    transport: TransportClass,
    _permit: AdmissionPermit,
}

impl<'a> Admitted<'a> {
    pub fn parsed(&self) -> &ParsedDnsQuery<'a> {
        &self.parsed
    }

    pub fn transport(&self) -> TransportClass {
        self.transport
    }
}

#[derive(Debug, Clone, Copy)]
struct AdmissionPermit;

/// The result of one admission decision.
pub enum Admission<'a> {
    /// Serve this query. The value cannot be constructed outside this module.
    Allow(Admitted<'a>),
    /// Send exactly these bytes as the DNS response.
    Reply(Vec<u8>),
    /// Send nothing at all.
    Drop,
}

/// Decide what to do with one packet.
///
/// `query` may be any bytes the listener received; every step is bounded and
/// this function never panics on hostile input. `client_ip` is the transport's
/// peer address, used by the firewall and the rate limiter exactly as the UDP
/// and TCP loops used it before this gate existed.
pub fn admit<'a>(
    query: &'a [u8],
    client_ip: IpAddr,
    transport: TransportKind,
    ctx: &QueryContext<'_>,
) -> Admission<'a> {
    // 1. Size bound. `ctx.connection_limits` is the constructed limits
    //    runtime (`LimitsRuntimeConfig`): the same values that size the TCP
    //    framing and the UDP receive buffer. A packet larger than the
    //    configured maximum is refused before any parse.
    if let Some(limits) = ctx.connection_limits {
        if limits.validate_query_size(query.len()).is_err() {
            return reply(query, wire::RCODE_REFUSED);
        }
    }

    // 2. A DNS header is 12 bytes. There is nothing to answer and no ID to
    //    echo, so a shorter packet is dropped rather than guessed at.
    if query.len() < 12 {
        return drop_with("short_header");
    }

    let raw_flags = u16::from_be_bytes([query[2], query[3]]);

    // 3. A response must never be answered (D14). Two servers fed each
    //    other's responses would otherwise loop, and a spoofed source turns
    //    the server into a small reflector.
    if raw_flags & 0x8000 != 0 {
        return drop_with("qr_set");
    }

    let opcode = ((raw_flags & 0x7800) >> 11) as u8;
    // 4. Only the three query opcodes are served; anything else (STATUS,
    //    IQUERY, unassigned) is NOTIMP rather than silently treated as QUERY.
    if !matches!(
        opcode,
        wire::OPCODE_QUERY | wire::OPCODE_NOTIFY | wire::OPCODE_UPDATE
    ) {
        return reply(query, wire::RCODE_NOTIMP);
    }

    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    // 5. A query with no question has nothing to answer; multiple questions
    //    are not supported (NOTIMP, matching the pre-existing policy).
    if qdcount == 0 {
        return reply(query, wire::RCODE_FORMERR);
    }
    if qdcount > 1 {
        return reply(query, wire::RCODE_NOTIMP);
    }

    // 6. Canonical parse plus the configured structural bounds. The validator
    //    re-walks the question intentionally (defense in depth); it also
    //    rejects a packet whose declared records do not fit, which is what
    //    makes a lying RDLENGTH a FORMERR instead of a truncated parse.
    let parsed = match ParsedDnsQuery::parse(query) {
        Ok(parsed) => parsed,
        Err(_) => return reply(query, wire::RCODE_FORMERR),
    };

    if let Some(validator) = ctx.query_validator {
        if validator.validate_request_structure(query).is_err() {
            return reply(query, wire::RCODE_FORMERR);
        }
    } else if !crate::parsed_query::declared_records_well_formed(query) {
        return reply(query, wire::RCODE_FORMERR);
    }

    // The canonical parser does not reject the reserved QTYPE 0; the validator
    // normally does. Keep the rejection when no validator is configured.
    if parsed.qtype == 0 {
        return reply(query, wire::RCODE_FORMERR);
    }

    // 7. IN only. ANY-class queries are not served (the pre-existing policy).
    if parsed.qclass != 1 {
        return reply(query, wire::RCODE_NOTIMP);
    }

    // 8. EDNS envelope. BADVERS must carry the client's OPT back, so it is
    //    built through the same encoder the handler uses.
    if parsed.duplicate_opt || parsed.malformed_edns {
        return reply(query, wire::RCODE_FORMERR);
    }
    if let Some(edns) = parsed.edns.as_ref() {
        if edns.version != crate::edns::EDNS_VERSION {
            return match DnsServer::build_edns_error_response(
                &parsed,
                0,
                crate::edns::EXTENDED_RCODE_BADVERS,
            ) {
                Some(response) => Admission::Reply(response.as_ref().clone()),
                None => Admission::Drop,
            };
        }
    }

    // 9. Firewall. Until phase 03 this ran only on UDP/TCP; a client that
    //    switched to an encrypted port bypassed every rule.
    if let Some(firewall) = ctx.firewall {
        let firewall = firewall.read();
        match firewall.evaluate_query(&parsed, client_ip, &parsed.qname) {
            Ok(decision) => {
                if decision.action == DnsFirewallAction::Block {
                    tracing::warn!(
                        transport = ?transport,
                        client = %client_ip,
                        qname = %parsed.qname,
                        rule = %decision.rule_id,
                        "DNS query blocked by firewall"
                    );
                    return reply(query, wire::RCODE_REFUSED);
                }
            }
            // An evaluation failure must not become an allow-or-block
            // accident. The firewall's own rule evaluation is fail-closed for
            // restrictive rules; an engine error is logged and treated as no
            // match, which is the pre-existing behavior.
            Err(error) => {
                tracing::warn!(
                    transport = ?transport,
                    client = %client_ip,
                    "DNS firewall evaluation error: {}",
                    error
                );
            }
        }
    }

    // 10. Per-IP rate limit. The same REFUSED on every transport means a
    //     client cannot escape the limit by switching ports.
    if let Some(rate_limiter) = ctx.rate_limiter {
        if rate_limiter.check_ip(client_ip).is_err() {
            tracing::debug!(
                transport = ?transport,
                client = %client_ip,
                "DNS query rate limited"
            );
            return reply(query, wire::RCODE_REFUSED);
        }
    }

    // 11. Admitted.
    Admission::Allow(Admitted {
        transport: transport.response_class(&parsed),
        parsed,
        _permit: AdmissionPermit,
    })
}

/// Build an error response, degrading to [`Admission::Drop`] when the packet
/// is too short to echo a header at all.
fn reply(query: &[u8], rcode: u8) -> Admission<'_> {
    match wire::build_error_response(query, rcode) {
        Some(response) => Admission::Reply(response),
        None => Admission::Drop,
    }
}

fn drop_with(reason: &'static str) -> Admission<'static> {
    metrics::counter!("synvoid.dns.admission.dropped", "reason" => reason).increment(1);
    Admission::Drop
}

impl DnsServer {
    /// Serve one query that passed [`admit`].
    ///
    /// This is the only dispatch entry a listener may use. It owns the
    /// coalescing and cache decisions so all five transports behave
    /// identically; a listener keeps framing, admission, and the response
    /// write.
    pub async fn serve_admitted(
        ctx: &QueryContext<'_>,
        admitted: &Admitted<'_>,
        query: &[u8],
        client_ip: Option<IpAddr>,
    ) -> Option<Arc<Vec<u8>>> {
        let parsed = admitted.parsed();
        let transport_class = admitted.transport();

        if crate::query_coalesce::should_skip_coalescing(parsed.qtype, parsed.flags.opcode) {
            return Self::dispatch_admitted(ctx, parsed, query, client_ip, transport_class);
        }

        let Some(coalescer) = ctx.query_coalescer else {
            return Self::dispatch_admitted(ctx, parsed, query, client_ip, transport_class);
        };

        let key = match crate::query_coalesce::QueryKey::from_parsed(
            parsed,
            client_ip,
            query,
            Some(transport_class),
        ) {
            Some(key) => key,
            None => return Self::dispatch_admitted(ctx, parsed, query, client_ip, transport_class),
        };

        // `get_or_wait_for` restores this waiter's message ID and question case
        // and refuses to hand over a packet answering a different question:
        // a shared body belongs to the owner's ID and question only.
        match coalescer.get_or_wait_for(key.clone(), query).await {
            Some(CoalesceResult::Response(response)) => Some(response),
            Some(CoalesceResult::QuestionMismatch) => {
                // The in-flight owner answered a different question. Answer
                // this client instead of delivering a mismatched packet.
                Self::dispatch_admitted(ctx, parsed, query, client_ip, transport_class)
            }
            Some(CoalesceResult::NewQuery(_tx)) => {
                let response =
                    Self::dispatch_admitted(ctx, parsed, query, client_ip, transport_class);
                match response {
                    Some(ref bytes) => coalescer.broadcast_response(key.clone(), bytes.clone()),
                    None => coalescer.cancel_in_flight(&key),
                }
                response
            }
            // Lagged / Timeout: this caller owns the answer.
            _ => Self::dispatch_admitted(ctx, parsed, query, client_ip, transport_class),
        }
    }

    fn dispatch_admitted(
        ctx: &QueryContext<'_>,
        parsed: &ParsedDnsQuery<'_>,
        query: &[u8],
        client_ip: Option<IpAddr>,
        transport_class: TransportClass,
    ) -> Option<Arc<Vec<u8>>> {
        match ctx.cache {
            Some(cache) => Self::handle_parsed_query_with_cache(
                ctx,
                parsed,
                query,
                cache,
                transport_class,
                client_ip,
            ),
            None => Self::handle_parsed_query(ctx, parsed, query, client_ip, transport_class),
        }
    }
}
