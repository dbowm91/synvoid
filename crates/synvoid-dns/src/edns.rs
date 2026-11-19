use std::net::IpAddr;

pub const EDNS_OPTION_COOKIE: u16 = 10;
pub const EDNS_OPTION_CLIENT_SUBNET: u16 = 8;
pub const EDNS_OPTION_KEYTAG: u16 = 0;
pub const EDNS_OPTION_KEEPALIVE: u16 = 11;
pub const EDNS_OPTION_EDE: u16 = 15;
pub const EDNS_OPTION_PADDING: u16 = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendedDnsError {
    OtherError = 0,
    UnsupportedDsDigestType = 1,
    StaleAnswer = 2,
    ForgedAnswer = 3,
    DnsKeyMissing = 4,
    RrsigsMissing = 5,
    ZoneNotAuthoritative = 6,
    ZoneSignedInvalid = 7,
    SignatureNotValid = 8,
    MismatchRcode = 9,
    NotSupported = 10,
    Rejected = 11,
    NoReachableAuthority = 12,
    NetworkError = 13,
    InvalidData = 14,
}

impl ExtendedDnsError {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::OtherError),
            1 => Some(Self::UnsupportedDsDigestType),
            2 => Some(Self::StaleAnswer),
            3 => Some(Self::ForgedAnswer),
            4 => Some(Self::DnsKeyMissing),
            5 => Some(Self::RrsigsMissing),
            6 => Some(Self::ZoneNotAuthoritative),
            7 => Some(Self::ZoneSignedInvalid),
            8 => Some(Self::SignatureNotValid),
            9 => Some(Self::MismatchRcode),
            10 => Some(Self::NotSupported),
            11 => Some(Self::Rejected),
            12 => Some(Self::NoReachableAuthority),
            13 => Some(Self::NetworkError),
            14 => Some(Self::InvalidData),
            _ => None,
        }
    }

    pub fn to_u16(&self) -> u16 {
        *self as u16
    }

    pub fn code(&self) -> u16 {
        *self as u16
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedDnsErrorOption {
    pub info_code: u16,
    pub extra_text: Option<String>,
}

impl ExtendedDnsErrorOption {
    pub fn new(info_code: ExtendedDnsError) -> Self {
        Self {
            info_code: info_code.to_u16(),
            extra_text: None,
        }
    }

    pub fn with_extra_text(mut self, text: String) -> Self {
        self.extra_text = Some(text);
        self
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.info_code.to_be_bytes());
        if let Some(ref extra) = self.extra_text {
            data.extend_from_slice(extra.as_bytes());
        }
        data
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        let info_code = u16::from_be_bytes([data[0], data[1]]);
        let extra_text = if data.len() > 2 {
            Some(String::from_utf8_lossy(&data[2..]).to_string())
        } else {
            None
        };
        Some(Self {
            info_code,
            extra_text,
        })
    }
}

/// Smallest UDP payload honored in either direction.
///
/// RFC 6891 §6.2.5: "Values lower than 512 MUST be treated as equal to 512".
pub const EDNS_MIN_UDP_PAYLOAD: u16 = 512;

/// Largest UDP payload this server is willing to emit.
///
/// A client may advertise up to 65535, but a 64 KiB datagram is fragmented and
/// gives a spoofed source a large amplification factor. 4096 covers the
/// largest response this server produces; anything larger is truncated
/// (`TC=1`) so the client retries over TCP.
pub const EDNS_MAX_UDP_PAYLOAD: u16 = 4096;

/// No extended RCODE: the header RCODE alone carries the result.
pub const EXTENDED_RCODE_NONE: u16 = 0;

/// BADVERS (RFC 6891 §6.1.3) as the full 12-bit extended RCODE.
///
/// The low 4 bits go in the message header (0), the upper 8 bits go in the OPT
/// TTL (1); this constant is the version-independent value, 16.
pub const EXTENDED_RCODE_BADVERS: u16 = 16;

/// BADCOOKIE (RFC 7873 §5.2.3) as the full 12-bit extended RCODE.
///
/// The low 4 bits (7) go in the message header and the upper 8 bits (1) in the
/// OPT TTL. The OPT record also carries a fresh COOKIE option.
pub const EXTENDED_RCODE_BADCOOKIE: u16 = 23;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EdnsOptions {
    pub udp_payload_size: u16,
    pub extended_rcode: u8,
    pub version: u8,
    pub dnssec_ok: bool,
    pub client_subnet: Option<ClientSubnet>,
    pub keytag: Option<u16>,
    pub cookie: Option<Cookie>,
    pub keepalive: Option<u16>,
    pub extended_dns_errors: Vec<ExtendedDnsErrorOption>,
    pub padding_requested: bool,
}

/// EDNS state discovered in a query's additional section.
///
/// The header counts are authoritative: an `ARCOUNT` of zero means the query
/// has no EDNS state even when OPT-shaped bytes trail the question.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryEdns {
    /// The first OPT record, when the query carried one.
    pub options: Option<EdnsOptions>,
    /// Number of OPT records seen. RFC 6891 §6.1.1 allows exactly one.
    pub opt_count: u16,
    /// True when an option body violated the framing it declared.
    ///
    /// A malformed option is a FORMERR (RFC 6891 §6.1.2): the query carried
    /// bytes the server cannot interpret, and silently ignoring them would
    /// answer a request the peer did not make. Parsing itself is bounded
    /// either way; this flag only records the verdict.
    pub malformed: bool,
}

impl QueryEdns {
    /// True when a second OPT record was present (a FORMERR).
    pub fn has_duplicate_opt(&self) -> bool {
        self.opt_count > 1
    }

    /// True when any OPT record in the packet was structurally malformed.
    pub fn is_malformed(&self) -> bool {
        self.malformed
    }
}

/// A bounded EDNS option parser rejected an option body.
///
/// Every variant means the bytes present disagree with the framing the packet
/// declares, so the query is a FORMERR rather than something to ignore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdnsOptionError {
    /// A CLIENT-SUBNET option violated RFC 7871 §6: unsupported family, a
    /// prefix longer than the family allows, or an address that is not
    /// present in the option body.
    InvalidClientSubnet,
    /// An option declared more bytes than the OPT record's RDLENGTH holds.
    OptionOverrun,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cookie {
    pub client_cookie: Vec<u8>,
    pub server_cookie: Option<Vec<u8>>,
}

impl Cookie {
    pub fn new(client_cookie: Vec<u8>) -> Self {
        Self {
            client_cookie,
            server_cookie: None,
        }
    }

    pub fn with_server_cookie(mut self, server_cookie: Vec<u8>) -> Self {
        self.server_cookie = Some(server_cookie);
        self
    }

    pub fn is_valid(&self) -> bool {
        self.client_cookie.len() >= 8
            && match &self.server_cookie {
                Some(sc) => sc.len() >= 8 && sc.len() <= 32,
                None => true,
            }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.client_cookie);
        if let Some(ref sc) = self.server_cookie {
            data.extend_from_slice(sc);
        }
        data
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSubnet {
    pub address: IpAddr,
    pub prefix_len: u8,
}

impl EdnsOptions {
    /// Build the parsed state from one OPT record's fixed header and RDATA.
    ///
    /// `udp_payload_size` is the CLASS field; it is clamped to
    /// `[EDNS_MIN_UDP_PAYLOAD, EDNS_MAX_UDP_PAYLOAD]` so a client that asks
    /// for less than 512 is never answered with more than 512, and a client
    /// that asks for 64 KiB is never answered with more than 4 KiB.
    ///
    /// `option_rdata` must already be bounded by the OPT record's RDLENGTH
    /// *and* the packet length: this function never sees a slice that reaches
    /// past the datagram. Every option is bounded again against that slice, so
    /// an option that declares more bytes than the record holds is reported as
    /// [`EdnsOptionError::OptionOverrun`] rather than read.
    fn from_opt_record(
        udp_payload_size: u16,
        ttl: u32,
        option_rdata: &[u8],
    ) -> Result<Self, EdnsOptionError> {
        let mut edns = Self {
            udp_payload_size: udp_payload_size.clamp(EDNS_MIN_UDP_PAYLOAD, EDNS_MAX_UDP_PAYLOAD),
            extended_rcode: (ttl >> 24) as u8,
            version: ((ttl >> 16) & 0xFF) as u8,
            dnssec_ok: (ttl as u16 & 0x8000) != 0,
            ..Self::default()
        };
        edns.parse_options(option_rdata)?;
        Ok(edns)
    }

    /// Decode the option RDATA of an OPT record.
    ///
    /// `rdata` is the `opt_end`-clamped option area. The loop only consumes an
    /// option when its 4-byte header and its whole body fit inside `rdata`; a
    /// declared length that runs past `opt_end` is an error, never a read past
    /// the buffer. A trailing run shorter than an option header is ignored
    /// (it cannot describe an option).
    fn parse_options(&mut self, rdata: &[u8]) -> Result<(), EdnsOptionError> {
        let mut pos = 0usize;
        loop {
            // Option header: CODE(2) + LENGTH(2).
            let header_end = match pos.checked_add(4) {
                Some(end) if end <= rdata.len() => end,
                _ => return Ok(()),
            };
            let code = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
            let len = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
            let body_start = header_end;
            let body_end = match body_start.checked_add(len) {
                Some(end) if end <= rdata.len() => end,
                // The option's declared body does not fit inside opt_end.
                _ => return Err(EdnsOptionError::OptionOverrun),
            };
            let data = &rdata[body_start..body_end];

            match code {
                EDNS_OPTION_CLIENT_SUBNET => {
                    self.parse_client_subnet(data)?;
                }
                EDNS_OPTION_KEYTAG => {
                    if let Some(first_two) = data.get(..2) {
                        self.keytag = Some(u16::from_be_bytes([first_two[0], first_two[1]]));
                    }
                }
                EDNS_OPTION_COOKIE => {
                    // RFC 7873 §5.1: an 8-byte client cookie, optionally
                    // followed by an 8..32-byte server cookie.
                    if let Some(client) = data.get(..8) {
                        let server_cookie = data
                            .get(8..)
                            .filter(|rest| !rest.is_empty())
                            .map(|rest| rest[..rest.len().min(24)].to_vec());
                        self.cookie = Some(
                            Cookie::new(client.to_vec())
                                .with_server_cookie(server_cookie.unwrap_or_default()),
                        );
                    }
                }
                EDNS_OPTION_KEEPALIVE => {
                    if let Some(first_two) = data.get(..2) {
                        self.keepalive = Some(u16::from_be_bytes([first_two[0], first_two[1]]));
                    }
                }
                EDNS_OPTION_EDE => {
                    if let Some(ede) = ExtendedDnsErrorOption::decode(data) {
                        self.extended_dns_errors.push(ede);
                    }
                }
                EDNS_OPTION_PADDING => self.padding_requested = true,
                _ => {}
            }

            // `body_end` is provably <= rdata.len(), so this cannot skip past
            // opt_end. The next iteration re-checks a full option header.
            pos = body_end;
        }
    }

    /// Parse a CLIENT-SUBNET option body (RFC 7871 §6).
    ///
    /// The declared address bytes must be present: a source prefix of 24 for
    /// IPv4 needs three address octets, and a body that stops short is a
    /// malformed option, not a shorter address. The octets are copied through
    /// `get_mut(..n)` so a prefix longer than the family allows cannot become
    /// a slice index.
    fn parse_client_subnet(&mut self, data: &[u8]) -> Result<(), EdnsOptionError> {
        let Some((family, prefix_len, scope)) = data
            .get(..4)
            .map(|fixed| (u16::from_be_bytes([fixed[0], fixed[1]]), fixed[2], fixed[3]))
        else {
            return Err(EdnsOptionError::InvalidClientSubnet);
        };

        // RFC 7871 §6: family 1 is IPv4 (32 bits), family 2 is IPv6 (128 bits).
        let family_bits: u8 = match family {
            1 => 32,
            2 => 128,
            _ => return Err(EdnsOptionError::InvalidClientSubnet),
        };
        if prefix_len > family_bits {
            return Err(EdnsOptionError::InvalidClientSubnet);
        }

        let address_bytes = usize::from(prefix_len).div_ceil(8);
        let Some(address) = data.get(4..).and_then(|rest| rest.get(..address_bytes)) else {
            return Err(EdnsOptionError::InvalidClientSubnet);
        };

        // A zero source prefix carries no address; it still parses (the
        // family/prefix checks above ran) but there is nothing to record.
        if scope != 0 || prefix_len == 0 {
            return Ok(());
        }

        match family {
            1 => {
                let mut octets = [0u8; 4];
                if let Some(slot) = octets.get_mut(..address_bytes) {
                    slot.copy_from_slice(address);
                    self.client_subnet = Some(ClientSubnet {
                        address: IpAddr::from(octets),
                        prefix_len,
                    });
                }
            }
            2 => {
                let mut octets = [0u8; 16];
                if let Some(slot) = octets.get_mut(..address_bytes) {
                    slot.copy_from_slice(address);
                    self.client_subnet = Some(ClientSubnet {
                        address: IpAddr::from(octets),
                        prefix_len,
                    });
                }
            }
            _ => return Err(EdnsOptionError::InvalidClientSubnet),
        }

        Ok(())
    }

    pub fn build_cookie_option(client_cookie: &[u8], server_cookie: &[u8]) -> Vec<u8> {
        let mut opt = Vec::new();

        opt.extend_from_slice(&EDNS_OPTION_COOKIE.to_be_bytes());

        let data_len = client_cookie.len() + server_cookie.len();
        opt.extend_from_slice(&(data_len as u16).to_be_bytes());

        opt.extend_from_slice(client_cookie);
        opt.extend_from_slice(server_cookie);

        opt
    }

    pub fn build_keepalive_option(timeout_secs: u16) -> Vec<u8> {
        let mut opt = Vec::new();
        opt.extend_from_slice(&EDNS_OPTION_KEEPALIVE.to_be_bytes());
        opt.extend_from_slice(&2u16.to_be_bytes());
        opt.extend_from_slice(&timeout_secs.to_be_bytes());
        opt
    }
}

/// Locate the first byte of the additional section.
///
/// For a standard query the answer and authority counts are zero, so this is
/// the byte after the question. For an UPDATE (or a malformed packet that
/// declares records there) the sections must be walked by their RDLENGTH
/// before the additional section starts.
///
/// Returns `None` when a record cannot be located in `query`; the caller then
/// has no EDNS state rather than a guessed offset.
pub fn additional_section_start(
    query: &[u8],
    after_question: usize,
    ancount: u16,
    nscount: u16,
) -> Option<usize> {
    let mut pos = after_question;
    for _ in 0..(u32::from(ancount) + u32::from(nscount)) {
        let (name_end, _) = skip_rr_owner(query, pos)?;
        if name_end + 10 > query.len() {
            return None;
        }
        let rdlen = u16::from_be_bytes([query[name_end + 8], query[name_end + 9]]) as usize;
        pos = name_end.checked_add(10 + rdlen)?;
        if pos > query.len() {
            return None;
        }
    }
    Some(pos)
}

/// Scan the additional section of `query` for an OPT record (RFC 6891).
///
/// `additional_start` must be the byte after the single question section and
/// `arcount` the header's additional count. Both come from the caller's
/// already-validated parse, so the walk never has to guess where the
/// additional section begins.
///
/// Returns the first OPT and the number of OPT records seen. A truncated
/// additional section, a non-root owner, or an overstated RDLENGTH yields the
/// records that are actually present instead of a read past the packet.
pub fn parse_query_edns(query: &[u8], additional_start: usize, arcount: u16) -> QueryEdns {
    let mut state = QueryEdns::default();
    if arcount == 0 || additional_start >= query.len() {
        return state;
    }

    let mut pos = additional_start;
    for _ in 0..arcount {
        // A whole OPT pseudo-RR needs at least 11 bytes: root owner (1) +
        // TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2). Without that guard
        // the fixed-header read below is one byte short.
        if pos.checked_add(11).is_none_or(|end| end > query.len()) {
            break;
        }

        let Some((name_end, is_root)) = skip_rr_owner(query, pos) else {
            break;
        };
        // Fixed RR header: TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2).
        if name_end + 10 > query.len() {
            break;
        }

        let rtype = u16::from_be_bytes([query[name_end], query[name_end + 1]]);
        let class = u16::from_be_bytes([query[name_end + 2], query[name_end + 3]]);
        let ttl = u32::from_be_bytes([
            query[name_end + 4],
            query[name_end + 5],
            query[name_end + 6],
            query[name_end + 7],
        ]);
        let rdlen = u16::from_be_bytes([query[name_end + 8], query[name_end + 9]]) as usize;

        let rdata_start = name_end + 10;
        // The attacker-declared RDLENGTH is clamped to the packet before the
        // option loop sees it. `opt_end` is the only end the option parser is
        // allowed to consider.
        let opt_end = rdata_start.saturating_add(rdlen).min(query.len());

        // An OPT RR must have the root owner (RFC 6891 §6.1.2). A type-41 RR
        // under any other name is not an OPT record and is ignored.
        if rtype == 41 && is_root {
            state.opt_count = state.opt_count.saturating_add(1);
            if state.options.is_none() {
                match EdnsOptions::from_opt_record(class, ttl, &query[rdata_start..opt_end]) {
                    Ok(options) => state.options = Some(options),
                    Err(_) => state.malformed = true,
                }
            }
        }

        if rdata_start.saturating_add(rdlen) > query.len() {
            // The remaining records cannot be located.
            break;
        }
        pos = opt_end;
    }

    state
}

/// Skip an RR owner name, returning the position after it and whether it was
/// the bare root label.
fn skip_rr_owner(buf: &[u8], start: usize) -> Option<(usize, bool)> {
    let mut pos = start;
    loop {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            return Some((pos + 1, pos == start));
        }
        if (len & 0xC0) == 0xC0 {
            if pos + 2 > buf.len() {
                return None;
            }
            return Some((pos + 2, false));
        }
        if len > 63 {
            return None;
        }
        let next = pos.checked_add(1 + len)?;
        if next > buf.len() {
            return None;
        }
        pos = next;
    }
}

pub const EDNS_VERSION: u8 = 0;

pub fn validate_edns_version(edns: &EdnsOptions) -> Result<(), EdnsVersionError> {
    if edns.version > EDNS_VERSION {
        return Err(EdnsVersionError::UnsupportedVersion(edns.version));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq)]
pub enum EdnsVersionError {
    UnsupportedVersion(u8),
}

impl std::fmt::Display for EdnsVersionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EdnsVersionError::UnsupportedVersion(v) => {
                write!(f, "Unsupported EDNS version: {}", v)
            }
        }
    }
}

impl std::error::Error for EdnsVersionError {}

#[derive(Debug, Clone)]
pub struct EcsFilterConfig {
    pub enabled: bool,
    pub prefix_v4: u8,
    pub prefix_v6: u8,
    pub allow_private_prefix: bool,
}

impl Default for EcsFilterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            prefix_v4: 24,
            prefix_v6: 48,
            allow_private_prefix: false,
        }
    }
}

impl EcsFilterConfig {
    /// Build from the DNS-owned runtime ECS values (Phase 126).
    pub fn from_runtime(config: &crate::runtime_config::EcsRuntimeConfig) -> Self {
        Self {
            enabled: config.enabled,
            prefix_v4: config.prefix_v4,
            prefix_v6: config.prefix_v6,
            allow_private_prefix: config.allow_private_prefix,
        }
    }
}

pub fn filter_ecs(edns: &mut EdnsOptions, config: &EcsFilterConfig) {
    if !config.enabled {
        return;
    }

    if let Some(ref mut subnet) = edns.client_subnet {
        let is_private = crate::net_policy::is_restricted_ip(&subnet.address);

        if is_private && !config.allow_private_prefix {
            edns.client_subnet = None;
            return;
        }

        let new_prefix = match subnet.address {
            IpAddr::V4(_) => config.prefix_v4,
            IpAddr::V6(_) => config.prefix_v6,
        };

        if new_prefix < subnet.prefix_len {
            subnet.prefix_len = new_prefix;
            match subnet.address {
                IpAddr::V4(ref mut ip) => {
                    let ip_val = u32::from_be_bytes(ip.octets());
                    let mask = crate::runtime_config::dns_ipv4_prefix_mask(new_prefix);
                    let masked = ip_val & mask;
                    *ip = std::net::Ipv4Addr::from(masked);
                }
                IpAddr::V6(ref mut ip) => {
                    let segments = ip.segments();
                    let full_bytes = new_prefix / 8;
                    let remaining_bits = new_prefix % 8;

                    let mut new_segments = [0u16; 8];
                    for (i, seg) in segments.iter().enumerate() {
                        if i < full_bytes as usize {
                            new_segments[i] = *seg;
                        } else if i == full_bytes as usize && remaining_bits > 0 {
                            new_segments[i] = *seg & !(0xFFFF >> remaining_bits);
                        }
                    }
                    *ip = std::net::Ipv6Addr::from(new_segments);
                }
            }
        }
    }
}

pub fn strip_ecs(edns: &mut EdnsOptions) {
    edns.client_subnet = None;
}

#[derive(Debug, Clone, Default)]
pub struct DnsPadding {
    pub block_size: usize,
    pub generated_padding: Vec<u8>,
}

impl DnsPadding {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_block_size(block_size: usize) -> Self {
        Self {
            block_size: block_size.clamp(32, 256),
            generated_padding: Vec::new(),
        }
    }

    pub fn is_requested_in_query(edns: &EdnsOptions) -> bool {
        edns.padding_requested
    }

    pub fn generate_padding(
        &mut self,
        target_size: usize,
    ) -> Result<Vec<u8>, crate::crypto_rng::CryptoRngError> {
        use crate::crypto_rng::random_bytes;

        let block_size = self.block_size;
        let blocks = target_size.div_ceil(block_size);
        let total_size = blocks * block_size;

        let padding = random_bytes(total_size)?;

        self.generated_padding = padding.clone();

        Ok(padding)
    }

    pub fn build_padding_option(&self, target_size: usize) -> Vec<u8> {
        let mut opt = Vec::new();

        let padding = if target_size <= self.generated_padding.len() {
            &self.generated_padding[..target_size]
        } else {
            &[]
        };

        opt.extend_from_slice(&EDNS_OPTION_PADDING.to_be_bytes());
        opt.extend_from_slice(&(padding.len() as u16).to_be_bytes());
        opt.extend_from_slice(padding);

        opt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A standard query for example.com/A with one OPT record appended.
    ///
    /// Returns the packet and the offset of the OPT owner byte.
    fn query_with_opt(payload: u16, version: u8, flags: u16, rdata: &[u8]) -> (Vec<u8>, usize) {
        let mut q = Vec::new();
        q.extend_from_slice(&0x1234u16.to_be_bytes());
        q.extend_from_slice(&0x0100u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT
        q.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        q.extend_from_slice(&[3, b'c', b'o', b'm']);
        q.push(0);
        q.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN

        let question_end = q.len();
        q.push(0); // OPT owner: root
        q.extend_from_slice(&41u16.to_be_bytes());
        q.extend_from_slice(&payload.to_be_bytes());
        let ttl = (u32::from(version) << 16) | u32::from(flags);
        q.extend_from_slice(&ttl.to_be_bytes());
        q.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        q.extend_from_slice(rdata);
        (q, question_end)
    }

    #[test]
    fn parses_payload_do_and_version_from_the_opt_fixed_header() {
        let (q, question_end) = query_with_opt(1232, 0, 0x8000, &[]);
        let state = parse_query_edns(&q, question_end, 1);

        assert_eq!(state.opt_count, 1);
        let edns = state.options.expect("one OPT must parse");
        assert_eq!(edns.udp_payload_size, 1232);
        assert!(edns.dnssec_ok);
        assert_eq!(edns.version, 0);
    }

    #[test]
    fn advertised_payload_is_clamped_to_five_twelve_and_four_kib() {
        let (q, question_end) = query_with_opt(100, 0, 0, &[]);
        let edns = parse_query_edns(&q, question_end, 1)
            .options
            .expect("one OPT must parse");
        assert_eq!(edns.udp_payload_size, 512);

        let (q, question_end) = query_with_opt(8000, 0, 0, &[]);
        let edns = parse_query_edns(&q, question_end, 1)
            .options
            .expect("one OPT must parse");
        assert_eq!(edns.udp_payload_size, 4096);
    }

    #[test]
    fn arcount_zero_is_not_edns_even_with_opt_shaped_bytes() {
        let (mut q, question_end) = query_with_opt(4096, 0, 0x8000, &[]);
        q[10..12].copy_from_slice(&0u16.to_be_bytes());

        let state = parse_query_edns(&q, question_end, 0);
        assert!(!state.has_duplicate_opt());
        assert!(state.options.is_none());
    }

    #[test]
    fn a_truncated_opt_fixed_header_yields_no_edns_instead_of_panicking() {
        let (q, question_end) = query_with_opt(4096, 0, 0, &[]);
        // Leave the root byte and the TYPE, but drop CLASS/TTL/RDLENGTH.
        let truncated = &q[..question_end + 3];
        let state = parse_query_edns(truncated, question_end, 1);
        assert!(state.options.is_none());
    }

    #[test]
    fn an_overstated_rdlength_is_clamped_and_still_parsed() {
        let (mut q, question_end) = query_with_opt(4096, 0, 0, &[]);
        // RDLENGTH is the two bytes immediately before the (empty) RDATA.
        let rdlength_at = q.len() - 2;
        q[rdlength_at..].copy_from_slice(&60_000u16.to_be_bytes());

        let state = parse_query_edns(&q, question_end, 1);
        assert_eq!(state.opt_count, 1);
        assert!(state.options.is_some());
    }

    #[test]
    fn an_ecs_prefix_wider_than_the_address_family_is_malformed() {
        // Option 8, length 36: family 1, prefix 255, scope 0, 32 address bytes.
        // The pre-phase-03 decoder copied 32 bytes into a 4-byte array and
        // panicked. A prefix above the family's width is now a FORMERR rather
        // than a silently ignored option: the peer declared an address this
        // server cannot interpret.
        let mut rdata = vec![0, EDNS_OPTION_CLIENT_SUBNET as u8, 0, 36];
        rdata.extend_from_slice(&1u16.to_be_bytes());
        rdata.push(255);
        rdata.push(0);
        rdata.extend_from_slice(&[0xFF; 32]);

        let (q, question_end) = query_with_opt(4096, 0, 0, &rdata);
        let state = parse_query_edns(&q, question_end, 1);
        assert!(state.is_malformed());
        assert!(
            state
                .options
                .as_ref()
                .and_then(|edns| edns.client_subnet.as_ref())
                .is_none(),
            "a rejected ECS option must not produce a client subnet"
        );
    }

    #[test]
    fn an_ecs_family_that_is_neither_ipv4_nor_ipv6_is_malformed() {
        let mut rdata = vec![0, EDNS_OPTION_CLIENT_SUBNET as u8, 0, 8];
        rdata.extend_from_slice(&3u16.to_be_bytes()); // family 3 does not exist
        rdata.push(8);
        rdata.push(0);
        rdata.extend_from_slice(&[10]);

        let (q, question_end) = query_with_opt(4096, 0, 0, &rdata);
        assert!(parse_query_edns(&q, question_end, 1).is_malformed());
    }

    #[test]
    fn an_ecs_address_shorter_than_its_prefix_is_malformed() {
        // Family 1, prefix 24 needs three address octets; supply two.
        let mut rdata = vec![0, EDNS_OPTION_CLIENT_SUBNET as u8, 0, 6];
        rdata.extend_from_slice(&1u16.to_be_bytes());
        rdata.push(24);
        rdata.push(0);
        rdata.extend_from_slice(&[10, 1]);

        let (q, question_end) = query_with_opt(4096, 0, 0, &rdata);
        assert!(parse_query_edns(&q, question_end, 1).is_malformed());
    }

    #[test]
    fn an_option_body_past_opt_end_is_malformed_and_reads_nothing() {
        // One option header claims 64 bytes of body; the packet holds two.
        let rdata = vec![0, EDNS_OPTION_COOKIE as u8, 0, 64, 0xAA, 0xBB];
        let (q, question_end) = query_with_opt(4096, 0, 0, &rdata);

        let state = parse_query_edns(&q, question_end, 1);
        assert!(state.is_malformed());
        assert!(
            state
                .options
                .as_ref()
                .and_then(|edns| edns.cookie.as_ref())
                .is_none(),
            "an option whose body overruns opt_end must not be stored"
        );
    }

    #[test]
    fn a_two_option_opt_parses_both_within_the_record() {
        // ECS family 1, prefix 24, 198.51.100.0 → option length 7.
        let mut rdata = vec![0, EDNS_OPTION_CLIENT_SUBNET as u8, 0, 7];
        rdata.extend_from_slice(&1u16.to_be_bytes());
        rdata.push(24);
        rdata.push(0);
        rdata.extend_from_slice(&[198, 51, 100]);
        // Cookie: 8-byte client cookie, no server cookie.
        rdata.extend_from_slice(&EDNS_OPTION_COOKIE.to_be_bytes());
        rdata.extend_from_slice(&8u16.to_be_bytes());
        rdata.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

        let (q, question_end) = query_with_opt(4096, 0, 0, &rdata);
        let edns = parse_query_edns(&q, question_end, 1)
            .options
            .expect("the two options must parse");
        assert!(!parse_query_edns(&q, question_end, 1).is_malformed());
        let subnet = edns.client_subnet.expect("ECS must parse");
        assert_eq!(subnet.prefix_len, 24);
        assert_eq!(subnet.address, "198.51.100.0".parse::<IpAddr>().unwrap());
        assert_eq!(
            edns.cookie.expect("cookie must parse").client_cookie,
            vec![1, 2, 3, 4, 5, 6, 7, 8]
        );
    }

    /// The exact 30-byte packet from the capability audit (D3): a one-label
    /// question plus an OPT fixed header whose RDLENGTH claims 65535 bytes.
    ///
    /// Before phase 03 the option loop trusted that RDLENGTH and read
    /// `query[30]` with `len == 30`, unwinding the UDP listener task.
    #[test]
    fn the_audit_thirty_byte_packet_is_bounded_and_does_not_panic() {
        let mut q = Vec::new();
        q.extend_from_slice(&0x1234u16.to_be_bytes());
        q.extend_from_slice(&0x0100u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT
        q.extend_from_slice(&[1, b'a', 0]); // question name "a."
        q.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        assert_eq!(q.len(), 19);
        q.push(0); // OPT owner root
        q.extend_from_slice(&41u16.to_be_bytes());
        q.extend_from_slice(&4096u16.to_be_bytes());
        q.extend_from_slice(&0u32.to_be_bytes());
        q.extend_from_slice(&0xFFFFu16.to_be_bytes()); // lying RDLENGTH
        assert_eq!(q.len(), 30, "the audit packet is exactly 30 bytes");

        let state = parse_query_edns(&q, 19, 1);
        assert_eq!(state.opt_count, 1);
        // RDLENGTH is clamped to the packet, so the (absent) option area is
        // empty. The bounded parser reports no options, not a panic.
        assert!(state
            .options
            .as_ref()
            .is_some_and(|edns| edns.client_subnet.is_none() && edns.cookie.is_none()));
    }

    /// The 40-byte off-by-one packet (D15): the OPT record starts 10 bytes
    /// before the end, one byte short of its 11-byte fixed header.
    ///
    /// The old loop guard admitted it (`pos + 10 <= len`) and then read the
    /// last RDLENGTH byte at index 40 of a 40-byte packet.
    #[test]
    fn the_forty_byte_off_by_one_packet_is_bounded_and_does_not_panic() {
        let mut q = Vec::new();
        q.extend_from_slice(&0x1234u16.to_be_bytes());
        q.extend_from_slice(&0x0100u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT
        q.push(12u8); // 12-byte label
        q.extend_from_slice(b"aaaaaaaaaaaa");
        q.push(0);
        q.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        assert_eq!(q.len(), 30);
        q.push(0); // OPT owner root
        q.extend_from_slice(&41u16.to_be_bytes());
        q.extend_from_slice(&4096u16.to_be_bytes());
        q.extend_from_slice(&0u32.to_be_bytes());
        q.push(0); // first RDLENGTH byte only
        assert_eq!(q.len(), 40, "the D15 packet is exactly 40 bytes");

        let state = parse_query_edns(&q, 30, 1);
        assert_eq!(state.opt_count, 0, "an incomplete OPT is not EDNS state");
        assert!(state.options.is_none());
        assert!(!state.is_malformed(), "the option parser was never reached");
    }

    #[test]
    fn an_unlocatable_answer_section_means_no_edns() {
        let (mut q, after_question) = query_with_opt(4096, 0, 0, &[]);
        // Claim one answer RR whose RDLENGTH runs past the packet.
        q[6..8].copy_from_slice(&1u16.to_be_bytes());
        let rdlength_at = q.len() - 2;
        q[rdlength_at..].copy_from_slice(&60_000u16.to_be_bytes());
        assert_eq!(
            additional_section_start(&q, after_question, 1, 0),
            None,
            "an overstated answer RDLENGTH must not locate an additional section"
        );
    }
}
