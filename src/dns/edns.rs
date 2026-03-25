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

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone, Default)]
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

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct ClientSubnet {
    pub address: IpAddr,
    pub prefix_len: u8,
}

impl EdnsOptions {
    pub fn parse_from_query(query: &[u8], qd_end: usize) -> Option<Self> {
        if query.len() < qd_end + 11 {
            return None;
        }

        let opt_position = qd_end;

        let mut pos = opt_position;

        while pos + 10 <= query.len() {
            let name = query[pos];

            if name != 0 {
                break;
            }
            pos += 1;

            let qtype = u16::from_be_bytes([query[pos], query[pos + 1]]);
            pos += 2;

            if qtype != 41 {
                let rdlen = u16::from_be_bytes([query[pos], query[pos + 1]]);
                pos += 2;
                pos += rdlen as usize;
                continue;
            }

            let udp_payload = u16::from_be_bytes([query[pos], query[pos + 1]]);
            pos += 2;

            let extended_rcode_and_version = u16::from_be_bytes([query[pos], query[pos + 1]]);
            pos += 2;
            let extended_rcode = (extended_rcode_and_version >> 8) as u8;
            let version = (extended_rcode_and_version & 0xFF) as u8;

            let flags = u16::from_be_bytes([query[pos], query[pos + 1]]);
            pos += 2;

            let dnssec_ok = (flags & 0x8000) != 0;

            let rdlen = u16::from_be_bytes([query[pos], query[pos + 1]]);
            pos += 2;

            let mut client_subnet = None;
            let mut keytag = None;
            let mut cookie = None;
            let mut keepalive = None;
            let mut extended_dns_errors = Vec::new();
            let mut padding_requested = false;

            let mut rdata_pos = pos;
            while rdata_pos + 4 <= pos + rdlen as usize {
                let option_code = u16::from_be_bytes([query[rdata_pos], query[rdata_pos + 1]]);
                let option_len = u16::from_be_bytes([query[rdata_pos + 2], query[rdata_pos + 3]]);
                rdata_pos += 4;

                if option_code == EDNS_OPTION_CLIENT_SUBNET && option_len >= 4 {
                    let family = u16::from_be_bytes([query[rdata_pos], query[rdata_pos + 1]]);
                    let prefix_len = query[rdata_pos + 2];
                    let scope = query[rdata_pos + 3];

                    if scope == 0 && prefix_len > 0 {
                        let addr_bytes = prefix_len.div_ceil(8);
                        if rdata_pos + 4 + addr_bytes as usize <= pos + rdlen as usize {
                            let ip = if family == 1 {
                                let mut octets = [0u8; 4];
                                octets[..addr_bytes as usize].copy_from_slice(
                                    &query[rdata_pos + 4..rdata_pos + 4 + addr_bytes as usize],
                                );
                                IpAddr::from(octets)
                            } else if family == 2 {
                                let mut octets = [0u8; 16];
                                octets[..addr_bytes as usize].copy_from_slice(
                                    &query[rdata_pos + 4..rdata_pos + 4 + addr_bytes as usize],
                                );
                                IpAddr::from(octets)
                            } else {
                                IpAddr::from([0, 0, 0, 0])
                            };

                            client_subnet = Some(ClientSubnet {
                                address: ip,
                                prefix_len,
                            });
                        }
                    }
                    rdata_pos += option_len as usize;
                } else if option_code == EDNS_OPTION_KEYTAG && option_len >= 2 {
                    keytag = Some(u16::from_be_bytes([query[rdata_pos], query[rdata_pos + 1]]));
                    rdata_pos += option_len as usize;
                } else if option_code == EDNS_OPTION_COOKIE && option_len >= 8 {
                    let client_cookie_len = std::cmp::min(option_len as usize, 8);
                    let mut client_cookie = vec![0u8; client_cookie_len];
                    client_cookie.copy_from_slice(&query[rdata_pos..rdata_pos + client_cookie_len]);

                    let mut server_cookie = None;
                    if option_len as usize > 8 {
                        let server_cookie_len = (option_len as usize - 8).min(24);
                        let mut sc = vec![0u8; server_cookie_len];
                        sc.copy_from_slice(
                            &query[rdata_pos + 8..rdata_pos + 8 + server_cookie_len],
                        );
                        server_cookie = Some(sc);
                    }

                    cookie = Some(
                        Cookie::new(client_cookie)
                            .with_server_cookie(server_cookie.unwrap_or_default()),
                    );
                    rdata_pos += option_len as usize;
                } else if option_code == EDNS_OPTION_KEEPALIVE && option_len >= 2 {
                    let timeout = u16::from_be_bytes([query[rdata_pos], query[rdata_pos + 1]]);
                    keepalive = Some(timeout);
                    rdata_pos += option_len as usize;
                } else if option_code == EDNS_OPTION_EDE && option_len >= 2 {
                    if let Some(ede) = ExtendedDnsErrorOption::decode(
                        &query[rdata_pos..rdata_pos + option_len as usize],
                    ) {
                        extended_dns_errors.push(ede);
                    }
                    rdata_pos += option_len as usize;
                } else if option_code == EDNS_OPTION_PADDING {
                    padding_requested = true;
                    rdata_pos += option_len as usize;
                } else {
                    rdata_pos += option_len as usize;
                }
            }

            return Some(Self {
                udp_payload_size: if udp_payload >= 4096 {
                    udp_payload
                } else {
                    4096
                },
                extended_rcode,
                version,
                dnssec_ok,
                client_subnet,
                keytag,
                cookie,
                keepalive,
                extended_dns_errors,
                padding_requested,
            });
        }

        None
    }

    pub fn build_opt_record(udp_payload_size: u16, dnssec_ok: bool) -> Vec<u8> {
        let mut opt = Vec::new();

        let udp = if udp_payload_size >= 4096 {
            udp_payload_size
        } else {
            4096
        };
        opt.extend_from_slice(&udp.to_be_bytes());

        let mut flags = 0u16;
        if dnssec_ok {
            flags |= 0x8000;
        }
        opt.extend_from_slice(&flags.to_be_bytes());

        opt.extend_from_slice(&0u16.to_be_bytes());

        opt
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

pub fn parse_edns_options(query: &[u8]) -> Option<EdnsOptions> {
    if query.len() < 12 {
        return None;
    }

    let qdcount = u16::from_be_bytes([query[4], query[5]]);

    let mut pos = 12;
    for _ in 0..qdcount {
        while pos < query.len() {
            let len = query[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            pos += 1 + len;
        }
        pos += 4;
    }

    EdnsOptions::parse_from_query(query, pos)
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

pub fn build_bad_version_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }

    let id = u16::from_be_bytes([query[0], query[1]]);
    let mut response = Vec::with_capacity(28);

    response.extend_from_slice(&id.to_be_bytes());

    response.push(0x81);
    response.push(0x20);

    response.extend_from_slice(&[0x00, 0x01]);

    response.extend_from_slice(&[0x00, 0x00]);
    response.extend_from_slice(&[0x00, 0x00]);

    let opt_record = build_opt_record_bad_version();
    response.extend_from_slice(&opt_record);

    Some(response)
}

fn build_opt_record_bad_version() -> Vec<u8> {
    let mut opt = Vec::new();

    opt.push(0);
    opt.extend_from_slice(&41u16.to_be_bytes());
    opt.extend_from_slice(&11u16.to_be_bytes());

    opt.extend_from_slice(&4096u16.to_be_bytes());
    opt.extend_from_slice(&(0x20u16 | (EDNS_VERSION as u16)).to_be_bytes());
    opt.extend_from_slice(&0u16.to_be_bytes());

    opt.extend_from_slice(&0u16.to_be_bytes());

    opt
}

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
    pub fn from_settings(config: &crate::config::dns::EcsFilteringConfig) -> Self {
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
        let is_private = match subnet.address {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                octets[0] == 10
                    || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                    || (octets[0] == 192 && octets[1] == 168)
            }
            IpAddr::V6(ipv6) => {
                let segments = ipv6.segments();
                segments[0] & 0xfe00 == 0xfc00 || segments[0] & 0xffc0 == 0xfe80
            }
        };

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
                    let mask = !((1u32 << (32 - new_prefix)) - 1);
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
            block_size: block_size.max(32).min(256),
            generated_padding: Vec::new(),
        }
    }

    pub fn is_requested_in_query(edns: &EdnsOptions) -> bool {
        edns.padding_requested
    }

    pub fn generate_padding(&mut self, target_size: usize) -> Vec<u8> {
        use crate::dns::crypto_rng::random_bytes;

        let block_size = self.block_size;
        let blocks = target_size.div_ceil(block_size);
        let total_size = blocks * block_size;

        let padding = random_bytes(total_size);

        self.generated_padding = padding.clone();

        padding
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
