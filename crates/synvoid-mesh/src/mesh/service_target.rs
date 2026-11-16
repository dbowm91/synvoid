//! Mesh HTTP service-identity contract (mesh multi-upstream forwarding).
//!
//! A mesh HTTP request carries an explicit, typed service ID ahead of the
//! HTTP/1.x request bytes. The service ID is the origin's
//! `[tunnel.mesh.local_upstreams.<service_id>]` key. It is never inferred from
//! the request `Host`, and local listener identity never appears here.
//!
//! Wire format (version 2, the current encoder output):
//!
//! ```text
//! +--------+---------+--------+--------+--------------+------------+--------+
//! | magic  | version | flags  | len    | service_id   | meta_len   | meta   |
//! | 4 B    | 1 B     | 1 B    | 2 B BE | len bytes    | 2 B BE     | TLV    |
//! +--------+---------+--------+--------+--------------+------------+--------+
//! ```
//!
//! Version 1 carries only `magic + version + flags + len + service_id` and is
//! still accepted from legacy peers. Version 2 always carries the 2-byte
//! `meta_len`; `flags` bit 0 advertises that the metadata block is present.
//!
//! The metadata block is a sequence of `{type: u8, len: u8, value}` entries:
//!
//! - `0x01` client address: a family byte (`4` or `6`) followed by 4 or 16
//!   address bytes;
//! - `0x02` client protocol: `0` for `http`, `1` for `https`.
//!
//! Both entries are mandatory when bit 0 is set. The metadata is authored by
//! the authenticated edge from its socket peer; it is the only source of client
//! identity at the origin, and the origin never merges it with a client header.
//!
//! The magic starts with `0x1f`, which cannot begin a length-prefixed mesh
//! control message: the length prefix is a `u32` big-endian bounded by
//! `MAX_MESSAGE_SIZE` (10 MiB), so its first byte is always `0x00`. It also
//! cannot begin an HTTP request line, because no HTTP method starts with
//! `0x1f`. Peers that do not send a preface keep the legacy `Host`-derived
//! service key.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// First bytes of the service-target preface.
pub const SERVICE_PREFACE_MAGIC: [u8; 4] = [0x1f, b'M', b'S', b'V'];

/// Current wire version of the service-target preface.
pub const SERVICE_PREFACE_VERSION: u8 = 2;

/// Legacy version accepted from peers that predate authenticated metadata.
pub const SERVICE_PREFACE_VERSION_LEGACY: u8 = 1;

/// `flags` bit 0: the preface carries the client-metadata block.
pub const SERVICE_PREFACE_FLAG_CLIENT_METADATA: u8 = 0x01;

/// Maximum accepted service-ID length in bytes.
pub const MAX_SERVICE_ID_BYTES: usize = 255;

/// Length of the fixed preface header (magic + version + flags + length).
pub const SERVICE_PREFACE_HEADER_BYTES: usize = 8;

/// Maximum accepted metadata block length in bytes.
pub const MAX_SERVICE_METADATA_BYTES: usize = 64;

/// Metadata TLV type: client address (family byte + address bytes).
pub const SERVICE_METADATA_TYPE_CLIENT_IP: u8 = 0x01;

/// Metadata TLV type: client protocol (`0` = http, `1` = https).
pub const SERVICE_METADATA_TYPE_CLIENT_PROTOCOL: u8 = 0x02;

/// Address family byte for an IPv4 metadata address.
const ADDRESS_FAMILY_IPV4: u8 = 4;

/// Address family byte for an IPv6 metadata address.
const ADDRESS_FAMILY_IPV6: u8 = 6;

/// Protocol byte for `http`.
const PROTOCOL_HTTP: u8 = 0;

/// Protocol byte for `https`.
const PROTOCOL_HTTPS: u8 = 1;

/// Authenticated client identity reported by the edge in the preface.
///
/// The edge fills this from the socket peer of the accepted connection. It
/// never reads `X-Forwarded-For` or any other client header to populate it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientMetadata {
    /// Real client address as observed by the edge.
    pub client_ip: IpAddr,
    /// Protocol the client used towards the edge.
    pub proto: ClientProtocol,
}

/// Protocol the client used towards the edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientProtocol {
    /// Plain HTTP.
    Http,
    /// TLS-terminated HTTPS.
    Https,
}

impl ClientProtocol {
    /// Lower-case protocol token used in `X-Forwarded-Proto`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    fn to_metadata_byte(self) -> u8 {
        match self {
            Self::Http => PROTOCOL_HTTP,
            Self::Https => PROTOCOL_HTTPS,
        }
    }

    fn from_metadata_byte(byte: u8) -> Option<Self> {
        match byte {
            PROTOCOL_HTTP => Some(Self::Http),
            PROTOCOL_HTTPS => Some(Self::Https),
            _ => None,
        }
    }
}

/// Validation and decoding failures for the service-target contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceTargetError {
    /// The service ID was empty.
    EmptyServiceId,
    /// The service ID exceeded [`MAX_SERVICE_ID_BYTES`].
    ServiceIdTooLong { len: usize },
    /// The service ID contained an ASCII control character.
    ControlCharacter { index: usize },
    /// The stream did not start with [`SERVICE_PREFACE_MAGIC`].
    InvalidMagic,
    /// The preface advertised an unsupported version.
    UnsupportedVersion(u8),
    /// The preface advertised reserved flags that are not understood.
    UnsupportedFlags(u8),
    /// The preface or service ID was truncated.
    Truncated,
    /// The metadata block exceeded [`MAX_SERVICE_METADATA_BYTES`].
    MetadataTooLong { len: usize },
    /// A TLV entry used a type this version does not define.
    UnknownMetadataField(u8),
    /// A TLV entry type appeared more than once.
    DuplicateMetadataField(u8),
    /// A TLV entry had an invalid length or value.
    InvalidMetadataValue(&'static str),
}

impl std::fmt::Display for ServiceTargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyServiceId => write!(f, "mesh service ID must not be empty"),
            Self::ServiceIdTooLong { len } => write!(
                f,
                "mesh service ID is {} bytes, maximum is {}",
                len, MAX_SERVICE_ID_BYTES
            ),
            Self::ControlCharacter { index } => {
                write!(
                    f,
                    "mesh service ID contains a control character at {}",
                    index
                )
            }
            Self::InvalidMagic => write!(f, "mesh service preface magic mismatch"),
            Self::UnsupportedVersion(v) => {
                write!(f, "unsupported mesh service preface version {}", v)
            }
            Self::UnsupportedFlags(flags) => {
                write!(f, "unsupported mesh service preface flags {:#04x}", flags)
            }
            Self::Truncated => write!(f, "truncated mesh service preface"),
            Self::MetadataTooLong { len } => write!(
                f,
                "mesh service metadata is {} bytes, maximum is {}",
                len, MAX_SERVICE_METADATA_BYTES
            ),
            Self::UnknownMetadataField(field) => {
                write!(f, "unknown mesh service metadata field {:#04x}", field)
            }
            Self::DuplicateMetadataField(field) => {
                write!(f, "duplicate mesh service metadata field {:#04x}", field)
            }
            Self::InvalidMetadataValue(reason) => {
                write!(f, "invalid mesh service metadata: {}", reason)
            }
        }
    }
}

impl std::error::Error for ServiceTargetError {}

/// Validate an explicit mesh service ID.
///
/// Rules (Phase 01):
/// - non-empty;
/// - at most [`MAX_SERVICE_ID_BYTES`] bytes;
/// - no ASCII control characters;
/// - `http://host:port` stays valid, because it is the compatibility form of
///   the original domain-based model.
pub fn validate_service_id(service_id: &str) -> Result<(), ServiceTargetError> {
    if service_id.is_empty() {
        return Err(ServiceTargetError::EmptyServiceId);
    }
    if service_id.len() > MAX_SERVICE_ID_BYTES {
        return Err(ServiceTargetError::ServiceIdTooLong {
            len: service_id.len(),
        });
    }
    for (index, byte) in service_id.bytes().enumerate() {
        if byte < 0x20 || byte == 0x7f {
            return Err(ServiceTargetError::ControlCharacter { index });
        }
    }
    Ok(())
}

/// Returns true when `first_byte` can begin a service-target preface.
///
/// The byte is intentionally distinct from every HTTP method initial and from
/// a mesh control-message length prefix (always `0x00`).
pub fn is_service_preface_start(first_byte: u8) -> bool {
    first_byte == SERVICE_PREFACE_MAGIC[0]
}

/// Encode the typed service-target preface for `service_id`.
///
/// Always emits version 2. `flags` bit 0 is set exactly when `meta` is present;
/// the `meta_len` field is emitted in both cases so the layout is fixed.
pub fn encode_service_preface(
    service_id: &str,
    meta: Option<&ClientMetadata>,
) -> Result<Vec<u8>, ServiceTargetError> {
    validate_service_id(service_id)?;
    let metadata = match meta {
        Some(meta) => encode_metadata(meta)?,
        None => Vec::new(),
    };
    let flags = if meta.is_some() {
        SERVICE_PREFACE_FLAG_CLIENT_METADATA
    } else {
        0
    };

    let mut out =
        Vec::with_capacity(SERVICE_PREFACE_HEADER_BYTES + service_id.len() + 2 + metadata.len());
    out.extend_from_slice(&SERVICE_PREFACE_MAGIC);
    out.push(SERVICE_PREFACE_VERSION);
    out.push(flags);
    out.extend_from_slice(&(service_id.len() as u16).to_be_bytes());
    out.extend_from_slice(service_id.as_bytes());
    out.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    out.extend_from_slice(&metadata);
    Ok(out)
}

/// Decode a complete service-target preface from `bytes`.
///
/// Returns the service ID, the authenticated client metadata (version 2 only)
/// and the number of bytes consumed. Only a complete preface decodes; callers
/// reading from a stream must first accumulate the fixed header plus the
/// advertised lengths.
///
/// Version 1 prefaces decode with `None` metadata so legacy peers keep working
/// unchanged.
pub fn decode_service_preface(
    bytes: &[u8],
) -> Result<(String, Option<ClientMetadata>, usize), ServiceTargetError> {
    if bytes.len() < SERVICE_PREFACE_HEADER_BYTES {
        return Err(ServiceTargetError::Truncated);
    }
    if bytes[..4] != SERVICE_PREFACE_MAGIC {
        return Err(ServiceTargetError::InvalidMagic);
    }
    let version = bytes[4];
    let flags = bytes[5];
    match version {
        SERVICE_PREFACE_VERSION_LEGACY => {
            if flags != 0 {
                return Err(ServiceTargetError::UnsupportedFlags(flags));
            }
        }
        SERVICE_PREFACE_VERSION => {
            if flags & !SERVICE_PREFACE_FLAG_CLIENT_METADATA != 0 {
                return Err(ServiceTargetError::UnsupportedFlags(flags));
            }
        }
        other => return Err(ServiceTargetError::UnsupportedVersion(other)),
    }

    let len = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
    if len > MAX_SERVICE_ID_BYTES {
        return Err(ServiceTargetError::ServiceIdTooLong { len });
    }
    let service_end = SERVICE_PREFACE_HEADER_BYTES
        .checked_add(len)
        .ok_or(ServiceTargetError::Truncated)?;
    if bytes.len() < service_end {
        return Err(ServiceTargetError::Truncated);
    }
    let service_id = std::str::from_utf8(&bytes[SERVICE_PREFACE_HEADER_BYTES..service_end])
        .map_err(|_| ServiceTargetError::InvalidMagic)?
        .to_string();
    validate_service_id(&service_id)?;

    if version == SERVICE_PREFACE_VERSION_LEGACY {
        return Ok((service_id, None, service_end));
    }

    let meta_len_end = service_end
        .checked_add(2)
        .ok_or(ServiceTargetError::Truncated)?;
    if bytes.len() < meta_len_end {
        return Err(ServiceTargetError::Truncated);
    }
    let meta_len = u16::from_be_bytes([bytes[service_end], bytes[service_end + 1]]) as usize;
    if meta_len > MAX_SERVICE_METADATA_BYTES {
        return Err(ServiceTargetError::MetadataTooLong { len: meta_len });
    }
    let meta_end = meta_len_end
        .checked_add(meta_len)
        .ok_or(ServiceTargetError::Truncated)?;
    if bytes.len() < meta_end {
        return Err(ServiceTargetError::Truncated);
    }

    let has_metadata_flag = flags & SERVICE_PREFACE_FLAG_CLIENT_METADATA != 0;
    let metadata = match (has_metadata_flag, meta_len) {
        (true, _) => Some(decode_metadata(&bytes[meta_len_end..meta_end])?),
        (false, 0) => None,
        (false, _) => {
            return Err(ServiceTargetError::InvalidMetadataValue(
                "metadata block without the metadata flag",
            ))
        }
    };

    Ok((service_id, metadata, meta_end))
}

fn encode_metadata(meta: &ClientMetadata) -> Result<Vec<u8>, ServiceTargetError> {
    let mut out = Vec::with_capacity(MAX_SERVICE_METADATA_BYTES);
    out.push(SERVICE_METADATA_TYPE_CLIENT_IP);
    match meta.client_ip {
        IpAddr::V4(address) => {
            out.push(5);
            out.push(ADDRESS_FAMILY_IPV4);
            out.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            out.push(17);
            out.push(ADDRESS_FAMILY_IPV6);
            out.extend_from_slice(&address.octets());
        }
    }
    out.push(SERVICE_METADATA_TYPE_CLIENT_PROTOCOL);
    out.push(1);
    out.push(meta.proto.to_metadata_byte());

    if out.len() > MAX_SERVICE_METADATA_BYTES {
        return Err(ServiceTargetError::MetadataTooLong { len: out.len() });
    }
    Ok(out)
}

fn decode_metadata(bytes: &[u8]) -> Result<ClientMetadata, ServiceTargetError> {
    let mut client_ip: Option<IpAddr> = None;
    let mut proto: Option<ClientProtocol> = None;

    let mut index = 0usize;
    while index < bytes.len() {
        let header_end = index.checked_add(2).ok_or(ServiceTargetError::Truncated)?;
        if header_end > bytes.len() {
            return Err(ServiceTargetError::InvalidMetadataValue(
                "truncated metadata entry header",
            ));
        }
        let field_type = bytes[index];
        let field_len = bytes[index + 1] as usize;
        let value_end = header_end
            .checked_add(field_len)
            .ok_or(ServiceTargetError::Truncated)?;
        if value_end > bytes.len() {
            return Err(ServiceTargetError::InvalidMetadataValue(
                "truncated metadata entry value",
            ));
        }
        let value = &bytes[header_end..value_end];

        match field_type {
            SERVICE_METADATA_TYPE_CLIENT_IP => {
                if client_ip.is_some() {
                    return Err(ServiceTargetError::DuplicateMetadataField(field_type));
                }
                client_ip = Some(decode_client_ip(value)?);
            }
            SERVICE_METADATA_TYPE_CLIENT_PROTOCOL => {
                if proto.is_some() {
                    return Err(ServiceTargetError::DuplicateMetadataField(field_type));
                }
                proto = Some(decode_client_protocol(value).ok_or(
                    ServiceTargetError::InvalidMetadataValue("invalid client protocol"),
                )?);
            }
            other => return Err(ServiceTargetError::UnknownMetadataField(other)),
        }

        index = value_end;
    }

    match (client_ip, proto) {
        (Some(client_ip), Some(proto)) => Ok(ClientMetadata { client_ip, proto }),
        (None, _) => Err(ServiceTargetError::InvalidMetadataValue(
            "client address is required",
        )),
        (_, None) => Err(ServiceTargetError::InvalidMetadataValue(
            "client protocol is required",
        )),
    }
}

fn decode_client_ip(value: &[u8]) -> Result<IpAddr, ServiceTargetError> {
    let (family, address) = value
        .split_first()
        .ok_or(ServiceTargetError::InvalidMetadataValue(
            "client address family is missing",
        ))?;
    match (*family, address.len()) {
        (ADDRESS_FAMILY_IPV4, 4) => {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(address);
            Ok(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        (ADDRESS_FAMILY_IPV6, 16) => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(address);
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        (ADDRESS_FAMILY_IPV4 | ADDRESS_FAMILY_IPV6, _) => {
            Err(ServiceTargetError::InvalidMetadataValue(
                "client address length does not match its family",
            ))
        }
        _ => Err(ServiceTargetError::InvalidMetadataValue(
            "unknown client address family",
        )),
    }
}

fn decode_client_protocol(value: &[u8]) -> Option<ClientProtocol> {
    match value {
        [byte] => ClientProtocol::from_metadata_byte(*byte),
        _ => None,
    }
}

/// Returns true when `service_id` is the compatibility `http://host[:port]`
/// form, which the original domain-based model used as its service key.
pub fn is_url_like_service_id(service_id: &str) -> bool {
    service_id.starts_with("http://") || service_id.starts_with("https://")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata_v4(ip: [u8; 4], proto: ClientProtocol) -> ClientMetadata {
        ClientMetadata {
            client_ip: IpAddr::V4(Ipv4Addr::from(ip)),
            proto,
        }
    }

    #[test]
    fn validates_explicit_and_url_like_ids() {
        assert!(validate_service_id("blog-public").is_ok());
        assert!(validate_service_id("http://blog.example:8082").is_ok());
        assert!(is_url_like_service_id("http://blog.example:8082"));
        assert!(!is_url_like_service_id("blog-public"));
    }

    #[test]
    fn rejects_empty_overlong_and_control_ids() {
        assert_eq!(
            validate_service_id(""),
            Err(ServiceTargetError::EmptyServiceId)
        );
        let long = "a".repeat(MAX_SERVICE_ID_BYTES + 1);
        assert!(matches!(
            validate_service_id(&long),
            Err(ServiceTargetError::ServiceIdTooLong { .. })
        ));
        assert!(matches!(
            validate_service_id("blog\npublic"),
            Err(ServiceTargetError::ControlCharacter { .. })
        ));
        assert!(matches!(
            validate_service_id("blog\u{7f}public"),
            Err(ServiceTargetError::ControlCharacter { .. })
        ));
    }

    #[test]
    fn preface_round_trips_without_metadata() {
        let encoded = encode_service_preface("blog-public", None).unwrap();
        assert_eq!(&encoded[..4], &SERVICE_PREFACE_MAGIC);
        assert_eq!(encoded[4], SERVICE_PREFACE_VERSION);
        assert_eq!(encoded[5], 0);
        let (decoded, meta, consumed) = decode_service_preface(&encoded).unwrap();
        assert_eq!(decoded, "blog-public");
        assert_eq!(meta, None);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn preface_round_trips_with_metadata() {
        let meta = metadata_v4([203, 0, 113, 7], ClientProtocol::Https);
        let encoded = encode_service_preface("blog-public", Some(&meta)).unwrap();
        assert_eq!(encoded[5], SERVICE_PREFACE_FLAG_CLIENT_METADATA);

        let (decoded, decoded_meta, consumed) = decode_service_preface(&encoded).unwrap();
        assert_eq!(decoded, "blog-public");
        assert_eq!(decoded_meta, Some(meta));
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn preface_round_trips_ipv6_metadata() {
        let meta = ClientMetadata {
            client_ip: "2001:db8::1".parse().unwrap(),
            proto: ClientProtocol::Http,
        };
        let encoded = encode_service_preface("blog-public", Some(&meta)).unwrap();
        let (_, decoded_meta, consumed) = decode_service_preface(&encoded).unwrap();
        assert_eq!(decoded_meta, Some(meta));
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn version_1_preface_still_decodes() {
        let mut encoded = vec![0x1f, b'M', b'S', b'V', SERVICE_PREFACE_VERSION_LEGACY, 0];
        encoded.extend_from_slice(&(b"blog".len() as u16).to_be_bytes());
        encoded.extend_from_slice(b"blog");

        let (service_id, meta, consumed) = decode_service_preface(&encoded).unwrap();
        assert_eq!(service_id, "blog");
        assert_eq!(meta, None);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn version_1_flags_must_stay_zero() {
        let mut encoded = vec![0x1f, b'M', b'S', b'V', SERVICE_PREFACE_VERSION_LEGACY, 1];
        encoded.extend_from_slice(&(b"blog".len() as u16).to_be_bytes());
        encoded.extend_from_slice(b"blog");
        assert_eq!(
            decode_service_preface(&encoded),
            Err(ServiceTargetError::UnsupportedFlags(1))
        );
    }

    #[test]
    fn preface_round_trips_url_like_id() {
        let encoded = encode_service_preface("http://blog.example:8082", None).unwrap();
        let (decoded, meta, consumed) = decode_service_preface(&encoded).unwrap();
        assert_eq!(decoded, "http://blog.example:8082");
        assert_eq!(meta, None);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn preface_rejects_bad_version_flags_and_magic() {
        let mut encoded = encode_service_preface("blog", None).unwrap();
        encoded[4] = 9;
        assert_eq!(
            decode_service_preface(&encoded),
            Err(ServiceTargetError::UnsupportedVersion(9))
        );

        let mut encoded = encode_service_preface("blog", None).unwrap();
        encoded[5] = 0x80;
        assert_eq!(
            decode_service_preface(&encoded),
            Err(ServiceTargetError::UnsupportedFlags(0x80))
        );

        let mut encoded = encode_service_preface("blog", None).unwrap();
        encoded[0] = b'X';
        assert_eq!(
            decode_service_preface(&encoded),
            Err(ServiceTargetError::InvalidMagic)
        );
    }

    #[test]
    fn preface_rejects_truncation_and_mismatched_length() {
        let encoded = encode_service_preface("blog-public", None).unwrap();
        assert_eq!(
            decode_service_preface(&encoded[..4]),
            Err(ServiceTargetError::Truncated)
        );
        assert_eq!(
            decode_service_preface(&encoded[..encoded.len() - 1]),
            Err(ServiceTargetError::Truncated)
        );

        let mut encoded = encode_service_preface("blog", None).unwrap();
        encoded[6] = 0;
        encoded[7] = 9;
        assert_eq!(
            decode_service_preface(&encoded),
            Err(ServiceTargetError::Truncated)
        );
    }

    /// Build a version-2 preface with an arbitrary metadata block, bypassing
    /// the encoder's mandatory-field rules.
    fn preface_with_raw_metadata(metadata: &[u8]) -> Vec<u8> {
        let mut encoded = vec![
            0x1f,
            b'M',
            b'S',
            b'V',
            SERVICE_PREFACE_VERSION,
            SERVICE_PREFACE_FLAG_CLIENT_METADATA,
        ];
        encoded.extend_from_slice(&(b"blog".len() as u16).to_be_bytes());
        encoded.extend_from_slice(b"blog");
        encoded.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
        encoded.extend_from_slice(metadata);
        encoded
    }

    fn ipv4_entry(ip: [u8; 4]) -> Vec<u8> {
        let mut entry = vec![SERVICE_METADATA_TYPE_CLIENT_IP, 5, ADDRESS_FAMILY_IPV4];
        entry.extend_from_slice(&ip);
        entry
    }

    fn protocol_entry(byte: u8) -> Vec<u8> {
        vec![SERVICE_METADATA_TYPE_CLIENT_PROTOCOL, 1, byte]
    }

    #[test]
    fn metadata_rejects_duplicate_types() {
        let mut metadata = ipv4_entry([10, 0, 0, 1]);
        metadata.extend_from_slice(&ipv4_entry([10, 0, 0, 2]));
        metadata.extend_from_slice(&protocol_entry(PROTOCOL_HTTP));

        assert_eq!(
            decode_service_preface(&preface_with_raw_metadata(&metadata)),
            Err(ServiceTargetError::DuplicateMetadataField(
                SERVICE_METADATA_TYPE_CLIENT_IP
            ))
        );

        let mut metadata = ipv4_entry([10, 0, 0, 1]);
        metadata.extend_from_slice(&protocol_entry(PROTOCOL_HTTP));
        metadata.extend_from_slice(&protocol_entry(PROTOCOL_HTTPS));
        assert_eq!(
            decode_service_preface(&preface_with_raw_metadata(&metadata)),
            Err(ServiceTargetError::DuplicateMetadataField(
                SERVICE_METADATA_TYPE_CLIENT_PROTOCOL
            ))
        );
    }

    #[test]
    fn metadata_rejects_unknown_types() {
        let mut metadata = ipv4_entry([10, 0, 0, 1]);
        metadata.extend_from_slice(&protocol_entry(PROTOCOL_HTTP));
        metadata.extend_from_slice(&[0x7f, 1, 0]);

        assert_eq!(
            decode_service_preface(&preface_with_raw_metadata(&metadata)),
            Err(ServiceTargetError::UnknownMetadataField(0x7f))
        );
    }

    #[test]
    fn metadata_rejects_oversized_block() {
        let mut encoded = vec![
            0x1f,
            b'M',
            b'S',
            b'V',
            SERVICE_PREFACE_VERSION,
            SERVICE_PREFACE_FLAG_CLIENT_METADATA,
        ];
        encoded.extend_from_slice(&(b"blog".len() as u16).to_be_bytes());
        encoded.extend_from_slice(b"blog");
        encoded.extend_from_slice(&((MAX_SERVICE_METADATA_BYTES + 1) as u16).to_be_bytes());

        assert_eq!(
            decode_service_preface(&encoded),
            Err(ServiceTargetError::MetadataTooLong {
                len: MAX_SERVICE_METADATA_BYTES + 1
            })
        );
    }

    #[test]
    fn metadata_rejects_bad_family_and_length() {
        // Unknown family.
        let mut metadata = vec![SERVICE_METADATA_TYPE_CLIENT_IP, 5, 5, 10, 0, 0, 1];
        metadata.extend_from_slice(&protocol_entry(PROTOCOL_HTTP));
        assert!(matches!(
            decode_service_preface(&preface_with_raw_metadata(&metadata)),
            Err(ServiceTargetError::InvalidMetadataValue(_))
        ));

        // Family 4 with a 16-byte address.
        let mut metadata = vec![SERVICE_METADATA_TYPE_CLIENT_IP, 17, ADDRESS_FAMILY_IPV4];
        metadata.extend_from_slice(&[0u8; 16]);
        metadata.extend_from_slice(&protocol_entry(PROTOCOL_HTTP));
        assert!(matches!(
            decode_service_preface(&preface_with_raw_metadata(&metadata)),
            Err(ServiceTargetError::InvalidMetadataValue(_))
        ));

        // Truncated address: family says 4, only 2 address bytes.
        let mut metadata = vec![
            SERVICE_METADATA_TYPE_CLIENT_IP,
            3,
            ADDRESS_FAMILY_IPV4,
            10,
            0,
        ];
        metadata.extend_from_slice(&protocol_entry(PROTOCOL_HTTP));
        assert!(matches!(
            decode_service_preface(&preface_with_raw_metadata(&metadata)),
            Err(ServiceTargetError::InvalidMetadataValue(_))
        ));
    }

    #[test]
    fn metadata_rejects_bad_protocol_byte() {
        let mut metadata = ipv4_entry([10, 0, 0, 1]);
        metadata.extend_from_slice(&protocol_entry(2));
        assert!(matches!(
            decode_service_preface(&preface_with_raw_metadata(&metadata)),
            Err(ServiceTargetError::InvalidMetadataValue(_))
        ));
    }

    #[test]
    fn metadata_rejects_missing_mandatory_field() {
        let metadata = ipv4_entry([10, 0, 0, 1]);
        assert!(matches!(
            decode_service_preface(&preface_with_raw_metadata(&metadata)),
            Err(ServiceTargetError::InvalidMetadataValue(_))
        ));

        let metadata = protocol_entry(PROTOCOL_HTTP);
        assert!(matches!(
            decode_service_preface(&preface_with_raw_metadata(&metadata)),
            Err(ServiceTargetError::InvalidMetadataValue(_))
        ));
    }

    #[test]
    fn metadata_without_the_flag_is_rejected() {
        let mut metadata = ipv4_entry([10, 0, 0, 1]);
        metadata.extend_from_slice(&protocol_entry(PROTOCOL_HTTP));

        let mut encoded = preface_with_raw_metadata(&metadata);
        encoded[5] = 0;

        assert!(matches!(
            decode_service_preface(&encoded),
            Err(ServiceTargetError::InvalidMetadataValue(_))
        ));
    }

    #[test]
    fn preface_start_is_distinct_from_http_and_control_frames() {
        assert!(is_service_preface_start(0x1f));
        for method in *b"GPHDOTC" {
            assert!(!is_service_preface_start(method));
        }
        // Control-message length prefixes are bounded by MAX_MESSAGE_SIZE,
        // so their most-significant byte is always zero.
        assert!(!is_service_preface_start(0x00));
    }
}
