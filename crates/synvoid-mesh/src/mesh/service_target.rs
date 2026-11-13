//! Mesh HTTP service-identity contract (mesh multi-upstream forwarding).
//!
//! A mesh HTTP request carries an explicit, typed service ID ahead of the
//! HTTP/1.x request bytes. The service ID is the origin's
//! `[tunnel.mesh.local_upstreams.<service_id>]` key. It is never inferred from
//! the request `Host`, and local listener identity never appears here.
//!
//! Wire format (version 1):
//!
//! ```text
//! +--------+--------+---------+--------+----------------+
//! | magic  | version| flags   | len    | service_id     |
//! | 4 B    | 1 B    | 1 B     | 2 B BE | len bytes      |
//! +--------+--------+---------+--------+----------------+
//! ```
//!
//! The magic starts with `0x1f`, which cannot begin a length-prefixed mesh
//! control message: the length prefix is a `u32` big-endian bounded by
//! `MAX_MESSAGE_SIZE` (10 MiB), so its first byte is always `0x00`. It also
//! cannot begin an HTTP request line, because no HTTP method starts with
//! `0x1f`. Peers that do not send a preface keep the legacy `Host`-derived
//! service key.

/// First bytes of the service-target preface.
pub const SERVICE_PREFACE_MAGIC: [u8; 4] = [0x1f, b'M', b'S', b'V'];

/// Current wire version of the service-target preface.
pub const SERVICE_PREFACE_VERSION: u8 = 1;

/// Reserved flags byte. Must be zero in version 1.
pub const SERVICE_PREFACE_FLAGS: u8 = 0;

/// Maximum accepted service-ID length in bytes.
pub const MAX_SERVICE_ID_BYTES: usize = 255;

/// Length of the fixed preface header (magic + version + flags + length).
pub const SERVICE_PREFACE_HEADER_BYTES: usize = 8;

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
pub fn encode_service_preface(service_id: &str) -> Result<Vec<u8>, ServiceTargetError> {
    validate_service_id(service_id)?;
    let mut out = Vec::with_capacity(SERVICE_PREFACE_HEADER_BYTES + service_id.len());
    out.extend_from_slice(&SERVICE_PREFACE_MAGIC);
    out.push(SERVICE_PREFACE_VERSION);
    out.push(SERVICE_PREFACE_FLAGS);
    out.extend_from_slice(&(service_id.len() as u16).to_be_bytes());
    out.extend_from_slice(service_id.as_bytes());
    Ok(out)
}

/// Decode a complete service-target preface from `bytes`.
///
/// Returns the service ID and the number of bytes consumed. Only a complete
/// preface decodes; callers reading from a stream must first accumulate
/// [`SERVICE_PREFACE_HEADER_BYTES`] plus the advertised length.
pub fn decode_service_preface(bytes: &[u8]) -> Result<(String, usize), ServiceTargetError> {
    if bytes.len() < SERVICE_PREFACE_HEADER_BYTES {
        return Err(ServiceTargetError::Truncated);
    }
    if bytes[..4] != SERVICE_PREFACE_MAGIC {
        return Err(ServiceTargetError::InvalidMagic);
    }
    let version = bytes[4];
    if version != SERVICE_PREFACE_VERSION {
        return Err(ServiceTargetError::UnsupportedVersion(version));
    }
    let flags = bytes[5];
    if flags != SERVICE_PREFACE_FLAGS {
        return Err(ServiceTargetError::UnsupportedFlags(flags));
    }
    let len = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
    if len > MAX_SERVICE_ID_BYTES {
        return Err(ServiceTargetError::ServiceIdTooLong { len });
    }
    let end = SERVICE_PREFACE_HEADER_BYTES
        .checked_add(len)
        .ok_or(ServiceTargetError::Truncated)?;
    if bytes.len() < end {
        return Err(ServiceTargetError::Truncated);
    }
    let service_id = std::str::from_utf8(&bytes[SERVICE_PREFACE_HEADER_BYTES..end])
        .map_err(|_| ServiceTargetError::InvalidMagic)?
        .to_string();
    validate_service_id(&service_id)?;
    Ok((service_id, end))
}

/// Returns true when `service_id` is the compatibility `http://host[:port]`
/// form, which the original domain-based model used as its service key.
pub fn is_url_like_service_id(service_id: &str) -> bool {
    service_id.starts_with("http://") || service_id.starts_with("https://")
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn preface_round_trips() {
        let encoded = encode_service_preface("blog-public").unwrap();
        assert_eq!(&encoded[..4], &SERVICE_PREFACE_MAGIC);
        let (decoded, consumed) = decode_service_preface(&encoded).unwrap();
        assert_eq!(decoded, "blog-public");
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn preface_round_trips_url_like_id() {
        let encoded = encode_service_preface("http://blog.example:8082").unwrap();
        let (decoded, consumed) = decode_service_preface(&encoded).unwrap();
        assert_eq!(decoded, "http://blog.example:8082");
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn preface_rejects_bad_version_flags_and_magic() {
        let mut encoded = encode_service_preface("blog").unwrap();
        encoded[4] = 9;
        assert_eq!(
            decode_service_preface(&encoded),
            Err(ServiceTargetError::UnsupportedVersion(9))
        );

        let mut encoded = encode_service_preface("blog").unwrap();
        encoded[5] = 1;
        assert_eq!(
            decode_service_preface(&encoded),
            Err(ServiceTargetError::UnsupportedFlags(1))
        );

        let mut encoded = encode_service_preface("blog").unwrap();
        encoded[0] = b'X';
        assert_eq!(
            decode_service_preface(&encoded),
            Err(ServiceTargetError::InvalidMagic)
        );
    }

    #[test]
    fn preface_rejects_truncation_and_mismatched_length() {
        let encoded = encode_service_preface("blog-public").unwrap();
        assert_eq!(
            decode_service_preface(&encoded[..4]),
            Err(ServiceTargetError::Truncated)
        );
        assert_eq!(
            decode_service_preface(&encoded[..encoded.len() - 1]),
            Err(ServiceTargetError::Truncated)
        );

        let mut encoded = encode_service_preface("blog").unwrap();
        encoded[6] = 0;
        encoded[7] = 9;
        assert_eq!(
            decode_service_preface(&encoded),
            Err(ServiceTargetError::Truncated)
        );
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
