use std::io;

/// Extract the SNI hostname from a raw TLS ClientHello without consuming the stream.
/// Returns the SNI hostname if present, or None.
///
/// This parses just enough of the TLS record layer + ClientHello to extract
/// the SNI extension, preserving the stream for forwarding in passthrough mode.
pub fn extract_sni(data: &[u8]) -> Result<Option<String>, SniError> {
    if data.len() < 5 {
        return Err(SniError::TooShort);
    }

    // TLS record layer: ContentType (1) + Version (2) + Length (2)
    let content_type = data[0];
    if content_type != 0x16 {
        return Err(SniError::NotHandshake(content_type));
    }

    // TLS version (record layer)
    let _record_version = u16::from_be_bytes([data[1], data[2]]);
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;

    if data.len() < 5 + record_len {
        return Err(SniError::Incomplete);
    }

    let handshake = &data[5..5 + record_len];
    parse_client_hello_sni(handshake)
}

/// Parse a TLS ClientHello handshake message for the SNI extension.
fn parse_client_hello_sni(data: &[u8]) -> Result<Option<String>, SniError> {
    if data.len() < 4 {
        return Err(SniError::TooShort);
    }

    // Handshake message: type (1) + length (3)
    let msg_type = data[0];
    if msg_type != 0x01 {
        return Err(SniError::NotClientHello(msg_type));
    }

    let msg_len = ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | (data[3] as usize);
    if data.len() < 4 + msg_len {
        return Err(SniError::Incomplete);
    }

    let hello = &data[4..4 + msg_len];

    // ClientHello: version (2) + random (32) + session_id
    if hello.len() < 34 {
        return Err(SniError::TooShort);
    }

    let mut pos = 34; // skip version (2) + random (32)

    // Session ID
    if pos >= hello.len() {
        return Err(SniError::TooShort);
    }
    let session_id_len = hello[pos] as usize;
    pos += 1 + session_id_len;

    if pos + 2 > hello.len() {
        return Err(SniError::TooShort);
    }

    // Cipher suites
    let cipher_suites_len = ((hello[pos] as usize) << 8) | (hello[pos + 1] as usize);
    pos += 2 + cipher_suites_len;

    if pos >= hello.len() {
        return Err(SniError::TooShort);
    }

    // Compression methods
    let compression_len = hello[pos] as usize;
    pos += 1 + compression_len;

    if pos + 2 > hello.len() {
        // No extensions — ClientHello without SNI
        return Ok(None);
    }

    // Extensions
    let extensions_len = ((hello[pos] as usize) << 8) | (hello[pos + 1] as usize);
    pos += 2;

    if pos + extensions_len > hello.len() {
        return Err(SniError::Incomplete);
    }

    let extensions = &hello[pos..pos + extensions_len];
    parse_sni_extension(extensions)
}

/// Parse extensions block looking for SNI (type 0x0000).
fn parse_sni_extension(data: &[u8]) -> Result<Option<String>, SniError> {
    let mut pos = 0;

    while pos + 4 <= data.len() {
        let ext_type = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
        let ext_len = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
        pos += 4;

        if pos + ext_len > data.len() {
            return Err(SniError::Incomplete);
        }

        if ext_type == 0x0000 {
            // SNI extension
            return parse_sni_list(&data[pos..pos + ext_len]);
        }

        pos += ext_len;
    }

    Ok(None)
}

/// Parse the ServerNameList from the SNI extension.
fn parse_sni_list(data: &[u8]) -> Result<Option<String>, SniError> {
    if data.len() < 2 {
        return Err(SniError::TooShort);
    }

    let list_len = ((data[0] as usize) << 8) | (data[1] as usize);
    if data.len() < 2 + list_len {
        return Err(SniError::Incomplete);
    }

    let mut pos = 2;
    while pos + 3 <= data.len() {
        let name_type = data[pos];
        let name_len = ((data[pos + 1] as usize) << 8) | (data[pos + 2] as usize);
        pos += 3;

        if pos + name_len > data.len() {
            return Err(SniError::Incomplete);
        }

        if name_type == 0x00 {
            // host_name type
            let name_bytes = &data[pos..pos + name_len];
            let hostname =
                std::str::from_utf8(name_bytes).map_err(|_| SniError::InvalidHostname)?;
            return Ok(Some(hostname.to_string()));
        }

        pos += name_len;
    }

    Ok(None)
}

/// Result of peeking at a TLS stream for SNI.
pub struct SniPeekResult {
    pub sni: Option<String>,
    pub client_hello_bytes: Vec<u8>,
}

/// Peek at a TcpStream to extract SNI from the ClientHello.
/// Returns the SNI hostname and the bytes read (to be forwarded in passthrough mode).
pub async fn peek_sni(stream: &mut tokio::net::TcpStream) -> Result<SniPeekResult, SniError> {
    use tokio::io::AsyncReadExt;

    // Read the TLS record header + a chunk of the ClientHello
    let mut buf = vec![0u8; 4096];
    let n = stream
        .read(&mut buf)
        .await
        .map_err(|e| SniError::Io(e.to_string()))?;

    if n == 0 {
        return Err(SniError::ConnectionClosed);
    }

    buf.truncate(n);
    let sni = extract_sni(&buf)?;

    Ok(SniPeekResult {
        sni,
        client_hello_bytes: buf,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum SniError {
    #[error("Data too short for TLS record")]
    TooShort,

    #[error("Not a TLS handshake record (type=0x{0:02x})")]
    NotHandshake(u8),

    #[error("Not a ClientHello message (type=0x{0:02x})")]
    NotClientHello(u8),

    #[error("Incomplete TLS record")]
    Incomplete,

    #[error("Invalid UTF-8 in hostname")]
    InvalidHostname,

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("IO error: {0}")]
    Io(String),
}

impl From<io::Error> for SniError {
    fn from(e: io::Error) -> Self {
        SniError::Io(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_sni_from_real_client_hello() {
        // Minimal valid ClientHello with SNI "example.com"
        // This is a crafted minimal TLS ClientHello
        let hello = build_test_client_hello("example.com");
        let result = extract_sni(&hello).unwrap();
        assert_eq!(result, Some("example.com".to_string()));
    }

    #[test]
    fn test_extract_sni_empty_data() {
        let result = extract_sni(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_sni_not_handshake() {
        let data = [0x15, 0x03, 0x03, 0x00, 0x02]; // Alert record
        let result = extract_sni(&data);
        assert!(matches!(result, Err(SniError::NotHandshake(0x15))));
    }

    fn build_test_client_hello(hostname: &str) -> Vec<u8> {
        // Build a minimal ClientHello with SNI
        let mut hello = Vec::new();

        // Handshake header: type = ClientHello (0x01), placeholder for length
        hello.push(0x01);
        let len_pos = hello.len();
        hello.extend_from_slice(&[0, 0, 0]); // 3-byte length placeholder

        // Client version TLS 1.2 (for compatibility)
        hello.extend_from_slice(&[0x03, 0x03]);

        // Random (32 bytes)
        hello.extend_from_slice(&[0u8; 32]);

        // Session ID (empty)
        hello.push(0);

        // Cipher suites: TLS_AES_128_GCM_SHA256 (0x13, 0x01)
        hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);

        // Compression methods: null
        hello.push(0x01);
        hello.push(0x00);

        // Extensions
        let ext_start = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]); // placeholder for extensions length

        // SNI extension (type 0x0000)
        let sni_data = build_sni_extension(hostname);
        hello.extend_from_slice(&sni_data);

        // Fill in extensions length
        let ext_len = hello.len() - ext_start - 2;
        hello[ext_start] = (ext_len >> 8) as u8;
        hello[ext_start + 1] = (ext_len & 0xFF) as u8;

        // Fill in handshake message length
        let msg_len = hello.len() - 4;
        hello[len_pos] = (msg_len >> 16) as u8;
        hello[len_pos + 1] = ((msg_len >> 8) & 0xFF) as u8;
        hello[len_pos + 2] = (msg_len & 0xFF) as u8;

        // Wrap in TLS record layer
        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
        let record_len = hello.len();
        record.extend_from_slice(&((record_len as u16).to_be_bytes()));
        record.extend_from_slice(&hello);

        record
    }

    fn build_sni_extension(hostname: &str) -> Vec<u8> {
        let mut ext = Vec::new();
        ext.extend_from_slice(&[0x00, 0x00]); // type = SNI

        // Extension data length placeholder
        let len_pos = ext.len();
        ext.extend_from_slice(&[0x00, 0x00]);

        // ServerNameList length placeholder
        let list_pos = ext.len();
        ext.extend_from_slice(&[0x00, 0x00]);

        // ServerName entry: type = host_name (0), name
        ext.push(0x00); // type
        let name_len = hostname.len() as u16;
        ext.extend_from_slice(&name_len.to_be_bytes());
        ext.extend_from_slice(hostname.as_bytes());

        // Fill in ServerNameList length
        let list_len = ext.len() - list_pos - 2;
        ext[list_pos] = (list_len >> 8) as u8;
        ext[list_pos + 1] = (list_len & 0xFF) as u8;

        // Fill in extension data length
        let ext_data_len = ext.len() - len_pos - 2;
        ext[len_pos] = (ext_data_len >> 8) as u8;
        ext[len_pos + 1] = (ext_data_len & 0xFF) as u8;

        ext
    }
}
