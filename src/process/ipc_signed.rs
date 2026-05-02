use std::collections::{BTreeSet, HashSet};
use std::io::{self, Read, Write};
use std::sync::{Arc, LazyLock};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use hmac::{Hmac, Mac};
use sha3::Sha3_256;

use crate::process::Message;

pub type HmacSha3_256 = Hmac<Sha3_256>;

#[derive(Debug)]
enum IpcSignerError {
    InvalidHexLength(usize),
    InvalidHexChar(String),
}

impl std::fmt::Display for IpcSignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpcSignerError::InvalidHexLength(len) => {
                write!(f, "IPC key hex must be exactly 64 characters, got {}", len)
            }
            IpcSignerError::InvalidHexChar(msg) => {
                write!(f, "IPC key hex contains invalid characters: {}", msg)
            }
        }
    }
}

fn parse_hex_key(hex: &str) -> Result<[u8; 32], IpcSignerError> {
    if hex.len() != 64 {
        return Err(IpcSignerError::InvalidHexLength(hex.len()));
    }
    let mut key = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk)
            .map_err(|_| IpcSignerError::InvalidHexChar("non-utf8 chunk".to_string()))?;
        let b = u8::from_str_radix(s, 16)
            .map_err(|_| IpcSignerError::InvalidHexChar(format!("invalid hex byte: {}", s)))?;
        key[i] = b;
    }
    Ok(key)
}

pub const HMAC_SIZE: usize = 32;
pub const TIMESTAMP_SIZE: usize = 8;
pub const NONCE_SIZE: usize = 16;
pub const SIGNED_MESSAGE_OVERHEAD: usize = 4 + TIMESTAMP_SIZE + NONCE_SIZE + HMAC_SIZE;
pub const MAX_IPC_MESSAGE_SIZE: usize = 1024 * 1024;

static OVERSIZED_REJECTED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn oversized_rejected_count() -> u64 {
    OVERSIZED_REJECTED.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn increment_oversized_rejected() {
    OVERSIZED_REJECTED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

struct NonceEntry {
    nonce: [u8; 16],
    timestamp: u64,
}

impl Ord for NonceEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.timestamp.cmp(&other.timestamp)
    }
}

impl PartialOrd for NonceEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for NonceEntry {
    fn eq(&self, other: &Self) -> bool {
        self.nonce == other.nonce
    }
}

impl Eq for NonceEntry {}

struct NonceCache {
    by_nonce: HashSet<[u8; 16]>,
    by_timestamp: BTreeSet<NonceEntry>,
}

impl NonceCache {
    fn new() -> Self {
        Self {
            by_nonce: HashSet::new(),
            by_timestamp: BTreeSet::new(),
        }
    }

    fn contains(&self, nonce: &[u8; 16]) -> bool {
        self.by_nonce.contains(nonce)
    }

    fn insert(&mut self, nonce: [u8; 16], timestamp: u64) {
        let entry = NonceEntry { nonce, timestamp };
        self.by_nonce.insert(nonce);
        self.by_timestamp.insert(entry);
    }

    fn evict_oldest(&mut self) {
        while self.by_timestamp.len() > MAX_NONCE_CACHE_SIZE {
            if let Some(oldest) = self.by_timestamp.pop_first() {
                self.by_nonce.remove(&oldest.nonce);
            }
        }
    }
}

static NONCE_CACHE: LazyLock<parking_lot::Mutex<NonceCache>> =
    LazyLock::new(|| parking_lot::Mutex::new(NonceCache::new()));
const MAX_NONCE_CACHE_SIZE: usize = 10000;
const REPLAY_WINDOW_SECS: u64 = 60;

fn check_and_insert_nonce(nonce: &[u8; 16], timestamp: u64) -> bool {
    let mut cache = NONCE_CACHE.lock();

    if cache.contains(nonce) {
        return false;
    }

    cache.insert(*nonce, timestamp);
    cache.evict_oldest();
    true
}

fn generate_nonce() -> [u8; 16] {
    // rand::rng() in rand 0.9+ uses OsRng internally - acceptable for nonce generation
    use rand::RngCore;
    let mut nonce = [0u8; 16];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

fn verify_timestamp(timestamp: u64) -> bool {
    let now = crate::utils::current_timestamp();
    let diff = now.abs_diff(timestamp);
    diff <= REPLAY_WINDOW_SECS
}

pub struct IpcSigner {
    key: [u8; 32],
}

impl IpcSigner {
    pub fn new(key: &[u8; 32]) -> Self {
        Self { key: *key }
    }

    /// Derives an IPC signing key from a secret string.
    ///
    /// **This should only be used for testing/development.** Production
    /// deployments must use generated random session keys via
    /// [`generate_session_key()`] and file-based key exchange to avoid
    /// deterministic key material.
    pub fn from_secret(secret: &str) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        Self { key }
    }

    pub fn try_from_env() -> Option<Self> {
        #[cfg(unix)]
        {
            use libc::O_EXCL;
            if let Ok(key_file) = std::env::var("MALUWAF_IPC_KEY_FILE") {
                let file = match std::fs::File::options()
                    .read(true)
                    .custom_flags(O_EXCL)
                    .open(&key_file)
                {
                    Ok(f) => f,
                    Err(_) => return None,
                };
                let mut key_hex = String::new();
                std::io::Read::read_to_string(&mut std::io::BufReader::new(&file), &mut key_hex)
                    .ok()?;
                let _ = file;
                std::fs::remove_file(&key_file).ok();
                let key_hex = key_hex.trim();
                let key = parse_hex_key(key_hex).ok()?;
                return Some(Self { key });
            }
        }
        if let Ok(key_hex) = std::env::var("MALUWAF_IPC_KEY") {
            let key = parse_hex_key(key_hex.trim()).ok()?;
            return Some(Self { key });
        }
        None
    }

    pub fn sign(&self, data: &[u8]) -> [u8; HMAC_SIZE] {
        let mut mac =
            HmacSha3_256::new_from_slice(&self.key).expect("HMAC can take key of any size");
        mac.update(data);
        let result = mac.finalize();
        let mut hmac_bytes = [0u8; HMAC_SIZE];
        hmac_bytes.copy_from_slice(&result.into_bytes());
        hmac_bytes
    }

    pub fn verify(&self, data: &[u8], expected_hmac: &[u8; HMAC_SIZE]) -> bool {
        let computed_hmac = self.sign(data);
        use subtle::ConstantTimeEq;
        computed_hmac.ct_eq(expected_hmac).into()
    }

    pub fn sign_parts(&self, parts: &[&[u8]]) -> [u8; HMAC_SIZE] {
        let mut mac =
            HmacSha3_256::new_from_slice(&self.key).expect("HMAC can take key of any size");
        for part in parts {
            mac.update(part);
        }
        let result = mac.finalize();
        let mut hmac_bytes = [0u8; HMAC_SIZE];
        hmac_bytes.copy_from_slice(&result.into_bytes());
        hmac_bytes
    }

    pub fn verify_parts(&self, parts: &[&[u8]], expected_hmac: &[u8; HMAC_SIZE]) -> bool {
        let computed = self.sign_parts(parts);
        use subtle::ConstantTimeEq;
        computed.ct_eq(expected_hmac).into()
    }
}

pub struct SignedWriter<W> {
    inner: W,
    signer: Arc<IpcSigner>,
    buffer: Vec<u8>,
}

impl<W> SignedWriter<W> {
    pub fn new(inner: W, signer: Arc<IpcSigner>) -> Self {
        Self {
            inner,
            signer,
            buffer: Vec::new(),
        }
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for SignedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        let timestamp = crate::utils::current_timestamp();
        let nonce = generate_nonce();
        let ts_bytes = timestamp.to_be_bytes();
        let hmac = self.signer.sign_parts(&[&ts_bytes, &nonce, &self.buffer]);

        let total_len = (TIMESTAMP_SIZE + NONCE_SIZE + HMAC_SIZE + self.buffer.len()) as u32;
        self.inner.write_all(&total_len.to_be_bytes())?;
        self.inner.write_all(&ts_bytes)?;
        self.inner.write_all(&nonce)?;
        self.inner.write_all(&hmac)?;
        self.inner.write_all(&self.buffer)?;
        self.inner.flush()?;

        self.buffer.clear();
        Ok(())
    }
}

pub struct SignedReader<R> {
    inner: R,
    signer: Arc<IpcSigner>,
    payload_buffer: Vec<u8>,
    payload_pos: usize,
}

impl<R: Read> SignedReader<R> {
    pub fn new(inner: R, signer: Arc<IpcSigner>) -> Self {
        Self {
            inner,
            signer,
            payload_buffer: Vec::new(),
            payload_pos: 0,
        }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }

    fn read_message(&mut self) -> io::Result<()> {
        let mut len_buf = [0u8; 4];
        self.inner.read_exact(&mut len_buf).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                io::Error::new(io::ErrorKind::UnexpectedEof, "EOF reading len")
            } else {
                e
            }
        })?;
        let total_len = u32::from_be_bytes(len_buf) as usize;

        if !(TIMESTAMP_SIZE + NONCE_SIZE + HMAC_SIZE..=MAX_IPC_MESSAGE_SIZE).contains(&total_len) {
            increment_oversized_rejected();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "signed message size invalid",
            ));
        }

        let mut raw = vec![0u8; total_len];
        self.inner.read_exact(&mut raw)?;

        let timestamp = u64::from_be_bytes(
            raw[0..TIMESTAMP_SIZE]
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad timestamp"))?,
        );

        if !verify_timestamp(timestamp) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message timestamp outside replay window",
            ));
        }

        let nonce: [u8; 16] = raw[TIMESTAMP_SIZE..TIMESTAMP_SIZE + NONCE_SIZE]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad nonce"))?;

        let hmac: [u8; HMAC_SIZE] = raw
            [TIMESTAMP_SIZE + NONCE_SIZE..TIMESTAMP_SIZE + NONCE_SIZE + HMAC_SIZE]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad hmac"))?;

        let payload = &raw[TIMESTAMP_SIZE + NONCE_SIZE + HMAC_SIZE..];
        let ts_bytes = timestamp.to_be_bytes();

        if !self
            .signer
            .verify_parts(&[&ts_bytes, &nonce, payload], &hmac)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HMAC verification failed",
            ));
        }

        if !check_and_insert_nonce(&nonce, timestamp) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "replay detected: duplicate nonce",
            ));
        }

        let header_len = TIMESTAMP_SIZE + NONCE_SIZE + HMAC_SIZE;
        raw.drain(..header_len);
        self.payload_buffer = raw;
        self.payload_pos = 0;
        Ok(())
    }
}

impl<R: Read> Read for SignedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.payload_pos >= self.payload_buffer.len() {
            match self.read_message() {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                Err(e) => return Err(e),
            }
        }

        let available = &self.payload_buffer[self.payload_pos..];
        let to_copy = available.len().min(buf.len());
        buf[..to_copy].copy_from_slice(&available[..to_copy]);
        self.payload_pos += to_copy;
        Ok(to_copy)
    }
}

pub struct SignedIpcMessage {
    pub payload: Vec<u8>,
    pub timestamp: u64,
    pub nonce: [u8; 16],
    pub hmac: Option<[u8; HMAC_SIZE]>,
}

impl SignedIpcMessage {
    pub fn new(
        payload: Vec<u8>,
        timestamp: u64,
        nonce: [u8; 16],
        hmac: Option<[u8; HMAC_SIZE]>,
    ) -> Self {
        Self {
            payload,
            timestamp,
            nonce,
            hmac,
        }
    }

    pub fn serialize_signed<T: serde::Serialize>(
        msg: &T,
        signer: &IpcSigner,
    ) -> io::Result<Vec<u8>> {
        let payload = crate::serialization::serialize(msg)?;

        let timestamp = crate::utils::current_timestamp();
        let nonce = generate_nonce();
        let ts_bytes = timestamp.to_be_bytes();
        let hmac = signer.sign_parts(&[&ts_bytes, &nonce, &payload]);

        let total_len = (TIMESTAMP_SIZE + NONCE_SIZE + HMAC_SIZE + payload.len()) as u32;
        let mut result = Vec::with_capacity(4 + total_len as usize);
        result.extend_from_slice(&total_len.to_be_bytes());
        result.extend_from_slice(&ts_bytes);
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&hmac);
        result.extend_from_slice(&payload);

        Ok(result)
    }

    pub fn deserialize_signed<T: serde::de::DeserializeOwned>(
        data: &[u8],
        signer: &IpcSigner,
    ) -> io::Result<T> {
        if data.len() < 4 + TIMESTAMP_SIZE + NONCE_SIZE + HMAC_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "signed message too short",
            ));
        }

        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if !(TIMESTAMP_SIZE + NONCE_SIZE + HMAC_SIZE..=MAX_IPC_MESSAGE_SIZE).contains(&len) {
            increment_oversized_rejected();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "signed message size invalid",
            ));
        }
        if data.len() < 4 + len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "signed message incomplete",
            ));
        }

        let timestamp =
            u64::from_be_bytes(data[4..4 + TIMESTAMP_SIZE].try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "timestamp extraction failed")
            })?);

        if !verify_timestamp(timestamp) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message timestamp outside replay window",
            ));
        }

        let nonce: [u8; 16] = data[4 + TIMESTAMP_SIZE..4 + TIMESTAMP_SIZE + NONCE_SIZE]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "nonce extraction failed"))?;

        let hmac: [u8; HMAC_SIZE] = data
            [4 + TIMESTAMP_SIZE + NONCE_SIZE..4 + TIMESTAMP_SIZE + NONCE_SIZE + HMAC_SIZE]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "HMAC extraction failed"))?;

        let payload = &data[4 + TIMESTAMP_SIZE + NONCE_SIZE + HMAC_SIZE..4 + len];
        let ts_bytes = timestamp.to_be_bytes();

        if !signer.verify_parts(&[&ts_bytes, &nonce, payload], &hmac) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HMAC verification failed",
            ));
        }

        if !check_and_insert_nonce(&nonce, timestamp) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "replay detected: duplicate nonce",
            ));
        }

        crate::serialization::deserialize(payload)
    }

    pub fn deserialize_signed_from_stream<R: Read>(
        stream: &mut R,
        signer: &IpcSigner,
    ) -> io::Result<Option<Message>> {
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }

        let total_len = u32::from_be_bytes(len_buf) as usize;
        if !(TIMESTAMP_SIZE + NONCE_SIZE + HMAC_SIZE..=MAX_IPC_MESSAGE_SIZE).contains(&total_len) {
            increment_oversized_rejected();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "signed message size invalid",
            ));
        }

        let mut raw = vec![0u8; total_len];
        stream.read_exact(&mut raw).map_err(io::Error::other)?;

        let timestamp = u64::from_be_bytes(
            raw[0..TIMESTAMP_SIZE]
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad timestamp"))?,
        );

        if !verify_timestamp(timestamp) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message timestamp outside replay window",
            ));
        }

        let nonce: [u8; 16] = raw[TIMESTAMP_SIZE..TIMESTAMP_SIZE + NONCE_SIZE]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad nonce"))?;

        let hmac: [u8; HMAC_SIZE] = raw
            [TIMESTAMP_SIZE + NONCE_SIZE..TIMESTAMP_SIZE + NONCE_SIZE + HMAC_SIZE]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad hmac"))?;

        let payload = &raw[TIMESTAMP_SIZE + NONCE_SIZE + HMAC_SIZE..];
        let ts_bytes = timestamp.to_be_bytes();

        if !signer.verify_parts(&[&ts_bytes, &nonce, payload], &hmac) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HMAC verification failed",
            ));
        }

        if !check_and_insert_nonce(&nonce, timestamp) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "replay detected: duplicate nonce",
            ));
        }

        crate::serialization::deserialize(payload).map(Some)
    }
}

pub fn generate_session_key() -> [u8; 32] {
    // rand::rng() in rand 0.9+ uses OsRng internally - acceptable for key generation
    use rand::RngCore;
    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);
    key
}

#[cfg(unix)]
fn read_ipc_key_file_impl(path: &std::path::Path) -> Option<Arc<IpcSigner>> {
    use std::fs::OpenOptions;
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_EXCL | libc::O_NOFOLLOW)
        .open(path)
        .ok()?;

    let mut reader = std::io::BufReader::new(file);
    let mut key_hex = String::new();
    reader.read_to_string(&mut key_hex).ok()?;
    drop(reader);

    let _ = std::fs::remove_file(path);

    let key_hex = key_hex.trim();
    let key = parse_hex_key(key_hex).ok()?;
    Some(Arc::new(IpcSigner::new(&key)))
}

#[cfg(not(unix))]
fn read_ipc_key_file_impl(path: &std::path::Path) -> Option<Arc<IpcSigner>> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() {
        return None;
    }
    if !meta.is_file() {
        return None;
    }
    if meta.len() < 64 || meta.len() > 128 {
        return None;
    }

    let key_hex = std::fs::read_to_string(path).ok()?;
    let _ = std::fs::remove_file(path);
    let key = parse_hex_key(key_hex.trim()).ok()?;
    Some(Arc::new(IpcSigner::new(&key)))
}

pub fn read_ipc_key_file(key_file: &str) -> Option<Arc<IpcSigner>> {
    read_ipc_key_file_impl(std::path::Path::new(key_file))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let key = generate_session_key();
        let signer = IpcSigner::new(&key);

        let data = b"test message";
        let hmac = signer.sign(data);

        assert!(signer.verify(data, &hmac));
        assert!(!signer.verify(b"different message", &hmac));
    }

    #[test]
    fn test_serialize_signed() {
        let key = generate_session_key();
        let signer = IpcSigner::new(&key);

        let msg = vec![1u8, 2, 3, 4];

        let signed = SignedIpcMessage::serialize_signed(&msg, &signer).unwrap();
        let decoded: Vec<u8> = SignedIpcMessage::deserialize_signed(&signed, &signer).unwrap();

        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_invalid_hmac() {
        let key = generate_session_key();
        let signer = IpcSigner::new(&key);

        let msg = vec![1u8, 2, 3, 4];

        let signed = SignedIpcMessage::serialize_signed(&msg, &signer).unwrap();

        let mut tampered = signed.clone();
        tampered[30] ^= 0xFF;

        let result: Result<Vec<u8>, _> = SignedIpcMessage::deserialize_signed(&tampered, &signer);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_cache_reject_duplicate() {
        let nonce = [0xABu8; 16];
        let timestamp = 1234567890u64;
        assert!(check_and_insert_nonce(&nonce, timestamp));
        assert!(!check_and_insert_nonce(&nonce, timestamp));
    }

    #[test]
    fn test_signed_writer_reader_roundtrip() {
        let key = generate_session_key();
        let signer = Arc::new(IpcSigner::new(&key));

        let mut writer = SignedWriter::new(Vec::new(), signer.clone());
        let data = b"hello signed world";
        writer.write_all(data).unwrap();
        writer.flush().unwrap();

        let raw = writer.into_inner();

        let mut reader = SignedReader::new(raw.as_slice(), signer);

        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn test_signed_reader_tampered_payload() {
        let key = generate_session_key();
        let signer = Arc::new(IpcSigner::new(&key));

        let mut writer = SignedWriter::new(Vec::new(), signer.clone());
        writer.write_all(b"original").unwrap();
        writer.flush().unwrap();

        let mut raw = writer.into_inner();
        raw[20] ^= 0xFF;

        let mut reader = SignedReader::new(raw.as_slice(), signer);
        let mut out = Vec::new();
        let result = reader.read_to_end(&mut out);
        assert!(result.is_err());
    }

    #[test]
    fn test_oversized_rejected_signed_deserialize() {
        let key = generate_session_key();
        let signer = IpcSigner::new(&key);

        let oversized_len = (MAX_IPC_MESSAGE_SIZE + 1) as u32;
        let mut data = Vec::with_capacity(4 + 56);
        data.extend_from_slice(&oversized_len.to_be_bytes());
        data.extend_from_slice(&[0u8; 56]);

        let result: Result<Vec<u8>, _> = SignedIpcMessage::deserialize_signed(&data, &signer);
        assert!(result.is_err());
    }

    #[test]
    fn test_oversized_rejected_signed_reader() {
        let key = generate_session_key();
        let signer = Arc::new(IpcSigner::new(&key));

        let oversized_len = (MAX_IPC_MESSAGE_SIZE + 1) as u32;
        let mut data = Vec::new();
        data.extend_from_slice(&oversized_len.to_be_bytes());
        data.extend_from_slice(&[0u8; 8]);

        let mut reader = SignedReader::new(data.as_slice(), signer);
        let mut out = Vec::new();
        let result = reader.read_to_end(&mut out);
        assert!(result.is_err());
    }

    #[test]
    fn test_oversized_rejected_unsigned_framing() {
        let mut buf = Vec::new();
        let large_msg = vec![0u8; super::super::ipc_framing::MAX_MESSAGE_SIZE + 1];
        let result: Result<(), _> =
            super::super::ipc_framing::write_message_sync(&mut buf, &large_msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_signed_unsigned_length_semantics_agree() {
        assert_eq!(
            super::super::ipc_framing::MAX_MESSAGE_SIZE,
            MAX_IPC_MESSAGE_SIZE
        );
    }

    #[test]
    fn test_multiple_messages_sequential() {
        let key = generate_session_key();
        let signer = Arc::new(IpcSigner::new(&key));

        let mut writer = SignedWriter::new(Vec::new(), signer.clone());

        let messages: &[&[u8]] = &[b"first", b"second", b"third"];
        for msg in messages {
            writer.write_all(msg).unwrap();
            writer.flush().unwrap();
        }

        let raw = writer.into_inner();
        let mut reader = SignedReader::new(raw.as_slice(), signer);

        for msg in messages {
            let mut buf = vec![0u8; msg.len()];
            reader.read_exact(&mut buf).unwrap();
            assert_eq!(&buf[..], *msg);
        }
    }

    #[test]
    fn test_oversized_counter_increments() {
        let key = generate_session_key();
        let signer = IpcSigner::new(&key);

        let before = oversized_rejected_count();

        let oversized_len = (MAX_IPC_MESSAGE_SIZE + 1) as u32;
        let mut data = Vec::with_capacity(4 + 56);
        data.extend_from_slice(&oversized_len.to_be_bytes());
        data.extend_from_slice(&[0u8; 56]);
        let _: Result<Vec<u8>, _> = SignedIpcMessage::deserialize_signed(&data, &signer);

        assert!(oversized_rejected_count() > before);
    }

    #[test]
    fn test_unsigned_message_rejected_when_signer_expected() {
        let key = generate_session_key();
        let signer = IpcSigner::new(&key);

        let payload = vec![1u8, 2, 3, 4];
        let unsigned_frame = {
            let len = payload.len() as u32;
            let mut buf = Vec::with_capacity(4 + payload.len());
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(&payload);
            buf
        };

        let result: Result<Vec<u8>, _> =
            SignedIpcMessage::deserialize_signed(&unsigned_frame, &signer);
        assert!(
            result.is_err(),
            "Unsigned payload must be rejected by signed deserializer, but got: {:?}",
            result
        );
    }

    #[test]
    fn test_tampered_timestamp_rejected() {
        let key = generate_session_key();
        let signer = IpcSigner::new(&key);

        let msg = vec![42u8; 100];
        let mut signed = SignedIpcMessage::serialize_signed(&msg, &signer).unwrap();

        let old_ts = u64::from_be_bytes(signed[4..12].try_into().unwrap());
        let bad_ts = old_ts.wrapping_add(999999);
        signed[4..12].copy_from_slice(&bad_ts.to_be_bytes());

        let result: Result<Vec<u8>, _> = SignedIpcMessage::deserialize_signed(&signed, &signer);
        assert!(result.is_err());
    }
}
