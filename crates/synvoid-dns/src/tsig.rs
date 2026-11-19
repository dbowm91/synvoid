use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::runtime_config::{TsigAlgorithmRuntime, TsigRuntimeKey};
use crate::time::unix_timestamp_secs;
use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;

use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

const TSIG_REPLAY_CACHE_TTL_SECS: u64 = 300;
const MAX_REPLAY_CACHE_SIZE: usize = 10000;

/// TSIG error BADSIG (RFC 8945 §5.2.2).
pub const TSIG_ERROR_BADSIG: u16 = 16;
/// TSIG error BADKEY (RFC 8945 §5.2.1).
pub const TSIG_ERROR_BADKEY: u16 = 17;
/// TSIG error BADTIME (RFC 8945 §5.2.3).
pub const TSIG_ERROR_BADTIME: u16 = 18;

/// RFC 8945 §5.2.2.1: the smallest MAC a verifier may accept is
/// `max(10, half the algorithm output length)`.
fn minimum_mac_len(algorithm_output: usize) -> usize {
    (algorithm_output / 2).max(10)
}

struct ReplayCacheEntry {
    timestamp: Instant,
}

struct ReplayCache {
    entries: HashMap<Vec<u8>, ReplayCacheEntry>,
    last_cleanup: Instant,
}

impl ReplayCache {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }

    fn is_replay(&self, mac_hash: &[u8]) -> bool {
        self.entries.contains_key(mac_hash)
    }

    fn insert(&mut self, mac_hash: Vec<u8>) {
        if self.last_cleanup.elapsed().as_secs() >= TSIG_REPLAY_CACHE_TTL_SECS {
            self.cleanup_expired();
        }

        if self.entries.len() >= MAX_REPLAY_CACHE_SIZE {
            self.evict_oldest();
        }
        self.entries.insert(
            mac_hash,
            ReplayCacheEntry {
                timestamp: Instant::now(),
            },
        );
    }

    fn evict_oldest(&mut self) {
        let key_to_remove = self
            .entries
            .iter()
            .min_by_key(|(_, v)| v.timestamp)
            .map(|(k, _)| k.clone());
        if let Some(key) = key_to_remove {
            self.entries.remove(&key);
        }
    }

    fn cleanup_expired(&mut self) {
        let cutoff = Instant::now()
            .checked_sub(std::time::Duration::from_secs(TSIG_REPLAY_CACHE_TTL_SECS))
            .unwrap_or(Instant::now());
        self.entries.retain(|_, v| v.timestamp > cutoff);
        self.last_cleanup = Instant::now();
    }

    fn compute_mac_hash(mac: &[u8]) -> Vec<u8> {
        Sha256::digest(mac).to_vec()
    }
}

#[derive(Clone)]
pub struct TsigKey {
    pub name: String,
    pub secret: Vec<u8>,
    pub algorithm: TsigAlgorithmRuntime,
}

impl TsigKey {
    /// Build from a DNS-owned runtime key.
    ///
    /// The application-owned adapter already base64-decoded and
    /// length-checked the secret, so this is normally infallible. The
    /// length check is repeated here because `TsigVerifier::new` is public
    /// and a hand-built `TsigRuntimeKey` must never reach the verifier with an
    /// undersized secret. The error carries the key name and algorithm only,
    /// never secret bytes.
    pub fn from_runtime(key: &TsigRuntimeKey) -> Result<Self, String> {
        if key.secret.len() < key.algorithm.min_secret_len() {
            return Err(format!(
                "TSIG key '{}' secret too short for {}",
                key.name,
                key.algorithm.as_str()
            ));
        }

        Ok(Self {
            name: key.name.clone(),
            secret: key.secret.clone(),
            algorithm: key.algorithm,
        })
    }
}

/// A TSIG RR emitted by [`TsigVerifier::sign_response`], with the MAC that a
/// subsequent message in the same transfer must carry in its own digest
/// (RFC 8945 §5.3.1).
pub struct SignedTsig {
    pub rr: Vec<u8>,
    pub mac: Vec<u8>,
}

pub struct TsigVerifier {
    keys: Arc<RwLock<HashMap<String, TsigKey>>>,
    replay_cache: Arc<RwLock<ReplayCache>>,
}

impl TsigVerifier {
    pub fn new(keys_config: Vec<TsigRuntimeKey>) -> Result<Self, String> {
        let mut keys = HashMap::new();

        for config in keys_config {
            let key = TsigKey::from_runtime(&config)?;
            // RFC 8945 §4.2: TSIG names are DNS names, so lookup is
            // case-insensitive. Store the folded form once.
            keys.insert(key.name.to_ascii_lowercase(), key);
        }

        Ok(Self {
            keys: Arc::new(RwLock::new(keys)),
            replay_cache: Arc::new(RwLock::new(ReplayCache::new())),
        })
    }

    pub fn add_key(&self, config: TsigRuntimeKey) -> Result<(), String> {
        let key = TsigKey::from_runtime(&config)?;
        self.keys.write().insert(key.name.to_ascii_lowercase(), key);
        Ok(())
    }

    pub fn remove_key(&self, name: &str) -> Option<TsigKey> {
        self.keys.write().remove(&name.to_ascii_lowercase())
    }

    /// Verify a request's TSIG RR against the message it arrived in.
    ///
    /// The digest is RFC 8945 §5.2 canonical:
    ///
    /// ```text
    /// HMAC(key, message-without-TSIG || tsig_variables)
    /// ```
    ///
    /// where `message-without-TSIG` is the received message with the TSIG RR
    /// removed and ARCOUNT decremented. Verification order follows §5.2:
    /// key name and algorithm, MAC (with the truncation policy), time within
    /// fudge, then the replay cache.
    pub fn verify(&self, message: &[u8], tsig: &TsigParseResult) -> Result<(), TsigError> {
        // A request may not carry a TSIG error: the error field is only
        // meaningful in a signed response.
        if tsig.tsig_error != 0 {
            return Err(TsigError::BadSignature);
        }

        let keys = self.keys.read();
        let lookup = tsig.key_name.to_ascii_lowercase();
        let key = keys
            .get(&lookup)
            .ok_or_else(|| TsigError::UnknownKey(tsig.key_name.clone()))?;

        // RFC 8945 §5.2.1: the algorithm in the TSIG RR must be the one the
        // key was configured with; otherwise this is BADKEY.
        if key.algorithm.to_u16() != tsig.algorithm {
            return Err(TsigError::AlgorithmMismatch);
        }

        let message_without_tsig = strip_tsig(message, tsig).ok_or_else(|| {
            TsigError::ParseError("TSIG RR does not fit the message it verifies".to_string())
        })?;

        let variables = tsig_variables(
            &tsig.key_name,
            &tsig.algorithm_name,
            tsig.time_signed,
            tsig.fudge,
            tsig.tsig_error,
            &tsig.other_data,
        )
        .ok_or_else(|| TsigError::ParseError("TSIG name is not a valid domain name".to_string()))?;

        let mut data_to_sign = message_without_tsig;
        data_to_sign.extend_from_slice(&variables);

        let computed_mac = compute_mac(key.algorithm, &key.secret, &data_to_sign)?;

        // RFC 8945 §5.2.2: a MAC longer than the algorithm output is a
        // format error, never a longer secret.
        if tsig.mac.len() > computed_mac.len() {
            return Err(TsigError::MacTooLong {
                algorithm: computed_mac.len(),
                actual: tsig.mac.len(),
            });
        }
        // RFC 8945 §5.2.2.1 truncation policy: at least half the digest and
        // never fewer than 10 octets.
        let minimum = minimum_mac_len(computed_mac.len());
        if tsig.mac.len() < minimum {
            return Err(TsigError::MacTooShort {
                minimum,
                actual: tsig.mac.len(),
            });
        }

        let expected = &computed_mac[..tsig.mac.len()];
        if !bool::from(expected.ct_eq(tsig.mac.as_slice())) {
            return Err(TsigError::MacVerificationFailed);
        }

        // Time last, so a forged MAC never gets a time oracle (RFC 8945
        // §5.2.3).
        let now = unix_timestamp_secs();
        if tsig.time_signed.abs_diff(now) > u64::from(tsig.fudge) {
            return Err(TsigError::TimeInvalid);
        }

        // The replay cache is keyed on the computed full MAC — the canonical
        // value that verified — so neither garbage nor a different truncation
        // of the same MAC can bypass it.
        let mac_hash = ReplayCache::compute_mac_hash(&computed_mac);
        let mut cache = self.replay_cache.write();
        if cache.is_replay(&mac_hash) {
            return Err(TsigError::ReplayAttack);
        }
        cache.insert(mac_hash);

        Ok(())
    }

    /// Sign a request (no request MAC in the digest) and return the complete
    /// TSIG RR to append to the message.
    pub fn sign(
        &self,
        key_name: &str,
        message: &[u8],
        tsig_error: u16,
    ) -> Result<Vec<u8>, TsigError> {
        self.sign_response(key_name, message, None, tsig_error)
            .map(|signed| signed.rr)
    }

    /// Sign a response and return the complete TSIG RR plus the MAC it
    /// carries.
    ///
    /// `message` is the response **without** its TSIG RR (ARCOUNT does not
    /// count the TSIG being added). `request_mac` is the verified MAC of the
    /// request this response answers; RFC 8945 §5.3.1 also requires every
    /// message after the first in a multi-message response to carry the
    /// previous message's MAC here.
    pub fn sign_response(
        &self,
        key_name: &str,
        message: &[u8],
        request_mac: Option<&[u8]>,
        tsig_error: u16,
    ) -> Result<SignedTsig, TsigError> {
        let keys = self.keys.read();
        let key = keys
            .get(&key_name.to_ascii_lowercase())
            .ok_or_else(|| TsigError::UnknownKey(key_name.to_string()))?;

        let now = unix_timestamp_secs();
        let fudge: u16 = 300;
        let algorithm_name = key.algorithm.as_str();
        let original_id = if message.len() >= 2 {
            u16::from_be_bytes([message[0], message[1]])
        } else {
            0
        };

        let variables = tsig_variables(key_name, algorithm_name, now, fudge, tsig_error, &[])
            .ok_or_else(|| {
                TsigError::ParseError("TSIG key name is not a domain name".to_string())
            })?;

        let mut data_to_sign = Vec::new();
        if let Some(request_mac) = request_mac {
            let mac_len = u16::try_from(request_mac.len())
                .map_err(|_| TsigError::ParseError("request MAC too long".to_string()))?;
            data_to_sign.extend_from_slice(&mac_len.to_be_bytes());
            data_to_sign.extend_from_slice(request_mac);
        }
        data_to_sign.extend_from_slice(message);
        data_to_sign.extend_from_slice(&variables);

        let mac = compute_mac(key.algorithm, &key.secret, &data_to_sign)?;

        let mut rdata = Vec::new();
        rdata.extend_from_slice(&encode_canonical_name(algorithm_name).ok_or_else(|| {
            TsigError::ParseError("TSIG algorithm name is not a domain name".to_string())
        })?);
        rdata.extend_from_slice(&now.to_be_bytes()[2..8]);
        rdata.extend_from_slice(&fudge.to_be_bytes());
        rdata.extend_from_slice(&(mac.len() as u16).to_be_bytes());
        rdata.extend_from_slice(&mac);
        rdata.extend_from_slice(&original_id.to_be_bytes());
        rdata.extend_from_slice(&tsig_error.to_be_bytes());
        rdata.extend_from_slice(&0u16.to_be_bytes());

        let mut rr = Vec::with_capacity(rdata.len() + 32);
        rr.extend_from_slice(&encode_canonical_name(key_name).ok_or_else(|| {
            TsigError::ParseError("TSIG key name is not a domain name".to_string())
        })?);
        rr.extend_from_slice(&TSIG_TYPE.to_be_bytes());
        rr.extend_from_slice(&TSIG_CLASS_ANY.to_be_bytes());
        rr.extend_from_slice(&0u32.to_be_bytes());
        rr.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        rr.extend_from_slice(&rdata);

        Ok(SignedTsig { rr, mac })
    }
}

#[derive(Debug, Clone, Error)]
pub enum TsigError {
    #[error("Unknown TSIG key: {0}")]
    UnknownKey(String),
    #[error("Invalid TSIG key")]
    InvalidKey,
    #[error("TSIG MAC verification failed")]
    MacVerificationFailed,
    #[error("TSIG MAC length mismatch: expected {expected}, got {actual}")]
    MacMismatch { expected: usize, actual: usize },
    #[error("TSIG MAC is longer than the {algorithm}-byte algorithm output ({actual})")]
    MacTooLong { algorithm: usize, actual: usize },
    #[error("TSIG MAC is shorter than the {minimum}-byte truncation floor ({actual})")]
    MacTooShort { minimum: usize, actual: usize },
    #[error("TSIG time out of valid range")]
    TimeInvalid,
    #[error("TSIG error code indicates failure")]
    BadSignature,
    #[error("TSIG algorithm mismatch")]
    AlgorithmMismatch,
    #[error("TSIG parse error: {0}")]
    ParseError(String),
    #[error("TSIG replay attack detected")]
    ReplayAttack,
}

impl TsigError {
    /// The RFC 8945 TSIG error code for this failure, when the failure is a
    /// TSIG error rather than a message format error.
    ///
    /// `None` means FORMERR: the TSIG RR itself is structurally invalid, so
    /// no TSIG error token can be returned (RFC 8945 §5.2.2).
    pub fn tsig_error_code(&self) -> Option<u16> {
        match self {
            TsigError::UnknownKey(_) | TsigError::AlgorithmMismatch => Some(TSIG_ERROR_BADKEY),
            TsigError::TimeInvalid => Some(TSIG_ERROR_BADTIME),
            TsigError::MacVerificationFailed
            | TsigError::MacMismatch { .. }
            | TsigError::MacTooShort { .. }
            | TsigError::BadSignature
            | TsigError::ReplayAttack => Some(TSIG_ERROR_BADSIG),
            TsigError::MacTooLong { .. } | TsigError::ParseError(_) | TsigError::InvalidKey => None,
        }
    }
}

const TSIG_TYPE: u16 = 250;
const TSIG_CLASS_ANY: u16 = 255;

/// Encode a domain name in canonical wire form: uncompressed, lowercase, and
/// root-terminated (RFC 8945 §4.3.3 uses names in this form inside the digest).
pub(crate) fn encode_canonical_name(name: &str) -> Option<Vec<u8>> {
    let trimmed = name.trim().trim_end_matches('.');
    let mut out = Vec::with_capacity(trimmed.len() + 2);
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            if label.is_empty() || label.len() > 63 {
                return None;
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.to_ascii_lowercase().as_bytes());
        }
    }
    out.push(0);
    Some(out)
}

/// The RFC 8945 §4.3.3 TSIG variables, in wire order.
fn tsig_variables(
    key_name: &str,
    algorithm_name: &str,
    time_signed: u64,
    fudge: u16,
    error: u16,
    other_data: &[u8],
) -> Option<Vec<u8>> {
    let mut variables = Vec::new();
    variables.extend_from_slice(&encode_canonical_name(key_name)?);
    variables.extend_from_slice(&TSIG_CLASS_ANY.to_be_bytes());
    variables.extend_from_slice(&0u32.to_be_bytes());
    variables.extend_from_slice(&encode_canonical_name(algorithm_name)?);
    variables.extend_from_slice(&time_signed.to_be_bytes()[2..8]);
    variables.extend_from_slice(&fudge.to_be_bytes());
    variables.extend_from_slice(&error.to_be_bytes());
    variables.extend_from_slice(&(other_data.len() as u16).to_be_bytes());
    variables.extend_from_slice(other_data);
    Some(variables)
}

fn compute_mac(
    algorithm: TsigAlgorithmRuntime,
    secret: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, TsigError> {
    let mac = match algorithm {
        TsigAlgorithmRuntime::HmacSha256 => {
            let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| TsigError::InvalidKey)?;
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        TsigAlgorithmRuntime::HmacSha384 => {
            let mut mac = HmacSha384::new_from_slice(secret).map_err(|_| TsigError::InvalidKey)?;
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        TsigAlgorithmRuntime::HmacSha512 => {
            let mut mac = HmacSha512::new_from_slice(secret).map_err(|_| TsigError::InvalidKey)?;
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
    };
    Ok(mac)
}

/// The message a TSIG digest covers: the received message with the TSIG RR
/// removed and ARCOUNT decremented.
///
/// [`TsigParseResult::original_offset`] is the first byte of the TSIG RR, and
/// the parser rejects any record after it, so this is an exact cut.
fn strip_tsig(message: &[u8], tsig: &TsigParseResult) -> Option<Vec<u8>> {
    if message.len() < 12 || tsig.original_offset < 12 || tsig.original_offset > message.len() {
        return None;
    }
    let arcount = u16::from_be_bytes([message[10], message[11]]);
    let new_arcount = arcount.checked_sub(1)?;

    let mut stripped = Vec::with_capacity(tsig.original_offset);
    stripped.extend_from_slice(&message[..tsig.original_offset]);
    stripped[10..12].copy_from_slice(&new_arcount.to_be_bytes());
    Some(stripped)
}

/// A cursor over one bounded byte slice.
///
/// Every read either advances `pos` past the bytes it returned or fails with
/// `None`; no method can index outside `buf`. TSIG parsing is reachable before
/// any ACL check on a transfer, so a hostile packet must never be able to make
/// this module read past the datagram.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8], pos: usize) -> Self {
        Self {
            buf,
            pos: pos.min(buf.len()),
        }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let bytes = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(bytes)
    }

    fn u16(&mut self) -> Option<u16> {
        let bytes = self.take(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        let bytes = self.take(4)?;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u48(&mut self) -> Option<u64> {
        let bytes = self.take(6)?;
        Some(
            (u64::from(bytes[0]) << 40)
                | (u64::from(bytes[1]) << 32)
                | (u64::from(bytes[2]) << 24)
                | (u64::from(bytes[3]) << 16)
                | (u64::from(bytes[4]) << 8)
                | u64::from(bytes[5]),
        )
    }

    /// Read an uncompressed domain name and return its dotted presentation
    /// form (no trailing dot; `""` for the root).
    ///
    /// A TSIG owner and algorithm name are never compressed (RFC 8945 §4.2),
    /// so a pointer is a malformed record rather than a name to follow.
    fn name(&mut self) -> Option<String> {
        let mut name = String::new();
        loop {
            let len = *self.buf.get(self.pos)? as usize;
            if len == 0 {
                self.pos += 1;
                return Some(name);
            }
            if (len & 0xC0) == 0xC0 || len > 63 {
                return None;
            }
            // Consume the length octet before taking the label bytes.
            self.pos += 1;
            let label = self.take(len)?;
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(&String::from_utf8_lossy(label));
        }
    }
}

/// Parse the TSIG resource record from a query's additional section.
///
/// `qd_end` is the byte after the question section. Every preceding resource
/// record is walked by its own `RDLENGTH`, and the TSIG RDATA is parsed inside
/// exactly its declared `RDLENGTH`:
///
/// ```text
/// NAME ALGORITHM TIME FUDGE MAC-SIZE MAC ORIGINAL-ID ERROR OTHER-LEN OTHER-DATA
/// ```
///
/// `Ok(None)` means the message carries no TSIG RR. `Err` means a TSIG-shaped
/// record was present but did not fit its declared layout, or was not the last
/// record (RFC 8945 §5.2): the caller must answer FORMERR rather than treat
/// the message as unsigned. The parser never indexes outside the packet, so a
/// hostile name, MAC length, or trailing bytes are a rejection rather than a
/// panic.
pub fn parse_tsig_from_query(
    query: &[u8],
    qd_end: usize,
) -> Result<Option<TsigParseResult>, TsigError> {
    let mut reader = Reader::new(query, qd_end);
    loop {
        if reader.remaining() == 0 {
            return Ok(None);
        }

        // The record starts here; this is the cut point that removes it.
        let rr_start = reader.pos;
        let key_name = reader.name().ok_or_else(malformed_name)?;
        let rtype = reader.u16().ok_or_else(malformed_rr)?;
        let class = reader.u16().ok_or_else(malformed_rr)?;
        let ttl = reader.u32().ok_or_else(malformed_rr)?;
        let rdlen = reader.u16().ok_or_else(malformed_rr)? as usize;

        let rdata = reader.take(rdlen).ok_or_else(malformed_rr)?;

        if rtype != TSIG_TYPE {
            continue;
        }

        // RFC 8945 §5.2: the TSIG RR's class is ANY and its TTL is zero. A
        // record that disagrees is not a TSIG record we may authenticate.
        if class != TSIG_CLASS_ANY || ttl != 0 {
            return Err(TsigError::ParseError(
                "TSIG class must be ANY and TTL must be zero".to_string(),
            ));
        }

        let parsed = parse_tsig_rdata(rdata, key_name, rr_start)?;

        // RFC 8945 §5.2: TSIG MUST be the last record in the additional
        // section. A record after it would make the digest cut ambiguous.
        if reader.remaining() != 0 {
            return Err(TsigError::ParseError(
                "TSIG is not the final record in the message".to_string(),
            ));
        }

        return Ok(Some(parsed));
    }
}

fn malformed_name() -> TsigError {
    TsigError::ParseError("TSIG owner name is malformed".to_string())
}

fn malformed_rr() -> TsigError {
    TsigError::ParseError("TSIG record is truncated".to_string())
}

/// Parse one TSIG RDATA body, which is exactly `RDLENGTH` bytes.
fn parse_tsig_rdata(
    rdata: &[u8],
    key_name: String,
    original_offset: usize,
) -> Result<TsigParseResult, TsigError> {
    let mut reader = Reader::new(rdata, 0);

    let algorithm_name = reader.name().ok_or_else(malformed_name)?;
    let time_signed = reader.u48().ok_or_else(malformed_rr)?;
    let fudge = reader.u16().ok_or_else(malformed_rr)?;
    let mac_size = reader.u16().ok_or_else(malformed_rr)? as usize;
    let mac = reader
        .take(mac_size)
        .ok_or_else(|| TsigError::ParseError("TSIG MAC is truncated".to_string()))?
        .to_vec();
    let original_id = reader.u16().ok_or_else(malformed_rr)?;
    let tsig_error = reader.u16().ok_or_else(malformed_rr)?;
    let other_len = reader.u16().ok_or_else(malformed_rr)?;
    let other_data = reader
        .take(other_len as usize)
        .ok_or_else(|| TsigError::ParseError("TSIG other data is truncated".to_string()))?
        .to_vec();

    // The RDATA is exactly RDLENGTH bytes; anything left over means the
    // record's fields disagree with its declared length.
    if reader.remaining() != 0 {
        return Err(TsigError::ParseError(
            "TSIG RDATA has trailing bytes".to_string(),
        ));
    }

    Ok(TsigParseResult {
        key_name,
        algorithm: algorithm_code(&algorithm_name),
        algorithm_name,
        time_signed,
        fudge,
        mac,
        original_id,
        tsig_error,
        other_len,
        other_data,
        original_offset,
    })
}

/// Map a TSIG algorithm name to the runtime algorithm code.
///
/// The wire field is a domain name (RFC 8945 §4.2); `TsigParseResult` still
/// carries the numeric code because `TsigVerifier::verify` compares it to the
/// configured key's algorithm. An unknown name maps to zero and fails that
/// comparison, which is the same fail-closed outcome as an unsupported
/// algorithm.
fn algorithm_code(name: &str) -> u16 {
    match name.to_ascii_lowercase().as_str() {
        "hmac-sha256" => TsigAlgorithmRuntime::HmacSha256.to_u16(),
        "hmac-sha384" => TsigAlgorithmRuntime::HmacSha384.to_u16(),
        "hmac-sha512" => TsigAlgorithmRuntime::HmacSha512.to_u16(),
        _ => 0,
    }
}

#[derive(Debug, Clone)]
pub struct TsigParseResult {
    pub key_name: String,
    pub algorithm: u16,
    /// The algorithm name exactly as it appeared in the RDATA, used verbatim
    /// (canonicalised) inside the digest.
    pub algorithm_name: String,
    pub time_signed: u64,
    pub fudge: u16,
    pub mac: Vec<u8>,
    /// RFC 8945 §4.2 Original ID. Not part of the digest; carried so a
    /// conforming client can restore the message ID.
    pub original_id: u16,
    pub tsig_error: u16,
    pub other_len: u16,
    pub other_data: Vec<u8>,
    /// Byte offset of the first byte of the TSIG RR (its owner name). The
    /// bytes from here to the end of the message are exactly the TSIG RR,
    /// which makes this the cut point for the RFC 8945 digest.
    pub original_offset: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tsig_algorithm_u16() {
        assert_eq!(TsigAlgorithmRuntime::HmacSha256.to_u16(), 161);
        assert_eq!(TsigAlgorithmRuntime::HmacSha384.to_u16(), 170);
        assert_eq!(TsigAlgorithmRuntime::HmacSha512.to_u16(), 172);
    }

    #[test]
    fn test_tsig_algorithm_from_u16() {
        assert_eq!(
            TsigAlgorithmRuntime::from_u16(161),
            Some(TsigAlgorithmRuntime::HmacSha256)
        );
        assert_eq!(
            TsigAlgorithmRuntime::from_u16(170),
            Some(TsigAlgorithmRuntime::HmacSha384)
        );
        assert_eq!(
            TsigAlgorithmRuntime::from_u16(172),
            Some(TsigAlgorithmRuntime::HmacSha512)
        );
        assert_eq!(TsigAlgorithmRuntime::from_u16(999), None);
    }

    #[test]
    fn test_tsig_algorithm_dns_name() {
        assert_eq!(TsigAlgorithmRuntime::HmacSha256.as_str(), "hmac-sha256.");
        assert_eq!(TsigAlgorithmRuntime::HmacSha384.as_str(), "hmac-sha384.");
        assert_eq!(TsigAlgorithmRuntime::HmacSha512.as_str(), "hmac-sha512.");
    }

    /// Pins the minimum-secret threshold to the pre-cutover
    /// `TsigAlgorithm::key_size()` values (the HMAC output length). A
    /// regression to the HMAC input block size would silently accept weaker
    /// keys than the server rejected before the runtime-DTO cutover.
    #[test]
    fn test_tsig_algorithm_min_secret_len_matches_pre_cutover_key_size() {
        assert_eq!(TsigAlgorithmRuntime::HmacSha256.min_secret_len(), 32);
        assert_eq!(TsigAlgorithmRuntime::HmacSha384.min_secret_len(), 48);
        assert_eq!(TsigAlgorithmRuntime::HmacSha512.min_secret_len(), 64);
    }

    fn runtime_key(name: &str, secret_len: usize) -> TsigRuntimeKey {
        TsigRuntimeKey {
            name: name.to_string(),
            secret: vec![0x7C; secret_len],
            algorithm: TsigAlgorithmRuntime::HmacSha256,
        }
    }

    #[test]
    fn test_tsig_key_from_runtime() {
        let key = TsigKey::from_runtime(&runtime_key("test-key", 32)).unwrap();
        assert_eq!(key.name, "test-key");
        assert!(!key.secret.is_empty());
    }

    #[test]
    fn test_tsig_key_rejects_short_secret() {
        // 16 bytes is below the 32-byte HMAC-SHA256 minimum.
        assert!(TsigKey::from_runtime(&runtime_key("short-key", 16)).is_err());
    }

    /// The error names the key and algorithm but must never echo the secret.
    #[test]
    fn test_tsig_key_rejection_error_does_not_leak_the_secret() {
        let key = TsigRuntimeKey {
            name: "short-key".to_string(),
            secret: vec![0xDE, 0xAD, 0xBE, 0xEF],
            algorithm: TsigAlgorithmRuntime::HmacSha256,
        };
        let rendered = TsigKey::from_runtime(&key).err().expect("must reject");
        assert!(rendered.contains("short-key"));
        assert!(!rendered.contains("deadbeef"));
    }

    #[test]
    fn test_tsig_key_from_runtime_all_algorithms() {
        let algorithms = [
            TsigAlgorithmRuntime::HmacSha256,
            TsigAlgorithmRuntime::HmacSha384,
            TsigAlgorithmRuntime::HmacSha512,
        ];

        for algorithm in algorithms {
            let key = TsigRuntimeKey {
                name: format!("test-key-{algorithm:?}"),
                // Long enough for the strictest (HMAC-SHA512) threshold.
                secret: vec![0x7C; 64],
                algorithm,
            };

            let parsed = TsigKey::from_runtime(&key);
            assert!(
                parsed.is_ok(),
                "Should be able to create key for {algorithm:?}"
            );
        }
    }

    #[test]
    fn test_tsig_verifier() {
        let verifier = TsigVerifier::new(vec![runtime_key("test-key", 32)]).unwrap();
        assert!(verifier.remove_key("test-key").is_some());
    }

    #[test]
    fn test_tsig_verifier_add_remove_key() {
        let verifier = TsigVerifier::new(vec![]).unwrap();

        let key = runtime_key("new-key", 32);

        assert!(verifier.add_key(key.clone()).is_ok());
        assert!(verifier.remove_key("new-key").is_some());
        assert!(verifier.remove_key("nonexistent").is_none());
    }

    // ------------------------------------------------------------------
    // parse_tsig_from_query: bounded RR parsing (phase 03, D12)
    // ------------------------------------------------------------------

    /// The 48-bit time, 16-bit fudge, MAC, original ID, and error/other
    /// fields in RFC 8945 §4.2 order.
    fn tsig_rdata(algorithm: &str, time: u64, mac: &[u8], trailing: &[u8]) -> Vec<u8> {
        let mut rdata = Vec::new();
        for label in algorithm.trim_end_matches('.').split('.') {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0);
        rdata.extend_from_slice(&time.to_be_bytes()[2..8]);
        rdata.extend_from_slice(&300u16.to_be_bytes());
        rdata.extend_from_slice(&(mac.len() as u16).to_be_bytes());
        rdata.extend_from_slice(mac);
        rdata.extend_from_slice(&0x1234u16.to_be_bytes()); // original ID
        rdata.extend_from_slice(&0u16.to_be_bytes()); // error
        rdata.extend_from_slice(&(trailing.len() as u16).to_be_bytes());
        rdata.extend_from_slice(trailing);
        rdata
    }

    /// A query with one question and one additional RR carrying `rdata`.
    ///
    /// Returns the packet, the byte after the question, and the offset of the
    /// RR's owner name.
    fn query_with_rr(
        owner: &[u8],
        rtype: u16,
        class: u16,
        ttl: u32,
        rdata: &[u8],
    ) -> (Vec<u8>, usize, usize) {
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
        let qd_end = q.len();

        let rr_start = q.len();
        q.extend_from_slice(owner);
        q.extend_from_slice(&rtype.to_be_bytes());
        q.extend_from_slice(&class.to_be_bytes());
        q.extend_from_slice(&ttl.to_be_bytes());
        q.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        q.extend_from_slice(rdata);
        (q, qd_end, rr_start)
    }

    fn tsig_owner() -> Vec<u8> {
        let mut owner = Vec::new();
        owner.push(5);
        owner.extend_from_slice(b"mykey");
        owner.push(0);
        owner
    }

    /// `Ok(None)` is "no TSIG"; `Err` is "a TSIG that cannot be trusted".
    fn parsed(query: &[u8], qd_end: usize) -> Option<TsigParseResult> {
        parse_tsig_from_query(query, qd_end).ok().flatten()
    }

    #[test]
    fn a_conforming_tsig_record_parses_from_its_rdata() {
        let mac = [0x5Au8; 32];
        let rdata = tsig_rdata("hmac-sha256.", 1_700_000_000, &mac, &[]);
        let (query, qd_end, rr_start) =
            query_with_rr(&tsig_owner(), TSIG_TYPE, TSIG_CLASS_ANY, 0, &rdata);

        let parsed = parsed(&query, qd_end).expect("a conforming TSIG must parse");
        assert_eq!(parsed.key_name, "mykey");
        assert_eq!(parsed.algorithm, 161); // HMAC-SHA256
        assert_eq!(parsed.algorithm_name, "hmac-sha256");
        assert_eq!(parsed.time_signed, 1_700_000_000);
        assert_eq!(parsed.fudge, 300);
        assert_eq!(parsed.mac, mac);
        assert_eq!(parsed.original_id, 0x1234);
        assert_eq!(parsed.tsig_error, 0);
        assert_eq!(parsed.other_len, 0);
        assert_eq!(
            parsed.original_offset, rr_start,
            "the cut point is the first byte of the TSIG RR"
        );
    }

    #[test]
    fn a_tsig_name_ending_on_the_final_byte_is_rejected_without_panicking() {
        // The owner name's terminating zero is the last byte of the packet:
        // there is no TYPE left to read. The old scanner walked to `pos ==
        // len` and then indexed `query[pos]`.
        let (mut query, qd_end, rr_start) =
            query_with_rr(&tsig_owner(), TSIG_TYPE, TSIG_CLASS_ANY, 0, &[]);
        query.truncate(rr_start + tsig_owner().len());
        assert_eq!(*query.last().expect("non-empty"), 0);

        assert!(parsed(&query, qd_end).is_none());
        assert!(parse_tsig_from_query(&query, qd_end).is_err());
    }

    #[test]
    fn a_tsig_name_that_runs_past_the_packet_is_rejected_without_panicking() {
        let mut query = Vec::new();
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0x0100u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
        let qd_end = query.len();

        // A label claims 40 bytes but the packet ends immediately.
        query.push(40);
        assert!(parsed(&query, qd_end).is_none());
    }

    #[test]
    fn a_truncated_mac_is_rejected() {
        // RDATA declares a 32-byte MAC but the record ends after 16.
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&[11]);
        rdata.extend_from_slice(b"hmac-sha256");
        rdata.push(0);
        rdata.extend_from_slice(&[0, 0, 0, 0, 0, 1]); // time
        rdata.extend_from_slice(&300u16.to_be_bytes());
        rdata.extend_from_slice(&32u16.to_be_bytes()); // MAC size
        rdata.extend_from_slice(&[0xAA; 16]); // only half the MAC

        let (query, qd_end, _) = query_with_rr(&tsig_owner(), TSIG_TYPE, TSIG_CLASS_ANY, 0, &rdata);
        assert!(parsed(&query, qd_end).is_none());
    }

    #[test]
    fn trailing_bytes_after_the_tsig_rdata_are_rejected() {
        let rdata = tsig_rdata("hmac-sha256.", 1, &[0x11; 32], &[]);
        let mut with_trailing = rdata.clone();
        with_trailing.push(0xFF); // one byte past the declared fields
        let (query, qd_end, _) =
            query_with_rr(&tsig_owner(), TSIG_TYPE, TSIG_CLASS_ANY, 0, &with_trailing);
        assert!(parsed(&query, qd_end).is_none());
    }

    #[test]
    fn an_unsupported_tsig_algorithm_maps_to_an_unmatched_code() {
        let rdata = tsig_rdata("hmac-md5.sig-alg.reg.int.", 1, &[0x11; 16], &[]);
        let (query, qd_end, _) = query_with_rr(&tsig_owner(), TSIG_TYPE, TSIG_CLASS_ANY, 0, &rdata);
        let parsed = parsed(&query, qd_end).expect("the record layout is valid");
        assert_eq!(
            parsed.algorithm, 0,
            "unknown algorithms must not match a key"
        );
    }
}
