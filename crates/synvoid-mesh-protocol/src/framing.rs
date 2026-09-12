//! Bounded length-prefix framing helpers (fail-closed).
//!
//! Mirrors `MeshMessage::encode_with_length` / `decode_with_length` semantics
//! for raw wire bytes: 4-byte big-endian length prefix followed by the payload.
//! Malformed or over-bound inputs return `Err`/`None` without panicking and
//! without allocating the claimed length upfront beyond the bound check.

use crate::constants::MAX_WIRE_MESSAGE_SIZE;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame too short: need 4-byte length prefix, got {got}")]
    TooShort { got: usize },
    #[error("frame length {len} exceeds bound {bound}")]
    OverBound { len: usize, bound: usize },
    #[error("frame truncated: declared {declared}, available {available}")]
    Truncated { declared: usize, available: usize },
    #[error("frame is empty (zero-length payload rejected)")]
    Empty,
}

/// Encode `payload` with a 4-byte big-endian length prefix. Fails when the
/// payload exceeds `MAX_WIRE_MESSAGE_SIZE`.
pub fn encode_with_length_prefix(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.is_empty() {
        return Err(FrameError::Empty);
    }
    if payload.len() > MAX_WIRE_MESSAGE_SIZE {
        return Err(FrameError::OverBound {
            len: payload.len(),
            bound: MAX_WIRE_MESSAGE_SIZE,
        });
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decode one length-prefixed frame. Returns the payload slice plus total
/// consumed bytes (`4 + len`). Returns `Err` fail-closed on truncation,
/// over-bound lengths, or empty payloads.
pub fn decode_with_length_prefix(data: &[u8]) -> Result<(&[u8], usize), FrameError> {
    if data.len() < 4 {
        return Err(FrameError::TooShort { got: data.len() });
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if len == 0 {
        return Err(FrameError::Empty);
    }
    if len > MAX_WIRE_MESSAGE_SIZE {
        return Err(FrameError::OverBound {
            len,
            bound: MAX_WIRE_MESSAGE_SIZE,
        });
    }
    if data.len() < 4 + len {
        return Err(FrameError::Truncated {
            declared: len,
            available: data.len() - 4,
        });
    }
    Ok((&data[4..4 + len], 4 + len))
}
