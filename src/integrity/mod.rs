//! Signed Integrity Module
//!
//! This module provides end-to-end integrity verification for HTTP traffic
//! flowing through edge WAF nodes, without requiring end-to-end encryption.
//!
//! This enables:
//! - WAF inspection at edge nodes
//! - Caching at edge nodes
//! - Tamper detection by clients and origins
//! - Audit reporting to global nodes
//!
//! # Protocol Flow (Origin-Signed Key Exchange)
//!
//! This flow ensures the client can verify the session key was actually signed
//! by the origin's mesh identity, bypassing untrusted edge nodes.
//!
//! ```text
//! 1. Client ──HTTP──▶ Edge ──HTTP──▶ Origin
//!                     |
//! 2. Edge injects: X-Integrity-Config: {"key_server": "...", "mesh_id": "..."}
//!
//! 3. Client JS ──HTTPS──▶ Global Node: key-request-origin
//!    - Client generates ephemeral X25519 key pair
//!    - Includes: mesh_id, client_x25519_pubkey
//!
//! 4. Global Node: Looks up origin's Ed25519 pubkey by mesh_id
//!    - Global Node ──KeyForward──▶ Origin (via mesh)
//!
//! 5. Origin signs session key with its mesh Ed25519 key:
//!    sign_message = session_id|key_id|mesh_id|server_x25519_pubkey|expires_at
//!    - Origin ──KeySigned──▶ Global Node (via mesh)
//!
//! 6. Global Node ──HTTPS──▶ Client: key-offer-origin
//!    - Contains: origin_signature, origin_ed25519_pubkey, origin_mesh_id
//!
//! 7. Client verifies origin's Ed25519 signature using origin's mesh public key
//!    - If valid, client derives session key via X25519 DH
//!
//! 8. Client ──Signed──▶ Edge ──Verified──▶ Origin
//!    Response: Origin ──Signed──▶ Edge ──Verified──▶ Client
//! ```
//!
//! # Feature Flags
//!
//! - `origin_key_exchange`: Enable origin-signed key exchange (disabled by default)

pub mod attestation;
pub mod config;
pub mod protocol;
pub mod signing;
pub mod verification;

pub use attestation::{
    AttestationRegistry, AttestationRequest, AttestationResponse, AttestationSigner,
    AttestationVerifier, OriginAttestation,
};
pub use config::{IntegrityConfig, IntegrityMode};
pub use protocol::origin_key_exchange::{
    verify_global_signature, verify_origin_signature, OriginKeyExchangeManager,
    OriginSignedSessionKey, PendingOriginSession,
};
pub use protocol::{
    derive_session_key, generate_random_key, Ed25519Signer, Ed25519Verifier, IntegrityHeader,
    KeyExchangeMessage, SessionKey, SessionKeyManager, SignedHttpMessage, X25519KeyExchange,
    KEY_HEADER_PREFIX, SIG_HEADER_PREFIX,
};
pub use signing::HttpMessageSigner;
pub use verification::IntegrityVerifier;
pub use verification::{AuditReport, AuditReporter, VerificationResult};
