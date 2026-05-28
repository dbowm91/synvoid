# TLS & Crypto Review Plan

**Reviewed:** 2026-05-28
**Documents:** `architecture/tls.md`, `architecture/layer_3_5_deep_dive.md`

## Verified Correct Items

- **tls.md file structure**: All 7 files in `src/tls/` match documented submodule list (`mod.rs`, `server.rs`, `cert_resolver.rs`, `config.rs`, `acme.rs`, `acme_dns.rs`, `sni_peek.rs`)
- **InternalTlsConfig struct** (`config.rs:4-17`): All 12 fields match documentation exactly
- **InternalAcmeConfig struct** (`config.rs:20-28`): All 7 fields match documentation
- **InternalAcmeChallengeType enum** (`config.rs:31-35`): `Http01` (default) and `Dns01` match
- **InternalClientAuthConfig struct** (`config.rs:38-41`): Both fields match
- **Default values** (`config.rs:43-59`): `prefer_post_quantum: true`, `tls_1_3_only: true`, `ocsp_stapling_enabled: true`, `port: 443` all match
- **CertResolver struct** (`cert_resolver.rs:22-27`): Has `certs`, `default_cert`, `config`, `reload_tx` (all documented)
- **CertResolver::resolve()** (`cert_resolver.rs:328-348`): SNI resolution with exact match then wildcard match matches documentation
- **RSA key validation** (`cert_resolver.rs:164-213`): <2048 bits rejected, <3072 bits warned, EC keys accepted - matches
- **OCSP response size limit** (`cert_resolver.rs:436`): `MAX_OCSP_SIZE = 256 * 1024` (256KB) matches
- **Certificate validity enforcement** (`cert_resolver.rs:125-162`): Parses `not_before`/`not_after`, rejects expired/not-yet-valid
- **watch_for_cert_changes debounce** (`cert_resolver.rs:487`): 500ms sleep matches documentation
- **Flood protection before TLS** (`server.rs:333-351`): L3/L4 flood check before `acceptor.accept()` matches
- **ALPN routing** (`server.rs:410-411`): `b"h2"` check for HTTP/2 matches
- **JA4 fingerprint** (`server.rs:91-92`): `compute_ja4()` called on connection creation matches
- **HttpsConnection struct** (`server.rs:83-87`): `io`, `drop_requested`, `ja4_hash` fields match
- **Strict protocol validation** (`server.rs:382-398`): 16-byte peek, HTTP method detection matches
- **AcmeManager struct** (`acme.rs:53-63`): All documented fields present
- **ChallengeGuard RAII** (`acme.rs:22-50`): Drop impl cleans up challenges matches
- **ACME 24-hour renewal** (`acme.rs:433`): `Duration::from_secs(24 * 3600)` matches
- **30-day renewal threshold** (`acme.rs:397`): `Duration::from_secs(30 * 24 * 3600)` matches
- **ACME credentials 0o600** (`acme.rs:178`): Unix permissions set correctly
- **AcmeDnsChallenge methods** (`acme_dns.rs:17-63`): `prepare_challenge`, `get_txt_value`, `cleanup`, `pending_challenges` all exist
- **DNS-01 SHA-256 base64url** (`acme_dns.rs:29-33`): SHA-256 hash + URL_SAFE_NO_PAD encoding matches
- **SniError variants** (`sni_peek.rs:448-469`): `TooShort`, `NotHandshake`, `Incomplete`, `NotClientHello` all present
- **compute_ja4 function** (`sni_peek.rs:180`): JA4 fingerprint computation matches documentation
- **HybridSignature struct** (`hybrid_signature.rs:17-22`): `ed25519_signature`, `ml_dsa_signature`, `ed25519_public_key`, `ml_dsa_public_key` all match
- **HybridSignature sizes** (`hybrid_signature.rs:13-14`): `ED25519_SIGNATURE_SIZE = 64`, `ML_DSA_SIGNATURE_SIZE = 2420` match
- **HybridSigner trait** (`hybrid_signature.rs:190`): Location and method signatures match
- **MeshHybridSigner struct** (`ml_dsa.rs:122`): Location matches
- **verify_hybrid()** (`ml_dsa.rs:189-219`): Fail-safe behavior (returns true when ML-DSA absent) matches
- **verify_hybrid_async()** (`protocol.rs:197-232`): Uses CryptoVerificationPool for parallel verification matches
- **ML-KEM confirm_key** (`ml_kem_key_exchange.rs:204-279`): Public key match + decapsulation test matches
- **TunnelBackend enum** (`tunnel/router.rs:200-209`): `Direct` and `Tunnel` variants match
- **resolve_tunnel_backend()** (`tunnel/router.rs:150-170`): QUIC client first, then session mappings, uses configured upstream_host
- **validate_peer_role()** exists (`peer_auth.rs:248`): Role boundary enforcement confirmed
- **validate_edge_node_pow()** exists (`peer_auth.rs:540`): Edge node PoW validation confirmed
- **DhtAccessControl struct** (`dht/mod.rs:689`): Has `authorized_genesis_keys` field
- **GlobalNodeRevocationList** (`peer_auth.rs:21`): CRL implementation exists
- **Post-quantum feature flag** (`Cargo.toml:30`): `post-quantum = ["dep:rustls-post-quantum"]` matches
- **rustls-post-quantum dependency** (`Cargo.toml:157`): `version = "0.2", optional = true` matches
- **dns feature gate for acme_dns** (`mod.rs:9`): `#[cfg(feature = "dns")]` matches documentation
- **mesh feature gate for server** (`server.rs:135-138`): `#[cfg(feature = "mesh")]` on mesh_config/mesh_transport fields matches
- **post-quantum startup logging** (`server.rs:272-275`): Feature-gated logging matches
- **Constant-time comparison in ML-KEM** (`ml_kem_key_exchange.rs:255-259`): Uses `subtle::ConstantTimeEq` for shared secret comparison - correct security pattern

## Discrepancies Found

- **layer_3_5_deep_dive.md:39** — Claimed post-quantum provider installed at `src/startup/master.rs:210-234`. **Actual:** No `src/startup/master.rs` exists. The post-quantum TLS provider installation is handled implicitly by `rustls-post-quantum` crate when feature is enabled, with verification at `src/mesh/cert.rs:87-139` (`verify_post_quantum_tls()`). The startup directory contains only `bootstrap.rs`, `daemon.rs`, `mod.rs`, `worker.rs`.
- **tls.md:70** — Claimed `CertResolver` holds `certs: HashMap<String, Arc<CertifiedKey>>`. **Actual:** Field is `Arc<RwLock<HashMap<String, Arc<rustls::sign::CertifiedKey>>>>` (`cert_resolver.rs:23`). The `RwLock` wrapper is not mentioned.
- **tls.md:67** — Claimed `reload_tx: broadcast::Sender<()>`. **Actual:** Correct type but the struct also holds `config: InternalTlsConfig` (`cert_resolver.rs:25`) which is not listed in the field documentation.
- **tls.md:76** — Claimed `watch_for_cert_changes()` is a method. **Actual:** It's a free function `pub fn watch_for_cert_changes(resolver: Arc<CertResolver>, watch_dir: PathBuf)` (`cert_resolver.rs:457`), not a method on `CertResolver`.
- **tls.md:201-208** — `SniError` enum documentation lists only 4 variants. **Actual:** 6 variants exist: `TooShort`, `NotHandshake`, `Incomplete`, `NotClientHello`, `InvalidHostname`, `ConnectionClosed`, plus `Io(String)` (`sni_peek.rs:448-469`).
- **tls.md:418** — Feature flag table says `dns` feature affects `acme_dns.rs`. **Actual:** The `dns` feature also enables `hickory-proto`, `hickory-resolver`, `tokio-dstip`, `cryptoki`, and `getrandom` (`Cargo.toml:23`), not just ACME DNS challenges.
- **layer_3_5_deep_dive.md:134-156** — Claims `TunnelBackend` is at `src/tunnel/upstream.rs`. **Actual:** `TunnelBackend` enum is at `src/tunnel/router.rs:200`. The `upstream.rs` file documents the struct was removed from there (line 11-15).
- **layer_3_5_deep_dive.md:144** — Claims `resolve_tunnel_backend()` is at `src/tunnel/router.rs:150-170`. **Actual:** Function is at `src/tunnel/router.rs:150-170` (correct line range).
- **layer_3_5_deep_dive.md:43-44** — Claims `rustls-post-quantum = { version = "0.2", optional = true }  # Line 156`. **Actual:** It's at line 157 (`Cargo.toml:157`).

## Bugs Identified

- [MEDIUM] BUG-TLS-1: `load_certs_from_dir()` (`cert_resolver.rs:215-253`) does not call `validate_key_strength()` for certificates loaded from the watch directory. Only the primary certificate loaded via `load_certificates()` gets strength validation. Certificates added via the directory watcher could bypass RSA key strength checks.

- [LOW] BUG-TLS-2: ACME credential file on non-unix platforms (`acme.rs:190-193`) writes directly without setting restrictive permissions. While Windows has different permission semantics, the documentation claims `0o600` permissions universally. The `#[cfg(not(unix))]` path uses `std::fs::write()` with no permission hardening.

- [LOW] BUG-TLS-3: `watch_for_cert_changes()` (`cert_resolver.rs:484-498`) debounce logic sleeps 500ms after every single event, then drains the queue. This means rapid consecutive file changes (e.g., writing domain.pem then domain.key) could trigger two reloads instead of one coalesced reload, since the second event arrives during the drain loop and is discarded but the first event already triggered a reload.

## Suggested Improvements

- **Documentation**: Update `SniError` enum documentation in `tls.md` to include all 7 variants (`InvalidHostname`, `ConnectionClosed`, `Io(String)` are missing)
- **Documentation**: Update `layer_3_5_deep_dive.md` to correct the post-quantum provider installation location from `src/startup/master.rs` to `src/mesh/cert.rs`
- **Documentation**: Update `layer_3_5_deep_dive.md` to correct `TunnelBackend` location from `src/tunnel/upstream.rs` to `src/tunnel/router.rs`
- **Documentation**: Update `layer_3_5_deep_dive.md` to correct `rustls-post-quantum` line number from 156 to 157
- **Documentation**: Update `tls.md` to clarify `watch_for_cert_changes` is a free function, not a method
- **Documentation**: Update `tls.md` to document `RwLock` wrapper on CertResolver fields
- **Security**: Consider adding `validate_key_strength()` call in `load_certs_from_dir()` for consistency with primary cert loading
- **Security**: Consider adding a comment explaining the non-unix permission handling for ACME credentials, or add Windows-specific ACL handling
- **Code Quality**: The `watch_for_cert_changes` debounce could use a more robust approach (e.g., `tokio::time::sleep` + drain in a loop with a longer window) to properly coalesce rapid file events
- **Documentation**: Expand `tls.md` feature flag table to list ALL effects of each feature flag, not just the module name

## Stale Content

- **layer_3_5_deep_dive.md:39**: References `src/startup/master.rs:210-234` which does not exist. The startup module contains `bootstrap.rs`, `daemon.rs`, `mod.rs`, `worker.rs` only.
- **layer_3_5_deep_dive.md:134**: References `src/tunnel/upstream.rs` as location of `TunnelBackend`. The struct was removed from that file and now lives in `src/tunnel/router.rs:200`. The `upstream.rs` file header (lines 11-15) explicitly documents this removal.

## Cross-Reference Status

- **AGENTS.md "Verified Already Fixed" — BUG-L1 verify_hybrid() fail-safe**: Still accurate. `verify_hybrid()` at `ml_dsa.rs:189-219` returns true when ML-DSA absent, confirmed as fail-safe behavior.
- **AGENTS.md "Codebase Quick Reference — HybridSignature struct**: Field names and sizes match documentation (`hybrid_signature.rs:17-22`, constants at lines 13-14).
- **AGENTS.md "Codebase Quick Reference — MeshHybridSigner**: Location at `ml_dsa.rs:122` confirmed correct.
- **AGENTS.md "Codebase Quick Reference — DhtAccessControl**: `authorized_genesis_keys` field confirmed at `dht/mod.rs:693`.
- **AGENTS.md "Codebase Quick Reference — validate_edge_node_pow**: Function exists at `peer_auth.rs:540`, called at lines 281, 431, 434.
- **AGENTS.md "Codebase Quick Reference — GlobalNodeRevocationList**: Exists at `peer_auth.rs:21`, documented correctly.
- **AGENTS.md "Security Patterns — Constant-Time Comparison**: ML-KEM `confirm_key` uses `subtle::ConstantTimeEq` correctly at `ml_kem_key_exchange.rs:255-259`.
- **AGENTS.md "Security Patterns — ACME credentials 0o600**: Confirmed at `acme.rs:178` for Unix platforms.
