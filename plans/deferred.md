# Deferred Items

Items identified during Phase 1 execution that were not completed and are deferred to later phases.

---

## From Phase 1

### 1. `nix` Features Assessment Was Incorrect

**Original plan**: Remove `"net"` and `"uio"` features from nix dependency.
**Reality**: Both features are required. `platform/unix.rs` needs `"net"` for `SockaddrIn`/`SockaddrIn6`/`Ipv6V6Only` and `"uio"` for `ControlMessage`/`ControlMessageOwned`/`sendmsg`/`recvmsg`/`cmsg_space`. Removing either causes compilation failures.
**Action**: None needed — features correctly kept in Cargo.toml.

### 2. 95 Pre-existing Clippy Warnings

**Current count**: 95 warnings from `cargo clippy --lib`.
**Categories**:
- Dead code (~60): Unused methods, constants, and types across mesh transport files
- Empty lines after doc comments/attributes (~10)
- Redundant field names (~5)
- Result unit err (~5)
- Other style issues (~15)

**Deferred to**: Phase 6 (Code Quality & Readability)

### 3. 125 `#[allow(dead_code)]` Annotations

**Current count**: 125 annotations across ~70 files.
**Categories identified**:
- **Mesh transport** (~29): Unused handler methods for DHT, DNS, org, peer, global, routing, rate-limit
- **Worker** (4): MinifierCache, get_content_type, get_compressed_content, ListenerType
- **WAF** (2): Rate limiter fields
- **DNS** (5): Cache helpers, DNSSEC helpers
- **Other** (~85): Various fields and methods

**Deferred to**: Phase 6 (Code Quality & Readability) — requires deciding which are truly removable vs feature-gatable.

### 4. `unicode-segmentation` Yanked Entry

**Original plan**: Add yanked entry to SECURITY.md.
**Reality**: `unicode-segmentation` 1.13.1 exists as a transitive dependency in Cargo.lock. No RUSTSEC advisory found for a yanked version. The crate appears healthy on crates.io.
**Action**: None needed unless a specific yanked version is identified.

### 5. Mesh → DNS Cross-Module Feature Gating

**Issue**: 6 mesh files unconditionally reference `crate::dns` types:
- `src/mesh/protocol_proto_decode.rs`
- `src/mesh/transport_dns.rs`
- `src/mesh/protocol.rs`
- `src/mesh/transports/quic.rs`
- `src/mesh/transport.rs`
- `src/mesh/backend.rs`

This means `--no-default-features --features mesh` (without `dns`) will fail to compile. The DNS crate dependencies are properly gated as optional, but the mesh code that uses them is not.
**Deferred to**: Phase 6 (Code Quality & Readability) — requires adding `#[cfg(feature = "dns")]` gates or abstracting DNS types behind a trait.

### 6. `Cargo.lock` Transitive Dependencies

`once_cell` and `bincode` 1.3.3 still appear in `Cargo.lock` as transitive dependencies (via tracing-core, gloo-worker, etc.). This is expected and not a bug — they are not direct dependencies.

### 7. Trailing Whitespace in 4 Files

Fixed during Phase 1 but worth noting for future agents: these files had trailing whitespace that caused `cargo fmt` to fail internal checks:
- `src/honeypot_port/protocol.rs`
- `src/waf/violation_tracker.rs`
- `src/admin/legacy.rs`
- `src/captcha/mod.rs`

---

## From Phase 1 Plan (Not Attempted)

The following items from the Phase 1 plan were identified as belonging to other phases and were not attempted:

- **1.5 dead code audit** — Deferred to Phase 6 (bulk annotation removal)
- **1.8 clippy fixes beyond unreachable pattern** — Deferred to Phase 6 (95 warnings)
