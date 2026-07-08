# Milestone B Phase 4: Honeypot Protocol Detection Correctness — Complete

## Summary

Rewrote protocol detection to be binary-safe, deterministic, and correctly integrated with banner/responder selection. Removed unused Aho-Corasick automaton, fixed TLS detection, normalized protocol identifiers, replaced per-call HashMap allocation with static lookup, and added comprehensive table-driven tests.

## Files Modified

| File | Change |
|------|--------|
| `crates/synvoid-honeypot/src/protocol.rs` | **Rewritten** — Binary-safe detection (no UTF-8 dependency), fixed TLS record header detection (`0x16 0x03 0x00-0x04`), added `Confidence` enum, replaced per-call HashMap with `LazyLock`, removed AhoCorasick, 50 table-driven tests |
| `crates/synvoid-honeypot/src/listener.rs` | Updated `ConnectionEvent` to include `Confidence` field; updated `detected_pattern` to use `evidence` field |
| `crates/synvoid-honeypot/src/lib.rs` | Added `Confidence` to public exports |
| `crates/synvoid-honeypot/Cargo.toml` | Removed unused `aho-corasick` dependency |
| `architecture/honeypot.md` | Added Section 7: Protocol Detection Correctness (Phase 4) |

## Test Results

- **97 tests passing** in `synvoid-honeypot` (50 protocol tests + 12 listener tests + 35 other)
- **0 clippy warnings** (`cargo clippy -p synvoid-honeypot --all-targets -- -D warnings`)
- **0 fmt issues** (`cargo fmt --all -- --check`)

## Key Changes

### 1. Binary-Safe Detection

Detection now runs in two phases:
1. **Binary prefix checks** — pure `&[u8]` byte matching, no UTF-8 required
2. **Text protocol checks** — UTF-8 required, only runs if binary phase finds nothing

Binary protocols detected: TLS/SSL, SSH, VNC, SMB, MySQL, PostgreSQL, RDP, Redis RESP, DNS, MongoDB.

### 2. Fixed TLS Detection

Old: Checked `(payload[1] & 0x80) != 0` (SSLv2 bit), which fails for normal TLS records like `0x16 0x03 0x01`.

New: Checks `payload[0] == 0x16 && payload[1] == 0x03 && payload[2] <= 0x04` with record length sanity check.

### 3. Confidence Enum

Added `Confidence` enum (Low/Medium/High) with proper ordering. Each detection provides a confidence level and evidence string.

### 4. Static Banner Lookup

Replaced per-call `HashMap::from([...])` with `LazyLock<HashMap<&'static str, ServiceBanner>>`. Lookup keys are normalized lowercase protocol identifiers.

### 5. Removed Aho-Corasick

The `AhoCorasick` automaton was built from regex pattern strings but never used in detection. Removed entirely along with the `aho-corasick` Cargo dependency.

## Protocol Detection Coverage

| Protocol | Signature | Confidence | Binary-Safe |
|----------|-----------|------------|-------------|
| TLS/SSL | `0x16 0x03 0x00-0x04` record header | High | Yes |
| SSH | `SSH-` prefix | High | Yes |
| VNC | `RFB ` prefix | High | Yes |
| SMB | `\xffSMB` / `\xfeSMB` | High | Yes |
| PostgreSQL | SSLRequest `0x00 0x00 0x00 0x08 0x04 0xd2` | High | Yes |
| HTTP | `GET `, `POST `, etc. / `HTTP/` response | High | No (text) |
| SMTP | `EHLO`, `HELO`, `MAIL FROM:`, `220 *SMTP` | High | No (text) |
| FTP | `USER `, `PASS `, `QUIT`, `220 *FTP` | High/Medium | No (text) |
| MySQL | `0x0a` protocol v10 handshake | Medium | Yes |
| Redis | RESP `*N\r\n` / inline PING/AUTH/SET/GET | High/Medium | Both |
| POP3 | `+OK` response | High | No (text) |
| IMAP | `* OK` greeting | Medium | No (text) |
| RDP | TPKT `0x03 0x00` | Low | Yes |
| DNS | 12-byte header with standard query flags | Low | Yes |
| MongoDB | `0x3a 0x00` opmsg / JSON ismaster | Low | Both |
