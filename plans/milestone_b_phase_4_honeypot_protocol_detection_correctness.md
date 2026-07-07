# Milestone B Phase 4: Honeypot Protocol Detection Correctness

## Purpose

Make honeypot protocol detection deterministic, binary-safe, and compatible with listener/banner/responder selection. This phase fixes protocol identification correctness rather than increasing honeypot interaction depth.

The immediate target is `crates/synvoid-honeypot/src/protocol.rs` and its integration with the listener. The detector should reliably classify common first-packet probes and should not depend on UTF-8 conversion for binary protocols.

## Current issues to address

1. Regex-based detection only runs when payload is valid UTF-8, so binary protocol probes can be missed.
2. Aho-Corasick state appears to be built from regex pattern strings but not used in detection.
3. TLS detection appears incorrect for normal records such as `16 03 01` or `16 03 03`.
4. Detection returns display service names such as `HTTP` while banner lookup expects normalized keys such as `http`.
5. Banner lookup builds a map on every call and can fail due to case/service mismatch.
6. Listener currently needs a clean normalized protocol/service boundary from the detector.
7. Tests currently tolerate TLS returning `None`; that should be replaced with positive TLS fixtures.

## Non-goals

- Do not implement full protocol parsers.
- Do not add active protocol negotiation beyond the existing low/medium interaction model.
- Do not add AI responder hardening here.
- Do not change threat-intel actionability/scoring here.
- Do not expand the honeypot service catalog without tests and config rationale.

## Data model target

Normalize detection output around stable internal identifiers and optional display labels.

Recommended structure:

```rust
struct ProtocolDetection {
    protocol: String,       // normalized identifier: http, ssh, tls, mysql, redis, postgres, smb, dns, unknown
    service: String,        // display/service label if needed: HTTP, SSH, PostgreSQL
    confidence: Confidence, // High, Medium, Low
    evidence: String,       // short non-payload reason, e.g. "http_method", "tls_record_header"
}
```

If the existing type already has similar fields, use it. The key requirement is that banner/responder selection consumes `protocol`, not display `service`.

## Implementation plan

### 1. Split binary prefix detection from text detection

Detection should run in this order:

1. Binary fixed-prefix and structural checks.
2. ASCII/text protocol method checks on a lossy or bounded ASCII path.
3. Regex checks only for rules that truly need text regex.
4. Fallback/unknown.

Binary checks must not require `std::str::from_utf8(payload)` to succeed.

### 2. Fix TLS detection

Detect normal TLS records:

- content type `0x16` for handshake
- version bytes `0x03 0x00` through `0x03 0x04` for SSLv3/TLS 1.0-1.3 style record versions
- minimum record header length 5
- length sanity check when enough bytes exist

Fixtures:

- `16 03 01 00 2e ...` -> tls
- `16 03 03 ...` -> tls
- `16 03 04 ...` -> tls, if accepted
- obvious non-TLS binary -> unknown

Do not retain a test that says TLS may return `None` because the detector is wrong.

### 3. Add binary-safe protocol checks

Implement simple checks for:

- SSH: starts with `SSH-`
- HTTP: methods `GET `, `POST `, `HEAD `, `PUT `, `DELETE `, `OPTIONS `, `PATCH `, `TRACE `, `CONNECT `
- Redis: RESP arrays/simple commands, e.g. `*1\r\n`, `PING\r\n`, `AUTH `
- MySQL: first packet shape where practical, or known handshake/client packet markers if reliable
- PostgreSQL: SSLRequest/startup packet shape where practical
- SMB: `\xffSMB` and `\xfeSMB`
- DNS: minimal header shape for UDP-style payloads if relevant to TCP listener context; keep confidence low if ambiguous
- RDP: TPKT/X.224 prefix if configured
- VNC: starts with `RFB `
- SMTP/POP3/IMAP/FTP: text command prefixes

Keep ambiguous signatures low-confidence and do not overclassify random binary as high-confidence.

### 4. Decide Aho-Corasick usage

The current `AhoCorasick` field should either be removed or used correctly.

Preferred options:

- Remove it if regex/prefix checks are sufficient.
- Or use Aho-Corasick for fixed text tokens only, not regex strings.

Do not build an Aho-Corasick automaton from regex syntax and leave it unused.

### 5. Replace per-call banner map allocation

Change `get_banner_for_service` to avoid constructing a new `HashMap` on every call.

Options:

- static `LazyLock<HashMap<&'static str, &'static str>>`
- `match` on normalized protocol string
- precomputed config map if banners are operator configurable

Also ensure lookup lowercases or consumes normalized identifiers only.

### 6. Listener integration

Update listener call sites:

- Use `detection.protocol` for banner/responder selection.
- Use `detection.service` or display label for storage/UI if desired.
- Store normalized protocol in the record if schema allows; otherwise store service consistently and document it.
- Avoid passing uppercase display names to lower-case lookup APIs.

### 7. Tests

Add table-driven tests with byte fixtures for:

- HTTP methods, valid and invalid.
- SSH banner.
- TLS 1.0/1.2/1.3-style records.
- Random binary does not classify as TLS.
- Redis RESP and inline command forms.
- MySQL representative packet, if reliable.
- PostgreSQL SSLRequest/startup, if reliable.
- SMB1 and SMB2 markers.
- RDP TPKT marker.
- VNC banner.
- SMTP/FTP/POP3/IMAP command prefixes.
- Binary payload with invalid UTF-8 and a valid binary signature still detects.
- Invalid UTF-8 with no known signature returns unknown.
- Banner lookup for uppercase display name and normalized protocol works or uppercase path is removed.
- Listener stores/uses normalized protocol for banner selection.

### 8. Confidence and ambiguity policy

Add a short policy:

- High confidence: strong magic/prefix (`SSH-`, TLS record header, SMB marker, HTTP method with request syntax).
- Medium confidence: recognizable text command with common protocol token.
- Low confidence: weak shape-only binary checks.

Low-confidence detections should not produce aggressive threat-intel actions by themselves. That later actionability belongs to Milestone C, but the detector should expose confidence now.

### 9. Documentation

Update honeypot docs or architecture notes to state:

- protocol detection is lightweight, not full parsing
- binary-safe detection is supported for key first packets
- normalized protocol identifiers drive banners/responders
- confidence is available for downstream scoring

## Local validation commands

Minimum:

```bash
cargo fmt --all -- --check
cargo clippy -p synvoid-honeypot --all-targets -- -D warnings
cargo test -p synvoid-honeypot --all-targets protocol
cargo test -p synvoid-honeypot --all-targets
```

Preferred:

```bash
cargo test -p synvoid-honeypot --features mesh --all-targets
cargo test -p synvoid-honeypot --all-features --all-targets
```

If listener integration tests are added:

```bash
cargo test -p synvoid-honeypot --all-targets listener
```

## Success criteria

- TLS normal records are detected with positive tests.
- Binary protocols do not require valid UTF-8.
- Unused Aho-Corasick state is removed or used for fixed-token matching.
- Banner lookup uses normalized protocol identifiers and no longer fails due to uppercase display service names.
- Banner lookup no longer allocates a new map on every call.
- Table-driven tests cover common protocols and negative cases.
- Listener uses normalized protocol for banner/responder selection.
- Docs reflect lightweight/first-packet detection limits.

## Handoff notes

This phase should follow Phase 3 or be coordinated with it. Phase 3 ensures the listener has correct admission/accounting boundaries; Phase 4 ensures the listener classifies and responds consistently once a connection is admitted.
