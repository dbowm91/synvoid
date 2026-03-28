# DNS Codebase Remediation Plan

## Overview

This plan addresses critical bugs, security issues, compliance failures, and test gaps identified in the DNS subsystem review. Work is organized by priority: correctness/protocol compliance first, then security, then performance, then code quality.

All changes should run `cargo clippy -- -D warnings` and `cargo test` after completion.

**Note:** Line numbers are approximate and may shift as the codebase evolves. Verify before editing.

---

## Phase 1: Critical Correctness Bugs (DNS Wire Format & DNSSEC)

### Task 1.1 — Fix NSEC3 hashing (RFC 5155 §5)

**File:** `src/dns/dnssec.rs:1324-1331`

**Problem:** `hash_name_nsec3()` applies salt (`H(hash || salt)`) on every iteration. RFC 5155 §5 requires:
1. `hash = H(name || salt)` (initial hash with salt)
2. `for i in 0..iterations { hash = H(hash || salt) }`

**Fix:** Restructure the loop to apply salt only to the hash, not to the name-then-hash sequence incorrectly. The first step hashes `name + salt`, subsequent steps hash `previous_hash + salt`.

**Also check:** `server/dnssec_impl.rs` callers of `hash_name_nsec3()` to ensure the computed hashes match expected values.

**Verification:** Add a unit test with known NSEC3 vectors (RFC 5155 Appendix A has test vectors).

---

### Task 1.2 — Fix NSEC3 base32hex encoding (no padding)

**File:** `src/dns/dnssec.rs:1432-1434`

**Problem:** NSEC3 uses base32hex encoding without padding per RFC 4648. Current code adds `=` padding characters, producing invalid DNS owner names.

**Fix:** Strip padding from base32hex output. Use a base32hex implementation that supports no-padding mode, or truncate trailing `=` after encoding.

**Verification:** Unit test that `hash_name_nsec3()` produces a valid DNS label (no `=`, valid base32hex characters only).

---

### Task 1.3 — Fix NSEC3 owner name missing hash-length byte

**File:** `src/dns/dnssec.rs:1404-1407`

**Problem:** `create_nsec3_owner_name()` does not prepend a length byte to the base32-encoded hash before appending the zone name. RFC 5155 §3.2 requires the hash to be a length-prefixed label.

**Fix:** Prepend the hash length as a single byte before the base32hex-encoded hash bytes.

**Verification:** Unit test with known NSEC3 owner name vectors from RFC 5155.

---

### Task 1.4 — Publish ZSK in DNSKEY RRset

**File:** `src/dns/server/dnssec_impl.rs:35-52`

**Problem:** `build_dnskey_records()` only publishes the KSK (flags=257). Per RFC 4034 §2.1, the DNSKEY RRset MUST contain all zone signing keys. Resolvers cannot validate RRSIGs without the ZSK public key.

**Fix:** Include both KSK (flags=257) and ZSK (flags=256) in the DNSKEY RRset. The `DnsSecKeyManager` already stores both; the builder just needs to emit both.

**Verification:** Query DNSKEY for a test zone and verify both keys appear. Verify RRSIG validation succeeds with the combined RRset.

---

### Task 1.5 — Fix CDS record type (use RecordType::CDS, not DS)

**File:** `src/dns/server/dnssec_impl.rs:74,84`

**Problem:** `build_cds_records()` returns records with `record_type: RecordType::DS` (43). CDS is type 59. This breaks child-to-parent signaling per RFC 7344.

**Fix:** Change `RecordType::DS` to `RecordType::CDS` in both locations.

**Verification:** Query CDS for a test zone and verify response contains type 59, not 43.

---

### Task 1.6 — Fix NXDOMAIN response hardcoded NSEC3 type

**File:** `src/dns/server/query.rs:807`

**Problem:** `build_nxdomain_response()` writes type 50 (NSEC3) unconditionally. When NSEC records (type 47) are passed, the wire format is wrong.

**Fix:** Determine the record type from the first element of the records vector and use the correct type code.

**Verification:** Test NXDOMAIN responses with both NSEC and NSEC3 modes.

---

### Task 1.7 — Return proper response for unmatched queries

**File:** `src/dns/server/query.rs:749-751`

**Problem:** When `handle_query()` finds no matching records and falls through without generating NSEC/NSEC3 proofs, it returns `None`. The client times out.

**Fix:** At the end of `handle_query()`, if no records matched, return NXDOMAIN (with NSEC/NSEC3 if DO bit set) or NODATA (NOERROR with empty answer + SOA in authority). Never return `None`.

**Verification:** Query for a nonexistent name within a zone and verify NXDOMAIN is returned.

---

### Task 1.8 — Fix SRV canonical_rdata encoding

**File:** `src/dns/dnssec.rs:1520-1526`

**Problem:** `canonical_rdata()` for SRV only encodes the 2-byte priority field, omitting weight (2 bytes), port (2 bytes), and the target name.

**Fix:** Encode all SRV RDATA fields: priority + weight + port + canonical(target_name).

**Verification:** Unit test comparing computed RRSIG against a known-good SRV RRSIG.

---

### Task 1.9 — Fix ARCOUNT to account for EDNS OPT record

**File:** `src/dns/server/response.rs:30-38`

**Problem:** ARCOUNT is written to the header before the OPT record is appended. When DNSSEC or EDNS is present, the count is off by one (or more if RRSIGs go in additional).

**Fix:** Compute ARCOUNT after all additional records (including OPT) are known. Use a two-pass approach: build body into a separate buffer, then write the header with correct counts, then concatenate.

**Verification:** Parse a response with `dns_parser` and verify header ARCOUNT matches actual additional record count.

---

### Task 1.10 — Fix MX record trailing null byte

**File:** `src/dns/server/response.rs:135-148`

**Problem:** MX RDATA encoding does not append a trailing 0x00 byte after the exchange name. RFC 1035 §3.3.9 requires a fully-qualified domain name in wire format (with null terminator).

**Fix:** Append 0x00 after writing the exchange name labels.

**Verification:** Parse MX response with `dns_parser` and verify the exchange name is correctly terminated.

---

### Task 1.11 — Fix CDNSKEY flags (incorrect CD bit)

**File:** `src/dns/dnssec.rs:213`

**Problem:** `generate_cdnskey_record()` sets bit 15 of flags as a "CD flag." CDNSKEY (RFC 7344) has the same wire format as DNSKEY — there is no separate CD bit in the flags field. The CDNSKEY record type (60) itself indicates "check disabled."

**Fix:** Remove the bit manipulation that sets the CD flag. The flags field should contain only the SEP bit (bit 15 for KSK, per RFC 4034 §2.1.1), not an invented CD bit.

**Verification:** Query CDNSKEY and verify flags match the corresponding DNSKEY flags.

---

### Task 1.12 — Extract TTL from response correctly (handle compression)

**File:** `src/dns/server/query.rs:376-398`

**Problem:** `extract_ttl_from_response()` walks labels by reading length bytes but does not handle DNS name compression pointers (0xC0 prefix). If the question section uses compression, TTL extraction reads garbage.

**Fix:** Detect the 0xC0 prefix and skip 2 bytes (the pointer) instead of treating it as a label length. Or delegate to `dns_parser::Packet` to extract the TTL from the parsed question.

**Verification:** Construct a DNS response with a compressed question name and verify TTL is extracted correctly.

---

## Phase 2: Critical Recursive Resolver Bugs

### Task 2.1 — Fix negative cache returning None on hit

**File:** `src/dns/recursive_cache.rs:229-243`

**Problem:** `RecursiveDnsCache::get()` returns `None` for negative cache hits. The caller in `recursive.rs:409` treats `None` as a cache miss, triggering a new upstream query every time. The negative cache is dead.

**Fix:** Change `get()` to return a three-state result: `CacheHit(positive)`, `NegativeHit`, or `Miss`. The caller must distinguish "negatively cached" from "not cached." Alternatively, return a sentinel value (empty vec with a flag) for negative hits.

**Verification:** Test that after an upstream query returns no records, a second query for the same name does NOT trigger a new upstream query (use a mock resolver with a call counter).

---

### Task 2.2 — Increase UDP query buffer size

**File:** `src/dns/recursive.rs:151`

**Problem:** `let mut buf = vec![0u8; 512]` limits UDP queries to 512 bytes. EDNS0 clients can send 4096+ byte queries.

**Fix:** Use `config.limits.udp_buffer_size` (default 65535) or at minimum 4096 for the recv buffer.

**Verification:** Send a query with a large EDNS0 OPT record and verify it is processed correctly.

---

### Task 2.3 — Return SERVFAIL on upstream resolution failure

**File:** `src/dns/recursive.rs:475`

**Problem:** Upstream failures return `Err(_) => Vec::new()`, which triggers negative caching (NXDOMAIN). RFC 1035 requires SERVFAIL (RCODE=2) on resolution failures.

**Fix:** On upstream error, build and return a SERVFAIL response. Do NOT cache SERVFAIL responses (or cache with a very short TTL). Consider using Extended DNS Errors (RFC 8914) code 2 (Server Failure) or 12 (No Reachable Authority) for diagnostics.

**Verification:** Configure an unreachable upstream and verify SERVFAIL is returned to the client.

---

### Task 2.4 — Fix RFC 5011 shutdown channel

**File:** `src/dns/resolver.rs:663,666`

**Problem:** `start_rfc5011_updates()` creates a local `_shutdown_tx` that is immediately dropped. The `shutdown_tx` field on `HickoryRecursor` is never set, so `stop_rfc5011_updates()` cannot signal shutdown.

**Fix:** Store the `oneshot::Sender` on `self.shutdown_tx` before spawning the task. On clone, either share it via `Arc<Mutex<Option<Sender>>>` or accept that cloned instances cannot stop the task (document the limitation).

**Verification:** Verify that dropping the recursor (or calling stop) causes the background task to exit cleanly.

---

### Task 2.5 — Propagate DNSSEC validation status in forwarding mode

**File:** `src/dns/resolver.rs:370-374`

**Problem:** `HickoryResolver::lookup_ip_with_ttl()` hardcodes `is_dnssec_validated: false`. When forwarding to a validating resolver (8.8.8.8), the AD bit in the response indicates validation, but this is ignored.

**Fix:** Parse the AD (Authenticated Data) flag from the upstream response and set `is_dnssec_validated` accordingly. The `hickory-resolver` `Lookup` type exposes the response header; extract the flags.

**Verification:** Query a DNSSEC-signed name through a forwarding resolver and verify `is_dnssec_validated` is true.

---

## Phase 3: Security Fixes

### Task 3.1 — Harden cache fingerprint validation

**File:** `src/dns/cache.rs:155-183`

**Problem:** Fingerprint validation only triggers after `max_fingerprints_per_name` unique fingerprints have been seen. During the first N queries for a name, any fingerprint is accepted — an attacker can poison initial entries.

**Fix:** Require a minimum of 2 agreeing fingerprints before accepting a cached response (or use DNSSEC validation as the trust anchor). Alternatively, make the fingerprint window smaller (e.g., start at 1, not N).

**Verification:** Attempt cache poisoning with different fingerprints and verify rejection.

---

### Task 3.2 — Make trust anchor DB operations transactional

**File:** `src/dns/trust_anchor.rs:319`

**Problem:** `save_anchors()` does `DELETE FROM anchors` then `INSERT INTO anchors` — not wrapped in a transaction. A crash between DELETE and INSERT loses all trust anchors.

**Fix:** Wrap DELETE + INSERT in a SQLite transaction (`BEGIN` / `COMMIT`). Or use `INSERT OR REPLACE` (UPSERT) to avoid the DELETE entirely.

**Verification:** Simulate a crash (kill process) between DELETE and INSERT; verify anchors are preserved after restart.

---

### Task 3.3 — Make hardcoded `.example` block configurable

**File:** `src/dns/server/query.rs:572-574`, `src/config/dns.rs`

**Problem:** Unconditional block for all `.example` queries. Not configurable. May block legitimate use.

**Fix:** Add `blocked_tlds: Vec<String>` to `DnsConfig` with an empty default. Replace the hardcoded check with `config.blocked_tlds.contains(&tld)`. Or remove the block entirely if not intended for production.

**Verification:** Configure a TLD block and verify it works; verify `.example` is not blocked by default.

---

## Phase 4: Performance Improvements

### Task 4.1 — Cache RRSIG signatures per (name, type) pair

**File:** `src/dns/server/dnssec_impl.rs:426`

**Problem:** Every response record is individually signed with Ed25519 per query. No caching.

**Fix:** Add a short-lived (TTL-matched) cache for computed RRSIG records, keyed by `(canonical_name, record_type, key_tag)`. Evict on zone serial change.

**Verification:** Benchmark query throughput before/after. Verify signatures remain valid.

---

### Task 4.2 — Eliminate unnecessary rate limiter cleanup calls

**File:** `src/dns/server/rate_limit.rs:147-163`

**Problem:** `cleanup_if_needed()` is called on every `check_ip()` and `should_respond()` invocation. Unnecessary lock contention.

**Fix:** Run cleanup on a separate timer task (e.g., every 60s) rather than inline with every check. Use an atomic timestamp to track last cleanup if a timer is not feasible.

**Verification:** Benchmark high-concurrency query throughput.

---

### Task 4.3 — Fix sharded cache allocation on hit

**File:** `src/dns/sharded_cache.rs:99`

**Problem:** `get()` clones data inside Arc: `Arc::new(entry.data.clone())`. Allocates on every cache hit.

**Fix:** Store `Arc<Vec<u8>>` in the cache entry instead of `Vec<u8>`. Return `Arc::clone(&entry.data)` (cheap reference bump).

**Verification:** Benchmark cache hit throughput.

---

### Task 4.4 — Replace ANY query O(N) iteration with index

**File:** `src/dns/server/query.rs:636`

**Problem:** ANY queries iterate all zone records to find matching names. O(N) in zone size.

**Fix:** Add a secondary index: `HashMap<String, Vec<(RecordType, Vec<DnsZoneRecord>)>>` keyed by name. ANY queries then do O(1) lookup by name.

**Verification:** Benchmark ANY query throughput on a zone with 10K+ records.

---

### Task 4.5 — Reduce zone serial history clone cost

**File:** `src/dns/server/mod.rs:203-204`

**Problem:** `increment_serial_with_limit()` clones the entire `records` HashMap into history. O(N) memory copy per serial increment.

**Fix:** Use `Arc<HashMap<...>>` for zone records and store `Arc` references in history instead of full clones. On zone modification, clone-on-write (copy-on-write via `Arc::make_mut`).

**Verification:** Benchmark serial increment on a large zone.

---

## Phase 5: Code Quality & DRY

### Task 5.1 — Extract duplicated coalescer dispatch logic

**Files:** `src/dns/server/startup.rs`, `src/dns/server/query.rs`

**Problem:** ~150 lines of coalescer dispatch logic duplicated across UDP handler, TCP handler, and anycast variants.

**Fix:** Extract into a single method on `DnsServer`:
```rust
async fn coalesce_or_handle(&self, query: &[u8], client_ip: IpAddr, ...) -> Vec<u8>
```

**Verification:** Compile and run existing tests. Behavior should be identical.

---

### Task 5.2 — Fix TCP buffer size using UDP config

**File:** `src/dns/server/startup.rs:732`

**Problem:** `let tcp_buffer_size = self.config.limits.udp_buffer_size` uses UDP config for TCP.

**Fix:** Use `self.config.limits.max_tcp_connections` or add a dedicated `tcp_buffer_size` config field.

**Verification:** Config test for TCP buffer size.

---

### Task 5.3 — Fix stale cache hit metrics recording

**File:** `src/dns/recursive.rs:411-413`

**Problem:** `metrics.record_cache_hit()` is only called when `stale == true`. Fresh cache hits are not recorded.

**Fix:** Always call `metrics.record_cache_hit()` on any cache hit. Additionally call `metrics.record_stale_hit()` when `stale == true`.

**Verification:** Test that cache hit/miss metrics are correct.

---

## Phase 6: Test Coverage

### Task 6.1 — Add end-to-end authoritative server tests

**New file:** `tests/dns_server_test.rs`

- Start a UDP DNS server on a random port with a test zone
- Send queries using a DNS client library (or raw UDP)
- Verify responses for: A, AAAA, CNAME, MX, TXT, NS, SOA, ANY
- Verify NXDOMAIN for nonexistent names
- Verify DNSSEC responses (RRSIG present when DO bit set)
- Verify truncation behavior (TC flag set for large responses)
- Verify rate limiting (exceed rate, verify rejection)

### Task 6.2 — Add recursive resolver integration tests

**New file:** `tests/dns_recursive_test.rs`

- Start recursive resolver with mock upstream
- Verify cache hit/miss behavior
- Verify negative caching (query returned no records, second query doesn't hit upstream)
- Verify SERVFAIL on upstream failure
- Verify stale cache serving

### Task 6.3 — Add unit tests for untested critical modules

| Module | Tests to add |
|--------|-------------|
| `resolver.rs` | Mock resolver returns, DNSSEC flag propagation |
| `edns.rs` | ECS filtering, option parsing, padding |
| `transfer.rs` | AXFR/IXFR message construction, serial comparison |
| `firewall.rs` | Rule evaluation, subnet matching |
| `server/response.rs` | Record encoding for each type, truncation |
| `server/dnssec_impl.rs` | RRSIG signing, NSEC/NSEC3 generation, DNSKEY construction |

### Task 6.4 — Add NSEC3 RFC 5155 test vectors

**File:** `src/dns/dnssec.rs` (test module)

Use the test vectors from RFC 5155 Appendix A to validate:
- `hash_name_nsec3()` produces correct hashes
- `create_nsec3_owner_name()` produces correct owner names
- NSEC3 RDATA encoding is correct

---

## Phase 7: Documentation & Configuration

### Task 7.1 — Document known limitations

Add to `AGENTS.md`:
- Forwarding mode does NOT perform DNSSEC validation (only recursive mode does)
- QNAME minimization is not yet implemented
- CDNSKEY record format has known issues
- The `.example` TLD block is now configurable via `blocked_tlds` (was hardcoded)

---

## Execution Order

1. **Phase 1** (Tasks 1.1–1.12): Wire format and DNSSEC correctness — these are protocol-breaking bugs
2. **Phase 2** (Tasks 2.1–2.5): Recursive resolver correctness — negative cache, SERVFAIL, buffer sizes
3. **Phase 3** (Tasks 3.1–3.3): Security hardening
4. **Phase 4** (Tasks 4.1–4.5): Performance — after correctness is established
5. **Phase 5** (Tasks 5.1–5.3): Code quality — DRY, config fixes
6. **Phase 6** (Tasks 6.1–6.4): Test coverage — to prevent regressions
7. **Phase 7** (Task 7.1): Documentation

Within each phase, tasks are independent and can be done in any order unless noted.

## Estimated Scope

| Phase | Tasks | Estimated LOC Changed | Risk |
|-------|-------|-----------------------|------|
| 1 | 12 | ~250 | High — wire format changes can break everything |
| 2 | 5 | ~100 | Medium — cache/recursive changes need careful testing |
| 3 | 3 | ~50 | Low — isolated changes |
| 4 | 5 | ~150 | Low — additive (caches, indexes) |
| 5 | 3 | ~100 | Low — refactoring |
| 6 | 4 | ~800 | Low — new test files |
| 7 | 1 | ~10 | Low — documentation |
