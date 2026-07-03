# DNS Milestone 2 Phase 1: Transport Runtime Closure

## Objective

Close the runtime transport boundary after the first Milestone 2 implementation pass. The repo now has fail-fast bind address parsing, shutdown signaling, TCP response-size enforcement, and removal of the duplicate DNS tree. This phase turns those improvements into a verified and documented runtime contract.

## Current state

Already improved:

- `configured_bind_addr` validates bind address and port.
- standard startup uses configured bind address.
- shutdown signaling includes a watch channel for background tasks.
- TCP connection guards are held in spawned task lifetime.
- TCP hard response-size violations produce SERVFAIL instead of warning-only behavior.
- duplicate `src/dns` implementation tree was removed.

Still requiring closure:

- compile/test proof after the large deletion;
- one-query TCP versus persistent TCP decision;
- hard-limit SERVFAIL should echo parsed question when possible;
- shutdown lifecycle tests;
- transport-class integration with cache/coalescing;
- documentation of runtime behavior.

## Primary files

- `crates/synvoid-dns/src/server/startup.rs`
- `crates/synvoid-dns/src/server/query.rs`
- `crates/synvoid-dns/src/limits.rs`
- `crates/synvoid-dns/src/cache.rs`
- `crates/synvoid-dns/src/query_coalesce.rs`
- `crates/synvoid-dns/tests/dns_recursive_isolation.rs`
- `architecture/dns.md`

## Workstream 1: Compile verification after duplicate-tree deletion

Run:

```bash
cargo fmt --all --check
cargo test -p synvoid-dns
cargo test -p synvoid-config dns
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

Fix any references to removed `src/dns` modules. Search explicitly for:

```bash
rg "src/dns|crate::dns|mod dns|path = .*dns" .
```

Acceptance criteria:

- DNS crate compiles and tests pass.
- workspace status is known.
- no stale deleted-tree references remain.

## Workstream 2: TCP lifecycle decision

Tasks:

- Choose one-query-per-connection or persistent TCP.
- If one-query is retained:
  - rename internal comments/docs to make this explicit;
  - add a test confirming one response then close;
  - document that persistent TCP is deferred.
- If persistent TCP is implemented:
  - add length-prefixed read loop;
  - enforce idle timeout and maximum queries per connection;
  - preserve connection guard across the full loop;
  - keep AXFR/IXFR multi-message behavior correct.

Acceptance criteria:

- TCP lifecycle is not accidental.
- docs and code agree.

## Workstream 3: TCP hard-limit response correctness

Current TCP hard-limit behavior returns a compact SERVFAIL. Improve it to be fully DNS-shaped when the query was parsed.

Tasks:

- Build SERVFAIL using parsed query ID, qname, qtype, qclass, and RD bit.
- Echo question section when possible.
- RA=false, AD=false, AA=true if authoritative context produced the response.
- If parsing failed, fall back to minimal FORMERR/SERVFAIL as appropriate.
- Ensure response itself fits TCP hard limit or close connection.

Tests:

- oversized TCP response returns length-prefixed SERVFAIL;
- SERVFAIL preserves query ID;
- SERVFAIL echoes question;
- SERVFAIL preserves RD and has RA=false;
- no partial oversized original response is written.

Acceptance criteria:

- TCP hard-limit handling is enforceable and protocol-shaped.

## Workstream 4: Shutdown lifecycle tests

Tasks:

- Add start/stop integration test using ephemeral port.
- Verify UDP and TCP ports are reusable after shutdown.
- Ensure coalescer cleanup task observes shutdown watcher.
- Ensure calling shutdown twice is safe.
- Decide whether recursive server and key rotation task join handles need explicit ownership or documentation.

Acceptance criteria:

- normal DNS runtime start/stop does not leak listener tasks in tests.
- shutdown is idempotent.

## Workstream 5: Transport class propagation

Tasks:

- Define a helper that converts incoming transport/EDNS context into `TransportClass`.
- UDP no EDNS -> `Udp512`.
- UDP EDNS -> `UdpEdns(size)`.
- TCP -> `Tcp`.
- Future DoH/DoQ adapters should use `Http`/`Quic`.
- Pass transport class into cache key and coalescing key construction.

Acceptance criteria:

- cache/coalescing response-shape dimensions include actual transport.
- UDP truncation responses cannot poison TCP cache entries.

## Workstream 6: Documentation

Update docs with:

- bind fail-fast behavior;
- TCP lifecycle policy;
- UDP/EDNS truncation behavior;
- TCP hard-limit behavior;
- shutdown behavior and any deferred task ownership gaps.

## Final verification

```bash
cargo fmt --all --check
cargo test -p synvoid-dns transport
cargo test -p synvoid-dns limits
cargo test -p synvoid-dns
cargo check -p synvoid-dns --all-features
cargo check --workspace
```

## Completion criteria

Phase 1 is complete when transport startup, TCP lifecycle, hard-limit responses, shutdown, and transport-class propagation are verified and documented.
