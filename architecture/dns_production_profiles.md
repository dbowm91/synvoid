# DNS Production Profiles

Phase 4 deliverable — defines validated deployment profiles with verified config snippets, safe defaults, mandatory overrides, and verification commands.

---

## Overview

SynVoid DNS ships with secure-by-default configuration. Every profile below starts from the default config and layers only the minimum changes required for its use case. Profiles are classified by support status:

| Status | Meaning |
|--------|---------|
| **Production-Supported** | Tested in CI, documented, recommended for production |
| **Beta** | Functional but limited real-world validation |
| **Experimental** | Wired but untested at scale, may change without notice |

### Production-Supported Boundary

Every profile labeled **Production-Supported** means: **verified by the internal in-process Rust test suite; external client interop (`dig`, `delv`, `kdig`, `ldns-verify-zone`, `named-checkzone`) is NOT automatically run in CI and remains operator-validated.** The `scripts/dns/conformance.sh` script documents external tool checks but requires those tools to be installed locally. Profiles that rely on external client compatibility should be validated against the conformance script before production deployment.

### Global Safe Defaults

These defaults are verified safe and apply to all profiles unless overridden:

| Setting | Default | Rationale |
|---------|---------|-----------|
| `dns.enabled` | `false` | DNS off until explicitly enabled |
| `dns.bind_address` | `"0.0.0.0"` | Bind all interfaces (authoritative) |
| `dns.port` | `53` | Standard DNS port |
| `dns.mode` | `Standalone` | No mesh dependency |
| `dns.ratelimit.mode` | `Shared` | Shared rate limiter across zones |
| `dns.ratelimit.per_second` | `500` | Prevents query floods |
| `dns.rrl.enabled` | `true` | Response Rate Limiting on by default |
| `dns.rrl.responses_per_second` | `100` | Per-client response cap |
| `dns.firewall.enabled` | `false` | Disabled (opt-in for public-facing) |
| `dns.firewall.block_internal_ips` | `true` | Prevents rebinding when firewall is on |
| `dns.firewall.block_zone_transfers` | `true` | Blocks AXFR by default |
| `dns.settings.default_ttl` | `300` | 5-minute fallback TTL |
| `dns.settings.cache_enabled` | `true` | Cache on by default |
| `dns.settings.cache_size` | `100000` | ~100K entries |
| `dns.settings.cache_min_ttl` | `60` | Floor TTL |
| `dns.settings.cache_max_ttl` | `3600` | Ceiling TTL |
| `dns.settings.negative_cache_ttl` | `300` | NXDOMAIN/NODATA caching |
| `dns.dnssec.enabled` | `false` | DNSSEC off until explicitly enabled |
| `dns.dot.enabled` | `false` | DoT off until explicitly enabled |
| `dns.doh.enabled` | `false` | DoH off until explicitly enabled |
| `dns.doq.enabled` | `false` | DoQ off until explicitly enabled |
| `dns.recursive.enabled` | `false` | Recursive resolver off by default |

---

## 1. Authoritative-Only Public

**Support Status**: Production-Supported

Serving DNS zones to the internet. This is the most common production profile.

### Required Config

```toml
[dns]
enabled = true
bind_address = "0.0.0.0"
port = 53
mode = "Standalone"

[dns.ratelimit]
mode = "Shared"
per_second = 500
per_minute = 5000

[dns.rrl]
enabled = true
responses_per_second = 100
window_secs = 5
max_responses = 1000
ttl = 300

[dns.firewall]
enabled = true
block_internal_ips = true
block_zone_transfers = true

[dns.settings]
default_ttl = 300
cache_enabled = true
cache_size = 100000
cache_min_ttl = 60
cache_max_ttl = 3600

[dns.zones]
# Load zones from files or zone store
```

### Safe Defaults (No Override Needed)

> **Production-Supported Boundary**: This profile is verified by internal in-process Rust tests. External client interop (`dig`, `delv`, `kdig`) is NOT run in CI. See the [Production-Supported Boundary](#production-supported-boundary) section above.

- Rate limiting: 500/sec shared, 100/sec RRL
- Cache: 100K entries, 60–3600s TTL range
- Firewall: blocks internal IPs and zone transfers
- TCP connection limit: 500
- Concurrent query limit: 2500

### Defaults That MUST Be Changed

| Setting | Default | Required Value | Why |
|---------|---------|----------------|-----|
| `dns.zones` | `[]` | At least one zone | No zones = no serving |
| `dns.firewall.enabled` | `false` | `true` | Public-facing requires firewall |

### Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| DDoS / query flood | Rate limiting (500/sec) + RRL (100/sec) active by default |
| Zone transfer exposure | `block_zone_transfers = true` enforced |
| Rebinding attacks | `block_internal_ips = true` when firewall enabled |
| Open resolver | Recursive is disabled by default; no risk |
| Cache poisoning | Cache key includes transport class, qclass, DO bit |

### Verification

```bash
# Compile check
cargo check --release

# Run authoritative tests
cargo test -p synvoid-dns -- transport_lifecycle
cargo test -p synvoid-dns -- configured_bind_addr
cargo test -p synvoid-dns -- tcp_hard_limit
cargo test -p synvoid-dns -- truncation

# Interop tests
cargo test -p synvoid-dns --test dns_interop_authoritative
cargo test -p synvoid-dns --test dns_interop_truncation

# Stress tests
cargo test -p synvoid-dns --test dns_stress_resource_limits -- --test-threads=1

# Verify firewall blocks zone transfers
cargo test -p synvoid-dns -- axfr_tcp_only
cargo test -p synvoid-dns -- axfr_disabled_by_default

# Verify rate limiting
cargo test -p synvoid-dns -- rate_limit

# Verify cache isolation
cargo test -p synvoid-dns -- phase7_cache_tests
```

---

## 2. Local Recursive

**Support Status**: Production-Supported

Local DNS resolver for a single host. Binds to loopback only, preventing external use.

### Required Config

```toml
[dns]
enabled = true
bind_address = "127.0.0.1"
port = 53

[dns.recursive]
enabled = true
upstream_provider = "System"
dnssec_validation = true
qname_minimization = true
root_hints_path = "root.hints"
query_timeout_secs = 5
```

### Safe Defaults (No Override Needed)

> **Production-Supported Boundary**: This profile is verified by internal in-process Rust tests. External client interop (`dig`, `delv`, `kdig`) is NOT run in CI. See the [Production-Supported Boundary](#production-supported-boundary) section above.

- Binds to `127.0.0.1` — not accessible from the network
- DNSSEC validation enabled (Recursive provider required for real validation)
- QNAME minimization enabled for privacy
- Cache enabled with 100K entry capacity
- Open-resolver prevention rejects `0.0.0.0` / `::` bind addresses

### Defaults That MUST Be Changed

| Setting | Default | Required Value | Why |
|---------|---------|----------------|-----|
| `dns.recursive.upstream_provider` | `"System"` | `"System"` or `"Custom"` | `"System"` uses OS resolvers; `"Custom"` for explicit upstreams |
| `dns.recursive.root_hints_path` | `"root.hints"` | Valid path to root hints file | Required for recursive resolution |

### Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Open resolver | Bind address validation rejects `0.0.0.0` / `::` |
| DNSSEC validation bypass | Only `"Recursive"` provider validates; `"System"` forwards |
| Upstream failure | Query timeout (default 5s) prevents hanging |
| Cache poisoning | Cache key includes transport class, namespace separation |

### Important: Forwarder Mode Limitation

`upstream_provider = "System"` uses `HickoryResolver` which does **not** perform DNSSEC validation. This is by design — the OS resolvers handle their own validation. To get end-to-end DNSSEC validation, use `upstream_provider = "Recursive"`.

The `"Recursive"` provider is what delivers real DNSSEC validation: it performs its own chain-of-trust verification against configured trust anchors. The `"System"` provider only forwards queries to OS resolvers and returns whatever they return — if the OS resolver strips the AD bit or fails validation, SynVoid will not detect it. For production deployments requiring DNSSEC, always use `upstream_provider = "Recursive"` with a valid `root_hints_path`.

### Verification

```bash
# Compile check
cargo check --release

# Recursive resolver tests
cargo test -p synvoid-dns -- recursive_cache
cargo test -p synvoid-dns -- open_resolver
cargo test -p synvoid-dns -- query_timeout
cargo test -p synvoid-dns --test dns_recursive_isolation
cargo test -p synvoid-dns --test dns_config_fidelity

# DNSSEC validation tests (Recursive provider only)
cargo test -p synvoid-dns --test dns_interop_dnssec

# Cache isolation
cargo test -p synvoid-dns -- phase7_cache_tests

# Recursive isolation (open-resolver guard)
cargo test -p synvoid-dns --test dns_recursive_isolation -- open_resolver
```

---

## 3. Internal Recursive

**Support Status**: Production-Supported

Internal network resolver for a LAN/VLAN. Binds to an internal interface with client ACL.

### Required Config

```toml
[dns]
enabled = true
bind_address = "10.0.0.53"
port = 53

[dns.recursive]
enabled = true
upstream_provider = "Custom"
dnssec_validation = true
qname_minimization = true
root_hints_path = "root.hints"
query_timeout_secs = 5

[dns.recursive.custom_upstreams]
addresses = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]

[dns.limits]
max_tcp_connections = 500
max_concurrent_queries = 2500

[dns.settings.cache_enabled]
enabled = true
cache_size = 100000
```

### Safe Defaults (No Override Needed)

> **Production-Supported Boundary**: This profile is verified by internal in-process Rust tests. External client interop (`dig`, `delv`, `kdig`) is NOT run in CI. See the [Production-Supported Boundary](#production-supported-boundary) section above.

- Cache: 100K entries, 60–3600s TTL range
- Rate limiting: 500/sec shared
- TCP connections: 500, concurrent queries: 2500
- DNSSEC validation enabled

### Defaults That MUST Be Changed

| Setting | Default | Required Value | Why |
|---------|---------|----------------|-----|
| `dns.bind_address` | `"0.0.0.0"` | Internal IP (e.g. `10.0.0.53`) | Must not bind to public interface without firewall |
| `dns.recursive.custom_upstreams` | `[]` | At least one upstream | No upstreams = resolution failure |
| `dns.recursive.root_hints_path` | `"root.hints"` | Valid path | Required for Recursive provider |

### Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Exposure to internet | Bind to internal IP, firewall rules at network layer |
| Upstream exposure | Custom upstreams use DNS (not DoT/DoH) — consider encrypted transport |
| Cache exhaustion | Cache size limit (100K) prevents unbounded growth |
| Client tracking | QNAME minimization enabled by default |

### Verification

```bash
# Same as Local Recursive, plus:
cargo test -p synvoid-dns --test dns_recursive_isolation
cargo test -p synvoid-dns --test dns_config_fidelity

# Verify bind address validation
cargo test -p synvoid-dns -- configured_bind_addr
```

---

## 4. Transfer-Enabled Primary

**Support Status**: Production-Supported

Primary DNS server that serves zone transfers to secondary servers via AXFR/IXFR. TSIG authentication required.

### Required Config

```toml
[dns]
enabled = true
bind_address = "0.0.0.0"
port = 53

[dns.dnssec]
tsig_keys = [
    { name = "transfer-key", algorithm = "hmac-sha256", secret = "<base64-secret>" }
]

[dns.settings]
allow_transfer = ["10.0.0.2", "10.0.0.3"]
require_tsig = true

[dns.firewall]
enabled = true
block_zone_transfers = false
```

### Safe Defaults (No Override Needed)

> **Production-Supported Boundary**: This profile is verified by internal in-process Rust tests. External client interop (`dig`, `delv`, `kdig`) is NOT run in CI. See the [Production-Supported Boundary](#production-supported-boundary) section above.

- `require_tsig = true` — transfers require TSIG authentication
- Firewall blocks zone transfers by default (`block_zone_transfers = true`)
- Rate limiting active (500/sec shared)

### Defaults That MUST Be Changed

| Setting | Default | Required Value | Why |
|---------|---------|----------------|-----|
| `dns.dnssec.tsig_keys` | `[]` | At least one key | Transfers fail without TSIG |
| `dns.settings.allow_transfer` | `[]` | Secondary server IPs | No allowed clients = no transfers |
| `dns.firewall.block_zone_transfers` | `true` | `false` | Must unblock for transfers |

### Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Unauthorized zone transfer | TSIG required + IP allowlist |
| Zone data exposure | Transfers only to allowed clients |
| Key compromise | Rotate TSIG keys periodically; key names are not logged |
| Cache poisoning via transfer | DNSSEC signing validates zone integrity |

### Verification

TSIG coverage spans positive and negative paths:

- **Positive TSIG**: `tsig_success_fixtures` — sign+verify roundtrips for HMAC-SHA256, SHA-512, SHA-1, SHA-384; key management (add, remove, coexist, runtime addition); error codes (BADTIME); key name embedding in RDATA.
- **Negative TSIG / unsigned rejection**: `control_plane_authorization` — AXFR/IXFR denied by default when `require_tsig = true` but no TSIG present; `notify_behavior` — NOTIFY refused when `require_tsig = true` without TSIG; `update_authorized_semantics` — UPDATE refused when `require_tsig = true` without TSIG; `update_atomicity_rollback` — serial unchanged when TSIG absent.
- **Denied-by-default authorization**: `control_plane_authorization` — 10 deny-by-default tests enforcing that UPDATE/NOTIFY/AXFR/IXFR all require explicit authorization.

```bash
# Transfer tests
cargo test -p synvoid-dns -- axfr_tcp_only
cargo test -p synvoid-dns -- axfr_disabled_by_default
cargo test -p synvoid-dns -- ixfr_history
cargo test -p synvoid-dns -- store_volatile
cargo test -p synvoid-dns -- store_atomic_write

# TSIG positive tests
cargo test -p synvoid-dns --test tsig_success_fixtures

# IXFR tests
cargo test -p synvoid-dns --test ixfr_record_delta

# Interop
cargo test -p synvoid-dns --test dns_interop_transfers

# Authorization tests (includes TSIG negative / deny-by-default)
cargo test -p synvoid-dns --test control_plane_authorization

# NOTIFY TSIG enforcement
cargo test -p synvoid-dns --test notify_behavior

# UPDATE TSIG enforcement
cargo test -p synvoid-dns --test update_authorized_semantics
```

---

## 5. Transfer-Enabled Secondary

**Support Status**: Beta

Secondary DNS server that receives zone transfers from a primary. Zone synchronization is automatic.

### Required Config

```toml
[dns]
enabled = true
bind_address = "0.0.0.0"
port = 53

[dns.dnssec]
tsig_keys = [
    { name = "transfer-key", algorithm = "hmac-sha256", secret = "<base64-secret>" }
]

[dns.settings]
require_tsig = true

[dns.firewall]
enabled = true
block_zone_transfers = true
```

### Safe Defaults (No Override Needed)

> **Beta Boundary**: This profile relies on Transfer-Enabled Primary's TSIG implementation and the `cache_invalidation_axfr` test path. No separate passive-listener harness exists for the secondary role. See the [Production-Supported Boundary](#production-supported-boundary) section above.

- `require_tsig = true` — validates transfer responses
- Firewall blocks outgoing transfers (secondary only receives)
- Cache enabled for serving

### Defaults That MUST Be Changed

| Setting | Default | Required Value | Why |
|---------|---------|----------------|-----|
| `dns.dnssec.tsig_keys` | `[]` | Must match primary's key | TSIG validation fails without matching key |

### Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Stale zone data | IXFR history tracking, serial comparison |
| Transfer MITM | TSIG authentication on all transfers |
| Primary unreachable | Serve-stale from cache (if enabled) |
| Zone integrity | DNSSEC signatures validated on receipt |

### Verification

This profile reuses the primary's TSIG and IXFR test paths. No separate passive-listener harness exists for the secondary role, which is why this profile is **Beta**. The `cache_invalidation_axfr` test verifies cache invalidation on AXFR receipt — the closest path to secondary-as-receiver behavior.

```bash
# TSIG validation (reuses primary's fixtures)
cargo test -p synvoid-dns --test tsig_success_fixtures

# IXFR record deltas (reuses primary's test path)
cargo test -p synvoid-dns --test ixfr_record_delta

# Transfer interop (primary sends, secondary receives)
cargo test -p synvoid-dns --test dns_interop_transfers

# Cache invalidation on AXFR receipt (secondary behavior)
cargo test -p synvoid-dns -- cache_invalidation_axfr
```

---

## 6. DNSSEC-Signed Authoritative

**Support Status**: Production-Supported

Authoritative server with DNSSEC signing enabled. Signs zone records with RRSIGs and provides NSEC/NSEC3 authenticated denial of existence.

### Required Config

```toml
[dns]
enabled = true
bind_address = "0.0.0.0"
port = 53

[dns.dnssec]
enabled = true
domain = "example.com"
algorithm = "Ed25519"
key_path = "/var/lib/synvoid/dns/keys"
nsec3_enabled = true
nsec3_iterations = 50
nsec3_algorithm = 1
rollover_interval_days = 30

[dns.firewall]
enabled = true
block_zone_transfers = true
```

### Safe Defaults (No Override Needed)

> **Production-Supported Boundary**: This profile is verified by internal in-process Rust tests. External client interop (`dig`, `delv`, `kdig`, `ldns-verify-zone`) is NOT run in CI. See the [Production-Supported Boundary](#production-supported-boundary) section above.

- Algorithm: Ed25519 (modern, fast, small signatures)
- NSEC3 enabled (prevents zone walking)
- Key rollover: 30 days
- RRSIG validity: inception now - 1 day, expiration now + 7 days

### Defaults That MUST Be Changed

| Setting | Default | Required Value | Why |
|---------|---------|----------------|-----|
| `dns.dnssec.domain` | `""` | Your zone domain | Empty = no signing |
| `dns.dnssec.key_path` | `"/var/lib/synvoid/dns/keys"` | Writable path for key storage | Must exist and be writable |

### Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Key compromise | KSK/ZSK separation, rollover every 30 days |
| NSEC3 salt rotation | Configurable iterations and algorithm |
| Clock skew | RRSIG inception set 1 day in the past |
| Key storage security | `key_path` should have `0o700` permissions |

### Coverage Boundary

DNSSEC coverage is layered across three tiers:

| Tier | What | Status | Example Tests |
|------|------|--------|---------------|
| **Known-vector DNSSEC tests** | Primitives (hashes, signatures, key tags, NSEC/NSEC3 wire format, RRSIG encoding) | Covered | `dnssec_known_vectors`, `dns_interop_dnssec` |
| **Live signed-answer path tests** | End-to-end signing with real key material, RRSIG generation, canonical rdata ordering | Covered | `dnssec_live_signing` |
| **External delv/ldns-verify-zone/named-checkzone** | Third-party DNSSEC chain-of-trust validation | **NOT run in CI** | Deferred — see [Deferred Features](#deferred-features) |

### Verification

```bash
# DNSSEC signing tests
cargo test -p synvoid-dns --test dnssec_live_signing
cargo test -p synvoid-dns --test dnssec_known_vectors
cargo test -p synvoid-dns --test dns_interop_dnssec

# DNSSEC config
cargo test -p synvoid-dns -- dnssec

# NSEC/NSEC3 tests
cargo test -p synvoid-dns --test dnssec_known_vectors
```

---

## 7. Encrypted Transport

**Support Status**: Beta

DNS-over-TLS (DoT), DNS-over-HTTPS (DoH), and DNS-over-QUIC (DoQ) serving. Requires TLS certificates.

### Required Config

```toml
[dns]
enabled = true
bind_address = "0.0.0.0"
port = 53

[dns.dot]
enabled = true
port = 853
bind_address = "0.0.0.0"
tls_cert_path = "/etc/synvoid/dns/tls/cert.pem"
tls_key_path = "/etc/synvoid/dns/tls/key.pem"
use_system_cert_store = false

[dns.doh]
enabled = true
port = 443
bind_address = "0.0.0.0"
path = "/dns-query"
tls_cert_path = "/etc/synvoid/dns/tls/cert.pem"
tls_key_path = "/etc/synvoid/dns/tls/key.pem"
use_system_cert_store = false

[dns.doq]
enabled = true
port = 853
tls_cert_path = "/etc/synvoid/dns/tls/cert.pem"
tls_key_path = "/etc/synvoid/dns/tls/key.pem"
use_system_cert_store = false
max_concurrent_streams = 100
idle_timeout_secs = 30
```

### Safe Defaults (No Override Needed)

> **Beta Boundary**: Internal Rust integration tests verify wire format and config roundtrip. External client live-wire tests (`kdig`, `khost`, `ldns`) are NOT run in CI. See the [Production-Supported Boundary](#production-supported-boundary) section above.

- DoT: port 853, TCP+TLS 1.3
- DoH: port 443, HTTP/2+TLS 1.3, `application/dns-message` enforced
- DoQ: port 853, QUIC+TLS 1.3, 100 concurrent streams, 30s idle timeout
- Per-transport cache namespace separation prevents cross-contamination

### Defaults That MUST Be Changed

| Setting | Default | Required Value | Why |
|---------|---------|----------------|-----|
| `dns.dot.tls_cert_path` | `None` | Valid cert path | Server won't start without cert |
| `dns.dot.tls_key_path` | `None` | Valid key path | Server won't start without key |
| `dns.doh.tls_cert_path` | `None` | Valid cert path | Same as DoT |
| `dns.doh.tls_key_path` | `None` | Valid key path | Same as DoT |
| `dns.doq.tls_cert_path` | `None` | Valid cert path | Same as DoT |
| `dns.doq.tls_key_path` | `None` | Valid key path | Same as DoT |

### Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Certificate expiry | Use certbot or similar; monitor cert expiry |
| TLS downgrade | TLS 1.3 enforced by quinn/rustls |
| DoH amplification | Content-type enforcement (`application/dns-message`) |
| DoQ stream exhaustion | `max_concurrent_streams = 100` bounded |
| Cross-transport response contamination | TransportClass in cache key |

### Verification

Internal Rust integration tests (`encrypted_transport`, `dot`, `doh`, `doq`) verify wire format parsing, config roundtrip, TLS cert configuration, and transport class cache namespace separation. The `dns_interop_encrypted` test suite covers additional config validation (disabled-by-default, cert path validation). **No external client live-wire tests** (`kdig`, `khost`, `ldns`) are run in CI. The Beta label reflects internal test coverage only for encrypted mode.

```bash
# Encrypted transport tests
cargo test -p synvoid-dns --test encrypted_transport
cargo test -p synvoid-dns -- dot
cargo test -p synvoid-dns -- doh
cargo test -p synvoid-dns -- doq

# Interop
cargo test -p synvoid-dns --test dns_interop_encrypted

# Transport class separation
cargo test -p synvoid-dns -- transport
```

---

## 8. Full Mesh DNS

**Support Status**: Experimental

DNS server with mesh networking integration for dynamic service discovery via DHT registration. Requires the `mesh` and `dns` feature flags.

### Required Config

```toml
[dns]
enabled = true
mode = "Mesh"

[dns.mesh]
# Mesh-specific config validated only in mesh mode

[dns.recursive]
enabled = true
upstream_provider = "GlobalNodes"
dnssec_validation = true

[dns.settings]
cache_enabled = true
cache_size = 100000
```

### Safe Defaults (No Override Needed)

> **Experimental Boundary**: This profile requires the `mesh` and `dns` feature flags. External client interop is NOT run in CI. See the [Production-Supported Boundary](#production-supported-boundary) section above.

- Cache: 100K entries with namespace separation
- DNSSEC validation enabled
- Mesh mode validation only (no runtime dispatch on mode)

### Defaults That MUST Be Changed

| Setting | Default | Required Value | Why |
|---------|---------|----------------|-----|
| `dns.mode` | `"Standalone"` | `"Mesh"` | Must match mesh feature gate |
| `dns.mesh` | N/A | Valid mesh config | Mesh mode requires mesh config |

### Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Mesh peer compromise | DHT records signed, peer auth via mesh |
| Stale mesh records | TTL-based expiration, mesh health checks |
| DNSSEC in mesh | Mesh DNSSEC validation (`MeshDnsSecValidator`) |
| Experimental status | May change without notice |

### Verification

```bash
# Build with mesh+dns features
cargo build --release --features mesh,dns

# Mesh DNS tests
cargo test -p synvoid-mesh --test mesh_forced_cleanup --features mesh
cargo test --test mesh_task_ownership_guard --features mesh,dns
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test --test composition_root_behavioral --features mesh,dns
```

---

## Deferred Features

The following features exist in config schema but are **not implemented or not wired** at runtime. Do not rely on them.

| Feature | Config Status | Reason Deferred | Expected Phase |
|---------|---------------|-----------------|----------------|
| **Response Policy Zones (RPZ)** | Config fields present, not consumed | Not implemented | Phase 7 |
| **DNS Prefetch** | Config fields present, not consumed | Not implemented | Future |
| **Anycast** | Feature gate only, not consumed | Platform-specific, not wired | Future |
| **DNS Padding** | Struct exists in `edns.rs`, not wired | Not connected to query path | Future |
| **QNAME Privacy** | `sanitize_qname()` exists, not wired | Not connected to query path | Future |
| **Custom Trust Anchors** | Config fields present, not consumed | `TrustAnchorManager` exists but config not wired | Future |
| **HSM Integration** | Config field exists, not consumed | `hsm.rs` module exists but not wired | Future |
| **Firewall Rebinding Protection** | Partially implemented | `rebinding_protection()` exists, not wired | Future |
| **Firewall Default Action** | Config field exists, not consumed | Not implemented | Future |
| **Firewall Max Rules** | Config field exists, not consumed | Not implemented | Future |
| **IXFR Config Toggle** | Partially implemented | Handler exists, config toggle not consumed | Future |
| **IXFR Fallback to AXFR** | Config field exists, not consumed | `ZoneTransfer` accepts it, not wired from config | Future |
| **Serve-Stale (IXFR History)** | Config field exists, not consumed | Not wired from config | Future |
| **Persistent TCP Pipelining** | Deferred | RFC 7766 §4 one-query-per-connection currently enforced | Future |
| **EDNS Keepalive** | Parsed only | Not acted upon | Future |
| **NSEC3 Closest-Encloser Proofs** | Deferred | Full proof generation not implemented | Future |
| **External DNSSEC Tooling** | Not in CI | `dig`, `ldns-verify-zone`, `named-checkzone` not integrated | Future |
| **Bailiwick Enforcement** | Observability only | Checks exist but not enforced | Future |

### Config Fields That Are Wired but Deferred

These config fields have runtime consumers but are experimental or limited:

| Field | Status | Note |
|-------|--------|------|
| `dns.doq.bind_address` | Partially implemented | Hardcoded to `0.0.0.0` in `startup.rs:580`; config field not consumed |
| `dns.settings.ixfr_enabled` | Partially implemented | Handler exists, config toggle not consumed |
| `dns.dns64.enabled` | Implemented | Working but not tested at scale |
| `dns.ecs_filtering.enabled` | Implemented | EDNS Client Subnet filtering working |

---

## Profile Selection Guide

| Use Case | Profile | Support |
|----------|---------|---------|
| Public authoritative DNS | Authoritative-Only Public (#1) | Production |
| Local dev/test resolver | Local Recursive (#2) | Production |
| Office/DC resolver | Internal Recursive (#3) | Production |
| Primary for zone distribution | Transfer-Enabled Primary (#4) | Production |
| Secondary for redundancy | Transfer-Enabled Secondary (#5) | Beta |
| Signed authoritative | DNSSEC-Signed Authoritative (#6) | Production |
| Encrypted DNS serving | Encrypted Transport (#7) | Beta |
| Mesh-integrated DNS | Full Mesh DNS (#8) | Experimental |

### Combining Profiles

Profiles can be combined. Common combinations:

| Combination | Notes |
|-------------|-------|
| Authoritative + DNSSEC | Sign your public zones |
| Authoritative + DoT/DoH | Encrypted authoritative serving |
| Internal Recursive + DNSSEC | Validating internal resolver |
| Primary + DNSSEC | Signed zones + transfer to secondaries |

When combining profiles, merge the config snippets and ensure no conflicting settings. The safest approach is to start with the most restrictive profile and add features incrementally.

---

## CI Verification Matrix

All profiles should pass the baseline test suite:

```bash
# Full DNS test suite (1001+ tests)
cargo test --release --no-fail-fast -p synvoid-dns

# Security regression tests (single-threaded)
cargo test --test security_regression -- --test-threads=1

# Profile-specific verification
cargo test -p synvoid-dns -- transport_lifecycle configured_bind_addr tcp_hard_limit truncation  # Authoritative
cargo test -p synvoid-dns -- recursive_cache open_resolver query_timeout                          # Recursive
cargo test -p synvoid-dns --test dns_recursive_isolation                                          # Recursive isolation
cargo test -p synvoid-dns --test tsig_success_fixtures ixfr_record_delta                          # Transfers
cargo test -p synvoid-dns --test dnssec_live_signing dnssec_known_vectors                         # DNSSEC
cargo test -p synvoid-dns --test encrypted_transport dot doh doq                                  # Encrypted
cargo test -p synvoid-dns --test dns_stress_resource_limits -- --test-threads=1                   # Stress
cargo test -p synvoid-dns --test verification_gate                                                # Gate checks
```

---

## Release Support Matrix

| Profile | Internal Tests | External Checks | Benchmark Coverage | Known Deferrals |
|---------|---------------|-----------------|-------------------|-----------------|
| **Authoritative-Only Public** | `transport_lifecycle`, `configured_bind_addr`, `tcp_hard_limit`, `truncation`, `dns_interop_authoritative`, `dns_interop_truncation`, `authoritative_negative`, `dns_stress_resource_limits`, `axfr_tcp_only`, `axfr_disabled_by_default`, `phase7_cache_tests` | Not run in CI | `cache_bench`, `wire_bench`, `zone_bench`, `coalescer_bench`, `limits_bench` | RPZ, DNS Prefetch, Anycast |
| **Local Recursive** | `recursive_cache`, `open_resolver`, `query_timeout`, `dns_recursive_isolation`, `dns_config_fidelity`, `dns_interop_dnssec`, `dns_interop_recursive`, `phase7_cache_tests` | Not run in CI — requires local `dig`/`delv` | `cache_bench`, `wire_bench` | Custom Trust Anchors, HSM Integration |
| **Internal Recursive** | `dns_recursive_isolation`, `dns_config_fidelity`, `configured_bind_addr`, `dns_interop_recursive` | Not run in CI — requires local `dig`/`delv` | `cache_bench`, `wire_bench` | Custom Trust Anchors, HSM Integration |
| **Transfer-Enabled Primary** | `axfr_tcp_only`, `axfr_disabled_by_default`, `ixfr_history`, `store_volatile`, `store_atomic_write`, `tsig_success_fixtures`, `ixfr_record_delta`, `dns_interop_transfers`, `control_plane_authorization`, `control_plane_cache_completion`, `notify_behavior`, `update_authorized_semantics` | Not run in CI — requires local `dig` with TSIG | `cache_bench`, `wire_bench`, `zone_bench` | IXFR Config Toggle, IXFR Fallback to AXFR, Persistent TCP Pipelining |
| **Transfer-Enabled Secondary** | `tsig_success_fixtures`, `ixfr_record_delta`, `dns_interop_transfers`, `cache_invalidation_axfr`, `control_plane_cache_completion` | Not run in CI — requires primary+secondary pair | `cache_bench`, `wire_bench` | No passive-listener harness, Persistent TCP Pipelining |
| **DNSSEC-Signed Authoritative** | `dnssec_live_signing`, `dnssec_known_vectors`, `dns_interop_dnssec` | Not run in CI — requires `delv`, `ldns-verify-zone`, `named-checkzone` | `cache_bench`, `wire_bench`, `zone_bench` | External DNSSEC Tooling, NSEC3 Closest-Encloser Proofs, Bailiwick Enforcement |
| **Encrypted Transport** | `encrypted_transport`, `dot`, `doh`, `doq`, `dns_interop_encrypted`, `transport` | Not run in CI — requires `kdig`, `khost`, `ldns` | `wire_bench` | DoQ bind_address hardcoded, EDNS Keepalive, DNS Padding, QNAME Privacy |
| **Full Mesh DNS** | `mesh_forced_cleanup` (in synvoid-mesh), `mesh_task_ownership_guard`, `worker_mesh_supervision_boundary_guard`, `composition_root_behavioral` | Not run in CI — requires multi-node mesh | `cache_bench`, `wire_bench` | Experimental — may change without notice |

**Total cells**: 32 (8 profiles × 4 columns)

---

## Related Documents

| Document | Description |
|----------|-------------|
| `architecture/dns.md` | DNS module architecture overview |
| `architecture/dns_config_runtime_matrix.md` | Config field inventory with runtime status |
| `architecture/dns_operations_diagnostics.md` | Operator guide, smoke tests, alerting |
| `architecture/dns_zone_lifecycle.md` | Zone lifecycle management |
| `architecture/dns_deep_dive.md` | Deep dive into DNS internals |
| `plans/dns_milestone_4_phase_01_observability_operations.md` | M4P1 deliverables |
| `plans/dns_milestone_4_phase_02_performance_load_testing.md` | M4P2 deliverables |
