# Phase 08 Plan: Mesh DNS Trust and Configuration Truth

Status: **IMPLEMENTED** (2026-11-19; `dns_mesh_trust_contract`, 9 tests with
`--features mesh`, and `dns_truthfulness_contract`, 5 tests. D11 is enforced at
the DNS boundary: authenticity, publisher binding, and authorization must all
pass. The producer-side signature binding remains gated on mesh phase 04b, so
real DHT registrations default-deny; the DNS-side trust decision is complete).
Audit: `plans/dns_capability_audit.md` (D11, D34, D35).
Registered in: `plans/roadmap.md`.
Campaign: `plans/dns_serving_correctness_roadmap.md`.
Predecessor: mesh campaign Phase 04b (DHT record author binding).
Depends on: mesh `plans/mesh_trust_boundaries_phase_04_message_and_state_authentication.md`
for a verified DHT record; this phase must not invent a second signature scheme.

## The findings

**D11 (High).** `apply_dht_domain_registration` (`mesh_sync/dht.rs:5-50`)
inserts an advertised `domain -> origin_node_id` mapping with
`authenticated: true`, `cert_chain_verified: false`, and no signature check.
The DNS-owned trait returns plain tuples with no signature
(`mesh_sync/dht_capability.rs:100`), and the sync loop applies them every
interval (`mesh_sync/registry.rs:188`). `resolve_from_mesh`
(`server/query.rs:869-925`) then answers DNS queries for any domain with a
registered origin.

The mesh side verifies a DHT record against the record's own
`signer_public_key` without binding it to `source_node_id` (campaign finding
B4), so today any peer that can publish can choose a global node's answers for
any domain. The DNS registry inherits that gap and additionally defaults the
`authenticated` flag to `true`.

**D34 (Medium).** `/health` reports configuration intent as realized state:
`set_axfr_enabled(true)` is unconditional (`server/mod.rs:2206`) while AXFR answers
NOTIMP, `set_update_enabled` mirrors a config field although the handler is
never constructed (`:2210`, `update_handler: None` at `:2128`), and
`set_dnssec_signing_enabled` mirrors `dnssec_runtime.enabled` rather than a
loaded key.

**D35 (Medium).** `GET /config/dns` serializes `config.main.dns` whole
(`src/admin/handlers/config.rs:1740-1751`), including
`tsig_keys[].secret_base64`. `TsigKeyConfig` also derives `Debug`
(`dns_dnssec.rs:223-228`), so the secret can reach a log line.

## Root cause

The DNS/mesh seam was inverted (Phase 139) to keep `synvoid-mesh` types out of
DNS, but the inversion stopped at anycast: the anycast path asks the capability
"is this authentic?", while the domain-registration path kept the old
`Vec<(domain, node, ips)>` shape with no authenticity question. Health flags
were set from config because the runtime had no way to report realization.

## Fix scope

### R1 — Registrations are authenticated like anycast advertisements

- Change the DNS-owned capability to mirror the anycast shape:

```rust
fn all_domain_registrations(&self) -> Vec<AdvertisedDomainRegistration>;
fn is_domain_registration_authentic(&self, reg: &AdvertisedDomainRegistration) -> bool;
```

`AdvertisedDomainRegistration` carries `domain`, `origin_node_id`,
`ip_addresses`, `publisher_id`, `signature`, `created_at`, `ttl_seconds` — the
fields the provider needs to rebuild and verify its signed record.

- `sync_from_dht` applies a registration only when the capability says it is
  authentic **and** `publisher_id == origin_node_id`; a mismatch is dropped with
  a metric.
- `apply_dht_domain_registration` loses its `authenticated: true` default and
  takes the verified flag from the caller; an unverified registration is never
  inserted.
- `resolve_from_mesh` returns `None` when the matching origin entry is not
  authenticated, so an unverified entry cannot answer even if it slipped into
  the map.

### R2 — Authorization is separate from authenticity

A signature proves who advertised; it does not prove the node may serve that
domain. Add an explicit authorization check before an origin may answer for a
domain:

- the origin node's own zones (`DnsRegistration.zones`) for its configured
  domains, or
- an allowlist entry in config (`[dns.mesh] authorized_domains`), or
- an org-key claim when the mesh peer carries one (Phase 03's role grant).

Default is deny: a signed registration for an unlisted domain is stored for
telemetry but not served. This is the DNS-side expression of campaign T5/I5.

### R3 — Health reports realization

`DnsHealthChecker` setters are called from the place that knows:

- `axfr_enabled` ← `zone_transfer.is_some() && zone_transfer.axfr_enabled()`
  (today always false because `with_zone_transfer_config` hardcodes
  `axfr_enabled: false`);
- `update_enabled` ← `update_handler.is_some()`;
- `dnssec_signing_enabled` ← at least one zone has a ZSK handle, per zone where
  the surface allows it;
- `recursive_healthy` ← `start_recursive_server` result, not `config.enabled`;
- encrypted transports ← the listener actually bound.

`/health` gains `dns.capabilities: { axfr, ixfr, update, notify, dnssec_signing,
recursive, dot, doh, doq }` with `realized: bool` and `config_requested: bool`
per entry, so a mismatch is visible rather than inferred.

### R4 — Redact secrets

- `GET /config/dns` returns a redacted DTO: `tsig_keys: [{ name, algorithm,
  secret_set: true }]`. The secret is never serialized.
- `PUT /config/dns` still accepts `secret_base64` (write-only). An omitted field
  means "keep the existing secret"; an explicit empty string clears it. The
  redacted DTO and the request DTO are separate types.
- `TsigKeyConfig` gets a manual `Debug` that prints `secret: <redacted>`; add a
  test that `format!("{:?}")` does not contain the secret.
- Audit: no other DNS field is a secret today; `trust_anchor` paths are not
  secrets.

## Tests

New suite `tests/dns_mesh_trust_contract.rs` (feature `mesh`, using the
`CountingDht` double already in `mesh_capability_wiring.rs`):

1. an unauthenticated registration is not applied and `resolve_from_mesh`
   returns no records;
2. a registration signed by a node other than the claimed origin is dropped;
3. a correctly signed registration for an unauthorized domain is not served;
4. a correctly signed, authorized registration is served, and the answer owner
   is the queried FQDN (phase 01);
5. `authenticated` is never `true` without the capability's verdict;
6. a registration that appears after startup is picked up by the sync loop and
   then answered;
7. an origin removal stops answering immediately.

Health/redaction suite `tests/dns_truthfulness_contract.rs`:

8. with no transfer handler, `axfr` is `realized: false` even if config asked;
9. with DNSSEC enabled but no key loaded, `dnssec_signing` is false;
10. recursive that fails to start reports degraded, not healthy;
11. `GET /config/dns` JSON contains no `secret_base64` and does contain
    `secret_set: true`;
12. `PUT /config/dns` with an omitted secret preserves the previous one, and a
    subsequent GET still shows `secret_set: true`;
13. `Debug` of a TSIG key does not contain the secret.

## Out of scope

- The mesh-side signature verification itself (mesh Phase 04b).
- Anycast advertisement handling (already asks the capability).
- Admin UI presentation of the redacted DTO (follow-up if the UI reads the
  field; grep `secret_base64` in `admin-ui/` before merging).

## Verification

```bash
cargo test -p synvoid-dns --features mesh --test dns_mesh_trust_contract --profile ci
cargo test -p synvoid-dns --test dns_truthfulness_contract --profile ci
cargo test -p synvoid-dns --profile ci
cargo test -p synvoid --test admin_contract --profile ci   # config DTO shape
```

Acceptance:

- no code path constructs an `AdvertisedDomainRegistration` with
  `authenticated: true` unconditionally;
- `rg 'secret_base64' src/admin crates/synvoid-admin` shows only the request DTO
  and the canary test;
- `/health` capability flags match a matrix test that toggles each config field.
