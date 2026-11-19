# DNS Serving Correctness and Trust Boundaries — Closeout

Status: **CLOSED** (2026-11-19).
Campaign: `plans/dns_serving_correctness_roadmap.md`.
Audit: `plans/dns_capability_audit.md` (D1–D39; D40 was found and fixed at the
phase-10 gate).
Baseline: `ea638ff9` (merged `main`). The campaign is implemented in the
working tree on top of that commit; no campaign commit was created during the
implementation run.

## What was actually broken

The audit's core finding was structural, not a list of edge cases:

1. **No owner encoder.** Authoritative records are stored origin-relative, and
   one path wrote the storage key (`www`) as the owner while the other wrote
   presentation-format ASCII (`example.com`). Signing used the same relative
   name, so no RRSIG could verify.
2. **No admission path.** UDP and TCP validated and consulted the firewall;
   DoT/DoH/DoQ called the handler directly, and the EDNS parser had no bound,
   so one 30-byte packet stopped the UDP listener for the process lifetime.
3. **Proofs and signatures were synthesized per query** instead of derived from
   the zone, so NSEC/NSEC3 asserted names and types that did not exist.

The campaign established five invariants and made each one testable.

## Invariants and where they are enforced

| Invariant | Enforcement | Proof |
|---|---|---|
| **I1 one owner encoder** | `wire::OwnerName`/`encode_owner`; `encode_rr(record, origin, …)`; question echoed verbatim; recursive owners and RDATA through the same encoder | `dns_wire_contract` (9) |
| **I2 one admission path** | `server::admit` is the only way to obtain an `Admitted`, required by `serve_admitted`; UDP, TCP, DoT, DoH, DoQ all call it | `dns_admission_contract` (9) |
| **I3 proofs come from the zone** | `ZoneDenial` built once from a canonical owner index; NSEC/NSEC3 selected by coverage; RRSIGs over canonical FQDNs with the KSK/ZSK split | `dnssec_denial_contract` (18), `dnssec_signature_contract` (13) |
| **I4 fail closed and say so** | resolver failures → SERVFAIL (never cached as NODATA); signing/denial failure → SERVFAIL; `/health` reports `realized` vs `config_requested` | `dns_recursive_contract` (25), `dns_truthfulness_contract` (5) |
| **I5 trust follows the channel** | mesh registration served only when authenticity **and** publisher binding **and** authorization pass; unauthenticated entries never answer | `dns_mesh_trust_contract` (9, `--features mesh`) |

## Phase summary

| Phase | Change | Suite | Tests |
|---|---|---|---|
| 01 | Total owner-name encoder; verbatim question echo; recursive wire names | `dns_wire_contract` | 9 |
| 02 | Field-by-field OPT; honest payload budgets; QDCOUNT-consistent errors; one ARCOUNT-aware EDNS parse | `dns_envelope_contract` | 12 |
| 03 | Bounded EDNS/TSIG parsers; unified `admit`; encrypted-listener parity and caps; fuzz targets | `dns_admission_contract` | 9 |
| 04 | RRSIG over canonical FQDN; KSK-signed DNSKEY; signed SOA in negative answers; RRset-wide signatures; fail-closed signing | `dnssec_signature_contract` | 13 |
| 05 | `ZoneDenial` canonical owner index; derived NSEC/NSEC3; correct NSEC3 hash/owner; rotation removed honestly | `dnssec_denial_contract` | 18 |
| 06 | Failure vs absence; stale as fallback; `cd` cache key; per-waiter answers; firewall/limits; explicit upstreams; RFC 5011 deleted | `dns_recursive_contract` | 25 |
| 07 | RFC 8945 TSIG (full RR, response MAC); per-zone transfer ACL; IXFR parity; RFC 2136 updates; NOTIFY auth; cookie enforcement | `dns_control_plane_contract` | 22 |
| 08 | Mesh authenticity + publisher + authorization; health realization matrix; secret redaction | `dns_mesh_trust_contract`, `dns_truthfulness_contract` | 9 + 5 |
| 09 | Wildcard/referral/ENT/DNAME lookup; single zone writer; `Arc<Zone>` snapshots; zone-file/store correctness; cache-hit ID rewrite (D40) | `dns_authoritative_lookup` | 11 |
| 10 | CI registration with count guards; external interop lane; documentation and audit closure | `dns_external_interop` | 6 |

## Verification matrix (executed 2026-11-19)

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy -p synvoid-dns -p synvoid-config -p xtask --profile ci --all-targets -- -D warnings` | clean |
| `cargo test -p synvoid-dns --profile ci` | **1391 passed, 0 failed** |
| `cargo test -p synvoid-dns --features mesh --profile ci` | **1423 passed, 0 failed** |
| `cargo test -p synvoid-config --profile ci` | **297 passed, 0 failed** |
| `cargo test -p synvoid --features dns --test dns_truthfulness_contract --profile ci` | 5 passed |
| `cargo test -p synvoid-dns --test dns_wire_contract --profile ci` | 9 passed |
| `cargo test -p synvoid-dns --test dns_envelope_contract --profile ci` | 12 passed |
| `cargo test -p synvoid-dns --test dns_admission_contract --profile ci` | 9 passed |
| `cargo test -p synvoid-dns --test dnssec_signature_contract --profile ci` | 13 passed |
| `cargo test -p synvoid-dns --test dnssec_denial_contract --profile ci` | 18 passed |
| `cargo test -p synvoid-dns --test dns_recursive_contract --profile ci` | 25 passed |
| `cargo test -p synvoid-dns --test dns_control_plane_contract --profile ci` | 22 passed |
| `cargo test -p synvoid-dns --test dns_authoritative_lookup --profile ci` | 11 passed |
| `cargo test -p synvoid-dns --features mesh --test dns_mesh_trust_contract --profile ci` | 9 passed |
| `bash scripts/dns/conformance.sh --test-threads=1` | **21/21 internal lanes passed**, 0 failed; 9 external checks skipped because `DNS_CONFORMANCE_TARGET` was unset |
| `cargo build --profile ci --bin synvoid` | succeeds |
| `cargo xtask verify` | see "Routine lane" below |

Every new suite is registered in `verify_steps()` with a `--list` count guard,
so a suite that compiles but runs zero cases fails the lane.

### Routine lane

`cargo xtask verify` was executed on this tree. `fmt` (4.5 s) and
`clippy --workspace` (145.5 s) passed; the lane then **failed at
`dependency-policy`**:

```text
RUSTSEC-2026-0573  wasmtime 48.0.8 via yara-x 1.23.0
advisories FAILED, bans ok, licenses ok, sources ok
```

The runner is fail-fast, so the DNS steps after it did not run in that
invocation. The advisory is pre-existing: `Cargo.lock` is unchanged from
`ea638ff9` and the campaign adds no dependency version (it only enables
`tokio`'s `test-util` feature for a paused-time test). Every DNS step was run
directly (the matrix above) and passes; `cargo xtask verify --dry-run` lists
all of them. The lane is therefore **not green**, for a reason outside the DNS
campaign.

## Gate status

| Criterion | Status |
|---|---|
| D1–D40 closed, or deferred by an owner decision | **Met** — L10 and the D11 producer binding are recorded as deferred; key rotation is a documented manual runbook |
| `cargo xtask verify` green | **Not met** — fails at `dependency-policy` on the pre-existing wasmtime advisory; `fmt` and workspace `clippy` pass, and every DNS step passes directly |
| Release-profile run of the ten suites through `scripts/dns/conformance.sh --release` | **Partial** — the conformance script ran all 21 internal lanes on the `ci` profile (21/21); `--release` was not run because the workspace release profile uses fat LTO and the ten test binaries do not fit the host's time/memory budget. No DNS suite failed in the ci-profile run. |
| External validator accepts a served signed zone | **Met** — `delv 9.18.39` reports `fully validated` against the served KSK |
| No document claims a control the runtime does not realize | **Met** — `/health` capability matrix is tested; docs corrected |
| Audit and roadmap updated | **Met** |

## External validation

Executed on 2026-11-19 with `DiG 9.18.39` and `delv 9.18.39`. The
`dns_external_interop` lane starts a real listener on an ephemeral loopback
port and invokes the tools against it; absent tools are reported as `SKIP`,
never as validation.

| Check | Result |
|---|---|
| `dig +short www.example.com A` / apex A | PASS — configured addresses |
| wildcard `host.wild.example.com` and NODATA `txtonly.example.com` | PASS — synthesized answer / NOERROR with 0 answers |
| NXDOMAIN `missing.example.com` | PASS — `status: NXDOMAIN`, empty `+short` |
| `dig +bufsize=512 +ignore +notcp big.example.com A` | PASS — MSG SIZE ≤ 512 with `tc` set |
| `dig +tcp www.example.com A` | PASS — NOERROR with the address |
| `dig +dnssec www.example.com A` | PASS — `RRSIG A 15 3 … example.com.` served |
| `delv -a <served-KSK-anchor> +root=example.com` | **PASS — `fully validated`** against the KSK the fixture served |
| `delv` without an anchor | INCONCLUSIVE (recorded, never counted as validation) |
| `delv +cd` | UNSUPPORTED on 9.18 (recorded, not asserted) |
| `kdig`, `ldns-verify-zone`, `named-checkzone` | SKIP — not installed on this host |

The in-process proof tests do not depend on these tools: every served RRSIG is
verified with hickory's verifier and the RFC 4034 §3.1.2 signed-data
reconstruction, and every NSEC/NSEC3 proof is checked against the zone index.

## Fuzz

`fuzz/dns_edns_options` and `fuzz/dns_tsig_parse` are registered as `[[bin]]`
targets with committed corpus seeds. 60-second smoke runs:

- EDNS: 300,471 executions in 61 s, exit 0.
- TSIG: 285,829 executions in 61 s, exit 0.

The runs use the `--dev` fuzz profile: the workspace release profile sets
`lto = true`, and the ASan/fuzz build did not fit this host's memory within a
20-minute budget. Fuzz is not part of `cargo xtask verify`; that is a gap in
coverage, not a claim of coverage.

## Deferred items and owner decisions

| Item | Status | Reason |
|---|---|---|
| D11 producer-side signature binding | **deferred to mesh phase 04b** | The DNS boundary now refuses unauthenticated registrations, so production DHT registrations default-deny. The mesh record must bind its signer to `source_node_id` before anything can be served. |
| Key rotation (`D24`) | **removed, manual runbook** | No rotation-to-zone writer exists; the old task rotated keystore handles that were never served, and rollover state was in memory, so a restart resurrected a retired key. `docs/dns-dnssec-architecture.md` documents the manual procedure. |
| `mesh_dnssec.rs` (`L10`) | **deferred** | Public dead code with no callers; deleting it is a product decision (possible future mesh-validation entry). It is unreachable today. |
| NSEC3 Opt-Out referral response | **covered by chain tests, not a referral test** | The chain and no-DS proof are tested; a signed NSEC3 Opt-Out referral response is not. |
| `GET /config/main` and HSM PIN | **closed beyond the original plan** | Both leaked credentials the audit's D35 scope did not name; redaction and write-only semantics were extended to them. |

## Operator-visible changes

- Answer owners are FQDNs and the client's question is echoed byte-for-byte
  (0x20 case survives).
- EDNS responses carry `CLASS = payload`, `TTL = ext-RCODE/DO`,
  `RDLENGTH = 0`; a client advertising 512/1232 is never sent 4 KiB; stream
  transports use the 65535 budget; unsupported versions get BADVERS.
- `QR=1` packets are dropped, not answered; DoT/DoH/DoQ apply the same
  validator/firewall/rate limit as UDP/TCP and are connection-capped.
- DNSSEC: RRSIGs verify; the DNSKEY RRset is KSK-signed; negative answers sign
  the SOA; NSEC/NSEC3 are derived from the zone. Cached RRSIGs from before the
  upgrade must be flushed.
- Recursive: upstream failures are SERVFAIL and are not negative-cached;
  NXDOMAIN returns RCODE 3 with the SOA TTL; stale is served only after an
  upstream failure, with TTL 30; TTL 0 is not cached; custom upstream ports
  are honoured; an empty/hostname-only upstream list fails startup;
  `dnssec_validation = true` with a forwarder requires
  `allow_unvalidated_forwarding = true` and reports `delegated`.
- Control plane: TSIG is RFC 8945-canonical and a present TSIG is always
  verified; transfer authorization is per-zone; IXFR over UDP is truncated;
  UPDATE follows RFC 2136 metavalues and commits atomically. The
  `allow_transfer` / `dynamic_update` / `notify` config gates remain closed.
- Cookies: `dns.settings.require_cookie` (default false) enables BADCOOKIE
  enforcement on UDP.
- `/health` reports `dns.capabilities` with `realized` and `config_requested`;
  TSIG secrets and HSM PINs are write-only on `GET`, `PUT` preserves an
  omitted value.
- Mesh domain registrations are served only after authenticity, publisher
  binding, and authorization; the default is deny.
- `ShardedZoneStore` returns `Arc<Zone>` snapshots, so a query no longer copies
  the zone plus up to 200 history versions; zones support wildcards, referrals,
  empty non-terminals, and DNAME.
- A cached authoritative response now echoes the *current* query's transaction
  ID (D40); previously the second client for the same name received the first
  client's ID and discarded the datagram.

## Residual risks

- The signed-referral test is NSEC-only; NSEC3 Opt-Out referral responses are
  not exercised end to end.
- `Zone::lookup` requires a current owner index; a hand-built `Zone` must call
  `rebuild_denial`/`commit_records` first (documented in the test fixture).
- Dynamic update rebuilds the denial chain twice on its rare path (correct, not
  free).
- The coalescer's waiter adaptation is tested at the coalescer and admission
  levels; a full two-client network test does not exist.
- External `delv` validation depends on the host's toolchain; a skip is
  reported as a skip.

## Evidence

- Audit with per-finding remediation status: `plans/dns_capability_audit.md`.
- Campaign and phase plans: `plans/dns_serving_correctness_roadmap.md`,
  `plans/dns_serving_correctness_phase_01_*` … `_phase_10_*`.
- CI lane: `tools/xtask/src/verify.rs` (`dns-*` steps).
- Conformance script: `scripts/dns/conformance.sh`.
- Operator configuration: `docs/CONFIGURATION.md`.
- Verification contract: `docs/testing/verification-contract.md`.
