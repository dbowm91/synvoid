# DNS Geo Firewall Residual Closure — F-3, P-2, and Two Stale Status Lines

Status: **IN PROGRESS** (opened 2026-10-06, after the DNS residual-truthfulness
campaign Phases 137–140 closed and registered no successor phase).

This is a small, self-contained closure of the two cheapest registered residuals
the campaign deliberately left unphased, plus two bookkeeping defects found while
auditing the plan corpus on 2026-10-06. It does **not** reopen any closed
campaign and does not change any persisted TOML, OpenAPI, or admin schema.

## Why this is eligible now

`plans/dns_residual_truthfulness_roadmap.md` recorded F-3 and P-2 as
"registered, not phased" — not deferred, not blocked, just unclaimed. An audit on
2026-10-06 confirmed neither has been picked up and neither has acquired a live
trigger that would make it dangerous. Both are correctness/truthfulness fixes
with no config-reachability change.

## What the residual records say, and what the code shows

Three of the recorded premises are wrong or imprecise. Scope here is set by the
code, and historical closeouts are corrected **by pointer only**.

### F-3 — premise corrected

Recorded: *"`GeoLocation::from_str` still cannot fail:
`crates/synvoid-dns/src/firewall.rs:572`'s `parts.is_empty()` is unreachable
because `"".split(',')` always yields one element. A typo silently produces a
never-matching rule."*

Measured:

1. The unreachable branch is real (`firewall.rs:572-574`), but it is **not the
   worst consequence**. The reachable silent-failure is worse and unrecorded:
   `firewall.rs:576-580` parses the ASN with `parts[3].parse::<u32>().ok()`.
   `.ok()` **discards** the error, so `"RU, , , 99999999999"` (out of `u32`
   range) and `"RU, , , abc"` both silently yield `asn: None`. A rule the
   operator scoped to one ASN is therefore silently **broadened** to
   country-only. For a `Block` action that widens the block; for `Allow` it
   widens the grant. The recorded consequence ("never-matching rule") is the
   *benign* direction; the unrecorded one is a silent scope change.
2. The consuming arm at `firewall.rs:277-280` already handles failure correctly
   and correctly (`RuleIndeterminate::UnparseableTarget` plus
   `fails_closed_when_indeterminate()`), and its comment says it is kept
   "because a future validator would land here." **That future validator is this
   phase.** The infrastructure was built in Phase 133 and waited for a parser
   that could actually fail.
3. `DnsFirewallConfig` (`crates/synvoid-config/src/dns/dns_firewall.rs:139-157`)
   has **no `rules` field**, and all nine `add_rule` call sites are hardcoded
   `Subnet`/`Block`/`Opcode` rules in `DnsServer::new`
   (`crates/synvoid-dns/src/server/mod.rs:1971-2069`). So **no operator can
   declare a `GeoLocation` rule today.** This bounds the blast radius to
   programmatic callers — which is why F-3 has stayed low severity, and why
   tightening the parser carries no config-compatibility risk.

### P-2 — count confirmed, line numbers wrong, plus one unverified item resolved

Recorded: *"`block_internal_ips = true`, which installs **8** `Subnet`/`Block`
rules (`crates/synvoid-dns/src/server/mod.rs:1886-1982`), including
`127.0.0.0/8` `block_loopback` (`:1923-1933`) and `::1/128` (`:1947-1957`)."*

Measured: the **count of 8 is correct**, and all eight are `Subnet`/`Block`.
The cited line numbers are stale (`server/mod.rs` moved; the rules are now
`:1961-2055`). Current set, all gated on `block_internal_ips`:

| id | target |
|----|--------|
| `block_internal_ips` | `10.0.0.0/8` |
| `block_private_172` | `172.16.0.0/12` |
| `block_private_192` | `192.168.0.0/16` |
| `block_loopback` | `127.0.0.0/8` |
| `block_linklocal` | `169.254.0.0/16` |
| `block_ipv6_loopback` | `::1/128` |
| `block_ipv6_ula` | `fc00::/7` |
| `block_ipv6_linklocal` | `fe80::/10` |

A **ninth** rule, `block_axfr` (opcode `0x2`), is installed separately under
`block_zone_transfers` (`:2058-2070`) and is not part of the 8.

**The item the residual flagged as "unverified" is now resolved, and it is
worse than "not diffed".** `create_default_firewall_rules`
(`crates/synvoid-dns/src/firewall.rs:626`) has **zero callers** anywhere
(`src/`, `crates/`, `tests/`, `tools/` — the only other hit is
`architecture/standalone_crate_dependency_baseline.json`, a historical
measurement artifact). Its 7 rules are **not** a stale copy of the live 8:

- live-only: `block_loopback`, `block_linklocal`, `block_ipv6_loopback`,
  `block_ipv6_ula`, `block_ipv6_linklocal`, `block_private_172`,
  `block_private_192`;
- helper-only: `block_multicast`, `block_reserved_domains`,
  `block_example_domains`, `block_zone_transfer`, `block_ixfr`,
  `rate_limit_per_domain`.

So a reader who trusted the helper would conclude that multicast, reserved
domains, IXFR, and per-domain rate limiting are blocked in production, and that
loopback and IPv6 link-local are **not**. Every one of those conclusions is
wrong. This is the "mistaken for the live path" hazard the residual warned about,
realised.

## Workstreams

### A — Make `GeoLocation::from_str` able to fail (F-3)

In `crates/synvoid-dns/src/firewall.rs`:

1. Reject a missing country. The country is `parts[0]`; if it trims to empty the
   spec cannot describe a location, and today it yields a rule that matches
   nothing. Error.
2. Reject a **malformed** ASN while preserving the Phase 135 F-16 placeholder
   semantics: an **empty** 4th field is a placeholder and stays `None`
   (`"RU, , , "` must keep working, and `"RU, , , 64500"` must keep parsing);
   a **non-empty** 4th field that is not a `u32` is an error. This is the
   precise distinction — treating empty as an error would regress F-16.
3. Remove the unreachable `parts.is_empty()` branch; `parts[0]` cannot be empty
   after step 1 rejects it.
4. Rewrite the `Err(_)` arm comment at `:274-276`, which currently claims the
   arm is unreachable-in-practice, and widen the match to bind the error so the
   reason string can name the malformed field.

Error text must be stable and operator-facing, consistent with
`TimeWindow::from_str` (`:605-624`), which already fails closed on a bad field.

### B — Delete the divergent duplicate helper (P-2)

Remove `create_default_firewall_rules` from `crates/synvoid-dns/src/firewall.rs`.

Not "fix it to match the live set": a second definition of the internal-IP rule
set is a *worse* trap than the current one, because it would then require
manual synchronisation forever. The live rules are config-driven and built in
the composition-visible constructor; a "default rules" builder is conceptually
the wrong home for them. Deletion also removes the last thing that could be
mistaken for the live path.

### C — Pin the loopback posture in docs and by test (P-2)

1. **Doc note** in `docs/FEATURE_STATUS.md`, under a new short subsection beside
   the DNS Server row. It must state that `block_internal_ips = true` includes
   `127.0.0.0/8` and `::1/128`, that loopback is **not separately controllable**,
   that the block is at firewall admission so the symptom is **silence** (no
   SERVFAIL — just no answer), and that the correct local-verification pattern is
   an **in-memory** override of `block_internal_ips`, not a config flag.
   `docs/FEATURE_STATUS.md` currently mentions none of `loopback`,
   `authoritative_public`, or `block_internal` — confirmed by grep.
2. **Behavioural test** in `tests/dns_zone_startup_activation.rs` (already
   `#![cfg(feature = "dns")]`) that starts the **shipped profile unmodified** and
   proves a loopback client is refused, then proves the same profile with the
   in-memory `block_internal_ips: false` override answers. That pins the
   operator-visible consequence in both directions, and reuses the existing
   `start_with_zones` harness and free-port retry loop.

**Explicitly not doing**, per the residual: adding a config key to exempt
loopback. It would be a persisted-TOML schema change and would weaken a correct
production posture to fix a documentation gap.

### D — Correct the two stale status lines (bookkeeping)

1. `plans/roadmap.md:3` — declares the DNS residual-truthfulness campaign
   **ACTIVE** and then self-contradicts two sentences later ("The campaign is
   **complete**; no phase remains registered"). The same line contains a
   **spliced sentence**: *"The campaign was They are the registered successor
   for…"*. Rewrite the status to say closed, and repair the splice.
2. `plans/runtime_dependency_security_followup_roadmap.md:4` — still reads
   **"Phase 38 pending"**. Phase 38 completed; `deny.toml` carries exactly the
   two sanctioned ignores and was re-audited 2026-10-01.

Neither file is rewritten beyond its stale status sentence. The 2026-09-18
roadmap's PR #769 ordering is permanently unreachable (closed-unmerged, recorded
at `Cargo.toml:483`) and is corrected **by pointer** in the closeout rather than
edited here, to keep this unit small.

## Guards (each mutation-tested)

1. `geo_firewall_target_parsing_is_not_silently_permissive` —
   `GeoLocation::from_str` must reject a missing country and must not discard an
   ASN parse error (no `.ok()` / `unwrap_or` on the ASN). Fails if the silent
   widening is reintroduced.
2. `internal_ip_rules_have_exactly_one_definition` — the internal-IP block rule
   set may only be defined inside `DnsServer::new`; no default-rule builder may
   reappear in `synvoid-dns`. Fails if a parallel copy is added.
3. `no_plan_status_line_claims_a_closed_campaign_is_open` — a `plans/` status
   line may not claim `ACTIVE`/`PENDING` for a campaign that also claims
   completion. Scoped statement-wise so it cannot fire vacuously or on unrelated
   prose. Fails if either stale line is restored.

Plus behavioural evidence in `crates/synvoid-dns/tests/geoip_rule_evidence.rs`
for the parser and the resulting firewall posture, and the two-sided loopback
test from Workstream C.

## Rejection criteria

- Fails if any persisted TOML, OpenAPI schema, or admin response schema changes.
- Fails if `synvoid-dns` gains or loses a SynVoid dependency edge.
- Fails if `docs/FEATURE_STATUS.md` gains a config knob that does not exist.
- Fails if `"RU, , , 64500"` or `"RU, , , "` stops parsing (F-16 regression).
- Fails if any of the three guards cannot be made to fail by a real mutation.
- Fails if a historical closeout is edited rather than corrected by pointer.

## Verification

- `cargo xtask verify` (10 lanes).
- `cargo test -p synvoid-dns --profile ci --features mesh` full parallel suite.
- `cargo test --test dns_zone_startup_activation --features dns --profile ci`.
- `cargo test -p synvoid-repo-guards --profile ci`.
- Mutation-test all three guards; record which mutations fired.
- Every skipped lane recorded as not-run with its reason.