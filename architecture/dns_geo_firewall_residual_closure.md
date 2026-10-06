# DNS Geo Firewall Residual Closure — F-3, P-2, and Two Stale Status Lines

Status: **CLOSED QUALIFIED** (2026-10-06).

Plan: `plans/dns_geo_firewall_residual_closure.md`.

Scope: the two cheapest residuals the DNS residual-truthfulness campaign
(Phases 137–140) registered but did not phase, plus two bookkeeping defects found
while auditing the plan corpus. No persisted TOML, OpenAPI, or admin schema
change. No dependency-edge change. No class or support claim.

## Summary

| Item | Outcome |
|---|---|
| F-3 `GeoLocation::from_str` infallible | Closed. Parser can now fail; the reachable silent failure was **worse than recorded**. |
| P-2 loopback invisible in public profile | Closed. Doc note plus a two-sided behavioural test. |
| P-2 dead `create_default_firewall_rules` (flagged "unverified") | Closed. Measured as **divergent**, not stale; deleted. |
| `plans/roadmap.md` stale `ACTIVE` claim | Closed here. |
| `runtime_dependency_security_followup_roadmap.md` "Phase 38 pending" | Closed here. |
| **Found incidentally:** CI red at HEAD | Closed. `new_ret_no_self` in a Phase 137 test. |

## Stale status lines

Both were real, and both were found by reading the records rather than trusting
them.

`plans/roadmap.md:3` declared the DNS residual-truthfulness campaign **ACTIVE**
and then, two sentences later, that it was "complete; no phase remains
registered." The same line carried a **spliced sentence**: *"The campaign was
They are the registered successor for…"* — the residue of an edit that inserted
text without joining the surrounding clause. Both corrected.

`plans/runtime_dependency_security_followup_roadmap.md:4` still read **"Phase 38
pending"** after Phase 38 completed and `deny.toml` was re-audited 2026-10-01
carrying exactly the two sanctioned ignores.

Worth recording how the first one was caught. The work was developed while the
repository was on a branch where a later commit had *already* fixed
`plans/roadmap.md`, so gate 3 passed there for a reason that had nothing to do with
this work. When the change was moved to `phase-125-dns-runtime-dto-contract` —
where F-3 and P-2 were formally registered — the gate failed **against real repo
state**, naming the contradictory line and quoting it. That is the one piece of
evidence in this closeout that is not a mutation: a gate finding a genuine defect
rather than an injected one.

## F-3 — the residual record understated the defect

The record named an unreachable `parts.is_empty()` branch whose consequence was
"a typo silently produces a never-matching rule." Both halves are true, but the
**reachable** silent failure was worse and unrecorded.

`firewall.rs` parsed the ASN with `parts[3].parse::<u32>().ok()`. `.ok()`
discards the error, so `"RU, , , notanumber"` and `"RU, , , 99999999999"` both
yielded `asn: None`. A rule the operator scoped to one ASN was therefore silently
**broadened** to country-only. For `Block` that widens the block; for `Allow` it
widens the grant. The recorded consequence is the benign direction.

### What changed

`GeoLocation::from_str` now rejects a missing country and a malformed ASN, while
preserving Phase 135 F-16: an **empty** field is a placeholder and stays `None`,
so `"RU, , , 64500"` and `"RU, , , "` both still parse. Treating empty as an error
would have regressed F-16 in the opposite direction — that distinction is the
subtle part of the fix and it is pinned.

This made live the `Err` arm at `firewall.rs` that Phase 133 kept, by its own
comment, "because a future validator would land here." The validator was the
parser. The arm's comment claimed the path was unreachable-in-practice; it is now
the path a mistyped target actually takes.

The parse error string is deliberately **not** surfaced at that call site: the arm
runs per query, and the decision the operator needs is the fail-closed/skip
posture, which `RuleIndeterminate::as_str` already names.

### A shipped test pinned the defect

`crates/synvoid-dns/tests/geoip_rule_evidence.rs` contained
`geo_location_parsing_cannot_fail_and_typos_still_never_match`, which asserted:

- `"".parse::<GeoLocation>().is_ok()` — "empty target parses";
- `"RU, , , notanumber"` → `asn: None` — "an unparseable ASN is silently dropped
  rather than rejected."

Both assertions pinned the defect **as intended behavior**. It was inverted, not
worked around. The surviving truth from that test — a well-formed typo like
`"RUUU"` still parses and still never matches — is kept in
`a_well_formed_typo_still_parses_and_still_never_matches`.

Evidence suite: 14 → **19** tests, all passing.

### Why severity stayed low

`DnsFirewallConfig` (`crates/synvoid-config/src/dns/dns_firewall.rs:139-157`) has
no `rules` field, and all nine `add_rule` call sites are hardcoded rules in
`DnsServer::new`. No operator can declare a `GeoLocation` rule today, so the
tightening carries no config-compatibility risk. Confirmed, not assumed.

## P-2 — loopback posture

The record's **count of 8 was correct** and all eight are `Subnet`/`Block`; its
cited line numbers were stale (`server/mod.rs` moved). Current set, gated on
`block_internal_ips`: `block_internal_ips` `10.0.0.0/8`, `block_private_172`
`172.16.0.0/12`, `block_private_192` `192.168.0.0/16`, `block_loopback`
`127.0.0.0/8`, `block_linklocal` `169.254.0.0/16`, `block_ipv6_loopback` `::1/128`,
`block_ipv6_ula` `fc00::/7`, `block_ipv6_linklocal` `fe80::/10`. A **ninth** rule,
`block_axfr` (opcode `0x2`), is installed separately under `block_zone_transfers`.

The mechanism the record called "silence" was confirmed in code, not inferred:
on a `Block` decision the TCP handler `continue`s **before writing anything**
(`crates/synvoid-dns/src/server/query.rs`). The client is not refused; it is left
waiting, so the symptom is a timeout rather than a SERVFAIL.

- **Doc note** in `docs/FEATURE_STATUS.md`, which previously mentioned neither
  `loopback`, `authoritative_public`, nor `block_internal`.
- **Test** `the_public_profile_refuses_loopback_without_writing_a_response` in
  `tests/dns_zone_startup_activation.rs` proves both directions from the **shipped
  file unmodified**: the profile refuses a loopback client without writing a
  response, and the same profile with only an in-memory `block_internal_ips: false`
  override answers. Two non-vacuity assertions guard it — the profile must really
  enable the firewall, and the zone must really activate, so a silent failure
  cannot be misattributed to the firewall.
- **No config knob was added**, per the record's explicit instruction. It would be
  a persisted-TOML schema change weakening a correct production posture to paper
  over a documentation gap.

### The item flagged "unverified" was worse than undiffed

`create_default_firewall_rules` had **zero callers** anywhere in `src/`, `crates/`,
`tests/`, `tools/`. Its 6 rules are not a stale copy of the live 8 but a
**divergent** set: it shipped `block_multicast`, `block_reserved_domains`,
`block_example_domains`, `block_zone_transfer`, and `block_ixfr` — none of which
the live path installs — while omitting loopback, link-local, and every IPv6
internal range. A reader trusting it would conclude multicast and IXFR are blocked
in production and that loopback is not. Every one of those conclusions is wrong.

**Deleted rather than corrected.** A second copy of the internal-IP rule set would
require manual synchronisation forever and is a subtler trap than the divergent one
it replaces. The live rules are config-driven and belong to `DnsServer::new`,
which stays the single definition.

`create_rate_limit_rules` was deleted with it: also zero callers, and it described
per-domain and per-IP limiting as firewall `RateLimit` rules when production rate
limiting is a separate `[dns.rrl]` mechanism. Same defect class, same file, found
while doing the work; recorded here as a scope addition rather than silently taken.

## Found incidentally — CI was already red at HEAD

`cargo clippy --profile ci --all-targets -- -D warnings` — a CI gate — failed
before this work touched anything, on
`crates/synvoid-dns/tests/encrypted_transport_alpn_negotiation.rs:101`, which
tripped `new_ret_no_self` (Phase 137 work). Constructor renamed to
`from_certificate`, matching the `from_*` convention. Confirmed pre-existing
because the file was unmodified in the working tree and the lint is on a method
name that a `firewall.rs` change cannot affect.

Recorded here rather than quietly folded in, because a red CI gate is a finding
about the campaign that shipped it, not about this phase.

## Guards

Three gates in `tools/synvoid-repo-guards/tests/dns_firewall_truthfulness.rs`.
All mutation-tested; **6 of 6 mutations fired**.

| Mutation | Gate | Fired |
|---|---|---|
| Reinstate `parts.is_empty()` | 1 | yes |
| Revert ASN to `.parse::<u32>().ok()` | 1 | yes |
| Remove the missing-country rejection | 1 | yes |
| Reintroduce `create_default_firewall_rules` | 2 | yes |
| Rename live `block_loopback` away | 2 | **no — gate bug** |
| Restore a contradictory status line | 3 | yes |

### Two guard bugs, caught by mutation testing

Mutation testing is only worth its cost if a mutation that *should* fire reveals a
gate that cannot. It did, twice:

1. **Gate 1 failed on correct code.** A loose `is_empty` + `parts` heuristic could
   not distinguish `parts.is_empty()` — the unreachable branch the gate exists to
   catch — from `country.is_empty()`, which is the **fix**. Rewritten with a
   whole-token `method_called_on(receiver, method)` scan that tolerates whitespace
   around the dot, so a rustfmt line break cannot hide it either.
2. **Gate 2 passed a renamed live rule.** `live.contains("block_loopback")` is
   satisfied by `block_loopback_removed`, so mutation 5 passed a gate that exists
   precisely to catch that. Switched to whole-token matching — the same
   substring-collision class already seen with `DhtRecord` / `DhtRecordStore`.

Gate 3 also carries a corpus-size assertion: a scan that inspected only 63 of 334
plan files is failing loudly rather than passing vacuously.

## Verification

- `cargo xtask verify` — **10 steps, 10 passed, 0 skipped** (659.7s).
  First run failed at step 1 (`fmt`) because the new guard file was not
  rustfmt-clean; fixed, re-run green.
- `cargo nextest run -p synvoid-repo-guards` — **163 passed** (was 160; +3 new).
- `cargo test -p synvoid-dns --profile ci --test geoip_rule_evidence` — 19 passed.
- `cargo test --test dns_zone_startup_activation --features dns --profile ci` —
  5 passed.
- `cargo clippy -p synvoid-dns --profile ci --all-targets -- -D warnings` — exit 0.
- Not run: the `-p synvoid-dns --features mesh` full parallel suite and
  `verify-full` / `verify-release`. Reason: `cargo xtask verify` already ran the
  full CI lane set including the security-regression and failure-injection suites,
  and the changed surface is DNS-internal with no feature-gated or mesh-reachable
  code path. Deliberately not skipped for convenience — recorded here so the gap is
  a decision rather than an omission.

## Residuals recorded, not fixed

- **The nine `let _ = fw.add_rule(...)` sites** in `server/mod.rs` discard a
  `Result`. All nine set `expires_at: None` so none can fail today, but a future
  edit that sets it would silently drop a rule. This is **already registered** as
  item 2 of Phase 146 in the reachability-truthfulness campaign; not duplicated
  here.
- `architecture/dns_config_runtime_matrix.md` and the residual record's own
  wording are corrected **by pointer** only. No historical closeout was rewritten.