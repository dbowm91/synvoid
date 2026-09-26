# Phase 81 Plan: ICMP Policy Model and Config Canonicalization

Status: planned.

Registered in: `plans/roadmap.md` and
`plans/icmp_policy_enforcement_extraction_preparation_roadmap.md`.

Baseline: `main` at `81638c251592913579bd9bbce51d013c44d67910`.

Depends on: none. This is the first phase of the extraction-preparation
campaign.

## Goal

Eliminate shape-coupled duplicate ICMP policy ownership and establish a
portable, family-aware policy contract that later backend phases can compile
without depending on SynVoid configuration, admin, metrics, or runtime types.

This phase is primarily a semantic/canonicalization cleanup. It must preserve
the existing SynVoid configuration surface wherever possible.

## Current defects to close

### Duplicate config families

Today both of these files independently own an ICMP policy/config vocabulary:

- `crates/synvoid-config/src/icmp_filter.rs`
- `crates/synvoid-icmp-filter/src/config.rs`

They no longer have equivalent serialization or behavior. The admin handler
converts between them through JSON, so a field present on one side can be
silently defaulted, dropped, or rejected on the other side.

This phase must make one owner authoritative for enforcement semantics.

### Raw type numbers are the only policy vocabulary

Raw `u8` type/code remains necessary as an escape hatch, but it is not a
sufficient primary API for a reusable ICMP policy library. The model must be
able to distinguish family and common message semantics, especially for
ICMPv6.

### Rate-limit meaning is underspecified

`packets_per_second` + `burst` does not say whether the limit is global,
per-interface, per-source, per-type/code, or some combination. Backends cannot
truthfully negotiate a policy whose scope is undefined.

## Workstream A — separate application config from portable policy

Define a portable enforcement model in `synvoid-icmp-filter` (or a clearly
isolated internal module selected during implementation) with names that
describe policy rather than SynVoid config, for example:

- `IcmpPolicy`
- `IcmpRule`
- `IcmpFamily`
- `IcmpMatch`
- `IcmpVerdict`
- `PolicyDirection`
- `InterfaceSelector`
- `RateLimitPolicy`
- `BackendPreference` / backend options kept outside the protocol policy

Do not force these exact names if the implementation finds a cleaner API, but
the ownership split is binding:

- portable protocol policy is independent of TOML/OpenAPI concerns;
- SynVoid config remains responsible for user-facing serialization/schema;
- backend-specific knobs such as nft table identity or eBPF object path are not
  protocol policy.

The enforcement crate must no longer expose a second
`IcmpFilterConfig` that competes with the application config DTO.

A schema DTO may mirror fields when required by `schemars`/`utoipa`, but it
must not become a second semantic authority.

## Workstream B — replace serde-shape conversion with an exhaustive adapter

Remove ICMP conversions that go through `serde_json::Value`, especially the
admin persistence path.

Create an explicit conversion at the composition boundary:

```text
synvoid_config::icmp_filter::IcmpFilterConfig
        |
        | TryFrom / named adapter
        v
portable IcmpPolicy + BackendPreference/BackendOptions
```

The adapter must:

- parse exempt addresses exactly once;
- preserve direction/interface intent;
- preserve all ICMPv4 and ICMPv6 rules supported by the public config;
- map rate-limit semantics explicitly;
- validate backend-specific fields separately from protocol policy;
- return typed errors for invalid/inexpressible configuration;
- never default a field merely because the other struct lacks it.

If the current user-facing config cannot express a separate ICMPv6 rule list,
either add a backwards-compatible family field/list with defaults/aliases or
map the legacy list under a documented family rule. Do not silently reinterpret
legacy ICMPv4 numeric types as ICMPv6.

## Workstream C — canonicalize defaults without breaking persisted config

Resolve and test current divergences:

- `synvoid-icmp` vs `synvoid_icmp` table default;
- `custom_ebpf_bytecode_path` vs `ebpf_bytecode_path`;
- interface identifier validation;
- enum serde casing;
- rate-limit absent/disabled representation.

Choose one internal canonical representation. Preserve legacy serialized
spelling/default compatibility with aliases or explicit adaptation where
necessary.

Add golden TOML and JSON fixtures representing the currently supported
configuration shapes before changing implementation.

## Workstream D — family-aware typed ICMP vocabulary

Introduce typed constants/enums for common ICMPv4 and ICMPv6 messages while
retaining an explicit raw escape hatch.

The model must not make numeric type `N` meaningful without a family.

At minimum cover current SynVoid rules plus operationally significant ICMPv6
messages:

- Destination Unreachable
- Packet Too Big
- Time Exceeded
- Parameter Problem
- Echo Request/Reply
- Router Solicitation/Advertisement
- Neighbor Solicitation/Advertisement
- Redirect

Unknown/reserved types remain representable.

Type/code validation should distinguish:

- structurally representable raw values;
- known message/type-code combinations;
- unknown but intentionally allowed raw combinations.

Do not reject every unknown value simply because the library does not have a
named enum variant.

## Workstream E — RFC-aware safety validation

Add a policy-validation layer informed by RFC 4890 and RFC 8201.

The validator should support an explicit context/role (at least host vs
router/transit where semantics differ) and return structured findings.

Important behavior:

- identify rules that block ICMPv6 messages required for correct IPv6
  operation;
- specifically protect visibility of Packet Too Big / PMTUD hazards;
- distinguish warning/advisory validation from an opt-in strict mode;
- do not silently rewrite user rules;
- make override/acknowledgement explicit for intentionally dangerous policy.

The default SynVoid migration should preserve existing behavior while surfacing
new diagnostics unless the current behavior is unambiguously invalid.

References:
- https://www.rfc-editor.org/rfc/rfc4890
- https://www.rfc-editor.org/rfc/rfc8201

## Workstream F — define rate-limit semantics

Replace ambiguous "rate limit exists" semantics with an explicit scope.

The first implementation may support only the scopes the current backends can
truthfully implement. A minimal initial contract could make the existing
behavior explicitly `Global`; richer scopes such as per-source or
per-type/code must be capability-gated.

The policy type should carry:

- rate;
- burst;
- scope;
- family/type selector when applicable;
- whether unsupported exact semantics are a hard error.

Do not emulate a requested per-source limit with a global limit and call it
equivalent.

## Workstream G — keep application-only concerns outside the portable model

Do not move into the portable policy model:

- admin API DTOs;
- OpenAPI response wrappers;
- metrics names;
- tracing text;
- config file paths;
- SynVoid process/runtime handles;
- eBPF artifact discovery policy.

Backend selection/options may live beside enforcement, but they are not part of
the protocol policy value.

## Required tests

Add focused tests for:

1. legacy/default TOML round-trip;
2. admin JSON shape compatibility;
3. exhaustive config-to-policy conversion;
4. invalid IP/interface/backend option rejection;
5. ICMPv4 and ICMPv6 family separation;
6. named and raw type/code round-trip;
7. RFC-sensitive ICMPv6 safety findings;
8. Packet Too Big blocking warning/strict behavior;
9. rate-limit scope serialization/conversion;
10. no serde-Value conversion in active ICMP paths.

Add a repo guard or source-level invariant if practical so a second
`IcmpFilterConfig` semantic owner or JSON bridge is not reintroduced.

## Verification

At minimum:

```bash
cargo fmt --all -- --check
cargo test -p synvoid-icmp-filter --profile ci
cargo test -p synvoid-config --profile ci
cargo check --no-default-features --features icmp-filter --profile ci
cargo xtask test guards
cargo xtask verify
```

If user-facing schema changes are unavoidable, include the admin route/config
contract suites that exercise the ICMP endpoints.

## Acceptance criteria

- One canonical semantic policy owner exists.
- Active code contains no JSON round-trip between ICMP config models.
- Backend-specific options are separated from portable protocol policy.
- Existing persisted/default SynVoid ICMP configuration remains readable.
- IPv4 and IPv6 rule families cannot be confused implicitly.
- Common ICMP messages have typed representations plus a raw escape hatch.
- RFC-aware validation detects at least the critical ICMPv6/PMTUD hazards.
- Rate-limit scope has defined semantics.
- All conversion errors are explicit and typed.
- No publication/external-repo change occurs in this phase.

## Rejection criteria

Reject the phase if it:

- keeps two independent policy validators and merely adds another adapter;
- uses serde/JSON as the compatibility contract;
- breaks existing config without a migration/alias;
- makes `u8` type numbers family-agnostic;
- treats all ICMPv6 blocking as equivalent to IPv4 ping filtering;
- invents backend support for a rate-limit scope no backend implements;
- introduces OpenAPI/metrics/runtime dependencies into the reusable policy
  model.
