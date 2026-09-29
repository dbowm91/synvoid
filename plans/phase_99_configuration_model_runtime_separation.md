# Phase 99 Plan: Configuration Model and Runtime Capability Separation

Status: implemented and closed 2026-09-28.

Closeout: `architecture/config_model_phase99_closeout.md`.

Registered in: plans/roadmap.md and plans/architecture_maintenance_auditability_roadmap.md.

Planning baseline: main at 30e68af8f6e79ce0fe07f0c1871f1d0caa6be6f2. Execute after Phase 98 lands and rebase the implementation baseline to the then-current main.

Depends on: Phase 96 dependency-direction policy. Phase 98 should be complete first so request-path ownership is stable while configuration consumers migrate.

## Goal

Separate high-fanout configuration data/validation from configuration loading, mutation, filesystem discovery, and runtime key realization so domain crates can depend on a lower-capability model boundary.

Existing user configuration, defaults, schemas, feature behavior, and runtime semantics must remain compatible.

## Current-head findings

synvoid-config currently owns all of the following in one package:

- user-facing configuration DTOs and defaults;
- serde/schemars/utoipa schema ownership;
- deterministic validation and normalization;
- TOML parsing and file loading;
- ConfigManager, site discovery, reload, and path ownership;
- mesh identity/key decoding and derivation methods;
- feature-gated DNS/mesh/ICMP configuration;
- utility crypto dependencies used by parts of mesh configuration.

The crate has roughly half the workspace as reverse consumers.

Source inspection also shows overlapping mesh identity realization in synvoid-config::mesh and synvoid-mesh::config_identity. The two layers must not continue independently evolving key-derivation behavior.

## Binding design

Create a new internal crate named synvoid-config-model only if the dependency and API inventory in Workstream A confirms that the model can remain materially lower-capability.

Target direction:

    synvoid-config-model
            ^
            |
      synvoid-config
            ^
            |
       root/admin runtime

Domain crates that only need immutable configuration values should depend on synvoid-config-model directly.

synvoid-config remains the application-facing loading/mutation owner and may re-export model types for compatibility.

The new crate remains internal and pre-1.0. No public support promise is created.

## Workstream A — freeze the current configuration compatibility contract

Before moving types, inventory:

- every type exported by synvoid-config;
- every serialized TOML/JSON field and default;
- feature-gated sections and fail-closed unsupported-section behavior;
- types with from_file/from_toml_str or filesystem-aware validation;
- types with runtime/crypto methods;
- current direct reverse dependencies and which symbols each consumer imports.

Capture golden fixtures for at least:

- minimal main.toml;
- default/full main.toml;
- representative site configuration;
- mesh-enabled configuration;
- DNS-enabled configuration;
- ICMP-enabled configuration;
- tunnel/WireGuard configuration where feature-supported;
- admin/theme/upload/serverless sections;
- legacy aliases/defaults that current compatibility tests protect.

No move proceeds until parse -> serialize/normalize behavior is characterized.

## Workstream B — define the low-capability model crate

synvoid-config-model should own only:

- DTOs/enums/newtypes;
- defaults;
- pure deterministic validation;
- pure normalization/canonicalization;
- schema derives required by current admin/OpenAPI consumers;
- small parsing helpers that do not perform I/O.

It must not own:

- ConfigManager;
- directory discovery/reload;
- direct filesystem reads/writes;
- runtime service handles;
- background tasks;
- HTTP clients;
- mesh transport;
- key generation from OS randomness;
- private-key realization/derivation;
- HSM access;
- metrics/tracing state.

Expected dependencies should be limited to the actual model/schema needs. Re-evaluate whether every current synvoid-config dependency is still needed after the split.

Do not force a zero-dependency model crate if schema compatibility requires serde/schemars/utoipa/chrono/uuid/rkyv-style dependencies. The objective is authority/capability reduction, not dependency-count theater.

## Workstream C — retain loading/mutation ownership in synvoid-config

synvoid-config remains responsible for:

- ConfigManager;
- main/site TOML loading;
- site discovery;
- reload;
- filesystem-aware validation;
- application path ownership;
- compatibility helpers that logically perform configuration I/O.

Prefer explicit loader functions/traits over reintroducing filesystem behavior into model types.

Because all SynVoid crates except synvoid-rate-limit are internal support surfaces, internal call sites may migrate from SiteConfig::from_file/MainConfig::from_file to loader APIs if necessary. Preserve the user-facing file format and root/operator behavior.

Where cheap and acyclic, synvoid-config should re-export model modules/types so common paths such as synvoid_config::SiteConfig and synvoid_config::site::* continue to work during migration.

## Workstream D — remove runtime key realization from configuration DTO ownership

The current synvoid-config mesh types perform operations such as node identity generation, HKDF-derived signing material, X25519 public-key derivation, and Ed25519 key loading/derivation.

Move runtime realization to an explicit mesh-side adapter/identity owner.

Target rule:

- configuration model describes serialized paths/material/policy;
- configuration loader validates shape and required presence;
- synvoid-mesh realizes cryptographic runtime identity.

Do not change key formats, derivation labels, generated identifiers, or persisted configuration semantics.

Before removing any implementation, compare synvoid-config mesh methods with synvoid-mesh config_identity behavior and consolidate onto one implementation. Add known-answer tests for:

- node/router ID derivation;
- X25519 public-key derivation;
- Ed25519 public-key derivation;
- HKDF context/info behavior;
- invite-token comparison semantics;
- existing genesis/global-node key parsing.

If two current implementations differ, treat that as a compatibility/security finding. Do not silently choose one. Record the actual production caller and preserve production behavior unless a separate corrective is justified.

## Workstream E — migrate consumers according to actual capability needs

Classify reverse consumers into:

1. model-only: reads DTOs/defaults/validation results;
2. runtime-config: needs ConfigManager/reload/path ownership;
3. composition adapters: convert application config into domain policy/runtime types.

Move category 1 to synvoid-config-model.

Keep category 2 on synvoid-config.

For category 3, prefer conversion at the owning subsystem boundary, as already done by synvoid-upstream for site -> TLS policy and by the ICMP policy/config canonicalization work.

High-value candidates to inspect include WAF, proxy, HTTP, upstream, TLS, theme, app handlers, metrics-adjacent helpers, and feature-gated domain crates.

Do not churn a consumer to the new crate merely for count. The dependency should reflect what the consumer actually needs.

## Workstream F — feature forwarding and unsupported-section truth

Preserve current root feature behavior:

- dns config is only accepted when the binary has the corresponding capability according to the current fail-closed contract;
- mesh/tunnel.mesh/icmp_filter unsupported sections continue to reject as currently documented;
- no config section becomes silently ignored because its model type moved crates;
- root feature forwarding remains explicit.

The new model crate may have lightweight feature gates for schema/type availability if required, but these must not become an independent runtime capability system.

## Workstream G — architecture guards

Extend the workspace dependency policy so synvoid-config-model cannot depend on:

- root synvoid;
- synvoid-admin;
- synvoid-mesh;
- synvoid-http/proxy;
- synvoid-platform unless a concrete pure type need is proven;
- synvoid-ipc;
- HTTP clients;
- runtime engine crates.

Add a guard preventing random/key-generation APIs and filesystem mutation APIs from being introduced into the model crate.

Keep these checks semantic enough to allow normal std/serde/schema evolution.

## Required verification

At minimum:

    cargo test -p synvoid-config-model --profile ci
    cargo test -p synvoid-config --profile ci
    cargo test -p synvoid-mesh --profile ci --features mesh
    cargo test --test admin_router_composition --profile ci
    cargo test --test admin_route_contract --profile ci
    cargo check --no-default-features --profile ci
    cargo check --no-default-features --features mesh --profile ci
    cargo check --no-default-features --features dns --profile ci
    cargo check --no-default-features --features icmp-filter --profile ci
    cargo check --no-default-features --features mesh,dns --profile ci
    cargo xtask test guards
    cargo xtask verify

Run the repository's config fuzz/parsing target or bounded equivalent against the same corpus before/after.

## Acceptance criteria

- A materially lower-capability configuration model boundary exists, or the phase records measured evidence that a new crate would not provide such a boundary and keeps the separation internal. A count-only crate is not acceptable.
- ConfigManager/file discovery/reload remain outside the low-capability model.
- Runtime mesh key realization has one owner and is not duplicated in the config model.
- Existing TOML/JSON configurations and defaults remain readable/equivalent.
- Unsupported feature sections still fail closed exactly as documented.
- Model-only consumers can avoid the broad runtime config owner.
- No domain capability is removed.
- Architecture/config docs and dependency graphs reflect the final owner.

## Rejection criteria

Reject the phase if it:

- creates synvoid-config-model but leaves ConfigManager/filesystem/key generation inside it;
- breaks current configuration without aliases/migration evidence;
- changes mesh key derivation or IDs as an incidental cleanup;
- creates a config crate per subsystem;
- moves runtime domain behavior into configuration for convenience;
- disables a feature to simplify the dependency graph;
- preserves two crypto/key-realization implementations with no authority decision;
- claims a dependency win without measuring actual direct/transitive graph changes.
