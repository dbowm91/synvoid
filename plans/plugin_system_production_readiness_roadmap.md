# Plugin System Production Readiness Roadmap

## Purpose

This roadmap hardens Synvoid's plugin system into a production-grade extension boundary. The current repository already has the right direction: WASM is the safe plugin substrate; plugins have manifests, trust tiers, capabilities, signatures, resource-limit types, metrics, and lifecycle code. The remaining work is to make those pieces mandatory, consistently wired, and operationally auditable.

The core production rule for this line of work is simple: sandboxed WASM plugins must never inherit ambient server authority, and native dynamic-library plugins must never be described or treated as sandboxed plugins.

## Current Assessment

The WASM runtime has useful foundations: `synvoid-plugin-runtime`, `PluginManifest`, `PluginTrustTier`, `PluginCapabilities`, `PluginLimits`, signing primitives, load policy enforcement, metrics hooks, and a runtime manager. However, the trust boundary is not yet fully composed.

The most important gaps are:

1. Manifest-defined capabilities and limits are used for load-policy checks but are not consistently converted into the actual `WasmResourceLimits` used by plugin instances.
2. File-based signed plugin loading does not appear to verify the actual file bytes before instantiation; signature verification must bind the manifest to the exact bytes that are instantiated.
3. `PluginInvocationGuard` exists but is not yet the mandatory invocation path for every plugin hook, so failure/quarantine semantics are not fully enforced.
4. The pointer-length ABI has unsafe/correctness hazards, especially the fixed-offset fallback when `guest_alloc` is absent.
5. Native Axum plugins are full-process dynamic library execution and need to be isolated as an explicit unsafe extension mode.

## Milestone 1: Mandatory Trust Boundary

Goal: make the intended trust model actually true for every WASM plugin load and invocation path.

This milestone contains four corrective phases:

- Phase 1: Manifest Authority Wiring
- Phase 2: Signed Byte Loading and TOCTOU Closure
- Phase 3: Mandatory Invocation Guard Integration
- Phase 4: ABI Memory Boundary Hardening

After this milestone, each WASM plugin should have independently enforced capabilities, limits, signing state, runtime state, failure handling, and safe host/guest memory transfer. This is the minimum viable production boundary.

Success criteria for the milestone:

- Two plugins loaded into the same process can have different capabilities and resource budgets, and those differences are enforced at runtime.
- A signed file plugin is verified against the exact bytes that are instantiated.
- Repeated traps, fuel exhaustion, or timeouts transition plugin runtime state and stop repeated unsafe invocation.
- The guest ABI cannot silently alias method, URI, headers, and body into the same memory range.
- No plugin load path bypasses duplicate-name, capability, signature, or limit enforcement.
- Guardrail and integration tests exercise the real runtime, not only static source scans.

## Milestone 2: Sandbox Depth

Goal: strengthen runtime containment against semantic bypass, resource exhaustion, and host API abuse.

Planned phases:

- Phase 5: Request and Response Serialization Semantics
- Phase 6: Execution Containment and Pool Isolation
- Phase 7: Host API Sub-Capabilities for Mesh, Persistence, Filesystem, Network, and Metrics

Expected outcomes:

- Request serialization rejects oversized or lossy metadata rather than truncating.
- Response transform output has explicit size, status, and mutation bounds.
- Fuel is mandatory for sandboxed tiers in production.
- Wall-clock and host-call timeouts cover blocking host APIs such as streaming body reads.
- Instance pooling preserves per-plugin isolation and either resets guest state or explicitly documents stateful plugin semantics.
- Mesh access is scoped by DHT prefixes, event topics, and threat-check permissions rather than a single coarse `mesh = true` authority.
- Future filesystem/network/persistence APIs have default-deny allowlist checks from the first implementation.

## Milestone 3: Operator Safety and Native Extension Containment

Goal: keep unsafe native extension mechanisms from undermining the WASM trust model.

Planned phases:

- Phase 8: Unsafe Native Axum Plugin Reclassification
- Phase 9: Hot Reload Atomicity and Lifecycle Hardening

Expected outcomes:

- Native `.so`/`.dylib`/`.dll` plugins are configured as `unsafe_native_plugins`, disabled by default, and explicitly documented as full-process trusted code.
- Native plugin loading retains the `Library` handle for the full router lifetime if native plugins remain supported.
- Native hot reload is development-only.
- WASM hot reload validates a complete stable file, verifies signature/hash, loads a new runtime first, and atomically swaps only on success.
- Failed reloads keep the previous working plugin active.
- All reload operations produce structured audit events.

## Milestone 4: Documentation, Test Fixtures, and Operations

Goal: make the system maintainable by future implementers and reviewable by operators.

Planned phase:

- Phase 10: Plugin Documentation, Fixtures, Metrics, and Audit Surface

Expected outcomes:

- `docs/PLUGINS.md` matches the actual ABI, manifest schema, trust tiers, and runtime behavior.
- The architecture document distinguishes implemented behavior from target behavior.
- Plugin author docs include a minimal valid plugin, a signed plugin example, and a manifest reference.
- Operator docs explain production policy, trusted key management, unsafe native plugins, hot reload, and failure/quarantine behavior.
- Test fixtures include valid pass/block/challenge plugins, no-allocator plugins, infinite-loop plugins, trap plugins, oversized-header requests, unauthorized mesh calls, signed plugins, tampered signed plugins, duplicate-name plugins, and partial hot-reload writes.
- Logs and metrics identify plugin name, version, trust tier, binary hash, manifest hash, key ID, runtime state, failure count, invocation count, duration, fuel consumed, and decision result.

## Recommended Execution Order

The first milestone should be implemented before any new plugin feature expansion. It fixes the core trust boundary. Milestone 2 can then deepen sandbox behavior without fighting architectural ambiguity. Milestone 3 should be completed before recommending native extensions or hot reload for non-development deployments. Milestone 4 should run alongside implementation but should be completed before declaring the plugin system production-ready.

Suggested near-term sequence:

1. Complete Phase 1 and Phase 2 together if possible, because manifest authority and signed byte verification are tightly coupled.
2. Complete Phase 3 before adding new host APIs, because all hooks should share one invocation state machine.
3. Complete Phase 4 before publishing any external plugin ABI guidance.
4. Run a full plugin guardrail suite after each phase.

## Target End State

The final plugin model should have three clearly separated classes:

- `SignedSandboxed`: production default for third-party, distributed, or mesh-delivered plugins.
- `LocalSandboxed`: acceptable for explicitly configured local deployments, still bounded by capabilities and resources.
- `UnsafeNative`: operator-only full-process extension escape hatch, disabled by default, never treated as sandboxed, and preferably replaced over time by out-of-process extension services over HTTP/gRPC/UDS.

Production readiness means the system can answer, for any plugin decision: which plugin made the decision, under which manifest, with which capabilities, from which signed binary hash, using which trusted key, under which resource budget, and with which runtime state.