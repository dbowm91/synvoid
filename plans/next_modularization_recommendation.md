# Next Modularization Recommendation

## Validation status after SDC pass

- Root yara-x removed: YES (moved to `crates/synvoid-upload`)
- Mesh feature now compiles: YES (fixed in SDC-A02)
- Workspace all-targets: **FAILED** — 4 pre-existing errors (myapp-dynamic E0507, synvoid-ipc test sha2 missing, admin-ui 5 errors, synvoid-mesh test errors). None introduced by SDC work.
- Dead upload duplicates removed: YES (duplicate yara rules, crypto, scanner types consolidated)

## SDC results summary

All 6 profile checks pass cleanly. Only warnings remain (dead code, unused variables). The mesh feature was the critical fix — it now compiles with the full feature set.

## Next recommended technical pass

1. **HTTP3 Http3RequestWaf object-safety check** — Http3RequestWaf uses generics preventing dynamic dispatch; worth investigating if it can be made object-safe for runtime polymorphism.
2. **server-runtime context design** — The per-request context threading pattern could be consolidated.
3. **admin/schema ownership cleanup** — Admin OpenAPI surface sits on root; schema ownership decisions depend on `plans/admin_schema_ownership.md` (MDM-A01).

Depends on latest validation and measurements. All profile checks pass, so the team can proceed with any of these in any order.
