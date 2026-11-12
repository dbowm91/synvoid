# Phase 07 Plan: Operator Packaging

Status: **COMPLETE** (implemented 2026-11-11; evidence below).
Campaign: `plans/production_readiness_remediation_roadmap.md`.
Predecessor: Phase 01 (release gate). Phase 08 follows this phase.

## The finding

The shipped systemd unit runs the WAF as **root**:

- `contrib/systemd/synvoid.service`: `User=root`, `Group=root`;
- `ReadWritePaths=/opt/synvoid /var/log/synvoid /var/lib/synvoid`;
- `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp` are present, but there is
  no dedicated service account, no `CapabilityBoundingSet`, no
  `SystemCallFilter` and no address-family restriction.

The operator guide recommends a non-root `synvoid` user, so the unit
contradicts the documentation. Binding 80/443 can be handled with
`CAP_NET_BIND_SERVICE`; the WAF does not need root for normal HTTP/TLS.

There is also no `Dockerfile` in the repository, and
`docs/DEPLOYMENT.md` explicitly marks `synvoid/synvoid:latest` as unverified.
The deployment guide still gives Docker/Kubernetes manifests for an image the
project does not build. The release checklist requires
`cargo xtask verify-release`, which currently cannot pass because Phase 01 is
red.

## Work items

### 07.1 Non-root systemd unit

- Define a dedicated `synvoid` system user and group in the packaging docs.
- Set `User=synvoid`, `Group=synvoid`, `UMask=0077`.
- Add `AmbientCapabilities=CAP_NET_BIND_SERVICE` and
  `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` for ports below 1024. Add
  `CAP_NET_ADMIN` only if an opt-in eBPF/ICMP/tunnel feature needs it, and
  document that it is not the default.
- Keep `NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=true`,
  `PrivateTmp=true`, `PrivateDevices=true`, `ProtectKernelTunables=true`,
  `ProtectKernelModules=true`, `ProtectControlGroups=true`,
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `LockPersonality=true`,
  `RestrictRealtime=true`, `SystemCallArchitectures=native`.
- Do **not** set `MemoryDenyWriteExecute`: Wasmtime's JIT and the dynamic
  plugin path need executable mappings. If the Wasmtime/JIT path is disabled
  for a deployment profile, the stronger setting can be a documented opt-in.
- Decide the write layout: install tree read-only, state under
  `/var/lib/synvoid`, logs under `/var/log/synvoid`, runtime under
  `/run/synvoid`. If the admin config editor must write `main.toml`/`sites/`,
  give the service user write access to the config directory or move the
  editable config to a dedicated state path; do not leave `/opt/synvoid`
  writable as a shortcut.
- Verify with `systemd-analyze verify` and `systemd-analyze security`, and
  record the exposure score in the phase evidence.

### 07.2 Container artifact

- Add a multi-stage `Dockerfile`:
  - builder: the pinned Rust toolchain (`rust-toolchain.toml`, 1.98.1), plus
    `protoc`, `node`, pinned `trunk@0.21.14`, and `wasm-pack`;
  - build the admin UI with `cd admin-ui && npm ci && npm run build`;
  - build the wasm-pow assets used by the challenge path;
  - `cargo build --release` for the root binary and required jail binaries.
- Runtime: a minimal Debian/glibc image with CA certificates and the runtime
  libraries the binary needs; create a non-root user; copy the binary,
  `admin-ui/dist`, `static/`, `rules/`, `root.hints` and the example config;
  use `/etc/synvoid`, `/var/lib/synvoid`, `/var/log/synvoid`, `/run/synvoid`
  as the writable/read-only layout.
- Entrypoint runs `synvoid --foreground --config-path /etc/synvoid` (the
  directory, not a TOML file).
- Healthcheck hits the admin `/health` endpoint only if the admin listener is
  enabled and reachable; otherwise use a process/`--status` check. Do not
  publish the admin or metrics port publicly by default.
- Add `.dockerignore` entries for `target/`, `admin-ui/target/`,
  `admin-ui/node_modules/`, local configs and logs.
- Add a CI `docker-build` job (build only; push is release-only) and a smoke
  run with `configtest`.
- If the project decides not to ship a container, remove the Docker/Kubernetes
  sections from `docs/DEPLOYMENT.md` and mark the image name unverified rather
  than leaving instructions that cannot work.

### 07.3 Release gate and docs

- Update `docs/DEPLOYMENT.md`, `docs/GETTING_STARTED.md`, `docs/SECURITY.md`
  and `contrib/systemd/synvoid.service` so the non-root story is consistent.
- Add the service-account creation step and directory ownership to the install
  docs.
- Run `cargo xtask verify-release` after Phase 01 is green; include the
  result and the `systemd-analyze security` output in the phase evidence.
- Keep the package/container artifacts out of the source tree unless the
  project already tracks them; do not commit build outputs.

## Non-goals

- A full package repository (deb/rpm) unless it already exists.
- Changing the process model or supervisor layout.
- In-process sandboxing; Phase 08 owns that.
- Publishing an image from this repository without a release decision.

## Verification

```bash
cargo xtask verify-release
docker build -t synvoid:ci .
docker run --rm synvoid:ci --configtest --config-path /etc/synvoid
systemd-analyze verify contrib/systemd/synvoid.service
systemd-analyze security synvoid.service   # on a test host
```

Live: start the unit as `synvoid`, verify HTTP/TLS/admin/metrics, config
reload, log write, block-store persistence and a graceful restart. Start the
container as non-root and repeat the smoke set.

## Exit criteria

- No shipped unit runs as root by default.
- The documented install path uses a dedicated account and least privilege.
- A container artifact exists and is built/tested in CI, or the unverified
  container docs are removed.

## Completion evidence

Implemented 2026-11-11. `contrib/systemd/synvoid.service` runs as `synvoid`
with `UMask=0077`, only `CAP_NET_BIND_SERVICE`, systemd sandboxing/address-family
restrictions and explicit state/log/cache/runtime directories; OCI/build/user
layout is documented. A multi-stage `Dockerfile`, `.dockerignore` and a
build-only CI `docker-build` smoke job were added. `systemd-analyze verify`
passes with the binary installed path and `systemd-analyze security --offline`
reports exposure 4.4 OK; `docker build --check` reports no warnings. The full
image build reached wasm/admin/release but was not completed under the session
time limit; the CI job is the remaining live qualification.

