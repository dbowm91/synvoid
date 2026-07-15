use std::collections::HashMap;

/// A test lane definition with its description and command steps.
#[derive(Debug, Clone)]
pub struct Lane {
    pub name: &'static str,
    pub description: &'static str,
    pub steps: Vec<Step>,
}

/// A single step within a lane.
#[derive(Debug, Clone)]
pub struct Step {
    pub name: &'static str,
    pub command: &'static str,
}

impl Step {
    pub const fn new(name: &'static str, command: &'static str) -> Self {
        Self { name, command }
    }
}

/// Build the lane registry.
pub fn build_lanes() -> HashMap<&'static str, Lane> {
    let mut lanes = HashMap::new();

    lanes.insert(
        "fast",
        Lane {
            name: "fast",
            description:
                "Fast PR lane: format check, clippy, guard tests, security regression, core compile, affected domain tests. Target <10 min.",
            steps: vec![
                Step::new("fmt", "cargo fmt --all -- --check"),
                Step::new("clippy", "cargo clippy --all-targets --all-features -- -D warnings"),
                Step::new("guards", "cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci"),
                Step::new("security", "cargo test --test security_regression -- --test-threads=1"),
                Step::new("compile", "cargo test --lib --no-run"),
                Step::new(
                    "affected",
                    "python3 scripts/ci/select-affected.py --base <BASE_REF> --head HEAD --format json",
                ),
            ],
        },
    );

    lanes.insert(
        "affected",
        Lane {
            name: "affected",
            description:
                "Run tests only for packages and root tests affected by changes since a base ref.",
            steps: vec![
                Step::new(
                    "select",
                    "python3 scripts/ci/select-affected.py --base <BASE_REF> --head HEAD --format json",
                ),
                Step::new("packages", "cargo nextest run -p <PKG> --cargo-profile ci --profile ci"),
                Step::new("root-tests", "cargo test --test <TEST>"),
                Step::new("doctests", "cargo test --workspace --doc --profile ci"),
            ],
        },
    );

    lanes.insert(
        "package",
        Lane {
            name: "package",
            description: "Test a single workspace package with nextest.",
            steps: vec![Step::new(
                "nextest",
                "cargo nextest run -p <PKG> --cargo-profile ci --profile ci",
            )],
        },
    );

    lanes.insert(
        "guards",
        Lane {
            name: "guards",
            description:
                "Run all architectural guard tests (repo-guards crate + root guard tests).",
            steps: vec![
                Step::new(
                    "repo-guards",
                    "cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci",
                ),
                Step::new(
                    "boundary-composition",
                    "cargo test --test boundary_composition_guard",
                ),
                Step::new(
                    "root-facade",
                    "cargo test --test root_facade_boundary_guard",
                ),
                Step::new("mesh-id", "cargo test --test mesh_id_boundary_guard"),
                Step::new("security", "cargo test --test security_guard"),
                Step::new("lifecycle", "cargo test --test lifecycle_task_guard"),
                Step::new("cli-admin", "cargo test --test cli_admin_guard"),
                Step::new("plugin", "cargo test --test plugin_guard"),
                Step::new(
                    "worker-mesh",
                    "cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns",
                ),
                Step::new(
                    "mesh-task",
                    "cargo test --test mesh_task_ownership_guard --features mesh,dns",
                ),
                Step::new(
                    "admin-mutation",
                    "cargo test --test admin_mutation_response_guard",
                ),
                Step::new(
                    "admin-mutation-blocklist",
                    "cargo test --test admin_mutation_blocklist",
                ),
                Step::new("admin-auth", "cargo test --test admin_auth_boundary"),
                Step::new("mesh-admin", "cargo test --test mesh_admin_edge_cases"),
                Step::new("abi-memory", "cargo test --test abi_memory_boundary_guard"),
                Step::new(
                    "root-ownership",
                    "cargo test --test root_test_ownership_guard",
                ),
            ],
        },
    );

    lanes.insert(
        "security",
        Lane {
            name: "security",
            description: "Run security regression tests (single-threaded, uses env var serialization guard).",
            steps: vec![Step::new(
                "security-regression",
                "cargo test --test security_regression -- --test-threads=1",
            )],
        },
    );

    lanes.insert(
        "comprehensive",
        Lane {
            name: "comprehensive",
            description:
                "Full workspace validation: all profiles, all crates, all guards, security, doctests. Used by main-comprehensive CI lane.",
            steps: vec![
                Step::new("fmt", "cargo fmt --all -- --check"),
                Step::new("clippy", "cargo clippy --all-targets --all-features -- -D warnings"),
                Step::new("profile-core", "cargo check --no-default-features"),
                Step::new("profile-mesh", "cargo check --no-default-features --features mesh"),
                Step::new("profile-dns", "cargo check --no-default-features --features dns"),
                Step::new("profile-full", "cargo check --no-default-features --features mesh,dns"),
                Step::new("compile", "cargo test --lib --no-run"),
                Step::new("nextest-all", "cargo nextest run --workspace --cargo-profile ci --profile ci --exclude synvoid-fuzz"),
                Step::new("doctests", "cargo test --workspace --doc --profile ci"),
                Step::new("guards", "cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci"),
                Step::new("security", "cargo test --test security_regression -- --test-threads=1"),
                Step::new("root-ownership", "cargo test --test root_test_ownership_guard"),
            ],
        },
    );

    lanes.insert(
        "nightly-plan",
        Lane {
            name: "nightly-plan",
            description:
                "Print the commands that nightly scheduled qualification would run (portability, safety, extended checks).",
            steps: vec![
                Step::new("fmt", "cargo fmt --all -- --check"),
                Step::new("clippy", "cargo clippy --all-targets --all-features -- -D warnings"),
                Step::new("compile", "cargo test --lib --no-run"),
                Step::new("nextest-all", "cargo nextest run --workspace --cargo-profile ci --profile ci --exclude synvoid-fuzz"),
                Step::new("doctests", "cargo test --workspace --doc --profile ci"),
                Step::new("guards", "cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci"),
                Step::new("security", "cargo test --test security_regression -- --test-threads=1"),
                Step::new("platform-compat", "cargo check --target x86_64-unknown-linux-musl"),
                Step::new("deny", "cargo deny check"),
            ],
        },
    );

    lanes.insert(
        "qualification",
        Lane {
            name: "qualification",
            description:
                "Print the commands that release qualification would run (production artifacts, full validation).",
            steps: vec![
                Step::new("fmt", "cargo fmt --all -- --check"),
                Step::new("clippy", "cargo clippy --all-targets --all-features -- -D warnings"),
                Step::new("compile", "cargo test --lib --no-run"),
                Step::new("nextest-all", "cargo nextest run --workspace --cargo-profile ci --profile ci --exclude synvoid-fuzz"),
                Step::new("doctests", "cargo test --workspace --doc --profile ci"),
                Step::new("guards", "cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci"),
                Step::new("security", "cargo test --test security_regression -- --test-threads=1"),
                Step::new("root-ownership", "cargo test --test root_test_ownership_guard"),
                Step::new("deny", "cargo deny check"),
            ],
        },
    );

    lanes.insert(
        "release",
        Lane {
            name: "release",
            description:
                "Print the commands for release validation (--release profile, never substitute CI profile).",
            steps: vec![
                Step::new("fmt", "cargo fmt --all -- --check"),
                Step::new("clippy", "cargo clippy --all-targets --all-features -- -D warnings"),
                Step::new("compile-release", "cargo test --lib --no-run --release"),
                Step::new("nextest-release", "cargo nextest run --workspace --release --exclude synvoid-fuzz"),
                Step::new("doctests", "cargo test --workspace --doc --release"),
                Step::new("guards", "cargo nextest run -p synvoid-repo-guards --cargo-profile ci --profile ci"),
                Step::new("security", "cargo test --test security_regression -- --test-threads=1"),
            ],
        },
    );

    lanes
}

/// Get a specific lane by name.
pub fn get_lane(name: &str) -> Option<Lane> {
    build_lanes().remove(name)
}

/// List all lane names in a defined order.
pub fn list_lane_names() -> Vec<&'static str> {
    vec![
        "fast",
        "affected",
        "package",
        "guards",
        "security",
        "comprehensive",
        "nightly-plan",
        "qualification",
        "release",
    ]
}
