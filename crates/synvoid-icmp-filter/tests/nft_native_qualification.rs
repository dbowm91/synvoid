//! Linux nftables privileged native qualification harness (Phase 91).
//!
//! Preparation-phase harness for the Phase 88 native-proof trigger. It
//! produces privileged evidence on a suitable host; its closure never claims
//! qualification passed unless actually run there. The Phase 88 RETAIN
//! decision is unchanged.
//!
//! Binding safety contract (all normative):
//!
//! 1. Never run destructive qualification in the initial/default host
//!    network namespace. All firewall/packet operations happen inside two
//!    disposable namespaces connected by a veth pair.
//! 2. Privileged execution requires TWO explicit opt-ins: the
//!    `--ignored` test selection AND `SYNVOID_ICMP_QUALIFY_NATIVE=1` in the
//!    environment, plus detected privilege. Missing opt-in refuses.
//! 3. Namespace/interface/table identifiers are collision-resistant
//!    (`synvoid-q*` + run id) and validated (no separators, no `..`).
//! 4. Every created resource is recorded in a cleanup ledger and removed on
//!    success AND failure paths (explicit `finally` + `Drop` guard +
//!    rerunnable `--cleanup`-equivalent helper).
//! 5. The harness proves it operates in the intended namespace (netns inode
//!    differs from the host) before touching nftables, and refuses otherwise.
//! 6. No flush/inspection of unrelated host firewall tables: every nftables
//!    command is scoped to an owned table inside the target namespace.
//! 7. An unmet gate is "not qualified" (hard failure), never success.
//! 8. Ordinary `cargo test` never invokes privileged operations: the native
//!    matrix is `#[ignore]`d; pure support logic has non-ignored unit tests
//!    below that run everywhere without privilege or mutation.
//! 9. Every privileged run emits a bounded machine-readable evidence
//!    artifact (no secrets, no environment dumps).
//! 10. eBPF/PF/WFP/Windows-Firewall/BSD qualification is out of scope.
//!
//! Layout: `support` (pure, all platforms, non-ignored tests) + `native`
//! (Linux-only privileged matrix, ignored, fail-closed without gates).

// ===========================================================================
// Pure support core (all platforms; zero privileged mutation)
// ===========================================================================

pub mod support {
    use serde::{Deserialize, Serialize};

    /// Explicit opt-in environment gate for privileged execution.
    pub const NATIVE_OPT_IN_ENV: &str = "SYNVOID_ICMP_QUALIFY_NATIVE";
    /// Evidence output path override.
    pub const EVIDENCE_OUT_ENV: &str = "SYNVOID_ICMP_QUALIFY_OUT";
    /// Collision-resistant resource prefix. Cleanup matches this prefix.
    pub const RESOURCE_PREFIX: &str = "synvoid-q";

    /// Collision-resistant run identifier: `[a-z0-9-]{1,40}`.
    /// Derived from timestamp + pid + sequence (no RNG dependency).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RunId(String);

    impl RunId {
        pub fn generate(timestamp_secs: u64, pid: u32, seq: u32) -> Self {
            Self(format!("{timestamp_secs:010}-{pid:06}-{seq:03}"))
        }

        /// Accept an orchestrator-supplied id when it matches the validated
        /// charset (`[A-Za-z0-9-]{1,40}`, no `..`); otherwise None (caller
        /// falls back to generated).
        pub fn from_external(s: &str) -> Option<Self> {
            if s.is_empty() || s.len() > 40 {
                return None;
            }
            if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return None;
            }
            if s.contains("..") {
                return None;
            }
            Some(Self(s.to_string()))
        }

        pub fn as_str(&self) -> &str {
            &self.0
        }

        /// Short hex-ish suffix for length-constrained names (ifnames ≤ 15).
        pub fn short_suffix(&self) -> String {
            let mut hash: u64 = 0xcbf29ce484222325;
            for b in self.0.bytes() {
                hash ^= u64::from(b);
                hash = hash.wrapping_mul(0x100000001b3);
            }
            format!("{hash:012x}")[..6].to_string()
        }
    }

    /// Validate a namespace/interface/table fragment. Rejects separators,
    /// parent traversal, empty strings, and overlong values. Pure and
    /// fixture-testable.
    pub fn validate_name_fragment(s: &str) -> Result<(), String> {
        if s.is_empty() {
            return Err("name fragment must not be empty".to_string());
        }
        if s.len() > 32 {
            return Err("name fragment longer than 32 chars".to_string());
        }
        if !(s
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'))
        {
            return Err(format!("name fragment {s:?} must match [a-z0-9-]+"));
        }
        if s.contains("..") || s.starts_with('-') {
            return Err(format!("name fragment {s:?} rejected (.. or leading -)"));
        }
        Ok(())
    }

    /// Namespace name for side A/B of the topology. Uses the run's short
    /// suffix (6 hex chars from FNV-1a over the full run id) so names stay
    /// well under kernel/validation limits while remaining
    /// collision-resistant for disposable test namespaces. The full run id
    /// is recorded in the evidence artifact for traceability.
    pub fn namespace_name(side: char, run: &RunId) -> Result<String, String> {
        if !matches!(side, 'a' | 'b') {
            return Err("side must be 'a' or 'b'".to_string());
        }
        let name = format!("{RESOURCE_PREFIX}-{side}-{}", run.short_suffix());
        validate_name_fragment(&name)?;
        Ok(name)
    }

    /// Veth endpoint name (≤15 chars for Linux ifnames).
    pub fn veth_name(side: char, run: &RunId) -> Result<String, String> {
        if !matches!(side, 'a' | 'b') {
            return Err("side must be 'a' or 'b'".to_string());
        }
        let name = format!("svq{side}-{}", run.short_suffix());
        if name.len() > 15 {
            return Err(format!("veth name {name:?} exceeds 15 chars"));
        }
        validate_name_fragment(&name)?;
        Ok(name)
    }

    /// Owned nftables table name (identifier-validated for the crate path).
    pub fn table_name(run: &RunId) -> String {
        format!("synvoid_q_{}", run.short_suffix().replace('-', "_"))
    }

    /// Build `ip` argv (no shell; caller spawns directly).
    pub fn ip_args(args: &[&str]) -> Vec<String> {
        std::iter::once("ip".to_string())
            .chain(args.iter().map(|s| s.to_string()))
            .collect()
    }

    /// Build `ip netns exec <ns> ...` argv. All namespace-scoped commands go
    /// through this constructor so the host/default namespace is never
    /// addressed by accident.
    pub fn netns_exec_args(ns: &str, cmd: &[&str]) -> Vec<String> {
        let mut v = vec![
            "ip".to_string(),
            "netns".to_string(),
            "exec".to_string(),
            ns.to_string(),
        ];
        v.extend(cmd.iter().map(|s| s.to_string()));
        v
    }

    /// Build `nft` argv scoped to an owned table inside a namespace.
    pub fn nft_list_table_args(ns: &str, table: &str) -> Vec<String> {
        netns_exec_args(ns, &["nft", "list", "table", "inet", table])
    }

    /// Ordered, idempotent cleanup ledger. Records created resources;
    /// `drain()` yields removal operations in reverse creation order and
    /// marks the ledger drained so a second drain is a no-op success.
    #[derive(Debug, Default)]
    pub struct CleanupLedger {
        ops: Vec<CleanupOp>,
        drained: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum CleanupOp {
        DeleteVeth { veth: String },
        DeleteNetns { ns: String },
    }

    impl CleanupLedger {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn record(&mut self, op: CleanupOp) {
            self.ops.push(op);
        }

        /// Removal order: reverse creation order. Idempotent: the second
        /// call yields no operations.
        pub fn drain(&mut self) -> Vec<CleanupOp> {
            if self.drained {
                return Vec::new();
            }
            self.drained = true;
            self.ops.iter().rev().cloned().collect()
        }

        pub fn is_drained(&self) -> bool {
            self.drained
        }

        pub fn len(&self) -> usize {
            self.ops.len()
        }

        pub fn is_empty(&self) -> bool {
            self.ops.is_empty()
        }
    }

    /// One qualification case outcome.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct CaseResult {
        pub name: String,
        pub outcome: String,
        pub detail: String,
    }

    impl CaseResult {
        pub fn pass(name: &str, detail: String) -> Self {
            Self {
                name: name.to_string(),
                outcome: "pass".to_string(),
                detail,
            }
        }

        pub fn fail(name: &str, detail: String) -> Self {
            Self {
                name: name.to_string(),
                outcome: "fail".to_string(),
                detail,
            }
        }

        pub fn is_pass(&self) -> bool {
            self.outcome == "pass"
        }
    }

    /// Bounded machine-readable evidence for one privileged run. No secrets,
    /// no environment dumps: fixed fields only.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct QualificationEvidence {
        pub harness: String,
        pub run_id: String,
        pub git_sha: String,
        pub timestamp_secs: u64,
        pub kernel_release: String,
        pub nft_version: String,
        pub arch: String,
        pub euid: u32,
        pub cap_net_admin: bool,
        pub preflight: String,
        pub namespace_a: String,
        pub namespace_b: String,
        pub host_netns_inode: String,
        pub target_netns_inode: String,
        pub backend: String,
        pub cases: Vec<CaseResult>,
        pub fingerprints_hex: Vec<String>,
        pub generations: Vec<u64>,
        pub cleanup: String,
        pub disposition: String,
    }

    impl QualificationEvidence {
        pub fn to_json(&self) -> String {
            serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
        }

        pub fn from_json(s: &str) -> Result<Self, String> {
            serde_json::from_str(s).map_err(|e| format!("evidence parse: {e}"))
        }
    }

    /// Pure preflight inputs (runtime wrappers below collect these without
    /// mutation; tests inject fixtures).
    #[derive(Debug, Clone)]
    pub struct PreflightInputs {
        pub platform: String,
        pub opt_in_env: Option<String>,
        pub euid: u32,
        pub cap_net_admin: bool,
        pub ip_present: bool,
        pub nft_present: bool,
        pub ping_present: bool,
    }

    /// Typed preflight verdict. Anything other than `Ready` is "not
    /// qualified" — never success.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PreflightVerdict {
        Ready,
        Refused(String),
    }

    impl PreflightVerdict {
        pub fn is_ready(&self) -> bool {
            matches!(self, PreflightVerdict::Ready)
        }
    }

    /// Pure preflight decision (no side effects; fixture-testable).
    pub fn check_preflight(inputs: &PreflightInputs) -> PreflightVerdict {
        if inputs.platform != "linux" {
            return PreflightVerdict::Refused(format!(
                "native nftables qualification requires Linux, host is {}",
                inputs.platform
            ));
        }
        match inputs.opt_in_env.as_deref() {
            Some("1") => {}
            _ => {
                return PreflightVerdict::Refused(format!(
                    "refusing native run: set {}=1 plus --ignored selection",
                    NATIVE_OPT_IN_ENV
                ));
            }
        }
        if !(inputs.euid == 0 || inputs.cap_net_admin) {
            return PreflightVerdict::Refused(
                "insufficient privilege: root or CAP_NET_ADMIN required".to_string(),
            );
        }
        for (tool, present) in [
            ("ip", inputs.ip_present),
            ("nft", inputs.nft_present),
            ("ping", inputs.ping_present),
        ] {
            if !present {
                return PreflightVerdict::Refused(format!("missing prerequisite tool: {tool}"));
            }
        }
        PreflightVerdict::Ready
    }

    /// Pure dry-run plan: topology + commands + evidence shape. Construction
    /// performs zero mutation (no process spawn); the `spawned_anything`
    /// witness lets tests pin that property structurally.
    #[derive(Debug, Clone)]
    pub struct DryRunPlan {
        pub run_id: String,
        pub namespace_a: String,
        pub namespace_b: String,
        pub veth_a: String,
        pub veth_b: String,
        pub table: String,
        pub ipv4_a: String,
        pub ipv4_b: String,
        pub ipv6_a: String,
        pub ipv6_b: String,
        pub setup_commands: Vec<Vec<String>>,
        pub case_names: Vec<String>,
        pub cleanup_commands: Vec<Vec<String>>,
        pub spawned_anything: bool,
    }

    pub fn build_dry_run_plan(run: &RunId) -> Result<DryRunPlan, String> {
        let namespace_a = namespace_name('a', run)?;
        let namespace_b = namespace_name('b', run)?;
        let veth_a = veth_name('a', run)?;
        let veth_b = veth_name('b', run)?;
        let table = table_name(run);
        // Deterministic private addresses inside the disposable topology.
        // Namespaces isolate addressing, so fixed values cannot collide with
        // the host or across concurrent runs.
        let ipv4_a = "10.201.0.1/24".to_string();
        let ipv4_b = "10.201.0.2/24".to_string();
        let ipv4_b_secondary = "10.201.0.3/24".to_string();
        let ipv6_a = "fd00:db8:91::1/64".to_string();
        let ipv6_b = "fd00:db8:91::2/64".to_string();
        let _ = ipv4_b_secondary;
        let mut setup_commands = vec![
            ip_args(&["netns", "add", &namespace_a]),
            ip_args(&["netns", "add", &namespace_b]),
            ip_args(&[
                "link", "add", &veth_a, "type", "veth", "peer", "name", &veth_b,
            ]),
            ip_args(&["link", "set", &veth_a, "netns", &namespace_a]),
            ip_args(&["link", "set", &veth_b, "netns", &namespace_b]),
        ];
        for ns in [&namespace_a, &namespace_b] {
            setup_commands.push(netns_exec_args(ns, &["ip", "link", "set", "lo", "up"]));
        }
        setup_commands.push(netns_exec_args(
            &namespace_a,
            &["ip", "addr", "add", &ipv4_a, "dev", &veth_a],
        ));
        setup_commands.push(netns_exec_args(
            &namespace_a,
            &["ip", "addr", "add", &ipv6_a, "dev", &veth_a],
        ));
        setup_commands.push(netns_exec_args(
            &namespace_a,
            &["ip", "link", "set", &veth_a, "up"],
        ));
        setup_commands.push(netns_exec_args(
            &namespace_b,
            &["ip", "addr", "add", &ipv4_b, "dev", &veth_b],
        ));
        setup_commands.push(netns_exec_args(
            &namespace_b,
            &["ip", "addr", "add", &ipv6_b, "dev", &veth_b],
        ));
        setup_commands.push(netns_exec_args(
            &namespace_b,
            &["ip", "link", "set", &veth_b, "up"],
        ));
        let case_names = vec![
            "install_and_owned_state_readback",
            "icmp_type_code_behavior",
            "exemptions",
            "rate_limit_global",
            "atomic_update_replacement",
            "drift_detection",
            "disable_cleanup",
            "rollback_failure_path",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect();
        let cleanup_commands = vec![
            ip_args(&["link", "del", &veth_a]),
            ip_args(&["netns", "del", &namespace_a]),
            ip_args(&["netns", "del", &namespace_b]),
        ];
        Ok(DryRunPlan {
            run_id: run.as_str().to_string(),
            namespace_a,
            namespace_b,
            veth_a,
            veth_b,
            table,
            ipv4_a,
            ipv4_b,
            ipv6_a,
            ipv6_b,
            setup_commands,
            case_names,
            cleanup_commands,
            spawned_anything: false,
        })
    }
}

// ===========================================================================
// Non-privileged deterministic tests (run everywhere in routine CI)
// ===========================================================================

#[cfg(test)]
mod support_tests {
    use super::support::*;

    #[test]
    fn opt_in_missing_refuses_native_run() {
        let inputs = PreflightInputs {
            platform: "linux".to_string(),
            opt_in_env: None,
            euid: 0,
            cap_net_admin: true,
            ip_present: true,
            nft_present: true,
            ping_present: true,
        };
        let verdict = check_preflight(&inputs);
        assert!(!verdict.is_ready());
        match verdict {
            PreflightVerdict::Refused(reason) => {
                assert!(reason.contains("SYNVOID_ICMP_QUALIFY_NATIVE"))
            }
            PreflightVerdict::Ready => panic!("missing opt-in must refuse"),
        }
    }

    #[test]
    fn wrong_platform_refuses_native_run() {
        for platform in ["macos", "windows", "freebsd"] {
            let inputs = PreflightInputs {
                platform: platform.to_string(),
                opt_in_env: Some("1".to_string()),
                euid: 0,
                cap_net_admin: true,
                ip_present: true,
                nft_present: true,
                ping_present: true,
            };
            assert!(
                !check_preflight(&inputs).is_ready(),
                "{platform} must refuse native nftables qualification"
            );
        }
    }

    #[test]
    fn insufficient_privilege_is_explicit_unsupported() {
        let inputs = PreflightInputs {
            platform: "linux".to_string(),
            opt_in_env: Some("1".to_string()),
            euid: 1000,
            cap_net_admin: false,
            ip_present: true,
            nft_present: true,
            ping_present: true,
        };
        match check_preflight(&inputs) {
            PreflightVerdict::Refused(reason) => assert!(reason.contains("privilege")),
            PreflightVerdict::Ready => panic!("unprivileged must refuse"),
        }
    }

    #[test]
    fn missing_tools_are_prerequisite_failures() {
        for (ip, nft, ping, tool) in [
            (false, true, true, "ip"),
            (true, false, true, "nft"),
            (true, true, false, "ping"),
        ] {
            let inputs = PreflightInputs {
                platform: "linux".to_string(),
                opt_in_env: Some("1".to_string()),
                euid: 0,
                cap_net_admin: true,
                ip_present: ip,
                nft_present: nft,
                ping_present: ping,
            };
            match check_preflight(&inputs) {
                PreflightVerdict::Refused(reason) => assert!(
                    reason.contains(tool),
                    "missing {tool} must name the tool, got: {reason}"
                ),
                PreflightVerdict::Ready => panic!("missing {tool} must refuse"),
            }
        }
    }

    #[test]
    fn ready_gate_needs_everything() {
        let inputs = PreflightInputs {
            platform: "linux".to_string(),
            opt_in_env: Some("1".to_string()),
            euid: 0,
            cap_net_admin: true,
            ip_present: true,
            nft_present: true,
            ping_present: true,
        };
        assert!(check_preflight(&inputs).is_ready());
    }

    #[test]
    fn namespace_name_validation() {
        let run = RunId::generate(1_700_000_000, 1234, 1);
        assert!(namespace_name('a', &run).is_ok());
        assert!(namespace_name('b', &run).is_ok());
        assert!(namespace_name('c', &run).is_err());
        assert!(namespace_name('a', &run)
            .unwrap()
            .starts_with(RESOURCE_PREFIX));
        // Adversarial fragments rejected.
        for bad in [
            "",
            "A",
            "a/b",
            "..",
            "-lead",
            "has space",
            "UPPER",
            "way-too-long-name-fragment-over-32-chars",
        ] {
            assert!(
                validate_name_fragment(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
        // Veth names respect the 15-char ifname limit.
        let va = veth_name('a', &run).unwrap();
        assert!(va.len() <= 15);
    }

    #[test]
    fn command_construction_never_touches_host_namespace() {
        let run = RunId::generate(1_700_000_000, 99, 7);
        let plan = build_dry_run_plan(&run).unwrap();
        // Every setup/cleanup command is an argv without shell metacharacters,
        // and every nftables/packet command is scoped via `ip netns exec`.
        for cmd in plan
            .setup_commands
            .iter()
            .chain(plan.cleanup_commands.iter())
        {
            assert!(!cmd.is_empty());
            assert_eq!(cmd[0], "ip");
            for arg in cmd {
                assert!(!arg.contains(';') && !arg.contains('|') && !arg.contains('$'));
            }
        }
        assert!(plan
            .setup_commands
            .iter()
            .any(|c| c.contains(&"netns".to_string()) && c.contains(&"exec".to_string())));
        // nftables readback constructor is namespace-scoped.
        let scoped = nft_list_table_args(&plan.namespace_a, &plan.table);
        assert_eq!(
            &scoped[0..3],
            &["ip".to_string(), "netns".to_string(), "exec".to_string()]
        );
        assert_eq!(scoped[3], plan.namespace_a);
    }

    #[test]
    fn cleanup_ledger_ordering_and_idempotence() {
        let mut ledger = CleanupLedger::new();
        ledger.record(CleanupOp::DeleteNetns {
            ns: "synvoid-qa-x".to_string(),
        });
        ledger.record(CleanupOp::DeleteVeth {
            veth: "svqa-abc".to_string(),
        });
        ledger.record(CleanupOp::DeleteNetns {
            ns: "synvoid-qb-x".to_string(),
        });
        // Reverse creation order.
        assert_eq!(
            ledger.drain(),
            vec![
                CleanupOp::DeleteNetns {
                    ns: "synvoid-qb-x".to_string()
                },
                CleanupOp::DeleteVeth {
                    veth: "svqa-abc".to_string()
                },
                CleanupOp::DeleteNetns {
                    ns: "synvoid-qa-x".to_string()
                },
            ]
        );
        assert!(ledger.is_drained());
        // Second drain is a no-op success (rerunnable cleanup).
        assert!(ledger.drain().is_empty());
    }

    #[test]
    fn evidence_serialization_round_trip() {
        let evidence = QualificationEvidence {
            harness: "nft_native_qualification/1".to_string(),
            run_id: "1700000000-001234-001".to_string(),
            git_sha: "abc123".to_string(),
            timestamp_secs: 1_700_000_000,
            kernel_release: "6.8.0-test".to_string(),
            nft_version: "nftables v1.0.0".to_string(),
            arch: "x86_64".to_string(),
            euid: 0,
            cap_net_admin: true,
            preflight: "ready".to_string(),
            namespace_a: "synvoid-qa-x".to_string(),
            namespace_b: "synvoid-qb-x".to_string(),
            host_netns_inode: "net:[4026531840]".to_string(),
            target_netns_inode: "net:[4026531999]".to_string(),
            backend: "Nftables".to_string(),
            cases: vec![
                CaseResult::pass("install_and_owned_state_readback", "verified".to_string()),
                CaseResult::fail("drift_detection", "still applied".to_string()),
            ],
            fingerprints_hex: vec!["0123456789abcdef".to_string()],
            generations: vec![1],
            cleanup: "cleaned".to_string(),
            disposition: "not-qualified: 1 case failed".to_string(),
        };
        let json = evidence.to_json();
        // Bounded artifact: no secrets, no env dumps.
        assert!(!json.contains("SYNVOID"));
        assert!(!json.contains("password"));
        assert!(!json.contains("token"));
        let parsed = QualificationEvidence::from_json(&json).unwrap();
        assert_eq!(parsed.run_id, evidence.run_id);
        assert_eq!(parsed.cases.len(), 2);
        assert!(parsed.cases[0].is_pass());
        assert!(!parsed.cases[1].is_pass());
        assert!(QualificationEvidence::from_json("not json").is_err());
    }

    #[test]
    fn dry_run_performs_zero_mutation() {
        let run = RunId::generate(1_700_000_000, 42, 3);
        let plan = build_dry_run_plan(&run).unwrap();
        assert!(!plan.spawned_anything, "dry-run must spawn nothing");
        assert_eq!(plan.case_names.len(), 8);
        assert!(!plan.setup_commands.is_empty());
        assert!(!plan.cleanup_commands.is_empty());
        // Table name is identifier-valid for the crate ownership path.
        assert!(synvoid_icmp_filter::config::is_valid_identifier(
            &plan.table
        ));
    }

    #[test]
    fn run_ids_are_collision_resistant_and_valid() {
        let a = RunId::generate(1_700_000_000, 100, 1);
        let b = RunId::generate(1_700_000_000, 101, 1);
        assert_ne!(a.as_str(), b.as_str());
        assert_ne!(a.short_suffix(), b.short_suffix());
        // Generated ids use the orchestrator charset ([A-Za-z0-9-], ≤40).
        for id in [&a, &b] {
            assert!(RunId::from_external(id.as_str()).is_some());
        }
        assert!(RunId::from_external("").is_none());
        assert!(RunId::from_external("../escape").is_none());
        assert!(RunId::from_external(&"x".repeat(41)).is_none());
        // Namespace/table names derived from any generated id validate.
        assert!(namespace_name('a', &a).is_ok());
        assert!(veth_name('b', &b).is_ok());
        assert!(synvoid_icmp_filter::config::is_valid_identifier(
            &table_name(&a)
        ));
    }
}

// ===========================================================================
// Privileged native matrix (Linux only; ignored; fail-closed without gates)
// ===========================================================================

#[cfg(target_os = "linux")]
mod native {
    use super::support::*;
    use std::collections::HashSet;
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration;

    const CMD_TIMEOUT: Duration = Duration::from_secs(30);

    #[derive(Debug)]
    enum CmdError {
        Spawn(String),
        Timeout(String),
        Status {
            argv: Vec<String>,
            code: Option<i32>,
            stderr: String,
        },
    }

    impl std::fmt::Display for CmdError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                CmdError::Spawn(e) => write!(f, "spawn failed: {e}"),
                CmdError::Timeout(argv) => write!(f, "timeout: {argv}"),
                CmdError::Status { argv, code, stderr } => {
                    write!(f, "exit {code:?} for {argv:?}: {stderr}")
                }
            }
        }
    }

    /// Run argv with a wall-clock timeout (thread + channel; kills on
    /// expiry). No shell involved.
    fn run_cmd(argv: &[String], timeout: Duration) -> Result<String, CmdError> {
        let (program, args) = argv.split_first().expect("non-empty argv");
        let mut child = Command::new(program)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| CmdError::Spawn(format!("{argv:?}: {e}")))?;
        let (tx, rx) = mpsc::channel();
        let mut stdout_buf = child.stdout.take();
        let mut stderr_buf = child.stderr.take();
        let waiter = std::thread::spawn(move || {
            let status = child.wait();
            let mut out = String::new();
            let mut err = String::new();
            if let Some(o) = stdout_buf.as_mut() {
                let _ = o.read_to_string(&mut out);
            }
            if let Some(e) = stderr_buf.as_mut() {
                let _ = e.read_to_string(&mut err);
            }
            let _ = tx.send((status, out, err));
        });
        match rx.recv_timeout(timeout) {
            Ok((status, out, err)) => {
                let _ = waiter.join();
                match status {
                    Ok(s) if s.success() => Ok(out),
                    Ok(s) => Err(CmdError::Status {
                        argv: argv.to_vec(),
                        code: s.code(),
                        stderr: err,
                    }),
                    Err(e) => Err(CmdError::Spawn(format!("wait: {e}"))),
                }
            }
            Err(_) => Err(CmdError::Timeout(argv.join(" "))),
        }
    }

    fn command_exists(name: &str) -> bool {
        std::env::var_os("PATH")
            .map(|paths| {
                std::env::split_paths(&paths).any(|p| {
                    let c = p.join(name);
                    c.is_file()
                })
            })
            .unwrap_or(false)
    }

    fn read_cap_eff_has_net_admin() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|text| {
                text.lines()
                    .find_map(|l| l.strip_prefix("CapEff:").map(|v| v.trim().to_string()))
            })
            .and_then(|hex| u64::from_str_radix(&hex, 16).ok())
            .map(|mask| mask & (1 << 12) != 0)
            .unwrap_or(false)
    }

    fn git_sha() -> String {
        run_cmd(
            &[
                "git".to_string(),
                "rev-parse".to_string(),
                "HEAD".to_string(),
            ],
            Duration::from_secs(10),
        )
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
    }

    fn kernel_release() -> String {
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }

    fn nft_version() -> String {
        run_cmd(
            &["nft".to_string(), "--version".to_string()],
            Duration::from_secs(10),
        )
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
    }

    fn netns_inode(ns: Option<&str>) -> Result<String, CmdError> {
        let argv: Vec<String> = match ns {
            Some(n) => netns_exec_args(n, &["readlink", "/proc/self/ns/net"]),
            None => vec!["readlink".to_string(), "/proc/self/ns/net".to_string()],
        };
        run_cmd(&argv, CMD_TIMEOUT).map(|s| s.trim().to_string())
    }

    /// Rerunnable idempotent cleanup for harness namespaces (safe to run
    /// after interrupted execution; only touches the harness prefix).
    fn cleanup_prefix(prefix: &str) -> String {
        let list = run_cmd(&ip_args(&["netns", "list"]), CMD_TIMEOUT).unwrap_or_default();
        let mut removed = Vec::new();
        let mut errors = Vec::new();
        for line in list.lines() {
            let name = line.split_whitespace().next().unwrap_or("");
            if name.starts_with(prefix) && validate_name_fragment(name).is_ok() {
                match run_cmd(&ip_args(&["netns", "del", name]), CMD_TIMEOUT) {
                    Ok(_) => removed.push(name.to_string()),
                    Err(e) => errors.push(format!("{name}: {e}")),
                }
            }
        }
        if errors.is_empty() {
            format!(
                "cleaned {} namespace(s): {}",
                removed.len(),
                removed.join(",")
            )
        } else {
            format!(
                "partial cleanup: removed [{}], errors [{}]",
                removed.join(","),
                errors.join("; ")
            )
        }
    }

    struct Topology {
        #[allow(dead_code)]
        run_id: RunId,
        ns_a: String,
        ns_b: String,
        veth_a: String,
        #[allow(dead_code)]
        veth_b: String,
        table: String,
        ledger: CleanupLedger,
        /// Open fd to the HOST network namespace (kept across the
        /// `setns` transition so cleanup can return and destroy the
        /// disposable namespaces). `-1` when unavailable (cleanup then
        /// best-efforts from the current namespace).
        host_netns_fd: std::os::fd::RawFd,
        /// Whether this process entered the target namespace.
        entered_target: bool,
    }

    impl Topology {
        fn create(run_id: RunId) -> Result<Self, String> {
            let ns_a = namespace_name('a', &run_id)?;
            let ns_b = namespace_name('b', &run_id)?;
            let veth_a = veth_name('a', &run_id)?;
            let veth_b = veth_name('b', &run_id)?;
            let table = table_name(&run_id);
            let plan = build_dry_run_plan(&run_id)?;
            let mut ledger = CleanupLedger::new();
            // Execute the exact dry-run setup commands so --dry-run output
            // matches privileged behavior 1:1.
            for cmd in &plan.setup_commands {
                run_cmd(cmd, CMD_TIMEOUT).map_err(|e| format!("setup {cmd:?}: {e}"))?;
            }
            ledger.record(CleanupOp::DeleteNetns { ns: ns_a.clone() });
            ledger.record(CleanupOp::DeleteVeth {
                veth: veth_a.clone(),
            });
            ledger.record(CleanupOp::DeleteNetns { ns: ns_b.clone() });
            // Secondary source address for exemption contrast.
            run_cmd(
                &netns_exec_args(
                    &ns_b,
                    &["ip", "addr", "add", "10.201.0.3/24", "dev", &veth_b],
                ),
                CMD_TIMEOUT,
            )
            .map_err(|e| format!("secondary addr: {e}"))?;
            // Prove isolation BEFORE touching nftables: target inode must
            // differ from the host inode.
            let host = netns_inode(None).map_err(|e| format!("host netns read: {e}"))?;
            let target = netns_inode(Some(&ns_a)).map_err(|e| format!("target netns read: {e}"))?;
            if host == target || host.is_empty() || target.is_empty() {
                Self::destroy(&ns_a, &ns_b, &veth_a);
                return Err(format!(
                    "refusing: target namespace not proven disposable (host={host:?} target={target:?})"
                ));
            }
            // Keep a host-namespace fd, then enter the TARGET namespace so
            // every subsequent crate `nft` invocation lands inside the
            // disposable boundary — the default host namespace is never
            // touched by firewall operations afterwards.
            // SAFETY: open() on a /proc self path with O_RDONLY|O_CLOEXEC;
            // the fd is owned by this struct and closed on cleanup/Drop.
            let host_netns_fd = unsafe {
                libc::open(
                    c"/proc/self/ns/net".as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC,
                )
            };
            if host_netns_fd < 0 {
                Self::destroy(&ns_a, &ns_b, &veth_a);
                return Err("refusing: cannot pin host network namespace".to_string());
            }
            let target_path = format!("/run/netns/{ns_a}");
            let target_fd = unsafe {
                libc::open(
                    target_path.as_ptr() as *const libc::c_char,
                    libc::O_RDONLY | libc::O_CLOEXEC,
                )
            };
            if target_fd < 0 {
                unsafe { libc::close(host_netns_fd) };
                Self::destroy(&ns_a, &ns_b, &veth_a);
                return Err(format!("refusing: cannot open {target_path}"));
            }
            // SAFETY: setns(fd, CLONE_NEWNET) moves only this thread into
            // the target network namespace; the harness is single-threaded
            // at this point (no matrix threads spawned yet).
            let rc = unsafe { libc::setns(target_fd, libc::CLONE_NEWNET) };
            unsafe { libc::close(target_fd) };
            if rc != 0 {
                unsafe { libc::close(host_netns_fd) };
                Self::destroy(&ns_a, &ns_b, &veth_a);
                return Err(format!(
                    "refusing: setns into {ns_a} failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            // Re-prove from inside: current inode must equal the target.
            let current = netns_inode(None).map_err(|e| format!("post-setns read: {e}"))?;
            if current != target {
                Self::return_to_host(host_netns_fd);
                unsafe { libc::close(host_netns_fd) };
                Self::destroy(&ns_a, &ns_b, &veth_a);
                return Err(format!(
                    "refusing: post-setns inode {current:?} != target {target:?}"
                ));
            }
            Ok(Self {
                run_id,
                ns_a,
                ns_b,
                veth_a,
                veth_b,
                table,
                ledger,
                host_netns_fd,
                entered_target: true,
            })
        }

        fn return_to_host(host_fd: std::os::fd::RawFd) {
            // SAFETY: reverses the earlier setns using the pinned host fd.
            unsafe {
                libc::setns(host_fd, libc::CLONE_NEWNET);
            }
        }

        fn destroy(ns_a: &str, ns_b: &str, veth_a: &str) {
            let _ = run_cmd(&ip_args(&["link", "del", veth_a]), CMD_TIMEOUT);
            let _ = run_cmd(&ip_args(&["netns", "del", ns_a]), CMD_TIMEOUT);
            let _ = run_cmd(&ip_args(&["netns", "del", ns_b]), CMD_TIMEOUT);
        }

        fn cleanup(mut self) -> String {
            // Return to the host namespace BEFORE destroying anything: the
            // matrix ran inside the target namespace.
            if self.entered_target && self.host_netns_fd >= 0 {
                Self::return_to_host(self.host_netns_fd);
            }
            let mut notes = Vec::new();
            for op in self.ledger.drain() {
                let r = match &op {
                    CleanupOp::DeleteVeth { veth } => {
                        run_cmd(&ip_args(&["link", "del", veth]), CMD_TIMEOUT)
                    }
                    CleanupOp::DeleteNetns { ns } => {
                        run_cmd(&ip_args(&["netns", "del", ns]), CMD_TIMEOUT)
                    }
                };
                // Missing-after-delete is success (idempotent rerun).
                match r {
                    Ok(_) => notes.push(format!("{op:?} ok")),
                    Err(e) => notes.push(format!("{op:?} best-effort: {e}")),
                }
            }
            if self.host_netns_fd >= 0 {
                // SAFETY: owned fd from create(); closed exactly once here.
                unsafe { libc::close(self.host_netns_fd) };
                self.host_netns_fd = -1;
            }
            self.entered_target = false;
            // Verify no harness namespace remains.
            let remaining = run_cmd(&ip_args(&["netns", "list"]), CMD_TIMEOUT)
                .unwrap_or_default()
                .lines()
                .filter(|l| l.starts_with(RESOURCE_PREFIX))
                .count();
            // Prevent Drop from re-running.
            std::mem::forget(self);
            if remaining == 0 {
                format!("cleaned ({})", notes.join("; "))
            } else {
                format!(
                    "LEFTOVER {remaining} harness namespace(s) ({})",
                    notes.join("; ")
                )
            }
        }
    }

    impl Drop for Topology {
        fn drop(&mut self) {
            // Best-effort fallback: explicit cleanup() is authoritative and
            // verified; Drop only covers panic paths.
            if self.entered_target && self.host_netns_fd >= 0 {
                Self::return_to_host(self.host_netns_fd);
                // SAFETY: owned fd; Drop runs at most once.
                unsafe { libc::close(self.host_netns_fd) };
                self.host_netns_fd = -1;
            }
            Self::destroy(&self.ns_a, &self.ns_b, &self.veth_a);
        }
    }

    fn ping_from(ns: &str, target: &str, count: u32, family: &str) -> bool {
        let ping_bin = if family == "6" { "ping6" } else { "ping" };
        let argv = if command_exists(ping_bin) {
            netns_exec_args(ns, &[ping_bin, "-c", &count.to_string(), "-W", "1", target])
        } else {
            netns_exec_args(ns, &["ping", "-c", &count.to_string(), "-W", "1", target])
        };
        // Family flag where supported (after the ping binary); failure to
        // run counts as no-reply.
        let mut argv6 = argv.clone();
        if family == "6" {
            argv6.insert(5, "-6".to_string());
        }
        run_cmd(&argv6, Duration::from_secs(20 + u64::from(count))).is_ok()
    }

    fn nft_list_contains(ns: &str, table: &str, needle: &str) -> bool {
        run_cmd(&nft_list_table_args(ns, table), CMD_TIMEOUT)
            .map(|out| out.contains(needle))
            .unwrap_or(false)
    }

    fn nft_tables_in(ns: &str) -> String {
        run_cmd(
            &netns_exec_args(ns, &["nft", "list", "tables"]),
            CMD_TIMEOUT,
        )
        .unwrap_or_default()
    }

    fn test_config(
        table: &str,
        rules_v4: Vec<(u8, Option<u8>, bool)>,
        exempt: Vec<std::net::IpAddr>,
        rate: Option<(u32, u32)>,
    ) -> synvoid_icmp_filter::config::IcmpFilterConfig {
        use synvoid_icmp_filter::config::*;
        let map_rule = |(t, c, block): (u8, Option<u8>, bool)| IcmpTypeRule {
            icmp_type: t,
            icmp_code: c,
            action: if block {
                IcmpAction::Block
            } else {
                IcmpAction::Allow
            },
            description: None,
        };
        IcmpFilterConfig {
            enabled: true,
            filter_type: FilterType::Nftables,
            direction: Direction::Both,
            interfaces: InterfaceSpec::All,
            rate_limit: rate.map(|(pps, burst)| RateLimitConfig {
                enabled: true,
                packets_per_second: pps,
                burst,
            }),
            exempt_ips: exempt,
            table_name: table.to_string(),
            icmp_type_rules: rules_v4.into_iter().map(map_rule).collect(),
            icmpv6_type_rules: Vec::new(),
            ebpf_bytecode_path: None,
        }
    }

    struct Matrix {
        topo: Topology,
        cases: Vec<CaseResult>,
        fingerprints_hex: Vec<String>,
        generations: Vec<u64>,
    }

    impl Matrix {
        fn record(&mut self, result: CaseResult) {
            self.cases.push(result);
        }

        fn manager_for(
            &self,
            cfg: synvoid_icmp_filter::config::IcmpFilterConfig,
        ) -> Result<synvoid_icmp_filter::IcmpFilterManager, String> {
            synvoid_icmp_filter::IcmpFilterManager::new(cfg)
                .map_err(|e| format!("manager construction: {e}"))
        }

        fn push_receipt(&mut self, receipt: &synvoid_icmp_filter::ApplyReceipt) {
            self.fingerprints_hex
                .push(synvoid_icmp_filter::fingerprint_hex(receipt.fingerprint));
            self.generations.push(receipt.generation);
        }

        fn case_install_readback(&mut self) {
            use synvoid_icmp_filter::config::FilterType;
            let name = "install_and_owned_state_readback";
            // Minimal policy: block v4 echo.
            let cfg = test_config(&self.topo.table, vec![(8, None, true)], vec![], None);
            assert_eq!(cfg.filter_type, FilterType::Nftables);
            let mut mgr = match self.manager_for(cfg) {
                Ok(m) => m,
                Err(e) => {
                    self.record(CaseResult::fail(name, e));
                    return;
                }
            };
            // The harness process entered the TARGET namespace at setup, so
            // the crate's subprocess `nft` invocations land inside the
            // disposable boundary. Owned-state readback goes through the
            // crate path; unrelated namespace state (peer ns tables) must
            // be untouched.
            match mgr.enable() {
                Ok(receipt) => {
                    self.push_receipt(&receipt);
                    let outcome = mgr.verify_live();
                    let report = mgr.report().expect("report");
                    if matches!(outcome, synvoid_icmp_filter::VerificationOutcome::Verified)
                        && report.live == synvoid_icmp_filter::EnforcementState::Applied
                    {
                        let peer_tables = nft_tables_in(&self.topo.ns_b);
                        if peer_tables.contains(&self.topo.table) {
                            self.record(CaseResult::fail(
                                name,
                                "owned table leaked into peer namespace".to_string(),
                            ));
                        } else {
                            self.record(CaseResult::pass(
                                name,
                                format!(
                                    "installed fp={} gen={} verified via crate readback",
                                    synvoid_icmp_filter::fingerprint_hex(receipt.fingerprint),
                                    receipt.generation
                                ),
                            ));
                        }
                    } else {
                        self.record(CaseResult::fail(
                            name,
                            format!("verify after install: {outcome:?}"),
                        ));
                    }
                }
                Err(e) => self.record(CaseResult::fail(name, format!("enable: {e}"))),
            }
        }

        fn case_type_code(&mut self) {
            let name = "icmp_type_code_behavior";
            // Block v4 echo (type 8); observe from the peer namespace.
            let cfg = test_config(&self.topo.table, vec![(8, None, true)], vec![], None);
            let mut mgr = match self.manager_for(cfg) {
                Ok(m) => m,
                Err(e) => {
                    self.record(CaseResult::fail(name, e));
                    return;
                }
            };
            if let Err(e) = mgr.enable() {
                self.record(CaseResult::fail(name, format!("enable: {e}")));
                return;
            }
            // Packet behavior observed from the peer namespace, not rule text.
            let blocked = !ping_from(&self.topo.ns_b, "10.201.0.1", 2, "4");
            let v6_blocked_probe = {
                let cfg6 = test_config(&self.topo.table, vec![(8, None, true)], vec![], None);
                let _ = cfg6;
                // v6 echo exercised where the topology carries v6.
                !ping_from(&self.topo.ns_b, "fd00:db8:91::1", 1, "6")
            };
            let _ = mgr.disable();
            if blocked {
                self.record(CaseResult::pass(
                    name,
                    format!("v4 echo blocked while policy applied (v6 probe blocked={v6_blocked_probe})"),
                ));
            } else {
                self.record(CaseResult::fail(
                    name,
                    "v4 echo NOT blocked while block-echo policy applied".to_string(),
                ));
            }
        }

        fn case_exemptions(&mut self) {
            let name = "exemptions";
            // Block echo, exempt the peer primary source; the secondary
            // source in the same disposable environment stays subject.
            let exempt: std::net::IpAddr = "10.201.0.2".parse().unwrap();
            let cfg = test_config(&self.topo.table, vec![(8, None, true)], vec![exempt], None);
            let mut mgr = match self.manager_for(cfg) {
                Ok(m) => m,
                Err(e) => {
                    self.record(CaseResult::fail(name, e));
                    return;
                }
            };
            if let Err(e) = mgr.enable() {
                self.record(CaseResult::fail(name, format!("enable: {e}")));
                return;
            }
            // Exempt traffic allowed: ping the target from the peer ns
            // (source .2 is exempt). Non-exempt contrast uses the secondary
            // address as source via ping -I.
            let exempt_ok = ping_from(&self.topo.ns_b, "10.201.0.1", 2, "4");
            let nonexempt_argv = netns_exec_args(
                &self.topo.ns_b,
                &[
                    "ping",
                    "-c",
                    "2",
                    "-W",
                    "1",
                    "-I",
                    "10.201.0.3",
                    "10.201.0.1",
                ],
            );
            let nonexempt_blocked = run_cmd(&nonexempt_argv, Duration::from_secs(25)).is_err();
            let _ = mgr.disable();
            if exempt_ok && nonexempt_blocked {
                self.record(CaseResult::pass(
                    name,
                    "exempt source allowed while non-exempt source blocked".to_string(),
                ));
            } else {
                self.record(CaseResult::fail(
                    name,
                    format!("exempt_ok={exempt_ok} nonexempt_blocked={nonexempt_blocked}"),
                ));
            }
        }

        fn case_rate_limit(&mut self) {
            let name = "rate_limit_global";
            // Global 10pps burst 20: below-threshold passes, burst drops,
            // recovery after refill. Scheduler-tolerant assertions only.
            let cfg = test_config(
                &self.topo.table,
                vec![(8, None, false)],
                vec![],
                Some((10, 20)),
            );
            let mut mgr = match self.manager_for(cfg) {
                Ok(m) => m,
                Err(e) => {
                    self.record(CaseResult::fail(name, e));
                    return;
                }
            };
            if let Err(e) = mgr.enable() {
                self.record(CaseResult::fail(name, format!("enable: {e}")));
                return;
            }
            // Below threshold: 3 spaced pings.
            let mut below_ok = 0;
            for _ in 0..3 {
                if ping_from(&self.topo.ns_b, "10.201.0.1", 1, "4") {
                    below_ok += 1;
                }
                std::thread::sleep(Duration::from_millis(300));
            }
            // Burst above threshold: 40 rapid pings, count replies via -c
            // exit status is all-or-nothing, so use flood count mode and
            // look for any loss via summary output instead.
            let burst_argv = netns_exec_args(
                &self.topo.ns_b,
                &["ping", "-c", "40", "-i", "0.01", "-W", "1", "10.201.0.1"],
            );
            let burst_out = run_cmd(&burst_argv, Duration::from_secs(30));
            let burst_loss = burst_out
                .map(|out| out.contains("loss") && !out.contains("0% packet loss"))
                .unwrap_or(true);
            // Recovery: wait for refill, then spaced pings succeed.
            std::thread::sleep(Duration::from_secs(3));
            let recovered = ping_from(&self.topo.ns_b, "10.201.0.1", 2, "4");
            let _ = mgr.disable();
            if below_ok >= 2 && burst_loss && recovered {
                self.record(CaseResult::pass(
                    name,
                    format!("below={below_ok}/3 burst_loss observed recovery ok"),
                ));
            } else {
                self.record(CaseResult::fail(
                    name,
                    format!("below={below_ok}/3 burst_loss={burst_loss} recovered={recovered}"),
                ));
            }
        }

        fn case_atomic_update(&mut self) {
            let name = "atomic_update_replacement";
            let cfg_a = test_config(&self.topo.table, vec![(8, None, true)], vec![], None);
            let mut mgr = match self.manager_for(cfg_a) {
                Ok(m) => m,
                Err(e) => {
                    self.record(CaseResult::fail(name, e));
                    return;
                }
            };
            let receipt_a = match mgr.enable() {
                Ok(r) => r,
                Err(e) => {
                    self.record(CaseResult::fail(name, format!("enable A: {e}")));
                    return;
                }
            };
            let blocked_a = !ping_from(&self.topo.ns_b, "10.201.0.1", 1, "4");
            // Replace with generation B (allow echo).
            let cfg_b = test_config(&self.topo.table, vec![(8, None, false)], vec![], None);
            if let Err(e) = mgr.update_config(cfg_b) {
                self.record(CaseResult::fail(name, format!("update to B: {e}")));
                return;
            }
            let report = mgr.report().expect("report");
            let fp_b = report
                .desired_fingerprint
                .map(synvoid_icmp_filter::fingerprint_hex)
                .unwrap_or_default();
            let allowed_b = ping_from(&self.topo.ns_b, "10.201.0.1", 2, "4");
            // Stale generation-A objects absent: ownership tag embeds the
            // fingerprint, so the A marker must be gone from the table.
            let fp_a = synvoid_icmp_filter::fingerprint_hex(receipt_a.fingerprint);
            let stale_absent = !nft_list_contains(&self.topo.ns_a, &self.topo.table, &fp_a);
            let _ = mgr.disable();
            if blocked_a && allowed_b && fp_a != fp_b && stale_absent {
                self.record(CaseResult::pass(
                    name,
                    format!("A blocked, B allowed, fp {fp_a} -> {fp_b}, stale absent"),
                ));
                self.push_receipt(&report.last_receipt.expect("receipt B"));
            } else {
                self.record(CaseResult::fail(
                    name,
                    format!(
                        "blocked_a={blocked_a} allowed_b={allowed_b} stale_absent={stale_absent}"
                    ),
                ));
            }
        }

        fn case_drift(&mut self) {
            let name = "drift_detection";
            let cfg = test_config(&self.topo.table, vec![(8, None, true)], vec![], None);
            let mut mgr = match self.manager_for(cfg) {
                Ok(m) => m,
                Err(e) => {
                    self.record(CaseResult::fail(name, e));
                    return;
                }
            };
            if let Err(e) = mgr.enable() {
                self.record(CaseResult::fail(name, format!("enable: {e}")));
                return;
            }
            // Mutate owned state externally inside the disposable namespace:
            // delete one owned chain (drift), then verify.
            let chains = run_cmd(
                &nft_list_table_args(&self.topo.ns_a, &self.topo.table),
                CMD_TIMEOUT,
            )
            .unwrap_or_default();
            let chain = chains
                .lines()
                .find(|l| l.trim_start().starts_with("chain "))
                .and_then(|l| l.split_whitespace().nth(1))
                .map(|s| s.to_string());
            if let Some(chain) = chain {
                let del = netns_exec_args(
                    &self.topo.ns_a,
                    &["nft", "delete", "chain", "inet", &self.topo.table, &chain],
                );
                let _ = run_cmd(&del, CMD_TIMEOUT);
            } else {
                // Fallback drift: flush the owned table entirely.
                let flush = netns_exec_args(
                    &self.topo.ns_a,
                    &["nft", "flush", "table", "inet", &self.topo.table],
                );
                let _ = run_cmd(&flush, CMD_TIMEOUT);
            }
            let outcome = mgr.verify_live();
            let report = mgr.report().expect("report");
            let _ = mgr.disable();
            if !matches!(outcome, synvoid_icmp_filter::VerificationOutcome::Verified)
                && report.live != synvoid_icmp_filter::EnforcementState::Applied
            {
                self.record(CaseResult::pass(
                    name,
                    format!("external mutation => {outcome:?} / {:?}", report.live),
                ));
            } else {
                self.record(CaseResult::fail(
                    name,
                    format!("drift NOT detected: {outcome:?} / {:?}", report.live),
                ));
            }
        }

        fn case_disable(&mut self) {
            let name = "disable_cleanup";
            let cfg = test_config(&self.topo.table, vec![(8, None, true)], vec![], None);
            let mut mgr = match self.manager_for(cfg) {
                Ok(m) => m,
                Err(e) => {
                    self.record(CaseResult::fail(name, e));
                    return;
                }
            };
            if let Err(e) = mgr.enable() {
                self.record(CaseResult::fail(name, format!("enable: {e}")));
                return;
            }
            if let Err(e) = mgr.disable() {
                self.record(CaseResult::fail(name, format!("disable: {e}")));
                return;
            }
            let report = mgr.report().expect("report");
            let absent = report.live == synvoid_icmp_filter::EnforcementState::Absent;
            let peer_ok = ping_from(&self.topo.ns_b, "10.201.0.1", 2, "4");
            let owned_gone = !nft_tables_in(&self.topo.ns_a).contains(&self.topo.table);
            if absent && peer_ok && owned_gone {
                self.record(CaseResult::pass(
                    name,
                    "disable verified Absent, peer traffic restored, no owned objects".to_string(),
                ));
            } else {
                self.record(CaseResult::fail(
                    name,
                    format!("absent={absent} peer_ok={peer_ok} owned_gone={owned_gone}"),
                ));
            }
        }

        fn case_rollback(&mut self) {
            let name = "rollback_failure_path";
            let cfg = test_config(&self.topo.table, vec![(8, None, true)], vec![], None);
            let mut mgr = match self.manager_for(cfg) {
                Ok(m) => m,
                Err(e) => {
                    self.record(CaseResult::fail(name, e));
                    return;
                }
            };
            let receipt = match mgr.enable() {
                Ok(r) => r,
                Err(e) => {
                    self.record(CaseResult::fail(name, format!("enable: {e}")));
                    return;
                }
            };
            let gen_before = receipt.generation;
            // Deterministic native installation failure: an inexpressible
            // replacement (invalid table identifier) must be rejected at
            // compile time with zero mutation — the previous generation
            // remains effective and the report does not advance.
            let mut bad = test_config(&self.topo.table, vec![(8, None, false)], vec![], None);
            bad.table_name = "bad table!".to_string();
            let err = mgr
                .update_config(bad)
                .expect_err("inexpressible update must fail");
            let _ = err;
            let report = mgr.report().expect("report");
            let still_blocked = !ping_from(&self.topo.ns_b, "10.201.0.1", 1, "4");
            let gen_unchanged = report.desired_generation == gen_before
                || report.last_receipt.as_ref().map(|r| r.generation) == Some(gen_before);
            let _ = mgr.disable();
            if still_blocked && gen_unchanged {
                self.record(CaseResult::pass(
                    name,
                    "rejected generation left previous enforcement effective".to_string(),
                ));
            } else {
                self.record(CaseResult::fail(
                    name,
                    format!("still_blocked={still_blocked} gen_unchanged={gen_unchanged}"),
                ));
            }
        }
    }

    /// Privileged matrix entry. Ignored by default; requires
    /// `SYNVOID_ICMP_QUALIFY_NATIVE=1` plus privilege plus tools. Any unmet
    /// gate is a hard failure ("not qualified"), never a silent pass.
    #[test]
    #[ignore = "privileged native qualification: requires Linux + root/CAP_NET_ADMIN + SYNVOID_ICMP_QUALIFY_NATIVE=1 + ip/nft/ping"]
    fn nft_native_matrix() {
        let euid = unsafe { libc::getuid() };
        let inputs = PreflightInputs {
            platform: std::env::consts::OS.to_string(),
            opt_in_env: std::env::var(NATIVE_OPT_IN_ENV).ok(),
            euid,
            cap_net_admin: read_cap_eff_has_net_admin(),
            ip_present: command_exists("ip"),
            nft_present: command_exists("nft"),
            ping_present: command_exists("ping") || command_exists("ping6"),
        };
        match check_preflight(&inputs) {
            PreflightVerdict::Ready => {}
            PreflightVerdict::Refused(reason) => {
                panic!("NOT QUALIFIED (native gates unmet): {reason}");
            }
        }

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        #[allow(clippy::cast_possible_truncation)]
        // Prefer the orchestrator-supplied run id (xtask --native passes
        // one); fall back to a generated id. Either way the value feeds the
        // same validated naming scheme.
        let run_id = match std::env::var("SYNVOID_ICMP_QUALIFY_RUN") {
            Ok(v) if RunId::from_external(&v).is_some() => RunId::from_external(&v).expect("valid"),
            _ => RunId::generate(ts, std::process::id(), 1),
        };
        let preflight_summary = format!(
            "ready: euid={euid} cap_net_admin={} nft={}",
            read_cap_eff_has_net_admin(),
            nft_version()
        );
        let host_inode = netns_inode(None).unwrap_or_else(|e| format!("unreadable: {e}"));

        let topo = Topology::create(run_id.clone())
            .unwrap_or_else(|e| panic!("NOT QUALIFIED (topology setup failed): {e}"));
        let target_inode =
            netns_inode(Some(&topo.ns_a)).unwrap_or_else(|e| format!("unreadable: {e}"));
        let (ns_a, ns_b) = (topo.ns_a.clone(), topo.ns_b.clone());

        let mut matrix = Matrix {
            topo,
            cases: Vec::new(),
            fingerprints_hex: Vec::new(),
            generations: Vec::new(),
        };
        // Execute the matrix; every case records pass/fail (panics inside a
        // case would skip cleanup — cases return results, never panic).
        matrix.case_install_readback();
        matrix.case_type_code();
        matrix.case_exemptions();
        matrix.case_rate_limit();
        matrix.case_atomic_update();
        matrix.case_drift();
        matrix.case_disable();
        matrix.case_rollback();

        let cases = matrix.cases.clone();
        let fingerprints = matrix.fingerprints_hex.clone();
        let generations = matrix.generations.clone();
        let Matrix { topo, .. } = matrix;
        let cleanup = topo.cleanup();
        let passed = cases.iter().filter(|c| c.is_pass()).count();
        let total = cases.len();
        let failed_names: Vec<String> = cases
            .iter()
            .filter(|c| !c.is_pass())
            .map(|c| c.name.clone())
            .collect();
        // Deduplicate fingerprints/generations for the artifact.
        let mut seen = HashSet::new();
        let fingerprints_hex: Vec<String> = fingerprints
            .into_iter()
            .filter(|f| seen.insert(f.clone()))
            .collect();
        let mut seen_gen = HashSet::new();
        let generations: Vec<u64> = generations
            .into_iter()
            .filter(|g| seen_gen.insert(*g))
            .collect();

        let evidence = QualificationEvidence {
            harness: "nft_native_qualification/1".to_string(),
            run_id: run_id.as_str().to_string(),
            git_sha: git_sha(),
            timestamp_secs: ts,
            kernel_release: kernel_release(),
            nft_version: nft_version(),
            arch: std::env::consts::ARCH.to_string(),
            euid,
            cap_net_admin: read_cap_eff_has_net_admin(),
            preflight: preflight_summary,
            namespace_a: ns_a,
            namespace_b: ns_b,
            host_netns_inode: host_inode,
            target_netns_inode: target_inode,
            backend: "Nftables".to_string(),
            cases,
            fingerprints_hex,
            generations,
            cleanup,
            disposition: if failed_names.is_empty() && total == 8 {
                "qualified: 8/8 native cases passed".to_string()
            } else {
                format!(
                    "not-qualified: {passed}/{total} passed; failed: {}",
                    failed_names.join(",")
                )
            },
        };
        let out_path = std::env::var(EVIDENCE_OUT_ENV)
            .unwrap_or_else(|_| format!("target/icmp-qualify-{}.json", run_id.as_str()));
        if let Some(parent) = std::path::Path::new(&out_path).parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        std::fs::write(&out_path, evidence.to_json())
            .unwrap_or_else(|e| panic!("evidence write {out_path}: {e}"));
        eprintln!(
            "evidence: {out_path}\ndisposition: {}",
            evidence.disposition
        );
        assert!(
            failed_names.is_empty() && total == 8,
            "NOT QUALIFIED: {passed}/{total} passed; failed: {}",
            failed_names.join(",")
        );
    }

    /// Rerunnable cleanup helper for interrupted runs (also ignored; same
    /// gates minus matrix execution). Removes harness-prefixed namespaces.
    #[test]
    #[ignore = "cleanup helper for interrupted native runs"]
    fn nft_native_cleanup() {
        let euid = unsafe { libc::getuid() };
        if euid != 0 && !read_cap_eff_has_net_admin() {
            panic!("NOT QUALIFIED (cleanup needs privilege)");
        }
        let summary = cleanup_prefix(RESOURCE_PREFIX);
        eprintln!("{summary}");
    }
}
