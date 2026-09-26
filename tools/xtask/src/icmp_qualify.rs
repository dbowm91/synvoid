//! ICMP privileged native qualification front-end (Phase 91).
//!
//! Operator-facing harness orchestration for the Linux nftables native
//! matrix (`crates/synvoid-icmp-filter/tests/nft_native_qualification.rs`).
//! This module never touches firewall state itself: `--check` and
//! `--dry-run` are read-only/print-only; `--native` shells the ignored
//! crate test with explicit gates; `--cleanup` removes only
//! harness-prefixed namespaces.
//!
//! Safety mirrors the crate harness: explicit opt-in flag PLUS environment
//! (`SYNVOID_ICMP_QUALIFY_NATIVE=1`), privilege detection, prerequisite
//! tools, collision-resistant run ids, bounded evidence, idempotent
//! cleanup. Anything unmet is "not qualified", never success.

use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const OPT_IN_ENV: &str = "SYNVOID_ICMP_QUALIFY_NATIVE";
pub const RUN_ENV: &str = "SYNVOID_ICMP_QUALIFY_RUN";
pub const OUT_ENV: &str = "SYNVOID_ICMP_QUALIFY_OUT";
pub const RESOURCE_PREFIX: &str = "synvoid-q";

pub struct Options {
    pub check: bool,
    pub dry_run: bool,
    pub native: bool,
    pub cleanup: bool,
    pub json: bool,
    pub timeout_secs: u64,
    pub out: Option<String>,
}

impl Options {
    pub fn from_args(args: &[String]) -> Self {
        let has = |flag: &str| args.iter().any(|a| a == flag);
        let timeout_secs = args
            .windows(2)
            .find(|w| w[0] == "--timeout-secs")
            .and_then(|w| w[1].parse::<u64>().ok())
            .unwrap_or(900);
        let out = args
            .windows(2)
            .find(|w| w[0] == "--out")
            .map(|w| w[1].clone());
        Self {
            check: has("--check"),
            dry_run: has("--dry-run"),
            native: has("--native"),
            cleanup: has("--cleanup"),
            json: has("--json"),
            timeout_secs,
            out,
        }
    }
}

/// Collision-resistant run id: `<epoch>-<pid>-<seq>` (validated charset).
pub fn generate_run_id(seq: u32) -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{ts}-{}-{seq}", std::process::id())
}

/// Validate an operator-supplied run id (`[A-Za-z0-9-]{1,40}`, no `..`).
pub fn validate_run_id(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > 40 {
        return Err("run id must be 1..=40 chars".to_string());
    }
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(format!("run id {s:?} must match [A-Za-z0-9-]+"));
    }
    if s.contains("..") {
        return Err("run id must not contain ..".to_string());
    }
    Ok(())
}

fn command_exists(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|p| p.join(name).is_file()))
        .unwrap_or(false)
}

fn euid() -> u32 {
    #[cfg(unix)]
    {
        libc_euid()
    }
    #[cfg(not(unix))]
    {
        1000
    }
}

#[cfg(unix)]
fn libc_euid() -> u32 {
    // Minimal FFI without adding a dependency to xtask.
    extern "C" {
        fn getuid() -> u32;
    }
    // SAFETY: getuid is async-signal-safe with no preconditions.
    unsafe { getuid() }
}

fn has_cap_net_admin() -> bool {
    #[cfg(target_os = "linux")]
    {
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
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

pub struct Preflight {
    pub platform: String,
    pub opt_in: bool,
    pub euid: u32,
    pub cap_net_admin: bool,
    pub ip_present: bool,
    pub nft_present: bool,
    pub ping_present: bool,
}

impl Preflight {
    pub fn collect() -> Self {
        Self {
            platform: std::env::consts::OS.to_string(),
            opt_in: std::env::var(OPT_IN_ENV).as_deref() == Ok("1"),
            euid: euid(),
            cap_net_admin: has_cap_net_admin(),
            ip_present: command_exists("ip"),
            nft_present: command_exists("nft"),
            ping_present: command_exists("ping") || command_exists("ping6"),
        }
    }

    /// Human verdict lines + readiness. Anything unmet names its gate.
    pub fn verdict(&self) -> (bool, Vec<String>) {
        let mut lines = Vec::new();
        let mut ready = true;
        if self.platform != "linux" {
            ready = false;
            lines.push(format!("refuse: requires Linux, host is {}", self.platform));
        } else {
            lines.push("platform: linux ok".to_string());
        }
        if !self.opt_in {
            ready = false;
            lines.push(format!("refuse: set {OPT_IN_ENV}=1 plus --native"));
        } else {
            lines.push("opt-in: present".to_string());
        }
        if self.euid == 0 || self.cap_net_admin {
            lines.push(format!(
                "privilege: euid={} cap_net_admin={} ok",
                self.euid, self.cap_net_admin
            ));
        } else {
            ready = false;
            lines
                .push("refuse: insufficient privilege: root or CAP_NET_ADMIN required".to_string());
        }
        for (tool, present) in [
            ("ip", self.ip_present),
            ("nft", self.nft_present),
            ("ping", self.ping_present),
        ] {
            if present {
                lines.push(format!("tool {tool}: present"));
            } else {
                ready = false;
                lines.push(format!("refuse: missing prerequisite tool: {tool}"));
            }
        }
        (ready, lines)
    }
}

fn emit(
    json: bool,
    run_id: &str,
    command: &str,
    ok: bool,
    detail: &str,
    extra: Option<serde_json::Value>,
) {
    if json {
        let mut obj = serde_json::json!({
            "command": command,
            "run_id": run_id,
            "ok": ok,
            "detail": detail,
        });
        if let Some(v) = extra {
            obj["evidence"] = v;
        }
        println!("{obj}");
    } else {
        println!("icmp-qualify {command} run={run_id} ok={ok}\n{detail}");
        if let Some(v) = extra {
            println!("{v}");
        }
    }
}

fn run_check(opts: &Options, run_id: &str) -> Result<(), String> {
    let pre = Preflight::collect();
    let (ready, lines) = pre.verdict();
    let detail = lines.join("\n");
    if ready {
        emit(opts.json, run_id, "check", true, &detail, None);
        Ok(())
    } else {
        emit(
            opts.json,
            run_id,
            "check",
            false,
            &format!("NOT QUALIFIED\n{detail}"),
            None,
        );
        Err("preflight refused: host not qualified for native run".to_string())
    }
}

fn run_dry_run(opts: &Options, run_id: &str) -> Result<(), String> {
    // Print-only: the exact topology/commands a native run would execute.
    // Zero mutation by construction (no Command spawn on this path).
    let short = short_suffix(run_id);
    let ns_a = format!("{RESOURCE_PREFIX}-a-{short}");
    let ns_b = format!("{RESOURCE_PREFIX}-b-{short}");
    let veth_a = format!("svqa-{short}");
    let veth_b = format!("svqb-{short}");
    let table = format!("synvoid_q_{}", short.replace('-', "_"));
    let setup = vec![
        format!("ip netns add {ns_a}"),
        format!("ip netns add {ns_b}"),
        format!("ip link add {veth_a} type veth peer name {veth_b}"),
        format!("ip link set {veth_a} netns {ns_a}"),
        format!("ip link set {veth_b} netns {ns_b}"),
        format!("ip netns exec {ns_a} ip link set lo up"),
        format!("ip netns exec {ns_b} ip link set lo up"),
        format!("ip netns exec {ns_a} ip addr add 10.201.0.1/24 dev {veth_a}"),
        format!("ip netns exec {ns_a} ip addr add fd00:db8:91::1/64 dev {veth_a}"),
        format!("ip netns exec {ns_a} ip link set {veth_a} up"),
        format!("ip netns exec {ns_b} ip addr add 10.201.0.2/24 dev {veth_b}"),
        format!("ip netns exec {ns_b} ip addr add fd00:db8:91::2/64 dev {veth_b}"),
        format!("ip netns exec {ns_b} ip link set {veth_b} up"),
        format!("# prove isolation: readlink /proc/self/ns/net != ip netns exec {ns_a} readlink /proc/self/ns/net"),
        format!("# enter target ns (setns); crate nft ops land in {ns_a}"),
        format!("# matrix: install/readback, type-code, exemptions, rate-limit, update, drift, disable, rollback (owned table {table})"),
        format!("# evidence: target/icmp-qualify-{run_id}.json"),
        format!("ip link del {veth_a}"),
        format!("ip netns del {ns_a}"),
        format!("ip netns del {ns_b}"),
    ];
    let detail = format!(
        "dry-run plan (zero mutation; nothing spawned):\n{}",
        setup.join("\n")
    );
    emit(opts.json, run_id, "dry-run", true, &detail, None);
    Ok(())
}

fn short_suffix(run_id: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in run_id.bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:012x}")[..6].to_string()
}

fn run_native(opts: &Options, run_id: &str) -> Result<(), String> {
    // Gate 1: explicit --native flag is present (dispatch guarantees it).
    // Gate 2: environment opt-in.
    let pre = Preflight::collect();
    let (ready, lines) = pre.verdict();
    if !ready {
        let detail = lines.join("\n");
        emit(
            opts.json,
            run_id,
            "native",
            false,
            &format!("NOT QUALIFIED\n{detail}"),
            None,
        );
        return Err("preflight refused: host not qualified for native run".to_string());
    }
    let out_path = opts
        .out
        .clone()
        .unwrap_or_else(|| format!("target/icmp-qualify-{run_id}.json"));
    if let Some(parent) = std::path::Path::new(&out_path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("out dir: {e}"))?;
        }
    }
    let timeout = Duration::from_secs(opts.timeout_secs.max(60));
    // Shell the ignored crate matrix with gates passed through.
    let mut child = Command::new("cargo")
        .args([
            "test",
            "-p",
            "synvoid-icmp-filter",
            "--test",
            "nft_native_qualification",
            "--profile",
            "ci",
            "--",
            "--ignored",
            "--nocapture",
        ])
        .env(OPT_IN_ENV, "1")
        .env(RUN_ENV, run_id)
        .env(OUT_ENV, &out_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn native matrix: {e}"))?;
    // Bounded wait: kill on expiry (guaranteed cleanup attempt lives in the
    // crate harness Drop + ledger; --cleanup reruns deterministically).
    let status = wait_timeout(&mut child, timeout).ok_or_else(|| {
        let _ = child.kill();
        format!("native matrix exceeded timeout of {}s", timeout.as_secs())
    })?;
    let output = child
        .wait_with_output()
        .map_err(|e| format!("collect native output: {e}"))?;
    let _ = status;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    // Evidence is authoritative for the disposition.
    let evidence_text = std::fs::read_to_string(&out_path)
        .map_err(|e| format!("evidence {out_path}: {e}\n{stderr}"))?;
    let evidence: serde_json::Value =
        serde_json::from_str(&evidence_text).map_err(|e| format!("evidence parse: {e}"))?;
    let disposition = evidence
        .get("disposition")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let qualified = disposition.starts_with("qualified:");
    let detail = format!("disposition: {disposition}\nevidence: {out_path}\n{stdout}\n{stderr}");
    emit(
        opts.json,
        run_id,
        "native",
        qualified,
        &detail,
        Some(evidence),
    );
    if qualified {
        Ok(())
    } else {
        Err(format!("NOT QUALIFIED: {disposition}"))
    }
}

/// Wait with timeout using only std (no extra deps): poll `try_wait` until
/// exit or expiry. Returns None on expiry (caller kills the child).
fn wait_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Option<std::process::ExitStatus> {
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {
                if start.elapsed() >= timeout {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(_) => return None,
        }
    }
}

fn run_cleanup(opts: &Options, run_id: &str) -> Result<(), String> {
    // Idempotent, prefix-scoped, rerunnable after interruption.
    let list = Command::new("ip")
        .args(["netns", "list"])
        .output()
        .map_err(|e| format!("ip netns list: {e}"))?;
    if !list.status.success() {
        return Err(format!(
            "ip netns list failed: {}",
            String::from_utf8_lossy(&list.stderr)
        ));
    }
    let mut removed = Vec::new();
    let mut errors = Vec::new();
    for line in String::from_utf8_lossy(&list.stdout).lines() {
        let name = line.split_whitespace().next().unwrap_or("");
        // Prefix-scoped and shape-validated: never touch non-harness
        // namespaces, even when privileged.
        if !name.starts_with(RESOURCE_PREFIX) {
            continue;
        }
        {
            let rest = &name[RESOURCE_PREFIX.len()..];
            if rest.is_empty()
                || !rest
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                continue;
            }
        }
        match Command::new("ip").args(["netns", "del", name]).output() {
            Ok(o) if o.status.success() => removed.push(name.to_string()),
            Ok(o) => {
                let err = String::from_utf8_lossy(&o.stderr).to_string();
                if err.contains("No such file") {
                    removed.push(format!("{name} (already absent)"));
                } else {
                    errors.push(format!("{name}: {err}"));
                }
            }
            Err(e) => errors.push(format!("{name}: {e}")),
        }
    }
    let detail = format!(
        "cleanup: removed [{}]{}",
        removed.join(", "),
        if errors.is_empty() {
            String::new()
        } else {
            format!(" errors [{}]", errors.join("; "))
        }
    );
    let ok = errors.is_empty();
    emit(opts.json, run_id, "cleanup", ok, &detail, None);
    if ok {
        Ok(())
    } else {
        Err(detail)
    }
}

pub fn run_icmp_qualify(raw_args: &[String], json_output: bool) -> Result<(), String> {
    let mut opts = Options::from_args(raw_args);
    if json_output {
        opts.json = true;
    }
    let run_id = match std::env::var(RUN_ENV) {
        Ok(v) if validate_run_id(&v).is_ok() => v,
        _ => generate_run_id(1),
    };
    if !(opts.check || opts.dry_run || opts.native || opts.cleanup) {
        return Err("usage: cargo xtask icmp-qualify (--check | --dry-run | --native | --cleanup) [--json] [--timeout-secs N] [--out PATH]".to_string());
    }
    if opts.native {
        // --native requires the environment opt-in as a second gate; the
        // crate matrix enforces the same pair independently.
        if std::env::var(OPT_IN_ENV).as_deref() != Ok("1") {
            return Err(format!(
                "refusing native run: set {OPT_IN_ENV}=1 in addition to --native"
            ));
        }
    }
    let mut first_err: Option<String> = None;
    for (selected, run) in [
        (
            opts.check,
            run_check as fn(&Options, &str) -> Result<(), String>,
        ),
        (opts.dry_run, run_dry_run),
        (opts.native, run_native),
        (opts.cleanup, run_cleanup),
    ] {
        if selected {
            if let Err(e) = run(&opts, &run_id) {
                first_err = first_err.or(Some(e));
            }
        }
    }
    first_err.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_ids_validate_and_differ() {
        let a = generate_run_id(1);
        let b = generate_run_id(2);
        assert_ne!(a, b);
        assert!(validate_run_id(&a).is_ok());
        assert!(validate_run_id("").is_err());
        assert!(validate_run_id("../escape").is_err());
        assert!(validate_run_id("has space").is_err());
        assert!(validate_run_id(&"x".repeat(41)).is_err());
    }

    #[test]
    fn options_parse_modes() {
        let args = vec![
            "--native".to_string(),
            "--timeout-secs".to_string(),
            "120".to_string(),
        ];
        let opts = Options::from_args(&args);
        assert!(opts.native);
        assert!(!opts.check);
        assert_eq!(opts.timeout_secs, 120);
        let dflt = Options::from_args(&[]);
        assert_eq!(dflt.timeout_secs, 900);
    }

    #[test]
    fn preflight_fixture_matrix() {
        let refused = Preflight {
            platform: "linux".to_string(),
            opt_in: false,
            euid: 0,
            cap_net_admin: true,
            ip_present: true,
            nft_present: true,
            ping_present: true,
        };
        let (ready, lines) = refused.verdict();
        assert!(!ready);
        assert!(lines
            .iter()
            .any(|l| l.contains("SYNVOID_ICMP_QUALIFY_NATIVE")));

        let ready_pf = Preflight {
            platform: "linux".to_string(),
            opt_in: true,
            euid: 0,
            cap_net_admin: true,
            ip_present: true,
            nft_present: true,
            ping_present: true,
        };
        let (ready, _) = ready_pf.verdict();
        assert!(ready);

        let mac = Preflight {
            platform: "darwin".to_string(),
            opt_in: true,
            euid: 0,
            cap_net_admin: true,
            ip_present: true,
            nft_present: true,
            ping_present: true,
        };
        assert!(!mac.verdict().0);

        let unpriv = Preflight {
            platform: "linux".to_string(),
            opt_in: true,
            euid: 1000,
            cap_net_admin: false,
            ip_present: true,
            nft_present: true,
            ping_present: true,
        };
        assert!(!unpriv.verdict().0);
    }

    #[test]
    fn dry_run_names_share_crate_scheme() {
        // The xtask dry-run printer mirrors the crate harness naming
        // (prefix + side + 6-hex suffix; owned table identifier form).
        let short = short_suffix("1700000000-42-1");
        assert_eq!(short.len(), 6);
        assert!(short.chars().all(|c| c.is_ascii_hexdigit()));
        let ns = format!("{RESOURCE_PREFIX}-a-{short}");
        assert!(ns.starts_with(RESOURCE_PREFIX));
        let table = format!("synvoid_q_{short}");
        assert!(table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
    }
}
