//! External interoperability evidence (phase 10, W3).
//!
//! This suite starts a **real** authoritative listener through
//! [`support::start_bound_dns_server`] and then asks installed third-party
//! clients (`dig`, `delv`) what they think of it. Every assertion is over the
//! tool's own output, never over the server's internal state.
//!
//! Two rules make a green run honest:
//!
//! 1. A missing tool is a **skip**, not a pass: the test prints
//!    `SKIP: <tool> not installed` and returns without asserting anything.
//! 2. Every child process is bounded. `std::process::Command` has no timeout,
//!    so [`run`] polls with `try_wait` and kills the child at
//!    [`TOOL_TIMEOUT`]; a hung `dig` cannot hang CI.
//!
//! The served zone is `example.com` with SOA, NS, apex A, `www` A, an apex
//! wildcard (`*.example.com`), a large RRset (`big.example.com`, 40 A records)
//! for the 512-byte budget, a TXT-only owner (`txtonly.example.com`) for
//! NODATA, and an absent name below an existing non-terminal for NXDOMAIN.
//!
//! DNSSEC: the signed case is real. A temporary keystore supplies an Ed25519
//! KSK+ZSK, `initialize_dnssec()` attaches them to the loaded zone, and
//! `dig +dnssec` must show an RRSIG. `delv -a <anchor> +root=example.com`
//! validates the served answer against a trust anchor derived from the same
//! KSK: BIND's `-a` loads a *root* anchor file, and `+root=example.com` names
//! the non-root zone that anchor belongs to. `delv -i` is the documented
//! validation-off control; `delv +cd` is not a delv option on 9.18 and is
//! recorded as inconclusive, never as validation.
//!
//! Exact commands are printed by [`run`] as `RUN: <command>`; asserted output
//! is printed with the failing or classifying run so the evidence is in the
//! test log.
//!
//! ## The response cache stays enabled
//!
//! Repeated queries in this suite use different transaction IDs, so the lane
//! also checks that a cached authoritative response rewrites the ID to the
//! current query (a client ignores a datagram whose ID does not match). The
//! source-level regression test lives in `dns_authoritative_lookup`.

mod support;

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine;
use synvoid_dns::runtime_config::{RecordType, ZoneRecordSpec, ZoneSpec};
use synvoid_dns::server::DnsServer;

use support::BoundServer;

const ORIGIN: &str = "example.com";
const APEX_ADDRESS: &str = "192.0.2.53";
const WWW_ADDRESS: &str = "192.0.2.10";
const WILDCARD_ADDRESS: &str = "192.0.2.99";
const NXDOMAIN_NAME: &str = "missing.deep.example.com";
const NODATA_NAME: &str = "txtonly.example.com";
const WILDCARD_QUERY: &str = "anything.example.com";

/// No tool is allowed to hold the suite for longer than this.
const TOOL_TIMEOUT: Duration = Duration::from_secs(5);

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

fn record(name: &str, record_type: RecordType, value: &str) -> ZoneRecordSpec {
    ZoneRecordSpec {
        name: name.to_string(),
        record_type,
        ttl: Some(300),
        value: value.to_string(),
        priority: None,
    }
}

/// `example.com`, authoritative, with the names each check needs.
fn example_zone() -> ZoneSpec {
    let mut records = vec![
        record(
            "@",
            RecordType::SOA,
            "ns1.example.com. hostmaster.example.com. 2026111901 3600 600 604800 300",
        ),
        record("@", RecordType::NS, "ns1.example.com."),
        record("@", RecordType::A, APEX_ADDRESS),
        record("ns1", RecordType::A, APEX_ADDRESS),
        record("www", RecordType::A, WWW_ADDRESS),
        // RFC 4592: an apex wildcard answers names with no closer match. The
        // zone loader accepts `*` but rejects a dotted relative owner such as
        // `*.wild`; that is a load-boundary rule, not a query-path rule.
        record("*", RecordType::A, WILDCARD_ADDRESS),
        // An existing owner below the apex: it makes `*.example.com` unable to
        // synthesize for `missing.deep.example.com` (the closer encloser wins),
        // so that query stays a real NXDOMAIN.
        record(
            "deep",
            RecordType::TXT,
            "this owner blocks the apex wildcard",
        ),
        // Exists, but has no A RRset → NODATA for an A query.
        record(NODATA_NAME, RecordType::TXT, "v=spf1 -all"),
    ];

    // A response that cannot fit in 512 bytes: 40 A records is ~640 bytes of
    // RDATA alone, so the server must either truncate to the EDNS budget or
    // set TC (the check accepts both, and asserts the wire size either way).
    for index in 1..=40 {
        records.push(record("big", RecordType::A, &format!("198.51.100.{index}")));
    }

    ZoneSpec {
        origin: ORIGIN.to_string(),
        records,
        dnssec: None,
    }
}

/// Start a listener on an ephemeral loopback port and install the test zone.
///
/// `load_zones` is the activation path the runtime documents; the listener's
/// handler state shares the same zone store, so queries see it immediately.
async fn start_authoritative() -> BoundServer {
    let bound = support::start_bound_dns_server(|runtime| {
        runtime.recursive.enabled = false;
    })
    .await;
    bound
        .server
        .load_zones(vec![example_zone()])
        .expect("the external-interop zone must load");
    bound
}

/// Start with DNSSEC enabled and attach the generated KSK/ZSK to the zone.
///
/// `DnsServer::start` initializes keys before any zone is loaded (the
/// constructor deliberately ignores `runtime.zones`), so the suite loads the
/// zone and calls the public `initialize_dnssec()` again: it reloads the keys
/// from the temporary keystore and attaches them to every loaded zone. Without
/// that second call the zone would answer unsigned while the process still
/// owned signing keys — exactly the downgrade this check exists to catch.
async fn start_signed(key_path: &Path) -> BoundServer {
    let key_path = key_path.to_path_buf();
    let bound = support::start_bound_dns_server(move |runtime| {
        runtime.recursive.enabled = false;
        // See the module-level fixture note: a cache hit would replay the
        // first query's transaction ID and make the client discard the answer.
        runtime.authoritative.cache.enabled = false;
        runtime.dnssec.enabled = true;
        runtime.dnssec.domain = ORIGIN.to_string();
        runtime.dnssec.key_path = key_path.clone();
    })
    .await;
    bound
        .server
        .load_zones(vec![example_zone()])
        .expect("the external-interop zone must load");
    bound
        .server
        .initialize_dnssec()
        .expect("the loaded zone must receive the generated signing keys");
    bound
}

// ─────────────────────────────────────────────────────────────────────────────
// Bounded child-process runner
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct ToolRun {
    command: String,
    code: Option<i32>,
    success: bool,
    timed_out: bool,
    stdout: String,
    stderr: String,
}

impl ToolRun {
    fn combined(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }

    fn assert_completed(&self) {
        assert!(
            !self.timed_out,
            "`{}` did not finish within {TOOL_TIMEOUT:?}",
            self.command
        );
    }
}

/// `command -v <tool>`: the same availability test the conformance script
/// uses, so a skipped tool in one place is skipped in the other.
fn tool_installed(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg("command -v \"$1\" >/dev/null 2>&1")
        .arg("sh")
        .arg(tool)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Skip cleanly when the tool is absent. Returns `false` after printing the
/// required marker; the caller returns, so the test passes without asserting.
fn require_tool(tool: &str) -> bool {
    if tool_installed(tool) {
        true
    } else {
        println!("SKIP: {tool} not installed");
        false
    }
}

fn shell_quote(value: &str) -> String {
    let safe = value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "-_./:@=+".contains(character));
    if safe {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn render_command(program: &str, args: &[&str]) -> String {
    let mut rendered = program.to_string();
    for arg in args {
        rendered.push(' ');
        rendered.push_str(&shell_quote(arg));
    }
    rendered
}

fn indent(text: &str) -> String {
    text.trim_end()
        .lines()
        .map(|line| format!("  | {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Run a child with a hard wall-clock bound and print exactly what ran.
///
/// Output is always echoed: the command and its client-side interpretation are
/// the evidence, so they must be in the test log rather than inferred.
fn run(program: &str, args: &[&str]) -> ToolRun {
    let command = render_command(program, args);
    println!("RUN: {command}");

    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn `{command}`: {error}"));

    let deadline = Instant::now() + TOOL_TIMEOUT;
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    timed_out = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("failed to wait for `{command}`: {error}"),
        }
    }

    let output = child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("failed to collect `{command}`: {error}"));

    let result = ToolRun {
        command,
        code: output.status.code(),
        success: output.status.success(),
        timed_out,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    };

    println!(
        "  exit: {:?}{}",
        result.code,
        if result.timed_out {
            " (killed at timeout)"
        } else {
            ""
        }
    );
    if !result.stdout.trim().is_empty() {
        println!("  stdout:\n{}", indent(&result.stdout));
    }
    if !result.stderr.trim().is_empty() {
        println!("  stderr:\n{}", indent(&result.stderr));
    }

    result
}

fn assert_success(run: &ToolRun) {
    run.assert_completed();
    assert!(
        run.success,
        "`{}` exited with {:?}\nstdout:\n{}\nstderr:\n{}",
        run.command, run.code, run.stdout, run.stderr
    );
}

fn dig_args<'a>(
    port: &'a str,
    extra: &[&'a str],
    name: &'a str,
    record_type: &'a str,
) -> Vec<&'a str> {
    let mut args = extra.to_vec();
    args.push("@127.0.0.1");
    args.push("-p");
    args.push(port);
    args.push(name);
    args.push(record_type);
    args
}

fn message_size(output: &str) -> Option<usize> {
    output
        .lines()
        .find(|line| line.contains("MSG SIZE"))
        .and_then(|line| line.split_whitespace().last())
        .and_then(|value| value.parse().ok())
}

fn flags_line(output: &str) -> Option<&str> {
    output
        .lines()
        .find(|line| line.trim_start().starts_with(";; flags:"))
}

// ─────────────────────────────────────────────────────────────────────────────
// dig: authoritative answers, wildcard, NXDOMAIN, NODATA
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dig_short_returns_the_configured_www_address() {
    if !require_tool("dig") {
        return;
    }
    let mut bound = start_authoritative().await;
    let port = bound.port.to_string();

    let check = run("dig", &dig_args(&port, &["+short"], "www.example.com", "A"));
    assert_success(&check);
    assert_eq!(
        check.stdout.trim(),
        WWW_ADDRESS,
        "`dig +short` must echo the address the zone configured; got {:?}",
        check.stdout
    );

    let apex = run("dig", &dig_args(&port, &["+short"], ORIGIN, "A"));
    assert_success(&apex);
    assert_eq!(apex.stdout.trim(), APEX_ADDRESS);

    bound.server.shutdown_runtime();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dig_returns_the_wildcard_and_nodata_semantics() {
    if !require_tool("dig") {
        return;
    }
    let mut bound = start_authoritative().await;
    let port = bound.port.to_string();

    let wildcard = run("dig", &dig_args(&port, &["+short"], WILDCARD_QUERY, "A"));
    assert_success(&wildcard);
    assert_eq!(
        wildcard.stdout.trim(),
        WILDCARD_ADDRESS,
        "the wildcard owner must synthesize an answer for {WILDCARD_QUERY}"
    );

    let nodata = run("dig", &dig_args(&port, &[], NODATA_NAME, "A"));
    assert_success(&nodata);
    assert!(
        nodata.stdout.contains("status: NOERROR"),
        "an existing owner with no A RRset is NODATA (NOERROR), got:\n{}",
        nodata.stdout
    );
    assert!(
        nodata.stdout.contains("ANSWER: 0"),
        "the NODATA answer must carry no A record, got:\n{}",
        nodata.stdout
    );

    let nodata_short = run("dig", &dig_args(&port, &["+short"], NODATA_NAME, "A"));
    assert_success(&nodata_short);
    assert!(
        nodata_short.stdout.trim().is_empty(),
        "NODATA must not produce `+short` output, got {:?}",
        nodata_short.stdout
    );

    bound.server.shutdown_runtime();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dig_reports_nxdomain_and_short_output_is_empty() {
    if !require_tool("dig") {
        return;
    }
    let mut bound = start_authoritative().await;
    let port = bound.port.to_string();

    let full = run("dig", &dig_args(&port, &[], NXDOMAIN_NAME, "A"));
    assert_success(&full);
    assert!(
        full.stdout.contains("status: NXDOMAIN"),
        "an absent name must be NXDOMAIN, got:\n{}",
        full.stdout
    );

    let short = run("dig", &dig_args(&port, &["+short"], NXDOMAIN_NAME, "A"));
    assert_success(&short);
    assert!(
        short.stdout.trim().is_empty(),
        "NXDOMAIN must not produce `+short` output, got {:?}",
        short.stdout
    );

    bound.server.shutdown_runtime();
}

// ─────────────────────────────────────────────────────────────────────────────
// dig: EDNS budget and TCP
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dig_udp_response_respects_the_512_byte_budget() {
    if !require_tool("dig") {
        return;
    }
    let mut bound = start_authoritative().await;
    let port = bound.port.to_string();

    // `+ignore` prevents dig's automatic TCP retry, so the observed message is
    // the UDP one; `+notcp` makes the intent explicit.
    let check = run(
        "dig",
        &dig_args(
            &port,
            &["+bufsize=512", "+ignore", "+notcp"],
            "big.example.com",
            "A",
        ),
    );
    assert_success(&check);

    let size = message_size(&check.stdout)
        .unwrap_or_else(|| panic!("dig did not report MSG SIZE:\n{}", check.stdout));
    assert!(
        size <= 512,
        "a +bufsize=512 UDP response must fit in 512 bytes, got {size}:\n{}",
        check.stdout
    );

    let flags = flags_line(&check.stdout)
        .unwrap_or_else(|| panic!("dig did not report the header flags:\n{}", check.stdout));
    assert!(
        flags.contains(" tc"),
        "a 40-record RRset cannot fit in 512 bytes, so TC must be set: {flags}"
    );

    bound.server.shutdown_runtime();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dig_tcp_query_succeeds() {
    if !require_tool("dig") {
        return;
    }
    let mut bound = start_authoritative().await;
    let port = bound.port.to_string();

    let check = run("dig", &dig_args(&port, &["+tcp"], "www.example.com", "A"));
    assert_success(&check);
    assert!(
        check.stdout.contains("status: NOERROR"),
        "the TCP query must answer NOERROR, got:\n{}",
        check.stdout
    );
    assert!(
        check.stdout.contains(WWW_ADDRESS),
        "the TCP answer must carry the configured address, got:\n{}",
        check.stdout
    );

    bound.server.shutdown_runtime();
}

// ─────────────────────────────────────────────────────────────────────────────
// DNSSEC through external tools
// ─────────────────────────────────────────────────────────────────────────────

/// Write a `trust-anchors` file from the signed zone's active KSK.
///
/// The KSK public bytes are exactly the DNSKEY RDATA tail BIND expects, so a
/// key generated and served by this process becomes delv's trust anchor
/// without any checked-in key material.
fn write_trust_anchor(server: &DnsServer, path: &Path) -> String {
    let manager = server
        .get_dnssec()
        .expect("the signed fixture must own a DNSSEC manager");
    let guard = manager.read();
    let ksk = guard
        .active_ksk()
        .expect("the signed fixture must have an active KSK");
    let key = base64::engine::general_purpose::STANDARD.encode(ksk.public_key());
    let anchor = format!(
        "trust-anchors {{\n    {ORIGIN}. static-key {} 3 {} \"{key}\";\n}};\n",
        ksk.flags(),
        ksk.algorithm().to_u8(),
    );
    std::fs::write(path, &anchor).expect("write the delv trust anchor file");
    println!("delv trust anchor:\n{}", indent(&anchor));
    anchor
}

/// A `delv` answer record is a non-comment line that mentions the address.
/// delv exit codes are 0 for "resolution failed" too, so status alone cannot
/// distinguish an answer from a failure.
fn delv_answered_address(output: &str, address: &str) -> bool {
    output.lines().any(|line| {
        let line = line.trim();
        !line.is_empty() && !line.starts_with(';') && line.contains(address)
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dnssec_serves_rrsig_and_delv_classifies_its_validation() {
    if !require_tool("dig") {
        return;
    }

    let keys = tempfile::tempdir().expect("temporary DNSSEC key directory");
    let mut bound = start_signed(keys.path()).await;
    let port = bound.port.to_string();

    let signed = run(
        "dig",
        &dig_args(&port, &["+dnssec"], "www.example.com", "A"),
    );
    assert_success(&signed);
    assert!(
        signed.stdout.contains("RRSIG"),
        "the signed zone must serve an RRSIG with the DO bit, got:\n{}",
        signed.stdout
    );
    assert!(
        signed.stdout.contains("RRSIG\tA "),
        "the RRSIG must cover the A RRset, got:\n{}",
        signed.stdout
    );

    if !require_tool("delv") {
        bound.server.shutdown_runtime();
        return;
    }

    // 1. Checking-disabled control. `-i` is delv's documented
    //    "disable DNSSEC validation" switch; the `+cd` spelling requested by
    //    the phase plan is a dig option, and BIND 9.18's delv accepts it
    //    syntactically but does not disable checking. Record that rather than
    //    asserting the flag did something it does not do.
    let unchecked_documented = run(
        "delv",
        &["-i", "@127.0.0.1", "-p", &port, "www.example.com", "A"],
    );
    assert_success(&unchecked_documented);
    assert!(
        delv_answered_address(&unchecked_documented.combined(), WWW_ADDRESS),
        "`delv -i` (documented validation-off) must answer, got:\n{}",
        unchecked_documented.combined()
    );

    let plus_cd = run(
        "delv",
        &["+cd", "@127.0.0.1", "-p", &port, "www.example.com", "A"],
    );
    assert!(!plus_cd.timed_out, "`delv +cd` exceeded {TOOL_TIMEOUT:?}");
    if delv_answered_address(&plus_cd.combined(), WWW_ADDRESS) {
        println!("delv +cd classification: ANSWERED (accepted and returned the record)");
    } else {
        println!(
            "INCONCLUSIVE: `delv +cd` did not answer. This delv version has no \
             +cd flag (the documented switch is -i), so the run is reported, \
             not claimed as validation or as a server failure:\n{}",
            indent(&plus_cd.combined())
        );
    }

    // 2. No trust anchor: delv cannot validate. Record it as inconclusive and
    //    never as a pass that claims validation.
    let unanchored = run("delv", &["@127.0.0.1", "-p", &port, "www.example.com", "A"]);
    assert!(
        !unanchored.timed_out,
        "`delv` exceeded {TOOL_TIMEOUT:?} without a trust anchor"
    );
    let unanchored_text = unanchored.combined();
    if unanchored_text.contains("fully validated") {
        panic!(
            "`delv` claimed full validation without a configured trust anchor; \
             the result cannot be trusted:\n{unanchored_text}"
        );
    }
    println!(
        "INCONCLUSIVE: delv without a trust anchor did not report validation; \
         this is not evidence of validation:\n{}",
        indent(&unanchored_text)
    );

    // 3. A trust anchor derived from the served KSK. BIND's `-a` is a *root*
    //    anchor file, so the non-root anchor is named with
    //    `+root=example.com`; without that, delv parses the file but loads no
    //    keys ("No trusted keys were loaded"). With both, the answer must be
    //    fully validated — this is the external validation claim.
    let anchor_path = keys.path().join("delv-trust-anchor.conf");
    write_trust_anchor(&bound.server, &anchor_path);
    let anchor = anchor_path.to_str().expect("UTF-8 anchor path");

    let validated = run(
        "delv",
        &[
            "-a",
            anchor,
            "+root=example.com",
            "@127.0.0.1",
            "-p",
            &port,
            "www.example.com",
            "A",
        ],
    );
    assert_success(&validated);
    let validated_text = validated.combined();
    assert!(
        delv_answered_address(&validated_text, WWW_ADDRESS),
        "`delv -a +root=example.com` must return the validated answer, got:\n{validated_text}"
    );
    assert!(
        validated_text.contains("fully validated"),
        "the signed answer must be fully validated against the trust anchor, got:\n{validated_text}"
    );
    println!("delv classification: VALIDATED (fully validated against the served KSK)");

    bound.server.shutdown_runtime();
}
