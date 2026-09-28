//! Root-test ownership: QUALIFICATION
//! Rationale: owner-side live reverse-proxy semantic proof for the
//! Eggbench Security Qualification M002 asset contract
//! (policy `synvoid.eggbench-qualification.v1`). Exercises the exported
//! corpus through the real minimal (`--no-default-features`) SynVoid
//! binary against a controlled loopback origin and proves every case
//! agrees with its generated observable expectation: Pass controls reach
//! the origin (200), Detect cases are blocked (403) and never reach it.
//!
//! Opt-in: `#[ignore]`d and additionally gated on
//! `SYNVOID_EGGBENCH_LIVE_PROOF=1` (binds loopback ports, spawns the
//! supervisor + origin, ~60-120s). Never a routine-CI gate.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const POLICY_ID: &str = "synvoid.eggbench-qualification.v1";
const DRIVER_UA: &str = "synvoid-eggbench-qualification/1.0";
const OPT_IN_ENV: &str = "SYNVOID_EGGBENCH_LIVE_PROOF";

/// RAII child-process guard: kills and reaps on drop, even on panic.
struct ProcessGuard {
    child: Option<Child>,
}

impl ProcessGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
struct CorpusCase {
    id: String,
    #[allow(dead_code)]
    category: String,
    method: String,
    path: String,
    query_string: Option<String>,
    headers: Option<Vec<(String, String)>>,
    body: Option<CorpusBody>,
    expected_status: u16,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(untagged)]
enum CorpusBody {
    Inline {
        inline: String,
    },
    #[allow(dead_code)]
    File {
        file: String,
    },
}

#[derive(Debug, Clone, serde::Deserialize)]
struct Corpus {
    #[allow(dead_code)]
    schema_version: String,
    policy_id: String,
    #[allow(dead_code)]
    policy_version: String,
    listen_port: u16,
    origin_port: u16,
    case_count: usize,
    detect_status: u16,
    pass_status: u16,
    cases: Vec<CorpusCase>,
}

/// Controlled loopback origin state: total hits + per-path log.
#[derive(Debug, Default)]
struct OriginState {
    hits: u64,
    paths: Vec<String>,
}

/// Serve the controlled origin until `shutdown` fires. Records every
/// request; answers 200 with a small body, or a 64 KiB body on the
/// `/qualbench/stream` perf path (Workstream H).
async fn run_origin(
    listener: TcpListener,
    state: Arc<Mutex<OriginState>>,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let Ok((mut stream, _)) = accepted else { break };
                let state = state.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65536];
                    // Best-effort single read: enough to capture the
                    // request line + headers of qualification requests.
                    let Ok(n) = stream.read(&mut buf).await else { return };
                    let head = String::from_utf8_lossy(&buf[..n]);
                    let path = head
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_string();
                    {
                        let mut st = state.lock().unwrap();
                        st.hits += 1;
                        st.paths.push(path.clone());
                    }
                    // Minimal static response; leaks nothing.
                    static CHUNK: [u8; 65536] = [b'x'; 65536];
                    let body: &[u8] = if path == "/qualbench/stream" {
                        &CHUNK
                    } else if path == "/qualbench/small" {
                        b"ok"
                    } else {
                        b"qualbench-ok"
                    };
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(header.as_bytes()).await;
                    let _ = stream.write_all(body).await;
                });
            }
        }
    }
}

/// Pick an unused loopback port (bind :0, read back, release).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("loopback bind for port discovery")
        .local_addr()
        .expect("local addr")
        .port()
}

/// Wait until `127.0.0.1:port` accepts TCP, or time out.
async fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    false
}

/// Drive one corpus case over raw HTTP/1.1 (exact request-target bytes;
/// ASCII SP wire-encoded as %20 per the policy transport rules) and
/// return the observed status code.
async fn drive_case(
    listen_port: u16,
    case: &CorpusCase,
    extra_headers: &[(String, String)],
) -> Result<u16, String> {
    let mut target = case.path.clone();
    if let Some(qs) = &case.query_string {
        target.push('?');
        target.push_str(qs);
    }
    // Transport rule: raw SP is illegal in a request-target.
    let target = target.replace(' ', "%20");

    let body_bytes: Vec<u8> = match &case.body {
        Some(CorpusBody::Inline { inline }) => inline.as_bytes().to_vec(),
        Some(CorpusBody::File { file }) => {
            return Err(format!(
                "case {} uses body file {file}: unsupported",
                case.id
            ))
        }
        None => Vec::new(),
    };

    let mut request = format!(
        "{} {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nUser-Agent: {}\r\nConnection: close\r\n",
        case.method, target, listen_port, DRIVER_UA
    );
    for (name, value) in extra_headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(headers) = &case.headers {
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    if !body_bytes.is_empty() {
        request.push_str(&format!("Content-Length: {}\r\n", body_bytes.len()));
    }
    request.push_str("\r\n");

    let mut stream = TcpStream::connect(("127.0.0.1", listen_port))
        .await
        .map_err(|e| format!("connect failed: {e}"))?;
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write failed: {e}"))?;
    if !body_bytes.is_empty() {
        stream
            .write_all(&body_bytes)
            .await
            .map_err(|e| format!("body write failed: {e}"))?;
    }
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|e| format!("read failed: {e}"))?;
    let head = String::from_utf8_lossy(&response);
    let status_line = head.lines().next().unwrap_or("");
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("unparseable status line: {status_line:?}"))?;
    Ok(code)
}

fn origin_hits(state: &Arc<Mutex<OriginState>>) -> (u64, Vec<String>) {
    let st = state.lock().unwrap();
    (st.hits, st.paths.clone())
}

#[tokio::test]
#[ignore = "live proof: requires built synvoid binary, loopback ports, SYNVOID_EGGBENCH_LIVE_PROOF=1, ~60-120s"]
async fn eggbench_v1_live_semantic_proof() {
    if std::env::var(OPT_IN_ENV).as_deref() != Ok("1") {
        eprintln!("skipping: set {OPT_IN_ENV}=1 to run the live semantic proof");
        return;
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // Binary selection: explicit override wins (used to pin the exact
    // minimal binary by path + digest), then Cargo's built binary, then
    // the conventional debug output. The qualification run MUST resolve
    // to a `--no-default-features` build; the closeout records the exact
    // build command and binary SHA-256 alongside this proof.
    let binary = std::env::var("SYNVOID_EGGBENCH_SYNVOID_BIN")
        .map(PathBuf::from)
        .or_else(|_| {
            option_env!("CARGO_BIN_EXE_synvoid")
                .map(PathBuf::from)
                .ok_or_else(|| "no CARGO_BIN_EXE_synvoid".to_string())
        })
        .unwrap_or_else(|_| manifest_dir.join("target/debug/synvoid"));
    if !binary.exists() {
        eprintln!(
            "skipping: synvoid binary not found at {}; build with `cargo build --locked --no-default-features` first",
            binary.display()
        );
        return;
    }
    eprintln!("live proof binary: {}", binary.display());

    let listen_port = free_port();
    let origin_port = free_port();
    assert_ne!(listen_port, origin_port, "port collision");

    // 1. Controlled loopback origin.
    let origin_listener = TcpListener::bind(("127.0.0.1", origin_port))
        .await
        .expect("origin bind");
    let origin_state = Arc::new(Mutex::new(OriginState::default()));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let origin_task = {
        let state = origin_state.clone();
        tokio::spawn(run_origin(origin_listener, state, shutdown_rx))
    };

    // 2. Materialize the qualification tree via the owner materializer
    // (no duplicated templates: the test consumes `export` output).
    let workdir = std::env::temp_dir().join(format!(
        "synvoid-eggbench-liveproof-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    ));
    let export = Command::new("cargo")
        .args([
            "xtask",
            "eggbench-qualification",
            "export",
            "--output",
            &workdir.to_string_lossy(),
            "--listen-port",
            &listen_port.to_string(),
            "--origin-port",
            &origin_port.to_string(),
        ])
        .current_dir(&manifest_dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .expect("cargo xtask export must spawn");
    assert!(export.success(), "materializer export failed");

    let corpus_text = std::fs::read_to_string(workdir.join("corpus.json")).expect("corpus.json");
    let corpus: Corpus = serde_json::from_str(&corpus_text).expect("corpus parses");
    assert_eq!(corpus.policy_id, POLICY_ID, "policy binding");
    assert_eq!(corpus.listen_port, listen_port, "listen port binding");
    assert_eq!(corpus.origin_port, origin_port, "origin port binding");
    assert_eq!(corpus.cases.len(), corpus.case_count);
    assert!(!corpus.cases.is_empty());

    // 3. Minimal SynVoid binary in the foreground lifecycle. First prove
    // the binary accepts the materialized tree (`--configtest`), then
    // spawn. The guard owns the supervisor Child from spawn to test end
    // (kill + reap on drop, even on assertion failure) so no worker tree
    // can leak.
    let config_dir = workdir.join("config");
    let configtest = Command::new(&binary)
        .arg("--configtest")
        .arg("--config-path")
        .arg(&config_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("configtest must spawn");
    assert!(
        configtest.success(),
        "minimal binary must pass --configtest on the materialized tree"
    );
    let child = Command::new(&binary)
        .arg("--foreground")
        .arg("--config-path")
        .arg(&config_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn synvoid");
    let supervisor = ProcessGuard::new(child);

    assert!(
        wait_for_port(listen_port, Duration::from_secs(60)).await,
        "synvoid did not open the listen port in time"
    );

    // 4. Drive every exported case; prove observable agreement.
    let mut failures: Vec<String> = Vec::new();
    let mut pass_proven = 0usize;
    let mut detect_proven = 0usize;
    for case in &corpus.cases {
        let (hits_before, _) = origin_hits(&origin_state);
        match drive_case(listen_port, case, &[]).await {
            Ok(code) => {
                let (hits_after, _) = origin_hits(&origin_state);
                if code != case.expected_status {
                    failures.push(format!(
                        "{}: status {code} != expected {}",
                        case.id, case.expected_status
                    ));
                    continue;
                }
                if case.expected_status == corpus.pass_status {
                    if hits_after <= hits_before {
                        failures.push(format!(
                            "{}: pass control did not reach the origin",
                            case.id
                        ));
                        continue;
                    }
                    pass_proven += 1;
                } else if case.expected_status == corpus.detect_status {
                    if hits_after != hits_before {
                        failures.push(format!("{}: detect case reached the origin", case.id));
                        continue;
                    }
                    detect_proven += 1;
                } else {
                    failures.push(format!(
                        "{}: unexpected expected_status {}",
                        case.id, case.expected_status
                    ));
                }
            }
            Err(e) => failures.push(format!("{}: drive error: {e}", case.id)),
        }
    }

    // 5. Workstream H: deterministic origin-facing perf paths proxy clean.
    for perf_path in ["/qualbench/small", "/qualbench/stream"] {
        let perf_case = CorpusCase {
            id: format!("perf{perf_path}"),
            category: "perf".to_string(),
            method: "GET".to_string(),
            path: perf_path.to_string(),
            query_string: None,
            headers: None,
            body: None,
            expected_status: corpus.pass_status,
        };
        let (hits_before, _) = origin_hits(&origin_state);
        match drive_case(listen_port, &perf_case, &[]).await {
            Ok(code) => {
                let (hits_after, _) = origin_hits(&origin_state);
                if code != 200 || hits_after <= hits_before {
                    failures.push(format!(
                        "perf path {perf_path}: code={code} origin_delta={}",
                        hits_after.saturating_sub(hits_before)
                    ));
                }
            }
            Err(e) => failures.push(format!("perf path {perf_path}: drive error: {e}")),
        }
    }

    // 6. Cleanup: stop origin, drop supervisor guard (kills tree), scrub dir.
    let _ = shutdown_tx.send(());
    origin_task.abort();
    drop(supervisor);
    // Give workers a moment to exit with the supervisor before port reuse.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let _ = std::fs::remove_dir_all(&workdir);

    assert!(
        pass_proven > 0 && detect_proven > 0,
        "must prove at least one pass and one detect case"
    );
    // Every exported case must agree: no silent subset.
    assert_eq!(
        pass_proven + detect_proven,
        corpus.cases.len(),
        "every exported case must be proven; failures: {failures:?}"
    );
    assert!(
        failures.is_empty(),
        "live semantic mismatches: {failures:?}"
    );

    // Origin-side cross-check: the origin must have seen exactly the
    // pass cases plus the two perf paths — no detect payload path.
    let (_, paths) = origin_hits(&origin_state);
    assert_eq!(
        paths.len() as u64,
        origin_hits(&origin_state).0,
        "origin log consistent"
    );
    let expected_origin_hits = pass_proven + 2; // pass cases + small/stream
    assert_eq!(
        paths.len(),
        expected_origin_hits,
        "origin must see exactly the pass + perf requests, got: {paths:?}"
    );
}
