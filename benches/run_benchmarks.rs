use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

fn timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    format!("{}.{:09}", now.as_secs(), now.subsec_nanos())
}

fn get_git_revision() -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn parse_ns_from_line(line: &str) -> Option<u64> {
    if let Some(pos) = line.find("time:") {
        let rest = &line[pos + 5..];
        let rest = rest.trim();
        if rest.ends_with("ns") {
            rest[..rest.len() - 2].parse().ok()
        } else if rest.ends_with("µs") || rest.ends_with("us") {
            let val: f64 = rest[..rest.len() - 2].parse().ok()?;
            Some((val * 1000.0) as u64)
        } else if rest.ends_with("ms") {
            let val: f64 = rest[..rest.len() - 2].parse().ok()?;
            Some((val * 1_000_000.0) as u64)
        } else if rest.ends_with("s") {
            let val: f64 = rest[..rest.len() - 1].parse().ok()?;
            Some((val * 1_000_000_000.0) as u64)
        } else {
            rest.parse().ok()
        }
    } else {
        None
    }
}

struct BenchmarkResult {
    name: String,
    ns_per_op: u64,
    threshold_ns: u64,
    passed: bool,
    error: Option<String>,
}

fn run_benchmark(name: &str, threshold_ns: u64) -> BenchmarkResult {
    print!("  Running (threshold: {}ns)... ", threshold_ns);
    std::io::stdout().flush().ok();

    let output = Command::new("cargo")
        .args([
            "bench",
            "--bench",
            name,
            "--",
            "--warm-up-time=0",
            "--sample-size=10",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    match output {
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            let combined = format!("{}\n{}", stdout, stderr);

            let mut min_ns = u64::MAX;
            for line in combined.lines() {
                if let Some(ns) = parse_ns_from_line(line) {
                    if ns < min_ns {
                        min_ns = ns;
                    }
                }
            }

            if min_ns != u64::MAX {
                let passed = min_ns <= threshold_ns;
                println!(
                    "{} ns/op [{}]",
                    min_ns,
                    if passed { "PASS" } else { "FAIL" }
                );
                return BenchmarkResult {
                    name: name.to_string(),
                    ns_per_op: min_ns,
                    threshold_ns,
                    passed,
                    error: None,
                };
            }

            if stderr.contains("does not exist") || stderr.contains("no bench target") {
                println!("SKIP (benchmark not found)");
                return BenchmarkResult {
                    name: name.to_string(),
                    ns_per_op: 0,
                    threshold_ns,
                    passed: true,
                    error: Some("not found".to_string()),
                };
            }

            println!("FAILED TO PARSE");
            return BenchmarkResult {
                name: name.to_string(),
                ns_per_op: u64::MAX,
                threshold_ns,
                passed: false,
                error: Some("parse error".to_string()),
            };
        }
        Err(e) => {
            println!("ERROR - {}", e);
            return BenchmarkResult {
                name: name.to_string(),
                ns_per_op: u64::MAX,
                threshold_ns,
                passed: false,
                error: Some(e.to_string()),
            };
        }
    }
}

fn main() {
    println!("\n========================================");
    println!("SynVoid Benchmark Runner v1.0");
    println!("========================================\n");

    let revision = get_git_revision();
    println!("Git revision: {}", revision);
    println!("Timestamp: {}\n", timestamp());

    let benchmarks: Vec<(&str, u64)> = vec![
        ("bench_routing", 1_000_000),
        ("bench_proxy_headers", 500_000),
        ("bench_normalization", 200_000),
        ("bench_attack_detection", 1_000_000),
        ("bench_ratelimit", 200_000),
    ];

    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;

    println!("Running {} benchmarks...\n", benchmarks.len());

    for (name, threshold) in &benchmarks {
        print!("{}: ", name);
        std::io::stdout().flush().ok();
        let result = run_benchmark(name, *threshold);

        if result
            .error
            .as_ref()
            .map(|e| e == "not found")
            .unwrap_or(false)
        {
            skipped += 1;
        } else if result.passed {
            passed += 1;
        } else {
            failed += 1;
        }
    }

    println!("\n========================================");
    println!(
        "Results: {} passed, {} failed, {} skipped",
        passed, failed, skipped
    );
    println!("========================================\n");

    println!("--- JSON Output ---\n");
    println!("{{");
    println!("  \"timestamp\": \"{}\",", timestamp());
    println!("  \"revision\": \"{}\",", revision);
    println!(
        "  \"summary\": {{ \"passed\": {}, \"failed\": {}, \"skipped\": {} }},",
        passed, failed, skipped
    );
    println!("  \"benchmarks\": [");
    for (i, (name, threshold)) in benchmarks.iter().enumerate() {
        let result = run_benchmark(name, *threshold);
        let error_str = result
            .error
            .as_ref()
            .map(|e| format!("\"{}\"", e))
            .unwrap_or_else(|| "null".to_string());
        println!(
            "    {{ \"name\": \"{}\", \"ns_per_op\": {}, \"passed\": {}, \"error\": {} }}",
            name, result.ns_per_op, result.passed, error_str
        );
    }
    println!("  ]");
    println!("}}");

    std::process::exit(if failed > 0 { 1 } else { 0 });
}
