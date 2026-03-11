use std::sync::Arc;

#[derive(Clone)]
struct BenchmarkConfig {
    enabled: bool,
    max_payload_size: usize,
    normalization_enabled: bool,
    detection_threshold: u32,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_payload_size: 65536,
            normalization_enabled: true,
            detection_threshold: 1,
        }
    }
}

fn create_attack_detection_config() -> BenchmarkConfig {
    BenchmarkConfig::default()
}

fn benchmark_normalizer(input: &str) {
    let _ = input.to_lowercase();
    let _ = urlencoding_decode(input);
}

fn urlencoding_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }
    result
}

fn main() {
    println!("Running attack detection benchmarks...\n");

    let inputs = vec![
        "Hello World",
        "<script>alert('XSS')</script>",
        "1' OR '1'='1",
        "../../../etc/passwd",
        "{{7*7}}",
        "GET /admin HTTP/1.1\r\nHost: example.com\r\n",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
    ];

    println!("=== Normalizer Benchmark ===");
    for input in &inputs {
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            benchmark_normalizer(input);
        }
        let elapsed = start.elapsed();
        println!(
            "  Input len={:3}: {:.3}ms for 1000 iterations",
            input.len(),
            elapsed.as_secs_f64() * 1000.0
        );
    }

    println!("\n=== String Allocation Benchmark ===");
    let large_input = "x".repeat(10000);
    let start = std::time::Instant::now();
    for _ in 0..1000 {
        let _ = large_input.to_lowercase();
    }
    let elapsed = start.elapsed();
    println!(
        "  10KB to_lowercase(): {:.3}ms for 1000 iterations",
        elapsed.as_secs_f64() * 1000.0
    );

    let start = std::time::Instant::now();
    for _ in 0..1000 {
        let _ = large_input.as_bytes().to_vec();
    }
    let elapsed = start.elapsed();
    println!(
        "  10KB to_vec(): {:.3}ms for 1000 iterations",
        elapsed.as_secs_f64() * 1000.0
    );

    println!("\n=== URL Decode Benchmark ===");
    let encoded = "%3Cscript%3Ealert('xss')%3C/script%3E";
    let start = std::time::Instant::now();
    for _ in 0..10000 {
        let _ = urlencoding_decode(encoded);
    }
    let elapsed = start.elapsed();
    println!(
        "  URL decode: {:.3}ms for 10000 iterations",
        elapsed.as_secs_f64() * 1000.0
    );

    println!("\nDone!");
}
