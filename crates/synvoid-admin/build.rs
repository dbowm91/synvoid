fn main() {
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    println!("cargo:rustc-env=BUILD_TIMESTAMP={}", build_timestamp());
}

fn build_timestamp() -> String {
    let epoch = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .or_else(|| {
            std::process::Command::new("git")
                .args(["show", "-s", "--format=%ct", "HEAD"])
                .output()
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .and_then(|value| value.trim().parse::<i64>().ok())
        })
        .unwrap_or(0);

    chrono::DateTime::<chrono::Utc>::from_timestamp(epoch, 0)
        .map(|timestamp| timestamp.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "1970-01-01 00:00:00".to_string())
}
