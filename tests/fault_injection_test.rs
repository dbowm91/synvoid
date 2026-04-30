#[cfg(unix)]
mod tests {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_worker_crash_recovery() {
        // This test requires a built binary.
        // We'll skip it if not running in a CI-like environment with the binary available.
        let binary_path = "./target/debug/maluwaf";
        if !std::path::Path::new(binary_path).exists() {
            tracing::warn!(
                "Skipping test_worker_crash_recovery: binary not found at {}",
                binary_path
            );
            return;
        }

        // 1. Spawn Overseer in background
        let mut overseer = Command::new(binary_path)
            .arg("--foreground")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to spawn overseer");

        // Wait for workers to be ready
        sleep(Duration::from_secs(5)).await;

        // 2. Find a worker PID
        // In a real test we'd use IPC or status command, but here we'll grep
        let output = Command::new("pgrep")
            .arg("-f")
            .arg("maluwaf.*--unified-server-worker")
            .output()
            .expect("Failed to run pgrep");

        let pids = String::from_utf8_lossy(&output.stdout);
        let worker_pid = pids.lines().next().and_then(|l| l.parse::<i32>().ok());

        assert!(worker_pid.is_some(), "No worker process found");
        let worker_pid = worker_pid.unwrap();

        // 3. Kill the worker
        tracing::info!("Killing worker PID: {}", worker_pid);
        Command::new("kill")
            .arg("-9")
            .arg(worker_pid.to_string())
            .status()
            .expect("Failed to kill worker");

        // 4. Verify recovery
        let mut recovered = false;
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(15) {
            let output = Command::new("pgrep")
                .arg("-f")
                .arg("maluwaf.*--unified-server-worker")
                .output()
                .expect("Failed to run pgrep");

            let new_pids = String::from_utf8_lossy(&output.stdout);
            if !new_pids.is_empty() && !new_pids.contains(&worker_pid.to_string()) {
                recovered = true;
                break;
            }
            sleep(Duration::from_secs(1)).await;
        }

        assert!(recovered, "Worker did not recover within 15 seconds");

        // Cleanup
        let _ = overseer.kill();
    }
}
