//! Root-test ownership: COMPOSITION
//! Rationale: validates fault injection across supervisor, block-store, and plugin crates

#[cfg(unix)]
mod tests {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    use tokio::time::sleep;

    /// RAII guard that ensures a child process is killed and waited on,
    /// even if the test panics.
    struct ProcessGuard {
        child: Option<std::process::Child>,
    }

    impl ProcessGuard {
        fn new(child: std::process::Child) -> Self {
            Self { child: Some(child) }
        }

        fn id(&self) -> Option<u32> {
            self.child.as_ref().map(|c| c.id())
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

    /// Find direct child PIDs of the given parent PID via /proc/<pid>/task/<tid>/children.
    /// Falls back to pgrep if /proc is unavailable.
    fn find_child_pids(parent_pid: u32) -> Vec<u32> {
        // Try /proc first (Linux-specific, deterministic)
        let children_path = format!("/proc/{}/task/{}/children", parent_pid, parent_pid);
        if let Ok(children) = std::fs::read_to_string(&children_path) {
            return children
                .split_whitespace()
                .filter_map(|s| s.parse::<u32>().ok())
                .collect();
        }
        // Fallback: pgrep with exact parent PID matching
        let output = Command::new("pgrep")
            .arg("-P")
            .arg(parent_pid.to_string())
            .output();
        match output {
            Ok(o) => String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter_map(|l| l.parse::<u32>().ok())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Recursively kill a process and all its descendants.
    fn kill_tree(pid: u32) {
        let children = find_child_pids(pid);
        for child_pid in children {
            kill_tree(child_pid);
        }
        let _ = Command::new("kill").arg("-9").arg(pid.to_string()).status();
    }

    #[tokio::test]
    #[ignore = "requires built binary, full supervisor, and ~20s runtime"]
    async fn test_worker_crash_recovery() {
        // Use CARGO_BIN_EXE_synvoid for deterministic binary discovery.
        let binary_path = option_env!("CARGO_BIN_EXE_synvoid").unwrap_or("./target/debug/synvoid");

        if !std::path::Path::new(binary_path).exists() {
            eprintln!(
                "Skipping test_worker_crash_recovery: binary not found at {}. \
                 Build with `cargo build` first.",
                binary_path
            );
            return;
        }

        // 1. Spawn Supervisor in foreground
        let supervisor = ProcessGuard::new(
            Command::new(binary_path)
                .arg("--foreground")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("Failed to spawn supervisor"),
        );

        let supervisor_pid = supervisor.id().expect("supervisor has no PID");

        // Wait for workers to be ready
        sleep(Duration::from_secs(5)).await;

        // 2. Find a worker PID via /proc children (deterministic, no pgrep)
        let mut worker_pid: Option<u32> = None;
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(10) {
            let children = find_child_pids(supervisor_pid);
            // Workers are typically not the first child; look for any child that isn't
            // the immediate shell or helper process.
            if !children.is_empty() {
                worker_pid = children.first().copied();
                break;
            }
            sleep(Duration::from_millis(500)).await;
        }

        assert!(
            worker_pid.is_some(),
            "No worker process found as child of supervisor PID {}",
            supervisor_pid
        );
        let worker_pid = worker_pid.unwrap();

        // 3. Kill the worker (SIGKILL to simulate crash)
        tracing::info!(
            "Killing worker PID {} (supervisor PID: {})",
            worker_pid,
            supervisor_pid
        );
        kill_tree(worker_pid);

        // 4. Verify recovery — supervisor should respawn a new worker
        let mut recovered = false;
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(15) {
            let children = find_child_pids(supervisor_pid);
            // A new worker PID that differs from the killed one indicates recovery
            if children.iter().any(|&pid| pid != worker_pid) {
                recovered = true;
                break;
            }
            sleep(Duration::from_secs(1)).await;
        }

        // Ensure supervisor is cleaned up even if assertion fails
        drop(supervisor);

        assert!(
            recovered,
            "Worker PID {} was not replaced within 15 seconds",
            worker_pid
        );
    }
}
