use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::{broadcast, RwLock};
use tokio::time::interval;

use crate::app_server::AppServerConfig;
use crate::RunningFlag;

#[derive(Clone, Debug, Copy, PartialEq, Eq, Default)]
pub enum GranianInterface {
    #[default]
    Asgi,
    AsgiNl,
    Rsgi,
    Wsgi,
}

impl std::fmt::Display for GranianInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GranianInterface::Asgi => write!(f, "asgi"),
            GranianInterface::AsgiNl => write!(f, "asginl"),
            GranianInterface::Rsgi => write!(f, "rsgi"),
            GranianInterface::Wsgi => write!(f, "wsgi"),
        }
    }
}

impl From<&str> for GranianInterface {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "asgi" => GranianInterface::Asgi,
            "asginl" => GranianInterface::AsgiNl,
            "rsgi" => GranianInterface::Rsgi,
            "wsgi" => GranianInterface::Wsgi,
            _ => GranianInterface::Asgi,
        }
    }
}

impl<'de> serde::Deserialize<'de> for GranianInterface {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(GranianInterface::from(s.as_str()))
    }
}

impl serde::Serialize for GranianInterface {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[derive(Clone)]
pub struct GranianConfig {
    pub app_path: String,
    pub interface: GranianInterface,
    pub workers: u32,
    pub blocking_threads: u32,
    pub socket_path: Option<PathBuf>,
    pub port: Option<u16>,
    pub host: Option<String>,
    pub python_path: Option<PathBuf>,
    pub working_directory: Option<PathBuf>,
    pub env: HashMap<String, String>,
    pub restart_on_failure: bool,
    pub max_restarts: u32,
    pub health_check_path: String,
    pub health_check_interval_secs: u64,
    pub health_check_timeout_secs: u64,
    pub auto_install_granian: bool,
    pub auto_detect_venv: bool,
    pub auto_detect_app: bool,
    pub auto_install_requirements: bool,
    pub site_id: String,
    pub worker_id: usize,
}

impl From<&AppServerConfig> for GranianConfig {
    fn from(config: &AppServerConfig) -> Self {
        Self {
            app_path: config.app_path.clone(),
            interface: config.interface,
            workers: config.workers,
            blocking_threads: config.blocking_threads,
            socket_path: config.socket_path.clone(),
            port: config.port,
            host: config.host.clone(),
            python_path: config.python_path.clone(),
            working_directory: config.working_directory.clone(),
            env: config.env.clone(),
            restart_on_failure: config.restart_on_failure,
            max_restarts: config.max_restarts,
            health_check_path: config.health_check_path.clone(),
            health_check_interval_secs: config.health_check_interval_secs,
            health_check_timeout_secs: config.health_check_timeout_secs,
            auto_install_granian: config.auto_install_granian,
            auto_detect_venv: config.auto_detect_venv,
            auto_detect_app: config.auto_detect_app,
            auto_install_requirements: config.auto_install_requirements,
            site_id: String::new(),
            worker_id: 0,
        }
    }
}

impl GranianConfig {
    pub fn with_site_info(mut self, site_id: &str, worker_id: usize) -> Self {
        self.site_id = site_id.to_string();
        self.worker_id = worker_id;

        if self.socket_path.is_none() {
            let uuid = uuid::Uuid::new_v4().to_string()[..8].to_string();
            self.socket_path = Some(std::env::temp_dir().join(format!(
                "maluwaf-{}-{}-app-{}.sock",
                site_id, uuid, worker_id
            )));
        }

        if self.auto_detect_venv {
            self.python_path = self.python_path.clone().or_else(|| self.detect_venv());
        }

        self
    }

    fn detect_venv(&self) -> Option<PathBuf> {
        let working_dir = self.working_directory.as_ref()?;

        let candidates = vec![
            working_dir.join("venv").join("bin").join("python"),
            working_dir.join("venv").join("bin").join("python3"),
            working_dir.join(".venv").join("bin").join("python"),
            working_dir.join(".venv").join("bin").join("python3"),
            PathBuf::from(".venv").join("bin").join("python"),
            PathBuf::from(".venv").join("bin").join("python3"),
        ];

        for candidate in candidates {
            if candidate.exists() {
                tracing::info!("Auto-detected virtual environment: {}", candidate.display());
                return Some(candidate);
            }
        }

        if let Ok(var) = std::env::var("VIRTUAL_ENV") {
            let venv_path = PathBuf::from(var).join("bin").join("python");
            if venv_path.exists() {
                tracing::info!(
                    "Auto-detected virtual environment from VIRTUAL_ENV: {}",
                    venv_path.display()
                );
                return Some(venv_path);
            }
        }

        None
    }

    pub fn resolve_python_path(&self) -> PathBuf {
        if let Some(ref path) = self.python_path {
            path.clone()
        } else {
            PathBuf::from("python3")
        }
    }

    pub fn resolve_socket_path(&self) -> PathBuf {
        if let Some(ref path) = self.socket_path {
            path.clone()
        } else {
            std::env::temp_dir().join(format!(
                "maluwaf-{}-app-{}.sock",
                self.site_id, self.worker_id
            ))
        }
    }
}

#[derive(Clone)]
pub struct GranianSupervisor {
    config: Arc<GranianConfig>,
    child: Arc<RwLock<Option<tokio::process::Child>>>,
    healthy: RunningFlag,
    restart_count: Arc<AtomicU32>,
    consecutive_failures: Arc<AtomicU32>,
    consecutive_successes: Arc<AtomicU64>,
    shutdown_tx: broadcast::Sender<()>,
    running: RunningFlag,
    pid: Arc<AtomicU32>,
}

impl GranianSupervisor {
    pub fn new(config: GranianConfig) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);

        Self {
            config: Arc::new(config),
            child: Arc::new(RwLock::new(None)),
            healthy: RunningFlag::new(),
            restart_count: Arc::new(AtomicU32::new(0)),
            consecutive_failures: Arc::new(AtomicU32::new(0)),
            consecutive_successes: Arc::new(AtomicU64::new(0)),
            shutdown_tx,
            running: RunningFlag::new(),
            pid: Arc::new(AtomicU32::new(0)),
        }
    }

    pub fn config(&self) -> &GranianConfig {
        &self.config
    }

    fn resolve_app_path(&self) -> String {
        let config = self.config.as_ref();
        if !config.app_path.is_empty() {
            return config.app_path.clone();
        }

        if !config.auto_detect_app {
            return config.app_path.clone();
        }

        let working_dir = match &config.working_directory {
            Some(d) => d,
            None => {
                tracing::warn!("No app_path specified and no working_directory to auto-detect app");
                return config.app_path.clone();
            }
        };

        let candidates = vec![
            ("main:app", "main.py"),
            ("app:app", "app.py"),
            ("wsgi:application", "wsgi.py"),
            ("application:application", "application.py"),
            ("asgi:app", "asgi.py"),
        ];

        for (app_path, filename) in &candidates {
            if working_dir.join(*filename).exists() {
                tracing::info!("Auto-detected app: {} (from {})", app_path, filename);
                return app_path.to_string();
            }
        }

        tracing::warn!(
            "Could not auto-detect app. Tried: {:?}. Please specify app_path explicitly.",
            candidates
                .iter()
                .map(|(p, f)| format!("{} ({})", p, f))
                .collect::<Vec<_>>()
        );
        config.app_path.clone()
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.is_running()
    }

    pub fn pid(&self) -> Option<u32> {
        let pid = self.pid.load(Ordering::SeqCst);
        if pid == 0 {
            None
        } else {
            Some(pid)
        }
    }

    pub fn restart_count(&self) -> u32 {
        self.restart_count.load(Ordering::SeqCst)
    }

    pub async fn start(&self) -> Result<(), String> {
        if self.running.is_running() {
            return Ok(());
        }

        self.running.set(true);

        if let Err(e) = self.spawn_process().await {
            self.running.set(false);
            return Err(e);
        }

        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let health_check_config = self.config.clone();
        let healthy = self.healthy.clone();
        let running = self.running.clone();
        let _child = self.child.clone();
        let consecutive_failures = self.consecutive_failures.clone();
        let consecutive_successes = self.consecutive_successes.clone();
        let _max_restarts = self.config.max_restarts;

        tokio::spawn(async move {
            let mut health_interval = interval(Duration::from_secs(
                health_check_config.health_check_interval_secs,
            ));

            loop {
                tokio::select! {
                    _ = health_interval.tick() => {
                        if !running.is_running() {
                            break;
                        }

                        let is_healthy = Self::check_health(&health_check_config).await;

                        if is_healthy {
                            consecutive_failures.store(0, Ordering::SeqCst);
                            let successes = consecutive_successes.fetch_add(1, Ordering::SeqCst) + 1;
                            if successes >= 3 && !healthy.is_running() {
                                healthy.set(true);
                                tracing::info!(
                                    "Granian app server for site {} worker {} recovered",
                                    health_check_config.site_id, health_check_config.worker_id
                                );
                            }
                        } else {
                            consecutive_successes.store(0, Ordering::SeqCst);
                            let failures = consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;

                            if failures >= 3 && healthy.is_running() {
                                healthy.set(false);
                                tracing::warn!(
                                    "Granian app server for site {} worker {} marked unhealthy after {} failures",
                                    health_check_config.site_id, health_check_config.worker_id, failures
                                );
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        tracing::info!(
                            "Granian health check stopped for site {} worker {}",
                            health_check_config.site_id, health_check_config.worker_id
                        );
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    async fn ensure_granian_installed(&self, python_binary: &PathBuf) -> Result<(), String> {
        let check_output = Command::new(python_binary)
            .args(["-c", "import granian"])
            .output()
            .await;

        match check_output {
            Ok(output) if output.status.success() => {
                tracing::debug!("Granian is already installed");
                return Ok(());
            }
            _ => {}
        }

        if !self.config.auto_install_granian {
            return Err(format!(
                "Granian is not installed and auto_install_granian is disabled.\n\
                \nTo fix this, either:\n\
                \n  1. Run: {} -m pip install granian\n\
                \n  2. Or enable auto_install_granian in your config:\n\
                \n       [app_server]\n       auto_install_granian = true\n",
                python_binary.display()
            ));
        }

        tracing::info!("Installing Granian in virtual environment...");

        let install_output = Command::new(python_binary)
            .args(["-m", "pip", "install", "granian"])
            .output()
            .await
            .map_err(|e| format!("Failed to run pip install: {}", e))?;

        if !install_output.status.success() {
            let stderr = String::from_utf8_lossy(&install_output.stderr);
            return Err(format!(
                "Failed to install Granian:\n{}\n\
                \nPlease install manually: {} -m pip install granian",
                stderr,
                python_binary.display()
            ));
        }

        tracing::info!("Granian installed successfully");
        Ok(())
    }

    async fn ensure_requirements_installed(&self, python_binary: &PathBuf) -> Result<(), String> {
        let working_dir = match &self.config.working_directory {
            Some(d) => d,
            None => {
                tracing::debug!("No working_directory set, skipping requirements.txt check");
                return Ok(());
            }
        };

        let requirements_path = working_dir.join("requirements.txt");

        if !requirements_path.exists() {
            tracing::debug!(
                "No requirements.txt found at {}, skipping dependency installation",
                requirements_path.display()
            );
            return Ok(());
        }

        if !self.config.auto_install_requirements {
            tracing::info!(
                "requirements.txt found at {} but auto_install_requirements is disabled",
                requirements_path.display()
            );
            return Ok(());
        }

        tracing::info!(
            "Installing dependencies from requirements.txt at {}",
            requirements_path.display()
        );

        let install_output = Command::new(python_binary)
            .args([
                "-m",
                "pip",
                "install",
                "-r",
                requirements_path.to_str().unwrap_or(""),
            ])
            .current_dir(working_dir)
            .output()
            .await
            .map_err(|e| format!("Failed to run pip install: {}", e))?;

        if !install_output.status.success() {
            let stderr = String::from_utf8_lossy(&install_output.stderr);
            let stdout = String::from_utf8_lossy(&install_output.stdout);
            return Err(format!(
                "Failed to install requirements:\n{}\n{}\n\
                \nPlease install dependencies manually: {} -m pip install -r {}",
                stdout,
                stderr,
                python_binary.display(),
                requirements_path.display()
            ));
        }

        let stdout = String::from_utf8_lossy(&install_output.stdout);
        tracing::info!(
            "Requirements installed successfully:\n{}",
            stdout.lines().take(5).collect::<Vec<_>>().join("\n")
        );

        Ok(())
    }

    pub async fn spawn_process(&self) -> Result<(), String> {
        let python_binary = self
            .config
            .python_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("python3"));

        if !python_binary.exists() {
            return Err(format!(
                "Python binary not found at: {}. Please check the python_path configuration.\n\
                \nHint: Set python_path to your virtualenv's python (e.g., /path/to/venv/bin/python)\n\
                Hint: Or ensure auto_detect_venv is enabled and your venv is in the working_directory.",
                python_binary.display()
            ));
        }

        if self.config.auto_install_granian {
            self.ensure_granian_installed(&python_binary).await?;
        }

        self.ensure_requirements_installed(&python_binary).await?;

        let mut cmd = self.build_command();

        let socket_path = self.config.resolve_socket_path();

        if socket_path.exists() {
            if let Err(e) = std::fs::remove_file(&socket_path) {
                tracing::warn!("Failed to remove existing socket: {}", e);
            }
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Failed to spawn granian: {}", e))?;

        let pid = child
            .id()
            .ok_or_else(|| "Failed to get PID from spawned process".to_string())?;
        self.pid.store(pid, Ordering::SeqCst);

        tracing::info!(
            "Started granian for site {} worker {} with PID {}",
            self.config.site_id,
            self.config.worker_id,
            pid
        );

        let site_id = self.config.site_id.clone();
        let worker_id = self.config.worker_id;

        let stdout = child.stdout.take();
        if let Some(stdout) = stdout {
            let site_id_out = site_id.clone();
            let worker_id_out = worker_id;
            tokio::spawn(async move {
                let mut reader = BufReader::new(stdout);
                let mut line = String::new();
                while let Ok(n) = reader.read_line(&mut line).await {
                    if n == 0 {
                        break;
                    }
                    tracing::debug!(
                        "[granian {} worker {} stdout] {}",
                        site_id_out,
                        worker_id_out,
                        line.trim()
                    );
                    line.clear();
                }
            });
        }

        let stderr = child.stderr.take();
        if let Some(stderr) = stderr {
            let site_id_err = site_id.clone();
            let worker_id_err = worker_id;
            tokio::spawn(async move {
                let mut reader = BufReader::new(stderr);
                let mut line = String::new();
                while let Ok(n) = reader.read_line(&mut line).await {
                    if n == 0 {
                        break;
                    }
                    tracing::warn!(
                        "[granian {} worker {} stderr] {}",
                        site_id_err,
                        worker_id_err,
                        line.trim()
                    );
                    line.clear();
                }
            });
        }

        if let Some(ref socket) = self.config.socket_path {
            let mut attempts = 0;
            let max_attempts = 50;

            while !socket.exists() && attempts < max_attempts {
                tokio::time::sleep(Duration::from_millis(100)).await;
                attempts += 1;
            }

            if socket.exists() {
                tracing::debug!("Granian socket created at {}", socket.display());
            } else {
                tracing::warn!("Granian socket not created after {} attempts", max_attempts);
            }
        }

        *self.child.write().await = Some(child);
        self.healthy.set(true);

        let restart_count = self.restart_count.fetch_add(1, Ordering::SeqCst) + 1;
        tracing::info!(
            "Granian restart count for site {} worker {}: {}",
            self.config.site_id,
            self.config.worker_id,
            restart_count
        );

        Ok(())
    }

    fn build_command(&self) -> Command {
        let python_binary = self.config.resolve_python_path();

        let mut cmd = Command::new(&python_binary);

        cmd.arg("-m").arg("granian");

        let app_path = self.resolve_app_path();
        cmd.arg("--interface")
            .arg(self.config.interface.to_string());
        cmd.arg(&app_path);

        if let Some(ref socket) = self.config.socket_path {
            cmd.arg("--uds").arg(socket);
        } else if let Some(port) = self.config.port {
            if let Some(ref host) = self.config.host {
                cmd.arg("--host").arg(host);
            }
            cmd.arg("--port").arg(port.to_string());
        }

        cmd.arg("--workers").arg(self.config.workers.to_string());
        cmd.arg("--blocking-threads")
            .arg(self.config.blocking_threads.to_string());

        if let Some(ref working_dir) = self.config.working_directory {
            cmd.current_dir(working_dir);
        }

        for (key, value) in &self.config.env {
            cmd.env(key, value);
        }

        if let Ok(var) = std::env::var("PYTHONPATH") {
            cmd.env("PYTHONPATH", var);
        }

        cmd.kill_on_drop(true);

        use std::process::Stdio;
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        tracing::debug!(
            "Built granian command: {} {} (interface: {}, workers: {}, blocking-threads: {})",
            python_binary.display(),
            self.config.app_path,
            self.config.interface,
            self.config.workers,
            self.config.blocking_threads
        );

        cmd
    }

    async fn check_health(config: &GranianConfig) -> bool {
        let timeout = Duration::from_secs(config.health_check_timeout_secs);
        let path = &config.health_check_path;

        #[cfg(unix)]
        let url = if let Some(ref socket) = config.socket_path {
            let socket_display = socket.display().to_string();
            let socket_str = socket_display.trim_start_matches('/');
            format!("http://unix/{}:{}", socket_str, path)
        } else {
            let host = config.host.as_deref().unwrap_or("127.0.0.1");
            let port = config.port.unwrap_or(8000);
            format!("http://{}:{}{}", host, port, path)
        };

        #[cfg(not(unix))]
        let url = {
            let host = config.host.as_deref().unwrap_or("127.0.0.1");
            let port = config.port.unwrap_or(8000);
            format!("http://{}:{}{}", host, port, path)
        };

        let client = crate::http_client::create_http_client_with_config(
            timeout,
            10,
            Duration::from_secs(30),
        );

        match crate::http_client::send_request_with_timeout(
            &client,
            http::Method::HEAD,
            &url,
            Some(timeout),
        )
        .await
        {
            Ok(resp) => {
                let status = resp.status_code();
                (200..400).contains(&status)
            }
            Err(e) => {
                tracing::warn!(
                    "Granian health check failed for site {} worker {}: {}",
                    config.site_id,
                    config.worker_id,
                    e
                );
                false
            }
        }
    }

    pub async fn restart(&self) -> Result<(), String> {
        if !self.config.restart_on_failure {
            return Err("Restart disabled in config".to_string());
        }

        let current_restarts = self.restart_count.load(Ordering::SeqCst);
        if current_restarts >= self.config.max_restarts {
            return Err(format!(
                "Max restarts ({}) exceeded for site {} worker {}",
                self.config.max_restarts, self.config.site_id, self.config.worker_id
            ));
        }

        tracing::info!(
            "Restarting granian for site {} worker {} (attempt {}/{})",
            self.config.site_id,
            self.config.worker_id,
            current_restarts + 1,
            self.config.max_restarts
        );

        self.stop().await;

        tokio::time::sleep(Duration::from_secs(1)).await;

        self.start().await
    }

    pub async fn stop(&self) {
        self.running.set(false);
        let _ = self.shutdown_tx.send(());

        let mut child_guard = self.child.write().await;
        if let Some(ref mut child) = child_guard.take() {
            tracing::info!(
                "Stopping granian for site {} worker {} (PID: {:?})",
                self.config.site_id,
                self.config.worker_id,
                child.id()
            );

            #[cfg(unix)]
            {
                let pid = child.id().unwrap_or(0);

                let kill_output = tokio::task::spawn_blocking(move || {
                    std::process::Command::new("kill")
                        .arg("-TERM")
                        .arg(pid.to_string())
                        .output()
                })
                .await;

                match kill_output {
                    Ok(Ok(output)) => {
                        if !output.status.success() {
                            tracing::warn!(
                                "kill -TERM failed for granian PID {}: {}",
                                pid,
                                String::from_utf8_lossy(&output.stderr)
                            );
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("Failed to execute kill command: {}", e);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to spawn blocking task for kill: {}", e);
                    }
                }

                let start = Instant::now();
                let graceful_timeout = Duration::from_secs(5);
                while start.elapsed() < graceful_timeout {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            tracing::debug!("Granian process exited with status: {}", status);
                            break;
                        }
                        Ok(None) => tokio::time::sleep(Duration::from_millis(100)).await,
                        Err(e) => {
                            tracing::warn!("Error waiting for granian process: {}", e);
                            break;
                        }
                    }
                }

                if start.elapsed() >= graceful_timeout {
                    tracing::warn!("Granian process did not terminate gracefully, forcing kill");
                    if let Err(e) = child.kill().await {
                        tracing::warn!("Failed to kill granian process: {}", e);
                    }
                }
            }

            #[cfg(not(unix))]
            {
                if let Err(e) = child.kill().await {
                    tracing::warn!("Failed to kill granian process: {}", e);
                }
            }

            if let Err(e) = child.wait().await {
                tracing::debug!("Error waiting for granian process to exit: {}", e);
            }
        }

        if let Some(ref socket) = self.config.socket_path {
            if socket.exists() {
                let _ = std::fs::remove_file(socket);
            }
        }

        self.healthy.set(false);
        self.pid.store(0, Ordering::SeqCst);

        tracing::info!(
            "Stopped granian for site {} worker {}",
            self.config.site_id,
            self.config.worker_id
        );
    }

    pub async fn wait_for_shutdown(&self) {
        let mut child_guard = self.child.write().await;
        if let Some(ref mut child) = *child_guard {
            let _ = child.wait().await;
        }
    }

    pub fn socket_url(&self) -> String {
        let socket_path = self.config.resolve_socket_path();
        #[cfg(unix)]
        {
            format!("http://unix:{}:", socket_path.display())
        }
        #[cfg(not(unix))]
        {
            let host = self.config.host.as_deref().unwrap_or("127.0.0.1");
            let port = self.config.port.unwrap_or(8000);
            format!("http://{}:{}", host, port)
        }
    }

    pub async fn forward_request(
        &self,
        method: http::Method,
        path: &str,
        headers: &http::HeaderMap<http::HeaderValue>,
        body: Bytes,
    ) -> Result<http::Response<Bytes>, String> {
        let socket_path = self.config.resolve_socket_path();

        #[cfg(unix)]
        let url = { format!("http://unix:{}:{}", socket_path.display(), path) };

        #[cfg(not(unix))]
        let url = {
            let host = self.config.host.as_deref().unwrap_or("127.0.0.1");
            let port = self.config.port.unwrap_or(8000);
            format!("http://{}:{}{}", host, port, path)
        };

        let client = crate::http_client::create_http_client_with_config(
            std::time::Duration::from_secs(30),
            10,
            std::time::Duration::from_secs(60),
        );

        let response = crate::http_client::send_request_with_body_headers_and_timeout(
            &client,
            method,
            &url,
            Some(body),
            headers.clone(),
            Some(std::time::Duration::from_secs(30)),
        )
        .await
        .map_err(|e| format!("Granian request failed: {}", e))?;

        let mut builder = http::Response::builder().status(response.status_code());
        for (name, value) in response.headers_iter() {
            if let Ok(value_str) = value.to_str() {
                builder = builder.header(name, value_str);
            }
        }
        builder
            .body(response.body)
            .map_err(|e| format!("Failed to build response: {}", e))
    }
}

impl Drop for GranianSupervisor {
    fn drop(&mut self) {
        self.running.set(false);
        let _ = self.shutdown_tx.send(());

        let socket_path = self.config.resolve_socket_path();
        if socket_path.exists() {
            if let Err(e) = std::fs::remove_file(&socket_path) {
                tracing::debug!("Failed to remove socket file on drop: {}", e);
            }
        }
    }
}
