use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

#[derive(Debug, Clone)]
pub enum ProcessMode {
    Master,
    Worker { worker_id: usize, port: u16 },
    UnifiedServerWorker { worker_id: usize },
    StaticWorker { worker_id: usize },
    MeshControlPlane,
    PluginExecution,
}

#[derive(Debug, Clone)]
pub struct SpawnConfig {
    pub binary_path: PathBuf,
    pub config_path: PathBuf,
    pub mode: ProcessMode,
    pub master_socket: Option<PathBuf>,
    pub upgrade_mode: bool,
    pub reuse_port: bool,
    pub socket_generation: Option<u32>,
    pub versioned_socket: Option<PathBuf>,
    pub receive_sockets: bool,
    pub socket_ports: Vec<u16>,
}

impl SpawnConfig {
    pub fn for_current_binary(config_path: PathBuf, mode: ProcessMode) -> Self {
        Self {
            binary_path: std::env::current_exe().unwrap_or_else(|_| PathBuf::from("maluwaf")),
            config_path,
            mode,
            master_socket: None,
            upgrade_mode: false,
            reuse_port: false,
            socket_generation: None,
            versioned_socket: None,
            receive_sockets: false,
            socket_ports: Vec::new(),
        }
    }

    pub fn with_master_socket(mut self, socket: PathBuf) -> Self {
        self.master_socket = Some(socket);
        self
    }

    pub fn with_upgrade_mode(mut self, enabled: bool) -> Self {
        self.upgrade_mode = enabled;
        self
    }

    pub fn with_reuse_port(mut self, enabled: bool) -> Self {
        self.reuse_port = enabled;
        self
    }

    pub fn with_socket_generation(mut self, gen: u32, versioned_socket: PathBuf) -> Self {
        self.socket_generation = Some(gen);
        self.versioned_socket = Some(versioned_socket);
        self
    }

    pub fn with_receive_sockets(mut self, ports: Vec<u16>) -> Self {
        self.receive_sockets = true;
        self.socket_ports = ports;
        self
    }
}

pub fn build_spawn_command(config: &SpawnConfig) -> Command {
    let mut cmd = Command::new(&config.binary_path);

    match &config.mode {
        ProcessMode::Master => {
            cmd.arg("--master");
        }
        ProcessMode::Worker { worker_id, port } => {
            cmd.arg("--worker")
                .arg("--worker-id")
                .arg(worker_id.to_string())
                .arg("--port")
                .arg(port.to_string());
        }
        ProcessMode::UnifiedServerWorker { worker_id } => {
            cmd.arg("--unified-server-worker")
                .arg("--worker-id")
                .arg(worker_id.to_string());
        }
        ProcessMode::StaticWorker { worker_id } => {
            cmd.arg("--static-worker")
                .arg("--worker-id")
                .arg(worker_id.to_string());
        }
        ProcessMode::MeshControlPlane => {
            cmd.arg("--mesh-control-plane");
        }
        ProcessMode::PluginExecution => {
            cmd.arg("--plugin-execution");
        }
    }

    cmd.arg("--config-path")
        .arg(&config.config_path)
        .arg("--foreground");

    if let Some(ref socket) = config.master_socket {
        cmd.arg("--master-socket").arg(socket);
    }

    if config.upgrade_mode {
        cmd.arg("--upgrade-mode");
    }

    if config.reuse_port {
        cmd.arg("--reuse-port");
    }

    if let Some(gen) = config.socket_generation {
        cmd.arg("--socket-generation").arg(gen.to_string());
    }

    if let Some(ref versioned_socket) = config.versioned_socket {
        cmd.arg("--master-socket").arg(versioned_socket);
    }

    if config.receive_sockets {
        cmd.arg("--receive-sockets");
        for port in &config.socket_ports {
            cmd.arg("--socket-port").arg(port.to_string());
        }
    }

    cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());

    cmd
}

pub fn spawn_process(config: &SpawnConfig) -> Result<Child, std::io::Error> {
    let mut cmd = build_spawn_command(config);
    cmd.spawn()
}

pub fn spawn_and_log(config: &SpawnConfig, process_type: &str) -> Result<Child, std::io::Error> {
    let child = spawn_process(config)?;
    let pid = child.id();
    tracing::info!("Spawned {} process with PID {}", process_type, pid);
    Ok(child)
}

#[derive(Debug, Clone, Copy)]
pub enum Signal {
    Term,
    Kill,
    User1,
}

impl Signal {
    pub fn send(self, pid: u32) -> Result<(), std::io::Error> {
        #[cfg(unix)]
        {
            use nix::sys::signal::Signal as NixSignal;
            let nix_signal = match self {
                Signal::Term => NixSignal::SIGTERM,
                Signal::Kill => NixSignal::SIGKILL,
                Signal::User1 => NixSignal::SIGUSR1,
            };
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), nix_signal)?;
        }
        #[cfg(not(unix))]
        {
            let flag = match self {
                Signal::Term => "",
                Signal::Kill => "/F",
                Signal::User1 => "",
            };
            let result = std::process::Command::new("taskkill")
                .args([flag, "/PID", &pid.to_string()])
                .output();

            if let Err(e) = result {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to send signal: {}", e),
                ));
            }
        }
        Ok(())
    }
}

pub fn kill_process(pid: u32) -> Result<(), std::io::Error> {
    Signal::Term.send(pid)
}

pub fn force_kill_process(pid: u32) -> Result<(), std::io::Error> {
    Signal::Kill.send(pid)
}

pub fn signal_process(pid: u32, signal: Signal) -> Result<(), std::io::Error> {
    signal.send(pid)
}

pub fn cleanup_failed_spawns(pids: &[u32]) {
    for &pid in pids {
        let _ = force_kill_process(pid);
    }
}
