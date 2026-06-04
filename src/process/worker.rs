//! Worker process types for process management.
//!
//! Contains the worker process structs used by ProcessManager.

use std::process::Child;
use std::sync::Arc;
use std::time::Instant;

use super::ipc::{WorkerId, WorkerMetricsPayload, WorkerStatus};

pub trait WorkerProcessBase {
    fn base(&self) -> &BaseWorkerProcess;
    fn base_mut(&mut self) -> &mut BaseWorkerProcess;
}

macro_rules! delegate_to_base {
    ($ty:ty) => {
        impl $ty {
            pub fn pid(&self) -> Option<u32> {
                self.base.pid()
            }
            pub fn status(&self) -> &WorkerStatus {
                self.base.status()
            }
            pub fn status_mut(&mut self) -> &mut WorkerStatus {
                self.base.status_mut()
            }
            pub fn child_ref(&self) -> &Option<Child> {
                self.base.child_ref()
            }
            pub fn child_mut(&mut self) -> &mut Option<Child> {
                self.base.child_mut()
            }
            pub fn started_at(&self) -> Instant {
                self.base.started_at()
            }
            pub fn last_heartbeat(&self) -> Instant {
                self.base.last_heartbeat()
            }
            pub fn last_heartbeat_mut(&mut self) -> &mut Instant {
                self.base.last_heartbeat_mut()
            }
        }
    };
}

#[derive(Debug)]
pub struct BaseWorkerProcess {
    pub pid: Option<u32>,
    pub status: WorkerStatus,
    pub child: Option<Child>,
    pub started_at: Instant,
    pub last_heartbeat: Instant,
}

impl BaseWorkerProcess {
    pub fn new(pid: u32, child: Child) -> Self {
        Self {
            pid: Some(pid),
            status: WorkerStatus::Starting,
            child: Some(child),
            started_at: Instant::now(),
            last_heartbeat: Instant::now(),
        }
    }

    pub fn pid(&self) -> Option<u32> {
        self.pid
    }
    pub fn status(&self) -> &WorkerStatus {
        &self.status
    }
    pub fn status_mut(&mut self) -> &mut WorkerStatus {
        &mut self.status
    }
    pub fn child_ref(&self) -> &Option<Child> {
        &self.child
    }
    pub fn child_mut(&mut self) -> &mut Option<Child> {
        &mut self.child
    }
    pub fn started_at(&self) -> Instant {
        self.started_at
    }
    pub fn last_heartbeat(&self) -> Instant {
        self.last_heartbeat
    }
    pub fn last_heartbeat_mut(&mut self) -> &mut Instant {
        &mut self.last_heartbeat
    }
}

#[derive(Debug)]
pub struct WorkerProcess {
    pub id: WorkerId,
    pub base: BaseWorkerProcess,
    pub port: u16,
    pub metrics: WorkerMetricsPayload,
    pub restart_count: u32,
    pub last_restart_at: Option<Instant>,
}

impl WorkerProcess {
    pub fn new(id: WorkerId, pid: u32, port: u16, child: Child, restart_count: u32) -> Self {
        Self {
            id,
            base: BaseWorkerProcess::new(pid, child),
            port,
            metrics: WorkerMetricsPayload::default(),
            restart_count,
            last_restart_at: if restart_count > 0 {
                Some(Instant::now())
            } else {
                None
            },
        }
    }

    pub fn new_placeholder(id: WorkerId, port: u16, restart_count: u32) -> Self {
        Self {
            id,
            base: BaseWorkerProcess {
                pid: None,
                status: WorkerStatus::Starting,
                child: None,
                started_at: Instant::now(),
                last_heartbeat: Instant::now(),
            },
            port,
            metrics: WorkerMetricsPayload::default(),
            restart_count,
            last_restart_at: if restart_count > 0 {
                Some(Instant::now())
            } else {
                None
            },
        }
    }

    pub fn set_child(&mut self, child: Child) {
        let pid = child.id();
        self.base.pid = Some(pid);
        self.base.child = Some(child);
    }
}

impl WorkerProcessBase for WorkerProcess {
    fn base(&self) -> &BaseWorkerProcess {
        &self.base
    }
    fn base_mut(&mut self) -> &mut BaseWorkerProcess {
        &mut self.base
    }
}

delegate_to_base!(WorkerProcess);

pub struct CpuWorkerProcess {
    pub worker_id: usize,
    pub base: BaseWorkerProcess,
    pub ipc: Option<Arc<tokio::sync::Mutex<super::ipc::IpcStream>>>,
}

impl CpuWorkerProcess {
    pub fn new(worker_id: usize, pid: u32, child: Child) -> Self {
        Self {
            worker_id,
            base: BaseWorkerProcess::new(pid, child),
            ipc: None,
        }
    }
}

impl WorkerProcessBase for CpuWorkerProcess {
    fn base(&self) -> &BaseWorkerProcess {
        &self.base
    }
    fn base_mut(&mut self) -> &mut BaseWorkerProcess {
        &mut self.base
    }
}

delegate_to_base!(CpuWorkerProcess);

pub struct UnifiedServerWorkerProcess {
    pub id: WorkerId,
    pub base: BaseWorkerProcess,
    pub metrics: WorkerMetricsPayload,
    pub restart_count: u32,
    pub last_restart_at: Option<Instant>,
    pub ipc: Option<Arc<tokio::sync::Mutex<super::ipc::IpcStream>>>,
}

impl UnifiedServerWorkerProcess {
    pub fn new(id: WorkerId, pid: u32, child: Child) -> Self {
        Self {
            id,
            base: BaseWorkerProcess::new(pid, child),
            metrics: WorkerMetricsPayload::default(),
            restart_count: 0,
            last_restart_at: None,
            ipc: None,
        }
    }
}

impl WorkerProcessBase for UnifiedServerWorkerProcess {
    fn base(&self) -> &BaseWorkerProcess {
        &self.base
    }
    fn base_mut(&mut self) -> &mut BaseWorkerProcess {
        &mut self.base
    }
}

delegate_to_base!(UnifiedServerWorkerProcess);
