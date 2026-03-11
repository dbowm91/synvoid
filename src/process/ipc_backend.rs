use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::ipc::{Message, WorkerId, WorkerMetricsPayload};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerStatusInfo {
    pub id: usize,
    pub pid: u32,
    pub port: u16,
    pub status: String,
    pub requests: u64,
    pub blocked: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StatusStats {
    pub total_requests: u64,
    pub blocked_last_hour: u64,
    pub challenged_last_hour: u64,
    pub proxied_last_hour: u64,
    pub active_blocks: u64,
    pub active_violations: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatSummary {
    pub critical_ips: u64,
    pub elevated_ips: u64,
    pub total_blocked_ips: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterStatus {
    pub master_pid: u32,
    pub started_at: u64,
    pub uptime_secs: u64,
    pub version: String,
    pub workers: Vec<WorkerStatusInfo>,
    pub stats: StatusStats,
    pub threat_summary: ThreatSummary,
}

pub trait IpcBackend: Send + Sync {
    fn connect(path: &Path) -> io::Result<Self>
    where
        Self: Sized;

    fn listen(path: &Path) -> io::Result<Self>
    where
        Self: Sized;

    fn accept(&self) -> io::Result<IpcConnection>;

    fn platform_name(&self) -> &'static str;
}

pub struct IpcConnection {
    #[cfg(unix)]
    pub stream: std::os::unix::net::UnixStream,
    #[cfg(windows)]
    pub stream: NamedPipeStream,
    read_buffer: Vec<u8>,
}

#[cfg(windows)]
pub struct NamedPipeStream {
    handle: std::fs::File,
}

#[cfg(windows)]
impl NamedPipeStream {
    pub fn new(handle: std::fs::File) -> Self {
        Self { handle }
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        use std::os::windows::fs::FileExt;
        self.handle.seek(std::io::SeekFrom::Current(0))?;
        Ok(())
    }
}

impl IpcConnection {
    #[cfg(unix)]
    pub fn new(stream: std::os::unix::net::UnixStream) -> Self {
        use std::os::unix::net::UnixStream;
        let _ = UnixStream::set_nonblocking(&stream, true);
        Self {
            stream,
            read_buffer: Vec::with_capacity(64 * 1024),
        }
    }

    #[cfg(windows)]
    pub fn new(handle: std::fs::File) -> Self {
        use std::os::windows::fs::FileExt;
        let _ = handle.seek(std::io::SeekFrom::Current(0));
        Self {
            stream: NamedPipeStream::new(handle),
            read_buffer: Vec::with_capacity(64 * 1024),
        }
    }

    pub fn send(&mut self, msg: &Message) -> io::Result<()> {
        let json =
            serde_json::to_vec(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let len = json.len() as u32;

        #[cfg(unix)]
        {
            use std::io::Write;
            self.stream.write_all(&len.to_be_bytes())?;
            self.stream.write_all(&json)?;
            self.stream.flush()?;
        }

        #[cfg(windows)]
        {
            use std::io::Write;
            use std::os::windows::fs::FileExt;
            self.stream.handle.write_all(&len.to_be_bytes())?;
            self.stream.handle.write_all(&json)?;
        }

        Ok(())
    }

    pub fn try_recv(&mut self) -> io::Result<Option<Message>> {
        #[cfg(unix)]
        {
            self.try_recv_unix()
        }

        #[cfg(windows)]
        {
            self.try_recv_windows()
        }
    }

    #[cfg(unix)]
    fn try_recv_unix(&mut self) -> io::Result<Option<Message>> {
        use std::io::{Read, Write};

        if self.read_buffer.len() < 4 {
            let mut temp_buf = [0u8; 4096];
            match self.stream.read(&mut temp_buf) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed",
                    ))
                }
                Ok(n) => {
                    self.read_buffer.extend_from_slice(&temp_buf[..n]);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(None);
                }
                Err(e) => return Err(e),
            }
        }

        if self.read_buffer.len() < 4 {
            return Ok(None);
        }

        let len_bytes: [u8; 4] = [
            self.read_buffer[0],
            self.read_buffer[1],
            self.read_buffer[2],
            self.read_buffer[3],
        ];
        let len = u32::from_be_bytes(len_bytes) as usize;

        if len > 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message too large",
            ));
        }

        let total_needed = 4 + len;
        if self.read_buffer.len() < total_needed {
            let mut temp_buf = [0u8; 4096];
            loop {
                match self.stream.read(&mut temp_buf) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "connection closed",
                        ))
                    }
                    Ok(n) => {
                        self.read_buffer.extend_from_slice(&temp_buf[..n]);
                        if self.read_buffer.len() >= total_needed {
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        return Ok(None);
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        let json = self.read_buffer.drain(4..total_needed).collect::<Vec<_>>();
        let msg: Message = serde_json::from_slice(&json)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok(Some(msg))
    }

    #[cfg(windows)]
    fn try_recv_windows(&mut self) -> io::Result<Option<Message>> {
        use std::io::{Read, Write};
        use std::os::windows::fs::FileExt;

        let stream_handle = &self.stream.handle;

        if self.read_buffer.len() < 4 {
            let mut temp_buf = [0u8; 4096];
            match stream_handle.read(&mut temp_buf) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed",
                    ))
                }
                Ok(n) => {
                    self.read_buffer.extend_from_slice(&temp_buf[..n]);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(None);
                }
                Err(e) => return Err(e),
            }
        }

        if self.read_buffer.len() < 4 {
            return Ok(None);
        }

        let len_bytes: [u8; 4] = [
            self.read_buffer[0],
            self.read_buffer[1],
            self.read_buffer[2],
            self.read_buffer[3],
        ];
        let len = u32::from_be_bytes(len_bytes) as usize;

        if len > 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message too large",
            ));
        }

        let total_needed = 4 + len;
        if self.read_buffer.len() < total_needed {
            let mut temp_buf = [0u8; 4096];
            loop {
                match stream_handle.read(&mut temp_buf) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "connection closed",
                        ))
                    }
                    Ok(n) => {
                        self.read_buffer.extend_from_slice(&temp_buf[..n]);
                        if self.read_buffer.len() >= total_needed {
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        return Ok(None);
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        let json = self.read_buffer.drain(4..total_needed).collect::<Vec<_>>();
        let msg: Message = serde_json::from_slice(&json)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok(Some(msg))
    }
}
