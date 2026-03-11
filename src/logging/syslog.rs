use parking_lot::RwLock;
use std::fmt;
use std::sync::Arc;

#[derive(Clone)]
pub struct SyslogLogger {
    min_level: u8,
    app_name: String,
}

impl SyslogLogger {
    #[allow(unused_variables)]
    pub fn new(
        host: Option<&str>,
        port: u16,
        app_name: &str,
        min_level: log::Level,
    ) -> Result<Self, SyslogError> {
        let min_level = match min_level {
            log::Level::Error => 3,
            log::Level::Warn => 4,
            log::Level::Info => 6,
            log::Level::Debug => 7,
            log::Level::Trace => 7,
        };

        tracing::info!(
            "Syslog logger initialized to {}:{} (stub implementation)",
            host.unwrap_or("unix socket"),
            port
        );

        Ok(Self {
            min_level,
            app_name: app_name.to_string(),
        })
    }

    pub fn log(&self, level: log::Level, message: &str) {
        let level_num = match level {
            log::Level::Error => 3,
            log::Level::Warn => 4,
            log::Level::Info => 6,
            log::Level::Debug => 7,
            log::Level::Trace => 7,
        };

        if level_num > self.min_level {
            return;
        }
        tracing::debug!("[syslog {}] {}", self.app_name, message);
    }

    pub fn emergency(&self, msg: &str) {
        self.log(log::Level::Error, msg);
    }
    pub fn alert(&self, msg: &str) {
        self.log(log::Level::Error, msg);
    }
    pub fn critical(&self, msg: &str) {
        self.log(log::Level::Error, msg);
    }
    pub fn error(&self, msg: &str) {
        self.log(log::Level::Error, msg);
    }
    pub fn warning(&self, msg: &str) {
        self.log(log::Level::Warn, msg);
    }
    pub fn notice(&self, msg: &str) {
        self.log(log::Level::Info, msg);
    }
    pub fn info(&self, msg: &str) {
        self.log(log::Level::Info, msg);
    }
    pub fn debug(&self, msg: &str) {
        self.log(log::Level::Debug, msg);
    }
}

#[derive(Debug)]
pub enum SyslogError {
    Connection(String),
}

impl fmt::Display for SyslogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyslogError::Connection(e) => write!(f, "Syslog connection error: {}", e),
        }
    }
}

impl std::error::Error for SyslogError {}
