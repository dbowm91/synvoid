use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SyslogFacility {
    #[default]
    Daemon,
    Local0,
    Local1,
    Local2,
    Local3,
    Local4,
    Local5,
    Local6,
    Local7,
    Security,
    Auth,
    User,
}

#[derive(Debug, Clone)]
pub struct SyslogConfig {
    pub facility: SyslogFacility,
    pub app_name: String,
    pub pid: bool,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            facility: SyslogFacility::Daemon,
            app_name: "maluwaf".to_string(),
            pid: true,
        }
    }
}

impl SyslogConfig {
    pub fn new(app_name: impl Into<String>) -> Self {
        Self {
            app_name: app_name.into(),
            ..Default::default()
        }
    }

    pub fn with_facility(mut self, facility: SyslogFacility) -> Self {
        self.facility = facility;
        self
    }

    pub fn with_pid(mut self, pid: bool) -> Self {
        self.pid = pid;
        self
    }
}

#[derive(Clone)]
pub struct SyslogLogger {
    min_level: log::Level,
    #[allow(dead_code)]
    app_name: String,
    #[cfg(unix)]
    _backend: (),
    #[cfg(not(unix))]
    _phantom: (),
}

impl SyslogLogger {
    #[cfg(unix)]
    pub fn new(config: SyslogConfig, min_level: log::Level) -> Result<Self, SyslogError> {
        use syslog::Facility;

        let facility = match config.facility {
            SyslogFacility::Daemon => Facility::LOG_DAEMON,
            SyslogFacility::Local0 => Facility::LOG_LOCAL0,
            SyslogFacility::Local1 => Facility::LOG_LOCAL1,
            SyslogFacility::Local2 => Facility::LOG_LOCAL2,
            SyslogFacility::Local3 => Facility::LOG_LOCAL3,
            SyslogFacility::Local4 => Facility::LOG_LOCAL4,
            SyslogFacility::Local5 => Facility::LOG_LOCAL5,
            SyslogFacility::Local6 => Facility::LOG_LOCAL6,
            SyslogFacility::Local7 => Facility::LOG_LOCAL7,
            SyslogFacility::Security => Facility::LOG_AUTH,
            SyslogFacility::Auth => Facility::LOG_AUTH,
            SyslogFacility::User => Facility::LOG_USER,
        };

        let level_filter = match min_level {
            log::Level::Error => log::LevelFilter::Error,
            log::Level::Warn => log::LevelFilter::Warn,
            log::Level::Info => log::LevelFilter::Info,
            log::Level::Debug => log::LevelFilter::Debug,
            log::Level::Trace => log::LevelFilter::Trace,
        };

        match syslog::init_unix(facility, level_filter) {
            Ok(()) => {
                tracing::info!(
                    "Syslog logger initialized (facility: {:?})",
                    config.facility
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to initialize syslog: {}, falling back to tracing",
                    e
                );
            }
        }

        Ok(Self {
            min_level,
            app_name: config.app_name,
            _backend: (),
        })
    }

    #[cfg(not(unix))]
    pub fn new(config: SyslogConfig, min_level: log::Level) -> Result<Self, SyslogError> {
        tracing::info!("Syslog logger initialized (stub - not available on this platform)");

        Ok(Self {
            min_level,
            app_name: config.app_name,
            _phantom: (),
        })
    }

    pub fn log(&self, level: log::Level, message: &str) {
        if level > self.min_level {
            return;
        }

        #[cfg(unix)]
        {
            log::log!(level, "{}", message);
        }

        #[cfg(not(unix))]
        {
            tracing::debug!("[syslog {}] {}", self.app_name, message);
        }
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

    pub fn is_enabled(&self, level: log::Level) -> bool {
        level <= self.min_level
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

pub fn init_syslog(app_name: &str, min_level: log::Level) -> Result<SyslogLogger, SyslogError> {
    let config = SyslogConfig::new(app_name);
    SyslogLogger::new(config, min_level)
}

pub fn init_syslog_with_config(
    config: SyslogConfig,
    min_level: log::Level,
) -> Result<SyslogLogger, SyslogError> {
    SyslogLogger::new(config, min_level)
}
