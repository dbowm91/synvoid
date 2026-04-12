use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::{DrainFlag, RunningFlag};

pub struct ConnectionLimits {
    max_tcp_connections: usize,
    max_concurrent_queries: usize,
    max_query_size: usize,
    max_response_size: usize,
    max_records_per_response: usize,
    max_tcp_idle_time: Duration,
    max_tcp_query_time: Duration,
    max_amplification_ratio: f32,
    connection_count: AtomicUsize,
    query_count: AtomicUsize,
    degraded_mode: RunningFlag,
    graceful_shutdown: DrainFlag,
    reject_ratio: f32,
}

impl ConnectionLimits {
    pub fn new(
        max_tcp_connections: usize,
        max_concurrent_queries: usize,
        max_query_size: usize,
        max_response_size: usize,
        max_records_per_response: usize,
        max_tcp_idle_time_secs: u64,
        max_tcp_query_time_secs: u64,
    ) -> Self {
        Self {
            max_tcp_connections,
            max_concurrent_queries,
            max_query_size,
            max_response_size,
            max_records_per_response,
            max_tcp_idle_time: Duration::from_secs(max_tcp_idle_time_secs),
            max_tcp_query_time: Duration::from_secs(max_tcp_query_time_secs),
            max_amplification_ratio: 2.0,
            connection_count: AtomicUsize::new(0),
            query_count: AtomicUsize::new(0),
            degraded_mode: RunningFlag::new(),
            graceful_shutdown: DrainFlag::new(),
            reject_ratio: 0.0,
        }
    }

    pub fn enable_graceful_degradation(&mut self, reject_ratio: f32) {
        self.degraded_mode.set(true);
        self.reject_ratio = reject_ratio.clamp(0.0, 1.0);
    }

    pub fn disable_graceful_degradation(&mut self) {
        self.degraded_mode.set(false);
        self.reject_ratio = 0.0;
    }

    pub fn initiate_graceful_shutdown(&self) {
        self.graceful_shutdown.start_drain();
    }

    pub fn is_in_graceful_shutdown(&self) -> bool {
        self.graceful_shutdown.is_draining()
    }

    pub fn is_degraded(&self) -> bool {
        self.degraded_mode.is_running()
    }

    pub fn get_degradation_level(&self) -> DegradationLevel {
        let connections = self.connection_count.load(Ordering::Relaxed);
        let queries = self.query_count.load(Ordering::Relaxed);

        let conn_ratio = connections as f32 / self.max_tcp_connections as f32;
        let query_ratio = queries as f32 / self.max_concurrent_queries as f32;
        let max_ratio = conn_ratio.max(query_ratio);

        if max_ratio > 0.9 {
            DegradationLevel::Critical
        } else if max_ratio > 0.7 {
            DegradationLevel::High
        } else if max_ratio > 0.5 {
            DegradationLevel::Moderate
        } else {
            DegradationLevel::Normal
        }
    }

    pub fn should_reject_request(&self) -> bool {
        if !self.degraded_mode.get() {
            return false;
        }

        let connections = self.connection_count.load(Ordering::Relaxed);
        let queries = self.query_count.load(Ordering::Relaxed);

        let conn_ratio = connections as f32 / self.max_tcp_connections.max(1) as f32;
        let query_ratio = queries as f32 / self.max_concurrent_queries.max(1) as f32;

        let effective_ratio = self.reject_ratio.max(conn_ratio).max(query_ratio);
        let random_value = rand_f32();

        random_value < effective_ratio
    }

    pub fn get_load_factor(&self) -> f32 {
        let connections = self.connection_count.load(Ordering::Relaxed);
        let queries = self.query_count.load(Ordering::Relaxed);

        let conn_ratio = connections as f32 / self.max_tcp_connections.max(1) as f32;
        let query_ratio = queries as f32 / self.max_concurrent_queries.max(1) as f32;

        (conn_ratio + query_ratio) / 2.0
    }

    pub fn max_tcp_idle_time(&self) -> Duration {
        self.max_tcp_idle_time
    }

    fn maybe_reject(&self) -> Result<(), ConnectionLimitError> {
        if self.should_reject_request() {
            return Err(ConnectionLimitError::DegradationReject);
        }
        Ok(())
    }

    pub fn try_acquire_connection(&self) -> Result<ConnectionGuard, ConnectionLimitError> {
        if self.graceful_shutdown.get() {
            return Err(ConnectionLimitError::GracefulShutdown);
        }

        self.maybe_reject()?;

        let current = self.connection_count.fetch_add(1, Ordering::Acquire);

        if current >= self.max_tcp_connections {
            let _ = self
                .connection_count
                .fetch_update(Ordering::Release, Ordering::Relaxed, |v| v.checked_sub(1));
            return Err(ConnectionLimitError::MaxConnectionsReached);
        }

        Ok(ConnectionGuard {
            limits: self,
            start_time: Instant::now(),
        })
    }

    pub fn try_acquire_query(&self) -> Result<QueryGuard, ConnectionLimitError> {
        if self.graceful_shutdown.get() {
            return Err(ConnectionLimitError::GracefulShutdown);
        }

        self.maybe_reject()?;

        let current = self.query_count.fetch_add(1, Ordering::Acquire);

        if current >= self.max_concurrent_queries {
            let _ = self
                .query_count
                .fetch_update(Ordering::Release, Ordering::Relaxed, |v| v.checked_sub(1));
            return Err(ConnectionLimitError::MaxQueriesReached);
        }

        Ok(QueryGuard {
            limits: self,
            start_time: Instant::now(),
        })
    }

    pub fn validate_query_size(&self, size: usize) -> Result<(), ConnectionLimitError> {
        if size > self.max_query_size {
            return Err(ConnectionLimitError::QueryTooLarge {
                size,
                max: self.max_query_size,
            });
        }
        Ok(())
    }

    pub fn validate_response_size(&self, size: usize) -> Result<(), ConnectionLimitError> {
        if size > self.max_response_size {
            return Err(ConnectionLimitError::ResponseTooLarge {
                size,
                max: self.max_response_size,
            });
        }
        Ok(())
    }

    pub fn validate_record_count(&self, count: usize) -> Result<(), ConnectionLimitError> {
        if count > self.max_records_per_response {
            return Err(ConnectionLimitError::TooManyRecords {
                count,
                max: self.max_records_per_response,
            });
        }
        Ok(())
    }

    pub fn validate_amplification(
        &self,
        query_size: usize,
        response_size: usize,
    ) -> Result<(), ConnectionLimitError> {
        if query_size == 0 {
            return Ok(());
        }
        let ratio = response_size as f32 / query_size as f32;
        if ratio > self.max_amplification_ratio {
            return Err(ConnectionLimitError::AmplificationExceeded {
                query_size,
                response_size,
                ratio,
                max_ratio: self.max_amplification_ratio,
            });
        }
        Ok(())
    }

    pub fn set_max_amplification_ratio(&mut self, ratio: f32) {
        self.max_amplification_ratio = ratio.max(1.0);
    }

    pub fn get_stats(&self) -> ConnectionStats {
        ConnectionStats {
            current_connections: self.connection_count.load(Ordering::Relaxed),
            current_queries: self.query_count.load(Ordering::Relaxed),
            max_connections: self.max_tcp_connections,
            max_queries: self.max_concurrent_queries,
            load_factor: self.get_load_factor(),
            degradation_level: self.get_degradation_level(),
            is_graceful_shutdown: self.is_in_graceful_shutdown(),
        }
    }
}

impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        let _ =
            self.limits
                .connection_count
                .fetch_update(Ordering::Release, Ordering::Relaxed, |v| v.checked_sub(1));
    }
}

impl Drop for QueryGuard<'_> {
    fn drop(&mut self) {
        let _ = self
            .limits
            .query_count
            .fetch_update(Ordering::Release, Ordering::Relaxed, |v| v.checked_sub(1));
    }
}

pub struct ConnectionGuard<'a> {
    limits: &'a ConnectionLimits,
    start_time: Instant,
}

pub struct QueryGuard<'a> {
    limits: &'a ConnectionLimits,
    start_time: Instant,
}

impl<'a> ConnectionGuard<'a> {
    pub fn is_idle_timeout(&self) -> bool {
        self.start_time.elapsed() > self.limits.max_tcp_idle_time
    }
}

impl<'a> QueryGuard<'a> {
    pub fn is_query_timeout(&self) -> bool {
        self.start_time.elapsed() > self.limits.max_tcp_query_time
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradationLevel {
    Normal,
    Moderate,
    High,
    Critical,
}

impl DegradationLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            DegradationLevel::Normal => "normal",
            DegradationLevel::Moderate => "moderate",
            DegradationLevel::High => "high",
            DegradationLevel::Critical => "critical",
        }
    }
}

fn rand_f32() -> f32 {
    let bytes = crate::dns::crypto_rng::random_u32();
    (bytes as f32) / (u32::MAX as f32)
}

#[derive(Debug, Clone)]
pub enum ConnectionLimitError {
    MaxConnectionsReached,
    MaxQueriesReached,
    QueryTooLarge {
        size: usize,
        max: usize,
    },
    ResponseTooLarge {
        size: usize,
        max: usize,
    },
    TooManyRecords {
        count: usize,
        max: usize,
    },
    AmplificationExceeded {
        query_size: usize,
        response_size: usize,
        ratio: f32,
        max_ratio: f32,
    },
    ConnectionTimeout,
    QueryTimeout,
    DegradationReject,
    GracefulShutdown,
}

impl std::fmt::Display for ConnectionLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionLimitError::MaxConnectionsReached => {
                write!(f, "Maximum TCP connections reached")
            }
            ConnectionLimitError::MaxQueriesReached => {
                write!(f, "Maximum concurrent queries reached")
            }
            ConnectionLimitError::QueryTooLarge { size, max } => {
                write!(f, "Query size {} exceeds maximum {}", size, max)
            }
            ConnectionLimitError::ResponseTooLarge { size, max } => {
                write!(f, "Response size {} exceeds maximum {}", size, max)
            }
            ConnectionLimitError::TooManyRecords { count, max } => {
                write!(f, "Record count {} exceeds maximum {}", count, max)
            }
            ConnectionLimitError::AmplificationExceeded {
                query_size,
                response_size,
                ratio,
                max_ratio,
            } => {
                write!(
                    f,
                    "TCP amplification ratio {:.1} (query {} bytes, response {} bytes) exceeds maximum {:.1}",
                    ratio, query_size, response_size, max_ratio
                )
            }
            ConnectionLimitError::ConnectionTimeout => {
                write!(f, "Connection idle timeout")
            }
            ConnectionLimitError::QueryTimeout => {
                write!(f, "Query processing timeout")
            }
            ConnectionLimitError::DegradationReject => {
                write!(f, "Request rejected due to degraded mode")
            }
            ConnectionLimitError::GracefulShutdown => {
                write!(f, "Server in graceful shutdown mode")
            }
        }
    }
}

impl std::error::Error for ConnectionLimitError {}

#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub current_connections: usize,
    pub current_queries: usize,
    pub max_connections: usize,
    pub max_queries: usize,
    pub load_factor: f32,
    pub degradation_level: DegradationLevel,
    pub is_graceful_shutdown: bool,
}

impl ConnectionStats {
    pub fn connection_usage_percent(&self) -> f64 {
        if self.max_connections == 0 {
            return 0.0;
        }
        (self.current_connections as f64 / self.max_connections as f64) * 100.0
    }

    pub fn query_usage_percent(&self) -> f64 {
        if self.max_queries == 0 {
            return 0.0;
        }
        (self.current_queries as f64 / self.max_queries as f64) * 100.0
    }
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self::new(
            1000,  // max_tcp_connections
            5000,  // max_concurrent_queries
            65535, // max_query_size (RFC 1035 + EDNS0, use config to override)
            65535, // max_response_size
            1000,  // max_records_per_response
            300,   // max_tcp_idle_time_secs (5 minutes)
            30,    // max_tcp_query_time_secs
        )
    }
}
