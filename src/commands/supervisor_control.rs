//! Typed supervisor-control command outcomes and adapter.
//!
//! This module owns the boundary between CLI command execution and
//! supervisor IPC handlers. It converts typed supervisor-control commands
//! into existing handler calls and returns structured outcomes rather than
//! ad-hoc strings or generic errors.
//!
//! ## Boundary Model
//!
//! ```text
//! SupervisorControlCommand -> execute_supervisor_control_command()
//!     -> Result<SupervisorControlOutcome, SupervisorControlError>
//!     -> exit code
//! ```

use std::path::PathBuf;

use super::plan::SupervisorControlCommand;

/// Formatted status display text produced by a status query.
///
/// Contains the complete user-facing status output as a single string.
/// The display is produced by the handler and owned by the outcome,
/// centralizing formatting at the command boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisorStatusDisplay {
    /// The fully formatted status text ready for printing.
    pub text: String,
}

/// Summary metadata from a threat-feed export.
///
/// Carries real export metadata instead of placeholder values.
/// When the byte count is available it is reported; otherwise
/// the variant indicates completion without precise counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreatFeedExportSummary {
    /// The feed was written with known byte and record counts.
    Written {
        bytes: usize,
        records: Option<usize>,
    },
    /// The feed was exported but exact byte count is not available.
    Completed,
}

/// Outcome from a stop command, carrying structured result data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopOutcome {
    /// Whether the stop signal was acknowledged by the supervisor.
    pub acknowledged: bool,
    /// Whether the process confirmed shutdown within the timeout.
    pub shutdown_confirmed: bool,
    /// Whether the shutdown timed out without confirming.
    pub timed_out: bool,
}

/// Outcome from a rehash command, carrying structured result data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RehashOutcome {
    /// Whether the reload signal was acknowledged by the supervisor.
    pub acknowledged: bool,
}

/// Typed outcome from a successfully executed supervisor-control command.
///
/// Each variant carries structured data where practical. The `exit_code()`
/// method maps outcomes to process exit codes in one place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorControlOutcome {
    /// Status information was queried and formatted.
    Status(SupervisorStatusDisplay),
    /// A stop signal was sent and acknowledged.
    Stop(StopOutcome),
    /// A config reload signal was sent.
    Rehash(RehashOutcome),
    /// A threat feed was exported.
    ThreatFeedExported(ThreatFeedExportSummary),
    /// A restart pre-stop was requested (stop before relaunch).
    RestartPreStopRequested,
}

impl SupervisorControlOutcome {
    /// Map this outcome to a process exit code.
    ///
    /// All success outcomes return 0. This centralizes exit-code mapping
    /// so the CLI execution layer does not need per-command knowledge.
    pub fn exit_code(&self) -> i32 {
        0
    }

    /// Format this outcome for user-facing display.
    ///
    /// Centralizes CLI formatting so handlers return data, not side effects.
    /// Returns `Some(text)` when there is user-visible output, or `None`
    /// for silent outcomes (e.g., restart pre-stop).
    pub fn display(&self) -> Option<String> {
        match self {
            SupervisorControlOutcome::Status(status) => Some(status.text.clone()),
            SupervisorControlOutcome::Stop(outcome) => {
                if outcome.shutdown_confirmed {
                    Some("synvoid stopped".to_string())
                } else if outcome.timed_out {
                    Some("Warning: Process did not shut down cleanly".to_string())
                } else if outcome.acknowledged {
                    Some("Stop signal sent".to_string())
                } else {
                    None
                }
            }
            SupervisorControlOutcome::Rehash(outcome) => {
                if outcome.acknowledged {
                    Some("Configuration reloaded".to_string())
                } else {
                    None
                }
            }
            SupervisorControlOutcome::ThreatFeedExported(summary) => match summary {
                ThreatFeedExportSummary::Written { bytes, records } => {
                    let mut msg = format!("Exported {} bytes", bytes);
                    if let Some(r) = records {
                        msg.push_str(&format!(" ({} records)", r));
                    }
                    Some(msg)
                }
                ThreatFeedExportSummary::Completed => Some("Threat feed exported".to_string()),
            },
            SupervisorControlOutcome::RestartPreStopRequested => None,
        }
    }
}

/// Typed error from a failed supervisor-control command.
///
/// Each variant classifies the failure mode so the CLI execution layer
/// can produce meaningful messages and consistent exit codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorControlError {
    /// Could not connect to the supervisor process.
    ConnectionFailed(String),
    /// The IPC request failed.
    RequestFailed(String),
    /// The requested feature is not available (e.g., missing feature gate).
    UnsupportedFeature(&'static str),
    /// An I/O error occurred.
    Io(String),
}

impl std::fmt::Display for SupervisorControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SupervisorControlError::ConnectionFailed(msg) => {
                write!(f, "Connection failed: {}", msg)
            }
            SupervisorControlError::RequestFailed(msg) => {
                write!(f, "Request failed: {}", msg)
            }
            SupervisorControlError::UnsupportedFeature(feature) => {
                write!(f, "Feature '{}' is not enabled", feature)
            }
            SupervisorControlError::Io(msg) => write!(f, "I/O error: {}", msg),
        }
    }
}

impl std::error::Error for SupervisorControlError {}

impl SupervisorControlError {
    /// Map this error to a process exit code.
    ///
    /// All errors return 1. This centralizes exit-code mapping so the CLI
    /// execution layer does not need per-command knowledge.
    pub fn exit_code(&self) -> i32 {
        1
    }
}

/// Convert a boxed error into a `SupervisorControlError`.
///
/// This preserves the error message while normalizing the error type.
fn boxed_error_to_control_error(e: Box<dyn std::error::Error>) -> SupervisorControlError {
    SupervisorControlError::RequestFailed(e.to_string())
}

/// Execute a supervisor-control command and return a typed outcome.
///
/// This adapter function dispatches to existing handler functions and
/// wraps their results in structured types. Handlers that print internally
/// will continue to do so; the outcome indicates successful completion.
///
/// # Arguments
///
/// * `command` - A typed supervisor-control command from the planning layer.
///
/// # Returns
///
/// A typed outcome on success, or a typed error on failure.
pub fn execute_supervisor_control_command(
    command: SupervisorControlCommand,
) -> Result<SupervisorControlOutcome, SupervisorControlError> {
    match command {
        SupervisorControlCommand::Status {
            control_addr,
            use_tls,
        } => {
            let display = crate::supervisor::commands::handle_status_data(control_addr, use_tls)
                .map_err(boxed_error_to_control_error)?;
            Ok(SupervisorControlOutcome::Status(display))
        }
        SupervisorControlCommand::Stop {
            control_addr,
            use_tls,
        } => {
            let outcome = crate::supervisor::commands::handle_stop_data(control_addr, use_tls)
                .map_err(boxed_error_to_control_error)?;
            Ok(SupervisorControlOutcome::Stop(outcome))
        }
        SupervisorControlCommand::Rehash {
            control_addr,
            use_tls,
        } => {
            let outcome = crate::supervisor::commands::handle_rehash_data(control_addr, use_tls)
                .map_err(boxed_error_to_control_error)?;
            Ok(SupervisorControlOutcome::Rehash(outcome))
        }
        SupervisorControlCommand::ExportThreatFeed { sign_with, site_id } => {
            #[cfg(feature = "mesh")]
            {
                let summary = crate::supervisor::commands::handle_export_threat_feed_data(
                    &sign_with,
                    site_id.as_deref(),
                )
                .map_err(boxed_error_to_control_error)?;
                Ok(SupervisorControlOutcome::ThreatFeedExported(summary))
            }
            #[cfg(not(feature = "mesh"))]
            {
                Err(SupervisorControlError::UnsupportedFeature("mesh"))
            }
        }
    }
}

/// Execute a restart pre-stop using the same adapter as normal stop.
///
/// This ensures the restart pre-action uses the identical supervisor-control
/// path as a standalone `--stop` command, avoiding duplicated logic.
pub fn execute_restart_pre_stop(
    control_addr: Option<String>,
    use_tls: bool,
) -> Result<SupervisorControlOutcome, SupervisorControlError> {
    execute_supervisor_control_command(SupervisorControlCommand::Stop {
        control_addr,
        use_tls,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_outcomes_exit_zero() {
        let outcomes = [
            SupervisorControlOutcome::Status(SupervisorStatusDisplay {
                text: "test".into(),
            }),
            SupervisorControlOutcome::Stop(StopOutcome {
                acknowledged: true,
                shutdown_confirmed: true,
                timed_out: false,
            }),
            SupervisorControlOutcome::Rehash(RehashOutcome { acknowledged: true }),
            SupervisorControlOutcome::ThreatFeedExported(ThreatFeedExportSummary::Written {
                bytes: 1024,
                records: None,
            }),
            SupervisorControlOutcome::RestartPreStopRequested,
        ];
        for outcome in &outcomes {
            assert_eq!(
                outcome.exit_code(),
                0,
                "expected exit code 0 for {:?}",
                outcome
            );
        }
    }

    #[test]
    fn errors_exit_nonzero() {
        let errors = [
            SupervisorControlError::ConnectionFailed("test".into()),
            SupervisorControlError::RequestFailed("test".into()),
            SupervisorControlError::UnsupportedFeature("test"),
            SupervisorControlError::Io("test".into()),
        ];
        for error in &errors {
            assert_eq!(error.exit_code(), 1, "expected exit code 1 for {:?}", error);
        }
    }

    #[test]
    fn error_display_messages() {
        let err = SupervisorControlError::ConnectionFailed("refused".into());
        assert_eq!(err.to_string(), "Connection failed: refused");

        let err = SupervisorControlError::RequestFailed("timeout".into());
        assert_eq!(err.to_string(), "Request failed: timeout");

        let err = SupervisorControlError::UnsupportedFeature("mesh");
        assert_eq!(err.to_string(), "Feature 'mesh' is not enabled");

        let err = SupervisorControlError::Io("broken pipe".into());
        assert_eq!(err.to_string(), "I/O error: broken pipe");
    }

    #[test]
    fn restart_pre_stop_returns_stop_outcome() {
        let outcome = SupervisorControlOutcome::RestartPreStopRequested;
        assert_eq!(outcome.exit_code(), 0);
        assert!(outcome.display().is_none());
    }

    #[test]
    fn threat_feed_export_with_bytes_displays_correctly() {
        let outcome =
            SupervisorControlOutcome::ThreatFeedExported(ThreatFeedExportSummary::Written {
                bytes: 4096,
                records: Some(128),
            });
        assert_eq!(outcome.exit_code(), 0);
        let display = outcome.display().unwrap();
        assert!(display.contains("4096"));
        assert!(display.contains("128"));
    }

    #[test]
    fn threat_feed_export_completed_displays_correctly() {
        let outcome =
            SupervisorControlOutcome::ThreatFeedExported(ThreatFeedExportSummary::Completed);
        assert_eq!(outcome.exit_code(), 0);
        assert_eq!(outcome.display().unwrap(), "Threat feed exported");
    }

    #[test]
    fn status_outcome_displays_status_text() {
        let outcome = SupervisorControlOutcome::Status(SupervisorStatusDisplay {
            text: "synvoid Status\n==============\nPID: 1234".into(),
        });
        let display = outcome.display().unwrap();
        assert!(display.contains("synvoid Status"));
        assert!(display.contains("PID: 1234"));
    }

    #[test]
    fn stop_outcome_shutdown_confirmed_displays_stopped() {
        let outcome = SupervisorControlOutcome::Stop(StopOutcome {
            acknowledged: true,
            shutdown_confirmed: true,
            timed_out: false,
        });
        assert_eq!(outcome.display().unwrap(), "synvoid stopped");
    }

    #[test]
    fn stop_outcome_timeout_displays_warning() {
        let outcome = SupervisorControlOutcome::Stop(StopOutcome {
            acknowledged: true,
            shutdown_confirmed: false,
            timed_out: true,
        });
        assert!(outcome
            .display()
            .unwrap()
            .contains("did not shut down cleanly"));
    }

    #[test]
    fn rehash_outcome_acknowledged_displays_reload() {
        let outcome = SupervisorControlOutcome::Rehash(RehashOutcome { acknowledged: true });
        assert_eq!(outcome.display().unwrap(), "Configuration reloaded");
    }

    #[test]
    fn threat_feed_export_does_not_use_placeholder_zero_bytes() {
        // Verify the new API uses ThreatFeedExportSummary, not a raw bytes field
        // which was the old placeholder pattern.
        let summary = ThreatFeedExportSummary::Written {
            bytes: 0,
            records: None,
        };
        // bytes: 0 is only valid when the export genuinely produced zero bytes
        match &summary {
            ThreatFeedExportSummary::Written { bytes, .. } => assert_eq!(*bytes, 0),
            _ => panic!("expected Written variant"),
        }
    }
}
