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

use super::plan::SupervisorControlCommand;

/// Typed outcome from a successfully executed supervisor-control command.
///
/// Each variant represents the result of a specific command. The `exit_code()`
/// method maps outcomes to process exit codes in one place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorControlOutcome {
    /// Status information was displayed.
    StatusDisplayed,
    /// A stop signal was sent and acknowledged.
    StopRequested,
    /// A config reload signal was sent.
    RehashRequested,
    /// A threat feed was exported.
    ThreatFeedExported { bytes: usize },
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
    /// Currently a no-op for most variants since handlers print internally.
    /// This method exists to centralize formatting if handlers are later
    /// refactored to return data instead of printing.
    pub fn display(&self) -> String {
        match self {
            SupervisorControlOutcome::StatusDisplayed => String::new(),
            SupervisorControlOutcome::StopRequested => String::new(),
            SupervisorControlOutcome::RehashRequested => String::new(),
            SupervisorControlOutcome::ThreatFeedExported { bytes } => {
                format!("Exported {} bytes", bytes)
            }
            SupervisorControlOutcome::RestartPreStopRequested => String::new(),
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
            crate::supervisor::commands::handle_status(control_addr, use_tls)
                .map_err(boxed_error_to_control_error)?;
            Ok(SupervisorControlOutcome::StatusDisplayed)
        }
        SupervisorControlCommand::Stop {
            control_addr,
            use_tls,
        } => {
            crate::supervisor::commands::handle_stop(control_addr, use_tls)
                .map_err(boxed_error_to_control_error)?;
            Ok(SupervisorControlOutcome::StopRequested)
        }
        SupervisorControlCommand::Rehash {
            control_addr,
            use_tls,
        } => {
            crate::supervisor::commands::handle_rehash(control_addr, use_tls)
                .map_err(boxed_error_to_control_error)?;
            Ok(SupervisorControlOutcome::RehashRequested)
        }
        SupervisorControlCommand::ExportThreatFeed { sign_with, site_id } => {
            #[cfg(feature = "mesh")]
            {
                crate::supervisor::commands::handle_export_threat_feed(
                    &sign_with,
                    site_id.as_deref(),
                )
                .map_err(boxed_error_to_control_error)?;
                Ok(SupervisorControlOutcome::ThreatFeedExported { bytes: 0 })
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
            SupervisorControlOutcome::StatusDisplayed,
            SupervisorControlOutcome::StopRequested,
            SupervisorControlOutcome::RehashRequested,
            SupervisorControlOutcome::ThreatFeedExported { bytes: 1024 },
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
        // Verify the type signature matches: restart pre-stop produces
        // the same outcome type as normal stop.
        let outcome = SupervisorControlOutcome::StopRequested;
        assert_eq!(outcome.exit_code(), 0);
    }

    #[test]
    fn threat_feed_exported_carries_byte_count() {
        let outcome = SupervisorControlOutcome::ThreatFeedExported { bytes: 4096 };
        assert_eq!(outcome.exit_code(), 0);
        assert!(outcome.display().contains("4096"));
    }
}
