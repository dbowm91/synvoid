use super::plan::{
    CommandPlan, CommandPreAction, OneShotCommand, RuntimeCommand, SynvoidCommandPlan,
};
use super::runtime_launch::execute_runtime as runtime_launch_execute;
use super::supervisor_control::{execute_restart_pre_stop, execute_supervisor_control_command};

use super::one_shot::execute_one_shot_command;

/// Execute a command plan. This is the main entry point after command planning.
///
/// Returns a process exit code.
pub fn execute_command(mut plan: CommandPlan) -> i32 {
    // Handle restart pre-action before executing the main plan.
    // Uses the same typed supervisor-control adapter as normal stop.
    if let Some(CommandPreAction::RestartSupervisor {
        control_addr,
        use_tls,
    }) = plan.pre_action.take()
    {
        if let Err(e) = execute_restart_pre_stop(control_addr, use_tls) {
            eprintln!("Restart pre-stop failed: {}", e);
            return e.exit_code();
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // Take ownership of the inner plan to avoid partial move issues
    let inner = std::mem::replace(
        &mut plan.plan,
        SynvoidCommandPlan::Runtime(RuntimeCommand::Supervisor),
    );

    match inner {
        SynvoidCommandPlan::OneShot(cmd) => execute_one_shot(cmd),
        SynvoidCommandPlan::SupervisorControl(cmd) => execute_supervisor_control(cmd),
        SynvoidCommandPlan::Runtime(cmd) => execute_runtime(cmd, &plan),
    }
}

/// Execute a one-shot command that completes without launching the server runtime.
///
/// Delegates to the typed one-shot adapter which maps commands to outcomes/errors.
/// Exit codes are derived from the typed result, not ad-hoc branching.
fn execute_one_shot(command: OneShotCommand) -> i32 {
    match execute_one_shot_command(command) {
        Ok(outcome) => {
            if let Some(text) = outcome.display() {
                println!("{}", text);
            }
            outcome.exit_code()
        }
        Err(e) => {
            eprintln!("{}", e);
            e.exit_code()
        }
    }
}

/// Execute a supervisor-control command sent via IPC to a running instance.
///
/// Delegates to the typed adapter which maps commands to outcomes/errors.
/// Exit codes are derived from the typed result, not ad-hoc branching.
fn execute_supervisor_control(command: super::plan::SupervisorControlCommand) -> i32 {
    match execute_supervisor_control_command(command) {
        Ok(outcome) => {
            if let Some(text) = outcome.display() {
                println!("{}", text);
            }
            outcome.exit_code()
        }
        Err(e) => {
            eprintln!("{}", e);
            e.exit_code()
        }
    }
}

/// Execute a runtime launch command that starts a long-running process.
///
/// Delegates to the runtime-launch boundary in `runtime_launch.rs`.
fn execute_runtime(command: super::plan::RuntimeCommand, plan: &CommandPlan) -> i32 {
    runtime_launch_execute(command, plan)
}
