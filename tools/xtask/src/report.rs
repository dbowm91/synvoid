use serde::{Deserialize, Serialize};

/// A single step result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub name: String,
    pub command: String,
    pub status: StepStatus,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StepStatus {
    Success,
    Failed,
    Skipped,
    DryRun,
}

/// Budget severity level.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BudgetSeverity {
    Ok,
    Warning,
    Blocking,
}

/// A budget threshold check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetCheck {
    pub metric: String,
    pub actual: String,
    pub threshold: String,
    pub severity: BudgetSeverity,
    pub message: String,
}

/// Summary report for a lane run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaneReport {
    pub lane: String,
    pub total_steps: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub skipped: usize,
    pub total_duration_ms: u64,
    pub steps: Vec<StepResult>,
    pub failed_items: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub budget_checks: Vec<BudgetCheck>,
}

impl LaneReport {
    pub fn new(lane: &str) -> Self {
        Self {
            lane: lane.to_string(),
            total_steps: 0,
            succeeded: 0,
            failed: 0,
            skipped: 0,
            total_duration_ms: 0,
            steps: Vec::new(),
            failed_items: Vec::new(),
            budget_checks: Vec::new(),
        }
    }

    pub fn add_result(&mut self, result: StepResult) {
        self.total_steps += 1;
        self.total_duration_ms += result.duration_ms;
        match result.status {
            StepStatus::Success => self.succeeded += 1,
            StepStatus::Failed => {
                self.failed += 1;
                self.failed_items.push(result.name.clone());
            }
            StepStatus::Skipped => self.skipped += 1,
            StepStatus::DryRun => self.succeeded += 1,
        }
        self.steps.push(result);
    }

    pub fn is_success(&self) -> bool {
        self.failed == 0
    }

    /// Run budget checks against performance thresholds from
    /// `docs/testing/performance-budgets.md`.
    pub fn check_budgets(&mut self) {
        self.budget_checks.clear();

        // PR fast lane: <10 min warning, >15 min blocking
        if self.lane == "fast" {
            let duration_secs = self.total_duration_ms as f64 / 1000.0;
            let duration_mins = duration_secs / 60.0;

            if duration_mins > 15.0 {
                self.budget_checks.push(BudgetCheck {
                    metric: "PR fast total duration".to_string(),
                    actual: format!("{duration_mins:.1} min"),
                    threshold: ">15 min".to_string(),
                    severity: BudgetSeverity::Blocking,
                    message: "PR fast lane exceeds blocking threshold".to_string(),
                });
            } else if duration_mins > 10.0 {
                self.budget_checks.push(BudgetCheck {
                    metric: "PR fast total duration".to_string(),
                    actual: format!("{duration_mins:.1} min"),
                    threshold: ">10 min".to_string(),
                    severity: BudgetSeverity::Warning,
                    message: "PR fast lane exceeds warning threshold".to_string(),
                });
            } else {
                self.budget_checks.push(BudgetCheck {
                    metric: "PR fast total duration".to_string(),
                    actual: format!("{duration_mins:.1} min"),
                    threshold: "<10 min".to_string(),
                    severity: BudgetSeverity::Ok,
                    message: "Within budget".to_string(),
                });
            }
        }

        // Cargo invocation count check
        let cargo_invocations: usize = self
            .steps
            .iter()
            .filter(|s| s.command.starts_with("cargo ") && s.status != StepStatus::DryRun)
            .count();

        if self.lane == "fast" && cargo_invocations > 50 {
            self.budget_checks.push(BudgetCheck {
                metric: "Cargo invocations (PR fast)".to_string(),
                actual: cargo_invocations.to_string(),
                threshold: ">50".to_string(),
                severity: BudgetSeverity::Blocking,
                message: "Too many Cargo invocations in PR fast lane".to_string(),
            });
        } else if self.lane == "fast" && cargo_invocations > 40 {
            self.budget_checks.push(BudgetCheck {
                metric: "Cargo invocations (PR fast)".to_string(),
                actual: cargo_invocations.to_string(),
                threshold: ">40".to_string(),
                severity: BudgetSeverity::Warning,
                message: "Cargo invocation count approaching budget".to_string(),
            });
        }

        // Slow step check (>30s warning, >60s blocking)
        for step in &self.steps {
            if step.status == StepStatus::DryRun || step.duration_ms == 0 {
                continue;
            }
            let step_secs = step.duration_ms as f64 / 1000.0;
            if step_secs > 60.0 {
                self.budget_checks.push(BudgetCheck {
                    metric: format!("step '{}' duration", step.name),
                    actual: format!("{step_secs:.1}s"),
                    threshold: ">60s".to_string(),
                    severity: BudgetSeverity::Blocking,
                    message: format!("Step '{}' exceeds 60s blocking threshold", step.name),
                });
            } else if step_secs > 30.0 {
                self.budget_checks.push(BudgetCheck {
                    metric: format!("step '{}' duration", step.name),
                    actual: format!("{step_secs:.1}s"),
                    threshold: ">30s".to_string(),
                    severity: BudgetSeverity::Warning,
                    message: format!("Step '{}' exceeds 30s warning threshold", step.name),
                });
            }
        }

        // Warn on any failed steps
        if self.failed > 0 {
            self.budget_checks.push(BudgetCheck {
                metric: "step failures".to_string(),
                actual: self.failed.to_string(),
                threshold: "0".to_string(),
                severity: BudgetSeverity::Blocking,
                message: format!("{} step(s) failed", self.failed),
            });
        }
    }

    /// Get the number of blocking budget breaches.
    pub fn blocking_breaches(&self) -> usize {
        self.budget_checks
            .iter()
            .filter(|c| c.severity == BudgetSeverity::Blocking)
            .count()
    }

    /// Get the number of warning budget breaches.
    pub fn warning_breaches(&self) -> usize {
        self.budget_checks
            .iter()
            .filter(|c| c.severity == BudgetSeverity::Warning)
            .count()
    }
}

impl std::fmt::Display for LaneReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "═══ {} ═══", self.lane.to_uppercase())?;
        writeln!(f)?;

        for step in &self.steps {
            let icon = match step.status {
                StepStatus::Success | StepStatus::DryRun => "✓",
                StepStatus::Failed => "✗",
                StepStatus::Skipped => "⊘",
            };
            writeln!(f, "  {icon} {}", step.name)?;
            writeln!(f, "    {}", step.command)?;
            if step.duration_ms > 0 && step.status != StepStatus::DryRun {
                let secs = step.duration_ms as f64 / 1000.0;
                writeln!(f, "    ({secs:.1}s)")?;
            }
        }

        writeln!(f)?;
        writeln!(
            f,
            "Total: {} steps | {} passed | {} failed | {} skipped",
            self.total_steps, self.succeeded, self.failed, self.skipped
        )?;

        let total_secs = self.total_duration_ms as f64 / 1000.0;
        writeln!(f, "Duration: {total_secs:.1}s")?;

        // Budget summary
        let blocking = self.blocking_breaches();
        let warnings = self.warning_breaches();
        if blocking > 0 || warnings > 0 {
            writeln!(f)?;
            writeln!(f, "Budget: {blocking} blocking, {warnings} warnings")?;
            for check in &self.budget_checks {
                if check.severity != BudgetSeverity::Ok {
                    let icon = match check.severity {
                        BudgetSeverity::Blocking => "⛔",
                        BudgetSeverity::Warning => "⚠️ ",
                        BudgetSeverity::Ok => "✓",
                    };
                    writeln!(
                        f,
                        "  {icon} {}: {} (threshold: {})",
                        check.metric, check.actual, check.threshold
                    )?;
                }
            }
        }

        if !self.failed_items.is_empty() {
            writeln!(f)?;
            writeln!(f, "Failed items:")?;
            for item in &self.failed_items {
                writeln!(f, "  - {item}")?;
            }
        }

        Ok(())
    }
}
