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
