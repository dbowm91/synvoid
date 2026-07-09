use parking_lot::RwLock;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct TimerEntry {
    pub interval_secs: u64,
    pub function_name: String,
    pub topic: String,
    pub last_fired: Instant,
}

impl TimerEntry {
    pub fn new(interval_secs: u64, function_name: String, topic: String) -> Self {
        Self {
            interval_secs,
            function_name,
            topic,
            last_fired: Instant::now(),
        }
    }

    pub fn should_fire(&self) -> bool {
        self.last_fired.elapsed() >= Duration::from_secs(self.interval_secs)
    }

    pub fn mark_fired(&mut self) {
        self.last_fired = Instant::now();
    }
}

pub struct ServerlessScheduler {
    timers: RwLock<HashMap<String, TimerEntry>>,
}

impl ServerlessScheduler {
    pub fn new() -> Self {
        Self {
            timers: RwLock::new(HashMap::new()),
        }
    }

    pub fn add_timer(&self, interval_secs: u64, function_name: String, topic: String) {
        let entry = TimerEntry::new(interval_secs, function_name.clone(), topic);
        self.timers.write().insert(function_name, entry);
        tracing::debug!("Added timer with interval {} seconds", interval_secs);
    }

    pub fn remove_timer(&self, function_name: &str) {
        if self.timers.write().remove(function_name).is_some() {
            tracing::debug!("Removed timer for function {}", function_name);
        }
    }

    pub fn list_timers(&self) -> Vec<(String, u64, String)> {
        self.timers
            .read()
            .iter()
            .map(|(name, entry)| (name.clone(), entry.interval_secs, entry.topic.clone()))
            .collect()
    }

    pub fn check_and_fire(&self) -> Vec<(String, String)> {
        let mut fired_events = Vec::new();
        let mut timers = self.timers.write();

        for (_, entry) in timers.iter_mut() {
            if entry.should_fire() {
                entry.mark_fired();
                tracing::info!(
                    "Timer fired for function '{}' (topic: '{}')",
                    entry.function_name,
                    entry.topic
                );
                fired_events.push((entry.topic.clone(), entry.payload()));
            }
        }

        fired_events
    }

    pub fn get_timer(&self, function_name: &str) -> Option<TimerEntry> {
        self.timers.read().get(function_name).cloned()
    }

    pub fn clear_all(&self) {
        self.timers.write().clear();
    }
}

impl Default for ServerlessScheduler {
    fn default() -> Self {
        Self::new()
    }
}

pub trait TimerPayload {
    fn payload(&self) -> String;
}

impl TimerPayload for TimerEntry {
    fn payload(&self) -> String {
        let now = chrono::Utc::now();
        serde_json::json!({
            "source": "scheduler",
            "function": self.function_name,
            "topic": self.topic,
            "interval_secs": self.interval_secs,
            "timestamp": now.to_rfc3339(),
            "unix_ts": now.timestamp(),
        })
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timer_entry_creation() {
        let entry = TimerEntry::new(60, "test_func".to_string(), "test_topic".to_string());
        assert_eq!(entry.interval_secs, 60);
        assert_eq!(entry.function_name, "test_func");
        assert_eq!(entry.topic, "test_topic");
    }

    #[test]
    fn test_scheduler_add_remove() {
        let scheduler = ServerlessScheduler::new();
        scheduler.add_timer(3600, "hourly_func".to_string(), "hourly".to_string());

        let timers = scheduler.list_timers();
        assert_eq!(timers.len(), 1);
        assert_eq!(timers[0].0, "hourly_func");

        scheduler.remove_timer("hourly_func");
        let timers = scheduler.list_timers();
        assert_eq!(timers.len(), 0);
    }

    #[test]
    fn test_should_fire() {
        // Timer with interval 1 should not fire immediately after creation (needs at least 1 second)
        let entry = TimerEntry::new(1, "test".to_string(), "topic".to_string());
        assert!(
            !entry.should_fire(),
            "Timer should not fire immediately after creation"
        );

        // Timer with interval 0 fires immediately
        let entry2 = TimerEntry::new(0, "test2".to_string(), "topic".to_string());
        assert!(
            entry2.should_fire(),
            "Timer with interval 0 should fire immediately"
        );

        // Wait a tiny bit and mark fired - with interval 0, it will fire again immediately
        // Use interval 1 for the next test
        let mut entry3 = TimerEntry::new(1, "test3".to_string(), "topic".to_string());
        std::thread::sleep(std::time::Duration::from_millis(10));
        entry3.mark_fired();
        // After marking fired with interval 1, less than 1 second has passed since mark_fired
        // So should_fire should return false
        assert!(
            !entry3.should_fire(),
            "Timer should not fire immediately after mark_fired"
        );
    }
}
