//! Root-test ownership: COMPOSITION
//! Rationale: validates supervisor lifecycle across worker and supervisor

#[cfg(test)]
mod overseer_lifecycle_tests {
    use synvoid::process::WorkerId;
    use synvoid::supervisor::drain_manager::DrainManager;

    #[test]
    fn test_drain_manager_start_drain() {
        let manager = DrainManager::new(100);

        let drain_id = manager.start_drain(30);
        assert!(drain_id > 0);
        assert_eq!(manager.get_drain_status().drain_id, drain_id);
    }

    #[test]
    fn test_drain_manager_register_worker() {
        let manager = DrainManager::new(100);

        manager.start_drain(30);
        manager.register_worker(WorkerId(1), 10, 5);

        let status = manager.get_drain_status();
        assert_eq!(status.active_connections, 10);
        assert_eq!(status.idle_connections, 5);
    }

    #[test]
    fn test_drain_manager_multiple_workers() {
        let manager = DrainManager::new(100);

        manager.start_drain(60);
        manager.register_worker(WorkerId(1), 20, 10);
        manager.register_worker(WorkerId(2), 15, 8);
        manager.register_worker(WorkerId(3), 10, 5);

        let total = manager.total_active_connections();
        assert_eq!(total, 45);
    }

    #[test]
    fn test_drain_manager_update_connections() {
        let manager = DrainManager::new(100);

        manager.start_drain(30);
        manager.register_worker(WorkerId(1), 10, 5);

        manager.update_worker_connections(&WorkerId(1), 5, 5);

        let total = manager.total_active_connections();
        assert_eq!(total, 5);
    }

    #[test]
    fn test_drain_manager_mark_stopped_accepting() {
        let manager = DrainManager::new(100);

        manager.start_drain(30);
        manager.register_worker(WorkerId(1), 0, 10);

        manager.mark_worker_stopped_accepting(&WorkerId(1));

        assert!(manager.all_workers_drained());
    }

    #[test]
    fn test_drain_manager_mark_drain_complete() {
        let manager = DrainManager::new(100);

        manager.start_drain(30);
        manager.register_worker(WorkerId(1), 0, 0);

        manager.mark_worker_drain_complete(&WorkerId(1), 100);

        let status = manager.get_drain_status();
        assert!(status.drain_complete);
    }

    #[test]
    fn test_drain_manager_clear() {
        let manager = DrainManager::new(100);

        manager.start_drain(30);
        manager.register_worker(WorkerId(1), 10, 5);

        manager.clear();

        assert!(!manager.get_drain_status().is_draining);
        assert_eq!(manager.total_active_connections(), 0);
    }

    #[test]
    fn test_drain_manager_worker_status() {
        let manager = DrainManager::new(100);

        manager.start_drain(30);
        manager.register_worker(WorkerId(1), 10, 5);

        let status = manager.get_worker_status(&WorkerId(1));
        assert!(status.is_some());
        let worker_status = status.unwrap();
        assert_eq!(worker_status.active_connections, 10);
        assert_eq!(worker_status.idle_connections, 5);
    }

    #[test]
    fn test_drain_manager_not_all_drained_initially() {
        let manager = DrainManager::new(100);

        manager.start_drain(30);
        manager.register_worker(WorkerId(1), 10, 5);

        manager.register_worker(WorkerId(2), 5, 3);

        assert!(!manager.all_workers_drained());
    }

    #[test]
    fn test_drain_manager_all_drained_when_complete() {
        let manager = DrainManager::new(100);

        manager.start_drain(30);
        manager.register_worker(WorkerId(1), 0, 0);
        manager.register_worker(WorkerId(2), 0, 0);

        manager.mark_worker_stopped_accepting(&WorkerId(1));
        manager.mark_worker_stopped_accepting(&WorkerId(2));

        assert!(manager.all_workers_drained());
    }
}
