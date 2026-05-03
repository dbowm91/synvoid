use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::broadcast;
use uuid::Uuid;

pub struct Broadcaster {
    sender: broadcast::Sender<String>,
    client_count: AtomicUsize,
    max_clients: usize,
}

impl Broadcaster {
    pub fn new(max_clients: usize) -> Self {
        let (sender, _) = broadcast::channel(256);
        Self {
            sender,
            client_count: AtomicUsize::new(0),
            max_clients,
        }
    }

    pub fn broadcast(&self, message: String) {
        let _ = self.sender.send(message);
    }

    pub fn client_count(&self) -> usize {
        self.client_count.load(Ordering::Relaxed)
    }

    pub fn max_clients(&self) -> usize {
        self.max_clients
    }

    pub fn new_client(&self) -> Option<(String, broadcast::Receiver<String>)> {
        if self.client_count.load(Ordering::Relaxed) >= self.max_clients {
            return None;
        }

        let client_id = Uuid::new_v4().to_string();
        let rx = self.sender.subscribe();

        self.client_count.fetch_add(1, Ordering::Relaxed);

        Some((client_id, rx))
    }

    pub fn remove_client(&self, _client_id: &str) {
        self.client_count.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn get_sender(&self) -> broadcast::Sender<String> {
        self.sender.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_broadcaster_new() {
        let broadcaster = Broadcaster::new(100);
        assert_eq!(broadcaster.client_count(), 0);
    }

    #[test]
    fn test_broadcaster_new_client() {
        let broadcaster = Broadcaster::new(100);
        let (client_id, mut rx) = broadcaster.new_client().expect("should get client");

        assert!(!client_id.is_empty());
        assert_eq!(broadcaster.client_count(), 1);

        broadcaster.broadcast("test message".to_string());

        let msg = rx.blocking_recv().expect("should receive");
        assert_eq!(msg, "test message");

        drop(rx);
    }

    #[test]
    fn test_broadcaster_remove_client() {
        let broadcaster = Broadcaster::new(100);
        let (client_id, rx) = broadcaster.new_client().expect("should get client");

        broadcaster.remove_client(&client_id);
        assert_eq!(broadcaster.client_count(), 0);
        drop(rx);
    }

    #[test]
    fn test_broadcaster_max_clients_rejected() {
        let broadcaster = Broadcaster::new(2);

        let (_id1, _rx1) = broadcaster.new_client().expect("should get client 1");
        let (_id2, _rx2) = broadcaster.new_client().expect("should get client 2");
        assert_eq!(broadcaster.client_count(), 2);

        let result = broadcaster.new_client();
        assert!(result.is_none());
        assert_eq!(broadcaster.client_count(), 2);
    }

    #[test]
    fn test_broadcaster_get_sender() {
        let broadcaster = Broadcaster::new(100);
        let sender = broadcaster.get_sender();
        let _receiver = sender.subscribe();

        let result = sender.send("test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_broadcaster_broadcast_to_receiver() {
        let broadcaster = Broadcaster::new(100);

        let (_id, mut rx) = broadcaster.new_client().expect("should get client");

        broadcaster.broadcast("hello world".to_string());

        let msg = rx
            .blocking_recv()
            .expect("should receive broadcast message");
        assert_eq!(msg, "hello world");
    }

    #[test]
    fn test_broadcaster_lagged_receiver_handled() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::sync::broadcast;
        use uuid::Uuid;

        struct SmallBroadcaster {
            sender: broadcast::Sender<String>,
            client_count: AtomicUsize,
            max_clients: usize,
        }

        impl SmallBroadcaster {
            fn new(max_clients: usize) -> Self {
                let (sender, _) = broadcast::channel(4);
                Self {
                    sender,
                    client_count: AtomicUsize::new(0),
                    max_clients,
                }
            }

            fn new_client(&self) -> Option<(String, broadcast::Receiver<String>)> {
                if self.client_count.load(Ordering::Relaxed) >= self.max_clients {
                    return None;
                }
                let client_id = Uuid::new_v4().to_string();
                let rx = self.sender.subscribe();
                self.client_count.fetch_add(1, Ordering::Relaxed);
                Some((client_id, rx))
            }
        }

        let broadcaster = SmallBroadcaster::new(1);
        let (_id1, mut rx1) = broadcaster.new_client().expect("should get client 1");

        for i in 0..10 {
            let _ = broadcaster.sender.send(format!("msg{}", i));
        }

        let result = rx1.blocking_recv();
        assert!(result.is_err());
        match result {
            Err(broadcast::error::RecvError::Lagged(_)) => {}
            _ => panic!("expected Lagged error, got {:?}", result),
        }
    }
}
