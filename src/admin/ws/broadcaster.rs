use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;
use uuid::Uuid;

pub struct Broadcaster {
    sender: broadcast::Sender<String>,
    clients: Arc<RwLock<HashMap<String, broadcast::Sender<String>>>>,
    max_clients: usize,
}

impl Broadcaster {
    pub fn new(max_clients: usize) -> Self {
        let (sender, _) = broadcast::channel(256);
        Self {
            sender,
            clients: Arc::new(RwLock::new(HashMap::new())),
            max_clients,
        }
    }

    pub fn broadcast(&self, message: String) {
        let _ = self.sender.send(message);
    }

    pub fn client_count(&self) -> usize {
        self.clients.read().len()
    }

    pub fn new_client(&self) -> (String, broadcast::Receiver<String>) {
        let mut clients = self.clients.write();

        if clients.len() >= self.max_clients {
            let oldest = clients.keys().next().cloned();
            if let Some(id) = oldest {
                clients.remove(&id);
            }
        }

        let client_id = Uuid::new_v4().to_string();
        let (tx, rx) = broadcast::channel(64);

        clients.insert(client_id.clone(), tx);

        (client_id, rx)
    }

    pub fn remove_client(&self, client_id: &str) {
        self.clients.write().remove(client_id);
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
        let (client_id, rx) = broadcaster.new_client();

        assert!(!client_id.is_empty());
        assert_eq!(broadcaster.client_count(), 1);
        drop(rx);
    }

    #[test]
    fn test_broadcaster_remove_client() {
        let broadcaster = Broadcaster::new(100);
        let (client_id, rx) = broadcaster.new_client();

        broadcaster.remove_client(&client_id);
        assert_eq!(broadcaster.client_count(), 0);
        drop(rx);
    }

    #[test]
    fn test_broadcaster_max_clients_eviction() {
        let broadcaster = Broadcaster::new(2);

        let (_id1, rx1) = broadcaster.new_client();
        let (_id2, rx2) = broadcaster.new_client();
        let (_id3, rx3) = broadcaster.new_client();

        assert_eq!(broadcaster.client_count(), 2);

        drop(rx1);
        drop(rx2);
        drop(rx3);
    }

    #[test]
    fn test_broadcaster_get_sender() {
        let broadcaster = Broadcaster::new(100);
        let sender = broadcaster.get_sender();
        let _receiver = sender.subscribe();

        let result = sender.send("test".to_string());
        assert!(result.is_ok());
    }
}
