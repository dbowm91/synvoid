use axum::extract::ws::Message;
use futures::stream::StreamExt;
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
