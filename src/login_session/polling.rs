use crate::authentication_client::AuthenticationClient;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

pub enum Message {
    Closed,
}

#[derive(Debug, Default)]
struct Polling {
    started_time: Option<chrono::DateTime<chrono::Utc>>,
    canceled: bool,
}

pub async fn start_polling(
    handler: Arc<Mutex<AuthenticationClient>>,
) -> (JoinHandle<()>, mpsc::Sender<Message>) {
    let (tx, mut rx) = mpsc::channel::<Message>(10);
    let handle = tokio::spawn(async move {
        let mut polling = Polling::default();
        
        while let Some(message) = rx.recv().await {
            if polling.canceled {
                break;
            }
            
            if polling.started_time.is_none() {
                polling.started_time = Some(chrono::Utc::now());
            }
            
            let response = {
                let mut handler_lock = handler.lock().await;
            };
        }
    });

    (handle, tx)
}

struct Session {
    shared: Arc<Mutex<SessionShared>>,
}

struct SessionShared {
    number: u8,
}

impl Session {
    pub fn start_polling(&self) {
    
    }

    pub async fn get_number(&self) -> u8 {
        self.shared.lock().await.number
    }
}