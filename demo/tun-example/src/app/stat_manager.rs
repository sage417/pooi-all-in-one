use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};
use tokio::sync::RwLock;

use crate::session::Session;

pub type SyncStatManager = Arc<RwLock<StatManager>>;

#[allow(dead_code)]
pub struct StatManager {
    pub counters: Vec<Counter>,
}

#[allow(dead_code)]
pub struct Counter {
    pub sess: Session,
    pub bytes_recvd: Arc<AtomicU64>,
    pub bytes_sent: Arc<AtomicU64>,
    pub recv_completed: Arc<AtomicBool>,
    pub send_completed: Arc<AtomicBool>,
    pub last_peer_active: Arc<AtomicU32>,
}
