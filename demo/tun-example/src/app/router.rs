use std::sync::Arc;
use tokio::sync::RwLock;

use crate::app::{dns::SyncDnsClient, session::Session};

pub type SyncRouter = Arc<RwLock<Router>>;

#[allow(dead_code)]
pub struct Router {
    rules: Vec<Rule>,
    domain_resolve: bool,
    dns_client: SyncDnsClient,
}

#[allow(dead_code)]
pub trait Condition: Send + Sync + Unpin {
    fn apply(&self, sess: &Session) -> bool;
}

#[allow(dead_code)]
struct Rule {
    target: String,
    condition: Box<dyn Condition>,
}


