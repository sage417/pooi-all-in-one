use crate::{
    app::{
        dns::SyncDnsClient, outbound::manager::SyncOutboundManager, router::SyncRouter,
        stat_manager::SyncStatManager,
    },
    proxy::{MockOutboundDatagram, OutboundDatagram},
    session::Session,
};
#[allow(unused_imports)]
use async_recursion::async_recursion;
use std::io;

#[allow(dead_code)]
pub struct Dispatcher {
    router: SyncRouter,
    dns_client: SyncDnsClient,
    outbound_manager: SyncOutboundManager,
    stat_manager: SyncStatManager,
}

impl Dispatcher {
    pub async fn dispatch_datagram(
        &self,
        mut sess: Session,
    ) -> io::Result<Box<dyn OutboundDatagram>> {
        let _ = sess;
        io::Result::Ok(Box::new(MockOutboundDatagram {}))
    }
}
