use crate::app::{
    dns::SyncDnsClient, outbound::manager::SyncOutboundManager, router::SyncRouter,
    stat_manager::SyncStatManager,
};

#[allow(dead_code)]
pub struct Dispatcher {
    router: SyncRouter,
    dns_client: SyncDnsClient,
    outbound_manager: SyncOutboundManager,
    stat_manager: SyncStatManager,
}
