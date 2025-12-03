use std::{io, marker::PhantomData, net::SocketAddr, time::Duration};

use bytes::Bytes;
use lru::LruCache;
use tokio::task::JoinHandle;

use crate::proxy::inbound::socks5::SocksAddr;

/// Writer for sending packets back to client
#[trait_variant::make(Send)]
pub trait UdpInboundWrite {
    /// Sends packet `data` received from `remote_addr` back to `peer_addr`
    async fn send_to(
        &self,
        peer_addr: SocketAddr,
        remote_addr: &SocksAddr,
        data: &[u8],
    ) -> io::Result<()>;
}

type AssociationMap<W> = LruCache<SocketAddr, UdpAssociation<W>>;

/// UDP association manager
pub struct UdpAssociationManager<W>
where
    W: UdpInboundWrite + Clone + Send + Sync + Unpin + 'static,
{
    respond_writer: W,
    // context: Arc<ServiceContext>,
    assoc_map: AssociationMap<W>,
    keepalive_tx: tokio::sync::mpsc::Sender<SocketAddr>,
    // balancer: PingBalancer,
    server_session_expire_duration: Duration,
}

struct UdpAssociation<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    assoc_handle: JoinHandle<()>,
    sender: tokio::sync::mpsc::Sender<(SocksAddr, Bytes)>,
    writer: PhantomData<W>,
}

impl<W> UdpAssociationManager<W>
where
    W: UdpInboundWrite + Clone + Send + Sync + Unpin + 'static,
{
    /// Create a new `UdpAssociationManager`
    ///
    /// Returns (`UdpAssociationManager`, Cleanup Interval, Keep-alive Receiver<SocketAddr>)
    pub fn new(
        // context: Arc<ServiceContext>,
        respond_writer: W,
        ttl: Option<Duration>,
        capacity: Option<usize>,
        // balancer: PingBalancer,
    ) -> (Self, Duration, tokio::sync::mpsc::Receiver<SocketAddr>) {
        todo!();
    }

    pub async fn send_to(
        &mut self,
        peer_addr: SocketAddr,
        mut target_addr: SocksAddr,
        data: &[u8],
    ) -> io::Result<()> {
        todo!();
    }

        /// Cleanup expired associations
    pub async fn cleanup_expired(&mut self) {
        self.assoc_map.iter();
    }

    /// Keep-alive association
    pub async fn keep_alive(&mut self, peer_addr: &SocketAddr) {
        self.assoc_map.get(peer_addr);
    }
}
