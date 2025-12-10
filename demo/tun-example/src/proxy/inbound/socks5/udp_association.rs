use std::{
    cell::RefCell,
    io::{self, ErrorKind},
    marker::PhantomData,
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::Arc,
    time::Duration,
};

use crate::proxy::inbound::socks5::{MAXIMUM_UDP_PAYLOAD_SIZE, SocksAddr};
use bytes::Bytes;
use moka::future::Cache;
use rand::{Rng, SeedableRng, rngs::SmallRng};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{net::UdpSocket, task::JoinHandle};

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

type AssociationMap<W> = Cache<SocketAddr, Arc<UdpAssociation<W>>>;

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
    session_expire_duration: Duration,
}

struct UdpAssociation<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    assoc_handle: JoinHandle<()>,
    sender: tokio::sync::mpsc::Sender<(SocksAddr, Bytes)>,
    writer: PhantomData<W>,
}

struct UdpAssociationContext<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    // context: Arc<ServiceContext>,
    peer_addr: SocketAddr,
    bypassed_ipv4_socket: Option<UdpSocket>,
    bypassed_ipv6_socket: Option<UdpSocket>,
    // proxied_socket: Option<MonProxySocket<UdpSocket>>,
    keepalive_tx: tokio::sync::mpsc::Sender<SocketAddr>,
    keepalive_flag: bool,
    // balancer: PingBalancer,
    respond_writer: W,
    client_session_id: u64,
    client_packet_id: u64,
    // server_session: Option<ServerSessionContext>,
    server_session_expire_duration: Duration,
}

thread_local! {
    static CLIENT_SESSION_RNG: RefCell<SmallRng> = RefCell::new(SmallRng::from_os_rng());
}

/// Generate an AEAD-2022 Client SessionID
#[inline]
pub fn generate_client_session_id() -> u64 {
    CLIENT_SESSION_RNG.with(|rng| rng.borrow_mut().random_range(1..=u64::MAX))
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
        let ttl = ttl.unwrap_or(Duration::from_secs(5 * 60));

        let assoc_map = match capacity {
            Some(capacity) => Cache::builder()
                .max_capacity(capacity as u64)
                .time_to_live(ttl)
                .build(),
            None => Cache::builder().time_to_live(ttl).build(),
        };

        let (keepalive_tx, keepalive_rx) = tokio::sync::mpsc::channel(32);
        (
            Self {
                respond_writer,
                // context,
                assoc_map,
                keepalive_tx,
                // balancer,
                session_expire_duration: ttl,
            },
            ttl,
            keepalive_rx,
        )
    }

    pub async fn send_to(
        &mut self,
        peer_addr: SocketAddr,
        target_addr: SocksAddr,
        data: &[u8],
    ) -> io::Result<()> {
        if let Some(assoc) = self.assoc_map.get(&peer_addr).await {
            return assoc.try_send((target_addr, Bytes::copy_from_slice(data)));
        };

        log::debug!("created udp association for {}", peer_addr);

        let assoc = Arc::new(UdpAssociation::new(
            // self.context.clone(),
            peer_addr,
            self.keepalive_tx.clone(),
            // self.balancer.clone(),
            self.respond_writer.clone(),
            self.session_expire_duration,
        ));

        assoc.try_send((target_addr, Bytes::copy_from_slice(data)))?;
        self.assoc_map.insert(peer_addr, assoc).await;

        Ok(())

        // let assoc_entry = self
        //     .assoc_map
        //     .entry(peer_addr)
        //     .or_insert_with(async {
        //         log::debug!("created udp association for {}", peer_addr);

        //         Arc::new(UdpAssociation::new(
        //             // self.context.clone(),
        //             peer_addr,
        //             self.keepalive_tx.clone(),
        //             // self.balancer.clone(),
        //             self.respond_writer.clone(),
        //             self.session_expire_duration,
        //         ))
        //     })
        //     .await;

        // assoc_entry
        //     .value()
        //     .try_send((target_addr, Bytes::copy_from_slice(data)))
    }

    /// Cleanup expired associations
    pub async fn cleanup_expired(&mut self) {
        self.assoc_map.iter();
    }

    /// Keep-alive association
    pub async fn keep_alive(&mut self, peer_addr: &SocketAddr) {
        self.assoc_map.get(peer_addr).await;
    }
}

impl<W> Drop for UdpAssociation<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    fn drop(&mut self) {
        self.assoc_handle.abort();
    }
}

impl<W> UdpAssociation<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    fn new(
        // context: Arc<ServiceContext>,
        peer_addr: SocketAddr,
        keepalive_tx: tokio::sync::mpsc::Sender<SocketAddr>,
        // balancer: PingBalancer,
        respond_writer: W,
        server_session_expire_duration: Duration,
    ) -> Self {
        let (assoc_handle, sender) = UdpAssociationContext::create(
            // context,
            peer_addr,
            keepalive_tx,
            // balancer,
            respond_writer,
            server_session_expire_duration,
        );
        Self {
            assoc_handle,
            sender,
            writer: PhantomData,
        }
    }

    fn try_send(&self, data: (SocksAddr, Bytes)) -> io::Result<()> {
        // if self.sender.try_send(data).is_err() {
        //     let err = io::Error::other("udp relay channel full");
        //     return Err(err);
        // }
        if let Err(e) = self.sender.try_send(data) {
            return Err(io::Error::other(e));
        }
        Ok(())
    }
}

impl<W> UdpAssociationContext<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    fn create(
        // context: Arc<ServiceContext>,
        peer_addr: SocketAddr,
        keepalive_tx: tokio::sync::mpsc::Sender<SocketAddr>,
        // balancer: PingBalancer,
        respond_writer: W,
        server_session_expire_duration: Duration,
    ) -> (
        JoinHandle<()>,
        tokio::sync::mpsc::Sender<(SocksAddr, Bytes)>,
    ) {
        let client_session_id = generate_client_session_id();

        let mut assoc = Self {
            // context,
            peer_addr,
            bypassed_ipv4_socket: None,
            bypassed_ipv6_socket: None,
            // proxied_socket: None,
            keepalive_tx,
            keepalive_flag: false,
            // balancer,
            respond_writer,
            // client_session_id must be random generated,
            // server use this ID to identify every independent clients.
            client_session_id,
            client_packet_id: 0,
            // server_session: None,
            server_session_expire_duration,
        };

        // Pending packets UDP_ASSOCIATION_SEND_CHANNEL_SIZE for each association should be good enough for a server.
        // If there are plenty of packets stuck in the channel, dropping excessive packets is a good way to protect the server from
        // being OOM.
        let (sender, receiver) = tokio::sync::mpsc::channel::<(SocksAddr, Bytes)>(64);

        let handle: JoinHandle<()> =
            tokio::spawn(async move { assoc.dispatch_packet(receiver).await });

        (handle, sender)
    }

    async fn dispatch_packet(
        &mut self,
        mut receiver: tokio::sync::mpsc::Receiver<(SocksAddr, Bytes)>,
    ) {
        let mut bypassed_ipv4_buffer = Vec::new();
        let mut bypassed_ipv6_buffer = Vec::new();
        // let mut proxied_buffer = Vec::new();
        let mut keepalive_interval = tokio::time::interval(Duration::from_secs(1));

        loop {
            tokio::select! {
                packet_received_opt = receiver.recv() => {
                    let Some((target_addr, data)) =  packet_received_opt else {
                        log::trace!("udp association for {} -> ... channel closed", self.peer_addr);
                            break;
                    };

                    self.dispatch_received_packet(&target_addr, &data).await;
                }

                received_opt = receive_from_bypassed_opt(&self.bypassed_ipv4_socket, &mut bypassed_ipv4_buffer), if self.bypassed_ipv4_socket.is_some() => {
                    let (n, addr) = match received_opt {
                        Ok(r) => r,
                        Err(err) => {
                            log::error!("udp relay {} <- ... (bypassed) failed, error: {}", self.peer_addr, err);
                            // Socket failure. Reset for recreation.
                            self.bypassed_ipv4_socket = None;
                            continue;
                        }
                    };

                    let addr = SocksAddr::from(addr);
                    self.send_received_respond_packet(&addr, &bypassed_ipv4_buffer[..n], true).await;
                }

                received_opt = receive_from_bypassed_opt(&self.bypassed_ipv6_socket, &mut bypassed_ipv6_buffer), if self.bypassed_ipv6_socket.is_some() => {
                    let (n, addr) = match received_opt {
                        Ok(r) => r,
                        Err(err) => {
                            log::error!("udp relay {} <- ... (bypassed) failed, error: {}", self.peer_addr, err);
                            // Socket failure. Reset for recreation.
                            self.bypassed_ipv6_socket = None;
                            continue;
                        }
                    };

                    let addr = SocksAddr::from(addr);
                    self.send_received_respond_packet(&addr, &bypassed_ipv6_buffer[..n], true).await;
                }

                // received_opt = receive_from_proxied_opt(&self.proxied_socket, &mut proxied_buffer), if self.proxied_socket.is_some() => {
                //     let (n, addr, control_opt) = match received_opt {
                //         Ok(r) => r,
                //         Err(err) => {
                //             log::error!("udp relay {} <- ... (proxied) failed, error: {}", self.peer_addr, err);
                //             // Socket failure. Reset for recreation.
                //             self.proxied_socket = None;
                //             continue;
                //         }
                //     };

                //     if let Some(control) = control_opt {
                //         // Check if Packet ID is in the window

                //         let session = self.server_session.get_or_insert_with(|| {
                //             ServerSessionContext::new(self.server_session_expire_duration)
                //         });

                //         let packet_id = control.packet_id;
                //         let session_context = session
                //             .server_session_map
                //             .entry(control.server_session_id)
                //             .or_insert_with(|| {
                //                 log::trace!(
                //                     "udp server with session {} for {} created",
                //                     control.client_session_id,
                //                     self.peer_addr,
                //                 );

                //                 ServerContext {
                //                     packet_window_filter: PacketWindowFilter::new()
                //                 }
                //             });

                //         if !session_context.packet_window_filter.validate_packet_id(packet_id, u64::MAX) {
                //             log::error!("udp {} packet_id {} out of window", self.peer_addr, packet_id);
                //             continue;
                //         }
                //     }

                //     self.send_received_respond_packet(&addr, &proxied_buffer[..n], false).await;
                // }

                _ = keepalive_interval.tick() => {
                    if self.keepalive_flag {
                        if self.keepalive_tx.try_send(self.peer_addr).is_err() {
                            log::debug!("udp relay {} keep-alive failed, channel full or closed", self.peer_addr);
                        } else {
                            self.keepalive_flag = false;
                        }
                    }
                }
            }
        }

        #[inline]
        async fn receive_from_bypassed_opt(
            socket: &Option<UdpSocket>,
            buf: &mut Vec<u8>,
        ) -> io::Result<(usize, SocketAddr)> {
            match *socket {
                None => futures::future::pending().await,
                Some(ref s) => {
                    if buf.is_empty() {
                        buf.resize(MAXIMUM_UDP_PAYLOAD_SIZE, 0);
                    }
                    s.recv_from(buf).await
                }
            }
        }

        // #[inline]
        // async fn receive_from_proxied_opt(
        //     socket: &Option<MonProxySocket<UdpSocket>>,
        //     buf: &mut Vec<u8>,
        // ) -> io::Result<(usize, SocksAddr, Option<UdpSocketControlData>)> {
        //     match *socket {
        //         None => futures::future::pending().await,
        //         Some(ref s) => {
        //             if buf.is_empty() {
        //                 buf.resize(MAXIMUM_UDP_PAYLOAD_SIZE, 0);
        //             }
        //             s.recv_with_ctrl(buf).await
        //         }
        //     }
        // }
    }

    async fn dispatch_received_packet(&mut self, target_addr: &SocksAddr, data: &[u8]) {
        // Check if target should be bypassed. If so, send packets directly.
        let bypassed = true;
        // self.balancer.is_empty() || self.context.check_target_bypassed(target_addr).await;

        log::trace!(
            "udp relay {} -> {} ({}) with {} bytes",
            self.peer_addr,
            target_addr,
            if bypassed { "bypassed" } else { "proxied" },
            data.len()
        );

        if bypassed {
            if let Err(err) = self
                .dispatch_received_bypassed_packet(target_addr, data)
                .await
            {
                log::error!(
                    "udp relay {} -> {} (bypassed) with {} bytes, error: {}",
                    self.peer_addr,
                    target_addr,
                    data.len(),
                    err
                );
            }
            // } else if let Err(err) = self
            //     .dispatch_received_proxied_packet(target_addr, data)
            //     .await
            // {
            //     log::error!(
            //         "udp relay {} -> {} (proxied) with {} bytes, error: {}",
            //         self.peer_addr,
            //         target_addr,
            //         data.len(),
            //         err
            //     );
        }
    }

    async fn dispatch_received_bypassed_packet(
        &mut self,
        target_addr: &SocksAddr,
        data: &[u8],
    ) -> io::Result<()> {
        match *target_addr {
            SocksAddr::SocketAddr(sa) => self.send_received_bypassed_packet(sa, data).await,
            SocksAddr::DomainNameAddr(ref dname, port) => {
                let mut addrs = tokio::net::lookup_host((dname.as_str(), port)).await?;
                let sa: SocketAddr = addrs
                    .next()
                    .ok_or_else(|| io::Error::new(ErrorKind::Other, "No IP found for domain"))?;
                // lookup_then!(self.context.context_ref(), dname, port, |sa| {
                self.send_received_bypassed_packet(sa, data)
                    .await
                    // })
                    .map(|_| ())
            }
        }
    }

    async fn send_received_bypassed_packet(
        &mut self,
        mut target_addr: SocketAddr,
        data: &[u8],
    ) -> io::Result<()> {
        const UDP_SOCKET_SUPPORT_DUAL_STACK: bool = cfg!(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "watchos",
            target_os = "tvos",
            target_os = "freebsd",
            target_os = "windows",
        ));

        let socket = if UDP_SOCKET_SUPPORT_DUAL_STACK {
            match self.bypassed_ipv6_socket {
                Some(ref mut socket) => socket,
                None => {
                    let socket =
                        Self::create_outbound_udp_socket(Ipv6Addr::UNSPECIFIED.into()).await?;
                    self.bypassed_ipv6_socket.insert(socket)
                }
            }
        } else {
            match target_addr {
                SocketAddr::V4(..) => match self.bypassed_ipv4_socket {
                    Some(ref mut socket) => socket,
                    None => {
                        let socket =
                            Self::create_outbound_udp_socket("192.168.158.151".parse().unwrap())
                                .await?;
                        self.bypassed_ipv4_socket.insert(socket)
                    }
                },
                SocketAddr::V6(..) => match self.bypassed_ipv6_socket {
                    Some(ref mut socket) => socket,
                    None => {
                        let socket =
                            Self::create_outbound_udp_socket("192.168.158.151".parse().unwrap())
                                .await?;
                        self.bypassed_ipv6_socket.insert(socket)
                    }
                },
            }
        };

        if UDP_SOCKET_SUPPORT_DUAL_STACK {
            if let SocketAddr::V4(saddr) = target_addr {
                let mapped_ip = saddr.ip().to_ipv6_mapped();
                target_addr = SocketAddr::V6(SocketAddrV6::new(mapped_ip, saddr.port(), 0, 0));
            }
        }

        let n = socket.send_to(data, target_addr).await?;
        if n != data.len() {
            log::warn!(
                "{} -> {} sent {} bytes != expected {} bytes",
                self.peer_addr,
                target_addr,
                n,
                data.len()
            );
        }

        Ok(())
    }

    // async fn dispatch_received_proxied_packet(
    //     &mut self,
    //     target_addr: &SocksAddr,
    //     data: &[u8],
    // ) -> io::Result<()> {
    //     // Increase Packet ID before send
    //     self.client_packet_id = match self.client_packet_id.checked_add(1) {
    //         Some(i) => i,
    //         None => {
    //             // FIXME: client_packet_id overflowed. What's the proper way to handle this?
    //             //
    //             // Reopen a new session is not perfect, because the remote target will receive packets from a different address.
    //             // For most application protocol, like QUIC, it is fine to change client address.
    //             //
    //             // But it will happen only when a client continuously send 18446744073709551616 packets without renewing the socket.

    //             let new_session_id = generate_client_session_id();

    //             log::warn!(
    //                 "{} -> {} (proxied) packet id overflowed. socket reset and session renewed ({} -> {})",
    //                 self.peer_addr,
    //                 target_addr,
    //                 self.client_session_id,
    //                 new_session_id
    //             );

    //             self.proxied_socket.take();
    //             self.client_packet_id = 1;
    //             self.client_session_id = new_session_id;

    //             self.client_packet_id
    //         }
    //     };

    //     let socket = match self.proxied_socket {
    //         Some(ref mut socket) => socket,
    //         None => {
    //             // Create a new connection to proxy server

    //             let server = self.balancer.best_udp_server();
    //             let svr_cfg = server.server_config();

    //             let socket = ProxySocket::connect_with_opts(
    //                 self.context.context(),
    //                 svr_cfg,
    //                 server.connect_opts_ref(),
    //             )
    //             .await?;
    //             let socket = MonProxySocket::from_socket(socket, self.context.flow_stat());

    //             self.proxied_socket.insert(socket)
    //         }
    //     };

    //     let mut control = UdpSocketControlData::default();
    //     control.client_session_id = self.client_session_id;
    //     control.packet_id = self.client_packet_id;

    //     match socket.send_with_ctrl(target_addr, &control, data).await {
    //         Ok(..) => return Ok(()),
    //         Err(err) => {
    //             log::debug!(
    //                 "{} -> {} (proxied) sending {} bytes failed, error: {}",
    //                 self.peer_addr,
    //                 target_addr,
    //                 data.len(),
    //                 err
    //             );

    //             // Drop the socket and reconnect to another server.
    //             self.proxied_socket = None;
    //         }
    //     }

    //     Ok(())
    // }

    async fn send_received_respond_packet(
        &mut self,
        addr: &SocksAddr,
        data: &[u8],
        bypassed: bool,
    ) {
        log::trace!(
            "udp relay {} <- {} ({}) received {} bytes",
            self.peer_addr,
            addr,
            if bypassed { "bypassed" } else { "proxied" },
            data.len(),
        );

        // Keep association alive in map
        self.keepalive_flag = true;

        // Send back to client
        match self
            .respond_writer
            .send_to(self.peer_addr, addr, data)
            .await
        {
            Err(err) => {
                log::warn!(
                    "udp failed to send back {} bytes to client {}, from target {} ({}), error: {}",
                    data.len(),
                    self.peer_addr,
                    addr,
                    if bypassed { "bypassed" } else { "proxied" },
                    err
                );
            }
            Ok(..) => {
                log::trace!(
                    "udp relay {} <- {} ({}) with {} bytes",
                    self.peer_addr,
                    addr,
                    if bypassed { "bypassed" } else { "proxied" },
                    data.len()
                );
            }
        }
    }

    async fn create_outbound_udp_socket(bind_ip: IpAddr) -> io::Result<UdpSocket> {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_broadcast(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&socket2::SockAddr::from(SocketAddr::new(bind_ip.into(), 0)))?;
        log::debug!("UDP ASSOCIATE socket bound to {:?}", socket.local_addr()?);

        UdpSocket::from_std(socket.into())
    }
}
