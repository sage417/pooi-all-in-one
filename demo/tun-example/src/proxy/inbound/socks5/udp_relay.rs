use std::{
    io::{self, Cursor},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bytes::{BufMut, BytesMut};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UdpSocket,
};
use tokio_util::sync::CancellationToken;

use super::{
    MAXIMUM_UDP_PAYLOAD_SIZE, SocksAddr, SocksError,
    udp_association::{UdpAssociationManager, UdpInboundWrite},
};

pub struct UdpRelayServer {
    // context: Arc<ServiceContext>,
    pub(crate) ttl: Option<Duration>,
    pub(crate) capacity: Option<usize>,
    pub(crate) listener: Arc<UdpSocket>,
    // balancer: PingBalancer,
}

/// UDP ASSOCIATE request header
///
/// ```plain
/// +----+------+------+----------+----------+----------+
/// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +----+------+------+----------+----------+----------+
/// | 2  |  1   |  1   | Variable |    2     | Variable |
/// +----+------+------+----------+----------+----------+
/// ```
#[derive(Clone, Debug)]
pub struct UdpAssociateHeader {
    /// Fragment
    ///
    /// ShadowSocks does not support fragment, so this frag must be 0x00
    pub frag: u8,
    /// Remote address
    pub address: SocksAddr,
}

#[derive(Clone)]
struct Socks5UdpInboundWriter {
    inbound: Arc<UdpSocket>,
}

impl UdpRelayServer {
    /// Server's listen address
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Run server accept loop
    pub async fn run(self,  cancel_token: CancellationToken,) -> io::Result<()> {
        log::info!("socks5 UDP listening on {}", self.local_addr()?);

        let (mut manager, cleanup_interval, mut keepalive_rx) = UdpAssociationManager::new(
            // self.context.clone(),
            Socks5UdpInboundWriter {
                inbound: self.listener.clone(),
            },
            self.ttl,
            self.capacity,
            // self.balancer,
        );

        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        let mut cleanup_timer = tokio::time::interval(cleanup_interval);

        loop {
            tokio::select! {
                _ = cleanup_timer.tick() => {
                    // cleanup expired associations. iter() will remove expired elements
                    manager.cleanup_expired().await;
                }

                peer_addr_opt = keepalive_rx.recv() => {
                    let peer_addr = peer_addr_opt.expect("keep-alive channel closed unexpectly");
                    manager.keep_alive(&peer_addr).await;
                }

                recv_result = self.listener.recv_from(&mut buffer) => {
                    let (n, peer_addr) = match recv_result {
                        Ok(s) => s,
                        Err(err) => {
                            log::error!("udp server recv_from failed with error: {}", err);
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            continue;
                        }
                    };

                    let data = &buffer[..n];

                    // PKT = UdpAssociateHeader + PAYLOAD
                    let mut cur = Cursor::new(data);
                    let header = match UdpAssociateHeader::read_from(&mut cur).await {
                        Ok(h) => h,
                        Err(..) => {
                            log::error!("received invalid UDP associate packet: {:02x?}", data);
                            continue;
                        }
                    };

                    if header.frag != 0 {
                        log::error!("received UDP associate with frag != 0, which is not supported by shadowsocks");
                        continue;
                    }

                    let pos = cur.position() as usize;
                    let payload = &data[pos..];

                    log::trace!(
                        "UDP ASSOCIATE {} -> {}, {} bytes",
                        peer_addr,
                        header.address,
                        payload.len()
                    );

                    if let Err(err) = manager.send_to(peer_addr, header.address, payload).await {
                        log::debug!(
                            "udp packet from {} relay {} bytes failed, error: {}",
                            peer_addr,
                            data.len(),
                            err
                        );
                    }
                }
                _ = cancel_token.cancelled() => {
                    break Ok(());
                }
            }
        }
    }
}

impl UdpAssociateHeader {
    /// Creates a header
    pub fn new(frag: u8, address: SocksAddr) -> Self {
        Self { frag, address }
    }

    /// Read from a reader
    pub async fn read_from<R>(r: &mut R) -> Result<Self, SocksError>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 3];
        let _ = r.read_exact(&mut buf).await?;

        let frag = buf[2];
        let address = SocksAddr::read_from(r).await?;
        Ok(Self::new(frag, address))
    }

    /// Write to a writer
    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    /// Write to buffer
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let Self {
            ref frag,
            ref address,
        } = *self;
        buf.put_slice(&[0x00, 0x00, *frag]);
        address.write_to_buf(buf);
    }

    /// Length in bytes
    #[inline]
    pub fn serialized_len(&self) -> usize {
        3 + self.address.serialized_len()
    }
}

impl UdpInboundWrite for Socks5UdpInboundWriter {
    async fn send_to(
        &self,
        peer_addr: SocketAddr,
        remote_addr: &SocksAddr,
        data: &[u8],
    ) -> io::Result<()> {
        let remote_addr = match remote_addr {
            SocksAddr::SocketAddr(sa) => {
                // Try to convert IPv4 mapped IPv6 address if server is running on dual-stack mode
                let saddr = match *sa {
                    SocketAddr::V4(..) => *sa,
                    SocketAddr::V6(ref v6) => match v6.ip().to_ipv4_mapped() {
                        Some(v4) => SocketAddr::new(IpAddr::from(v4), v6.port()),
                        None => *sa,
                    },
                };

                SocksAddr::SocketAddr(saddr)
            }
            daddr => daddr.clone(),
        };

        // Reassemble packet
        let mut payload_buffer = BytesMut::new();
        let header = UdpAssociateHeader::new(0, remote_addr.clone());
        payload_buffer.reserve(header.serialized_len() + data.len());

        header.write_to_buf(&mut payload_buffer);
        payload_buffer.put_slice(data);

        self.inbound
            .send_to(&payload_buffer, peer_addr)
            .await
            .map(|_| ())
    }
}
