use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::HashMap,
    io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::RwLock,
};

use super::InboundHandler;
use crate::session::SocksAddr;

// RFC 1928
const SOCKS5_VER: u8 = 0x05;
// RFC 1929
const SOCKS5_AUTH_VER: u8 = 0x01;

pub(super) mod auth_methods {
    pub const NO_AUTHENTICATION_REQUIRED: u8 = 0x00;
    pub const USERNAME_PASSWORD: u8 = 0x02;
    pub const NO_ACCEPTABLE_METHODS: u8 = 0xff;
}

#[allow(dead_code)]
pub(super) mod socks_command {
    pub const CONNECT: u8 = 0x01;
    pub const BIND: u8 = 0x02;
    pub const UDP_ASSOCIATE: u8 = 0x03;
}

#[allow(dead_code)]
pub(super) mod atype {
    pub const IPV4: u8 = 0x01;
    pub const DOMAIN: u8 = 0x03;
    pub const IPV6: u8 = 0x04;
}

#[allow(dead_code)]
pub(super) mod response_code {
    pub const SUCCEEDED: u8 = 0x00;
    pub const FAILURE: u8 = 0x01;
    pub const RULE_FAILURE: u8 = 0x02;
    pub const NETWORK_UNREACHABLE: u8 = 0x03;
    pub const HOST_UNREACHABLE: u8 = 0x04;
    pub const CONNECTION_REFUSED: u8 = 0x05;
    pub const TTL_EXPIRED: u8 = 0x06;
    pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub const ADDR_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

type SocksResult<T> = Result<T, SocksError>;

#[derive(Error, Debug)]
pub enum SocksError {
    #[error("IO error: {0}")]
    Io(#[from] IoError),
    #[error("Invalid SOCKS version: expected {expected}, got {got}")]
    InvalidVersion { expected: u8, got: u8 },
    #[error("No acceptable authentication methods")]
    NoAcceptableMethods,
    #[error("Authentication failed for user: {username}")]
    AuthFailed { username: String },
    #[error("Invalid UTF-8 in {field}")]
    InvalidUtf8 { field: &'static str },
    #[error("Command not supported: 0x{code:02x}")]
    CommandNotSupported { code: u8 },
    #[error("Address type not supported: 0x{atype:02x}")]
    AddrTypeNotSupported { atype: u8 },
    #[error("Domain length invalid: {len}")]
    InvalidDomainLength { len: usize },
    #[error("UDP packet too short")]
    UdpPacketTooShort,
    #[error("UDP packet invalid")]
    UdpPacketInvalid,
}

pub(super) struct SocksInboundHandler {
    authenticator: Arc<dyn Authenticator>,
    buf: BytesMut,
}

pub trait Authenticator: Send + Sync {
    fn enabled(&self) -> bool;
    fn authenticate(&self, username: &str, password: &str) -> bool;
}

pub(super) struct SimpleAuthenticator {
    username: String,
    password: String,
    enabled: bool,
}

impl SocksInboundHandler {
    pub fn new(authenticator: Arc<dyn Authenticator>) -> Self {
        Self {
            authenticator,
            buf: BytesMut::new(),
        }
    }

    async fn handle_handshake(&mut self, stream: &mut TcpStream) -> SocksResult<()> {
        // +----+----------+----------+
        // |VER | NMETHODS | METHODS  |
        // +----+----------+----------+
        // | 1  |    1     | 1 to 255 |
        // +----+----------+----------+

        // 1) Handshake / Method Selection
        let buf = &mut self.buf;

        buf.resize(2, 0);
        stream.read_exact(buf.as_mut()).await?;

        if buf[0] != SOCKS5_VER {
            return Err(SocksError::InvalidVersion {
                expected: SOCKS5_VER,
                got: buf[0],
            });
        }

        let n_methods = buf[1] as usize;
        if n_methods == 0 {
            return Err(SocksError::NoAcceptableMethods);
        }

        buf.resize(n_methods, 0);
        stream.read_exact(buf.as_mut()).await?;

        let client_methods = &buf[..];

        // NO_ACCEPTABLE_METHODS
        if (self.authenticator.enabled()
            && !client_methods.contains(&auth_methods::USERNAME_PASSWORD))
            || !client_methods.contains(&auth_methods::NO_AUTHENTICATION_REQUIRED)
        {
            stream
                .write_all(&[SOCKS5_VER, auth_methods::NO_ACCEPTABLE_METHODS])
                .await?;
            stream.shutdown().await?;
            return Err(SocksError::NoAcceptableMethods);
        }
        // choose suitable auth method
        let auth_method = if self.authenticator.enabled() {
            auth_methods::USERNAME_PASSWORD
        } else {
            auth_methods::NO_AUTHENTICATION_REQUIRED
        };

        stream.write_all(&[SOCKS5_VER, auth_method]).await?;

        // 2) Authentication
        if auth_method == auth_methods::USERNAME_PASSWORD {
            self.user_password_negotiation(stream).await?;
        }

        Ok(())
    }

    async fn user_password_negotiation(
        &mut self,
        stream: &mut TcpStream,
    ) -> Result<(), SocksError> {
        let buf = &mut self.buf;

        // +----+------+----------+------+----------+
        // |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
        // +----+------+----------+------+----------+
        // | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
        // +----+------+----------+------+----------+
        buf.resize(2, 0);
        stream.read_exact(buf.as_mut()).await?;

        let ulen = buf[1] as usize;
        buf.resize(ulen, 0);
        stream.read_exact(buf.as_mut()).await?;

        let Ok(uname) = String::from_utf8(buf.to_vec()) else {
            stream
                .write_all(&[SOCKS5_AUTH_VER, response_code::FAILURE])
                .await?;
            stream.shutdown().await?;
            return Err(SocksError::InvalidUtf8 { field: "uname" });
        };

        buf.resize(1, 0);
        stream.read_exact(buf.as_mut()).await?;

        let plen = buf[0] as usize;
        buf.resize(plen, 0);

        stream.read_exact(buf.as_mut()).await?;

        let Ok(pass) = String::from_utf8(buf.to_vec()) else {
            stream
                .write_all(&[SOCKS5_AUTH_VER, response_code::FAILURE])
                .await?;
            stream.shutdown().await?;
            return Err(SocksError::InvalidUtf8 { field: "pass" });
        };

        // +----+--------+
        // |VER | STATUS |
        // +----+--------+
        // | 1  |   1    |
        // +----+--------+
        if matches!(self.authenticator.authenticate(&uname, &pass), true) {
            stream
                .write_all(&[SOCKS5_AUTH_VER, response_code::SUCCEEDED])
                .await?;
            Ok(())
        } else {
            stream
                .write_all(&[SOCKS5_AUTH_VER, response_code::FAILURE])
                .await?;
            stream.shutdown().await?;
            Err(SocksError::AuthFailed { username: uname })
        }

        // match self.authenticator.authenticate(&uname, &pass) {
        //     true => {
        //         stream
        //             .write_all(&[SOCKS5_AUTH_VER, response_code::SUCCEEDED])
        //             .await?;
        //         Ok(())
        //     }
        //     false => {
        //         stream
        //             .write_all(&[SOCKS5_AUTH_VER, response_code::FAILURE])
        //             .await?;
        //         stream.shutdown().await?;
        //         Err(SocksError::AuthFailed { username: uname })
        //     }
        // }
    }

    async fn handle_command(&mut self, stream: &mut TcpStream) -> SocksResult<()> {
        // +----+-----+-------+------+----------+----------+
        // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        // +----+-----+-------+------+----------+----------+
        // | 1  |  1  |   1   |  1   | Variable |    2     |
        // +----+-----+-------+------+----------+----------+

        let buf = &mut self.buf;
        buf.clear();
        buf.resize(4, 0);
        stream.read_exact(buf.as_mut()).await?;

        // let ver = buf[0];
        // let cmd = buf[1];
        // let atype = buf[3];

        let [ver, cmd, _, atype] = *&buf[0..4] else {
            return Err(SocksError::InvalidVersion {
                expected: SOCKS5_VER,
                got: 0u8,
            });
        };

        if ver != SOCKS5_VER {
            return Err(SocksError::InvalidVersion {
                expected: SOCKS5_VER,
                got: ver,
            });
        }

        let dst_addr = match atype {
            0x01 => {
                let mut ip_bytes: [u8; 4] = [0u8; 4];
                let mut port_bytes: [u8; 2] = [0u8; 2];

                stream.read_exact(&mut ip_bytes).await?;
                stream.read_exact(&mut port_bytes).await?;

                let ip = Ipv4Addr::from(ip_bytes);
                let port = u16::from_be_bytes(port_bytes);
                SocksAddr::from((ip, port))
            }
            0x03 => {
                buf.resize(1, 0);
                stream.read_exact(buf.as_mut()).await?;
                let domain_len = buf[0] as usize;

                if domain_len < 1 || domain_len > 255 {
                    self.command_reply_by_atype(
                        stream,
                        response_code::ADDR_TYPE_NOT_SUPPORTED,
                        atype,
                    )
                    .await?;
                    return Err(SocksError::InvalidDomainLength { len: domain_len });
                }

                buf.resize(domain_len, 0);
                stream.read_exact(buf.as_mut()).await?;

                // std::str::from_utf8(buf.as_ref());

                let Ok(domain) = String::from_utf8(buf.to_vec()) else {
                    // stream
                    //     .write_all(&[SOCKS5_AUTH_HEAD, response_code::FAILURE])
                    //     .await?;
                    // stream.shutdown().await?;
                    self.command_reply_by_atype(
                        stream,
                        response_code::ADDR_TYPE_NOT_SUPPORTED,
                        atype,
                    )
                    .await?;
                    return Err(SocksError::InvalidUtf8 { field: "domain" });
                };

                let mut port_bytes: [u8; 2] = [0u8; 2];
                stream.read_exact(&mut port_bytes).await?;

                let port = u16::from_be_bytes(port_bytes);

                SocksAddr::DomainNameAddr(domain, port)
            }
            0x04 => {
                let mut ip_bytes: [u8; 16] = [0u8; 16];
                let mut port_bytes: [u8; 2] = [0u8; 2];

                stream.read_exact(&mut ip_bytes).await?;
                stream.read_exact(&mut port_bytes).await?;

                let ip = Ipv6Addr::from(ip_bytes);
                let port = u16::from_be_bytes(port_bytes);
                SocksAddr::from((ip, port))
            }
            _ => {
                return Err(SocksError::AddrTypeNotSupported { atype });
            }
        };

        // +----+-----+-------+------+----------+----------+
        // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        // +----+-----+-------+------+----------+----------+
        // | 1  |  1  | X'00' |  1   | Variable |    2     |
        // +----+-----+-------+------+----------+----------+

        // let dst = SocksAddr::read_from(&mut stream).await?;
        buf.clear();

        log::debug!(
            "handle cmd: {} atype: {} {}, local_addr: {:?} client_addr: {:?}",
            cmd,
            atype,
            dst_addr,
            stream.local_addr(),
            stream.peer_addr()
        );

        match cmd {
            socks_command::CONNECT => {
                // let target_addr: SocketAddr;

                let target_addr = match dst_addr {
                    SocksAddr::SocketAddr(addr) => addr,
                    SocksAddr::DomainNameAddr(domain, port) => {
                        // domain lookup
                        let mut addrs = tokio::net::lookup_host((domain, port)).await?;
                        addrs
                            .next()
                            .ok_or(IoError::new(IoErrorKind::Other, "No IP found for domain"))?
                    }
                };

                // connect
                let result = TcpStream::connect(&target_addr).await;

                let Ok(outbound) = result else {
                    let rep = match &result {
                        Err(e) if e.kind() == IoErrorKind::ConnectionRefused => {
                            response_code::CONNECTION_REFUSED
                        }
                        Err(e) if e.kind() == IoErrorKind::TimedOut => response_code::TTL_EXPIRED,
                        Err(e) if e.kind() == IoErrorKind::HostUnreachable => {
                            response_code::HOST_UNREACHABLE
                        }
                        Err(e) if e.kind() == IoErrorKind::NetworkUnreachable => {
                            response_code::NETWORK_UNREACHABLE
                        }
                        _ => response_code::FAILURE,
                    };

                    // let rep = if let Err(e) = &result {
                    //     match e.kind() {
                    //         IoErrorKind::ConnectionRefused => response_code::CONNECTION_REFUSED,
                    //         IoErrorKind::TimedOut => response_code::TTL_EXPIRED,
                    //         IoErrorKind::HostUnreachable => response_code::HOST_UNREACHABLE,
                    //         IoErrorKind::NetworkUnreachable => response_code::NETWORK_UNREACHABLE,
                    //         _ => response_code::FAILURE,
                    //     }
                    // } else {
                    //     response_code::FAILURE
                    // };

                    self.command_reply_by_atype(stream, rep, atype).await?;

                    return match result {
                        Err(e) => Err(SocksError::Io(e)),
                        Ok(_) => unreachable!(),
                    };
                };

                let bind_addr = outbound
                    .local_addr()
                    .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());

                log::debug!("bind_addr {:?}", bind_addr);

                self.command_reply_by_bind_addr(stream, response_code::SUCCEEDED, bind_addr)
                    .await?;

                log::info!(
                    "SOCKS5 proxy established: {} -> {:?}",
                    stream.peer_addr()?,
                    target_addr
                );

                let (mut client_read, mut client_write) = stream.split();
                let (mut target_read, mut target_write) = tokio::io::split(outbound);

                // client -> remote server
                let client_to_target = tokio::io::copy(&mut client_read, &mut target_write);
                // remote server -> client
                let target_to_client = tokio::io::copy(&mut target_read, &mut client_write);

                tokio::select! {
                    res = client_to_target => {
                        if let Err(e) = res {
                            log::debug!("Client -> Target error: {}", e);
                        }
                    }
                    res = target_to_client => {
                        if let Err(e) = res {
                            log::debug!("Target -> Client error: {}", e);
                        }
                    }
                }
            }
            socks_command::UDP_ASSOCIATE => {
                let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
                socket.set_broadcast(true)?;
                socket.set_nonblocking(true)?;
                socket.bind(&socket2::SockAddr::from(SocketAddr::new(
                    stream.local_addr()?.ip(),
                    0,
                )))?;
                log::debug!("UDP ASSOCIATE socket bound to {:?}", socket.local_addr()?);

                let udp_socket = UdpSocket::from_std(socket.into())?;
                // let udp_socket = Arc::new(udp_socket);

                self.command_reply_by_bind_addr(
                    stream,
                    response_code::SUCCEEDED,
                    udp_socket.local_addr()?,
                )
                .await?;

                self.handle_udp_traffic(stream, udp_socket, stream.peer_addr()?)
                    .await?;
            }
            _ => {
                self.command_reply_by_atype(stream, response_code::COMMAND_NOT_SUPPORTED, atype)
                    .await?;

                return Err(SocksError::CommandNotSupported { code: cmd });
            }
        }

        Ok(())
    }

    async fn handle_udp_traffic(
        &self,
        tcp_stream: &mut TcpStream,
        udp_socket: UdpSocket,
        client_tcp_addr: SocketAddr,
    ) -> SocksResult<()> {
        let mut udp_buffer = vec![0u8; 65535];
        let mut tcp_buffer = [0u8; 1];

        log::info!(
            "SOCKS5 UDP association from {} at {}",
            client_tcp_addr,
            udp_socket.local_addr()?
        );

        // let client_mapping = Arc::new(RwLock::new(HashMap::new()));
        let client_mapping = Arc::new(RwLock::new(None::<SocketAddr>));

        loop {
            tokio::select! {
                recv_result = udp_socket.recv_from(&mut udp_buffer) => {
                    let (n, peer_addr) = match recv_result {
                        Ok(r) => r,
                        Err(e) => {
                            log::debug!("udp server recv_from failed with error: {}", e);
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            continue;
                        }
                    };
                    let data = &udp_buffer[..n];
                    
                    // client first req
                    if client_mapping.read().await.is_none() {
                        let mut mapping = client_mapping.write().await;
                        mapping.get_or_insert(peer_addr);
                        log::trace!("Mapped client {}", peer_addr);
                    }

                    if let Some(client_udp_addr) = *client_mapping.read().await {
                        if client_udp_addr == peer_addr {
                            let (target_addr, data) = match Self::parse_udp_packet(data).await {
                                Ok(r) => r,
                                Err(e) => {
                                    log::debug!("Failed to parse UDP packet from {}: {}", client_tcp_addr, e);
                                    continue;
                                }
                            };

                            log::debug!(
                                "UDP request from client {} to target {}, {} bytes",
                                client_tcp_addr,
                                target_addr,
                                data.len()
                            );

                            let socket_addr = match target_addr {
                                SocksAddr::SocketAddr(addr) => addr,
                                SocksAddr::DomainNameAddr(domain, port) => {
                                    // hostname lookup
                                    let mut addrs = tokio::net::lookup_host((domain, port)).await?;
                                    addrs.next().ok_or_else(||
                                        IoError::new(IoErrorKind::Other, "No IP found for domain")
                                    )?
                                }
                            };

                            if let Err(e) = udp_socket.send_to(data, socket_addr).await {
                                log::debug!("Failed to send UDP data to {}: {}", socket_addr, e);
                            }
                        } else {
                            let client_addr = {
                                let mapping = client_mapping.read().await;
                                mapping.as_ref().and_then(|client_addr| {
                                    Some(*client_addr)
                                })
                            };

                            let Some(client_udp_addr) = client_addr else {
                                log::debug!("No client mapping found for server {}, ignoring packet", peer_addr);
                                continue;
                            };

                            log::debug!(
                                "UDP response from server {} to client {}, {} bytes",
                                peer_addr,
                                client_udp_addr,
                                data.len()
                            );

                            let packet = Self::build_udp_packet(&peer_addr, data)?;
                            udp_socket.send_to(&packet, client_udp_addr).await?;
                        }
                    }
                }
                result = tcp_stream.read(&mut tcp_buffer) => {
                    match result {
                        Ok(0) => {
                            log::debug!("TCP control connection closed by client");
                            break;
                        }
                        Err(e) => {
                            log::debug!("TCP control connection error: {}", e);
                            break;
                        }
                       _ => {}
                    }
                }
            }
        }

        log::info!(
            "SOCKS5 UDP relay session ended for client: {}",
            client_tcp_addr
        );
        Ok(())
    }

    async fn parse_udp_packet(packet: &[u8]) -> SocksResult<(SocksAddr, &[u8])> {
        if packet.len() < 10 {
            return Err(SocksError::UdpPacketTooShort);
        }

        // +----+------+------+----------+----------+----------+
        // |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
        // +----+------+------+----------+----------+----------+
        // | 2  |  1   |  1   | Variable |    2     | Variable |
        // +----+------+------+----------+----------+----------+

        if packet[0] != 0x00 || packet[1] != 0x00 {
            log::debug!("Invalid RSV in UDP packet: {} {}", packet[0], packet[1]);
            return Err(SocksError::UdpPacketInvalid);
        }

        let frag = packet[2];
        if frag != 0x00 {
            log::debug!("Unsupported UDP frag: {}", frag);
            return Err(SocksError::UdpPacketInvalid);
        }

        let atype = packet[3];
        // let addr_start = 4;
        let (addr, offset) = match atype {
            atype::IPV4 => {
                if packet.len() < 10 {
                    return Err(SocksError::UdpPacketTooShort);
                }
                let ip = Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]);
                let port = u16::from_be_bytes([packet[8], packet[9]]);
                (SocksAddr::from((ip, port)), 10)
            }
            atype::DOMAIN => {
                let domain_len = packet[4] as usize;
                if packet.len() < 7 + domain_len {
                    return Err(SocksError::UdpPacketTooShort);
                }
                let domain_bytes = &packet[5..5 + domain_len];
                let domain = String::from_utf8(domain_bytes.to_vec())
                    .map_err(|_| SocksError::InvalidUtf8 { field: "domain" })?;
                // let domain_addr = Self::lookup_host(domain).await?;
                let port = u16::from_be_bytes([packet[5 + domain_len], packet[6 + domain_len]]);

                // domain lookup
                // let mut addrs = tokio::net::lookup_host(domain).await?;
                // let addr = addrs
                //     .next()
                //     .ok_or(IoError::new(IoErrorKind::Other, "No IP found for domain"))?;

                (
                    SocksAddr::DomainNameAddr(domain, port),
                    // SocketAddr::from((addr.ip(), port)),
                    7 + domain_len,
                )
            }
            atype::IPV6 => {
                if packet.len() < 22 {
                    return Err(SocksError::UdpPacketTooShort);
                }
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&packet[4..20]);
                let ip = Ipv6Addr::from(ip_bytes);
                let port = u16::from_be_bytes([packet[20], packet[21]]);
                (SocksAddr::from((ip, port)), 22)
            }
            _ => return Err(SocksError::AddrTypeNotSupported { atype }),
        };

        // let data_start = addr_start + offset;
        if offset > packet.len() {
            return Err(SocksError::UdpPacketInvalid);
        }

        Ok((SocksAddr::from(addr), &packet[offset..]))
    }

    fn build_udp_packet(target_addr: &SocketAddr, data: &[u8]) -> SocksResult<Vec<u8>> {
        let mut packet = Vec::with_capacity(256);

        // RSV
        packet.extend_from_slice(&[0x00, 0x00]);
        // FRAG
        packet.push(0x00);

        match target_addr {
            SocketAddr::V4(addr) => {
                packet.push(atype::IPV4);
                packet.extend_from_slice(&addr.ip().octets());
                packet.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                packet.push(atype::IPV6);
                packet.extend_from_slice(&addr.ip().octets());
                packet.extend_from_slice(&addr.port().to_be_bytes());
            }
        }

        packet.extend_from_slice(data);
        Ok(packet)
    }

    async fn command_reply_by_bind_addr(
        &mut self,
        stream: &mut TcpStream,
        resp: u8,
        bind_addr: SocketAddr,
    ) -> IoResult<()> {
        let buf = &mut self.buf;
        buf.clear();
        buf.put_u8(SOCKS5_VER);
        buf.put_u8(resp);
        buf.put_u8(0x0);
        // buf.put_u8(atype);

        match bind_addr {
            SocketAddr::V4(v4) => {
                buf.put_u8(0x01); // ATYP = IPv4
                buf.extend_from_slice(&v4.ip().octets()); // 4 bytes
                buf.extend_from_slice(&v4.port().to_be_bytes()); // 2 bytes
            }
            SocketAddr::V6(v6) => {
                buf.put_u8(0x04); // ATYP = IPv6
                buf.extend_from_slice(&v6.ip().octets()); // 16 bytes
                buf.extend_from_slice(&v6.port().to_be_bytes()); // 2 bytes
            }
        }

        stream.write_all(&buf).await
    }

    async fn command_reply_by_atype(
        &mut self,
        stream: &mut TcpStream,
        resp: u8,
        atype: u8,
    ) -> IoResult<()> {
        let buf = &mut self.buf;
        buf.clear();
        buf.put_u8(SOCKS5_VER);
        buf.put_u8(resp);
        buf.put_u8(0x0);
        buf.put_u8(atype);
        log::debug!("command_reply_by_atype {} {}", resp, atype);
        match atype {
            0x01 => {
                // IPv4: 4 bytes IP + 2 bytes PORT
                buf.extend(std::iter::repeat(0u8).take(6));
            }
            0x03 => {
                // DOMAIN: 1 byte len(=0) + 0 byte domain + 2 bytes PORT
                buf.extend(std::iter::repeat(0u8).take(3));
            }
            0x04 => {
                // IPv6: 16 bytes IP + 2 bytes PORT
                buf.extend(std::iter::repeat(0u8).take(18));
            }
            _ => {
                // IPv4: 4 bytes IP + 2 bytes PORT
                buf.extend(std::iter::repeat(0u8).take(6));
            }
        }

        stream.write_all(&buf).await
    }
}

#[async_trait]
impl InboundHandler for SocksInboundHandler {
    async fn handle_connection(&mut self, mut stream: TcpStream) -> anyhow::Result<()> {
        self.handle_handshake(&mut stream).await?;
        self.handle_command(&mut stream).await?;
        Ok(())
    }
}

impl SimpleAuthenticator {
    pub fn new(username: String, password: String, enabled: bool) -> Self {
        Self {
            username,
            password,
            enabled,
        }
    }
}

impl Authenticator for SimpleAuthenticator {
    fn enabled(&self) -> bool {
        self.enabled
    }

    fn authenticate(&self, username: &str, password: &str) -> bool {
        username == self.username && password == self.password
    }
}
