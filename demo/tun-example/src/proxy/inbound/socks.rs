use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

use bytes::{BufMut, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::session::{SocksAddr, socks_addr};

use super::InboundHandler;

// RFC 1928
const SOCKS5_VER: u8 = 0x05;
// RFC 1929
const SOCKS5_AUTH_VER: u8 = 0x01;

pub(crate) mod auth_methods {
    pub const NO_AUTHENTICATION_REQUIRED: u8 = 0x00;
    pub const USERNAME_PASSWORD: u8 = 0x02;
    pub const NO_ACCEPTABLE_METHODS: u8 = 0xff;
}

#[allow(dead_code)]
pub(crate) mod socks_command {
    pub const CONNECT: u8 = 0x01;
    pub const BIND: u8 = 0x02;
    pub const UDP_ASSOCIATE: u8 = 0x03;
}

#[allow(dead_code)]
pub(crate) mod atype {
    pub const IPV4: u8 = 0x01;
    pub const DOMAIN: u8 = 0x03;
    pub const IPV6: u8 = 0x04;
}

#[allow(dead_code)]
pub(crate) mod response_code {
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

pub(super) struct SocksInboundHandler {
    authenticator: Arc<dyn Authenticator>,
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
        Self { authenticator }
    }

    fn reject_connection(
        kind: io::ErrorKind,
        message: impl Into<String>,
        addr: std::net::SocketAddr,
    ) -> io::Error {
        io::Error::new(
            kind,
            format!(
                "Rejected SOCKS5 connection: {} (remote_addr={})",
                message.into(),
                addr
            ),
        )
    }

    async fn handle_handshake(&self, stream: &mut TcpStream) -> io::Result<()> {
        // +----+----------+----------+
        // |VER | NMETHODS | METHODS  |
        // +----+----------+----------+
        // | 1  |    1     | 1 to 255 |
        // +----+----------+----------+

        // 1) Handshake / Method Selection
        let mut buf = BytesMut::new();
        {
            buf.resize(2, 0);
            stream.read_exact(buf.as_mut()).await?;

            if buf[0] != SOCKS5_VER {
                return Err(Self::reject_connection(
                    io::ErrorKind::Unsupported,
                    format!("client sent version=0x{:02x}", buf[0]),
                    stream.peer_addr()?,
                ));
            }

            let n_methods = buf[1] as usize;
            if n_methods == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Rejected SOCKS5 connection: n_methods is zero, remote_addr={:?}",
                        stream.peer_addr()
                    ),
                ));
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
                // return Err(io::Error::other(
                //     "Rejected SOCKS5 connection: NO_ACCEPTABLE_METHODS, remote_addr={:?}",
                // ));
                return Err(Self::reject_connection(
                    io::ErrorKind::Other,
                    "NO_ACCEPTABLE_METHODS",
                    stream.peer_addr()?,
                ));
            }
            // choose suitable auth method
            let auth_method = if self.authenticator.enabled() {
                auth_methods::USERNAME_PASSWORD
            } else {
                auth_methods::NO_AUTHENTICATION_REQUIRED
            };

            stream.write_all(&[SOCKS5_VER, auth_method]).await?;
            // 2) Authentication
            if self.authenticator.enabled() {
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
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Rejected SOCKS5 connection: username is not valid UTF-8",
                    ));
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
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Rejected SOCKS5 connection: password is not valid UTF-8",
                    ));
                };

                match self.authenticator.authenticate(&uname, &pass) {
                    // +----+--------+
                    // |VER | STATUS |
                    // +----+--------+
                    // | 1  |   1    |
                    // +----+--------+
                    true => {
                        stream
                            .write_all(&[SOCKS5_AUTH_VER, response_code::SUCCEEDED])
                            .await?;
                    }
                    false => {
                        stream
                            .write_all(&[SOCKS5_AUTH_VER, response_code::FAILURE])
                            .await?;
                        stream.shutdown().await?;
                        return Err(io::Error::other(format!(
                            "Rejected SOCKS5 connection: auth failed, remote_addr={:?}",
                            stream.peer_addr()
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_command(&self, stream: &mut TcpStream) -> io::Result<()> {
        // +----+-----+-------+------+----------+----------+
        // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        // +----+-----+-------+------+----------+----------+
        // | 1  |  1  |   1   |  1   | Variable |    2     |
        // +----+-----+-------+------+----------+----------+

        let mut buf = BytesMut::new();

        buf.resize(4, 0);
        stream.read_exact(buf.as_mut()).await?;

        let ver = buf[0];
        let cmd = buf[1];
        let atype = buf[3];
        // let [ver, cmd, _, atype] = buf.as_ref() else {
        //     return Err(io::Error::other("unsupported SOCKS version"));
        // };

        if ver != SOCKS5_VER {
            return Err(Self::reject_connection(
                io::ErrorKind::Unsupported,
                format!("client sent version=0x{:02x}", buf[0]),
                stream.peer_addr()?,
            ));
        }

        let dst_addr = match atype {
            0x01 => {
                let mut ip_bytes: [u8; 4] = [0u8; 4];
                let mut port_bytes: [u8; 2] = [0u8; 2];

                stream.read_exact(&mut ip_bytes).await?;
                stream.read_exact(&mut port_bytes).await?;

                let ip = Ipv4Addr::from(ip_bytes);
                let port = u16::from_be_bytes(port_bytes);
                SocksAddr::Ip(SocketAddr::V4(SocketAddrV4::new(ip, port)))
            }
            0x03 => {
                buf.resize(1, 0);
                stream.read_exact(buf.as_mut()).await?;
                let domain_len = buf[0] as usize;

                if domain_len < 1 || domain_len > 255 {
                    Self::reply_command_by_atype(
                        stream,
                        response_code::ADDR_TYPE_NOT_SUPPORTED,
                        atype,
                    )
                    .await?;
                    return Err(Self::reject_connection(
                        io::ErrorKind::InvalidData,
                        &format!("Invalid domain length: {}", domain_len),
                        stream.peer_addr()?,
                    ));
                }

                buf.resize(domain_len, 0);
                stream.read_exact(buf.as_mut()).await?;

                // std::str::from_utf8(buf.as_ref());

                let Ok(domain) = String::from_utf8(buf.to_vec()) else {
                    // stream
                    //     .write_all(&[SOCKS5_AUTH_HEAD, response_code::FAILURE])
                    //     .await?;
                    // stream.shutdown().await?;
                    Self::reply_command_by_atype(stream, response_code::ADDR_TYPE_NOT_SUPPORTED, atype).await?;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid domain (not valid UTF-8)",
                    ));
                };

                let mut port_bytes: [u8; 2] = [0u8; 2];
                stream.read_exact(&mut port_bytes).await?;

                let port = u16::from_be_bytes(port_bytes);

                SocksAddr::Domain(domain, port)
            }
            0x04 => {
                let mut ip_bytes: [u8; 16] = [0u8; 16];
                let mut port_bytes: [u8; 2] = [0u8; 2];

                stream.read_exact(&mut ip_bytes).await?;
                stream.read_exact(&mut port_bytes).await?;

                let ip = Ipv6Addr::from(ip_bytes);
                let port = u16::from_be_bytes(port_bytes);
                SocksAddr::Ip(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
            }
            _ => {
                return Err(Self::reject_connection(
                    io::ErrorKind::InvalidData,
                    "invalid atype",
                    stream.peer_addr()?,
                ));
            }
        };

        // +----+-----+-------+------+----------+----------+
        // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        // +----+-----+-------+------+----------+----------+
        // | 1  |  1  | X'00' |  1   | Variable |    2     |
        // +----+-----+-------+------+----------+----------+

        // let dst = SocksAddr::read_from(&mut stream).await?;
        buf.clear();

        match cmd {
            socks_command::CONNECT => {
                // let target_addr: SocketAddr;

                let target_addr = match dst_addr {
                    SocksAddr::Ip(addr) => addr,
                    SocksAddr::Domain(domain, _) => {
                        // domain lookup
                        let mut addrs = tokio::net::lookup_host(domain).await?;
                        addrs.next().ok_or_else(|| {
                            io::Error::new(io::ErrorKind::Other, "No IP found for domain")
                        })?
                    }
                };

                // connect
                let result = TcpStream::connect(&target_addr).await;

                let Ok(outbound) = result else {
                    let rep = match result {
                        Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => response_code::CONNECTION_REFUSED,
                        Err(ref e) if e.kind() == io::ErrorKind::TimedOut => response_code::TTL_EXPIRED,
                        Err(ref e) if e.kind() == io::ErrorKind::HostUnreachable => response_code::HOST_UNREACHABLE,
                        Err(ref e) if e.kind() == io::ErrorKind::NetworkUnreachable => response_code::NETWORK_UNREACHABLE,
                        _ => response_code::FAILURE,
                    };

                    Self::reply_command_by_atype(stream, rep, atype).await?;

                    return Err(Self::reject_connection(
                        io::ErrorKind::Other,
                        format!("Failed to connect to target: {:?}", result.err()),
                        stream.peer_addr()?,
                    ));
                };

                let bind_addr = outbound
                    .local_addr()
                    .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());

                Self::command_reply_by_bind_addr(stream, response_code::SUCCEEDED, &bind_addr)
                    .await?;

                log::info!(
                    "SOCKS5 proxy established: {} -> {}",
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
                            log::debug!("Client->Target error: {}", e);
                        }
                    }
                    res = target_to_client => {
                        if let Err(e) = res {
                            log::debug!("Target->Client error: {}", e);
                        }
                    }
                }
            }
            _ => {
                Self::reply_command_by_atype(stream, response_code::COMMAND_NOT_SUPPORTED, atype)
                    .await?;

                return Err(Self::reject_connection(
                    io::ErrorKind::Other,
                    &format!("Unsupported command: 0x{:02x}", cmd),
                    stream.peer_addr()?,
                ));
            }
        }

        Ok(())
    }

    async fn command_reply_by_bind_addr(
        stream: &mut TcpStream,
        resp: u8,
        bind_addr: &SocketAddr,
    ) -> io::Result<()> {
        let mut buf = BytesMut::new();
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
            // (0x03,SocksAddr::Domain(domain, port)) => {
            //     // DOMAIN: 1 byte len(=0) + 0 byte domain + 2 bytes PORT
            //     buf.extend(std::iter::repeat(0u8).take(3));
            // }
            SocketAddr::V6(v6) => {
                buf.put_u8(0x04); // ATYP = IPv6
                buf.extend_from_slice(&v6.ip().octets()); // 16 bytes
                buf.extend_from_slice(&v6.port().to_be_bytes()); // 2 bytes
            }
        }

        stream.write_all(&buf).await
    }

    async fn reply_command_by_atype(stream: &mut TcpStream, resp: u8, atype: u8) -> io::Result<()> {
        let mut buf = BytesMut::new();

        buf.put_u8(SOCKS5_VER);
        buf.put_u8(resp);
        buf.put_u8(0x0);
        buf.put_u8(atype);

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

#[async_trait::async_trait]
impl InboundHandler for SocksInboundHandler {
    async fn handle_connection(&self, mut stream: TcpStream) -> io::Result<()> {
        self.handle_handshake(&mut stream).await?;
        self.handle_command(&mut stream).await
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
