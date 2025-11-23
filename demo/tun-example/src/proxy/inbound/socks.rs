use std::{io, sync::Arc};

use bytes::{BufMut, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use super::InboundHandler;

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_AUTH_HEAD: u8 = 0x01;

// SOCKS5 RFC 1928
pub(crate) mod auth_methods {
    pub const NO_AUTHENTICATION_REQUIRED: u8 = 0x00;
    pub const USERNAME_PASSWORD: u8 = 0x02;
    pub const NO_ACCEPTABLE_METHODS: u8 = 0xff;
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

    async fn handle_handshake(&self, stream: &mut TcpStream) -> io::Result<()> {
        // handshake
        let mut buf = BytesMut::new();
        {
            buf.resize(2, 0);
            stream.read_exact(&mut buf[..]).await?;

            if buf[0] != SOCKS5_VERSION {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "Rejected non-SOCKS5 connection: client sent version={}, remote_addr={:?}",
                        buf[0],
                        stream.peer_addr()
                    ),
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
            stream.read_exact(&mut buf[..]).await?;

            let client_methods = &buf[..];

            // NO_ACCEPTABLE_METHODS
            if (self.authenticator.enabled()
                && !client_methods.contains(&auth_methods::USERNAME_PASSWORD))
                || !client_methods.contains(&auth_methods::NO_AUTHENTICATION_REQUIRED)
            {
                stream
                    .write_all(&[SOCKS5_VERSION, auth_methods::NO_ACCEPTABLE_METHODS])
                    .await?;
                stream.shutdown().await?;
                return Err(io::Error::other(
                    "Rejected SOCKS5 connection: NO_ACCEPTABLE_METHODS, remote_addr={:?}",
                ));
            }
            // choose suitable auth method
            let auth_method = if self.authenticator.enabled() {
                auth_methods::USERNAME_PASSWORD
            } else {
                auth_methods::NO_AUTHENTICATION_REQUIRED
            };

            stream.write_all(&[SOCKS5_VERSION, auth_method]).await?;

            if self.authenticator.enabled() {
                // +----+------+----------+------+----------+
                // |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
                // +----+------+----------+------+----------+
                // | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
                // +----+------+----------+------+----------+
                buf.resize(2, 0);
                stream.read_exact(&mut buf[..]).await?;
                let ulen = buf[1] as usize;
                buf.resize(ulen, 0);
                stream.read_exact(&mut buf[..]).await?;
                let user_result = String::from_utf8(buf.to_vec());

                let user = match user_result {
                    Ok(u) => u,
                    Err(_) => {
                        stream
                            .write_all(&[SOCKS5_AUTH_HEAD, response_code::FAILURE])
                            .await?;
                        stream.shutdown().await?;
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Rejected SOCKS5 connection: username is not valid UTF-8",
                        ));
                    }
                };

                stream.read_exact(&mut buf[..1]).await?;
                let plen = buf[0] as usize;
                buf.resize(plen, 0);
                stream.read_exact(&mut buf[..]).await?;
                let pass_result = String::from_utf8(buf[..].to_vec());
                let pass = match pass_result {
                    Ok(p) => p,
                    Err(_) => {
                        stream
                            .write_all(&[SOCKS5_AUTH_HEAD, response_code::FAILURE])
                            .await?;
                        stream.shutdown().await?;
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Rejected SOCKS5 connection: password is not valid UTF-8",
                        ));
                    }
                };

                match self.authenticator.authenticate(&user, &pass) {
                    // +----+--------+
                    // |VER | STATUS |
                    // +----+--------+
                    // | 1  |   1    |
                    // +----+--------+
                    true => {
                        stream
                            .write_all(&[SOCKS5_AUTH_HEAD, response_code::SUCCEEDED])
                            .await?;
                    }
                    false => {
                        stream
                            .write_all(&[SOCKS5_AUTH_HEAD, response_code::FAILURE])
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
        Ok(())
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
