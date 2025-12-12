use bytes::BufMut;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

use std::{
    fmt,
    io::{Error as IoError},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    slice,
};

pub(crate) mod socks;
pub(crate) mod udp_association;
pub(crate) mod udp_relay;
pub(crate) use self::socks::{SimpleAuthenticator, SocksInboundHandler};

const MAXIMUM_UDP_PAYLOAD_SIZE: usize = 1500;

pub(crate) mod atype {
    pub const IPV4: u8 = 0x01;
    pub const DOMAIN_NAME: u8 = 0x03;
    pub const IPV6: u8 = 0x04;
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
    InvalidUtf8Encoding { field: &'static str },
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

#[derive(Debug, PartialEq, Eq)]
pub enum SocksAddr {
    SocketAddr(SocketAddr),
    DomainNameAddr(String, u16),
}

impl SocksAddr {
    pub fn any() -> Self {
        Self::any_ipv4()
    }

    pub fn any_ipv4() -> Self {
        Self::SocketAddr(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    #[allow(dead_code)]
    pub fn any_ipv6() -> Self {
        Self::SocketAddr(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))
    }

    #[allow(dead_code)]
    pub fn must_ip(&self) -> &SocketAddr {
        match self {
            SocksAddr::SocketAddr(a) => a,
            _ => {
                panic!("assert SocksAddr as SocketAddr failed");
            }
        }
    }

    #[allow(dead_code)]
    pub fn size(&self) -> usize {
        match self {
            Self::SocketAddr(addr) => match addr {
                SocketAddr::V4(_addr) => 1 + 4 + 2,
                SocketAddr::V6(_addr) => 1 + 16 + 2,
            },
            Self::DomainNameAddr(domain, _port) => 1 + 1 + domain.len() + 2,
        }
    }

    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        match self {
            SocksAddr::SocketAddr(addr) => addr.port(),
            SocksAddr::DomainNameAddr(_, port) => *port,
        }
    }

    #[allow(dead_code)]
    pub fn is_domain(&self) -> bool {
        match self {
            SocksAddr::SocketAddr(_) => false,
            SocksAddr::DomainNameAddr(_, _) => true,
        }
    }

    #[allow(dead_code)]
    pub fn domain(&self) -> Option<&String> {
        if let SocksAddr::DomainNameAddr(domain, _) = self {
            Some(domain)
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub fn ip(&self) -> Option<IpAddr> {
        if let SocksAddr::SocketAddr(addr) = self {
            Some(addr.ip())
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub fn host(&self) -> String {
        match self {
            SocksAddr::SocketAddr(addr) => {
                let ip = addr.ip();
                ip.to_string()
            }
            SocksAddr::DomainNameAddr(domain, _) => domain.to_owned(),
        }
    }
    /// Parse from a `AsyncRead`
    pub async fn read_from<R>(stream: &mut R) -> Result<Self, SocksError>
    where
        R: AsyncRead + Unpin,
    {
        let mut addr_type_buf = [0u8; 1];
        let _ = stream.read_exact(&mut addr_type_buf).await?;

        let addr_type = addr_type_buf[0];
        match addr_type {
            atype::IPV4 => {
                let mut buf = [0u8; 6];
                let _ = stream.read_exact(&mut buf).await?;

                let v4addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = u16::from_be_bytes([buf[4], buf[5]]);
                Ok(SocksAddr::from((v4addr, port)))
            }
            atype::IPV6 => {
                let mut buf = [0u16; 9];

                let bytes_buf =
                    unsafe { slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut _, 18) };
                let _ = stream.read_exact(bytes_buf).await?;

                let v6addr = Ipv6Addr::new(
                    u16::from_be(buf[0]),
                    u16::from_be(buf[1]),
                    u16::from_be(buf[2]),
                    u16::from_be(buf[3]),
                    u16::from_be(buf[4]),
                    u16::from_be(buf[5]),
                    u16::from_be(buf[6]),
                    u16::from_be(buf[7]),
                );
                let port = u16::from_be(buf[8]);

                Ok(SocksAddr::from((v6addr, port)))
            }
            atype::DOMAIN_NAME => {
                let mut length_buf = [0u8; 1];
                let _ = stream.read_exact(&mut length_buf).await?;
                let length = length_buf[0] as usize;

                // Len(Domain) + Len(Port)
                let buf_length = length + 2;

                let mut domain_name_bytes = vec![0u8; buf_length];
                let _ = stream.read_exact(&mut domain_name_bytes).await?;

                let port_bytes = &domain_name_bytes[length..];
                let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);

                domain_name_bytes.truncate(length);

                let domain_name = match String::from_utf8(domain_name_bytes) {
                    Ok(name) => name,
                    Err(..) => return Err(SocksError::InvalidUtf8Encoding { field: "domain" }),
                };

                Ok(Self::DomainNameAddr(domain_name, port))
            }
            _ => {
                // Wrong Address Type . Socks5 only supports ipv4, ipv6 and domain name
                Err(SocksError::AddrTypeNotSupported { atype: addr_type })
            }
        }
    }

    fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        match *self {
            SocksAddr::SocketAddr(ref addr) => {
                match *addr {
                    SocketAddr::V4(ref addr) => {
                        buf.put_u8(atype::IPV4); // Address type
                        buf.put_slice(&addr.ip().octets()); // Ipv4 bytes
                        buf.put_u16(addr.port()); // Port
                    }
                    SocketAddr::V6(ref addr) => {
                        buf.put_u8(atype::IPV6); // Address type
                        for seg in &addr.ip().segments() {
                            buf.put_u16(*seg); // Ipv6 bytes
                        }
                        buf.put_u16(addr.port()); // Port
                    }
                }
            }
            SocksAddr::DomainNameAddr(ref dnaddr, port) => {
                assert!(dnaddr.len() <= u8::MAX as usize);

                buf.put_u8(atype::DOMAIN_NAME);
                assert!(
                    dnaddr.len() <= u8::MAX as usize,
                    "domain name length must be smaller than 256"
                );
                buf.put_u8(dnaddr.len() as u8);
                buf.put_slice(dnaddr.as_bytes());
                buf.put_u16(port);
            }
        }
    }

    /// Get required buffer size for serializing
    #[inline]
    pub fn serialized_len(&self) -> usize {
        match *self {
            SocksAddr::SocketAddr(SocketAddr::V4(..)) => 1 + 4 + 2,
            SocksAddr::SocketAddr(SocketAddr::V6(..)) => 1 + 8 * 2 + 2,
            SocksAddr::DomainNameAddr(ref domain_name, _) => 1 + 1 + domain_name.len() + 2,
        }
    }
}

impl Clone for SocksAddr {
    fn clone(&self) -> Self {
        match self {
            SocksAddr::SocketAddr(addr) => SocksAddr::SocketAddr(*addr),
            SocksAddr::DomainNameAddr(domain, port) => {
                SocksAddr::DomainNameAddr(domain.clone(), *port)
            }
        }
    }
}

impl fmt::Display for SocksAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            SocksAddr::SocketAddr(addr) => addr.to_string(),
            SocksAddr::DomainNameAddr(domain, port) => format!("{}:{}", domain, port),
        };
        write!(f, "{}", s)
    }
}

impl From<(IpAddr, u16)> for SocksAddr {
    fn from(value: (IpAddr, u16)) -> Self {
        Self::SocketAddr(value.into())
    }
}

impl From<(Ipv4Addr, u16)> for SocksAddr {
    fn from(value: (Ipv4Addr, u16)) -> Self {
        Self::SocketAddr(value.into())
    }
}

impl From<(Ipv6Addr, u16)> for SocksAddr {
    fn from(value: (Ipv6Addr, u16)) -> Self {
        Self::SocketAddr(value.into())
    }
}

impl From<SocketAddr> for SocksAddr {
    fn from(value: SocketAddr) -> Self {
        Self::SocketAddr(value)
    }
}

impl From<&SocketAddr> for SocksAddr {
    fn from(addr: &SocketAddr) -> Self {
        Self::SocketAddr(addr.to_owned())
    }
}

impl From<SocketAddrV4> for SocksAddr {
    fn from(value: SocketAddrV4) -> Self {
        Self::SocketAddr(value.into())
    }
}

impl From<SocketAddrV6> for SocksAddr {
    fn from(value: SocketAddrV6) -> Self {
        Self::SocketAddr(value.into())
    }
}

impl TryFrom<(&str, u16)> for SocksAddr {
    type Error = IoError;

    fn try_from((addr, port): (&str, u16)) -> Result<Self, Self::Error> {
        Self::try_from((addr.to_string(), port))
    }
}

impl TryFrom<(&String, u16)> for SocksAddr {
    type Error = IoError;

    fn try_from((addr, port): (&String, u16)) -> Result<Self, Self::Error> {
        Self::try_from((addr.to_owned(), port))
    }
}

impl TryFrom<(String, u16)> for SocksAddr {
    type Error = IoError;

    fn try_from((addr, port): (String, u16)) -> Result<Self, Self::Error> {
        if let Ok(ip) = addr.parse::<IpAddr>() {
            return Ok(Self::from((ip, port)));
        }
        if addr.len() > 0xff {
            return Err(IoError::other("domain too long"));
        }
        Ok(Self::DomainNameAddr(addr, port))
    }
}
