#[allow(unused_imports)]
use std::{
    fmt,
    io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

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
}

impl Clone for SocksAddr {
    fn clone(&self) -> Self {
        match self {
            SocksAddr::SocketAddr(addr) => SocksAddr::SocketAddr(addr.clone()),
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
            return Err(IoError::new(IoErrorKind::Other, "domain too long"));
        }
        Ok(Self::DomainNameAddr(addr, port))
    }
}

#[allow(dead_code)]
fn insuff_bytes() -> IoError {
    IoError::new(IoErrorKind::Other, "insufficient bytes")
}

#[allow(dead_code)]
fn invalid_domain() -> IoError {
    IoError::new(IoErrorKind::Other, "invalid domain")
}

#[allow(dead_code)]
fn invalid_addr_type() -> IoError {
    IoError::new(IoErrorKind::Other, "invalid address type")
}
