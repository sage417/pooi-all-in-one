use std::{
    fmt,
    io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

#[derive(Debug, PartialEq, Eq)]
pub enum SocksAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl SocksAddr {
    pub fn any() -> Self {
        Self::any_ipv4()
    }

    pub fn any_ipv4() -> Self {
        Self::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    pub fn any_ipv6() -> Self {
        Self::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))
    }

    pub fn must_ip(&self) -> &SocketAddr {
        match self {
            SocksAddr::Ip(a) => a,
            _ => {
                panic!("assert SocksAddr as SocketAddr failed");
            }
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Self::Ip(addr) => match addr {
                SocketAddr::V4(_addr) => 1 + 4 + 2,
                SocketAddr::V6(_addr) => 1 + 16 + 2,
            },
            Self::Domain(domain, _port) => 1 + 1 + domain.len() + 2,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            SocksAddr::Ip(addr) => addr.port(),
            SocksAddr::Domain(_, port) => *port,
        }
    }

    pub fn is_domain(&self) -> bool {
        match self {
            SocksAddr::Ip(_) => false,
            SocksAddr::Domain(_, _) => true,
        }
    }

    pub fn domain(&self) -> Option<&String> {
        if let SocksAddr::Domain(domain, _) = self {
            Some(domain)
        } else {
            None
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        if let SocksAddr::Ip(addr) = self {
            Some(addr.ip())
        } else {
            None
        }
    }

    pub fn host(&self) -> String {
        match self {
            SocksAddr::Ip(addr) => {
                let ip = addr.ip();
                ip.to_string()
            }
            SocksAddr::Domain(domain, _) => domain.to_owned(),
        }
    }
}

impl Clone for SocksAddr {
    fn clone(&self) -> Self {
        match self {
            SocksAddr::Ip(addr) => SocksAddr::Ip(addr.clone()),
            SocksAddr::Domain(domain, port) => SocksAddr::Domain(domain.clone(), *port),
        }
    }
}

impl fmt::Display for SocksAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            SocksAddr::Ip(addr) => addr.to_string(),
            SocksAddr::Domain(domain, port) => format!("{}:{}", domain, port),
        };
        write!(f, "{}", s)
    }
}

impl From<(IpAddr, u16)> for SocksAddr {
    fn from(value: (IpAddr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(Ipv4Addr, u16)> for SocksAddr {
    fn from(value: (Ipv4Addr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(Ipv6Addr, u16)> for SocksAddr {
    fn from(value: (Ipv6Addr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<SocketAddr> for SocksAddr {
    fn from(value: SocketAddr) -> Self {
        Self::Ip(value)
    }
}

impl From<&SocketAddr> for SocksAddr {
    fn from(addr: &SocketAddr) -> Self {
        Self::Ip(addr.to_owned())
    }
}

impl From<SocketAddrV4> for SocksAddr {
    fn from(value: SocketAddrV4) -> Self {
        Self::Ip(value.into())
    }
}

impl From<SocketAddrV6> for SocksAddr {
    fn from(value: SocketAddrV6) -> Self {
        Self::Ip(value.into())
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
        Ok(Self::Domain(addr, port))
    }
}

fn insuff_bytes() -> IoError {
    IoError::new(IoErrorKind::Other, "insufficient bytes")
}

fn invalid_domain() -> IoError {
    IoError::new(IoErrorKind::Other, "invalid domain")
}

fn invalid_addr_type() -> IoError {
    IoError::new(IoErrorKind::Other, "invalid address type")
}
