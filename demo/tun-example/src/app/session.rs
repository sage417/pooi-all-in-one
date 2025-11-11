use std::net::{IpAddr, SocketAddr};

pub type StreamId = u64;

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SocksAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

#[allow(dead_code)]
pub struct Session {
    /// The network type, representing either TCP or UDP.
    pub protocol: TransportProtocol,
    /// The socket address of the remote peer of an inbound connection.
    pub source: SocketAddr,
    /// The socket address of the local socket of an inbound connection.
    pub local_addr: SocketAddr,
    /// The proxy target address of a proxy connection.
    pub destination: SocksAddr,
    /// The tag of the inbound handler this session initiated.
    pub inbound_tag: String,
    /// The tag of the first outbound handler this session goes.
    pub outbound_tag: String,
    /// Optional stream ID for multiplexing transports.
    pub stream_id: Option<StreamId>,
    /// Optional source address which is forwarded via HTTP reverse proxy.
    pub forwarded_source: Option<IpAddr>,
    /// Optional process name that initiated this connection.
    pub process_name: Option<String>,
    /// Instructs a multiplexed transport should creates a new underlying
    /// connection for this session, and it will be used only once.
    pub new_conn_once: bool,
}
