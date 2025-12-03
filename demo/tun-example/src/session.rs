use crate::proxy::inbound::socks5::SocksAddr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

pub type StreamId = u64;

#[allow(dead_code)]
#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum TransportProtocol {
    Tcp,
    Udp,
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

impl Clone for Session {
    fn clone(&self) -> Self {
        Session {
            protocol: self.protocol,
            source: self.source,
            local_addr: self.local_addr,
            destination: self.destination.clone(),
            inbound_tag: self.inbound_tag.clone(),
            outbound_tag: self.outbound_tag.clone(),
            stream_id: self.stream_id,
            forwarded_source: self.forwarded_source,
            process_name: self.process_name.clone(),
            new_conn_once: self.new_conn_once,
        }
    }
}

impl Default for Session {
    fn default() -> Self {
        Session {
            protocol: TransportProtocol::Tcp,
            source: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080)),
            local_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080)),
            destination: SocksAddr::any(),
            inbound_tag: "".to_string(),
            outbound_tag: "".to_string(),
            stream_id: None,
            forwarded_source: None,
            process_name: None,
            new_conn_once: false,
        }
    }
}
