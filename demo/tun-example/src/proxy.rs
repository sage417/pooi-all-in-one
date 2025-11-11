use async_trait::async_trait;
use std::io::Result as IoResult;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::app::session::{SocksAddr, TransportProtocol};

/// A reliable transport for both inbound and outbound handlers.
pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

impl<S> ProxyStream for S where S: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

pub type AnyProxyStream = Box<dyn ProxyStream>;

#[derive(Debug, Clone)]
pub enum OutboundConnect {
    Proxy(TransportProtocol, String, u16),
    Direct,
    Next,
    Unknown,
}

/// The receive half.
#[async_trait]
trait OutboundDatagramRecvHalf: Sync + Send + Unpin {
    /// Receives a message on the socket. On success, returns the number of
    /// bytes read and the origin of the message.
    async fn recv_from(&mut self, buf: &mut [u8]) -> IoResult<(usize, SocksAddr)>;
}

/// The send half.
#[async_trait]
trait OutboundDatagramSendHalf: Sync + Send + Unpin {
    /// Sends a message on the socket to `dst_addr`. On success, returns the
    /// number of bytes sent.
    async fn send_to(&mut self, buf: &[u8], dst_addr: &SocksAddr) -> IoResult<usize>;

    /// Close the soccket gracefully.
    async fn close(&mut self) -> IoResult<()>;
}

pub type AnyOutboundDatagramRecvHalf = Box<dyn OutboundDatagramRecvHalf>;
pub type AnyOutboundDatagramSendHalf = Box<dyn OutboundDatagramSendHalf>;

/// An unreliable transport for outbound handlers.
pub trait OutboundDatagram: Send + Unpin {
    /// Splits the datagram.
    fn split(self: Box<Self>) -> (AnyOutboundDatagramRecvHalf, AnyOutboundDatagramSendHalf);
}

pub type AnyOutboundDatagram = Box<dyn OutboundDatagram>;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum DatagramTransportType {
    Reliable,
    Unreliable,
    Unknown,
}

/// An outbound transport represents either a reliable or unreliable transport.
pub enum OutboundTransport<S, D> {
    /// The reliable transport.
    Stream(S),
    /// The unreliable transport.
    Datagram(D),
}

pub type AnyOutboundTransport = OutboundTransport<AnyProxyStream, AnyOutboundDatagram>;
