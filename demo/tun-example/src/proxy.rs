pub mod datagram;

use async_trait::async_trait;
use std::{fmt, io::Result as IoResult, net::SocketAddr};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::session::{SocksAddr, TransportProtocol};

/// A reliable transport for both inbound and outbound handlers.
pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

impl<S> ProxyStream for S where S: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum OutboundConnect {
    Proxy(TransportProtocol, String, u16),
    Direct,
    Next,
    Unknown,
}

#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum ProxyError {
    #[error(transparent)]
    DatagramWarn(anyhow::Error),
    #[error(transparent)]
    DatagramFatal(anyhow::Error),
}

#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum DatagramTransportType {
    Reliable,
    Unreliable,
    Unknown,
}

/// The receive half.
#[allow(dead_code)]
#[async_trait]
pub trait OutboundDatagramRecvHalf: Sync + Send + Unpin {
    /// Receives a message on the socket. On success, returns the number of
    /// bytes read and the origin of the message.
    async fn recv_from(&mut self, buf: &mut [u8]) -> IoResult<(usize, SocksAddr)>;
}

/// The send half.
#[allow(dead_code)]
#[async_trait]
pub trait OutboundDatagramSendHalf: Sync + Send + Unpin {
    /// Sends a message on the socket to `dst_addr`. On success, returns the
    /// number of bytes sent.
    async fn send_to(&mut self, buf: &[u8], dst_addr: &SocksAddr) -> IoResult<usize>;

    /// Close the soccket gracefully.
    async fn close(&mut self) -> IoResult<()>;
}

/// An unreliable transport for outbound handlers.
pub trait OutboundDatagram: Send + Unpin {
    /// Splits the datagram.
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    );
}

/// An outbound transport represents either a reliable or unreliable transport.
#[allow(dead_code)]
pub enum OutboundTransport<S, D> {
    /// The reliable transport.
    Stream(S),
    /// The unreliable transport.
    Datagram(D),
}

/// An unreliable transport for inbound handlers.
#[allow(dead_code)]
pub trait InboundDatagram: Send + Sync + Unpin {
    /// Splits the datagram.
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    );

    /// Turns the datagram into a [`std::net::UdpSocket`].
    fn into_std(self: Box<Self>) -> IoResult<std::net::UdpSocket>;
}

#[allow(dead_code)]
pub type ProxyResult<T> = Result<T, ProxyError>;

pub type StreamId = u64;

#[allow(dead_code)]
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct DatagramSource {
    pub address: SocketAddr,
    pub stream_id: Option<StreamId>,
    pub process_name: Option<String>,
}

/// The receive half.
#[allow(dead_code)]
#[async_trait]
pub trait InboundDatagramRecvHalf: Sync + Send + Unpin {
    /// Receives a single datagram message on the socket. On success, returns
    /// the number of bytes read, the source where this message
    /// originated and the destination this message shall be sent to.
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)>;
}

/// The send half.
#[allow(dead_code)]
#[async_trait]
pub trait InboundDatagramSendHalf: Sync + Send + Unpin {
    /// Sends a datagram message on the socket to `dst_addr`, the `src_addr`
    /// specifies the origin of the message. On success, returns the number
    /// of bytes sent.
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        dst_addr: &SocketAddr,
    ) -> IoResult<usize>;

    /// Close the socket gracefully.
    async fn close(&mut self) -> IoResult<()>;
}

impl DatagramSource {
    #[allow(dead_code)]
    pub fn new(address: SocketAddr, stream_id: Option<StreamId>) -> Self {
        DatagramSource {
            address,
            stream_id,
            process_name: None,
        }
    }

    #[allow(dead_code)]
    pub fn new_with_process_name(
        address: SocketAddr,
        stream_id: Option<StreamId>,
        process_name: Option<String>,
    ) -> Self {
        DatagramSource {
            address,
            stream_id,
            process_name,
        }
    }
}

impl fmt::Display for DatagramSource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(id) = self.stream_id.as_ref() {
            write!(f, "{}(stream-{})", self.address, id)
        } else {
            write!(f, "{}", self.address)
        }
    }
}

pub struct MockOutboundDatagram {

}

impl OutboundDatagram for MockOutboundDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        todo!()
    }
}
