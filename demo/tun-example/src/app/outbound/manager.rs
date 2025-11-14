use async_trait::async_trait;
use futures::future::AbortHandle;
use std::collections::HashMap;
use std::io::Result as IoResult;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{proxy::{OutboundDatagram, ProxyStream}, session::Session};
use crate::proxy::{
    DatagramTransportType, OutboundConnect, OutboundTransport,
};

pub type SyncOutboundManager = Arc<RwLock<OutboundManager>>;

#[allow(dead_code)]
pub struct OutboundManager {
    handlers: HashMap<String, Arc<dyn OutboundHandler>>,
    default_handler: Option<String>,
    abort_handles: Vec<AbortHandle>,
}

pub trait Tag {
    fn tag(&self) -> &String;
}

pub trait Color {
    fn color(&self) -> &colored::Color;
}

#[async_trait]
pub trait OutboundStreamHandler<S = Box<dyn ProxyStream>>: Send + Sync + Unpin {
    /// Returns the address which the underlying transport should
    /// communicate with.
    fn connect_addr(&self) -> OutboundConnect;

    /// Handles a session with the given stream. On success, returns a
    /// stream wraps the incoming stream.
    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        lhs: Option<&mut S>,
        stream: Option<S>,
    ) -> IoResult<S>;
}

type AnyOutboundStreamHandler = Box<dyn OutboundStreamHandler>;

/// An outbound handler for outgoing UDP connections.
#[async_trait]
pub trait OutboundDatagramHandler<S = Box<dyn ProxyStream>, D = Box<dyn OutboundDatagram>>:
    Send + Sync + Unpin
{
    /// Returns the address which the underlying transport should
    /// communicate with.
    fn connect_addr(&self) -> OutboundConnect;

    /// Returns the transport type of this handler.
    fn transport_type(&self) -> DatagramTransportType;

    /// Handles a session with the transport. On success, returns an outbound
    /// datagram wraps the incoming transport.
    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<OutboundTransport<S, D>>,
    ) -> IoResult<D>;
}

pub trait OutboundHandler: Tag + Color + Sync + Send + Unpin {
    fn stream(&self) -> IoResult<&AnyOutboundStreamHandler>;
    fn datagram(&self) -> IoResult<&Box<dyn OutboundDatagramHandler>>;
}
