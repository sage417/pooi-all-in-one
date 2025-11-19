use async_trait::async_trait;
use futures::future::AbortHandle;
use std::collections::HashMap;
use std::io::Result as IoResult;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::proxy::{
    DatagramTransportType, OutboundConnect, OutboundDatagram, OutboundTransport, ProxyStream,
};
use crate::session::Session;

pub type SyncOutboundManager = Arc<RwLock<OutboundManager>>;

#[allow(dead_code)]
pub struct OutboundManager {
    handlers: HashMap<String, Arc<dyn OutboundHandler>>,
    default_handler: Option<String>,
    abort_handles: Vec<AbortHandle>,
}

#[allow(dead_code)]
pub trait Tag {
    fn tag(&self) -> &String;
}

#[allow(dead_code)]
pub trait Color {
    fn color(&self) -> &colored::Color;
}

#[allow(dead_code)]
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

#[allow(dead_code)]
type AnyOutboundStreamHandler = Box<dyn OutboundStreamHandler>;

/// An outbound handler for outgoing UDP connections.
#[async_trait]
pub trait OutboundDatagramHandler<S = Box<dyn ProxyStream>, D = Box<dyn OutboundDatagram>>:
    Send + Sync + Unpin
{
    /// Returns the address which the underlying transport should
    /// communicate with.
    #[allow(dead_code)]
    fn connect_addr(&self) -> OutboundConnect;

    /// Returns the transport type of this handler.
    #[allow(dead_code)]
    fn transport_type(&self) -> DatagramTransportType;

    /// Handles a session with the transport. On success, returns an outbound
    /// datagram wraps the incoming transport.
    #[allow(dead_code)]
    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<OutboundTransport<S, D>>,
    ) -> IoResult<D>;
}

#[allow(dead_code)]
pub trait OutboundHandler: Tag + Color + Sync + Send + Unpin {
    fn stream(&self) -> IoResult<&AnyOutboundStreamHandler>;
    fn datagram(&self) -> IoResult<&Box<dyn OutboundDatagramHandler>>;
}
