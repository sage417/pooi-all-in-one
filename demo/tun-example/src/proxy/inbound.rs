use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use self::socks5::{SimpleAuthenticator, SocksInboundHandler};
use crate::config::Inbound as InBoundConfig;
use async_trait::async_trait;

pub(crate) mod socks5;

pub struct InboundManager {
    inbound_configs: Vec<InBoundConfig>,
    pub(crate) handler_factory: Arc<dyn InboundHandlerFactory + Send + Sync>,
}

#[async_trait]
pub trait InboundHandler: Send + Sync {
    async fn handle_connection(&mut self, stream: TcpStream) -> anyhow::Result<()>;
}

pub trait InboundHandlerFactory {
    fn create_handler(&self, inbound: &InBoundConfig) -> anyhow::Result<Box<dyn InboundHandler>>;
}

impl InboundManager {
    pub fn new(
        inbound_configs: Vec<InBoundConfig>,
        handler_factory: Arc<dyn InboundHandlerFactory + Send + Sync>,
    ) -> Self {
        Self {
            inbound_configs,
            handler_factory,
        }
    }

    pub fn get_inbound_configs(&self) -> &Vec<InBoundConfig> {
        &self.inbound_configs
    }

    pub async fn start_all(
        &self,
        cancel_token: CancellationToken,
    ) -> anyhow::Result<Vec<JoinHandle<()>>> {
        let mut handles: Vec<JoinHandle<()>> = vec![];

        for inbound_config in &self.inbound_configs {
            // asyc task may live longer than inbound_manager
            let inbound_config = inbound_config.clone();
            let handler_factory = Arc::clone(&self.handler_factory);
            let cancel_token = cancel_token.clone();

            let handle = tokio::spawn(async move {
                if let Err(e) =
                    self::listen_inbound(inbound_config, handler_factory, cancel_token).await
                {
                    log::error!("Inbound listener failed: {:?}", e);
                }
            });
            handles.push(handle);
        }

        Ok(handles)
    }
}

pub async fn listen_inbound(
    inbound_config: InBoundConfig,
    factory: Arc<dyn InboundHandlerFactory + Send + Sync>,
    cancel_token: CancellationToken,
) -> anyhow::Result<()> {
    let listener = {
        let addr = format!("{}:{}", inbound_config.address, inbound_config.port);
        create_listener(&addr)?
    };

    log::info!(
        "Inbound listening on {}://{}",
        inbound_config.protocol,
        listener.local_addr()?,
    );

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, remote_addr) = accept_result?;
                log::debug!( "Accepted connection from {} to {}://{}", remote_addr, inbound_config.protocol, stream.local_addr()?);

                let mut handler = factory.create_handler(&inbound_config)?;
                // async handler muti connections
                tokio::spawn(async move {
                    if let Err(e) = handler.handle_connection(stream).await {
                        log::error!("handle connection error: {:?} remote: {}", e, remote_addr);
                    }
                });
            }
            _ = cancel_token.cancelled() => {
                log::info!(
                    "Stopping inbound listener on {}://{}:{}",
                    inbound_config.protocol,
                    inbound_config.address,
                    inbound_config.port
                );
                break;
            }

        }
    }
    Ok(())
}

fn create_listener(addr: &str) -> anyhow::Result<TcpListener> {
    // let listener = TcpListener::bind(&addr).await?;
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;

    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;

    socket.bind(&(addr.parse::<SocketAddr>()?).into())?;
    socket.listen(512)?;

    Ok(TcpListener::from_std(socket.into())?)
}

pub(crate) struct SimpleInboundHandlerFactory;

impl InboundHandlerFactory for SimpleInboundHandlerFactory {
    fn create_handler(&self, inbound: &InBoundConfig) -> anyhow::Result<Box<dyn InboundHandler>> {
        match inbound.protocol.as_str() {
            "socks" => {
                let authenticator = Arc::new(SimpleAuthenticator::new(
                    "admin".into(),
                    "123456".into(),
                    true,
                ));
                Ok(Box::new(SocksInboundHandler::new(authenticator)))
            }
            "http" => Ok(Box::new(SimpleHttpHandler {})),
            "shadowsocks" => Ok(Box::new(SimpleShadowsocksHandler {})),
            "vmess" => Ok(Box::new(SimpleVmssHandler {})),
            _ => Err(anyhow::anyhow!(
                "Unsupported inbound protocol: {}",
                inbound.protocol
            )),
        }
    }
}

struct SimpleHttpHandler;
struct SimpleShadowsocksHandler;
struct SimpleVmssHandler;

#[async_trait]
impl InboundHandler for SimpleHttpHandler {
    async fn handle_connection(&mut self, _stream: TcpStream) -> anyhow::Result<()> {
        log::info!("Handling HTTP connection (stub)");
        Ok(())
    }
}

#[async_trait]
impl InboundHandler for SimpleShadowsocksHandler {
    async fn handle_connection(&mut self, _stream: TcpStream) -> anyhow::Result<()> {
        log::info!("Handling Shadowsocks connection (stub)");
        Ok(())
    }
}

#[async_trait]
impl InboundHandler for SimpleVmssHandler {
    async fn handle_connection(&mut self, _stream: TcpStream) -> anyhow::Result<()> {
        log::info!("Handling VMess connection (stub)");
        Ok(())
    }
}
