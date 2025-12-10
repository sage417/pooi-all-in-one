mod app;
mod protocol_handle;
mod proxy;
mod config {
    include!(concat!(env!("OUT_DIR"), "/config.rs"));
}
mod session;

use socket2::{Domain, Protocol, Socket, Type};
use std::{
    cmp, io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
};
#[allow(unused_imports)]
use std::{net::Ipv4Addr, time::Duration};
use thiserror::Error;
#[allow(unused_imports)]
use tokio::sync::RwLock;
use tokio::{net::UdpSocket, sync::oneshot::Sender};
use tokio_util::sync::CancellationToken;

#[allow(unused_imports)]
use crate::app::dns::DnsClient;
use crate::proxy::inbound::{InboundManager, SimpleInboundHandlerFactory};
use crate::{
    app::{
        dns::SyncDnsClient, outbound::manager::SyncOutboundManager, router::SyncRouter,
        stat_manager::SyncStatManager,
    },
    proxy::inbound::socks5::udp_relay::UdpRelayServer,
};

#[cfg(any(
    target_os = "windows",
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
#[allow(unused_imports)]
use tun_rs::DeviceBuilder;
#[allow(unused_imports)]
use tun_rs::{AsyncDevice, SyncDevice};

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Config(#[from] anyhow::Error),
    #[error("no associated config file")]
    NoConfigFile,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[cfg(feature = "auto-reload")]
    #[error(transparent)]
    Watcher(#[from] NotifyError),
    #[error(transparent)]
    AsyncChannelSend(
        #[from] tokio::sync::mpsc::error::SendError<std::sync::mpsc::SyncSender<Result<(), Error>>>,
    ),
    #[error(transparent)]
    SyncChannelRecv(#[from] std::sync::mpsc::RecvError),
    #[error("runtime manager error")]
    RuntimeManager,
}

#[allow(dead_code)]
pub struct RuntimeManager {
    config_path: Option<String>,

    router: SyncRouter,
    dns_client: SyncDnsClient,
    outbound_manager: SyncOutboundManager,
    stat_manager: SyncStatManager,
    shutdown_tx: Sender<()>,
}

pub fn start_service() -> Result<(), Error> {
    // let rt_manager = RuntimeManager{};

    let rt = new_runtime()?;
    log::info!("runtime worker num: {:?}", rt.metrics().num_workers());

    rt.block_on(async {
        let mut inbound_handles;
        let mut inbound_manager: InboundManager;

        loop {
            let cancel_token = CancellationToken::new();

            let udp_relay_server = build_udp_relay().await?;
            let udp_relay_addr = udp_relay_server.listener.clone().local_addr()?;
            log::info!("udp_relay_server listening on {}", udp_relay_addr);

            let cancel_token_cloned = cancel_token.clone();
            let upd_relay_handle = tokio::spawn(async move {
                let _ = udp_relay_server.run(cancel_token_cloned).await;
            });

            inbound_manager = InboundManager::new(
                vec![crate::config::Inbound {
                    address: String::from("0.0.0.0"),
                    port: 8888,
                    protocol: String::from("socks"),
                    tag: String::from(""),
                    settings: vec![],
                }],
                Arc::new(SimpleInboundHandlerFactory {}),
            );

            inbound_handles = inbound_manager
                .start_all(cancel_token.clone())
                .await
                .expect("Failed to start inbound handlers");

            inbound_handles.push(upd_relay_handle);

            #[cfg(unix)]
            {
                use tokio::signal::unix::{SignalKind, signal};

                let ctrl_c = tokio::signal::ctrl_c();
                let mut sighup = signal(SignalKind::hangup()).unwrap();

                tokio::select! {
                    _ = ctrl_c => {
                        log::info!("Received Ctrl+C, shutting down gracefully...");
                        cancel_token.cancel();
                        let _ = futures::future::join_all(inbound_handles).await;
                        break;
                    }
                    _ = sighup.recv() => {
                        log::info!("Received SIGHUP, reloading configuration...");
                        cancel_token.cancel();
                        let _ = futures::future::join_all(inbound_handles).await;
                        continue;
                    }
                }
            }

            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
                log::info!("Received Ctrl+C, shutting down (no SIGHUP on Windows)");
                cancel_token.cancel();
                break;
            }
        }
        Ok::<(), Error>(())
    })?;

    rt.shutdown_timeout(Duration::from_secs(1));

    Ok(())
}

fn new_runtime() -> Result<tokio::runtime::Runtime, Error> {
    let parallel = std::thread::available_parallelism()?;

    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cmp::min(parallel.into(), 4))
        .thread_stack_size(64 * 1024)
        .enable_all()
        .build()
        .map_err(Error::Io)
}

#[cfg(feature = "async_tokio")]
#[cfg(any(
    target_os = "windows",
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
// #[tokio::main]
// let dev = Arc::new(
//     DeviceBuilder::new()
//         .name("utun0")
//         .ipv4(Ipv4Addr::new(203, 0, 113, 1), 30, None)
//         // .ipv6("CDCD:910A:2222:5498:8475:1111:3900:2021", 64)
//         // .offload(true)
//         .mtu(1420)
//         .build_async()?,
// );

// log::info!("name:{:?}", dev.name()?);
// log::info!("addresses:{:?}", dev.addresses()?);
// let size = dev.mtu()? as usize;
// log::info!("mtu:{size:?}",);
// let mut buf = vec![0; size];
// loop {
//     tokio::select! {
//         _ = tokio::signal::ctrl_c() => {
//             log::info!("Quit...");
//             break;
//         }
//         len = dev.recv(&mut buf) => {
//             let len = len?;
//             log::info!("raw packet header (first 20B): {:02x?}", &buf[..std::cmp::min(len, 20)]);
//             //println!("pkt: {:?}", &buf[..len?]);
//             handle_pkt(&buf[..len], &dev).await?;
//         }
//     }
// }
// Ok(())
fn main() -> Result<(), Error> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace"))
        .format(|buf, record| {
            use std::io::Write;

            let timestamp = buf.timestamp();
            let level = record.level();
            let file = record.file().unwrap_or("unknown");
            let line = record.line().unwrap_or(0);
            let args = record.args();

            writeln!(
                buf,
                "{} {:>5} [{}:{}] {}",
                timestamp, level, file, line, args
            )
        })
        .init();
    start_service()
}

#[cfg(feature = "async_io")]
#[cfg(any(
    target_os = "windows",
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
))]
#[async_std::main]
async fn main() -> std::io::Result<()> {
    use async_ctrlc::CtrlC;
    use async_std::prelude::FutureExt;
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();
    let dev = Arc::new(
        DeviceBuilder::new()
            .ipv4(Ipv4Addr::from([10, 0, 0, 9]), 24, None)
            .build_async()?,
    );
    let size = dev.mtu()? as usize;
    let mut buf = vec![0; size];
    let ctrlc = CtrlC::new().expect("cannot create Ctrl+C handler?");
    ctrlc
        .race(async {
            while let Ok(len) = dev.recv(&mut buf).await {
                info!("len = {len}");
                //info!("pkt: {:?}", &buf[..len]);
                handle_pkt(&buf[..len], &dev).await.unwrap();
            }
        })
        .await;
    Ok(())
}

#[cfg(not(feature = "async_tokio"))]
#[cfg(any(
    target_os = "ios",
    target_os = "tvos",
    target_os = "android",
    all(target_os = "linux")
))]
fn main() -> std::io::Result<()> {
    unimplemented!()
}

#[allow(dead_code)]
async fn handle_pkt(pkt: &[u8], dev: &AsyncDevice) -> std::io::Result<()> {
    if let Some(buf) = protocol_handle::ping(pkt) {
        dev.send(&buf).await?;
    }
    Ok(())
}

async fn build_udp_relay() -> io::Result<UdpRelayServer> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_broadcast(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&socket2::SockAddr::from(SocketAddr::new(
        "0.0.0.0".parse().unwrap(),
        8888,
    )))?;

    let udp_socket = UdpSocket::from_std(socket.into())?;
    let udp_relay_server = UdpRelayServer {
        ttl: Some(Duration::from_mins(5)),
        capacity: Some(32),
        listener: Arc::new(udp_socket),
    };
    Ok(udp_relay_server)
}
