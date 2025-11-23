mod app;
mod protocol_handle;
mod proxy;
mod config {
    include!(concat!(env!("OUT_DIR"), "/config.rs"));
}
mod session;

#[allow(unused_imports)]
use std::{net::Ipv4Addr, time::Duration};
use std::{pin::Pin, sync::Arc};
use thiserror::Error;
#[allow(unused_imports)]
use tokio::sync::RwLock;
use tokio::sync::oneshot::Sender;
use tokio_util::sync::CancellationToken;

#[allow(unused_imports)]
use crate::app::dns::DnsClient;
use crate::app::{
    dns::SyncDnsClient, outbound::manager::SyncOutboundManager, router::SyncRouter,
    stat_manager::SyncStatManager,
};
use crate::proxy::inbound::{InboundManager, SimpleInboundHandlerFactory};

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
            inbound_manager = InboundManager::new(
                vec![crate::config::Inbound {
                    address: String::from("192.168.31.1"),
                    port: 8888,
                    protocol: String::from("socks"),
                    tag: String::from(""),
                    settings: vec![],
                }],
                Arc::new(SimpleInboundHandlerFactory {}),
            );

            let cancel_token = CancellationToken::new();

            inbound_handles = inbound_manager
                .start_all(cancel_token.clone())
                .await
                .expect("Failed to start inbound handlers");

            #[cfg(unix)]
            {
                use tokio::signal::unix::{SignalKind, signal};

                let ctrl_c = tokio::signal::ctrl_c();
                let mut sighup = signal(SignalKind::hangup()).unwrap();

                tokio::select! {
                    _ = ctrl_c => {
                        log::info!("Received Ctrl+C, shutting down gracefully...");
                        cancel_token.cancel();
                        break;
                    }
                    _ = sighup.recv() => {
                        log::info!("Received SIGHUP, reloading configuration...");
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

        let _ = futures::future::join_all(inbound_handles);
    });

    rt.shutdown_timeout(Duration::from_secs(1));

    Ok(())
}

fn new_runtime() -> Result<tokio::runtime::Runtime, Error> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_stack_size(128 * 1024)
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
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();
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
