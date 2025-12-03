use anyhow::{Result, anyhow};
use lru::LruCache;

#[allow(unused_imports)]
use hickory_proto::{
    op::{
        Message, header::MessageType, op_code::OpCode, query::Query, response_code::ResponseCode,
    },
    rr::{Name, record_data::RData, record_type::RecordType},
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use std::{collections::HashMap, num::NonZeroUsize};
use tokio::sync::{Mutex, RwLock};

use super::dispatcher::Dispatcher;
use crate::{
    proxy::{datagram::*, inbound::socks5::SocksAddr},
    session::*,
};

pub type SyncDnsClient = Arc<RwLock<DnsClient>>;
type DNSCache = Arc<Mutex<LruCache<String, CacheEntry>>>;

#[allow(dead_code)]
pub struct DnsClient {
    dispatcher: Option<Weak<Dispatcher>>,
    upstreams: Vec<SocketAddr>,
    hosts: HashMap<String, Vec<IpAddr>>,
    dns_cache: DNSCache,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct CacheEntry {
    pub v4_records: Vec<DnsRecord>,
    pub v6_records: Vec<DnsRecord>,
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
struct DnsRecord {
    pub ip: IpAddr,
    pub ttl: Duration,
    pub deadline: Instant,
}

impl CacheEntry {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            v4_records: Vec::new(),
            v6_records: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn add_record(&mut self, ip: IpAddr, ttl: Duration) {
        let record = DnsRecord::new(ip, ttl);
        match ip {
            IpAddr::V4(_) => self.v4_records.push(record),
            IpAddr::V6(_) => self.v6_records.push(record),
        }
    }

    #[allow(dead_code)]
    pub fn get_valid_v4_addrs(&self) -> Vec<IpAddr> {
        self.v4_records
            .iter()
            .filter(|r| !r.is_expired())
            .map(|r| r.ip)
            .collect()
    }

    #[allow(dead_code)]
    pub fn get_valid_v6_addrs(&self) -> Vec<IpAddr> {
        self.v6_records
            .iter()
            .filter(|r| !r.is_expired())
            .map(|r| r.ip)
            .collect()
    }
}

impl DnsRecord {
    #[allow(dead_code)]
    pub fn new(ip: IpAddr, ttl: Duration) -> Self {
        Self {
            ip,
            ttl,
            deadline: Instant::now() + ttl,
        }
    }

    #[allow(dead_code)]
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.deadline
    }
}

impl DnsClient {
    #[allow(dead_code)]
    pub fn new(dns_config: &crate::config::Dns) -> Result<Self> {
        if dns_config.upstreams.is_empty() {
            return Err(anyhow!("empty listening address"));
        }
        let mut upstreams = Vec::new();
        for addr in &dns_config.upstreams {
            upstreams.push(SocketAddr::new(addr.parse::<IpAddr>()?, 53));
        }

        let mut hosts = HashMap::new();

        for (name, str_ips) in &dns_config.hosts {
            let mut ips = Vec::new();
            for ip in &str_ips.values {
                if let Ok(parsed_ip) = ip.parse::<IpAddr>() {
                    ips.push(parsed_ip);
                }
            }
            hosts.insert(name.to_owned(), ips);
        }

        return Ok(Self {
            dispatcher: None,
            upstreams: upstreams,
            hosts,
            dns_cache: Arc::new(Mutex::new(LruCache::<String, CacheEntry>::new(
                NonZeroUsize::new(512).unwrap(),
            ))),
        });
    }

    #[allow(dead_code)]
    pub fn replace_dispatcher(&mut self, dispatcher: Weak<Dispatcher>) {
        self.dispatcher.replace(dispatcher);
    }

    #[allow(dead_code)]
    pub async fn optimize_dns_cache(&self, address: &str, connected_ip: IpAddr) {
        // Nothing to do if the target address is an IP address.
        if address.parse::<IpAddr>().is_ok() {
            return;
        }

        let mut cache_guard = self.dns_cache.lock().await;

        // If the connected IP is not in the first place, we should optimize it.
        if let Some(entry) = cache_guard.get_mut(address) {
            let optimize_record = match connected_ip {
                IpAddr::V4(..) => &mut entry.v4_records,
                IpAddr::V6(..) => &mut entry.v6_records,
            };

            if let Some(idx) = optimize_record.iter().position(|r| r.ip == connected_ip) {
                log::trace!(
                    "Moving connected IP {:?} to front in cache for address: {}",
                    connected_ip,
                    address
                );
                optimize_record.rotate_left(idx);
                log::trace!("Updated DNS cache entry for {}", address);
            }
        }
    }

    #[allow(dead_code)]
    async fn cache_insert(&self, host: &str, entry: CacheEntry) {
        if entry.v4_records.is_empty() && entry.v6_records.is_empty() {
            return;
        }
        self.dns_cache.lock().await.put(host.to_owned(), entry);
    }

    #[allow(dead_code)]
    async fn get_cached(&self, host: &str, options: (bool, bool)) -> Result<Vec<IpAddr>> {
        let mut cached_ips = Vec::new();

        // Query caches in priority order
        if let Some(entry) = self.dns_cache.lock().await.get(host) {
            match options {
                (true, true) => {
                    cached_ips.extend(entry.get_valid_v6_addrs());
                    cached_ips.extend(entry.get_valid_v4_addrs());
                }
                (true, false) => {
                    cached_ips.extend(entry.get_valid_v4_addrs());
                    cached_ips.extend(entry.get_valid_v6_addrs());
                }
                _ => {
                    cached_ips.extend(entry.get_valid_v4_addrs());
                }
            }
        }

        // Return results or error if no cached IPs found
        if !cached_ips.is_empty() {
            Ok(cached_ips)
        } else {
            Err(anyhow!("empty result"))
        }
    }

    #[allow(dead_code)]
    pub async fn direct_lookup(&self, host: &String) -> Result<Vec<IpAddr>> {
        let _ = host;
        Ok(vec![])
    }

    #[allow(dead_code)]
    async fn query_task(
        &self,
        is_direct: bool,
        request: Vec<u8>,
        host: &str,
        server: &SocketAddr,
    ) -> Result<CacheEntry> {
        let socket = if is_direct {
            log::debug!("direct lookup");
            let socket =
                tokio::net::UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                    .await?;
            socket.connect(server).await?;
            // let socket = self.new_udp_socket(server).await?;
            Box::new(StdOutboundDatagram::new(socket))
        } else {
            log::debug!("dispatched lookup");
            if let Some(dispatcher_weak) = self.dispatcher.as_ref() {
                // The source address will be used to determine which address the
                // underlying socket will bind.
                let source = match server {
                    SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
                };
                let sess = Session {
                    protocol: TransportProtocol::Udp,
                    source,
                    destination: SocksAddr::from(server),
                    inbound_tag: "internal".to_string(),
                    ..Default::default()
                };
                if let Some(dispatcher) = dispatcher_weak.upgrade() {
                    dispatcher.dispatch_datagram(sess).await?
                } else {
                    return Err(anyhow!("dispatcher is deallocated"));
                }
            } else {
                return Err(anyhow!("could not find a dispatcher"));
            }
        };
        let (mut r, mut s) = socket.split();
        let server = SocksAddr::from(server);
        let mut last_err = None;
        for _i in 0..3 {
            log::debug!("looking up host {} on {}", host, server);
            let start = Instant::now();
            // 1) send DNS request
            if let Err(err) = s.send_to(&request, &server).await {
                last_err = Some(anyhow!("send failed: {:?}", err));
                // socket send_to error, retry
                continue;
            }
            // 2) wait response
            let mut buf = vec![0u8; 512];
            let recv_result =
                match tokio::time::timeout(Duration::from_secs(3), r.recv_from(&mut buf)).await {
                    Ok(Ok((n, _))) => Ok((n, ())),
                    Ok(Err(err)) => Err(anyhow!("recv failed: {:?}", err)), // socket recv_from error
                    Err(e) => Err(anyhow!("recv timeout: {}", e)),          // timeout
                };
            // retry
            if let Err(err) = recv_result {
                last_err = Some(err);
                continue;
            }
            // happy path !!
            let n: usize = recv_result.unwrap().0;
            // 3) parse resp
            let resp = match Message::from_vec(&buf[..n]) {
                Ok(resp) => resp,
                Err(err) => {
                    last_err = Some(anyhow!("parse message failed: {:?}", err));
                    // broken response, no retry
                    break;
                }
            };
            // 4) check resp code
            if resp.response_code() != ResponseCode::NoError {
                last_err = Some(anyhow!("response error {}", resp.response_code()));
                // error response, no retry
                //
                // TODO Needs more careful investigations, I'm not quite sure about
                // this.
                break;
            }
            // 5) find address
            let mut ips = Vec::new();
            for ans in resp.answers() {
                // TODO checks?
                match ans.data() {
                    RData::A(ip) => {
                        ips.push(IpAddr::V4(**ip));
                    }
                    RData::AAAA(ip) => {
                        ips.push(IpAddr::V6(**ip));
                    }
                    _ => (),
                }
            }

            if ips.is_empty() {
                // response with 0 records
                //
                // TODO Not sure how to due with this.
                last_err = Some(anyhow!("no records"));
                break;
            }
            // 6) return cache entry
            let elapsed = Instant::now().duration_since(start);
            let ttl = resp.answers().iter().next().unwrap().ttl();
            log::debug!(
                "return {} ips (ttl {}) for {} from {} in {}ms",
                ips.len(),
                ttl,
                host,
                server,
                elapsed.as_millis(),
            );

            let Some(_) = Instant::now().checked_add(Duration::from_secs(ttl.into())) else {
                last_err = Some(anyhow!("invalid ttl"));
                break;
            };

            let mut entry = CacheEntry::new();
            for ip in ips {
                entry.add_record(ip, Duration::from_secs(ttl.into()));
            }
            log::debug!("ips for {}: {:#?}", host, &entry);
            return Ok(entry);
        }
        Err(last_err.unwrap_or_else(|| anyhow!("all lookup attempts failed")))
    }
}
