use anyhow::{Result, anyhow};
use lru::LruCache;

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use std::{collections::HashMap, num::NonZeroUsize};
use tokio::sync::{Mutex, RwLock};

use super::dispatcher::Dispatcher;
use crate::app::session::{Session, SocksAddr, TransportProtocol};

pub type SyncDnsClient = Arc<RwLock<DnsClient>>;
type DNSCache = Arc<Mutex<LruCache<String, CacheEntry>>>;

#[allow(dead_code)]
pub struct DnsClient {
    dispatcher: Option<Weak<Dispatcher>>,
    listen_addrs: Vec<SocketAddr>,
    hosts: HashMap<String, Vec<IpAddr>>,
    dns_cache: DNSCache,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct CacheEntry {
    pub v4_records: Vec<DnsRecord>,
    pub v6_records: Vec<DnsRecord>,
}

impl CacheEntry {
    pub fn new() -> Self {
        Self {
            v4_records: Vec::new(),
            v6_records: Vec::new(),
        }
    }

    pub fn add_record(&mut self, ip: IpAddr, ttl: Duration) {
        let record = DnsRecord::new(ip, ttl);
        match ip {
            IpAddr::V4(_) => self.v4_records.push(record),
            IpAddr::V6(_) => self.v6_records.push(record),
        }
    }

    pub fn get_valid_v4_addrs(&self) -> Vec<IpAddr> {
        self.v4_records
            .iter()
            .filter(|r| !r.is_expired())
            .map(|r| r.ip)
            .collect()
    }

    pub fn get_valid_v6_addrs(&self) -> Vec<IpAddr> {
        self.v6_records
            .iter()
            .filter(|r| !r.is_expired())
            .map(|r| r.ip)
            .collect()
    }
}

#[derive(Clone, Debug)]
struct DnsRecord {
    pub ip: IpAddr,
    pub ttl: Duration,
    pub deadline: Instant,
}

impl DnsRecord {
    pub fn new(ip: IpAddr, ttl: Duration) -> Self {
        Self {
            ip,
            ttl,
            deadline: Instant::now() + ttl,
        }
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() > self.deadline
    }
}

impl DnsClient {
    pub fn new(dns_config: &crate::config::Dns) -> Result<Self> {
        if dns_config.listen_addrs.is_empty() {
            return Err(anyhow!("empty listening address"));
        }
        let mut listen_addrs = Vec::new();
        for addr in &dns_config.listen_addrs {
            listen_addrs.push(SocketAddr::new(addr.parse::<IpAddr>()?, 53));
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
            listen_addrs,
            hosts,
            dns_cache: Arc::new(Mutex::new(LruCache::<String, CacheEntry>::new(
                NonZeroUsize::new(512).unwrap(),
            ))),
        });
    }

    pub fn replace_dispatcher(&mut self, dispatcher: Weak<Dispatcher>) {
        self.dispatcher.replace(dispatcher);
    }

    pub async fn optimize_dns_cache(&self, address: &str, connected_ip: &IpAddr) {
        // Nothing to do if the target address is an IP address.
        if address.parse::<IpAddr>().is_ok() {
            return;
        }

        let mut cache_guard = self.dns_cache.lock().await;

        // If the connected IP is not in the first place, we should optimize it.
        if let Some(entry) = cache_guard.get_mut(address) {
            let optimize_record = match connected_ip {
                IpAddr::V4(..) => &mut entry.v4_records,
                IpAddr::V6(..) => &mut entry.v4_records,
            };

            if let Some(idx) = optimize_record.iter().position(|r| r.ip == *connected_ip) {
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

    async fn cache_insert(&self, host: &str, entry: CacheEntry) {
        if entry.v4_records.is_empty() && entry.v6_records.is_empty() {
            return;
        }
        self.dns_cache.lock().await.put(host.to_owned(), entry);
    }

    async fn get_cached(&self, host: &String, option: (bool, bool)) -> Result<Vec<IpAddr>> {
        let mut cached_ips = Vec::new();

        // Query caches in priority order
        if let Some(entry) = self.dns_cache.lock().await.get(host) {
            match option {
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
}
