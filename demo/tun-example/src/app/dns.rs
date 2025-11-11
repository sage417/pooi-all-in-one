use anyhow::{Result, anyhow};
use lru::LruCache;
#[allow(unused_imports)]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Weak};
#[allow(unused_imports)]
use std::time::{Duration, Instant};
use std::{collections::HashMap, num::NonZeroUsize};
use tokio::sync::{Mutex, RwLock};

use super::dispatcher::Dispatcher;

pub type SyncDnsClient = Arc<RwLock<DnsClient>>;
type DNSCache = Arc<Mutex<LruCache<String, CacheEntry>>>;

#[allow(dead_code)]
pub struct DnsClient {
    dispatcher: Option<Weak<Dispatcher>>,
    listen_addrs: Vec<SocketAddr>,
    hosts: HashMap<String, Vec<IpAddr>>,
    ipv4_cache: DNSCache,
    ipv6_cache: DNSCache,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct CacheEntry {
    pub addrs: Vec<IpAddr>,
    // The deadline this entry should be considered expired.
    pub deadline: Instant,
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
            ipv4_cache: Arc::new(Mutex::new(LruCache::<String, CacheEntry>::new(
                NonZeroUsize::new(512).unwrap(),
            ))),
            ipv6_cache: Arc::new(Mutex::new(LruCache::<String, CacheEntry>::new(
                NonZeroUsize::new(512).unwrap(),
            ))),
        });
    }

    pub async fn optimize_dns_cache(&self, address: &str, connected_ip: &IpAddr) {
        self.inner_optimize_cache(&self.ipv4_cache, address, connected_ip).await;
        self.inner_optimize_cache(&self.ipv6_cache, address, connected_ip).await;
    }

    async fn inner_optimize_cache(
        &self,
        dns_cache: &DNSCache,
        address: &str,
        connected_ip: &IpAddr,
    ) {
        // Nothing to do if the target address is an IP address.
        if address.parse::<IpAddr>().is_ok() {
            return;
        }

        let mut cache_guard = dns_cache.lock().await;

        // If the connected IP is not in the first place, we should optimize it.
        if let Some(entry) = cache_guard.get_mut(address) {
            if let Some(idx) = entry.addrs.iter().position(|&ip| ip == *connected_ip) {
                log::trace!(
                    "Moving connected IP {:?} to front in cache for address: {}",
                    connected_ip,
                    address
                );
                entry.addrs.rotate_left(idx);
                log::trace!("Updated DNS cache entry for {}", address);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lru::LruCache;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    // 假设你的 CacheEntry 定义是这样的（根据你代码上下文推测）：
    #[derive(Clone, Debug, PartialEq)]
    struct CacheEntry {
        pub addrs: Vec<IpAddr>,
    }

    // 假设你的 DnsClient 或测试目标结构体大致如下（简化版，仅含 ipv4_cache）
    struct TestDnsClient {
        ipv4_cache: Arc<tokio::sync::Mutex<lru::LruCache<String, CacheEntry>>>,
    }

    impl TestDnsClient {
        fn new() -> Self {
            // 创建一个容量为 10 的 LRU 缓存
            let cache = lru::LruCache::new(std::num::NonZeroUsize::new(10).unwrap());
            Self {
                ipv4_cache: Arc::new(tokio::sync::Mutex::new(cache)),
            }
        }

        // 模拟你的 optimize_cache_ipv4 方法
        async fn optimize_cache_ipv4(&self, address: &str, connected_ip: &IpAddr) {
            if address.parse::<IpAddr>().is_ok() {
                return;
            }

            let mut cache_guard = self.ipv4_cache.lock().await;

            if let Some(entry) = cache_guard.get_mut(address) {
                if let Some(idx) = entry.addrs.iter().position(|&ip| ip == *connected_ip) {
                    entry.addrs.rotate_left(idx);
                    log::trace!("update Dns cache entry {} {}", address, connected_ip);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_optimize_cache_ipv4_moves_connected_ip_to_front() {
        // 1. 准备测试对象
        let client = TestDnsClient::new();

        // 2. 准备测试数据
        let domain = "example.com";
        let ip1 = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)); // 第二个 IP
        let ip2 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)); // 我们希望它移动到第一个

        let entry = CacheEntry {
            addrs: vec![ip1, ip2], // 注意顺序：2.2.2.2, 1.1.1.1
        };

        // 3. 插入缓存
        {
            let mut cache = client.ipv4_cache.lock().await;
            cache.put(domain.to_string(), entry);
        }

        // 4. 调用优化函数：connected_ip 是 1.1.1.1，当前在索引 1
        let connected_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        client.optimize_cache_ipv4(domain, &connected_ip).await;

        // 5. 检查缓存中的 entry 是否被正确修改
        {
            let mut cache = client.ipv4_cache.lock().await;
            if let Some(entry) = cache.get(domain) {
                // 期望 addrs 现在是 [1.1.1.1, 2.2.2.2]
                let expected = vec![
                    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                    IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
                ];
                assert_eq!(entry.addrs, expected, "IPs were not reordered");
            } else {
                panic!(
                    "Cache entry for domain '{}' not found after optimization",
                    domain
                );
            }
        }
    }
}
