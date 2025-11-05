use crate::config::Config;
use crate::ebpf_loader::{SshEvent, TcpEvent};
use crate::storage::Storage;
use crate::telegram_client::TelegramClient;
use anyhow::Context;
use chrono::{DateTime, Utc};
use log::{error, info, warn};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone)]
pub struct ThreatAlert {
    pub ip: IpAddr,
    pub threat_type: ThreatType,
    pub count: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub enum ThreatType {
    SshBruteForce,
    TcpPortScan,
    TcpFlood,
}

pub struct ThreatDetector {
    config: Config,
    storage: Arc<Storage>,
    telegram_client: Arc<TelegramClient>,
    inner: Arc<Mutex<ThreatDetectorInner>>,
}

struct ThreatDetectorInner {
    ssh_attempts: HashMap<IpAddr, Vec<SystemTime>>,
    tcp_connections: HashMap<IpAddr, Vec<SystemTime>>,
    blocked_ips: std::collections::HashSet<IpAddr>,
}

impl ThreatDetector {
    pub fn new(
        config: Config,
        storage: Arc<Storage>,
        telegram_client: Arc<TelegramClient>,
    ) -> Self {
        Self {
            config,
            storage,
            telegram_client,
            inner: Arc::new(Mutex::new(ThreatDetectorInner {
                ssh_attempts: HashMap::new(),
                tcp_connections: HashMap::new(),
                blocked_ips: std::collections::HashSet::new(),
            })),
        }
    }

    pub async fn process_ssh_event(&self, event: SshEvent) -> anyhow::Result<()> {
        let ip = self.u32_to_ip(event.ip)?;
        
        let (should_process, attempt_count) = {
            let mut inner = self.inner.lock().await;
            
            if inner.blocked_ips.contains(&ip) {
                return Ok(());
            }

            let now = SystemTime::now();
            
            let attempts = inner.ssh_attempts.entry(ip).or_insert_with(Vec::new);
            attempts.push(now);

            let window = Duration::from_secs(self.config.ssh_window_seconds);
            attempts.retain(|&time| now.duration_since(time).unwrap_or(Duration::ZERO) < window);

            let attempt_count = attempts.len() as u64;
            (attempt_count > self.config.ssh_threshold, attempt_count)
        };

        if should_process {
            warn!("SSH brute force detected from IP: {}", ip);
            
            let alert = ThreatAlert {
                ip,
                threat_type: ThreatType::SshBruteForce,
                count: attempt_count,
                timestamp: Utc::now(),
            };

            self.storage.store_alert(&alert).await?;
            
            self.telegram_client.send_alert(&alert).await?;
            
            if self.config.enable_ip_blocking {
                self.block_ip(ip).await?;
                self.storage.add_blocked_ip(&ip.to_string()).await?;
            }
        }

        Ok(())
    }

    pub async fn process_tcp_event(&self, event: TcpEvent) -> anyhow::Result<()> {
        let ip = self.u32_to_ip(event.src_ip)?;
        
        let (should_process, connection_count) = {
            let mut inner = self.inner.lock().await;
            
            if inner.blocked_ips.contains(&ip) {
                return Ok(());
            }

            let now = SystemTime::now();
            
            let connections = inner.tcp_connections.entry(ip).or_insert_with(Vec::new);
            connections.push(now);

            let window = Duration::from_secs(self.config.tcp_window_seconds);
            connections.retain(|&time| now.duration_since(time).unwrap_or(Duration::ZERO) < window);

            let connection_count = connections.len() as u64;
            (connection_count > self.config.tcp_threshold, connection_count)
        };

        if should_process {
            warn!("TCP flood/port scan detected from IP: {}", ip);
            
            let alert = ThreatAlert {
                ip,
                threat_type: ThreatType::TcpPortScan,
                count: connection_count,
                timestamp: Utc::now(),
            };

            self.storage.store_alert(&alert).await?;
            
            self.telegram_client.send_alert(&alert).await?;
            
            if self.config.enable_ip_blocking {
                self.block_ip(ip).await?;
                self.storage.add_blocked_ip(&ip.to_string()).await?;
            }
        }

        Ok(())
    }

    async fn block_ip(&self, ip: IpAddr) -> anyhow::Result<()> {
        self.inner.lock().await.blocked_ips.insert(ip);
        
        let ip_str = ip.to_string();
        let output = tokio::process::Command::new("iptables")
            .arg("-A")
            .arg("INPUT")
            .arg("-s")
            .arg(&ip_str)
            .arg("-j")
            .arg("DROP")
            .output()
            .await?;

        if !output.status.success() {
            warn!("Failed to block IP {} with iptables", ip_str);
        } else {
            info!("Blocked IP: {}", ip_str);
        }

        Ok(())
    }

    fn u32_to_ip(&self, ip: u32) -> anyhow::Result<IpAddr> {
        let bytes = ip.to_be_bytes();
        Ok(IpAddr::from(bytes))
    }
}

