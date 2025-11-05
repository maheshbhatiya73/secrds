use crate::ebpf_loader::{EbpfLoader, SshEvent, TcpEvent};
use crate::threat_detector::ThreatDetector;
use anyhow::Context;
use aya::maps::perf::AsyncPerfEventArray;
use aya::maps::MapData;
use aya::util::online_cpus;
use bytes::BytesMut;
use log::{error, info, warn};
use std::sync::Arc;
use std::time::Duration;
use tokio::task;

pub struct EventProcessor {
    threat_detector: Arc<ThreatDetector>,
}

impl EventProcessor {
    pub fn new(
        mut ebpf_loader: EbpfLoader,
        threat_detector: Arc<ThreatDetector>,
    ) -> anyhow::Result<Self> {
        // Take ownership of the perf event arrays
        let ssh_events = ebpf_loader.take_ssh_events()
            .context("Failed to get SSH events array")?;
        let tcp_events = ebpf_loader.take_tcp_events()
            .context("Failed to get TCP events array")?;

        let threat_detector_ssh = threat_detector.clone();
        let threat_detector_tcp = threat_detector.clone();

        // Spawn task to handle SSH events
        task::spawn(async move {
            if let Err(e) = Self::handle_ssh_events(ssh_events, threat_detector_ssh).await {
                error!("SSH event handler error: {}", e);
            }
        });

        // Spawn task to handle TCP events
        task::spawn(async move {
            if let Err(e) = Self::handle_tcp_events(tcp_events, threat_detector_tcp).await {
                error!("TCP event handler error: {}", e);
            }
        });

        Ok(Self {
            threat_detector,
        })
    }

    async fn handle_ssh_events(
        mut perf_array: AsyncPerfEventArray<MapData>,
        threat_detector: Arc<ThreatDetector>,
    ) -> anyhow::Result<()> {
        info!("Starting SSH event processing");

        let mut handles = Vec::new();

        let cpus = online_cpus().map_err(|(_, e)| anyhow::anyhow!("Failed to get online CPUs: {}", e))?;
        for cpu_id in cpus {
            let mut buf = perf_array.open(cpu_id, None)
                .map_err(|e| anyhow::anyhow!("Failed to open perf buffer for CPU {}: {}", cpu_id, e))?;
            let threat_detector_clone = threat_detector.clone();

            let handle = task::spawn(async move {
                let mut buf = buf;
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();
                loop {
                    match buf.read_events(&mut buffers).await {
                        Ok(events) => {
                            for i in 0..events.read {
                                let b = &buffers[i];
                                if b.len() >= std::mem::size_of::<SshEvent>() {
                                    let event_data: &SshEvent = unsafe { &*(b.as_ptr() as *const SshEvent) };
                                    let detector_event = SshEvent {
                                        ip: event_data.ip,
                                        port: event_data.port,
                                        pid: event_data.pid,
                                        event_type: event_data.event_type,
                                        timestamp: event_data.timestamp,
                                    };
                                    if let Err(e) = threat_detector_clone.process_ssh_event(detector_event).await {
                                        warn!("Failed to process SSH event: {}", e);
                                    }
                                } else {
                                    warn!("Invalid SSH event size: {} bytes", b.len());
                                }
                            }
                        }
                        Err(e) => warn!("Error reading SSH events: {}", e),
                    }
                }
            });

            handles.push(handle);
        }

        // Handles run forever in background, we don't need to wait
        // They'll be cancelled when the task is dropped
        Ok(())
    }

    async fn handle_tcp_events(
        mut perf_array: AsyncPerfEventArray<MapData>,
        threat_detector: Arc<ThreatDetector>,
    ) -> anyhow::Result<()> {
        info!("Starting TCP event processing");

        let mut handles = Vec::new();

        let cpus = online_cpus().map_err(|(_, e)| anyhow::anyhow!("Failed to get online CPUs: {}", e))?;
        for cpu_id in cpus {
            let mut buf = perf_array.open(cpu_id, None)
                .map_err(|e| anyhow::anyhow!("Failed to open perf buffer for CPU {}: {}", cpu_id, e))?;
            let threat_detector_clone = threat_detector.clone();

            let handle = task::spawn(async move {
                let mut buf = buf;
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();
                loop {
                    match buf.read_events(&mut buffers).await {
                        Ok(events) => {
                            for i in 0..events.read {
                                let b = &buffers[i];
                                if b.len() >= std::mem::size_of::<TcpEvent>() {
                                    let event_data: &TcpEvent = unsafe { &*(b.as_ptr() as *const TcpEvent) };
                                    let detector_event = TcpEvent {
                                        src_ip: event_data.src_ip,
                                        dst_ip: event_data.dst_ip,
                                        src_port: event_data.src_port,
                                        dst_port: event_data.dst_port,
                                        event_type: event_data.event_type,
                                        timestamp: event_data.timestamp,
                                    };
                                    if let Err(e) = threat_detector_clone.process_tcp_event(detector_event).await {
                                        warn!("Failed to process TCP event: {}", e);
                                    }
                                } else {
                                    warn!("Invalid TCP event size: {} bytes", b.len());
                                }
                            }
                        }
                        Err(e) => warn!("Error reading TCP events: {}", e),
                    }
                }
            });

            handles.push(handle);
        }

        // Handles run forever in background, we don't need to wait
        // They'll be cancelled when the task is dropped
        Ok(())
    }

    pub async fn process_events(&mut self) -> anyhow::Result<()> {
        info!("Starting event processing loop");
        // The actual event processing happens in spawned tasks
        // This function just keeps the main loop alive
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            info!("Event processor heartbeat");
        }
    }
}

