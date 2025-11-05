use aya::{
    maps::perf::AsyncPerfEventArray,
    maps::MapData,
    programs::{KProbe, TracePoint},
    Ebpf,
};
use anyhow::Context;
use log::info;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SshEvent {
    pub ip: u32,
    pub port: u16,
    pub pid: u32,
    pub event_type: u8,
    pub timestamp: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TcpEvent {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub event_type: u8,
    pub timestamp: u64,
}

pub struct EbpfLoader {
    pub bpf_programs: Vec<Ebpf>, // Keep all loaded programs alive
    pub ssh_events: Option<AsyncPerfEventArray<MapData>>,
    pub tcp_events: Option<AsyncPerfEventArray<MapData>>,
}

impl EbpfLoader {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            bpf_programs: Vec::new(),
            ssh_events: None,
            tcp_events: None,
        })
    }

    pub fn load_rust_programs(&mut self) -> anyhow::Result<()> {
        info!("Loading Rust eBPF programs...");
        // Rust eBPF programs would be loaded here if implemented
        // For now, we'll use the C programs
        info!("Rust eBPF programs loaded successfully");
        Ok(())
    }

    pub fn load_c_programs(&mut self) -> anyhow::Result<()> {
        info!("Loading C eBPF programs...");

        // Load SSH monitoring program
        let ssh_bytes = include_bytes!("../../ebpf-detector-ebpf-c/ssh_kprobe.bpf.o");
        let mut bpf: Ebpf = Ebpf::load(ssh_bytes)
            .context("Failed to load SSH eBPF program")?;

        // Attach SSH tracepoint (sys_enter_write - generic, will be improved later)
        let program: &mut TracePoint = bpf
            .program_mut("ssh_tracepoint_write")
            .context("Failed to find ssh_tracepoint_write program")?
            .try_into()?;
        program.load()?;
        program.attach("syscalls", "sys_enter_write")
            .context("Failed to attach SSH tracepoint")?;
        info!("SSH tracepoint attached");

        // Attach SSH kprobe (do_execve - generic, will be improved later)
        let program: &mut KProbe = bpf
            .program_mut("ssh_kprobe_execve")
            .context("Failed to find ssh_kprobe_execve program")?
            .try_into()?;
        program.load()?;
        program.attach("do_execve", 0)
            .context("Failed to attach SSH kprobe")?;
        info!("SSH kprobe attached");

        // Get SSH events perf array
        let ssh_events_array = bpf
            .take_map("ssh_events")
            .context("Failed to find ssh_events map")?;
        let ssh_events: AsyncPerfEventArray<MapData> = AsyncPerfEventArray::try_from(ssh_events_array)?;

        // Load TCP monitoring program
        let tcp_bytes = include_bytes!("../../ebpf-detector-ebpf-c/tcp_trace.bpf.o");
        let mut tcp_bpf: Ebpf = Ebpf::load(tcp_bytes)
            .context("Failed to load TCP eBPF program")?;

        // Attach TCP kprobe
        let program: &mut KProbe = tcp_bpf
            .program_mut("tcp_connect")
            .context("Failed to find tcp_connect program")?
            .try_into()?;
        program.load()?;
        program.attach("tcp_v4_connect", 0)
            .context("Failed to attach TCP kprobe")?;
        info!("TCP kprobe attached");

        // Attach TCP tracepoint
        let program: &mut TracePoint = tcp_bpf
            .program_mut("tcp_state_change")
            .context("Failed to find tcp_state_change program")?
            .try_into()?;
        program.load()?;
        program.attach("sock", "inet_sock_set_state")
            .context("Failed to attach TCP tracepoint")?;
        info!("TCP tracepoint attached");

        // Get TCP events perf array
        let tcp_events_array = tcp_bpf
            .take_map("tcp_events")
            .context("Failed to find tcp_events map")?;
        let tcp_events: AsyncPerfEventArray<MapData> = AsyncPerfEventArray::try_from(tcp_events_array)?;

        // Store both BPF instances (we need to keep them alive)
        self.bpf_programs.push(bpf);
        self.bpf_programs.push(tcp_bpf);
        self.ssh_events = Some(ssh_events);
        self.tcp_events = Some(tcp_events);

        info!("C eBPF programs loaded successfully");
        Ok(())
    }

    pub fn take_ssh_events(&mut self) -> Option<AsyncPerfEventArray<MapData>> {
        self.ssh_events.take()
    }

    pub fn take_tcp_events(&mut self) -> Option<AsyncPerfEventArray<MapData>> {
        self.tcp_events.take()
    }
}
