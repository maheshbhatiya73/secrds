## eBPF Security Monitor (secrds)

An eBPF-powered host security monitor that detects SSH brute-force and TCP anomalies (port scans / floods), optionally blocks offending IPs via iptables, and sends alerts to Telegram.

### Components
- **Agent (`ebpf-detector-agent`)**: Loads eBPF programs, processes events, persists alerts, sends Telegram notifications, and (optionally) blocks IPs.
- **CLI (`ebpf-detector`)**: Check status, list recent alerts, view stats, and control the agent.
- **eBPF Programs**: Implemented in Rust (`ebpf-detector-ebpf`) and C (`ebpf-detector-ebpf-c`).

### Requirements
- Linux kernel 5.8+ with eBPF features enabled
- `rustup`, Rust toolchain (nightly required for eBPF build), `cargo`
- `bpf-linker` (installed automatically by `build.sh` if missing)
- `iptables` (for optional auto-blocking)
- `systemd` (to run the agent as a service)
- Internet access for Telegram API

### Quick Start
```bash
# 1) Build everything (eBPF + agent + CLI)
./build.sh

# 2) Install system-wide (requires sudo)
sudo ./install.sh

# 3) Configure Telegram credentials
sudo nano /etc/ebpf-detector/env.conf
# Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID

# 4) (Optional) Tune thresholds
sudo nano /etc/ebpf-detector/config.toml

# 5) Start and enable the service
sudo systemctl start ebpf-detector
sudo systemctl enable ebpf-detector

# 6) Check status and logs
systemctl status ebpf-detector
journalctl -u ebpf-detector -f
```

### Installation Details
- `install.sh` will:
  - Build binaries (via `build.sh`)
  - Install `ebpf-detector-agent` and `ebpf-detector` to `/usr/local/bin/`
  - Install `ebpf-detector.service` to `/etc/systemd/system/`
  - Create config at `/etc/ebpf-detector/config.toml` (if missing)
  - Create env file at `/etc/ebpf-detector/env.conf` (Telegram settings)
  - Create data dir `/var/lib/ebpf-detector` and log dir `/var/log/ebpf-detector`

### Configuration
- Main config file: `/etc/ebpf-detector/config.toml`
  - `ssh_threshold` (default 5)
  - `ssh_window_seconds` (default 300)
  - `tcp_threshold` (default 10)
  - `tcp_window_seconds` (default 60)
  - `enable_ip_blocking` (default true)
  - `storage_path` (default `/var/lib/ebpf-detector/events.json`)
  - `pid_file` (default `/var/run/ebpf-detector.pid`)
  - `log_level` (default `info`)
  - `log_file` (default `/var/log/ebpf-detector/agent.log`)

- Environment file: `/etc/ebpf-detector/env.conf`
  - `TELEGRAM_BOT_TOKEN` = your bot token (from Telegram `@BotFather`)
  - `TELEGRAM_CHAT_ID` = your chat ID (e.g., via `@userinfobot`)
  - Optional: `EBPF_DETECTOR_CONFIG` to point to a custom config path

### Service (systemd)
```bash
sudo systemctl start ebpf-detector
sudo systemctl enable ebpf-detector
systemctl status ebpf-detector
journalctl -u ebpf-detector -f
```

### CLI Usage
```bash
# Show agent/service status
ebpf-detector status

# Show recent alerts (default 10; customize with --limit)
ebpf-detector alerts --limit 20

# Show stats (e.g., blocked IPs, counts)
ebpf-detector stats

# Print current config (resolved)
ebpf-detector config

# Control the agent
ebpf-detector start
ebpf-detector stop
ebpf-detector restart
```

### Paths
- Config: `/etc/ebpf-detector/`
- Data: `/var/lib/ebpf-detector/events.json`
- PID: `/var/run/ebpf-detector.pid`
- Logs: `/var/log/ebpf-detector/agent.log`
- Binaries: `/usr/local/bin/ebpf-detector-agent`, `/usr/local/bin/ebpf-detector`

### Troubleshooting
- Kernel 5.8+ required: `uname -r`
- Build tools: ensure `rustup`, `cargo` and network access to install `bpf-linker`
- Telegram alerts: verify `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` are set and correct
- IP blocking: requires `iptables` and root; see warnings in logs if a rule fails

---

Made with Rust and eBPF. Licensed under MIT or Apache-2.0.


