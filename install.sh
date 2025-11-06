#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"
SYSTEMD_DIR="/etc/systemd/system"
CONFIG_DIR="/etc/secrds"
DATA_DIR="/var/lib/secrds"
RUN_DIR="/var/run"

echo -e "${GREEN}Installing secrds Security Monitor${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"

# Check kernel version
KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
REQUIRED_VERSION="5.8"
if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$KERNEL_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo -e "${RED}Kernel version $KERNEL_VERSION is too old. Requires 5.8+${NC}"
    exit 1
fi

echo -e "${YELLOW}Checking for Go and system tools...${NC}"

# Check for required tools
for tool in go iptables clang; do
    if ! command -v $tool &> /dev/null; then
        echo -e "${RED}$tool is not installed${NC}"
        exit 1
    fi
done

# Check Go version (requires 1.21+)
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
REQUIRED_GO_VERSION="1.21"
if [ "$(printf '%s\n' "$REQUIRED_GO_VERSION" "$GO_VERSION" | sort -V | head -n1)" != "$REQUIRED_GO_VERSION" ]; then
    echo -e "${YELLOW}Warning: Go version $GO_VERSION may be too old. Recommended: 1.21+${NC}"
fi

# Build the project
echo -e "${YELLOW}Building project...${NC}"
if [ -f "build.sh" ]; then
    chmod +x build.sh
    ./build.sh
else
    echo -e "${RED}build.sh not found${NC}"
    exit 1
fi

# Create directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p "$CONFIG_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$RUN_DIR"
mkdir -p "$(dirname $INSTALL_PREFIX/bin)"

# Install binaries
echo -e "${YELLOW}Installing binaries...${NC}"

# Install secrds-agent
if [ -f "target/release/secrds-agent" ]; then
    cp target/release/secrds-agent "$INSTALL_PREFIX/bin/secrds-agent"
    chmod +x "$INSTALL_PREFIX/bin/secrds-agent"
    echo -e "${GREEN}Installed secrds-agent${NC}"
else
    echo -e "${RED}Error: secrds-agent binary not found${NC}"
    exit 1
fi

# Install secrds-cli as 'secrds'
if [ -f "target/release/secrds-cli" ]; then
    cp target/release/secrds-cli "$INSTALL_PREFIX/bin/secrds"
    chmod +x "$INSTALL_PREFIX/bin/secrds"
    echo -e "${GREEN}Installed secrds CLI${NC}"
else
    echo -e "${RED}Error: secrds-cli binary not found${NC}"
    exit 1
fi

# Install kernel program object files
echo -e "${YELLOW}Installing kernel program object files...${NC}"
mkdir -p /usr/local/lib/secrds
if [ -f "secrds-programs/ssh_kprobe.bpf.o" ]; then
    cp secrds-programs/ssh_kprobe.bpf.o /usr/local/lib/secrds/
    echo -e "${GREEN}Installed SSH kernel program${NC}"
fi
if [ -f "secrds-programs/tcp_trace.bpf.o" ]; then
    cp secrds-programs/tcp_trace.bpf.o /usr/local/lib/secrds/
    echo -e "${GREEN}Installed TCP kernel program${NC}"
fi

# Install systemd service
echo -e "${YELLOW}Installing systemd service...${NC}"
if [ -f "secrds.service" ]; then
    cp secrds.service "$SYSTEMD_DIR/secrds.service"
    systemctl daemon-reload
else
    echo -e "${YELLOW}Warning: secrds.service not found, skipping${NC}"
fi

# Create default config if it doesn't exist
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    echo -e "${YELLOW}Creating default configuration...${NC}"
    cat > "$CONFIG_DIR/config.yaml" <<EOF
ssh_threshold: 5
ssh_window_seconds: 300
tcp_threshold: 10
tcp_window_seconds: 60
enable_ip_blocking: true
storage_path: "$DATA_DIR/events.json"
pid_file: "$RUN_DIR/secrds.pid"
log_level: "info"
log_file: "/var/log/secrds/agent.log"

# Telegram Bot Configuration
# Get your bot token from @BotFather on Telegram
# Get your chat ID from @userinfobot on Telegram
telegram:
  bot_token: "your_bot_token_here"
  chat_id: "your_chat_id_here"
EOF
    chmod 644 "$CONFIG_DIR/config.yaml"
    echo -e "${YELLOW}Please edit $CONFIG_DIR/config.yaml and set your Telegram credentials${NC}"
fi

# Create log directory
mkdir -p /var/log/secrds
chmod 755 /var/log/secrds

# Set proper permissions
chown -R root:root "$CONFIG_DIR"
chown -R root:root "$DATA_DIR"
chmod 755 "$DATA_DIR"

echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Edit $CONFIG_DIR/config.yaml and set telegram.bot_token and telegram.chat_id"
echo "2. Optionally edit $CONFIG_DIR/config.yaml to customize thresholds"
echo "3. Start the service: systemctl start secrds"
echo "4. Enable auto-start: systemctl enable secrds"
echo "5. Check status: systemctl status secrds"
echo ""
echo -e "${GREEN}Installation successful!${NC}"

