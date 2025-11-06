#!/bin/bash
# Diagnostic script to check why detection isn't working

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}secrds Diagnostic Tool${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 1. Check service status
echo -e "${YELLOW}[1/8] Checking service status...${NC}"
if $SUDO systemctl is-active --quiet secrds 2>/dev/null; then
    echo -e "${GREEN}✓ Service is running${NC}"
    $SUDO systemctl status secrds --no-pager -l | head -10
else
    echo -e "${RED}✗ Service is NOT running${NC}"
    echo "Start it with: sudo systemctl start secrds"
fi
echo ""

# 2. Check kernel version
echo -e "${YELLOW}[2/8] Checking kernel version...${NC}"
KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
echo "Kernel version: $KERNEL_VERSION"
if [ "$(printf '%s\n' "5.8" "$KERNEL_VERSION" | sort -V | head -n1)" = "5.8" ]; then
    echo -e "${GREEN}✓ Kernel version is sufficient (5.8+)${NC}"
else
    echo -e "${RED}✗ Kernel version too old (needs 5.8+)${NC}"
fi
echo ""

# 3. Check eBPF support
echo -e "${YELLOW}[3/8] Checking eBPF support...${NC}"
if [ -d "/sys/fs/bpf" ]; then
    echo -e "${GREEN}✓ /sys/fs/bpf exists${NC}"
else
    echo -e "${RED}✗ /sys/fs/bpf not found${NC}"
fi

if [ -d "/sys/kernel/debug/tracing" ]; then
    echo -e "${GREEN}✓ Kernel tracing available${NC}"
else
    echo -e "${YELLOW}⚠ Kernel tracing not available${NC}"
fi
echo ""

# 4. Check eBPF program attachment
echo -e "${YELLOW}[4/8] Checking eBPF program attachment...${NC}"
if $SUDO journalctl -u secrds --no-pager 2>/dev/null | grep -q "Attached kprobe"; then
    echo -e "${GREEN}✓ eBPF programs attached:${NC}"
    $SUDO journalctl -u secrds --no-pager 2>/dev/null | grep "Attached kprobe" | tail -5
else
    echo -e "${RED}✗ No eBPF program attachment found${NC}"
    echo "Check recent logs:"
    $SUDO journalctl -u secrds --no-pager -n 20 2>/dev/null | tail -10
fi
echo ""

# 5. Check if events are being received
echo -e "${YELLOW}[5/8] Checking for SSH events in logs...${NC}"
RECENT_LOGS=$($SUDO journalctl -u secrds --no-pager -n 100 2>/dev/null)
if echo "$RECENT_LOGS" | grep -q "SSH event received\|Invalid SSH event\|Failed to process"; then
    echo -e "${GREEN}✓ Events found in logs:${NC}"
    echo "$RECENT_LOGS" | grep -E "SSH event|Invalid SSH|Failed to process" | tail -10
else
    echo -e "${RED}✗ No SSH events found in recent logs${NC}"
    echo "This means the eBPF program is not detecting connections"
fi
echo ""

# 6. Check for invalid IPs
echo -e "${YELLOW}[6/8] Checking for IP detection issues...${NC}"
if echo "$RECENT_LOGS" | grep -q "0.0.0.0\|invalid IP"; then
    echo -e "${YELLOW}⚠ Invalid IP addresses detected:${NC}"
    echo "$RECENT_LOGS" | grep -E "0.0.0.0|invalid IP" | tail -5
    echo ""
    echo "This indicates source IP detection is failing"
else
    echo -e "${GREEN}✓ No invalid IP issues found${NC}"
fi
echo ""

# 7. Check binary and kernel program files
echo -e "${YELLOW}[7/8] Checking installed files...${NC}"
if [ -f "/usr/local/bin/secrds-agent" ]; then
    echo -e "${GREEN}✓ secrds-agent binary exists${NC}"
else
    echo -e "${RED}✗ secrds-agent binary not found${NC}"
fi

if [ -f "/usr/local/lib/secrds/ssh_kprobe.bpf.o" ]; then
    echo -e "${GREEN}✓ SSH kernel program exists${NC}"
else
    echo -e "${RED}✗ SSH kernel program not found${NC}"
fi
echo ""

# 8. Test connection detection
echo -e "${YELLOW}[8/8] Testing connection detection...${NC}"
echo "Making a test SSH connection attempt..."
echo ""

# Clear recent logs for clean test
$SUDO journalctl --vacuum-time=1s -u secrds > /dev/null 2>&1 || true
sleep 1

# Make a test connection
timeout 2 ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=2 \
    -o BatchMode=yes \
    root@localhost "exit" 2>/dev/null || true

sleep 2

# Check if event was logged
if $SUDO journalctl -u secrds --no-pager -n 20 2>/dev/null | grep -q "SSH event\|Invalid SSH"; then
    echo -e "${GREEN}✓ Connection detected! Event logged${NC}"
    $SUDO journalctl -u secrds --no-pager -n 10 2>/dev/null | grep -E "SSH event|Invalid SSH" | tail -3
else
    echo -e "${RED}✗ Connection NOT detected${NC}"
    echo ""
    echo -e "${YELLOW}Recent logs:${NC}"
    $SUDO journalctl -u secrds --no-pager -n 15 2>/dev/null | tail -10
fi
echo ""

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "If events are not being detected, possible causes:"
echo "1. eBPF program not attaching (check kernel version and symbols)"
echo "2. Source IP detection failing (socket structure offsets wrong)"
echo "3. Kernel doesn't export required symbols (inet_csk_accept)"
echo "4. Service not running or crashed"
echo ""
echo "Next steps:"
echo "1. Check full logs: sudo journalctl -u secrds -f"
echo "2. Try manual run: sudo /usr/local/bin/secrds-agent"
echo "3. Check kernel symbols: sudo cat /proc/kallsyms | grep inet_csk_accept"
echo "4. Verify eBPF program loads: sudo bpftool prog list"

