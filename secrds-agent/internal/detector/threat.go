package detector

import (
	"fmt"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/secrds/secrds-agent/internal/config"
	"github.com/secrds/secrds-agent/internal/storage"
	"github.com/secrds/secrds-agent/internal/telegram"
)

type ThreatDetector struct {
	config         *config.Config
	storage        *storage.Storage
	telegramClient *telegram.Client
	mu             sync.Mutex
	sshAttempts    map[string][]time.Time
	tcpConnections map[string][]time.Time
	blockedIPs     map[string]bool
}

func New(cfg *config.Config, st *storage.Storage, tg *telegram.Client) *ThreatDetector {
	return &ThreatDetector{
		config:         cfg,
		storage:        st,
		telegramClient: tg,
		sshAttempts:    make(map[string][]time.Time),
		tcpConnections: make(map[string][]time.Time),
		blockedIPs:     make(map[string]bool),
	}
}

func (td *ThreatDetector) ProcessSSHEvent(ip uint32, port uint16, pid uint32, eventType uint8) error {
	ipAddr := u32ToIP(ip)
	ipStr := ipAddr.String()

	// Check if already blocked
	if td.storage.IsBlocked(ipStr) {
		return nil
	}

	td.mu.Lock()
	defer td.mu.Unlock()

	now := time.Now()
	window := td.config.SSHWindow()

	// Clean old attempts
	attempts := td.sshAttempts[ipStr]
	validAttempts := []time.Time{}
	for _, t := range attempts {
		if now.Sub(t) < window {
			validAttempts = append(validAttempts, t)
		}
	}
	validAttempts = append(validAttempts, now)
	td.sshAttempts[ipStr] = validAttempts

	attemptCount := uint64(len(validAttempts))

	if attemptCount > td.config.SSHThreshold {
		alert := &storage.Alert{
			IP:         ipStr,
			ThreatType: storage.ThreatTypeSSHBruteForce,
			Count:      attemptCount,
			Timestamp:  now,
		}

		if err := td.storage.StoreAlert(alert); err != nil {
			return fmt.Errorf("failed to store alert: %w", err)
		}

		// Send Telegram alert
		tgAlert := &telegram.Alert{
			IP:         ipStr,
			ThreatType: string(storage.ThreatTypeSSHBruteForce),
			Count:      attemptCount,
			Timestamp:  now,
		}
		if err := td.telegramClient.SendAlert(tgAlert); err != nil {
			fmt.Printf("Failed to send Telegram alert: %v\n", err)
		}

		// Block IP if enabled
		if td.config.EnableIPBlocking {
			if err := td.blockIP(ipStr); err != nil {
				fmt.Printf("Failed to block IP %s: %v\n", ipStr, err)
			} else {
				td.storage.AddBlockedIP(ipStr)
			}
		}
	}

	return nil
}

func (td *ThreatDetector) ProcessTCPEvent(srcIP, dstIP uint32, srcPort, dstPort uint16, eventType uint8) error {
	ipAddr := u32ToIP(srcIP)
	ipStr := ipAddr.String()

	// Check if already blocked
	if td.storage.IsBlocked(ipStr) {
		return nil
	}

	td.mu.Lock()
	defer td.mu.Unlock()

	now := time.Now()
	window := td.config.TCPWindow()

	// Clean old connections
	connections := td.tcpConnections[ipStr]
	validConnections := []time.Time{}
	for _, t := range connections {
		if now.Sub(t) < window {
			validConnections = append(validConnections, t)
		}
	}
	validConnections = append(validConnections, now)
	td.tcpConnections[ipStr] = validConnections

	connectionCount := uint64(len(validConnections))

	if connectionCount > td.config.TCPThreshold {
		threatType := storage.ThreatTypeTCPPortScan
		if connectionCount > td.config.TCPThreshold*2 {
			threatType = storage.ThreatTypeTCPFlood
		}

		alert := &storage.Alert{
			IP:         ipStr,
			ThreatType: threatType,
			Count:      connectionCount,
			Timestamp:  now,
		}

		if err := td.storage.StoreAlert(alert); err != nil {
			return fmt.Errorf("failed to store alert: %w", err)
		}

		// Send Telegram alert
		tgAlert := &telegram.Alert{
			IP:         ipStr,
			ThreatType: string(threatType),
			Count:      connectionCount,
			Timestamp:  now,
		}
		if err := td.telegramClient.SendAlert(tgAlert); err != nil {
			fmt.Printf("Failed to send Telegram alert: %v\n", err)
		}

		// Block IP if enabled
		if td.config.EnableIPBlocking {
			if err := td.blockIP(ipStr); err != nil {
				fmt.Printf("Failed to block IP %s: %v\n", ipStr, err)
			} else {
				td.storage.AddBlockedIP(ipStr)
			}
		}
	}

	return nil
}

func (td *ThreatDetector) blockIP(ip string) error {
	cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to block IP with iptables: %w", err)
	}
	return nil
}

func u32ToIP(ip uint32) net.IP {
	return net.IP{
		byte(ip >> 24),
		byte(ip >> 16),
		byte(ip >> 8),
		byte(ip),
	}
}

