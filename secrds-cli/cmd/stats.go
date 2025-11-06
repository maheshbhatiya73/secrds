package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show statistics",
	Run: func(cmd *cobra.Command, args []string) {
		storagePath := "/var/lib/secrds/events.json"
		if customPath := os.Getenv("SECRDS_STORAGE"); customPath != "" {
			storagePath = customPath
		}

		data, err := os.ReadFile(storagePath)
		if err != nil {
			fmt.Printf("No statistics available (storage file not found: %v)\n", err)
			return
		}

		var storageData struct {
			Statistics struct {
				TotalAlerts        uint64 `json:"total_alerts"`
				SSHBruteForceCount uint64 `json:"ssh_brute_force_count"`
				TCPPortScanCount  uint64 `json:"tcp_port_scan_count"`
				TCPFloodCount     uint64 `json:"tcp_flood_count"`
				BlockedIPsCount   uint64 `json:"blocked_ips_count"`
			} `json:"statistics"`
			BlockedIPs []string `json:"blocked_ips"`
		}

		if err := json.Unmarshal(data, &storageData); err != nil {
			fmt.Printf("Failed to parse storage file: %v\n", err)
			return
		}

		stats := storageData.Statistics
		fmt.Println("Statistics:")
		fmt.Printf("  Total Alerts: %d\n", stats.TotalAlerts)
		fmt.Printf("  SSH Brute Force: %d\n", stats.SSHBruteForceCount)
		fmt.Printf("  TCP Port Scans: %d\n", stats.TCPPortScanCount)
		fmt.Printf("  TCP Floods: %d\n", stats.TCPFloodCount)
		fmt.Printf("  Blocked IPs: %d\n", stats.BlockedIPsCount)

		if len(storageData.BlockedIPs) > 0 {
			fmt.Println("\nBlocked IPs:")
			for _, ip := range storageData.BlockedIPs {
				fmt.Printf("  - %s\n", ip)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(statsCmd)
}

