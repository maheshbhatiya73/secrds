package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var alertsLimit int

var alertsCmd = &cobra.Command{
	Use:   "alerts",
	Short: "Show recent alerts",
	Run: func(cmd *cobra.Command, args []string) {
		storagePath := "/var/lib/secrds/events.json"
		if customPath := os.Getenv("SECRDS_STORAGE"); customPath != "" {
			storagePath = customPath
		}

		data, err := os.ReadFile(storagePath)
		if err != nil {
			fmt.Printf("No alerts found (storage file not found: %v)\n", err)
			return
		}

		var storageData struct {
			Alerts []struct {
				IP         string    `json:"ip"`
				ThreatType string    `json:"threat_type"`
				Count      uint64    `json:"count"`
				Timestamp  time.Time `json:"timestamp"`
			} `json:"alerts"`
		}

		if err := json.Unmarshal(data, &storageData); err != nil {
			fmt.Printf("Failed to parse storage file: %v\n", err)
			return
		}

		alerts := storageData.Alerts
		if len(alerts) == 0 {
			fmt.Println("No recent alerts")
			return
		}

		// Show newest first
		start := len(alerts) - alertsLimit
		if start < 0 {
			start = 0
		}

		fmt.Printf("Recent alerts (showing %d of %d):\n\n", alertsLimit, len(alerts))
		for i := len(alerts) - 1; i >= start; i-- {
			alert := alerts[i]
			fmt.Printf("Time: %s\n", alert.Timestamp.Format("2006-01-02 15:04:05 UTC"))
			fmt.Printf("IP: %s\n", alert.IP)
			fmt.Printf("Threat: %s\n", alert.ThreatType)
			fmt.Printf("Count: %d\n", alert.Count)
			fmt.Println("---")
		}
	},
}

func init() {
	alertsCmd.Flags().IntVarP(&alertsLimit, "limit", "l", 10, "Number of alerts to show")
	rootCmd.AddCommand(alertsCmd)
}

