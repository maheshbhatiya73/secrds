package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Show current configuration",
	Run: func(cmd *cobra.Command, args []string) {
		configPath := os.Getenv("SECRDS_CONFIG")
		if configPath == "" {
			configPath = "/etc/secrds/config.yaml"
		}

		// Try to read config file
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			fmt.Println("Using default configuration (config file not found)")
			fmt.Println("\nDefault values:")
			fmt.Println("  SSH Threshold: 5")
			fmt.Println("  SSH Window: 300 seconds")
			fmt.Println("  TCP Threshold: 10")
			fmt.Println("  TCP Window: 60 seconds")
			fmt.Println("  IP Blocking: enabled")
			return
		}

		data, err := os.ReadFile(configPath)
		if err != nil {
			fmt.Printf("Failed to read config file: %v\n", err)
			return
		}

		// Try JSON first
		var cfg map[string]interface{}
		if err := json.Unmarshal(data, &cfg); err == nil {
			fmt.Println("Current configuration:")
			for k, v := range cfg {
				fmt.Printf("  %s: %v\n", k, v)
			}
			return
		}

		// Otherwise, just print the file content
		fmt.Println("Configuration file content:")
		fmt.Println(string(data))
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}

