package cmd

import (
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the agent service",
	Run: func(cmd *cobra.Command, args []string) {
		systemctlCmd := exec.Command("systemctl", "start", "secrds")
		if err := systemctlCmd.Run(); err != nil {
			fmt.Printf("Failed to start service: %v\n", err)
			return
		}
		fmt.Println("Service started successfully")
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
}

