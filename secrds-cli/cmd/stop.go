package cmd

import (
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the agent service",
	Run: func(cmd *cobra.Command, args []string) {
		systemctlCmd := exec.Command("systemctl", "stop", "secrds")
		if err := systemctlCmd.Run(); err != nil {
			fmt.Printf("Failed to stop service: %v\n", err)
			return
		}
		fmt.Println("Service stopped successfully")
	},
}

func init() {
	rootCmd.AddCommand(stopCmd)
}

