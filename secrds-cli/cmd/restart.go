package cmd

import (
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"
)

var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the agent service",
	Run: func(cmd *cobra.Command, args []string) {
		systemctlCmd := exec.Command("systemctl", "restart", "secrds")
		if err := systemctlCmd.Run(); err != nil {
			fmt.Printf("Failed to restart service: %v\n", err)
			return
		}
		fmt.Println("Service restarted successfully")
	},
}

func init() {
	rootCmd.AddCommand(restartCmd)
}

