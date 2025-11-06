package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show agent/service status",
	Run: func(cmd *cobra.Command, args []string) {
		pidFile := "/var/run/secrds.pid"
		pidData, err := os.ReadFile(pidFile)
		if err != nil {
			fmt.Println("Status: Not running (PID file not found)")
			return
		}

		pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
		if err != nil {
			fmt.Printf("Status: Unknown (invalid PID file: %v)\n", err)
			return
		}

		// Check if process is running
		process, err := os.FindProcess(pid)
		if err != nil {
			fmt.Printf("Status: Not running (PID %d not found)\n", pid)
			return
		}

		// Try to send signal 0 to check if process exists
		err = process.Signal(os.Signal(nil))
		if err != nil {
			fmt.Printf("Status: Not running (process %d not responding)\n", pid)
			return
		}

		// Check systemd service status
		systemctlCmd := exec.Command("systemctl", "is-active", "secrds")
		output, _ := systemctlCmd.Output()
		serviceStatus := strings.TrimSpace(string(output))

		fmt.Printf("Status: Running\n")
		fmt.Printf("PID: %d\n", pid)
		if serviceStatus == "active" {
			fmt.Println("Service: Active")
		} else {
			fmt.Printf("Service: %s\n", serviceStatus)
		}
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

