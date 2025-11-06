package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/secrds/secrds-agent/internal/config"
	"github.com/secrds/secrds-agent/internal/detector"
	"github.com/secrds/secrds-agent/internal/kernel"
	"github.com/secrds/secrds-agent/internal/processor"
	"github.com/secrds/secrds-agent/internal/storage"
	"github.com/secrds/secrds-agent/internal/telegram"
)


func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid config: %v", err)
	}

	// Get Telegram credentials from config (may be loaded from YAML or env file)
	botToken := cfg.Telegram.BotToken
	if botToken == "" {
		log.Fatalf("TELEGRAM_BOT_TOKEN not set. Please set it in /etc/secrds/config.yaml (telegram.bot_token) or as TELEGRAM_BOT_TOKEN environment variable")
	}

	// Initialize storage
	st, err := storage.New(cfg.StoragePath)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	defer st.Flush()

	// Initialize Telegram client
	chatID := cfg.Telegram.ChatID
	tgClient, err := telegram.New(botToken, chatID)
	if err != nil {
		log.Fatalf("Failed to initialize Telegram client: %v", err)
	}

	// Initialize threat detector
	threatDetector := detector.New(cfg, st, tgClient)

	// Initialize kernel program loader
	kernelLoader, err := kernel.NewLoader()
	if err != nil {
		log.Fatalf("Failed to create kernel program loader: %v", err)
	}
	// We'll close the loader explicitly during shutdown to ensure proper order:
	// cancel context -> close readers -> wait for goroutines

	// Load kernel programs
	if err := kernelLoader.LoadCPrograms(); err != nil {
		log.Fatalf("Failed to load kernel programs: %v", err)
	}

	// Initialize event processor
	eventProcessor := processor.New(threatDetector, kernelLoader)

	// Start event processing
	if err := eventProcessor.Start(); err != nil {
		log.Fatalf("Failed to start event processor: %v", err)
	}

	fmt.Println("secrds Security Monitor started successfully")
	fmt.Printf("Monitoring SSH connections on port 22...\n")
	fmt.Printf("Note: For incoming connections, ensure inet_csk_accept kprobe is attached.\n")
	fmt.Printf("If not, check kernel version and available symbols.\n")

	// Write PID file
	if err := writePIDFile(cfg.PIDFile); err != nil {
		log.Printf("Warning: failed to write PID file: %v", err)
	}

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan
	fmt.Println("\nShutting down...")

	// Shutdown sequence:
	// 1. Cancel context to signal goroutines to exit
	// 2. Close loader (which closes readers, unblocking any Read() calls)
	// 3. Wait for goroutines to finish (they'll see the error and return)
	eventProcessor.Cancel()
	
	// Close loader to unblock any Read() calls in goroutines
	if err := kernelLoader.Close(); err != nil {
		log.Printf("Error closing kernel program loader: %v", err)
	}
	
	// Now wait for goroutines to finish
	eventProcessor.Stop()

	// Cleanup
	if err := st.Flush(); err != nil {
		log.Printf("Error flushing storage: %v", err)
	}

	if err := os.Remove(cfg.PIDFile); err != nil {
		log.Printf("Error removing PID file: %v", err)
	}
}

func writePIDFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create PID file directory: %w", err)
	}

	pid := os.Getpid()
	return os.WriteFile(path, []byte(fmt.Sprintf("%d\n", pid)), 0644)
}

