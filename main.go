package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/load"
)

type Config struct {
	Hostname              string
	SlackWebhookURL       string
	CloudflareAPIKey      string
	CloudflareZoneID      string
	CPULimit              float64
	Client                *cloudflare.API
	InitialSecurityLevel  string
	CurrentSecurityLevel  string
	UnderAttackActive     bool
	ConsecutiveAlertCount int
	AlertDelayCount       int
}

type SlackMessage struct {
	Text string `json:"text"`
}

func sendMessage(cfg *Config, message string) {
	printToConsole(cfg, message)
	if strings.TrimSpace(cfg.SlackWebhookURL) != "" {
		err := sendSlackNotification(cfg, message)
		if err != nil {
			printToConsole(cfg, fmt.Sprintf("Failed to send Slack notification: %v", err))
		}
	}
}

func printToConsole(cfg *Config, message string) {
	fmt.Printf("[%s] %s\n", cfg.Hostname, message)
}

func sendSlackNotification(cfg *Config, message string) error {
	slackMsg := SlackMessage{
		Text: fmt.Sprintf("`[%s]` %s", cfg.Hostname, message),
	}

	messageBytes, err := json.Marshal(slackMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack message: %w", err)
	}

	resp, err := http.Post(cfg.SlackWebhookURL, "application/json", bytes.NewBuffer(messageBytes))
	if err != nil {
		return fmt.Errorf("failed to send Slack notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Slack webhook response: %s", resp.Status)
	}

	return nil
}

func loadCheck() (load.AvgStat, int, error) {
	loadAvg, err := load.Avg()
	if err != nil {
		return load.AvgStat{}, 0, err
	}

	cpuCount, err := cpu.Counts(true)
	if err != nil {
		return load.AvgStat{}, 0, err
	}

	return *loadAvg, cpuCount, nil
}

func initializeCloudflare(cfApiKey string) (*cloudflare.API, error) {
	client, err := cloudflare.NewWithAPIToken(cfApiKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloudflare client: %w", err)
	}
	return client, nil
}

func checkCloudflareSecurityLevel(client *cloudflare.API, cfZoneId string) (string, error) {
	settings, err := client.ZoneSettings(context.Background(), cfZoneId)
	if err != nil {
		return "", fmt.Errorf("error fetching zone settings: %w", err)
	}

	var currentSecurityLevel string
	for _, setting := range settings.Result {
		if setting.ID == "security_level" {
			if val, ok := setting.Value.(string); ok {
				currentSecurityLevel = val
			}
			break
		}
	}

	if currentSecurityLevel == "" {
		return "", fmt.Errorf("Security Level not found")
	}

	return currentSecurityLevel, nil
}

func updateCloudflareSecurityLevel(client *cloudflare.API, cfZoneId, securityLevel string) error {
	updateSettings := []cloudflare.ZoneSetting{
		{
			ID:    "security_level",
			Value: securityLevel,
		},
	}
	_, err := client.UpdateZoneSettings(context.Background(), cfZoneId, updateSettings)
	if err != nil {
		return err
	}

	return nil
}

func handleSigint(cfg *Config) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan

	printToConsole(cfg, fmt.Sprintf("Received termination signal, restoring Cloudflare Security Level to '%v'", cfg.InitialSecurityLevel))

	if cfg.InitialSecurityLevel == cfg.CurrentSecurityLevel {
		printToConsole(cfg, "Cloudflare Security Level is unchanged. Exiting.")
		os.Exit(0)
	}

	err := updateCloudflareSecurityLevel(cfg.Client, cfg.CloudflareZoneID, cfg.InitialSecurityLevel)
	if err != nil {
		printToConsole(cfg, fmt.Sprintf("Failed to restore initial Security Level: '%v'", err))
		os.Exit(1)
	} else {
		printToConsole(cfg, fmt.Sprintf("Cloudflare Security Level restored to '%s'", cfg.InitialSecurityLevel))
		os.Exit(0)
	}
}

func periodicSecurityCheck(cfg *Config) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			currentLevel, err := checkCloudflareSecurityLevel(cfg.Client, cfg.CloudflareZoneID)
			if err != nil {
				printToConsole(cfg, fmt.Sprintf("Error checking Cloudflare Security Level: %v", err))
				continue
			}
			cfg.CurrentSecurityLevel = currentLevel
		}
	}
}

func main() {
	slackWebhookURL := flag.String("w", "", "Slack Webhook URL for notifications")
	cfApiKey := flag.String("k", "", "Cloudflare API token")
	cfZoneId := flag.String("z", "", "Cloudflare Zone ID")
	cpuLimit := flag.Float64("l", 80, "Set the CPU load percentage limit")

	flag.Parse()

	fmt.Print("\x1bc")

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("Failed to get hostname: %v", err)
	}

	cfg := &Config{
		Hostname:              hostname,
		SlackWebhookURL:       *slackWebhookURL,
		CloudflareAPIKey:      *cfApiKey,
		CloudflareZoneID:      *cfZoneId,
		CPULimit:              *cpuLimit,
		UnderAttackActive:     false,
		ConsecutiveAlertCount: 0,
		AlertDelayCount:       3,
	}

	if strings.TrimSpace(cfg.CloudflareAPIKey) == "" || strings.TrimSpace(cfg.CloudflareZoneID) == "" {
		fmt.Printf("Cloudflare API variables are not specified\n")
		return
	}

	cfg.Client, err = initializeCloudflare(cfg.CloudflareAPIKey)
	if err != nil {
		log.Fatal(err)
	}

	cfg.InitialSecurityLevel, err = checkCloudflareSecurityLevel(cfg.Client, cfg.CloudflareZoneID)
	if err != nil {
		log.Fatal(err)
	}
	cfg.CurrentSecurityLevel = cfg.InitialSecurityLevel

	if cfg.InitialSecurityLevel == "under_attack" {
		fmt.Printf("Cloudflare Under Attack mode is already active. Exiting...\n")
		return
	}

	go handleSigint(cfg)
	go periodicSecurityCheck(cfg)

	for {
		loadAvg, cpuCount, err := loadCheck()
		if err != nil {
			log.Fatal(err)
		}

		loadPercentage := (loadAvg.Load1 / float64(cpuCount)) * 100

		if loadPercentage < cfg.CPULimit {
			printToConsole(cfg, fmt.Sprintf("OK: CPU Load Percentage: %.2f%%. Limit - %.2f%%", loadPercentage, cfg.CPULimit))
			printToConsole(cfg, fmt.Sprintf("Initial Cloudflare Security Level: %s", cfg.InitialSecurityLevel))
			printToConsole(cfg, fmt.Sprintf("Current Cloudflare Security Level: %s", cfg.CurrentSecurityLevel))

			if cfg.UnderAttackActive {
				printToConsole(cfg, "Disabling Under Attack mode")

				err := updateCloudflareSecurityLevel(cfg.Client, cfg.CloudflareZoneID, cfg.InitialSecurityLevel)
				if err != nil {
					sendMessage(cfg, fmt.Sprintf("Failed to disable Under Attack mode: %v", err))
				} else {
					cfg.UnderAttackActive = false
					cfg.CurrentSecurityLevel = cfg.InitialSecurityLevel
					sendMessage(cfg, fmt.Sprintf("CPU Load Percentage below limit: `%.2f%%`. Usage: `%.2f%%`. Cloudflare Security Level changed to `%s`", cfg.CPULimit, loadPercentage, cfg.CurrentSecurityLevel))

				}
			}

			cfg.ConsecutiveAlertCount = 0
		} else {
			printToConsole(cfg, fmt.Sprintf("ALERT: CPU Load Percentage: %.2f%%. Limit - %.2f%%", loadPercentage, cfg.CPULimit))
			printToConsole(cfg, fmt.Sprintf("Initial Cloudflare Security Level: %s", cfg.InitialSecurityLevel))
			printToConsole(cfg, fmt.Sprintf("Current Cloudflare Security Level: %s", cfg.CurrentSecurityLevel))

			cfg.ConsecutiveAlertCount++

			if cfg.ConsecutiveAlertCount >= cfg.AlertDelayCount && !cfg.UnderAttackActive {
				printToConsole(cfg, fmt.Sprintf("Activating Under Attack Cloudflare mode after %d consecutive alerts", cfg.ConsecutiveAlertCount))

				err := updateCloudflareSecurityLevel(cfg.Client, cfg.CloudflareZoneID, "under_attack")
				if err != nil {
					sendMessage(cfg, fmt.Sprintf("Failed to activate Under Attack mode: %v", err))
				} else {
					cfg.UnderAttackActive = true
					cfg.CurrentSecurityLevel = "under_attack"
					sendMessage(cfg, fmt.Sprintf("CPU Load Percentage over limit: `%.2f%%`. Usage: `%.2f%%`. Cloudflare Security Level changed to `%s`", cfg.CPULimit, loadPercentage, cfg.CurrentSecurityLevel))
					printToConsole(cfg, "Sleeping for 3 minutes...")
					time.Sleep(3 * time.Minute)
				}
			}
		}

		time.Sleep(3 * time.Second)
		fmt.Print("\x1bc")
	}
}
