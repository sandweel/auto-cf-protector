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
	"github.com/fatih/color"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/load"
)

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
		return nil, fmt.Errorf("failed to create CloudFlare client: %w", err)
	}
	return client, nil
}

func checkCloudflareSecurityLevel(client *cloudflare.API, cfZoneId string) (string, error) {
	settings, err := client.ZoneSettings(context.Background(), cfZoneId)
	if err != nil {
		return "", fmt.Errorf("failed to fetch zone settings: %w", err)
	}

	var currentSecurityLevel string
	for _, setting := range settings.Result {
		if setting.ID == "security_level" {
			currentSecurityLevel = setting.Value.(string)
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

func handleSigint(client *cloudflare.API, cfZoneId, initialSecurityLevel string, currentSecurityLevel *string) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)

	<-sigChan

	fmt.Printf("\nReceived SIGINT (process kill), restoring CloudFlare Security Level to '%v'\n", initialSecurityLevel)

	if initialSecurityLevel == *currentSecurityLevel {
		fmt.Printf("CloudFlare Security Level the same. Exiting...\n")
		os.Exit(0)
	}

	err := updateCloudflareSecurityLevel(client, cfZoneId, initialSecurityLevel)
	if err != nil {
		fmt.Printf("Failed to restore initial Security Level: '%v'\n", err)
		os.Exit(1)
	} else {
		fmt.Printf("CloudFlare Security Level restored to '%s'\n", initialSecurityLevel)
		os.Exit(0)
	}
}

func sendSlackNotification(webhookURL, message string) error {
	type SlackMessage struct {
		Text string `json:"text"`
	}

	slackMsg := SlackMessage{
		Text: message,
	}

	messageBytes, err := json.Marshal(slackMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack message: %w", err)
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(messageBytes))
	if err != nil {
		return fmt.Errorf("failed to send Slack notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Slack webhook response: %s", resp.Status)
	}

	return nil
}

func main() {
	red := color.New(color.FgRed).PrintfFunc()
	green := color.New(color.FgGreen).PrintfFunc()
	white := color.New(color.FgHiWhite).PrintfFunc()

	slackWebhookURL := flag.String("w", "", "Slack Webhook URL for notifications")
	cfApiKey := flag.String("k", "", "CloudFlare API token")
	cfZoneId := flag.String("z", "", "CloudFlare Zone ID")
	cpuLimit := flag.Float64("l", 80, "Set the CPU load percentage limit")

	flag.Parse()

	fmt.Print("\x1bc")

	//	if strings.TrimSpace(*slackWebhookURL) == "" {
	//		red("Slack Webhook URL is not specified\n")
	//		return
	//	}

	if strings.TrimSpace(*cfApiKey) == "" || strings.TrimSpace(*cfZoneId) == "" {
		red("CloudFlare API variables are not specified\n")
		return
	}

	client, err := initializeCloudflare(*cfApiKey)
	if err != nil {
		log.Fatal(err)
	}
	initialSecurityLevel, err := checkCloudflareSecurityLevel(client, *cfZoneId)
	if err != nil {
		log.Fatal(err)
	}

	if initialSecurityLevel == "under_attack" {
		white("CloudFlare Under Attack mode is already active. Exiting...\n")
		return
	}

	currentSecurityLevel := initialSecurityLevel
	underAttackActive := false
	consecutiveAlertCount := 0
	alertDelayCount := 3

	go handleSigint(client, *cfZoneId, initialSecurityLevel, &currentSecurityLevel)

	for {
		loadAvg, cpuCount, err := loadCheck()
		if err != nil {
			log.Fatal(err)
		}

		loadPercentage := (loadAvg.Load1 / float64(cpuCount)) * 100

		white("CPU Utilization\n")
		if loadPercentage < *cpuLimit {
			green("OK: CPU Load Percentage: %.2f%%. Limit - %.2f%%\n\n", loadPercentage, *cpuLimit)
			white("Initial CloudFlare Security Level: %s\n", initialSecurityLevel)
			white("Current CloudFlare Security Level: %s\n", currentSecurityLevel)

			if underAttackActive {
				white("Disabling Under Attack mode - ")
				err := updateCloudflareSecurityLevel(client, *cfZoneId, initialSecurityLevel)
				if err != nil {
					red("Failed to disable Under Attack mode: %v\n", err)
					message := fmt.Sprintf("Failed to disable Under Attack mode")
					err = sendSlackNotification(*slackWebhookURL, message)
				} else {
					green("OK\n")
					underAttackActive = false
					currentSecurityLevel = initialSecurityLevel
					message := fmt.Sprintf("CloudFlare Security Level changed to `%s`", currentSecurityLevel)
					err = sendSlackNotification(*slackWebhookURL, message)
				}
			}

			consecutiveAlertCount = 0
		} else {
			red("ALERT: CPU Load Percentage: %.2f%%. Limit - %.2f%%\n\n", loadPercentage, *cpuLimit)
			white("Initial CloudFlare Security Level: %s\n", initialSecurityLevel)
			white("Current CloudFlare Security Level: %s\n", currentSecurityLevel)

			consecutiveAlertCount++

			if consecutiveAlertCount >= alertDelayCount && !underAttackActive {
				white("Activating Under Attack CloudFlare mode after %d consecutive alerts - ", consecutiveAlertCount)
				err := updateCloudflareSecurityLevel(client, *cfZoneId, "under_attack")
				if err != nil {
					red("Failed to activate Under Attack mode: %v\n", err)
					message := fmt.Sprintf("Failed to activate Under Attack mode")
					err = sendSlackNotification(*slackWebhookURL, message)
				} else {
					green("OK\n")
					underAttackActive = true
					currentSecurityLevel = "under_attack"
					message := fmt.Sprintf("CloudFlare Security Level changed to `%s`", currentSecurityLevel)
					err = sendSlackNotification(*slackWebhookURL, message)
					white("Sleeping for 3 minutes...")
					time.Sleep(180 * time.Second)
				}
			}
		}

		time.Sleep(5 * time.Second)
		fmt.Print("\x1bc")
	}
}
