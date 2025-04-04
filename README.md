# Auto Cloudflare Protector

This Go program monitors CPU load and automatically adjusts Cloudflare security settings based on predefined thresholds. It also sends notifications to Slack.

## Features

-   Monitors CPU load percentage.
-   Automatically switches Cloudflare security level to "under_attack" when CPU load exceeds a specified limit for a set number of consecutive checks.
-   Restores the initial Cloudflare security level when CPU load returns to normal.
-   Sends notifications to Slack (optional).
-   Handles graceful shutdown and restores initial Cloudflare settings.

## Prerequisites

-   Go 1.16 or later.
-   Cloudflare API token and Zone ID.
-   (Optional) Slack Webhook URL.

## Installation

1.  Download the latest release from the [releases page](https://github.com/sandweel/auto-cf-protector/releases).
2.  Extract the archive.
3.  Make the executable file executable:

    ```bash
    chmod +x auto-cf-protector-*
    ```

## Usage

```bash
./cloudflare-cpu-monitor -k <cloudflare_api_token> -z <cloudflare_zone_id> -w <slack_webhook_url> -l <cpu_limit>
```

## Options
-   -k <cloudflare_api_token>: Cloudflare API token (required)
-   -z <cloudflare_zone_id>: Cloudflare Zone ID (required)
-   -w <slack_webhook_url>: Slack Webhook URL for notifications (optional)
-   -l <cpu_limit>: CPU load percentage limit (default: 80)
