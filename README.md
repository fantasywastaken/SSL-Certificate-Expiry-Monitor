# SSL-Certificate-Expiry-Monitor

Bulk SSL certificate expiry checker that prints a colored table for every domain and can push alerts to a Discord webhook when a certificate is about to expire.

### How It Works

1. Domains are collected from `--file` (one per line, `#` comments ignored) and any trailing CLI arguments.
2. A worker pool opens TLS connections in parallel using `crypto/tls` and reads the leaf certificate from `ConnectionState().PeerCertificates`.
3. The tool extracts `NotAfter`, computes days remaining, and pulls the issuer common name (falling back to the organization).
4. Results are sorted by urgency and rendered as a colored table (red for < threshold, yellow for < 2x threshold, green otherwise) or as JSON when `--json` is set.
5. If `--webhook` is configured, every domain below the threshold is packed into a single Discord message and POSTed to the webhook URL.

## Setup

### Requirements

- Go 1.21 or newer
- `github.com/fatih/color`

### Installation

```bash
git clone https://github.com/fantasywastaken/SSL-Certificate-Expiry-Monitor.git
cd SSL-Certificate-Expiry-Monitor
go mod tidy
go build -o sslmon .
```

### Usage

```bash
sslmon example.com google.com github.com
sslmon --file domains.txt
sslmon --file domains.txt --threshold 45 --workers 20
sslmon --file domains.txt --webhook https://discord.com/api/webhooks/xxx/yyy --threshold 30
sslmon --file domains.txt --json > report.json
```

Flags:

| Flag           | Default | Purpose                                              |
| -------------- | ------- | ---------------------------------------------------- |
| `--file`       | (empty) | File with one domain per line (# lines ignored)      |
| `--timeout`    | `10s`   | TLS dial timeout                                     |
| `--webhook`    | (empty) | Discord webhook URL for alerts                       |
| `--threshold`  | `30`    | Days threshold that triggers red rows and webhooks   |
| `--workers`    | `10`    | Concurrent dial workers                              |
| `--json`       | `false` | Print JSON instead of a table                        |

### Features

- Bulk checks with configurable concurrent worker pool.
- Table output color-coded by urgency using `fatih/color`.
- Optional JSON output for downstream tooling.
- Discord webhook integration that fires only when at least one domain is below threshold.
- Sensible timeouts and clear error messages for unreachable hosts.
- Sorted output: soonest expirations first, errors last.
