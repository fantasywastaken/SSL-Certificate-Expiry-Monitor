package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

type certInfo struct {
	Domain     string
	ExpiryDate time.Time
	DaysLeft   int
	Issuer     string
	Error      string
}

var (
	inputFile string
	timeout   time.Duration
	webhook   string
	threshold int
	workers   int
	jsonOut   bool
)

func init() {
	flag.StringVar(&inputFile, "file", "", "path to a file containing one domain per line")
	flag.DurationVar(&timeout, "timeout", 10*time.Second, "TLS dial timeout")
	flag.StringVar(&webhook, "webhook", "", "Discord webhook URL for alerts")
	flag.IntVar(&threshold, "threshold", 30, "days-left threshold for alert coloring and webhook")
	flag.IntVar(&workers, "workers", 10, "number of concurrent dial workers")
	flag.BoolVar(&jsonOut, "json", false, "print machine-readable JSON instead of a table")
}

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: sslmon [--file domains.txt] [domain ...]")
		flag.PrintDefaults()
	}
	flag.Parse()

	var domains []string
	if inputFile != "" {
		d, err := readLines(inputFile)
		if err != nil {
			fatalf("cannot read %s: %v", inputFile, err)
		}
		domains = append(domains, d...)
	}
	domains = append(domains, flag.Args()...)
	if len(domains) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	results := checkAll(domains, workers)

	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Error != "" && results[j].Error == "" {
			return false
		}
		if results[i].Error == "" && results[j].Error != "" {
			return true
		}
		return results[i].DaysLeft < results[j].DaysLeft
	})

	if jsonOut {
		emitJSON(results)
	} else {
		printTable(results, threshold)
	}

	if webhook != "" {
		var alerts []certInfo
		for _, r := range results {
			if r.Error == "" && r.DaysLeft < threshold {
				alerts = append(alerts, r)
			}
		}
		if len(alerts) > 0 {
			if err := sendDiscord(webhook, alerts); err != nil {
				fmt.Fprintf(os.Stderr, "webhook error: %v\n", err)
			}
		}
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

func checkAll(domains []string, workers int) []certInfo {
	if workers < 1 {
		workers = 1
	}
	results := make([]certInfo, len(domains))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for i, d := range domains {
		wg.Add(1)
		go func(idx int, domain string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = checkDomain(domain)
		}(i, d)
	}
	wg.Wait()
	return results
}

func checkDomain(domain string) certInfo {
	info := certInfo{Domain: domain}
	host := domain
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	dialer := &net.Dialer{Timeout: timeout}
	serverName, _, err := net.SplitHostPort(host)
	if err != nil {
		info.Error = err.Error()
		return info
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})
	if err != nil {
		info.Error = err.Error()
		return info
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		info.Error = "no certificate presented"
		return info
	}
	leaf := certs[0]
	info.ExpiryDate = leaf.NotAfter
	info.DaysLeft = int(time.Until(leaf.NotAfter).Hours() / 24)
	info.Issuer = leaf.Issuer.CommonName
	if info.Issuer == "" {
		info.Issuer = strings.Join(leaf.Issuer.Organization, " ")
	}
	return info
}

func printTable(results []certInfo, alertThreshold int) {
	red := color.New(color.FgRed, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	dim := color.New(color.Faint).SprintFunc()

	header := fmt.Sprintf("%-40s  %-12s  %-6s  %-30s  %s", "DOMAIN", "EXPIRY", "DAYS", "ISSUER", "STATUS")
	fmt.Println(header)
	fmt.Println(strings.Repeat("-", len(header)))

	for _, r := range results {
		if r.Error != "" {
			row := fmt.Sprintf("%-40s  %-12s  %-6s  %-30s  %s", truncate(r.Domain, 40), "-", "-", "-", "ERROR: "+r.Error)
			fmt.Println(red(row))
			continue
		}
		expiry := r.ExpiryDate.Format("2006-01-02")
		days := fmt.Sprintf("%d", r.DaysLeft)
		issuer := truncate(r.Issuer, 30)
		status := "OK"
		row := fmt.Sprintf("%-40s  %-12s  %-6s  %-30s  %s", truncate(r.Domain, 40), expiry, days, issuer, status)
		switch {
		case r.DaysLeft < 0:
			fmt.Println(red(row + " (EXPIRED)"))
		case r.DaysLeft < alertThreshold:
			fmt.Println(red(row))
		case r.DaysLeft < alertThreshold*2:
			fmt.Println(yellow(row))
		default:
			fmt.Println(green(dim(row)))
		}
	}
}

func emitJSON(results []certInfo) {
	type outEntry struct {
		Domain     string `json:"domain"`
		ExpiryDate string `json:"expiry_date,omitempty"`
		DaysLeft   int    `json:"days_left"`
		Issuer     string `json:"issuer,omitempty"`
		Error      string `json:"error,omitempty"`
	}
	out := make([]outEntry, 0, len(results))
	for _, r := range results {
		e := outEntry{Domain: r.Domain, DaysLeft: r.DaysLeft, Issuer: r.Issuer, Error: r.Error}
		if !r.ExpiryDate.IsZero() {
			e.ExpiryDate = r.ExpiryDate.Format(time.RFC3339)
		}
		out = append(out, e)
	}
	data, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(data))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 4 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

func sendDiscord(url string, alerts []certInfo) error {
	var b strings.Builder
	b.WriteString("**SSL Certificate Expiry Alerts**\n")
	for _, a := range alerts {
		b.WriteString(fmt.Sprintf("- `%s` -> %d days left (expires %s, issuer %s)\n",
			a.Domain, a.DaysLeft, a.ExpiryDate.Format("2006-01-02"), a.Issuer))
	}
	payload := map[string]string{"content": b.String()}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	fmt.Fprintf(os.Stderr, "webhook: delivered %d alerts (status %d)\n", len(alerts), resp.StatusCode)
	return nil
}
