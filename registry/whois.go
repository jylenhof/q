package registry

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// whoisHopLimit caps the number of refer-chain hops to avoid infinite loops
const whoisHopLimit = 5

type whoisHop struct {
	Server string `json:"server"`
	Body   string `json:"body"`
}

// queryWHOIS performs a port-43 WHOIS lookup, following refer/whois/ReferralServer
// pointers up to whoisHopLimit times
func queryWHOIS(ctx context.Context, opts Options) (string, error) {
	start := opts.WhoisServer
	if start == "" {
		start = rirWhoisHost(opts.RIR)
	}

	hops, err := whoisChain(ctx, opts.Target, start, opts.Timeout)
	if err != nil && len(hops) == 0 {
		return "", err
	}

	if strings.ToLower(opts.Format) == "json" {
		b, mErr := json.MarshalIndent(struct {
			Hops []whoisHop `json:"hops"`
		}{Hops: hops}, "", "  ")
		if mErr != nil {
			return "", fmt.Errorf("registry: marshal whois: %w", mErr)
		}
		return string(b), nil
	}

	var sb strings.Builder
	for i, h := range hops {
		if i > 0 {
			sb.WriteString("\n")
		}
		fmt.Fprintf(&sb, ";; Server: %s\n", h.Server)
		sb.WriteString(h.Body)
		if !strings.HasSuffix(h.Body, "\n") {
			sb.WriteString("\n")
		}
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

func whoisChain(ctx context.Context, target, start string, timeout time.Duration) ([]whoisHop, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	var hops []whoisHop
	server := start
	seen := map[string]bool{}

	for i := 0; i < whoisHopLimit; i++ {
		host := withDefaultPort(server, "43")
		if seen[host] {
			break
		}
		seen[host] = true

		body, err := whoisExchange(ctx, host, target, timeout)
		if err != nil {
			if len(hops) == 0 {
				return nil, fmt.Errorf("registry: whois %s: %w", host, err)
			}
			hops = append(hops, whoisHop{Server: host, Body: fmt.Sprintf(";; error: %v", err)})
			return hops, nil
		}
		hops = append(hops, whoisHop{Server: host, Body: body})

		next := parseWhoisReferral(body)
		if next == "" || next == server {
			return hops, nil
		}
		server = next
	}
	return hops, nil
}

func whoisExchange(ctx context.Context, hostport, query string, timeout time.Duration) (string, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write([]byte(query + "\r\n")); err != nil {
		return "", err
	}
	b, err := io.ReadAll(conn)
	if err != nil {
		return string(b), err
	}
	return string(b), nil
}

// parseWhoisReferral scans the body for a refer/whois/ReferralServer line
// and returns the host (with optional port) it points at, or "" if none
func parseWhoisReferral(body string) string {
	scanner := bufio.NewScanner(strings.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		value := strings.TrimSpace(line[idx+1:])
		if value == "" {
			continue
		}
		switch key {
		case "refer", "whois":
			return value
		case "referralserver":
			return stripWhoisScheme(value)
		}
	}
	return ""
}

func stripWhoisScheme(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "whois://")
	v = strings.TrimPrefix(v, "rwhois://")
	return strings.TrimRight(v, "/")
}

func withDefaultPort(hostport, port string) string {
	if hostport == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	return net.JoinHostPort(hostport, port)
}
