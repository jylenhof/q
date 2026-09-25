package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/openrdap/rdap"
)

// queryRDAP performs an RDAP lookup using github.com/openrdap/rdap.
// When opts.RDAPServer or a non-IANA RIR is set, the server URL is supplied
// directly on the request, bypassing bootstrap.
func queryRDAP(ctx context.Context, opts Options) (string, error) {
	kind := Classify(opts.Target)

	req, err := buildRDAPRequest(kind, opts.Target)
	if err != nil {
		return "", err
	}

	base := opts.RDAPServer
	if base == "" {
		base = rirRDAPBase(opts.RIR)
	}
	if base != "" {
		serverURL, err := url.Parse(base)
		if err != nil {
			return "", fmt.Errorf("registry: parse rdap server %q: %w", base, err)
		}
		req = req.WithServer(serverURL)
	}
	req = req.WithContext(ctx)
	req.Timeout = opts.Timeout

	client := &rdap.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("registry: rdap: %w", err)
	}
	if resp == nil || resp.Object == nil {
		return "", fmt.Errorf("registry: rdap: empty response")
	}

	return formatRDAP(resp, opts.Format)
}

func buildRDAPRequest(kind Kind, target string) (*rdap.Request, error) {
	switch kind {
	case KindDomain:
		return &rdap.Request{Type: rdap.DomainRequest, Query: target}, nil
	case KindIPv4, KindIPv6:
		return &rdap.Request{Type: rdap.IPRequest, Query: target}, nil
	case KindASN:
		num := strings.TrimPrefix(strings.ToUpper(target), "AS")
		return &rdap.Request{Type: rdap.AutnumRequest, Query: num}, nil
	case KindNICHandle:
		return &rdap.Request{Type: rdap.EntityRequest, Query: target}, nil
	}
	return nil, fmt.Errorf("registry: cannot classify rdap target %q", target)
}

func formatRDAP(resp *rdap.Response, format string) (string, error) {
	switch strings.ToLower(format) {
	case "json", "raw":
		b, err := json.MarshalIndent(resp.Object, "", "  ")
		if err != nil {
			return "", fmt.Errorf("registry: marshal rdap: %w", err)
		}
		return string(b), nil
	}

	if pretty := formatRDAPPretty(resp); pretty != "" {
		return pretty, nil
	}

	b, err := json.MarshalIndent(resp.Object, "", "  ")
	if err != nil {
		return "", fmt.Errorf("registry: marshal rdap: %w", err)
	}
	return string(b), nil
}
