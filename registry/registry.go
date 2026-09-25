package registry

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/charmbracelet/log"
)

// Kind classifies a registry-lookup target.
type Kind int

const (
	KindUnknown Kind = iota
	KindIPv4
	KindIPv6
	KindASN
	KindDomain
	KindNICHandle
)

func (k Kind) String() string {
	switch k {
	case KindIPv4:
		return "ipv4"
	case KindIPv6:
		return "ipv6"
	case KindASN:
		return "asn"
	case KindDomain:
		return "domain"
	case KindNICHandle:
		return "nic-handle"
	}
	return "unknown"
}

var (
	asnRe    = regexp.MustCompile(`^(?i)AS\d+$`)
	handleRe = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
)

// Classify inspects target and returns its Kind
func Classify(target string) Kind {
	t := strings.TrimSpace(target)
	if t == "" {
		return KindUnknown
	}
	if ip := net.ParseIP(t); ip != nil {
		if ip.To4() != nil {
			return KindIPv4
		}
		return KindIPv6
	}
	if asnRe.MatchString(t) {
		return KindASN
	}
	if strings.Contains(t, ".") {
		return KindDomain
	}
	if handleRe.MatchString(t) {
		return KindNICHandle
	}
	return KindUnknown
}

// Options controls a registry lookup.
type Options struct {
	Target      string
	UseRDAP     bool
	UseWHOIS    bool
	RDAPServer  string
	WhoisServer string
	RIR         string
	Format      string
	Timeout     time.Duration
}

// when passed --registry, attempts rdap first, then whois if fials
func Query(ctx context.Context, opts Options) (string, error) {
	if strings.TrimSpace(opts.Target) == "" {
		return "", fmt.Errorf("registry: empty target")
	}
	if !opts.UseRDAP && !opts.UseWHOIS {
		return "", fmt.Errorf("registry: neither RDAP nor WHOIS requested")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	opts.RIR = strings.ToLower(strings.TrimSpace(opts.RIR))
	if opts.RIR == "" {
		opts.RIR = "iana"
	}

	if Classify(opts.Target) == KindNICHandle &&
		opts.RIR == "iana" &&
		opts.RDAPServer == "" &&
		opts.WhoisServer == "" {
		if detected := DetectRIRFromHandle(opts.Target); detected != "" {
			log.Debugf("registry: detected RIR %s from handle %q", detected, opts.Target)
			opts.RIR = detected
		}
	}

	if opts.UseRDAP {
		out, err := queryRDAP(ctx, opts)
		if err == nil {
			return out, nil
		}
		if opts.UseWHOIS {
			log.Debugf("registry: RDAP failed (%s), falling back to WHOIS", err)
			return queryWHOIS(ctx, opts)
		}
		return "", err
	}
	return queryWHOIS(ctx, opts)
}

// matching whois(1) behavior to autoguess RIR based off of prefix
func DetectRIRFromHandle(handle string) string {
	h := strings.ToUpper(strings.TrimSpace(handle))
	switch {
	case strings.HasSuffix(h, "-RIPE"):
		return "ripe"
	case strings.HasSuffix(h, "-ARIN"), strings.HasPrefix(h, "ARIN-"):
		return "arin"
	case strings.HasSuffix(h, "-AP"):
		return "apnic"
	case strings.HasSuffix(h, "-LACNIC"):
		return "lacnic"
	case strings.HasSuffix(h, "-AFRINIC"):
		return "afrinic"
	}
	return ""
}

func rirRDAPBase(rir string) string {
	switch strings.ToLower(rir) {
	case "arin":
		return "https://rdap.arin.net/registry"
	case "ripe":
		return "https://rdap.db.ripe.net"
	case "apnic":
		return "https://rdap.apnic.net"
	case "lacnic":
		return "https://rdap.lacnic.net/rdap"
	case "afrinic":
		return "https://rdap.afrinic.net/rdap"
	}
	return ""
}

func rirWhoisHost(rir string) string {
	switch strings.ToLower(rir) {
	case "arin":
		return "whois.arin.net"
	case "ripe":
		return "whois.ripe.net"
	case "apnic":
		return "whois.apnic.net"
	case "lacnic":
		return "whois.lacnic.net"
	case "afrinic":
		return "whois.afrinic.net"
	}
	return "whois.iana.org"
}
