package swu

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// Diagnostic describes one startup stage result, with a result per DNS attempt.
// DNSMode is literal, system, custom, or proxy. DNSTarget is the configured
// endpoint actually used for custom/proxy queries; system resolution leaves it
// empty because its endpoint is unknown.
// Peer is the selected ePDG endpoint, which can change during initial failover.
type Diagnostic struct {
	Stage, DeviceID, TraceID, EPDG, ProxyID string
	DNSMode, DNSTarget                      string
	DNSQueries                              []DNSQueryDiagnostic
	DNSQueriesTruncated                     bool
	ResolvedIPs                             []string
	Peer, RequestedIPStack                  string
	AssignedIPFamilies                      []string
	Duration                                time.Duration
	NotifyType                              uint16
	NotifyName                              string
	Err                                     error
}

func (c Config) diagnostic(stage string, started time.Time, err error) Diagnostic {
	d := Diagnostic{
		Stage: stage, DeviceID: c.DeviceID, TraceID: c.TraceID,
		EPDG: c.EPDGAddr, RequestedIPStack: c.IPStack,
		Duration: time.Since(started), Err: err,
	}
	if c.Proxy != nil && c.Proxy.Enabled {
		d.ProxyID = c.Proxy.ID
	}
	return d
}

func (c Config) resolveEPDG(ctx context.Context, remote string) (string, []net.IP, error) {
	host, _, splitErr := net.SplitHostPort(remote)
	if c.Proxy == nil || !c.Proxy.Enabled || normalizeDNSServer(c.DNSServer) != "" ||
		splitErr != nil || net.ParseIP(host) != nil {
		return c.resolveEPDGAttempt(ctx, remote)
	}
	// Default proxy DNS gets one bounded budget. Reserve time for the backup
	// even if the primary stalls; an explicit DNSServer is used alone.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	servers := [...]string{defaultProxyDNS, backupProxyDNS}
	var peer string
	var ips []net.IP
	var err error
	for i, server := range servers {
		deadline, _ := ctx.Deadline()
		attemptCtx, finish := context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(servers)-i))
		attempt := c
		attempt.DNSServer = server
		peer, ips, err = attempt.resolveEPDGAttempt(attemptCtx, remote)
		finish()
		if err == nil || ctx.Err() != nil {
			break
		}
	}
	return peer, ips, err
}

func (c Config) resolveEPDGAttempt(ctx context.Context, remote string) (string, []net.IP, error) {
	started := time.Now()
	var queries *dnsQueryCapture
	if c.OnDiagnostic != nil && c.Proxy != nil && c.Proxy.Enabled {
		queries = &dnsQueryCapture{}
	}
	peer, ips, err := resolveEPDGWithProxyCapture(ctx, remote, c.DNSServer, c.Proxy, queries)
	if c.OnDiagnostic != nil {
		d := c.diagnostic("epdg_dns", started, err)
		d.Peer = peer
		if queries != nil {
			d.DNSQueries, d.DNSQueriesTruncated = queries.snapshot()
		}
		for _, ip := range ips {
			d.ResolvedIPs = append(d.ResolvedIPs, ip.String())
		}
		host, _, _ := net.SplitHostPort(remote)
		switch {
		case net.ParseIP(host) != nil:
			d.DNSMode = "literal"
		case c.Proxy != nil && c.Proxy.Enabled:
			d.DNSMode, d.DNSTarget = "proxy", proxyDNSServer(c.DNSServer)
		case normalizeDNSServer(c.DNSServer) != "":
			d.DNSMode, d.DNSTarget = "custom", normalizeDNSServer(c.DNSServer)
		default:
			d.DNSMode = "system"
		}
		c.OnDiagnostic(d)
	}
	return peer, ips, err
}

func (s *Session) reportHandshake(started time.Time, err error) {
	if s.cfg.OnDiagnostic == nil {
		return
	}
	d := s.cfg.diagnostic("ike_handshake", started, err)
	d.Peer = s.RemoteAddr
	var notify *ikeAuthNotifyError
	if errors.As(err, &notify) {
		d.NotifyType, d.NotifyName = notify.typ, ikeNotifyName(notify.typ)
	}
	if err == nil {
		seen := make(map[string]bool)
		for _, ip := range s.configuration.Addresses {
			family := "ipv6"
			if ip.Is4() {
				family = "ipv4"
			}
			if !seen[family] {
				d.AssignedIPFamilies = append(d.AssignedIPFamilies, family)
				seen[family] = true
			}
		}
	}
	s.cfg.OnDiagnostic(d)
}

type ikeAuthNotifyError struct{ typ uint16 }

func (e *ikeAuthNotifyError) Error() string { return fmt.Sprintf("IKE_AUTH error notify %d", e.typ) }

func ikeNotifyName(typ uint16) string {
	switch typ {
	case 14:
		return "NO_PROPOSAL_CHOSEN"
	case 24:
		return "AUTHENTICATION_FAILED"
	case 36:
		return "INTERNAL_ADDRESS_FAILURE"
	case 37:
		return "FAILED_CP_REQUIRED"
	case 38:
		return "TS_UNACCEPTABLE"
	case 43:
		return "TEMPORARY_FAILURE"
	default:
		return "UNKNOWN"
	}
}
