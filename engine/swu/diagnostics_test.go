package swu

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/iniwex5/vowifi-go/internal/testproxy"
)

func TestProxyDNSDiagnosticsReportActualTargetAndSelectedPeer(t *testing.T) {
	local := trapLocalDNS(t)
	for _, server := range []string{"", "resolver.proxy.invalid:5353"} {
		t.Run(server, func(t *testing.T) {
			wantTarget := server
			if wantTarget == "" {
				wantTarget = defaultProxyDNS
			}
			proxy := testproxy.Start(t, "user", "secret", func(c net.Conn, target string) {
				if target != wantTarget {
					t.Errorf("actual CONNECT target = %q, want %q", target, wantTarget)
				}
				answerProxyDNS(t, c)
			})
			var events []Diagnostic
			cfg := Config{
				DeviceID: "device", TraceID: "trace", EPDGAddr: "epdg.proxy.invalid.",
				DNSServer: server, IPStack: "ipv4v6",
				Proxy:        &ProxyConfig{ID: "de", Enabled: true, Addr: proxy, Username: "user", Password: "secret"},
				OnDiagnostic: func(d Diagnostic) { events = append(events, d) },
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			peer, ips, err := cfg.resolveEPDG(ctx, "epdg.proxy.invalid.:500")
			if err != nil || len(events) != 1 {
				t.Fatalf("DNS result = %s %v, diagnostics = %+v", peer, err, events)
			}
			d := events[0]
			if d.Stage != "epdg_dns" || d.DNSMode != "proxy" || d.DNSTarget != wantTarget || d.Peer != peer || d.Err != nil {
				t.Fatalf("DNS diagnostic = %+v", d)
			}
			if d.DeviceID != "device" || d.TraceID != "trace" || d.ProxyID != "de" || d.RequestedIPStack != "ipv4v6" {
				t.Fatalf("lost diagnostic correlation: %+v", d)
			}
			var wantIPs []string
			for _, ip := range ips {
				wantIPs = append(wantIPs, ip.String())
			}
			if !reflect.DeepEqual(d.ResolvedIPs, wantIPs) || d.Peer != "192.0.2.10:500" {
				t.Fatalf("diagnostic did not retain resolved peers: %+v", d)
			}
		})
	}
	if local.Load() != 0 {
		t.Fatal("diagnostic collection leaked queries to local DNS")
	}
}

func TestDNSFailureDiagnosticsSurviveStartupCleanup(t *testing.T) {
	local := trapLocalDNS(t)
	proxy := testproxy.Start(t, "", "", func(c net.Conn, target string) {
		if target != defaultProxyDNS {
			t.Errorf("actual target = %q", target)
		}
		answerProxyDNSCode(t, c, 3)
	})
	p := newMockPeer(t, "")
	cfg := p.cfg
	cfg.Transport, cfg.EPDGAddr = nil, "epdg.proxy.invalid."
	cfg.Proxy = &ProxyConfig{ID: "de", Enabled: true, Addr: proxy}
	var events []Diagnostic
	cfg.OnDiagnostic = func(d Diagnostic) { events = append(events, d) }
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	s, err := Start(ctx, cfg)
	var dnsErr *net.DNSError
	if s != nil || !errors.As(err, &dnsErr) || !dnsErr.IsNotFound || len(events) != 1 {
		t.Fatalf("DNS failure = %v, session = %v, diagnostics = %+v", err, s, events)
	}
	d := events[0]
	if d.Stage != "epdg_dns" || d.DNSTarget != defaultProxyDNS || d.Err != err || d.Peer != "" || len(d.ResolvedIPs) != 0 {
		t.Fatalf("failed startup lost actual DNS target: %+v", d)
	}
	if local.Load() != 0 {
		t.Fatal("failed proxy DNS fell back to local resolution")
	}
}

func TestHandshakeDiagnosticsCaptureAssignedFamilyAndNotify36(t *testing.T) {
	for _, mode := range []string{"cookie", "internal-address-failure"} {
		t.Run(mode, func(t *testing.T) {
			p := newMockPeer(t, mode)
			p.cfg.DeviceID, p.cfg.TraceID = "device", "trace"
			var events []Diagnostic
			p.cfg.OnDiagnostic = func(d Diagnostic) { events = append(events, d) }
			p.start()
			s, err := Start(t.Context(), p.cfg)
			if s != nil {
				defer s.Close()
			}
			p.check(t)
			if len(events) != 1 {
				t.Fatalf("handshake diagnostics = %+v", events)
			}
			d := events[0]
			if d.Stage != "ike_handshake" || d.DeviceID != "device" || d.TraceID != "trace" || d.Peer == "" || d.RequestedIPStack != "ipv4v6" {
				t.Fatalf("lost handshake correlation: %+v", d)
			}
			if mode == "cookie" {
				if err != nil || d.Err != nil || d.Peer != s.RemoteAddr || !reflect.DeepEqual(d.AssignedIPFamilies, []string{"ipv4"}) {
					t.Fatalf("success diagnostic = %+v, err = %v", d, err)
				}
			} else if s != nil || err == nil || err.Error() != "IKE_AUTH error notify 36" || d.Err != err || d.NotifyType != 36 || d.NotifyName != "INTERNAL_ADDRESS_FAILURE" || len(d.AssignedIPFamilies) != 0 || !p.transport.closed.Load() {
				t.Fatalf("notify 36 diagnostic or cleanup lost: %+v, err = %v", d, err)
			}
		})
	}
}

func TestLiteralPeerDiagnosticDoesNotClaimDNSQuery(t *testing.T) {
	var got Diagnostic
	cfg := Config{OnDiagnostic: func(d Diagnostic) { got = d }}
	peer, _, err := cfg.resolveEPDG(context.Background(), "[2001:db8::10]:4500")
	if err != nil || got.DNSMode != "literal" || got.DNSTarget != "" || !strings.Contains(peer, "2001:db8::10") {
		t.Fatalf("literal peer diagnostic = %+v, err = %v", got, err)
	}
}
