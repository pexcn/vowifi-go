package swu

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/iniwex5/vowifi-go/internal/testproxy"
)

func TestProxyDNSDefaultFailover(t *testing.T) {
	local := trapLocalDNS(t)
	for _, mode := range []string{"no-addresses", "nxdomain", "primary-timeout", "both-fail"} {
		t.Run(mode, func(t *testing.T) {
			primaryClosed := make(chan struct{}, 2)
			proxy := testproxy.Start(t, "user", "secret", func(c net.Conn, target string) {
				switch target {
				case defaultProxyDNS:
					if mode == "primary-timeout" {
						io.Copy(io.Discard, c)
						primaryClosed <- struct{}{}
						return
					}
					code := uint16(0)
					if mode == "nxdomain" {
						code = 3
					}
					answerProxyDNSResponse(t, c, code, true)
				case backupProxyDNS:
					if mode == "primary-timeout" {
						select {
						case <-primaryClosed:
						case <-time.After(time.Second):
							t.Error("timed-out primary stream was not closed")
						}
					}
					answerProxyDNSResponse(t, c, 0, mode == "both-fail")
				default:
					t.Errorf("unexpected DNS CONNECT target %q", target)
				}
			})
			var events []Diagnostic
			cfg := Config{
				Proxy:        &ProxyConfig{Enabled: true, Addr: proxy, Username: "user", Password: "secret"},
				OnDiagnostic: func(d Diagnostic) { events = append(events, d) },
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			peer, ips, err := cfg.resolveEPDG(ctx, "epdg.proxy.invalid.:500")
			if len(events) != 2 || events[0].DNSTarget != defaultProxyDNS || events[0].Err == nil ||
				events[1].DNSTarget != backupProxyDNS || events[1].Err != err {
				t.Fatalf("incorrect failover diagnostics: %+v", events)
			}
			if mode == "both-fail" {
				var dnsErr *net.DNSError
				if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound || dnsErr.Server != backupProxyDNS || peer != "" || len(ips) != 0 {
					t.Fatalf("lost final DNS failure: %s %v %v", peer, ips, err)
				}
			} else if err != nil || peer != "192.0.2.10:500" || len(ips) != 3 {
				t.Fatalf("backup resolution failed: %s %v %v", peer, ips, err)
			}
			if ctx.Err() != nil {
				t.Fatal("primary exhausted the shared deadline")
			}
		})
	}
	if local.Load() != 0 {
		t.Fatal("DNS failover leaked to the local resolver")
	}
}
