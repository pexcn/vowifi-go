package swu

import (
	"context"
	"net"
	"strings"

	"github.com/iniwex5/vowifi-go/engine/ipsec"
)

// The host's resolver can be a loopback/container stub unreachable from the
// proxy. Use an explicit routable resolver for proxied bootstrap DNS instead.
// Config.DNSServer overrides this default; all queries remain inside SOCKS5.
const defaultProxyDNS = "8.8.8.8:53"

func resolveEPDGWithProxy(ctx context.Context, remote, dnsServer string, proxy *ProxyConfig) (string, []net.IP, error) {
	if proxy == nil || !proxy.Enabled {
		return resolveEPDGUsingDNS(ctx, remote, dnsServer)
	}
	addr := proxy.Addr
	if addr == "" {
		addr = proxy.Address
	}
	dnsServer = strings.TrimSpace(dnsServer)
	if dnsServer == "" {
		dnsServer = defaultProxyDNS
	} else if _, _, err := net.SplitHostPort(dnsServer); err != nil {
		dnsServer = net.JoinHostPort(strings.Trim(dnsServer, "[]"), "53")
	}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		// Returning a stream makes Go frame DNS over TCP even when it initially
		// requested UDP. CONNECT carries the query through the same proxy exit.
		return ipsec.DialSOCKS5TCP(ctx, addr, dnsServer, proxy.Username, proxy.Password)
	}}
	return resolveEPDGWithResolver(ctx, remote, resolver)
}
