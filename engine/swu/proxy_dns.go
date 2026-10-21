package swu

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/iniwex5/vowifi-go/engine/ipsec"
)

// The host's resolver can be a loopback/container stub unreachable from the
// proxy. Use an explicit routable resolver for proxied bootstrap DNS instead.
// Config.DNSServer overrides this default; all queries remain inside SOCKS5.
const defaultProxyDNS = "8.8.8.8:53"
const backupProxyDNS = "8.8.4.4:53"

func resolveEPDGWithProxy(ctx context.Context, remote, dnsServer string, proxy *ProxyConfig) (string, []net.IP, error) {
	return resolveEPDGWithProxyCapture(ctx, remote, dnsServer, proxy, nil)
}

func resolveEPDGWithProxyCapture(ctx context.Context, remote, dnsServer string, proxy *ProxyConfig, queries *dnsQueryCapture) (string, []net.IP, error) {
	if proxy == nil || !proxy.Enabled {
		return resolveEPDGUsingDNS(ctx, remote, dnsServer)
	}
	addr := proxy.Addr
	if addr == "" {
		addr = proxy.Address
	}
	dnsServer = proxyDNSServer(dnsServer)
	resolver := &net.Resolver{PreferGo: true, Dial: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
		// Returning a stream makes Go frame DNS over TCP even when it initially
		// requested UDP. CONNECT carries the query through the same proxy exit.
		conn, err := ipsec.DialSOCKS5TCP(dialCtx, addr, dnsServer, proxy.Username, proxy.Password)
		if err != nil {
			return nil, err
		}
		// net.Resolver can return on cancellation before its reads finish.
		// Do not leave expired streams waiting while the backup lookup runs.
		stream := &proxyDNSConn{Conn: conn}
		stream.stop = context.AfterFunc(ctx, func() { _ = stream.Conn.Close() })
		conn = stream
		if queries != nil {
			conn = queries.wrap(conn)
		}
		return conn, nil
	}}
	peer, ips, err := resolveEPDGWithResolver(ctx, remote, resolver)
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		// Resolver.Dial overrides the destination, but Go still puts the system
		// resolver in DNSError.Server. Copy it to retain error flags and cause.
		actual := *dnsErr
		actual.Server = dnsServer
		err = fmt.Errorf("resolve ePDG via SOCKS5 DNS: %w", &actual)
	}
	return peer, ips, err
}

type proxyDNSConn struct {
	net.Conn
	stop func() bool
}

func (c *proxyDNSConn) Close() error {
	c.stop()
	return c.Conn.Close()
}

func normalizeDNSServer(server string) string {
	server = strings.TrimSpace(server)
	if server != "" {
		if _, _, err := net.SplitHostPort(server); err != nil {
			server = net.JoinHostPort(strings.Trim(server, "[]"), "53")
		}
	}
	return server
}

func proxyDNSServer(server string) string {
	if server = normalizeDNSServer(server); server == "" {
		return defaultProxyDNS
	}
	return server
}
