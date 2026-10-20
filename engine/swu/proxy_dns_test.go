package swu

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iniwex5/vowifi-go/internal/testproxy"
)

func trapLocalDNS(t *testing.T) *atomic.Int32 {
	t.Helper()
	previous := net.DefaultResolver
	var calls atomic.Int32
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("direct DNS forbidden")
	}}
	t.Cleanup(func() { net.DefaultResolver = previous })
	return &calls
}

func TestProxyDNSUsesConnectAndRetainsAllEPDGAddresses(t *testing.T) {
	local := trapLocalDNS(t)
	for _, dns := range []string{"", "resolver.proxy.invalid:5353"} {
		var calls atomic.Int32
		proxy := testproxy.Start(t, "user", "password", func(c net.Conn, target string) {
			want := dns
			if want == "" {
				want = defaultProxyDNS
			}
			if target != want {
				t.Errorf("DNS target %q, want %q", target, want)
			}
			calls.Add(1)
			answerProxyDNS(t, c)
		})
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		peer, ips, err := resolveEPDGWithProxy(ctx, "epdg.proxy.invalid.:500", dns, &ProxyConfig{Enabled: true, Addr: proxy, Username: "user", Password: "password"})
		cancel()
		if err != nil || peer != "192.0.2.10:500" || len(ips) != 3 || calls.Load() < 2 {
			t.Fatalf("proxied DNS: %s %v %v (%d calls)", peer, ips, err, calls.Load())
		}
	}
	if local.Load() != 0 {
		t.Fatal("ePDG lookup leaked to the local resolver")
	}
}

func TestProxyDNSFailureDoesNotFallBackToLocalResolver(t *testing.T) {
	local := trapLocalDNS(t)
	proxy := testproxy.Start(t, "user", "different", func(net.Conn, string) { t.Error("DNS after failed authentication") })
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, _, err := resolveEPDGWithProxy(ctx, "epdg.proxy.invalid.:500", "", &ProxyConfig{Enabled: true, Addr: proxy, Username: "user", Password: "password"}); err == nil {
		t.Fatal("proxy failure hidden")
	}
	if local.Load() != 0 {
		t.Fatal("proxy failure retried DNS directly")
	}
}

func TestProxyDNSCancellationClosesPendingQueries(t *testing.T) {
	local := trapLocalDNS(t)
	entered := make(chan struct{}, 2)
	proxy := testproxy.Start(t, "", "", func(c net.Conn, _ string) {
		entered <- struct{}{}
		io.Copy(io.Discard, c)
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := resolveEPDGWithProxy(ctx, "epdg.proxy.invalid.:500", "", &ProxyConfig{Enabled: true, Addr: proxy})
		done <- err
	}()
	<-entered
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled lookup succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("proxied DNS ignored cancellation")
	}
	if local.Load() != 0 {
		t.Fatal("cancelled proxy DNS retried locally")
	}
}

func answerProxyDNS(t *testing.T, c net.Conn) {
	t.Helper()
	for {
		var length [2]byte
		if _, err := io.ReadFull(c, length[:]); err != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(length[:]))
		if _, err := io.ReadFull(c, query); err != nil {
			return
		}
		if len(query) < 17 {
			t.Error("short DNS query")
			return
		}
		end := 12
		for end < len(query) && query[end] != 0 {
			end += int(query[end]) + 1
		}
		if end+5 > len(query) {
			t.Error("invalid DNS question")
			return
		}
		kind := binary.BigEndian.Uint16(query[end+1 : end+3])
		var addresses []net.IP
		if kind == 1 {
			addresses = []net.IP{net.ParseIP("192.0.2.10").To4(), net.ParseIP("192.0.2.11").To4()}
		}
		if kind == 28 {
			addresses = []net.IP{net.ParseIP("2001:db8::10").To16()}
		}
		response := append([]byte(nil), query[:end+5]...)
		binary.BigEndian.PutUint16(response[2:4], 0x8180)
		binary.BigEndian.PutUint16(response[6:8], uint16(len(addresses)))
		binary.BigEndian.PutUint16(response[8:10], 0)
		binary.BigEndian.PutUint16(response[10:12], 0)
		for _, address := range addresses {
			response = append(response, 0xc0, 0x0c, byte(kind>>8), byte(kind), 0, 1, 0, 0, 0, 60, 0, byte(len(address)))
			response = append(response, address...)
		}
		binary.BigEndian.PutUint16(length[:], uint16(len(response)))
		if _, err := c.Write(append(length[:], response...)); err != nil {
			return
		}
	}
}
