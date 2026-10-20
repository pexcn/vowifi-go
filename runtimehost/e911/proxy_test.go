package e911

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iniwex5/vowifi-go/internal/testproxy"
)

func forbidLocalDNS(t *testing.T) *atomic.Int32 {
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

func TestProxyHTTPPreservesTLSHeadersAndRedirectPolicy(t *testing.T) {
	localDNS := forbidLocalDNS(t)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "POST" || len(r.Header.Values("X-Test")) != 2 {
			t.Error("entitlement method or repeated headers lost")
		}
		w.Header().Add("Set-Cookie", "one=1")
		w.Header().Add("Set-Cookie", "two=2")
		w.Header().Set("Location", "https://must-not-follow.invalid/")
		w.WriteHeader(http.StatusFound)
		w.Write([]byte("proxied"))
	}))
	defer server.Close()
	if err := server.Certificate().VerifyHostname("example.com"); err != nil {
		t.Fatal(err)
	}
	upstream, _ := url.Parse(server.URL)
	_, port, _ := net.SplitHostPort(upstream.Host)
	target := net.JoinHostPort("example.com", port)
	seen := make(chan string, 4)
	proxy := testproxy.Start(t, "user", "password", func(c net.Conn, address string) {
		seen <- address
		remote, err := net.Dial("tcp", upstream.Host)
		if err != nil {
			t.Error(err)
			return
		}
		defer remote.Close()
		done := make(chan struct{})
		go func() { io.Copy(remote, c); remote.Close(); close(done) }()
		io.Copy(c, remote)
		<-done
	})
	newClient := func(trust bool) defaultHTTPClient {
		client, err := NewHTTPClientWithProxy(SOCKS5Proxy{Addr: proxy, Username: "user", Password: "password"})
		if err != nil {
			t.Fatal(err)
		}
		c := client.(defaultHTTPClient)
		if trust {
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			c.client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: roots}
		}
		t.Cleanup(c.CloseIdleConnections)
		return c
	}
	trusted := newClient(true)
	response, err := trusted.Do(&HTTPRequest{Method: "POST", URL: "https://" + target + "/entitlement", Headers: []HeaderPair{{"X-Test", "one"}, {"X-Test", "two"}}})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusFound || string(response.Body) != "proxied" || requests.Load() != 1 {
		t.Fatalf("unexpected proxied response: %+v (%d requests)", response, requests.Load())
	}
	cookies := 0
	for _, h := range response.Headers {
		if strings.EqualFold(h.Key, "Set-Cookie") {
			cookies++
		}
	}
	if cookies != 2 {
		t.Fatal("repeated response headers lost")
	}
	if address := <-seen; address != target {
		t.Fatalf("proxy target %q, want %q", address, target)
	}
	trusted.CloseIdleConnections()
	untrusted := newClient(false)
	_, err = untrusted.Do(&HTTPRequest{URL: "https://" + target + "/"})
	var certificateError x509.UnknownAuthorityError
	if !errors.As(err, &certificateError) {
		t.Fatalf("untrusted certificate accepted: %v", err)
	}
	untrusted.CloseIdleConnections()
	if localDNS.Load() != 0 {
		t.Fatal("HTTP target lookup bypassed proxy")
	}
}

func TestProxyHTTPCancellationStopsTLSHandshake(t *testing.T) {
	entered := make(chan struct{})
	proxy := testproxy.Start(t, "", "", func(c net.Conn, _ string) {
		close(entered)
		io.Copy(io.Discard, c)
	})
	client, err := NewHTTPClientWithProxy(SOCKS5Proxy{Addr: proxy})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := client.Do(&HTTPRequest{Context: ctx, URL: "https://target.invalid/"}); done <- err }()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("proxied TLS ignored cancellation")
	}
}

func TestEntitlementProxyFailureAndCustomClientDoNotFallBack(t *testing.T) {
	localDNS := forbidLocalDNS(t)
	proxy := testproxy.Start(t, "user", "different", func(net.Conn, string) { t.Error("HTTP after failed proxy authentication") })
	req := entitlementRequest()
	req.Proxy = &SOCKS5Proxy{Addr: proxy, Username: "user", Password: "password"}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := StartEmergencyAddressUpdate(ctx, req); err == nil || !strings.Contains(err.Error(), "SOCKS authentication failed") {
		t.Fatalf("entitlement ignored selected proxy: %v", err)
	}
	if localDNS.Load() != 0 {
		t.Fatal("entitlement proxy failure used direct DNS")
	}
	req.Client = httpFunc(func(*HTTPRequest) (*HTTPResponse, error) {
		t.Error("custom client bypassed mandatory proxy")
		return nil, nil
	})
	if _, err := StartEmergencyAddressUpdate(t.Context(), req); err == nil || !strings.Contains(err.Error(), "custom HTTP client") {
		t.Fatalf("ambiguous proxy routing accepted: %v", err)
	}
	if _, err := NewHTTPClientWithProxy(SOCKS5Proxy{}); err == nil {
		t.Fatal("empty proxy accepted")
	}
}
