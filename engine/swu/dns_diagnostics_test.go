package swu

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/iniwex5/vowifi-go/internal/testproxy"
)

func TestProxyDNSQueryDiagnostics(t *testing.T) {
	local := trapLocalDNS(t)
	for _, tc := range []struct {
		name, rcode string
		code        uint16
		empty       bool
		missing     bool
		timeout     bool
	}{
		{name: "addresses", rcode: "NOERROR"},
		{name: "no-addresses", rcode: "NOERROR", empty: true},
		{name: "nxdomain", code: 3, rcode: "NXDOMAIN"},
		{name: "servfail", code: 2, rcode: "SERVFAIL"},
		{name: "refused", code: 5, rcode: "REFUSED"},
		{name: "incomplete-response", missing: true},
		{name: "timeout", missing: true, timeout: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy := testproxy.Start(t, "", "", func(c net.Conn, target string) {
				if target != defaultProxyDNS {
					t.Errorf("CONNECT target = %q", target)
				}
				if tc.missing {
					var size [2]byte
					if _, err := io.ReadFull(c, size[:]); err != nil {
						return
					}
					io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint16(size[:])))
					if tc.timeout {
						io.Copy(io.Discard, c)
						return
					}
					// A partial frame must not look like a complete negative reply.
					c.Write([]byte{0, 12, 0})
					return
				}
				answerProxyDNSResponse(t, c, tc.code, tc.empty)
			})
			var d Diagnostic
			cfg := Config{DNSServer: defaultProxyDNS, Proxy: &ProxyConfig{Enabled: true, Addr: proxy}, OnDiagnostic: func(got Diagnostic) { d = got }}
			timeout := time.Second
			if tc.timeout {
				timeout = 100 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(t.Context(), timeout)
			defer cancel()
			_, _, err := cfg.resolveEPDG(ctx, "epdg.proxy.invalid.:500")
			wantFailure := tc.empty || tc.code != 0 || tc.missing
			if (err != nil) != wantFailure || d.Err != err {
				t.Fatalf("lookup error = %v, want failure %v", err, wantFailure)
			}
			if err != nil {
				var dnsErr *net.DNSError
				if !errors.As(err, &dnsErr) || dnsErr.Server != defaultProxyDNS || !strings.Contains(err.Error(), "via SOCKS5 DNS") {
					t.Fatalf("incorrect DNS error route: %v", err)
				}
				if tc.empty || tc.code == 3 {
					if !dnsErr.IsNotFound {
						t.Fatalf("lost not-found flag: %+v", dnsErr)
					}
				}
				if tc.timeout && (!dnsErr.IsTimeout || !errors.Is(err, context.DeadlineExceeded)) {
					t.Fatalf("lost timeout flag or cause: %v", err)
				}
			}
			seen := make(map[string]bool)
			for _, q := range d.DNSQueries {
				seen[q.Type] = true
				wantCount := uint16(0)
				if !wantFailure {
					wantCount = 1
					if q.Type == "A" {
						wantCount = 2
					}
				}
				if q.ResponseReceived == tc.missing || q.RCode != tc.rcode || q.AnswerCount != wantCount {
					t.Fatalf("wire summary = %+v, case %+v", q, tc)
				}
			}
			if !seen["A"] || !seen["AAAA"] || d.DNSQueriesTruncated {
				t.Fatalf("missing query types or unexpected truncation: %+v", d)
			}
		})
	}
	if local.Load() != 0 {
		t.Fatal("diagnostic lookup fell back to local DNS")
	}
}

func TestDNSDiagnosticCaptureBoundsAndFraming(t *testing.T) {
	// A maximum-size TCP response delivered byte by byte must not be copied
	// in full. Its header count is diagnostic data, not a validated RR count.
	body := make([]byte, 65535)
	binary.BigEndian.PutUint16(body, 123)
	binary.BigEndian.PutUint16(body[4:], 1)
	body[12], body[14], body[16] = 0, 1, 1 // Root question, type A, class IN.
	frame := append([]byte{255, 255}, body...)
	c := &dnsDiagnosticConn{}
	c.query.add(frame)
	body[2] = 0x80
	binary.BigEndian.PutUint16(body[6:], 7)
	response := append([]byte{255, 255}, body...)
	for _, b := range response[:len(response)-1] {
		c.response.add([]byte{b})
	}
	capture := &dnsQueryCapture{conns: []*dnsDiagnosticConn{c}}
	q, _ := capture.snapshot()
	if len(q) != 1 || q[0].ResponseReceived {
		t.Fatalf("partial response accepted: %+v", q)
	}
	c.response.add(response[len(response)-1:])
	q, _ = capture.snapshot()
	if !q[0].ResponseReceived || q[0].AnswerCount != 7 || len(c.response.prefix) > 273 {
		t.Fatalf("fragmented response or storage bound: %+v (%d bytes)", q, len(c.response.prefix))
	}
	c.response.prefix[2] ^= 1 // Wrong response ID.
	q, _ = capture.snapshot()
	if q[0].ResponseReceived {
		t.Fatal("unrelated response accepted")
	}
	malformed := append([]byte(nil), body[:17]...)
	malformed[12] = 64 // Reserved label encoding with a question present.
	for _, msg := range [][]byte{nil, make([]byte, 12), malformed} {
		if _, valid := dnsQuestionType(msg); valid {
			t.Fatal("malformed question accepted")
		}
	}
	capture = &dnsQueryCapture{}
	for range maxDNSDiagnosticQueries + 1 {
		capture.wrap(nil)
	}
	_, truncated := capture.snapshot()
	if !truncated || len(capture.conns) != maxDNSDiagnosticQueries {
		t.Fatal("capture exceeded query limit or failed to report truncation")
	}
}
