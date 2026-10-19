package ims

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestWireFramingAndHeaderAliases(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("\r\nSIP/2.0 200 OK\r\ni: one\r\nl: 3\r\n\r\nabcSIP/2.0 202 Accepted\r\nContent-Length: 0\r\n\r\n"))
	m, e := readMessage(r)
	if e != nil || m.get("call-id") != "one" || string(m.Body) != "abc" {
		t.Fatalf("first %#v %v", m, e)
	}
	m, e = readMessage(r)
	if e != nil || m.status() != 202 {
		t.Fatalf("second %#v %v", m, e)
	}
}
func TestMalformedMessagesRejected(t *testing.T) {
	for _, raw := range []string{"SIP/2.0 200 OK\n\n", "SIP/1.0 200 OK\r\n\r\n", "SIP/2.0 200 OK\r\nContent-Length: -1\r\n\r\n", "SIP/2.0 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab", "SIP/2.0 200 OK\r\nContent-Length: 100\r\n\r\na", "SIP/2.0 200 OK\r\n missing: prior\r\n\r\n"} {
		if _, e := readMessage(bufio.NewReader(strings.NewReader(raw))); e == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	m := &message{Start: "MESSAGE sip:x SIP/2.0"}
	m.set("from", "x\r\nInjected: yes")
	if _, e := m.bytes(); e == nil {
		t.Fatal("accepted injected header")
	}
}
func FuzzWireMessage(f *testing.F) {
	f.Add([]byte("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"))
	f.Add([]byte("MESSAGE sip:x SIP/2.0\r\nContent-Length: 2\r\n\r\nxx"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > maxMessage {
			return
		}
		m, e := readMessage(bufio.NewReader(bytes.NewReader(b)))
		if e == nil {
			if _, e = m.bytes(); e != nil {
				t.Fatal(e)
			}
		}
	})
}
func TestSecurityParsing(t *testing.T) {
	raw := "ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;prot=esp;mod=trans;spi-c=100;spi-s=200;port-c=5070;port-s=5071"
	p, e := parseSecurity(raw)
	if e != nil || p.SPIClient != 100 || p.PortServer != 5071 {
		t.Fatalf("%#v %v", p, e)
	}
	for _, x := range []string{strings.Replace(raw, "spi-c=100", "spi-c=0", 1), strings.Replace(raw, "ealg=null", "ealg=des", 1), raw + ";spi-c=3"} {
		if _, e := parseSecurity(x); e == nil {
			t.Fatalf("accepted %s", x)
		}
	}
}

func TestSecurityAlternativesOnlySelectOfferedAlgorithms(t *testing.T) {
	raw := "ipsec-3gpp;alg=hmac-md5-96;ealg=null;spi-c=90;spi-s=91;port-c=5070;port-s=5071;q=1," +
		"ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;spi-c=100;spi-s=101;port-c=5072;port-s=5073;q=0.2," +
		"ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;spi-c=200;spi-s=201;port-c=5074;port-s=5075;q=0.8"
	p, err := selectSecurity(raw, SecurityParameters{Algorithm: "hmac-sha-1-96", Encryption: "aes-cbc"})
	if err != nil || p.SPIClient != 200 {
		t.Fatalf("security selection %#v %v", p, err)
	}
	if _, err = selectSecurity(raw, SecurityParameters{Algorithm: "hmac-sha-1-96", Encryption: "null"}); err == nil {
		t.Fatal("unoffered security selected")
	}
}
func TestTransactionResponseMatchesViaBranch(t *testing.T) {
	req := &message{Headers: map[string][]string{}}
	req.set("call-id", "one")
	req.set("cseq", "5 MESSAGE")
	req.set("via", "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKone;rport")
	r := response(req, 200, "OK")
	if transactionKey(req) != transactionKey(r) {
		t.Fatal("response does not match")
	}
	r.set("via", "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKother;rport")
	if transactionKey(req) == transactionKey(r) {
		t.Fatal("unrelated branch matched")
	}
}
