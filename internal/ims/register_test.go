package ims

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestInitialRegisterPlaceholderIsReplacedByAKAResponse(t *testing.T) {
	for _, tc := range []struct {
		name  string
		plain bool
		proxy bool
	}{
		{name: "AKA-placeholder"},
		{name: "plain-placeholder", plain: true},
		{name: "proxy-challenge", proxy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := configPeer(t, func(c net.Conn) error {
				r := bufio.NewReader(c)
				initial, err := readMessage(r)
				if err != nil {
					return err
				}
				want := `Digest uri="sip:ims.test",username="001010123456789@ims.test"`
				if !tc.plain {
					want += `,algorithm=AKAv1-MD5`
				}
				want += `,response="",realm="ims.test",nonce=""`
				if initial.method() != "REGISTER" || initial.get("authorization") != want || initial.get("proxy-authorization") != "" {
					return fmt.Errorf("initial REGISTER did not request the expected AKA challenge")
				}
				if initial.get("require") != "" || initial.get("proxy-require") != "" {
					return fmt.Errorf("security agreement required without an offer")
				}
				code, challengeName, authName := 401, "www-authenticate", "authorization"
				if tc.proxy {
					code, challengeName, authName = 407, "proxy-authenticate", "proxy-authorization"
				}
				nonce := base64.StdEncoding.EncodeToString(make([]byte, 32))
				challenge := response(initial, code, "Authentication Required")
				challenge.set(challengeName, `Digest realm="ims.test", nonce="`+nonce+`", algorithm=AKAv1-MD5, qop="auth"`)
				if err = sendPeer(c, challenge); err != nil {
					return err
				}
				auth, err := readMessage(r)
				if err != nil {
					return err
				}
				value := auth.get(authName)
				if !strings.HasPrefix(value, "Digest ") {
					return fmt.Errorf("missing challenge response")
				}
				p, err := parameters(value[7:], ',')
				if err != nil || p["algorithm"] != "AKAv1-MD5" || p["nonce"] != nonce || len(p["response"]) != 32 || p["qop"] != "auth" {
					return fmt.Errorf("placeholder was not replaced by a complete AKA response")
				}
				if tc.proxy && auth.get("authorization") != "" {
					return fmt.Errorf("initial placeholder leaked into proxy-authenticated request")
				}
				if auth.get("call-id") != initial.get("call-id") || auth.get("cseq") == initial.get("cseq") {
					return fmt.Errorf("registration transaction continuity lost")
				}
				if err = sendPeer(c, response(auth, 200, "OK")); err != nil {
					return err
				}
				_, _ = readMessage(r)
				return nil
			})
			cfg.UsePlainDigestPlaceholder = tc.plain
			s, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if err = s.Start(context.Background()); err != nil || !s.Ready() {
				t.Fatalf("AKA registration failed: %v", err)
			}
		})
	}
}

func TestRegisterRejectionReportsPhaseAndCloses(t *testing.T) {
	for _, phase := range []string{"initial", "authenticated"} {
		t.Run(phase, func(t *testing.T) {
			cfg := configPeer(t, func(c net.Conn) error {
				r := bufio.NewReader(c)
				var m *message
				var err error
				if phase == "authenticated" {
					m, err = peerRegister(r, c)
				} else {
					m, err = readMessage(r)
				}
				if err != nil {
					return err
				}
				if err = sendPeer(c, response(m, 400, "Bad Request")); err != nil {
					return err
				}
				if _, err = readMessage(r); err == nil {
					return fmt.Errorf("rejected registration retried without a new challenge")
				}
				return nil
			})
			s, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			err = s.Start(context.Background())
			round := 1
			if phase == "authenticated" {
				round = 2
			}
			if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("400 Bad Request (phase=%s, round=%d, transport=tcp)", phase, round)) || s.Ready() {
				t.Fatalf("rejection phase lost or marked ready: %v", err)
			}
			if strings.Contains(err.Error(), cfg.PrivateIdentity) {
				t.Fatal("rejection diagnostic exposed private identity")
			}
		})
	}
}
