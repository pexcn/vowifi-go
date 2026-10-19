package ims

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRegisterBindingWithQuotedSIPInstance(t *testing.T) {
	cfg := configPeer(t, func(c net.Conn) error {
		r := bufio.NewReader(c)
		auth, err := peerRegister(r, c)
		if err != nil {
			return err
		}
		ok := response(auth, 200, "OK")
		ok.set("expires", "3600")
		ok.set("contact", auth.get("contact")+";expires=120")
		if err = sendPeer(c, ok); err != nil {
			return err
		}
		_, _ = readMessage(r)
		return nil
	})
	cfg.SIPInstance = "urn:gsma:imei:12345678-123456-0"
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Start(context.Background()); err != nil || !s.Ready() {
		t.Fatalf("quoted instance registration: %v", err)
	}
	s.mu.Lock()
	expires := s.cfg.Expires
	s.mu.Unlock()
	if expires != 120*time.Second {
		t.Fatalf("Contact expiry = %v", expires)
	}
}

func TestContactExpiryWithQuotedAnglesAndParameters(t *testing.T) {
	const uri = "sip:me@127.0.0.1:5071;transport=tcp"
	for _, tc := range []struct {
		name, value string
		want        time.Duration
		fail        bool
	}{
		{"instance-before-expiry", `<` + uri + `>;+sip.instance="<urn:uuid:00000000-0000-4000-8000-000000000001>";expires=120`, 120 * time.Second, false},
		{"instance-after-expiry", `<` + uri + `>;expires=120;+sip.instance="<urn:gsma:imei:12345678-123456-0>"`, 120 * time.Second, false},
		{"display-angles", `"Name <other>, \">" <` + uri + `>;+sip.instance="<urn:uuid:example>";expires=120`, 120 * time.Second, false},
		{"quoted-generic-param", `<` + uri + `>;note="x>y;expires=0";expires=120`, 120 * time.Second, false},
		{"no-binding-expiry", `<` + uri + `>;+sip.instance="<urn:uuid:example>"`, time.Hour, false},
		{"zero-expiry", `<` + uri + `>;+sip.instance="<urn:uuid:example>";expires=0`, 0, true},
		{"duplicate-expiry", `<` + uri + `>;+sip.instance="<urn:uuid:example>";expires=120;expires=180`, 0, true},
		{"unterminated-param", `<` + uri + `>;+sip.instance="<urn:uuid:example>;expires=120`, 0, true},
		{"unterminated-address", `<` + uri + `;expires=120`, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &message{Headers: map[string][]string{}}
			r.set("expires", "3600")
			r.set("contact", `<sip:other@127.0.0.1>;expires=0, `+tc.value)
			got, err := registrationExpiry(r, `<`+uri+`>;+sip.instance="<urn:uuid:example>"`, 2*time.Hour)
			if (err != nil) != tc.fail || got != tc.want {
				t.Fatalf("binding expiry = %v, err=%v, want %v (fail=%v)", got, err, tc.want, tc.fail)
			}
		})
	}
}

func TestRegisterMalformedHeaderErrorsIdentifyStage(t *testing.T) {
	for _, stage := range []string{"www-authenticate challenge", "Security-Server", "Contact/Expires"} {
		t.Run(stage, func(t *testing.T) {
			const marker = "private-header-marker"
			cfg := configPeer(t, func(c net.Conn) error {
				r := bufio.NewReader(c)
				if stage == "Contact/Expires" {
					auth, err := peerRegister(r, c)
					if err != nil {
						return err
					}
					ok := response(auth, 200, "OK")
					ok.set("contact", auth.get("contact")+`;note="`+marker)
					if err = sendPeer(c, ok); err != nil {
						return err
					}
				} else {
					initial, err := readMessage(r)
					if err != nil {
						return err
					}
					challenge := response(initial, 401, "Unauthorized")
					challenge.set("www-authenticate", `Digest realm="ims.test", nonce="`+base64.StdEncoding.EncodeToString(make([]byte, 32))+`", algorithm=AKAv1-MD5`)
					if stage == "Security-Server" {
						challenge.set("security-server", `ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;note="`+marker)
					} else {
						challenge.set("www-authenticate", `Digest realm="`+marker)
					}
					if err = sendPeer(c, challenge); err != nil {
						return err
					}
				}
				_, _ = readMessage(r)
				return nil
			})
			if stage == "Security-Server" {
				cfg.SecurityClient = &SecurityParameters{Algorithm: "hmac-sha-1-96", Encryption: "aes-cbc", SPIClient: 200, SPIServer: 201, PortClient: 5070, PortServer: 5071}
				cfg.InstallSecurity = func(context.Context, SecurityAgreement) (DialContextFunc, error) {
					return nil, errors.New("invalid Security-Server reached installer")
				}
			}
			s, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			err = s.Start(context.Background())
			if err == nil || !strings.Contains(err.Error(), "IMS REGISTER "+stage+":") || !strings.Contains(err.Error(), "unterminated quoted parameter") || s.Ready() {
				t.Fatalf("missing registration error stage: %v", err)
			}
			if strings.Contains(err.Error(), marker) {
				t.Fatal("registration error exposed raw header value")
			}
		})
	}
}

func TestContactExpiryDoesNotParseURIParametersAsBindingLifetime(t *testing.T) {
	const contact = `<sip:me@127.0.0.1:5071;expires=0;transport=tcp>`
	r := &message{Headers: map[string][]string{}}
	r.set("expires", "3600")
	r.set("contact", contact+`;note="expires=0; <ignore>";expires=120`)
	got, err := registrationExpiry(r, contact, time.Hour)
	if err != nil || got != 120*time.Second {
		t.Fatalf("URI versus binding params: %v %v", got, err)
	}
}
