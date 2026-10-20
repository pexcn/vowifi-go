package ims

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	smscodec "github.com/warthog618/sms"
)

type reauthenticationListener struct {
	recoveryListener
	connections chan net.Conn
}

func (l *reauthenticationListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.connections:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

type reauthenticationConn struct {
	net.Conn
	remote net.Addr
}

func (c *reauthenticationConn) RemoteAddr() net.Addr { return c.remote }

func TestProtectedRefreshReauthenticationRebuildsIMSAndReceivesSMS(t *testing.T) {
	for _, status := range []int{401, 407} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			const cycles = 3
			states := make(chan bool, 32)
			var agreements []SecurityAgreement
			var listeners []*reauthenticationListener
			var mu sync.Mutex
			var plainPeers, protectedPeers []Config
			var security []string
			challenge := func(m *message, raw string) *message {
				r := response(m, status, "Authentication required")
				h := "www-authenticate"
				if status == 407 {
					h = "proxy-authenticate"
				}
				r.set(h, `Digest realm="ims.test", nonce="`+base64.StdEncoding.EncodeToString(make([]byte, 32))+`", algorithm=AKAv1-MD5`)
				r.set("security-server", raw)
				return r
			}
			for cycle := range cycles {
				protected := configPeer(t, func(c net.Conn) error {
					r := bufio.NewReader(c)
					reg, err := readMessage(r)
					if err != nil {
						return err
					}
					auth := "authorization"
					if status == 407 {
						auth = "proxy-authorization"
					}
					if reg.method() != "REGISTER" || reg.get("security-verify") == "" || !strings.Contains(reg.get(auth), "response=") || strings.Contains(reg.get(auth), `response=""`) {
						return errors.New("missing fresh protected authentication")
					}
					ok := response(reg, 200, "OK")
					if cycle == cycles-1 {
						ok.set("expires", "3600")
					}
					if err = sendPeer(c, ok); err != nil {
						return err
					}
					next, err := readMessage(r)
					if err != nil {
						return err
					}
					if cycle == cycles-1 {
						if next.method() != "MESSAGE" || !bytes.Equal(next.Body, []byte{2, 44}) {
							return errors.New("missing SMS RP-ACK after reauthentication")
						}
						if err = sendPeer(c, response(next, 200, "OK")); err != nil {
							return err
						}
					} else {
						if next.method() != "REGISTER" || next.get("security-verify") == "" {
							return errors.New("expected protected refresh")
						}
						if err = sendPeer(c, challenge(next, security[cycle])); err != nil {
							return err
						}
					}
					if _, err = readMessage(r); err == nil {
						return errors.New("old protected flow reused after reauthentication")
					}
					return nil
				})
				protectedPeers = append(protectedPeers, protected)
				_, port, _ := net.SplitHostPort(protected.PCSCF[0])
				security = append(security, "ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;spi-c=400;spi-s=401;port-c="+port+";port-s="+port)
				plainPeers = append(plainPeers, configPeer(t, func(c net.Conn) error {
					r := bufio.NewReader(c)
					reg, err := readMessage(r)
					if err != nil {
						return err
					}
					if reg.get("security-verify") != "" || !strings.Contains(reg.get("authorization"), `nonce=""`) {
						return errors.New("fresh IMS flow inherited old authentication")
					}
					if err = sendPeer(c, challenge(reg, security[cycle])); err != nil {
						return err
					}
					if _, err = readMessage(r); err == nil {
						return errors.New("AKA response sent on unprotected flow")
					}
					return nil
				}))
			}
			cfg := plainPeers[0]
			var connects atomic.Int32
			// Each fresh flow reaches the same logical P-CSCF. Separate TCP
			// fixtures provide deterministic challenges for successive cycles.
			cfg.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				index := int(connects.Add(1)) - 1
				if address != cfg.PCSCF[0] || index >= cycles {
					return nil, errors.New("reauthentication changed P-CSCF or looped")
				}
				return (&net.Dialer{}).DialContext(ctx, network, plainPeers[index].PCSCF[0])
			}
			cfg.Expires = 150 * time.Millisecond
			cfg.SecurityClient = &SecurityParameters{Algorithm: "hmac-sha-1-96", Encryption: "aes-cbc", SPIClient: 256, SPIServer: 257, PortClient: 5070, PortServer: 5071}
			cfg.InstallSecurity = func(_ context.Context, a SecurityAgreement) (DialContextFunc, error) {
				mu.Lock()
				defer mu.Unlock()
				if len(listeners) > 0 {
					select {
					case <-listeners[len(listeners)-1].done:
					default:
						return nil, errors.New("new SAs installed before old listener closed")
					}
				}
				agreements = append(agreements, a)
				return (&net.Dialer{}).DialContext, nil
			}
			cfg.ListenTCP = func(_ context.Context, _, address string) (net.Listener, error) {
				a, err := net.ResolveTCPAddr("tcp", address)
				if err != nil {
					return nil, err
				}
				l := &reauthenticationListener{recoveryListener: recoveryListener{address: a, done: make(chan struct{})}, connections: make(chan net.Conn)}
				mu.Lock()
				listeners = append(listeners, l)
				mu.Unlock()
				return l, nil
			}
			cfg.OnState = func(ready bool, _ error) { states <- ready }
			received := make(chan string, 1)
			cfg.OnSMS = func(_, text string, _ time.Time) { received <- text }
			s, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if err = s.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			awaitIMSState(t, states, true)
			for range cycles - 1 {
				awaitIMSState(t, states, false)
				awaitIMSState(t, states, true)
			}
			mu.Lock()
			checkedAgreements := append([]SecurityAgreement(nil), agreements...)
			checkedListeners := append([]*reauthenticationListener(nil), listeners...)
			mu.Unlock()
			if len(checkedAgreements) != cycles || len(checkedListeners) != cycles {
				t.Fatalf("security/listener generations = %d/%d", len(checkedAgreements), len(checkedListeners))
			}
			last := checkedListeners[cycles-1]
			for i := 1; i < cycles; i++ {
				a, b := checkedAgreements[i-1].Client, checkedAgreements[i].Client
				if a.SPIClient == b.SPIClient || a.SPIServer == b.SPIServer || a.PortClient == b.PortClient || a.PortServer == b.PortServer {
					t.Fatal("reauthentication reused old security parameters")
				}
			}
			if !s.Ready() || s.Err() != nil || connects.Load() != cycles {
				t.Fatalf("reauthentication did not recover: %v", s.Err())
			}
			// Deliver a real SMS over the replacement protected server pair.
			client, peer := net.Pipe()
			defer peer.Close()
			defer client.Close()
			remote, _ := net.ResolveTCPAddr("tcp", protectedPeers[cycles-1].PCSCF[0])
			select {
			case last.connections <- &reauthenticationConn{Conn: client, remote: remote}:
			case <-time.After(time.Second):
				t.Fatal("replacement protected listener not accepting")
			}
			_ = peer.SetDeadline(time.Now().Add(time.Second))
			parts, err := smscodec.Encode([]byte("after reauthentication"), smscodec.AsDeliver, smscodec.From("+15551234"))
			if err != nil {
				t.Fatal(err)
			}
			tp, err := parts[0].MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			m := &message{Start: "MESSAGE sip:+15550100@ims.test SIP/2.0", Headers: map[string][]string{}, Body: append([]byte{1, 44, 0, 0, byte(len(tp))}, tp...)}
			m.set("via", "SIP/2.0/TCP "+remote.String()+";branch=z9hG4bKreauth")
			m.set("from", "<sip:smsc@ims.test>;tag=network")
			m.set("to", "<sip:+15550100@ims.test>")
			m.set("call-id", "sms-after-reauthentication")
			m.set("cseq", "1 MESSAGE")
			m.set("content-type", "application/vnd.3gpp.sms")
			if err = sendPeer(peer, m); err != nil {
				t.Fatal(err)
			}
			if reply, err := readMessage(bufio.NewReader(peer)); err != nil || reply.status() != 200 {
				t.Fatalf("inbound SMS reply = %v, %v", reply, err)
			}
			select {
			case text := <-received:
				if text != "after reauthentication" {
					t.Fatalf("received SMS = %q", text)
				}
			case <-time.After(time.Second):
				t.Fatal("SMS not received after reauthentication")
			}
			s.serverFailure(nil, checkedListeners[0], errors.New("late old-listener failure"))
			if !s.Ready() {
				t.Fatal("stale listener revoked the replacement registration")
			}
		})
	}
}
