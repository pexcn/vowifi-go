package swu

import (
	"bytes"
	"context"
	vc "github.com/iniwex5/vowifi-go/engine/crypto"
	"github.com/iniwex5/vowifi-go/engine/ikev2"
	"testing"
	"time"
)

func TestMOBIKENewPathAndRollback(t *testing.T) {
	for _, mode := range []string{"success", "bad-cookie", "missing-cookie"} {
		t.Run(mode, func(t *testing.T) {
			p := newMockPeer(t, "mobike")
			p.cfg.Encryption = vc.AESGCM16
			p.start()
			s, err := Start(t.Context(), p.cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			p.check(t)
			// NAT-T mock maps the logical port 4500 onto an ephemeral loopback port.
			s.RemoteAddr = p.natt.LocalAddr().String()
			old := *p.client
			done := make(chan error, 1)
			go func() { done <- s.UpdateAddresses(t.Context(), "") }()
			b, err := p.read(p.natt, true)
			if err != nil {
				t.Fatal(err)
			}
			candidate := *p.client
			if candidate.Port == old.Port {
				t.Fatal("migration did not use a new path")
			}
			m, err := ikev2.OpenProtected(b, p.keys.SKei, p.keys.SKai, p.protection())
			if err != nil {
				t.Fatal(err)
			}
			var cookie []byte
			for _, v := range m.Payloads {
				typ, d, e := ikev2.ParseNotification(v.Data)
				if e != nil {
					t.Fatal(e)
				}
				if typ == cookie2Notify {
					cookie = bytes.Clone(d)
				}
			}
			if len(cookie) != 16 {
				t.Fatal("missing path challenge")
			}
			reply := []ikev2.Payload{ikev2.Notification(cookie2Notify, cookie)}
			if mode == "bad-cookie" {
				reply = []ikev2.Payload{ikev2.Notification(cookie2Notify, make([]byte, 16))}
			}
			if mode == "missing-cookie" {
				reply = nil
			}
			if err = p.response(m.Header, reply); err != nil {
				t.Fatal(err)
			}
			if mode != "success" {
				replay, e := p.read(p.natt, true)
				if e != nil {
					t.Fatal(e)
				}
				if p.client.Port != old.Port || !bytes.Equal(replay, b) {
					t.Fatal("rollback lost path/transaction")
				}
				if e = p.response(m.Header, []ikev2.Payload{ikev2.Notification(cookie2Notify, cookie)}); e != nil {
					t.Fatal(e)
				}
				raw, e := p.read(p.natt, true)
				if e != nil {
					t.Fatal(e)
				}
				restore, e := ikev2.OpenProtected(raw, p.keys.SKei, p.keys.SKai, p.protection())
				if e != nil {
					t.Fatal(e)
				}
				var attrs []ikev2.Payload
				for _, v := range restore.Payloads {
					typ, _, _ := ikev2.ParseNotification(v.Data)
					if typ == cookie2Notify {
						attrs = append(attrs, v)
					}
				}
				if restore.Header.MessageID != m.Header.MessageID+1 {
					t.Fatal("rollback did not advance transaction")
				}
				if e = p.response(restore.Header, attrs); e != nil {
					t.Fatal(e)
				}
			}
			select {
			case err = <-done:
				if (err == nil) != (mode == "success") {
					t.Fatalf("migration result: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("migration hung")
			}
			if mode == "success" {
				p.client = &candidate
			} else {
				p.client = &old
			}
			sendTunnelPacket(t, p, p.toClient)
			receiveTunnelPacket(t, s)
			checkOutboundRekey(t, p, s, p.fromClient)
			if s.Err() != nil {
				t.Fatal(s.Err())
			}
		})
	}
}
func TestMOBIKECapabilityAndCancellation(t *testing.T) {
	p := newMockPeer(t, "")
	p.start()
	s, err := Start(t.Context(), p.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p.check(t)
	if err = s.UpdateAddresses(context.Background(), ""); err == nil {
		t.Fatal("migration without negotiation")
	}
	if _, err = s.peerMOBIKE([]ikev2.Payload{ikev2.Notification(updateAddressesNotify, nil)}); err == nil {
		t.Fatal("accepted responder address update")
	}
}
