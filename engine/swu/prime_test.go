package swu

import (
	vc "github.com/iniwex5/vowifi-go/engine/crypto"
	"github.com/iniwex5/vowifi-go/engine/eap"
	"testing"
)

func TestPrimeGCMAuthenticationAndFinalCacheCommit(t *testing.T) {
	for _, mode := range []string{"fragment", "bad-final"} {
		t.Run(mode, func(t *testing.T) {
			p := newMockPeer(t, mode)
			p.cfg.RequireAKAPrime = true
			p.cfg.AKAPrimeNetworkName = "WLAN"
			p.cfg.NAI = "6" + p.cfg.NAI[1:]
			p.cfg.Encryption = vc.AESGCM16
			p.cfg.EAPReauth = &eap.ReauthContext{}
			p.start()
			s, err := Start(t.Context(), p.cfg)
			if mode == "bad-final" {
				if err == nil {
					t.Fatal("bad final AUTH accepted")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				sendTunnelPacket(t, p, p.toClient)
				receiveTunnelPacket(t, s)
				checkOutboundRekey(t, p, s, p.fromClient)
			}
			p.check(t)
			c := eap.Client{Identity: p.cfg.NAI, Reauth: p.cfg.EAPReauth, Binding: p.cfg.NAI + "\x00" + p.cfg.ServerName + "\x00WLAN"}
			defer c.Close()
			b, _ := (eap.Packet{Code: eap.Request, Identifier: 1, Type: eap.Identity}).Marshal()
			reply, _, err := c.Handle(t.Context(), b)
			if err != nil {
				t.Fatal(err)
			}
			id, err := eap.Parse(reply)
			if err != nil {
				t.Fatal(err)
			}
			want := "reauth@epdg.test"
			if mode == "bad-final" {
				want = p.cfg.NAI
			}
			if string(id.Data) != want {
				t.Fatalf("cache published across wrong authentication boundary: got %q want %q", id.Data, want)
			}
		})
	}
}
