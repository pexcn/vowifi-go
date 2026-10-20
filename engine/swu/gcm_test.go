package swu

import (
	"bytes"
	vc "github.com/iniwex5/vowifi-go/engine/crypto"
	"github.com/iniwex5/vowifi-go/engine/ikev2"
	"testing"
	"time"
)

func TestGCMFullHandshakeRekeysAndRoleFlip(t *testing.T) {
	for _, peerInitiated := range []bool{false, true} {
		t.Run(map[bool]string{false: "local", true: "peer"}[peerInitiated], func(t *testing.T) {
			p := newMockPeer(t, "fragment")
			p.cfg.Encryption = vc.AESGCM16
			p.cfg.IKEFragmentMTU = 576
			p.cfg.APN = string(bytes.Repeat([]byte{'a'}, 1800)) + ".invalid"
			p.start()
			s, err := Start(t.Context(), p.cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			p.check(t)
			if s.integ != 0 || s.encLen != 20 || p.authFragments < 2 || p.responseFragments < 2 {
				t.Fatal("GCM or SKF not exercised")
			}
			sendTunnelPacket(t, p, p.toClient)
			receiveTunnelPacket(t, s)
			checkOutboundRekey(t, p, s, p.fromClient)
			// Child rekey under GCM, including inherited DH, reuses existing fixtures.
			completeInheritedPFSNotRequired(t, p, s)
			old := originalPeerIKE(p)
			var next rekeyPeerIKE
			if peerInitiated {
				next, _, _ = completePeerIKERekey(t, p, s, old)
			} else {
				next = completeLocalIKERekey(t, p, s, old, true)
			}
			checkIKECountersAndChild(t, p, s, next)
		})
	}
}
func completeInheritedPFSNotRequired(t *testing.T, p *mockPeer, s *Session) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- s.rekeyChild(s.ctx) }()
	req, _ := readRekeyControl(t, p)
	proposals, err := ikev2.ParseProposals(requirePayload(t, req, ikev2.SA))
	if err != nil {
		t.Fatal(err)
	}
	local := uint32(proposals[0].SPI[0])<<24 | uint32(proposals[0].SPI[1])<<16 | uint32(proposals[0].SPI[2])<<8 | uint32(proposals[0].SPI[3])
	peer := uint32(0x12344321)
	proposals[0].SPI = []byte{0x12, 0x34, 0x43, 0x21}
	sa, _ := ikev2.EncodeProposals(proposals)
	ni, nr := requirePayload(t, req, ikev2.Nonce), bytes.Repeat([]byte{0x63}, 32)
	ps := []ikev2.Payload{{Type: ikev2.SA, Data: sa}, {Type: ikev2.Nonce, Data: nr}, {Type: ikev2.TSi, Data: requirePayload(t, req, ikev2.TSi)}, {Type: ikev2.TSr, Data: requirePayload(t, req, ikev2.TSr)}}
	if err = p.response(req.Header, ps); err != nil {
		t.Fatal(err)
	}
	del, _ := readRekeyControl(t, p)
	if err = p.response(del.Header, nil); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	p.toClient, p.fromClient = peerRekeySAs(t, p, local, peer, ni, nr, nil, false)
	sendTunnelPacket(t, p, p.toClient)
	receiveTunnelPacket(t, s)
	checkOutboundRekey(t, p, s, p.fromClient)
}
func TestGCMFragmentPMTUFlight(t *testing.T) {
	s := &Session{cfg: Config{IKEFragmentPMTU: true}, fragmentation: true, encryption: vc.AESGCM16}
	key := make([]byte, 20)
	h := ikev2.Header{InitiatorSPI: 1, ResponderSPI: 2, Exchange: ikev2.IKEAuth, MessageID: 7}
	f, err := s.newIKEFlight(h, []ikev2.Payload{{Type: ikev2.CERT, Data: make([]byte, 3500)}}, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	count := len(f.packets)
	ids := map[string]bool{}
	for {
		var fb fragmentBuffer
		for _, b := range f.packets {
			if len(b) > f.limit {
				t.Fatal("probe limit")
			}
			frag, err := ikev2.OpenFragmentProtected(b, key, nil, s.protection())
			if err != nil {
				t.Fatal(err)
			}
			if frag.Header.MessageID != 7 {
				t.Fatal("probe changed ID")
			}
			if ids[string(b[36:44])] {
				t.Fatal("probe reused nonce")
			}
			ids[string(b[36:44])] = true
			_, _, err = fb.add(frag, time.Now())
			if err != nil {
				t.Fatal(err)
			}
		}
		if !f.nextProbe() {
			break
		}
		if len(f.packets) <= count {
			t.Fatal("probe did not increase total")
		}
		count = len(f.packets)
	}
	if f.limit != 576-52 {
		t.Fatal("did not reach minimum probe")
	}
}
