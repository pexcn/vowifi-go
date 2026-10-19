package swu

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	vc "github.com/iniwex5/vowifi-go/engine/crypto"
	"github.com/iniwex5/vowifi-go/engine/ikev2"
	"github.com/iniwex5/vowifi-go/engine/ipsec"
)

func startRekeyPeer(t *testing.T, lifetime time.Duration) (*mockPeer, *Session) {
	t.Helper()
	p := newMockPeer(t, "")
	p.cfg.Timeout = 20 * time.Millisecond
	if lifetime > 0 {
		p.cfg.ChildLifetime = lifetime
		p.cfg.NATKeepalive = 5 * time.Millisecond
	}
	p.start()
	s, err := Start(context.Background(), p.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	p.check(t)
	return p, s
}

func readRekeyControl(t *testing.T, p *mockPeer) (ikev2.Message, []byte) {
	t.Helper()
	for {
		b, err := p.read(p.natt, false)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(b, []byte{255}) {
			continue
		}
		if len(b) < 4 || binary.BigEndian.Uint32(b) != 0 {
			t.Fatalf("expected IKE, got %x", b)
		}
		m, err := ikev2.Open(b[4:], p.keys.SKei, p.keys.SKai, vc.HMACSHA256128)
		if err != nil {
			t.Fatal(err)
		}
		return m, b[4:]
	}
}

func sendRekeyRequest(t *testing.T, p *mockPeer, id uint32, exchange byte, ps []ikev2.Payload) []byte {
	t.Helper()
	h := ikev2.Header{InitiatorSPI: p.spii, ResponderSPI: p.spir, Exchange: exchange, MessageID: id}
	b, err := ikev2.Seal(h, ps, p.keys.SKer, p.keys.SKar, vc.HMACSHA256128, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.send(p.natt, b, true); err != nil {
		t.Fatal(err)
	}
	return b
}

func requirePayload(t *testing.T, m ikev2.Message, typ byte) []byte {
	t.Helper()
	b, err := ikev2.One(m.Payloads, typ)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Derive the peer's directions directly from RFC 7296 2.17, independently
// of the session's rekey helper. 'peerInitiator' is the CREATE_CHILD_SA role.
func peerRekeySAs(t *testing.T, p *mockPeer, localSPI, peerSPI uint32, ni, nr, shared []byte, peerInitiator bool) (*ipsec.SA, *ipsec.SA) {
	t.Helper()
	seed := append(append(append([]byte{}, shared...), ni...), nr...)
	key, err := vc.PRFSHA256.Plus(p.keys.SKd, seed, 96)
	if err != nil {
		t.Fatal(err)
	}
	to, from := key[48:], key[:48]
	if peerInitiator {
		to, from = from, to
	}
	out, err := ipsec.NewSA(ipsec.SAConfig{SPI: localSPI, EncryptionKey: to[:16], IntegrityKey: to[16:], Integrity: vc.HMACSHA256128})
	if err != nil {
		t.Fatal(err)
	}
	in, err := ipsec.NewSA(ipsec.SAConfig{SPI: peerSPI, EncryptionKey: from[:16], IntegrityKey: from[16:], Integrity: vc.HMACSHA256128})
	if err != nil {
		t.Fatal(err)
	}
	return out, in
}

func sendTunnelPacket(t *testing.T, p *mockPeer, sa *ipsec.SA) []byte {
	t.Helper()
	packet := inner([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2})
	wire, err := sa.Seal(packet, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.send(p.natt, wire, false); err != nil {
		t.Fatal(err)
	}
	return wire
}

func receiveTunnelPacket(t *testing.T, s *Session) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	packet, err := s.ReadPacket(ctx)
	if err != nil || !bytes.Equal(packet, inner([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2})) {
		t.Fatalf("tunnel packet: %x %v", packet, err)
	}
}

func checkOutboundRekey(t *testing.T, p *mockPeer, s *Session, fromClient *ipsec.SA) {
	t.Helper()
	packet := inner([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1})
	if err := s.WritePacket(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	for {
		wire, err := p.read(p.natt, false)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(wire, []byte{255}) {
			continue
		}
		got, next, err := fromClient.Open(wire)
		if err != nil || next != 4 || !bytes.Equal(got, packet) {
			t.Fatalf("outbound new SA: %x %d %v", got, next, err)
		}
		return
	}
}

func TestChildRekeyInitiatedSwitchOverlapRetransmitAndDelete(t *testing.T) {
	p, s := startRekeyPeer(t, 0)
	oldLocal, oldPeer := s.in.SPI(), s.out.SPI()
	done := make(chan error, 1)
	go func() { done <- s.rekeyChild(s.ctx) }()
	request, wire := readRekeyControl(t, p)
	if request.Header.Exchange != ikev2.CreateChildSA {
		t.Fatal("not CREATE_CHILD_SA")
	}
	_, retry := readRekeyControl(t, p) // Lose the first request: nonce, IV and ID must remain identical.
	if !bytes.Equal(wire, retry) {
		t.Fatal("rekey retransmission changed")
	}
	notify := requirePayload(t, request, ikev2.Notify)
	if !bytes.Equal(notify, binary.BigEndian.AppendUint32([]byte{3, 4, 0x40, 9}, oldLocal)) {
		t.Fatalf("REKEY_SA must identify local inbound SPI: %x", notify)
	}
	proposal, err := ikev2.ParseProposals(requirePayload(t, request, ikev2.SA))
	if err != nil || len(proposal) != 1 {
		t.Fatal(err)
	}
	localSPI := binary.BigEndian.Uint32(proposal[0].SPI)
	peerSPI := uint32(0x01020304)
	proposal[0].SPI = binary.BigEndian.AppendUint32(nil, peerSPI)
	sa, _ := ikev2.EncodeProposals(proposal)
	ni, nr := requirePayload(t, request, ikev2.Nonce), bytes.Repeat([]byte{0xa5}, 32)
	if bytes.Equal(ni, p.ni) {
		t.Fatal("reused IKE_AUTH nonce")
	}
	tsi, tsr := requirePayload(t, request, ikev2.TSi), requirePayload(t, request, ikev2.TSr)
	if err = p.response(request.Header, []ikev2.Payload{{Type: ikev2.SA, Data: sa}, {Type: ikev2.Nonce, Data: nr}, {Type: ikev2.TSi, Data: tsi}, {Type: ikev2.TSr, Data: tsr}}); err != nil {
		t.Fatal(err)
	}
	deletion, _ := readRekeyControl(t, p)
	if deletion.Header.Exchange != ikev2.Informational || !bytes.Equal(requirePayload(t, deletion, ikev2.Delete), binary.BigEndian.AppendUint32([]byte{3, 4, 0, 1}, oldLocal)) {
		t.Fatal("wrong old-SA Delete direction")
	}
	toClient, fromClient := peerRekeySAs(t, p, localSPI, peerSPI, ni, nr, nil, false)
	sendTunnelPacket(t, p, p.toClient)
	receiveTunnelPacket(t, s)
	sendTunnelPacket(t, p, toClient)
	receiveTunnelPacket(t, s)
	checkOutboundRekey(t, p, s, fromClient)
	if err = p.response(deletion.Header, []ikev2.Payload{childDelete(oldPeer)}); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if s.inboundChild(oldLocal) != nil || s.inboundChild(localSPI) == nil {
		t.Fatal("wrong association retired")
	}
	select {
	case <-s.Done():
		t.Fatal(s.Err())
	default:
	}
	if got := s.Configuration(); len(got.PCSCF) != 1 || got.PCSCF[0].String() != "10.0.0.1" {
		t.Fatal("lost tunnel configuration")
	}
}

func TestPeerChildRekeyRolesReplayAndOldDelete(t *testing.T) {
	for _, pfs := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-pfs", true: "dh14"}[pfs], func(t *testing.T) {
			p, s := startRekeyPeer(t, 0)
			oldLocal, oldPeer := s.in.SPI(), s.out.SPI()
			peerSPI := uint32(0x05060708)
			proposal := s.espProposal(peerSPI)
			ni := bytes.Repeat([]byte{0x3c}, 32)
			var dh *vc.MODP
			if pfs {
				var err error
				dh, err = vc.NewMODP(14, nil)
				if err != nil {
					t.Fatal(err)
				}
				proposal.Transforms = append(proposal.Transforms, ikev2.Transform{Type: 4, ID: 14})
			}
			sa, _ := ikev2.EncodeProposals([]ikev2.Proposal{proposal})
			ps := []ikev2.Payload{{Type: ikev2.SA, Data: sa}, {Type: ikev2.Nonce, Data: ni}, childNotify(rekeySANotify, oldPeer)}
			ps = append(ps, s.rekeySelectors(false)...)
			if pfs {
				ps = append(ps, ikev2.Payload{Type: ikev2.KE, Data: append([]byte{0, 14, 0, 0}, dh.Public...)})
			}
			request := sendRekeyRequest(t, p, 0, ikev2.CreateChildSA, ps)
			response, responseWire := readRekeyControl(t, p)
			proposalReply, err := ikev2.ParseProposals(requirePayload(t, response, ikev2.SA))
			if err != nil || len(proposalReply) != 1 {
				t.Fatal(err)
			}
			localSPI := binary.BigEndian.Uint32(proposalReply[0].SPI)
			nr := requirePayload(t, response, ikev2.Nonce)
			var shared []byte
			if pfs {
				ke := requirePayload(t, response, ikev2.KE)
				shared, err = dh.Shared(ke[4:])
				if err != nil {
					t.Fatal(err)
				}
			}
			toClient, fromClient := peerRekeySAs(t, p, localSPI, peerSPI, ni, nr, shared, true)
			if err = p.send(p.natt, request, true); err != nil {
				t.Fatal(err)
			}
			_, duplicate := readRekeyControl(t, p)
			if !bytes.Equal(responseWire, duplicate) {
				t.Fatal("duplicate peer rekey generated a new reply/SA")
			}
			oldWire := sendTunnelPacket(t, p, p.toClient)
			receiveTunnelPacket(t, s)
			if err = p.send(p.natt, oldWire, false); err != nil {
				t.Fatal(err)
			} // Replay must not advance the receive queue.
			sendTunnelPacket(t, p, toClient)
			receiveTunnelPacket(t, s)
			checkOutboundRekey(t, p, s, fromClient)
			// Peer deletes its old inbound SA, not ours. An unknown SPI is harmless.
			sendRekeyRequest(t, p, 1, ikev2.Informational, []ikev2.Payload{childDelete(0x12345678)})
			unknown, _ := readRekeyControl(t, p)
			if len(unknown.Payloads) != 0 {
				t.Fatal("answered unknown SPI with active Delete")
			}
			sendRekeyRequest(t, p, 2, ikev2.Informational, []ikev2.Payload{childDelete(oldPeer)})
			deleted, _ := readRekeyControl(t, p)
			if !bytes.Equal(requirePayload(t, deleted, ikev2.Delete), binary.BigEndian.AppendUint32([]byte{3, 4, 0, 1}, oldLocal)) {
				t.Fatal("wrong Delete reply")
			}
			if s.inboundChild(oldLocal) != nil || s.inboundChild(localSPI) == nil {
				t.Fatal("old Delete removed active SA")
			}
			sendTunnelPacket(t, p, toClient)
			receiveTunnelPacket(t, s)
			activePeerSPI := peerSPI
			if pfs {
				activePeerSPI = completeInheritedPFSRekey(t, p, s)
			}
			// Deleting the active SA still ends this session.
			sendRekeyRequest(t, p, 3, ikev2.Informational, []ikev2.Payload{childDelete(activePeerSPI)})
			readRekeyControl(t, p)
			select {
			case <-s.Done():
			case <-time.After(time.Second):
				t.Fatal("active Delete did not close")
			}
		})
	}
}

func TestChildRekeyFailureKeepsOldKeysAndCancels(t *testing.T) {
	for _, mode := range []string{"rejected", "bad-selector", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			p, s := startRekeyPeer(t, 0)
			oldLocal := s.in.SPI()
			ctx, cancel := context.WithCancel(s.ctx)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- s.rekeyChild(ctx) }()
			request, _ := readRekeyControl(t, p)
			switch mode {
			case "cancel":
				cancel()
			case "rejected":
				if err := p.response(request.Header, []ikev2.Payload{ikev2.Notification(14, nil)}); err != nil {
					t.Fatal(err)
				}
			case "bad-selector":
				proposal, _ := ikev2.ParseProposals(requirePayload(t, request, ikev2.SA))
				proposal[0].SPI = []byte{1, 2, 3, 4}
				sa, _ := ikev2.EncodeProposals(proposal)
				if err := p.response(request.Header, []ikev2.Payload{{Type: ikev2.SA, Data: sa}, {Type: ikev2.Nonce, Data: bytes.Repeat([]byte{0x55}, 32)}, {Type: ikev2.TSi, Data: requirePayload(t, request, ikev2.TSr)}, {Type: ikev2.TSr, Data: requirePayload(t, request, ikev2.TSr)}}); err != nil {
					t.Fatal(err)
				}
			}
			if err := <-done; err == nil {
				t.Fatal("failed rekey accepted")
			} else if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if s.inboundChild(oldLocal) == nil {
				t.Fatal("failure removed old SA")
			}
			sendTunnelPacket(t, p, p.toClient)
			receiveTunnelPacket(t, s)
		})
	}
}

func TestPeerChildRekeyCollisionAndInvalidRequests(t *testing.T) {
	p, s := startRekeyPeer(t, 0)
	oldLocal := s.in.SPI()
	sa, _ := ikev2.EncodeProposals([]ikev2.Proposal{s.espProposal(0x11223344)})
	valid := func() []ikev2.Payload {
		ps := []ikev2.Payload{{Type: ikev2.SA, Data: sa}, {Type: ikev2.Nonce, Data: bytes.Repeat([]byte{9}, 32)}, childNotify(rekeySANotify, s.out.SPI())}
		return append(ps, s.rekeySelectors(false)...)
	}
	for id, mode := range []string{"collision", "unknown", "missing-nonce", "changed-selector", "duplicate-notify", "zero-spi"} {
		ps := valid()
		code := uint16(7)
		switch mode {
		case "collision":
			s.rekeyMu.Lock()
			code = temporaryFailureNotify
		case "unknown":
			ps[2] = childNotify(rekeySANotify, 0x99999999)
			code = childNotFoundNotify
		case "missing-nonce":
			ps[1].Data = nil
		case "changed-selector":
			ps[3].Data = ps[4].Data
			code = 38
		case "duplicate-notify":
			ps = append(ps, ps[2])
		case "zero-spi":
			ps[2] = childNotify(rekeySANotify, 0)
		}
		sendRekeyRequest(t, p, uint32(id), ikev2.CreateChildSA, ps)
		response, _ := readRekeyControl(t, p)
		if mode == "collision" {
			s.rekeyMu.Unlock()
		}
		got, _, err := ikev2.ParseNotification(requirePayload(t, response, ikev2.Notify))
		if err != nil || got != code {
			t.Fatalf("%s: notify %d, want %d (%v)", mode, got, code, err)
		}
		if s.inboundChild(oldLocal) == nil {
			t.Fatal("invalid request removed old SA")
		}
	}
	sendTunnelPacket(t, p, p.toClient)
	receiveTunnelPacket(t, s)
}

func TestChildRekeyOldDeleteTimeoutAndResourceBound(t *testing.T) {
	p, s := startRekeyPeer(t, 0)
	oldLocal := s.in.SPI()
	done := make(chan error, 1)
	go func() { done <- s.rekeyChild(s.ctx) }()
	request, _ := readRekeyControl(t, p)
	proposal, _ := ikev2.ParseProposals(requirePayload(t, request, ikev2.SA))
	localSPI := binary.BigEndian.Uint32(proposal[0].SPI)
	proposal[0].SPI = []byte{1, 2, 3, 4}
	sa, _ := ikev2.EncodeProposals(proposal)
	ni, nr := requirePayload(t, request, ikev2.Nonce), bytes.Repeat([]byte{8}, 32)
	if err := p.response(request.Header, []ikev2.Payload{{Type: ikev2.SA, Data: sa}, {Type: ikev2.Nonce, Data: nr}, {Type: ikev2.TSi, Data: requirePayload(t, request, ikev2.TSi)}, {Type: ikev2.TSr, Data: requirePayload(t, request, ikev2.TSr)}}); err != nil {
		t.Fatal(err)
	}
	_, deleteWire := readRekeyControl(t, p)
	_, retry := readRekeyControl(t, p)
	if !bytes.Equal(deleteWire, retry) {
		t.Fatal("Delete retransmission changed")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	toClient, fromClient := peerRekeySAs(t, p, localSPI, 0x01020304, ni, nr, nil, false)
	sendTunnelPacket(t, p, toClient)
	receiveTunnelPacket(t, s)
	checkOutboundRekey(t, p, s, fromClient)
	if s.inboundChild(oldLocal) == nil {
		t.Fatal("old inbound SA dropped before overlap timeout")
	}
	s.childMu.Lock()
	old := s.retiredChildren[oldLocal]
	old.expires = time.Now().Add(-time.Second)
	s.retiredChildren[oldLocal] = old
	s.childMu.Unlock()
	if s.inboundChild(oldLocal) != nil {
		t.Fatal("expired old inbound SA retained")
	}
	s.childMu.Lock()
	for i := uint32(1); i <= maxRetiredChildren; i++ {
		s.retiredChildren[i] = retiredChild{in: s.in, peerSPI: i, expires: time.Now().Add(time.Minute)}
	}
	s.childMu.Unlock()
	ps, pair := s.preparePeerChild(nil)
	code, _, _ := ikev2.ParseNotification(ps[0].Data)
	if pair != nil || code != temporaryFailureNotify {
		t.Fatal("unbounded old-SA accumulation")
	}
}

func TestChildRekeyTimerAndKeepaliveContinue(t *testing.T) {
	p, s := startRekeyPeer(t, 250*time.Millisecond)
	request, _ := readRekeyControl(t, p)
	if request.Header.Exchange != ikev2.CreateChildSA {
		t.Fatal("lifetime did not initiate rekey")
	}
	// Delay the reply until a retransmission; keepalive must still run.
	keepalives := 0
	for {
		wire, err := p.read(p.natt, false)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(wire, []byte{255}) {
			keepalives++
			continue
		}
		break
	}
	if keepalives == 0 {
		t.Fatal("rekey blocked NAT keepalive")
	}
	// No peer reply: the configured hard lifetime still bounds this SA.
	select {
	case <-s.Done():
	case <-time.After(time.Second):
		t.Fatal("rekey failure exceeded hard lifetime")
	}
	if !errors.Is(s.Err(), ErrRekeyRequired) {
		t.Fatal(s.Err())
	}
}

func completeInheritedPFSRekey(t *testing.T, p *mockPeer, s *Session) uint32 {
	t.Helper()
	oldPeer := s.out.SPI()
	done := make(chan error, 1)
	go func() { done <- s.rekeyChild(s.ctx) }()
	request, _ := readRekeyControl(t, p)
	proposals, err := ikev2.ParseProposals(requirePayload(t, request, ikev2.SA))
	if err != nil {
		t.Fatal(err)
	}
	foundDH := false
	for _, transform := range proposals[0].Transforms {
		if transform.Type == 4 && transform.ID == 14 {
			foundDH = true
		}
	}
	if !foundDH {
		t.Fatal("local rekey dropped peer-negotiated PFS")
	}
	localSPI := binary.BigEndian.Uint32(proposals[0].SPI)
	peerSPI := uint32(0x61626364)
	proposals[0].SPI = binary.BigEndian.AppendUint32(nil, peerSPI)
	sa, _ := ikev2.EncodeProposals(proposals)
	dh, err := vc.NewMODP(14, nil)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := dh.Shared(requirePayload(t, request, ikev2.KE)[4:])
	if err != nil {
		t.Fatal(err)
	}
	ni, nr := requirePayload(t, request, ikev2.Nonce), bytes.Repeat([]byte{0x46}, 32)
	ps := []ikev2.Payload{{Type: ikev2.SA, Data: sa}, {Type: ikev2.Nonce, Data: nr}, {Type: ikev2.KE, Data: append([]byte{0, 14, 0, 0}, dh.Public...)}, {Type: ikev2.TSi, Data: requirePayload(t, request, ikev2.TSi)}, {Type: ikev2.TSr, Data: requirePayload(t, request, ikev2.TSr)}}
	if err = p.response(request.Header, ps); err != nil {
		t.Fatal(err)
	}
	deletion, _ := readRekeyControl(t, p)
	if deletion.Header.Exchange != ikev2.Informational {
		t.Fatal("PFS rekey did not switch SA")
	}
	if err = p.response(deletion.Header, []ikev2.Payload{childDelete(oldPeer)}); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	toClient, fromClient := peerRekeySAs(t, p, localSPI, peerSPI, ni, nr, shared, false)
	sendTunnelPacket(t, p, toClient)
	receiveTunnelPacket(t, s)
	checkOutboundRekey(t, p, s, fromClient)
	return peerSPI
}
