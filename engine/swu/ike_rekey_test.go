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
)

type rekeyPeerIKE struct {
	spii, spir uint64
	keys       vc.IKEKeys
	initiator  bool
}

func originalPeerIKE(p *mockPeer) rekeyPeerIKE { return rekeyPeerIKE{p.spii, p.spir, p.keys, false} }
func readIKEFromClient(t *testing.T, p *mockPeer, peer rekeyPeerIKE) (ikev2.Message, []byte) {
	t.Helper()
	enc, auth := peer.keys.SKei, peer.keys.SKai
	if peer.initiator {
		enc, auth = peer.keys.SKer, peer.keys.SKar
	}
	for {
		b, err := p.read(p.natt, false)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(b, []byte{255}) {
			continue
		}
		if len(b) < 4 || binary.BigEndian.Uint32(b) != 0 {
			t.Fatalf("expected IKE: %x", b)
		}
		m, err := ikev2.Open(b[4:], enc, auth, vc.HMACSHA256128)
		if err != nil {
			t.Fatal(err)
		}
		if m.Header.InitiatorSPI != peer.spii || m.Header.ResponderSPI != peer.spir {
			t.Fatal("wrong IKE SA header")
		}
		expected := byte(ikev2.FlagInitiator)
		if peer.initiator {
			expected = 0
		}
		if m.Header.Flags&ikev2.FlagInitiator != expected {
			t.Fatal("wrong initiator flag after IKE rekey")
		}
		return m, b[4:]
	}
}
func sendIKEFromPeer(t *testing.T, p *mockPeer, peer rekeyPeerIKE, id uint32, exchange byte, response bool, ps []ikev2.Payload) []byte {
	t.Helper()
	enc, auth := peer.keys.SKer, peer.keys.SKar
	flags := byte(0)
	if peer.initiator {
		enc, auth = peer.keys.SKei, peer.keys.SKai
		flags |= ikev2.FlagInitiator
	}
	if response {
		flags |= ikev2.FlagResponse
	}
	h := ikev2.Header{InitiatorSPI: peer.spii, ResponderSPI: peer.spir, Exchange: exchange, Flags: flags, MessageID: id}
	b, err := ikev2.Seal(h, ps, enc, auth, vc.HMACSHA256128, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.send(p.natt, b, true); err != nil {
		t.Fatal(err)
	}
	return b
}
func ikeDeletePayload() []ikev2.Payload {
	return []ikev2.Payload{{Type: ikev2.Delete, Data: []byte{1, 0, 0, 0}}}
}

func completeLocalIKERekey(t *testing.T, p *mockPeer, s *Session, old rekeyPeerIKE, loseRequest bool) rekeyPeerIKE {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- s.rekeyIKE(s.ctx) }()
	request, wire := readIKEFromClient(t, p, old)
	if loseRequest {
		_, retry := readIKEFromClient(t, p, old)
		if !bytes.Equal(wire, retry) {
			t.Fatal("IKE rekey retransmit changed")
		}
	}
	if request.Header.Exchange != ikev2.CreateChildSA {
		t.Fatal("not CREATE_CHILD_SA")
	}
	proposal, err := ikev2.ParseProposals(requirePayload(t, request, ikev2.SA))
	if err != nil || len(proposal) != 1 {
		t.Fatal(err)
	}
	if proposal[0].Protocol != 1 || len(proposal[0].SPI) != 8 {
		t.Fatal("wrong IKE rekey proposal")
	}
	spii := binary.BigEndian.Uint64(proposal[0].SPI)
	spir := old.spir + 0x100
	proposal[0].SPI = binary.BigEndian.AppendUint64(nil, spir)
	sa, _ := ikev2.EncodeProposals(proposal)
	dh, err := vc.NewMODP(14, nil)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := dh.Shared(requirePayload(t, request, ikev2.KE)[4:])
	if err != nil {
		t.Fatal(err)
	}
	ni, nr := requirePayload(t, request, ikev2.Nonce), bytes.Repeat([]byte{0x72}, 32)
	keys, err := vc.DeriveIKERekey(vc.PRFSHA256, vc.HMACSHA256128, 16, old.keys.SKd, ni, nr, shared, spii, spir)
	if err != nil {
		t.Fatal(err)
	}
	ps := []ikev2.Payload{{Type: ikev2.SA, Data: sa}, {Type: ikev2.Nonce, Data: nr}, {Type: ikev2.KE, Data: append([]byte{0, 14, 0, 0}, dh.Public...)}}
	replyWire := sendIKEFromPeer(t, p, old, request.Header.MessageID, ikev2.CreateChildSA, true, ps)
	deletion, _ := readIKEFromClient(t, p, old)
	for deletion.Header.Exchange == ikev2.CreateChildSA && deletion.Header.MessageID == request.Header.MessageID {
		if err := p.send(p.natt, replyWire, true); err != nil {
			t.Fatal(err)
		}
		deletion, _ = readIKEFromClient(t, p, old)
	}
	if deletion.Header.Exchange != ikev2.Informational || !bytes.Equal(requirePayload(t, deletion, ikev2.Delete), []byte{1, 0, 0, 0}) {
		t.Fatal("old IKE SA not deleted using old keys")
	}
	sendIKEFromPeer(t, p, old, deletion.Header.MessageID, ikev2.Informational, true, nil)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	return rekeyPeerIKE{spii, spir, keys, false}
}

func completePeerIKERekey(t *testing.T, p *mockPeer, s *Session, old rekeyPeerIKE) (rekeyPeerIKE, []byte, []byte) {
	t.Helper()
	dh, err := vc.NewMODP(14, nil)
	if err != nil {
		t.Fatal(err)
	}
	spii := uint64(0x9988776655443322)
	proposal := s.ikeRekeyProposal(spii)
	proposal.Number = 2
	unsupported := s.ikeRekeyProposal(spii)
	unsupported.Transforms[0].ID = 99
	sa, _ := ikev2.EncodeProposals([]ikev2.Proposal{unsupported, proposal})
	ni := bytes.Repeat([]byte{0x52}, 32)
	ps := []ikev2.Payload{{Type: ikev2.SA, Data: sa}, {Type: ikev2.Nonce, Data: ni}, {Type: ikev2.KE, Data: append([]byte{0, 14, 0, 0}, dh.Public...)}}
	request := sendIKEFromPeer(t, p, old, 0, ikev2.CreateChildSA, false, ps)
	response, responseWire := readIKEFromClient(t, p, old)
	proposalReply, err := ikev2.ParseProposals(requirePayload(t, response, ikev2.SA))
	if err != nil || len(proposalReply) != 1 {
		t.Fatal(err)
	}
	if proposalReply[0].Number != 2 {
		t.Fatal("peer IKE proposal number was not preserved")
	}
	spir := binary.BigEndian.Uint64(proposalReply[0].SPI)
	nr := requirePayload(t, response, ikev2.Nonce)
	shared, err := dh.Shared(requirePayload(t, response, ikev2.KE)[4:])
	if err != nil {
		t.Fatal(err)
	}
	keys, err := vc.DeriveIKERekey(vc.PRFSHA256, vc.HMACSHA256128, 16, old.keys.SKd, ni, nr, shared, spii, spir)
	if err != nil {
		t.Fatal(err)
	}
	return rekeyPeerIKE{spii, spir, keys, true}, request, responseWire
}

func checkIKECountersAndChild(t *testing.T, p *mockPeer, s *Session, peer rekeyPeerIKE) {
	t.Helper()
	// The first outbound and peer-initiated requests on the new IKE SA each
	// use message ID zero, regardless of the original IKE_AUTH direction.
	done := make(chan error, 1)
	go func() { done <- s.controlExchange(nil) }()
	request, _ := readIKEFromClient(t, p, peer)
	if request.Header.MessageID != 0 || request.Header.Exchange != ikev2.Informational {
		t.Fatal("new IKE counter did not reset")
	}
	sendIKEFromPeer(t, p, peer, 0, ikev2.Informational, true, nil)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	sendIKEFromPeer(t, p, peer, 0, ikev2.Informational, false, nil)
	response, _ := readIKEFromClient(t, p, peer)
	if response.Header.MessageID != 0 || response.Header.Flags&ikev2.FlagResponse == 0 {
		t.Fatal("new inbound window did not reset")
	}
	sendTunnelPacket(t, p, p.toClient)
	receiveTunnelPacket(t, s)
	checkOutboundRekey(t, p, s, p.fromClient)
}

func TestIKERekeyLocalPreservesChildAndResetsWindows(t *testing.T) {
	p, s := startRekeyPeer(t, 0)
	old := originalPeerIKE(p)
	peer := completeLocalIKERekey(t, p, s, old, true)
	if bytes.Equal(old.keys.SKd, peer.keys.SKd) {
		t.Fatal("IKE keys unchanged")
	}
	checkIKECountersAndChild(t, p, s, peer)
}

func TestIKERekeyPeerRoleFlipOldRetransmissionAndChildKeys(t *testing.T) {
	p, s := startRekeyPeer(t, 0)
	old := originalPeerIKE(p)
	peer, request, responseWire := completePeerIKERekey(t, p, s, old)
	if err := p.send(p.natt, request, true); err != nil {
		t.Fatal(err)
	}
	_, retry := readIKEFromClient(t, p, old)
	if !bytes.Equal(responseWire, retry) {
		t.Fatal("lost IKE rekey response created another SA")
	}
	sendIKEFromPeer(t, p, old, 1, ikev2.Informational, false, ikeDeletePayload())
	deleted, deleteWire := readIKEFromClient(t, p, old)
	if len(deleted.Payloads) != 0 {
		t.Fatal("IKE Delete response should be empty")
	}
	checkIKECountersAndChild(t, p, s, peer)
	// A late old-SA Delete retransmission must use its cached old-key reply
	// and must not close the replacement IKE SA or any Child SA.
	s.ikeStateMu.RLock()
	cached := append([]byte{}, s.retiredIKE.lastPeerRequest...)
	s.ikeStateMu.RUnlock()
	if err := p.send(p.natt, cached, true); err != nil {
		t.Fatal(err)
	}
	_, again := readIKEFromClient(t, p, old)
	if !bytes.Equal(deleteWire, again) {
		t.Fatal("old IKE Delete retransmission changed")
	}
	// Child rekey after the role flip uses the replacement IKE SK_d, while
	// the Child exchange initiator remains the local endpoint.
	done := make(chan error, 1)
	go func() { done <- s.rekeyChild(s.ctx) }()
	childRequest, _ := readIKEFromClient(t, p, peer)
	proposals, err := ikev2.ParseProposals(requirePayload(t, childRequest, ikev2.SA))
	if err != nil {
		t.Fatal(err)
	}
	localSPI := binary.BigEndian.Uint32(proposals[0].SPI)
	proposals[0].SPI = []byte{0x21, 0x22, 0x23, 0x24}
	sa, _ := ikev2.EncodeProposals(proposals)
	ni, nr := requirePayload(t, childRequest, ikev2.Nonce), bytes.Repeat([]byte{0x66}, 32)
	ps := []ikev2.Payload{{Type: ikev2.SA, Data: sa}, {Type: ikev2.Nonce, Data: nr}, {Type: ikev2.TSi, Data: requirePayload(t, childRequest, ikev2.TSi)}, {Type: ikev2.TSr, Data: requirePayload(t, childRequest, ikev2.TSr)}}
	sendIKEFromPeer(t, p, peer, childRequest.Header.MessageID, ikev2.CreateChildSA, true, ps)
	childDeleteRequest, _ := readIKEFromClient(t, p, peer)
	sendIKEFromPeer(t, p, peer, childDeleteRequest.Header.MessageID, ikev2.Informational, true, []ikev2.Payload{childDelete(0xdeadbeef)})
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	peerKeys := *p
	peerKeys.keys = peer.keys
	toClient, fromClient := peerRekeySAs(t, &peerKeys, localSPI, 0x21222324, ni, nr, nil, false)
	sendTunnelPacket(t, p, toClient)
	receiveTunnelPacket(t, s)
	checkOutboundRekey(t, p, s, fromClient)
	select {
	case <-s.Done():
		t.Fatal(s.Err())
	default:
	}
}

func TestIKERekeyFailuresAndRetiredLimit(t *testing.T) {
	for _, mode := range []string{"bad-key", "bad-nonce", "cancel", "collision"} {
		t.Run(mode, func(t *testing.T) {
			p, s := startRekeyPeer(t, 0)
			old := originalPeerIKE(p)
			if mode == "collision" {
				s.rekeyMu.Lock()
				sendIKEFromPeer(t, p, old, 0, ikev2.CreateChildSA, false, nil)
				response, _ := readIKEFromClient(t, p, old)
				s.rekeyMu.Unlock()
				code, _, _ := ikev2.ParseNotification(requirePayload(t, response, ikev2.Notify))
				if code != temporaryFailureNotify {
					t.Fatal(code)
				}
			} else {
				ctx, cancel := context.WithCancel(s.ctx)
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- s.rekeyIKE(ctx) }()
				request, _ := readIKEFromClient(t, p, old)
				if mode == "cancel" {
					cancel()
				} else {
					proposals, _ := ikev2.ParseProposals(requirePayload(t, request, ikev2.SA))
					proposals[0].SPI = binary.BigEndian.AppendUint64(nil, 0x1000000000000001)
					sa, _ := ikev2.EncodeProposals(proposals)
					nonce := bytes.Repeat([]byte{0x44}, 32)
					if mode == "bad-nonce" {
						nonce = nil
					}
					// MODP public value 1 must never produce keys or replace the SA.
					key := make([]byte, 256)
					key[255] = 1
					sendIKEFromPeer(t, p, old, request.Header.MessageID, ikev2.CreateChildSA, true, []ikev2.Payload{{Type: ikev2.SA, Data: sa}, {Type: ikev2.Nonce, Data: nonce}, {Type: ikev2.KE, Data: append([]byte{0, 14, 0, 0}, key...)}})
				}
				if err := <-done; err == nil {
					t.Fatal("invalid IKE rekey accepted")
				}
			}
			if s.currentIKE().spii != old.spii {
				t.Fatal("failure changed active IKE SA")
			}
			sendTunnelPacket(t, p, p.toClient)
			receiveTunnelPacket(t, s)
		})
	}
	p, s := startRekeyPeer(t, 0)
	old := originalPeerIKE(p)
	peer := completeLocalIKERekey(t, p, s, old, false)
	if err := s.rekeyIKE(s.ctx); err == nil {
		t.Fatal("unbounded retired IKE contexts")
	}
	checkIKECountersAndChild(t, p, s, peer)
	// Expiring the retained context makes another update possible, without
	// discarding the active association or accepting traffic on the old SPI.
	s.ikeStateMu.Lock()
	s.retiredIKEUntil = time.Now().Add(-time.Second)
	s.ikeStateMu.Unlock()
	if association, _ := s.ikeForHeader(ikev2.Header{InitiatorSPI: old.spii, ResponderSPI: old.spir}); association != nil {
		t.Fatal("expired IKE context accepted")
	}
	if !s.canRekeyIKE() {
		t.Fatal("retired context never expired")
	}
}

func TestIKERekeyTimerAndAuthenticationLifetime(t *testing.T) {
	for _, mode := range []string{"rekey", "reauth"} {
		t.Run(mode, func(t *testing.T) {
			p, s := startRekeyPeer(t, 0)
			if mode == "reauth" {
				// The deadline is immutable in production, set from IKE_AUTH.
				// Start a separate maintenance fixture to exercise its expiry.
				fixture := &Session{ctx: s.ctx, cancel: s.cancel, done: make(chan struct{}), authDeadline: time.Now().Add(10 * time.Millisecond), cfg: s.cfg, activeIKE: s.currentIKE(), ikeReset: make(chan struct{}, 1)}
				go fixture.maintainIKELifetime(time.Hour)
				select {
				case <-fixture.Done():
				case <-time.After(time.Second):
					t.Fatal("AUTH_LIFETIME was extended by rekey")
				}
				if !errors.Is(fixture.Err(), ErrRekeyRequired) {
					t.Fatal(fixture.Err())
				}
				return
			}
			go s.maintainIKELifetime(100 * time.Millisecond)
			request, _ := readIKEFromClient(t, p, originalPeerIKE(p))
			if request.Header.Exchange != ikev2.CreateChildSA {
				t.Fatal("IKE timer did not initiate update")
			}
			select {
			case <-s.Done():
			case <-time.After(time.Second):
				t.Fatal("failed IKE update exceeded lifetime")
			}
			if !errors.Is(s.Err(), ErrRekeyRequired) {
				t.Fatal(s.Err())
			}
		})
	}
}

func TestIKERekeyDoesNotExtendAuthenticatedLifetime(t *testing.T) {
	p := newMockPeer(t, "auth-lifetime")
	p.start()
	s, err := Start(context.Background(), p.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p.check(t)
	deadline := s.authDeadline
	if deadline.IsZero() || time.Until(deadline) < 29*time.Second || time.Until(deadline) > 30*time.Second {
		t.Fatal("AUTH_LIFETIME not applied")
	}
	peer := completeLocalIKERekey(t, p, s, originalPeerIKE(p), false)
	if !s.authDeadline.Equal(deadline) {
		t.Fatal("IKE rekey extended the authenticated lifetime")
	}
	checkIKECountersAndChild(t, p, s, peer)
}
