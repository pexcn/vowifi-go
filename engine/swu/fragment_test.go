package swu

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	vc "github.com/iniwex5/vowifi-go/engine/crypto"
	"github.com/iniwex5/vowifi-go/engine/ikev2"
)

func TestFragmentDeidentifiedWireReplay(t *testing.T) {
	for _, tc := range []struct {
		file       string
		encryption vc.Encryption
	}{{"ike_fragment_replay.json", vc.AESCBC}, {"ike_gcm_fragment_replay.json", vc.AESGCM16}} {
		t.Run(tc.file, func(t *testing.T) {
			var fixture struct {
				Provenance    string
				EncryptionKey string `json:"encryption_key"`
				IntegrityKey  string `json:"integrity_key"`
				First         byte   `json:"first_payload"`
				Plaintext     string
				Packets       []string
				Events        []struct {
					Packet int
					Tamper bool
					Result string
				}
			}
			raw, err := os.ReadFile("testdata/" + tc.file)
			if err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(raw, &fixture); err != nil {
				t.Fatal(err)
			}
			decode := func(s string) []byte {
				b, err := hex.DecodeString(s)
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			enc, auth := decode(fixture.EncryptionKey), decode(fixture.IntegrityKey)
			integ := vc.HMACSHA256128
			if tc.encryption == vc.AESGCM16 {
				integ = 0
			}
			s := &Session{fragmentation: true, encryption: tc.encryption, integ: integ}
			var fb fragmentBuffer
			for i, event := range fixture.Events {
				b := decode(fixture.Packets[event.Packet])
				if event.Tamper {
					b[len(b)-1] ^= 1
				}
				m, ready, err := s.openIKE(b, enc, auth, &fb)
				result := "pending"
				if err != nil {
					result = "reject"
				} else if ready {
					result = "complete"
				}
				if result != event.Result {
					t.Fatalf("event %d: %s, want %s (%v)", i, result, event.Result, err)
				}
				if ready {
					first, plain, err := ikev2.EncodePayloads(m.Payloads)
					if err != nil || first != fixture.First || !bytes.Equal(plain, decode(fixture.Plaintext)) {
						t.Fatal("replay changed plaintext", err)
					}
					if m.Header.MessageID != 1 || m.Header.Exchange != ikev2.IKEAuth || m.Header.Flags != ikev2.FlagResponse {
						t.Fatal("replay changed envelope")
					}
				}
			}
			if len(fb.sets) != 0 {
				t.Fatal("complete replay retained fragments")
			}
			// Completion is not a tombstone: a dropped delivery can be retried in full.
			for i, packet := range fixture.Packets {
				_, ready, err := s.openIKE(decode(packet), enc, auth, &fb)
				if err != nil || ready != (i == len(fixture.Packets)-1) {
					t.Fatal("retransmission could not reassemble", err)
				}
			}
			s.fragmentation = false
			if _, _, err := s.openIKE(decode(fixture.Packets[0]), enc, auth, &fb); err == nil {
				t.Fatal("unnegotiated SKF accepted")
			}
		})
	}
}

func TestFragmentIsolationPMTUAndResourceLimits(t *testing.T) {
	now := time.Now()
	h := ikev2.Header{InitiatorSPI: 1, ResponderSPI: 2, Version: 32, NextPayload: ikev2.SKF, Exchange: ikev2.Informational, MessageID: 0}
	first, plain, _ := ikev2.EncodePayloads([]ikev2.Payload{ikev2.Notification(16384, nil)})
	f := ikev2.Fragment{Header: h, Number: 1, Total: 2, FirstPayload: first, Plaintext: plain[:3]}
	var fb fragmentBuffer
	if _, ready, err := fb.add(f, now); err != nil || ready {
		t.Fatal(err)
	}
	// Identical IDs on another SA, direction or exchange cannot complete it.
	for _, change := range []func(*ikev2.Header){func(h *ikev2.Header) { h.ResponderSPI++ }, func(h *ikev2.Header) { h.Flags = ikev2.FlagResponse }, func(h *ikev2.Header) { h.Exchange = ikev2.CreateChildSA }} {
		other := f
		change(&other.Header)
		other.Number = 2
		other.FirstPayload = 0
		other.Plaintext = plain[3:]
		if _, ready, err := fb.add(other, now); err != nil || ready {
			t.Fatal("fragment envelope mixed", err)
		}
	}
	extra := f
	extra.Header.MessageID = 1
	if _, _, err := fb.add(extra, now); err == nil {
		t.Fatal("queue limit not enforced")
	}
	// Duplicates do not extend retention, including PMTU restarts.
	if _, ready, err := fb.add(f, now.Add(time.Second)); err != nil || ready {
		t.Fatal(err)
	}
	probe := f
	probe.Total = 3
	if _, ready, err := fb.add(probe, now.Add(2*time.Second)); err != nil || ready {
		t.Fatal(err)
	}
	if !fb.sets[h].expires.Equal(now.Add(fragmentLifetime)) || len(fb.sets[h].pieces) != 1 {
		t.Fatal("PMTU restart retention")
	}
	last := f
	last.Number = 2
	last.FirstPayload = 0
	last.Plaintext = plain[3:]
	if _, ready, err := fb.add(last, now.Add(3*time.Second)); err != nil || ready || len(fb.sets[h].pieces) != 1 {
		t.Fatal("older fragment set mixed", err)
	}
	fb.prune(now.Add(fragmentLifetime))
	if len(fb.sets) != 0 {
		t.Fatal("expired state retained")
	}
	if _, _, err := fb.add(f, now); err != nil {
		t.Fatal(err)
	}
	bad := f
	bad.Plaintext = []byte{99}
	if _, _, err := fb.add(bad, now); err == nil {
		t.Fatal("conflict accepted")
	}
	if _, ready, err := fb.add(last, now); err != nil || !ready {
		t.Fatal("conflict destroyed valid assembly", err)
	}
	// Per-message bytes are bounded before copying; another valid set survives.
	f.Plaintext = make([]byte, ikev2.MaxFragmentedSize)
	if _, _, err := fb.add(f, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fb.add(last, now); err == nil {
		t.Fatal("byte limit not enforced")
	}
	fb.clear()
	if len(fb.sets) != 0 {
		t.Fatal("clear retained state")
	}
}

func TestFragmentNegotiationStrictNotify(t *testing.T) {
	valid := ikev2.Notification(ikev2.FragmentationSupported, nil)
	if !fragmentationOffered([]ikev2.Payload{valid}) {
		t.Fatal("valid offer ignored")
	}
	for _, data := range [][]byte{{1, 0, 0x40, 0x2e}, {0, 1, 0x40, 0x2e, 1}, {0, 0, 0x40, 0x2e, 0}} {
		if fragmentationOffered([]ikev2.Payload{{Type: ikev2.Notify, Data: data}}) {
			t.Fatal("malformed offer accepted")
		}
	}
}

func TestFragmentCompleteAuthenticationAndNegotiationFallback(t *testing.T) {
	for _, mode := range []string{"fragment", ""} {
		t.Run(mode, func(t *testing.T) {
			p := newMockPeer(t, mode)
			// Synthetic large initial IKE_AUTH; authenticate the exact identity chain.
			p.cfg.APN = string(bytes.Repeat([]byte{'a'}, 1800)) + ".invalid"
			p.start()
			s, err := Start(t.Context(), p.cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			p.check(t)
			if s.fragmentation != (mode == "fragment") {
				t.Fatal("wrong negotiated capability")
			}
			if mode == "fragment" && (p.authFragments < 2 || p.responseFragments < 2) {
				t.Fatal("fragment path not exercised")
			}
			if mode == "" && (p.authFragments != 0 || p.responseFragments != 0) {
				t.Fatal("fragmentation without peer capability")
			}
			checkOutboundRekey(t, p, s, p.fromClient)
		})
	}
}

func TestFragmentEstablishedRetransmitPeerReplayAndRoleFlip(t *testing.T) {
	p := newMockPeer(t, "fragment")
	p.start()
	s, err := Start(t.Context(), p.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p.check(t)
	old := originalPeerIKE(p)
	// Peer rekey changes the local IKE initiator role and resets Message IDs.
	peer, _, _ := completePeerIKERekey(t, p, s, old)
	large := []ikev2.Payload{ikev2.Notification(40960, bytes.Repeat([]byte{0x65}, 2600))}
	current := s.currentIKE()
	done := make(chan error, 1)
	go func() {
		s.ikeMu.Lock()
		defer s.ikeMu.Unlock()
		_, err := s.establishedExchangeLocked(s.ctx, ikev2.Informational, large)
		done <- err
	}()
	var original [][]byte
	var fb fragmentBuffer
	var request ikev2.Message
	for {
		b, err := p.read(p.natt, true)
		if err != nil {
			t.Fatal(err)
		}
		if len(b)+52 > 1280 {
			t.Fatal("outer IPv6 datagram limit exceeded")
		}
		original = append(original, bytes.Clone(b))
		f, err := ikev2.OpenFragment(b, peer.keys.SKer, peer.keys.SKar, vc.HMACSHA256128)
		if err != nil {
			t.Fatal(err)
		}
		var ready bool
		request, ready, err = fb.add(f, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if ready {
			break
		}
	}
	if len(original) < 2 || request.Header.Flags&ikev2.FlagInitiator != 0 {
		t.Fatal("role-flipped request not fragmented")
	}
	// Drop the first request attempt. Every fragment must be byte-identical on retry.
	for _, want := range original {
		got, err := p.read(p.natt, true)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("fragment retransmit changed", err)
		}
	}
	responseHeader := current.header(ikev2.Informational, request.Header.MessageID, false)
	responseHeader.Flags = ikev2.FlagInitiator | ikev2.FlagResponse
	reply, err := ikev2.SealFragments(responseHeader, large, peer.keys.SKei, peer.keys.SKai, vc.HMACSHA256128, nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	for i := len(reply) - 1; i >= 0; i-- {
		if err = p.send(p.natt, reply[i], true); err != nil {
			t.Fatal(err)
		}
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	// Direction and both SPIs isolate same-ID fragmented old/new requests.
	// Keep an incomplete old-SA set while processing the active request.
	pendingHeader := ikev2.Header{InitiatorSPI: old.spii, ResponderSPI: old.spir, Exchange: ikev2.Informational, MessageID: 1}
	pending, err := ikev2.SealFragments(pendingHeader, large, old.keys.SKer, old.keys.SKar, vc.HMACSHA256128, nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.send(p.natt, pending[0], true); err != nil {
		t.Fatal(err)
	}
	h := ikev2.Header{InitiatorSPI: peer.spii, ResponderSPI: peer.spir, Exchange: ikev2.Informational, Flags: ikev2.FlagInitiator, MessageID: 0}
	packets, err := ikev2.SealFragments(h, large, peer.keys.SKei, peer.keys.SKai, vc.HMACSHA256128, nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	for i := len(packets) - 1; i >= 0; i-- {
		if err = p.send(p.natt, packets[i], true); err != nil {
			t.Fatal(err)
		}
	}
	m, wire := readIKEFromClient(t, p, peer)
	if m.Header.MessageID != 0 || len(m.Payloads) != 0 {
		t.Fatal("peer request not answered")
	}
	// A non-first replay must not send anything. The following DPD reply is a
	// deterministic barrier: an accidental replay would arrive before it.
	if err = p.send(p.natt, packets[1], true); err != nil {
		t.Fatal(err)
	}
	sendIKEFromPeer(t, p, peer, 1, ikev2.Informational, false, nil)
	barrier, _ := readIKEFromClient(t, p, peer)
	if barrier.Header.MessageID != 1 {
		t.Fatal("non-first fragment triggered reply")
	}
	// Use a new ID to test the cached first-fragment retry without a newer
	// request replacing the cache.
	h.MessageID = 2
	packets, err = ikev2.SealFragments(h, large, peer.keys.SKei, peer.keys.SKai, vc.HMACSHA256128, nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range packets {
		if err = p.send(p.natt, b, true); err != nil {
			t.Fatal(err)
		}
	}
	_, wire = readIKEFromClient(t, p, peer)
	if err = p.send(p.natt, packets[0], true); err != nil {
		t.Fatal(err)
	}
	_, retry := readIKEFromClient(t, p, peer)
	if !bytes.Equal(wire, retry) {
		t.Fatal("first fragment did not reuse cached reply")
	}
	// The Child SA still carries traffic after the role flip and fragment work.
	sendTunnelPacket(t, p, p.toClient)
	receiveTunnelPacket(t, s)
	checkOutboundRekey(t, p, s, p.fromClient)
}

func TestFragmentEmptyAndMalformedPayloadChain(t *testing.T) {
	var fb fragmentBuffer
	f := ikev2.Fragment{Header: ikev2.Header{NextPayload: ikev2.SKF, Exchange: ikev2.Informational}, Number: 1, Total: 1}
	if m, ready, err := fb.add(f, time.Now()); err != nil || !ready || len(m.Payloads) != 0 {
		t.Fatal("single empty fragment rejected", err)
	}
	f.Plaintext = []byte{1}
	if _, ready, err := fb.add(f, time.Now()); err == nil || ready {
		t.Fatal("plaintext with no payload type accepted")
	}
	if len(fb.sets) != 0 {
		t.Fatal("malformed chain retained")
	}
}
