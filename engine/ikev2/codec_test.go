package ikev2

import (
	"bytes"
	vc "github.com/iniwex5/vowifi-go/engine/crypto"
	"testing"
)

func TestEncryptedIKEIntegrityAndLengths(t *testing.T) {
	enc := bytes.Repeat([]byte{1}, 16)
	key := bytes.Repeat([]byte{2}, 32)
	h := Header{InitiatorSPI: 1, ResponderSPI: 2, Exchange: IKEAuth, Flags: FlagInitiator, MessageID: 3}
	ps := []Payload{{Type: Nonce, Data: bytes.Repeat([]byte{3}, 32)}}
	b, e := Seal(h, ps, enc, key, vc.HMACSHA256128, nil)
	if e != nil {
		t.Fatal(e)
	}
	m, e := Open(b, enc, key, vc.HMACSHA256128)
	if e != nil || m.Header.MessageID != 3 || !bytes.Equal(m.Payloads[0].Data, ps[0].Data) {
		t.Fatal(e)
	}
	b[20] ^= 1
	if _, e = Open(b, enc, key, vc.HMACSHA256128); e == nil {
		t.Fatal("header tamper accepted")
	}
	if _, e = ParsePayloads(Nonce, []byte{0, 0, 0, 3}); e == nil {
		t.Fatal("short payload accepted")
	}
	if _, e = ParsePayloads(200, []byte{0, 128, 0, 4}); e == nil {
		t.Fatal("critical unknown accepted")
	}
}
func TestProposalSelectionCodec(t *testing.T) {
	p := Proposal{Number: 1, Protocol: 1, Transforms: []Transform{{Type: 1, ID: 12, KeyBits: 128}, {Type: 4, ID: 14}}}
	b, e := EncodeProposals([]Proposal{p})
	if e != nil {
		t.Fatal(e)
	}
	ps, e := ParseProposals(b)
	if e != nil || len(ps) != 1 || len(ps[0].Transforms) != 2 || ps[0].Transforms[0] != p.Transforms[0] {
		t.Fatal(e)
	}
	b[7] = 1
	if _, e = ParseProposals(b); e == nil {
		t.Fatal("wrong count")
	}
}
func FuzzIKECodecs(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Parse(b)
		_, _ = ParseProposals(b)
		_, _, _ = ParseCP(b)
		_, _ = ParseTS(b)
		_, _ = ParsePayloads(Nonce, b)
	})
}
