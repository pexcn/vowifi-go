package ikev2

import (
	"bytes"
	"encoding/hex"
	vc "github.com/iniwex5/vowifi-go/engine/crypto"
	"strings"
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

func TestCPWireFormats(t *testing.T) {
	for _, tc := range []struct {
		name, wire string
		want       []CPAttribute
	}{
		{"standard", "0200000000010004c000020a00030004c0000235", []CPAttribute{{1, []byte{192, 0, 2, 10}}, {3, []byte{192, 0, 2, 53}}}},
		{"reserved-header", "02aabbcc00010004c000020a", []CPAttribute{{1, []byte{192, 0, 2, 10}}}},
		{"reserved-attribute-bit", "0200000080010004c000020a80030004c0000235", []CPAttribute{{1, []byte{192, 0, 2, 10}}, {3, []byte{192, 0, 2, 53}}}},
		{"legacy-TV-before-address", "02000000f00005dc00010004c000020a00030004c0000235", []CPAttribute{{0x7000, []byte{5, 0xdc}}, {1, []byte{192, 0, 2, 10}}, {3, []byte{192, 0, 2, 53}}}},
		{"standard-TLV-preferred", "02000000f0000002000100010004c000020a", []CPAttribute{{0x7000, []byte{0, 1}}, {1, []byte{192, 0, 2, 10}}}},
		{"empty-attributes", "020000000003000000080000", []CPAttribute{{3, []byte{}}, {8, []byte{}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			kind, got, err := ParseCP(wire)
			if err != nil || kind != 2 || len(got) != len(tc.want) {
				t.Fatalf("CFG_REPLY decode: kind=%d attrs=%v err=%v", kind, got, err)
			}
			for j, attr := range got {
				if attr.Type != tc.want[j].Type || !bytes.Equal(attr.Value, tc.want[j].Value) {
					t.Fatalf("attribute %d: got %+v, want %+v", j, attr, tc.want[j])
				}
			}
		})
	}
}

func TestMalformedCPKeepsDiagnosticsAndReturnsNoPartialAttributes(t *testing.T) {
	for _, tc := range []struct{ wire, diagnostic string }{
		{"020000", "truncated CP header"},
		{"02000000000100", "offset=4"},
		{"0200000000010005c000020a", "length=5 exceeds remaining=4"},
		{"02000000f00005dc00010004c000020a00", "remaining=1"},
		{"02000000f00005dc00010005c000020a", "length=5 exceeds remaining=4"},
	} {
		wire, err := hex.DecodeString(tc.wire)
		if err != nil {
			t.Fatal(err)
		}
		_, attrs, err := ParseCP(wire)
		if err == nil || attrs != nil || !strings.Contains(err.Error(), tc.diagnostic) {
			t.Fatalf("malformed CP lost diagnostic or returned partial result: attrs=%v err=%v", attrs, err)
		}
	}
	if _, err := EncodeCP(1, []CPAttribute{{Type: 0x8001}}); err == nil {
		t.Fatal("encoder emitted reserved attribute bit")
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
	f.Add([]byte{2, 0xaa, 0xbb, 0xcc, 0x80, 1, 0, 4, 192, 0, 2, 10})
	f.Add([]byte{2, 0, 0, 0, 0xf0, 0, 5, 0xdc, 0, 1, 0, 4, 192, 0, 2, 10})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Parse(b)
		_, _ = ParseProposals(b)
		_, _, _ = ParseCP(b)
		_, _ = ParseTS(b)
		_, _ = ParsePayloads(Nonce, b)
	})
}
