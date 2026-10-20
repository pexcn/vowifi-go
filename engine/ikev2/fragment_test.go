package ikev2

import (
	"bytes"
	"encoding/binary"
	"testing"

	vc "github.com/iniwex5/vowifi-go/engine/crypto"
)

func TestFragmentWireProtectionAndBounds(t *testing.T) {
	for _, alg := range []vc.Integrity{vc.HMACSHA196, vc.HMACSHA256128} {
		for _, bits := range []int{16, 32} {
			enc, auth := bytes.Repeat([]byte{3}, bits), bytes.Repeat([]byte{5}, alg.KeyLen())
			h := Header{InitiatorSPI: 1, ResponderSPI: 2, Exchange: IKEAuth, Flags: FlagResponse, MessageID: 7}
			ps := []Payload{{Type: CERT, Data: bytes.Repeat([]byte{9}, 3000)}}
			packets, err := SealFragments(h, ps, enc, auth, alg, nil, 512)
			if err != nil || len(packets) < 2 {
				t.Fatal(err)
			}
			var joined []byte
			for i, b := range packets {
				if len(b) > 512 {
					t.Fatal("packet limit exceeded")
				}
				f, err := OpenFragment(b, enc, auth, alg)
				if err != nil {
					t.Fatal(err)
				}
				if f.Number != uint16(i+1) || f.Total != uint16(len(packets)) || f.Header.MessageID != 7 || f.Header.Flags != FlagResponse {
					t.Fatal("fragment header changed")
				}
				if i == 0 && f.FirstPayload != CERT || i > 0 && f.FirstPayload != 0 {
					t.Fatal("next payload")
				}
				joined = append(joined, f.Plaintext...)
				// All headers, IV, ciphertext and ICV are covered by integrity.
				for _, at := range []int{0, 8, 18, 19, 20, 28, 29, 30, 32, 34, 36, 52, len(b) - 1} {
					bad := bytes.Clone(b)
					bad[at] ^= 1
					if _, err := OpenFragment(bad, enc, auth, alg); err == nil {
						t.Fatalf("tampering at %d accepted", at)
					}
				}
			}
			_, want, _ := EncodePayloads(ps)
			if !bytes.Equal(joined, want) {
				t.Fatal("plaintext changed")
			}
			if _, err := Parse(packets[0]); err == nil {
				t.Fatal("SKF accepted without authentication")
			}
			small, err := SealFragments(h, []Payload{{Type: Nonce, Data: []byte{1}}}, enc, auth, alg, nil, 512)
			if err != nil || len(small) != 1 || small[0][16] != SK {
				t.Fatal("small messages should use SK", err)
			}
			for _, limit := range []int{-1, 0, 80, 65536} {
				if _, err := SealFragments(h, ps, enc, auth, alg, nil, limit); err == nil {
					t.Fatal("invalid limit accepted")
				}
			}
			if _, err := SealFragments(h, []Payload{{Type: CERT, Data: make([]byte, 40000)}, {Type: CERT, Data: make([]byte, 40000)}}, enc, auth, alg, nil, 512); err == nil {
				t.Fatal("unbounded plaintext")
			}
			if _, err := SealFragments(h, []Payload{{Type: CERT, Data: make([]byte, 5000)}}, enc, auth, alg, nil, 84); err == nil {
				t.Fatal("fragment count unbounded")
			}
			// Authenticated malformed metadata must also fail closed.
			for _, mutate := range []func([]byte){
				func(b []byte) { binary.BigEndian.PutUint16(b[32:], 0) },
				func(b []byte) { binary.BigEndian.PutUint16(b[34:], 0) },
				func(b []byte) { binary.BigEndian.PutUint16(b[34:], 256) },
				func(b []byte) { binary.BigEndian.PutUint16(b[32:], uint16(len(packets)+1)) },
				func(b []byte) { b[18] = SAInit },
			} {
				b := bytes.Clone(packets[0])
				mutate(b)
				end := len(b) - alg.Size()
				tag, _ := alg.MAC(auth, b[:end])
				copy(b[end:], tag)
				if _, err := OpenFragment(b, enc, auth, alg); err == nil {
					t.Fatal("authenticated invalid metadata accepted")
				}
			}
		}
	}
}

func TestFragmentSingleEmptyInformational(t *testing.T) {
	enc, auth := make([]byte, 16), make([]byte, 32)
	h := Header{InitiatorSPI: 1, ResponderSPI: 2, Exchange: Informational}
	b, err := sealEncrypted(h, 0, nil, []byte{0, 1, 0, 1}, enc, auth, vc.HMACSHA256128, nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := OpenFragment(b, enc, auth, vc.HMACSHA256128)
	if err != nil || f.Total != 1 || len(f.Plaintext) != 0 || f.FirstPayload != 0 {
		t.Fatal("empty authenticated SKF rejected", err)
	}
}
