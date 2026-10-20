package ikev2

import (
	"bytes"
	vc "github.com/iniwex5/vowifi-go/engine/crypto"
	"testing"
)

func TestGCMHeaderAuthenticationFragmentationAndSalt(t *testing.T) {
	suite := vc.Protection{Encryption: vc.AESGCM16}
	for _, bits := range []uint16{128, 256} {
		key := bytes.Repeat([]byte{0x71}, suite.KeyLen(bits))
		ps := []Payload{{Type: CERT, Data: bytes.Repeat([]byte{0x82}, 4000)}}
		var seq vc.IVSequence
		h := Header{InitiatorSPI: 0x1234, ResponderSPI: 0x9876, Exchange: IKEAuth, MessageID: 8, Flags: FlagResponse}
		packets, err := SealFragmentsProtected(h, ps, key, nil, suite, &seq, 512)
		if err != nil {
			t.Fatal(err)
		}
		var plain []byte
		ivs := map[string]bool{}
		for _, b := range packets {
			if len(b) > 512 {
				t.Fatal("limit")
			}
			f, err := OpenFragmentProtected(b, key, nil, suite)
			if err != nil {
				t.Fatal(err)
			}
			plain = append(plain, f.Plaintext...)
			if ivs[string(b[36:44])] {
				t.Fatal("IV reused")
			}
			ivs[string(b[36:44])] = true
			for _, at := range []int{0, 8, 18, 19, 20, 28, 32, 34, 36, 44, len(b) - 1} {
				bad := bytes.Clone(b)
				bad[at] ^= 1
				if _, err := OpenFragmentProtected(bad, key, nil, suite); err == nil {
					t.Fatal("unauthenticated fragment metadata")
				}
			}
		}
		_, want, _ := EncodePayloads(ps)
		if !bytes.Equal(plain, want) {
			t.Fatal("fragment plaintext changed")
		}
		b, err := SealProtected(h, []Payload{Notification(40960, nil)}, key, nil, suite, &seq)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OpenProtected(b, key, nil, suite); err != nil {
			t.Fatal(err)
		}
		other := bytes.Clone(key)
		other[len(other)-1] ^= 1
		if _, err := OpenProtected(b, other, nil, suite); err == nil {
			t.Fatal("salt unauthenticated")
		}
	}
}
