package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func unhex(s string) []byte { b, _ := hex.DecodeString(s); return b }
func TestPublishedHMACVectors(t *testing.T) { // RFC 2202 case 1 / RFC 4231 case 1.
	for _, v := range []struct {
		p    PRF
		want string
	}{{PRFSHA1, "b617318655057264e28bc0b6fb378c8ef146be00"}, {PRFSHA256, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"}} {
		b, e := v.p.Sum(bytes.Repeat([]byte{11}, 20), []byte("Hi There"))
		if e != nil || !bytes.Equal(b, unhex(v.want)) {
			t.Fatalf("HMAC %d: %x %v", v.p, b, e)
		}
	}
}
func TestNISTAESCBC(t *testing.T) { // SP800-38A F.2.1 (first block).
	key := unhex("2b7e151628aed2a6abf7158809cf4f3c")
	iv := unhex("000102030405060708090a0b0c0d0e0f")
	plain := unhex("6bc1bee22e409f96e93d7e117393172a")
	b, e := EncryptCBC(key, plain, bytes.NewReader(iv))
	if e != nil || !bytes.Equal(b[16:], unhex("7649abac8119b246cee98e9b12e9197d")) {
		t.Fatalf("CBC %x %v", b, e)
	}
	p, e := DecryptCBC(key, b)
	if e != nil || !bytes.Equal(p, plain) {
		t.Fatal(e)
	}
}
func TestDH14Subgroup(t *testing.T) {
	if group14.BitLen() != 2048 {
		t.Fatal("wrong group")
	}
	a, e := NewDH14(nil)
	if e != nil {
		t.Fatal(e)
	}
	b, e := NewDH14(nil)
	if e != nil {
		t.Fatal(e)
	}
	x, e := a.Shared(b.Public)
	if e != nil {
		t.Fatal(e)
	}
	y, e := b.Shared(a.Public)
	if e != nil || !bytes.Equal(x, y) {
		t.Fatal("DH mismatch", e)
	}
	for _, v := range [][]byte{make([]byte, 256), append(make([]byte, 255), 1), {2}} {
		if _, e = a.Shared(v); e == nil {
			t.Fatal("invalid public accepted")
		}
	}
}
func TestPRFPlusBoundaries(t *testing.T) {
	if _, e := PRFSHA256.Plus(nil, nil, 255*32+1); e == nil {
		t.Fatal("counter overflow")
	}
	key, seed := []byte("key"), []byte("seed")
	b, e := PRFSHA256.Plus(key, seed, 65)
	if e != nil {
		t.Fatal(e)
	}
	t1, _ := PRFSHA256.Sum(key, append(append([]byte{}, seed...), 1))
	t2, _ := PRFSHA256.Sum(key, append(append(append([]byte{}, t1...), seed...), 2))
	if !bytes.Equal(b[:32], t1) || !bytes.Equal(b[32:64], t2) {
		t.Fatal("PRF+ chaining")
	}
}
