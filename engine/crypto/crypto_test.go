package crypto

import (
	"bytes"
	"crypto/sha256"
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

func TestIKERekeyDerivationVectors(t *testing.T) {
	// Fixed vectors generated independently with Python's hmac/hashlib and
	// struct.pack('>QQ', SPIi, SPIr), following RFC 7296 2.18.
	for _, v := range []struct {
		p      PRF
		a      Integrity
		enc    int
		digest string
	}{
		{PRFSHA1, HMACSHA196, 16, "450c57ffb66dc5659145bc4fc57b1663f4ed78cac1d9dcf8acdbebf2e7ce3e39"},
		{PRFSHA256, HMACSHA256128, 32, "a013483af58aea19d4718d3143a90d5c6a7dbff956339723cf7a117c4ed692a8"},
	} {
		old, ni, nr, shared := bytes.Repeat([]byte{0x11}, v.p.Size()), bytes.Repeat([]byte{0x33}, 32), bytes.Repeat([]byte{0x44}, 32), bytes.Repeat([]byte{0x22}, 128)
		k, err := DeriveIKERekey(v.p, v.a, v.enc, old, ni, nr, shared, 0x0102030405060708, 0x1112131415161718)
		if err != nil {
			t.Fatal(err)
		}
		var material []byte
		for _, part := range [][]byte{k.SKd, k.SKai, k.SKar, k.SKei, k.SKer, k.SKpi, k.SKpr} {
			material = append(material, part...)
		}
		digest := sha256.Sum256(material)
		if hex.EncodeToString(digest[:]) != v.digest {
			t.Fatalf("PRF %d: %x", v.p, digest)
		}
		old[0] ^= 1
		changed, err := DeriveIKERekey(v.p, v.a, v.enc, old, ni, nr, shared, 0x0102030405060708, 0x1112131415161718)
		if err != nil || bytes.Equal(k.SKd, changed.SKd) {
			t.Fatal("old SK_d did not bind rekey keys", err)
		}
	}
}
