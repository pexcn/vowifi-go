package crypto

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"
)

func TestGCMNISTAndStrictSuite(t *testing.T) {
	p := Protection{Encryption: AESGCM16}
	key := make([]byte, 20)
	iv := make([]byte, 8)
	body, err := p.Seal(make([]byte, 16), key, nil, iv, nil)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("00000000000000000388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")
	if !bytes.Equal(body, want) {
		t.Fatalf("NIST GCM vector mismatch: %x", body)
	}
	for _, at := range []int{0, 8, len(body) - 1} {
		bad := bytes.Clone(body)
		bad[at] ^= 1
		if _, err := p.Open(bad, key, nil, nil); err == nil {
			t.Fatal("forgery accepted")
		}
	}
	if _, err := (Protection{Encryption: AESCBC}).Seal(nil, make([]byte, 16), nil, make([]byte, 16), nil); err == nil {
		t.Fatal("CBC without authentication")
	}
	var seq IVSequence
	a, b := make([]byte, 8), make([]byte, 8)
	io.ReadFull(&seq, a)
	io.ReadFull(&seq, b)
	if bytes.Equal(a, b) {
		t.Fatal("IV reused")
	}
	seq.counter.Store(^uint64(0))
	if _, err := seq.Read(b); err == nil {
		t.Fatal("IV exhausted without failure")
	}
}
func TestECPGroupsRejectInvalidPublicValues(t *testing.T) {
	for _, g := range []uint16{19, 20, 21} {
		a, err := NewMODP(g, nil)
		if err != nil {
			t.Fatal(err)
		}
		b, err := NewMODP(g, nil)
		if err != nil {
			t.Fatal(err)
		}
		x, err := a.Shared(b.Public)
		if err != nil {
			t.Fatal(err)
		}
		y, err := b.Shared(a.Public)
		if err != nil || !bytes.Equal(x, y) {
			t.Fatal("ECP shared mismatch", err)
		}
		if _, err := a.Shared(make([]byte, len(a.Public))); err == nil {
			t.Fatal("invalid ECP point accepted")
		}
	}
}
