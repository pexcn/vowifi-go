package ipsec

import (
	"bytes"
	"errors"
	vc "github.com/iniwex5/vowifi-go/engine/crypto"
	"testing"
)

func sas(t *testing.T) (*SA, *SA) {
	t.Helper()
	cfg := SAConfig{SPI: 0x12345678, EncryptionKey: bytes.Repeat([]byte{1}, 16), IntegrityKey: bytes.Repeat([]byte{2}, 32), Integrity: vc.HMACSHA256128}
	a, e := NewSA(cfg)
	if e != nil {
		t.Fatal(e)
	}
	b, e := NewSA(cfg)
	if e != nil {
		t.Fatal(e)
	}
	return a, b
}
func TestESPReplayAndForgeryAreTransactional(t *testing.T) {
	tx, rx := sas(t)
	var packets [][]byte
	for i := 0; i < 70; i++ {
		p, e := tx.Seal([]byte{byte(i)}, 17)
		if e != nil {
			t.Fatal(e)
		}
		packets = append(packets, p)
	}
	bad := append([]byte{}, packets[69]...)
	bad[len(bad)-1] ^= 1
	if _, _, e := rx.Open(bad); !errors.Is(e, ErrIntegrity) {
		t.Fatal(e)
	}
	if p, next, e := rx.Open(packets[1]); e != nil || next != 17 || p[0] != 1 {
		t.Fatal("forgery advanced window", e)
	}
	if _, _, e := rx.Open(packets[69]); e != nil {
		t.Fatal(e)
	}
	if _, _, e := rx.Open(packets[69]); !errors.Is(e, ErrReplay) {
		t.Fatal(e)
	}
	if _, _, e := rx.Open(packets[1]); !errors.Is(e, ErrReplay) {
		t.Fatal(e)
	}
	if _, _, e := rx.Open(packets[68]); e != nil {
		t.Fatal("out-of-order rejected", e)
	}
}
func TestESPBadPaddingDoesNotConsumeSequence(t *testing.T) {
	tx, rx := sas(t)
	p, _ := tx.Seal([]byte{1}, 17)
	bad := append([]byte{}, p...) // Change IV to flip the authenticated padding byte, then resign.
	bad[8+1] ^= 255
	end := len(bad) - tx.alg.Size()
	tag, _ := tx.alg.MAC(tx.auth, bad[:end])
	copy(bad[end:], tag)
	if _, _, e := rx.Open(bad); e == nil {
		t.Fatal("bad padding accepted")
	}
	if _, _, e := rx.Open(p); e != nil {
		t.Fatal("bad padding committed replay", e)
	}
}
func TestESPSequenceExhaustion(t *testing.T) {
	tx, _ := sas(t)
	tx.seq = ^uint32(0)
	if _, e := tx.Seal(nil, 4); !errors.Is(e, ErrExhausted) {
		t.Fatal(e)
	}
}
func TestSOCKSCodecRejectsForeignPeerAndFragments(t *testing.T) {
	a, e := socksAddress("192.0.2.1:4500")
	if e != nil {
		t.Fatal(e)
	}
	h := append([]byte{0, 0, 0}, a...)
	b := append(append([]byte{}, h...), 1, 2, 3)
	p, e := decodeSOCKS(b, h)
	if e != nil || !bytes.Equal(p, []byte{1, 2, 3}) {
		t.Fatal(e)
	}
	b[2] = 1
	if _, e = decodeSOCKS(b, h); e == nil {
		t.Fatal("fragment accepted")
	}
	b[2] = 0
	b[4] ^= 1
	if _, e = decodeSOCKS(b, h); e == nil {
		t.Fatal("foreign peer accepted")
	}
}
