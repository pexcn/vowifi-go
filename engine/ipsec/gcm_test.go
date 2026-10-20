package ipsec

import (
	"bytes"
	"errors"
	vc "github.com/iniwex5/vowifi-go/engine/crypto"
	"testing"
)

func TestGCMESPReplayAndForgery(t *testing.T) {
	for _, n := range []int{20, 36} {
		cfg := SAConfig{SPI: 7, Encryption: vc.AESGCM16, EncryptionKey: bytes.Repeat([]byte{1}, n)}
		out, err := NewSA(cfg)
		if err != nil {
			t.Fatal(err)
		}
		in, err := NewSA(cfg)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := out.Seal([]byte("test payload"), 17)
		if err != nil {
			t.Fatal(err)
		}
		for _, at := range []int{4, 8, 16, len(wire) - 1} {
			b := bytes.Clone(wire)
			b[at] ^= 1
			if _, _, err := in.Open(b); err == nil {
				t.Fatal("forgery accepted")
			}
		}
		plain, next, err := in.Open(wire)
		if err != nil || next != 17 || string(plain) != "test payload" {
			t.Fatal(err)
		}
		if _, _, err := in.Open(wire); !errors.Is(err, ErrReplay) {
			t.Fatal("replay accepted", err)
		}
		out.seq = ^uint32(0)
		if _, err := out.Seal(nil, 17); !errors.Is(err, ErrExhausted) {
			t.Fatal("nonce reuse allowed", err)
		}
	}
}
