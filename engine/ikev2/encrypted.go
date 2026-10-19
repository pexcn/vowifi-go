package ikev2

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	vc "github.com/pexcn/vowifi-go/engine/crypto"
	"io"
)

// Seal protects an SK payload, including the outer IKE header, under RFC 7296.
func Seal(h Header, ps []Payload, enc, integ []byte, alg vc.Integrity, rng io.Reader) ([]byte, error) {
	first, plain, e := EncodePayloads(ps)
	if e != nil {
		return nil, e
	}
	pad := (16 - (len(plain)+1)%16) % 16
	plain = append(plain, make([]byte, pad)...)
	plain = append(plain, byte(pad))
	if rng == nil {
		rng = rand.Reader
	}
	ct, e := vc.EncryptCBC(enc, plain, rng)
	if e != nil {
		return nil, e
	}
	n := 4 + len(ct) + alg.Size()
	if n > 65535 {
		return nil, errors.New("SK payload too large")
	}
	h.NextPayload = SK
	b := h.Marshal(append([]byte{first, 0, byte(n >> 8), byte(n)}, ct...))
	binary.BigEndian.PutUint32(b[24:], uint32(len(b)+alg.Size()))
	tag, e := alg.MAC(integ, b)
	if e != nil {
		return nil, e
	}
	return append(b, tag...), nil
}
func Open(b, enc, integ []byte, alg vc.Integrity) (Message, error) {
	h, e := ParseHeader(b)
	if e != nil {
		return Message{}, e
	}
	if h.NextPayload != SK || len(b) < 32+32+alg.Size() || b[29] != 0 || int(binary.BigEndian.Uint16(b[30:])) != len(b)-28 {
		return Message{}, errors.New("invalid encrypted IKE payload")
	}
	end := len(b) - alg.Size()
	if !alg.Verify(integ, b[:end], b[end:]) {
		return Message{}, errors.New("IKE integrity verification failed")
	}
	plain, e := vc.DecryptCBC(enc, b[32:end])
	if e != nil {
		return Message{}, e
	}
	pad := int(plain[len(plain)-1])
	if pad+1 > len(plain) {
		return Message{}, errors.New("invalid IKE padding")
	}
	ps, e := ParsePayloads(b[28], plain[:len(plain)-pad-1])
	return Message{h, ps}, e
}
