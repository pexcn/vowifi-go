package ikev2

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	vc "github.com/iniwex5/vowifi-go/engine/crypto"
	"io"
)

// Seal protects an SK payload, including the outer IKE header, under RFC 7296.
func Seal(h Header, ps []Payload, enc, integ []byte, alg vc.Integrity, rng io.Reader) ([]byte, error) {
	first, plain, e := EncodePayloads(ps)
	if e != nil {
		return nil, e
	}
	return sealEncrypted(h, first, plain, nil, enc, integ, alg, rng)
}

func sealEncrypted(h Header, first byte, plain, fragmentHeader, enc, integ []byte, alg vc.Integrity, rng io.Reader) ([]byte, error) {
	if alg.Size() == 0 {
		return nil, errors.New("unsupported IKE integrity")
	}
	pad := (16 - (len(plain)+1)%16) % 16
	plain = append(plain[:len(plain):len(plain)], make([]byte, pad)...)
	plain = append(plain, byte(pad))
	if rng == nil {
		rng = rand.Reader
	}
	ct, e := vc.EncryptCBC(enc, plain, rng)
	if e != nil {
		return nil, e
	}
	n := 4 + len(fragmentHeader) + len(ct) + alg.Size()
	if n > 65535 {
		return nil, errors.New("encrypted IKE payload too large")
	}
	h.NextPayload = SK
	if len(fragmentHeader) != 0 {
		h.NextPayload = SKF
	}
	body := append([]byte{first, 0, byte(n >> 8), byte(n)}, fragmentHeader...)
	b := h.Marshal(append(body, ct...))
	binary.BigEndian.PutUint32(b[24:], uint32(len(b)+alg.Size()))
	tag, e := alg.MAC(integ, b)
	if e != nil {
		return nil, e
	}
	return append(b, tag...), nil
}

// openEncrypted authenticates all headers before decrypting or exposing plaintext.
func openEncrypted(b, enc, integ []byte, alg vc.Integrity, typ byte, prefix int) (Header, []byte, error) {
	h, e := ParseHeader(b)
	if e != nil {
		return Header{}, nil, e
	}
	if alg.Size() == 0 || h.NextPayload != typ || len(b) < prefix+32+alg.Size() || b[29] != 0 || int(binary.BigEndian.Uint16(b[30:])) != len(b)-28 {
		return Header{}, nil, errors.New("invalid encrypted IKE payload")
	}
	end := len(b) - alg.Size()
	if !alg.Verify(integ, b[:end], b[end:]) {
		return Header{}, nil, errors.New("IKE integrity verification failed")
	}
	plain, e := vc.DecryptCBC(enc, b[prefix:end])
	if e != nil {
		return Header{}, nil, e
	}
	pad := int(plain[len(plain)-1])
	if pad+1 > len(plain) {
		return Header{}, nil, errors.New("invalid IKE padding")
	}
	return h, plain[:len(plain)-pad-1], nil
}

func Open(b, enc, integ []byte, alg vc.Integrity) (Message, error) {
	h, plain, e := openEncrypted(b, enc, integ, alg, SK, 32)
	if e != nil {
		return Message{}, e
	}
	ps, e := ParsePayloads(b[28], plain)
	return Message{h, ps}, e
}
