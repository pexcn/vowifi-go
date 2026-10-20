package ikev2

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	vc "github.com/iniwex5/vowifi-go/engine/crypto"
	"io"
)

func Seal(h Header, ps []Payload, enc, integ []byte, alg vc.Integrity, rng io.Reader) ([]byte, error) {
	return SealProtected(h, ps, enc, integ, vc.Protection{Encryption: vc.AESCBC, Integrity: alg}, rng)
}

// SealProtected authenticates the final IKE header and SK header. For GCM the
// source must issue unique explicit IVs, e.g. one crypto.IVSequence per session.
func SealProtected(h Header, ps []Payload, enc, auth []byte, suite vc.Protection, rng io.Reader) ([]byte, error) {
	first, plain, err := EncodePayloads(ps)
	if err != nil {
		return nil, err
	}
	return sealProtected(h, first, plain, nil, enc, auth, suite, rng)
}
func sealEncrypted(h Header, first byte, plain, fh, enc, auth []byte, alg vc.Integrity, rng io.Reader) ([]byte, error) {
	return sealProtected(h, first, plain, fh, enc, auth, vc.Protection{Encryption: vc.AESCBC, Integrity: alg}, rng)
}
func sealProtected(h Header, first byte, plain, fh, enc, auth []byte, suite vc.Protection, rng io.Reader) ([]byte, error) {
	if !suite.Valid() {
		return nil, errors.New("invalid IKE protection suite")
	}
	block := suite.Alignment()
	pad := (block - (len(plain)+1)%block) % block
	plain = append(plain[:len(plain):len(plain)], make([]byte, pad)...)
	plain = append(plain, byte(pad))
	if rng == nil {
		if suite.AEAD() {
			return nil, errors.New("GCM requires a unique IV source")
		}
		rng = rand.Reader
	}
	iv := make([]byte, suite.IVSize())
	if _, err := io.ReadFull(rng, iv); err != nil {
		return nil, err
	}
	n := 4 + len(fh) + len(iv) + len(plain) + suite.TagSize()
	if n > 65535 {
		return nil, errors.New("encrypted IKE payload too large")
	}
	h.NextPayload = SK
	if len(fh) > 0 {
		h.NextPayload = SKF
	}
	prefix := h.Marshal(append([]byte{first, 0, byte(n >> 8), byte(n)}, fh...))
	binary.BigEndian.PutUint32(prefix[24:], uint32(28+n))
	body, err := suite.Seal(plain, enc, auth, iv, prefix)
	if err != nil {
		return nil, err
	}
	return append(prefix, body...), nil
}
func openProtected(b, enc, auth []byte, suite vc.Protection, typ byte, prefix int) (Header, []byte, error) {
	h, err := ParseHeader(b)
	if err != nil {
		return Header{}, nil, err
	}
	minimum := suite.Alignment()
	if suite.AEAD() {
		minimum = 1
	}
	if !suite.Valid() || h.NextPayload != typ || len(b) < prefix+suite.IVSize()+minimum+suite.TagSize() || b[29] != 0 || int(binary.BigEndian.Uint16(b[30:])) != len(b)-28 {
		return Header{}, nil, errors.New("invalid encrypted IKE payload")
	}
	plain, err := suite.Open(b[prefix:], enc, auth, b[:prefix])
	if err != nil {
		return Header{}, nil, err
	}
	if len(plain) == 0 {
		return Header{}, nil, errors.New("empty IKE plaintext")
	}
	pad := int(plain[len(plain)-1])
	if pad+1 > len(plain) {
		return Header{}, nil, errors.New("invalid IKE padding")
	}
	return h, plain[:len(plain)-pad-1], nil
}
func Open(b, enc, auth []byte, alg vc.Integrity) (Message, error) {
	return OpenProtected(b, enc, auth, vc.Protection{Encryption: vc.AESCBC, Integrity: alg})
}
func OpenProtected(b, enc, auth []byte, suite vc.Protection) (Message, error) {
	h, plain, err := openProtected(b, enc, auth, suite, SK, 32)
	if err != nil {
		return Message{}, err
	}
	ps, err := ParsePayloads(b[28], plain)
	return Message{h, ps}, err
}
