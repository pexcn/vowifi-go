package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"sync/atomic"
)

type Encryption uint16

const (
	AESCBC   Encryption = 12
	AESGCM16 Encryption = 20
)

// Protection binds encryption and authentication. Integrity zero is valid only
// with AES-GCM, whose mandatory 128-bit tag authenticates every packet.
type Protection struct {
	Encryption Encryption
	Integrity  Integrity
}

func (p Protection) AEAD() bool { return p.Encryption == AESGCM16 }
func (p Protection) Valid() bool {
	return p.Encryption == AESCBC && p.Integrity.KeyLen() != 0 || p.AEAD() && p.Integrity == 0
}
func (p Protection) KeyLen(bits uint16) int {
	if !p.Valid() || bits != 128 && bits != 192 && bits != 256 {
		return 0
	}
	n := int(bits) / 8
	if p.AEAD() {
		n += 4
	}
	return n
}
func (p Protection) KeyBits(n int) uint16 {
	if p.AEAD() {
		n -= 4
	}
	return uint16(n * 8)
}
func (p Protection) IVSize() int {
	if p.AEAD() {
		return 8
	}
	return 16
}
func (p Protection) TagSize() int {
	if p.AEAD() {
		return 16
	}
	return p.Integrity.Size()
}
func (p Protection) Alignment() int {
	if p.AEAD() {
		return 4
	}
	return 16
}
func (p Protection) validate(enc, auth, iv []byte) error {
	if !p.Valid() || p.KeyLen(p.KeyBits(len(enc))) != len(enc) || len(auth) != p.Integrity.KeyLen() || len(iv) != p.IVSize() {
		return errors.New("invalid protected cipher parameters")
	}
	return nil
}
func (p Protection) gcm(enc []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(enc[:len(enc)-4])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal returns IV | ciphertext | tag. aad is the final wire prefix (IKE header
// plus SK/SKF headers, or the ESP SPI and sequence). GCM uses salt | explicit IV.
func (p Protection) Seal(plain, enc, auth, iv, aad []byte) ([]byte, error) {
	if err := p.validate(enc, auth, iv); err != nil {
		return nil, err
	}
	out := append([]byte{}, iv...)
	if p.AEAD() {
		aead, err := p.gcm(enc)
		if err != nil {
			return nil, err
		}
		nonce := append(append([]byte{}, enc[len(enc)-4:]...), iv...)
		return aead.Seal(out, nonce, plain, aad), nil
	}
	if len(plain)%16 != 0 {
		return nil, errors.New("unaligned CBC plaintext")
	}
	block, err := aes.NewCipher(enc)
	if err != nil {
		return nil, err
	}
	out = append(out, make([]byte, len(plain))...)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out[len(iv):], plain)
	tag, err := p.Integrity.MAC(auth, append(append([]byte{}, aad...), out...))
	if err != nil {
		return nil, err
	}
	return append(out, tag...), nil
}
func (p Protection) Open(body, enc, auth, aad []byte) ([]byte, error) {
	n := p.IVSize()
	if len(body) < n+p.TagSize() {
		return nil, errors.New("truncated protected payload")
	}
	iv := body[:n]
	if err := p.validate(enc, auth, iv); err != nil {
		return nil, err
	}
	if p.AEAD() {
		aead, err := p.gcm(enc)
		if err != nil {
			return nil, err
		}
		nonce := append(append([]byte{}, enc[len(enc)-4:]...), iv...)
		return aead.Open(nil, nonce, body[n:], aad)
	}
	end := len(body) - p.TagSize()
	if !p.Integrity.Verify(auth, append(append([]byte{}, aad...), body[:end]...), body[end:]) {
		return nil, errors.New("integrity verification failed")
	}
	return DecryptCBC(enc, body[:end])
}

// IVSequence belongs to one session. Never reset it while any of that session's
// IKE keys remain usable; retries reuse sealed packets and consume no new IV.
// New sessions always derive fresh keys. ESP uses its own sequence counter.
type IVSequence struct{ counter atomic.Uint64 }

func (s *IVSequence) Read(b []byte) (int, error) {
	if len(b) != 8 {
		return 0, errors.New("GCM explicit IV must be eight bytes")
	}
	for {
		old := s.counter.Load()
		if old == ^uint64(0) {
			return 0, io.ErrUnexpectedEOF
		}
		if s.counter.CompareAndSwap(old, old+1) {
			binary.BigEndian.PutUint64(b, old+1)
			return 8, nil
		}
	}
}
