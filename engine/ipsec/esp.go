// Package ipsec implements ESP AES-CBC with authenticated replay protection.
package ipsec

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	vc "github.com/pexcn/vowifi-go/engine/crypto"
	"io"
	"sync"
)

var (
	ErrReplay    = errors.New("ESP replay or stale sequence")
	ErrIntegrity = errors.New("ESP integrity failure")
	ErrExhausted = errors.New("ESP sequence exhausted; rekey required")
)

type SAConfig struct {
	SPI                         uint32
	EncryptionKey, IntegrityKey []byte
	Integrity                   vc.Integrity
	Random                      io.Reader
}
type SA struct {
	mu           sync.Mutex
	spi          uint32
	enc, auth    []byte
	alg          vc.Integrity
	rng          io.Reader
	seq, highest uint32
	bitmap       uint64
}

func NewSA(c SAConfig) (*SA, error) {
	if c.SPI == 0 || (len(c.EncryptionKey) != 16 && len(c.EncryptionKey) != 24 && len(c.EncryptionKey) != 32) || len(c.IntegrityKey) != c.Integrity.KeyLen() || c.Integrity.KeyLen() == 0 {
		return nil, errors.New("invalid ESP SA")
	}
	if c.Random == nil {
		c.Random = rand.Reader
	}
	return &SA{spi: c.SPI, enc: append([]byte{}, c.EncryptionKey...), auth: append([]byte{}, c.IntegrityKey...), alg: c.Integrity, rng: c.Random}, nil
}
func (s *SA) SPI() uint32 { return s.spi }

// Seal protects a payload and IP protocol number. It also supports transport mode.
func (s *SA) Seal(payload []byte, next byte) ([]byte, error) {
	if len(payload) > 65535 {
		return nil, errors.New("ESP payload too large")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seq == ^uint32(0) {
		return nil, ErrExhausted
	}
	s.seq++
	padding := (16 - (len(payload)+2)%16) % 16
	p := append([]byte{}, payload...)
	for i := 1; i <= padding; i++ {
		p = append(p, byte(i))
	}
	p = append(p, byte(padding), next)
	ct, e := vc.EncryptCBC(s.enc, p, s.rng)
	if e != nil {
		return nil, e
	}
	b := binary.BigEndian.AppendUint32(nil, s.spi)
	b = binary.BigEndian.AppendUint32(b, s.seq)
	b = append(b, ct...)
	m, e := s.alg.MAC(s.auth, b)
	if e != nil {
		return nil, e
	}
	return append(b, m...), nil
}
func (s *SA) acceptable(seq uint32) bool {
	if seq == 0 {
		return false
	}
	if seq > s.highest {
		return true
	}
	delta := s.highest - seq
	return delta < 64 && s.bitmap&(uint64(1)<<delta) == 0
}

// Open updates the replay window only AFTER MAC, decryption, and padding validate.
func (s *SA) Open(b []byte) ([]byte, byte, error) {
	if len(b) < 8+32+s.alg.Size() || binary.BigEndian.Uint32(b) != s.spi {
		return nil, 0, errors.New("invalid ESP length or SPI")
	}
	seq := binary.BigEndian.Uint32(b[4:])
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.acceptable(seq) {
		return nil, 0, ErrReplay
	}
	end := len(b) - s.alg.Size()
	if !s.alg.Verify(s.auth, b[:end], b[end:]) {
		return nil, 0, ErrIntegrity
	}
	p, e := vc.DecryptCBC(s.enc, b[8:end])
	if e != nil {
		return nil, 0, e
	}
	if len(p) < 2 {
		return nil, 0, errors.New("truncated ESP trailer")
	}
	pad := int(p[len(p)-2])
	if pad+2 > len(p) {
		return nil, 0, errors.New("invalid ESP padding length")
	}
	for i := 0; i < pad; i++ {
		if p[len(p)-2-pad+i] != byte(i+1) {
			return nil, 0, errors.New("invalid ESP padding")
		}
	}
	if seq > s.highest {
		d := seq - s.highest
		if d >= 64 {
			s.bitmap = 1
		} else {
			s.bitmap = s.bitmap<<d | 1
		}
		s.highest = seq
	} else {
		s.bitmap |= uint64(1) << (s.highest - seq)
	}
	return p[:len(p)-pad-2], p[len(p)-1], nil
}
func ValidateInnerIP(p []byte, next byte) error {
	if len(p) == 0 {
		return errors.New("empty IP packet")
	}
	switch next {
	case 4:
		if len(p) < 20 || p[0]>>4 != 4 || int(p[0]&15)*4 < 20 || int(p[0]&15)*4 > len(p) || int(binary.BigEndian.Uint16(p[2:])) != len(p) {
			return errors.New("malformed inner IPv4")
		}
	case 41:
		if len(p) < 40 || p[0]>>4 != 6 || 40+int(binary.BigEndian.Uint16(p[4:])) != len(p) {
			return errors.New("malformed inner IPv6")
		}
	default:
		return fmt.Errorf("ESP next header %d is not tunnel IP", next)
	}
	return nil
}
