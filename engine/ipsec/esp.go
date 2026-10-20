// Package ipsec implements authenticated ESP with bounded replay protection.
package ipsec

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	vc "github.com/iniwex5/vowifi-go/engine/crypto"
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
	Encryption                  vc.Encryption
	Random                      io.Reader
}
type SA struct {
	mu           sync.Mutex
	spi          uint32
	enc, auth    []byte
	alg          vc.Integrity
	suite        vc.Protection
	rng          io.Reader
	seq, highest uint32
	bitmap       uint64
}

func NewSA(c SAConfig) (*SA, error) {
	if c.Encryption == 0 {
		c.Encryption = vc.AESCBC
	}
	suite := vc.Protection{Encryption: c.Encryption, Integrity: c.Integrity}
	if c.SPI == 0 || !suite.Valid() || suite.KeyLen(suite.KeyBits(len(c.EncryptionKey))) != len(c.EncryptionKey) || len(c.IntegrityKey) != c.Integrity.KeyLen() {
		return nil, errors.New("invalid ESP SA")
	}
	if c.Random == nil {
		c.Random = rand.Reader
	}
	return &SA{spi: c.SPI, enc: append([]byte{}, c.EncryptionKey...), auth: append([]byte{}, c.IntegrityKey...), alg: c.Integrity, suite: suite, rng: c.Random}, nil
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
	align := s.suite.Alignment()
	padding := (align - (len(payload)+2)%align) % align
	p := append([]byte{}, payload...)
	for i := 1; i <= padding; i++ {
		p = append(p, byte(i))
	}
	p = append(p, byte(padding), next)
	iv := make([]byte, s.suite.IVSize())
	if s.suite.AEAD() {
		binary.BigEndian.PutUint64(iv, uint64(s.seq))
	} else if _, err := io.ReadFull(s.rng, iv); err != nil {
		return nil, err
	}
	prefix := binary.BigEndian.AppendUint32(nil, s.spi)
	prefix = binary.BigEndian.AppendUint32(prefix, s.seq)
	body, err := s.suite.Seal(p, s.enc, s.auth, iv, prefix)
	if err != nil {
		return nil, err
	}
	return append(prefix, body...), nil
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
	minimum := s.suite.Alignment()
	if s.suite.AEAD() {
		minimum = 2
	}
	if len(b) < 8+s.suite.IVSize()+minimum+s.suite.TagSize() || binary.BigEndian.Uint32(b) != s.spi {
		return nil, 0, errors.New("invalid ESP length or SPI")
	}
	seq := binary.BigEndian.Uint32(b[4:])
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.acceptable(seq) {
		return nil, 0, ErrReplay
	}
	p, e := s.suite.Open(b[8:], s.enc, s.auth, b[:8])
	if e != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrIntegrity, e)
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
