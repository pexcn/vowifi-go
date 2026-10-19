// Package ipsec3gpp implements the separate IMS ESP transport security agreement.
// IMS keys/SPIs/selectors are never shared with the outer SWu Child SA.
package ipsec3gpp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"sync"
)

var ErrIntegrity = errors.New("ipsec3gpp: ESP integrity failure")
var ErrReplay = errors.New("ipsec3gpp: ESP replay or zero sequence")
var ErrSequenceExhausted = errors.New("ipsec3gpp: ESP sequence exhausted; renegotiate IMS security")

// SA is one unidirectional RFC 4303 SA. It supports 64-packet anti-replay,
// 32-bit sequence numbers, AES-CBC/null encryption and 96-bit HMAC ICVs.
type SA struct {
	mu           sync.Mutex
	spi          uint32
	block        cipher.Block
	key          []byte
	hash         func() hash.Hash
	rng          io.Reader
	seq, highest uint32
	window       uint64
}

func NewSA(spi uint32, encryption, algorithm string, ck, ik []byte) (*SA, error) {
	if spi < 256 {
		return nil, errors.New("ipsec3gpp: SPI must not be reserved (0..255)")
	}
	if len(ik) != 16 {
		return nil, errors.New("ipsec3gpp: AKA IK must be 16 bytes")
	}
	s := &SA{spi: spi, key: append([]byte(nil), ik...), rng: rand.Reader}
	switch algorithm {
	case "hmac-sha-1-96":
		s.hash = sha1.New
	case "hmac-md5-96":
		s.hash = md5.New
	default:
		return nil, fmt.Errorf("ipsec3gpp: unsupported integrity %q", algorithm)
	}
	switch encryption {
	case "null":
	case "aes-cbc":
		if len(ck) != 16 {
			return nil, errors.New("ipsec3gpp: AKA CK must be 16 bytes")
		}
		b, e := aes.NewCipher(ck)
		if e != nil {
			return nil, e
		}
		s.block = b
	default:
		return nil, fmt.Errorf("ipsec3gpp: unsupported encryption %q", encryption)
	}
	return s, nil
}
func (s *SA) tag(b []byte) []byte { h := hmac.New(s.hash, s.key); h.Write(b); return h.Sum(nil)[:12] }
func (s *SA) Protect(payload []byte, next uint8) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seq == math.MaxUint32 {
		return nil, ErrSequenceExhausted
	}
	align, ivlen := 4, 0
	if s.block != nil {
		align = s.block.BlockSize()
		ivlen = align
	}
	pad := (align - (len(payload)+2)%align) % align
	out := make([]byte, 8+ivlen+len(payload)+pad+2+12)
	binary.BigEndian.PutUint32(out, s.spi)
	binary.BigEndian.PutUint32(out[4:], s.seq+1)
	data := out[8+ivlen : len(out)-12]
	copy(data, payload)
	for i := 0; i < pad; i++ {
		data[len(payload)+i] = byte(i + 1)
	}
	data[len(data)-2] = byte(pad)
	data[len(data)-1] = next
	if s.block != nil {
		iv := out[8 : 8+ivlen]
		if _, e := io.ReadFull(s.rng, iv); e != nil {
			return nil, e
		}
		cipher.NewCBCEncrypter(s.block, iv).CryptBlocks(data, data)
	}
	copy(out[len(out)-12:], s.tag(out[:len(out)-12]))
	s.seq++
	return out, nil
}
func (s *SA) Unprotect(esp []byte) ([]byte, uint8, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ivlen, align := 0, 4
	if s.block != nil {
		ivlen = s.block.BlockSize()
		align = ivlen
	}
	if len(esp) < 8+ivlen+align+12 || (len(esp)-8-ivlen-12)%align != 0 {
		return nil, 0, errors.New("ipsec3gpp: malformed ESP length")
	}
	if binary.BigEndian.Uint32(esp) != s.spi {
		return nil, 0, errors.New("ipsec3gpp: unexpected SPI")
	}
	seq := binary.BigEndian.Uint32(esp[4:])
	if seq == 0 || seq <= s.highest && (s.highest-seq >= 64 || s.window&(uint64(1)<<(s.highest-seq)) != 0) {
		return nil, 0, ErrReplay
	}
	if !hmac.Equal(s.tag(esp[:len(esp)-12]), esp[len(esp)-12:]) {
		return nil, 0, ErrIntegrity
	}
	data := append([]byte(nil), esp[8+ivlen:len(esp)-12]...)
	if s.block != nil {
		cipher.NewCBCDecrypter(s.block, esp[8:8+ivlen]).CryptBlocks(data, data)
	}
	pad := int(data[len(data)-2])
	if pad+2 > len(data) {
		return nil, 0, errors.New("ipsec3gpp: malformed ESP padding")
	}
	for i := 0; i < pad; i++ {
		if data[len(data)-2-pad+i] != byte(i+1) {
			return nil, 0, errors.New("ipsec3gpp: malformed ESP padding")
		}
	}
	// Replay state is committed only after authenticating AND validating the packet.
	if seq > s.highest {
		d := seq - s.highest
		if d >= 64 {
			s.window = 1
		} else {
			s.window = (s.window << d) | 1
		}
		s.highest = seq
	} else {
		s.window |= uint64(1) << (s.highest - seq)
	}
	return data[:len(data)-pad-2], data[len(data)-1], nil
}
