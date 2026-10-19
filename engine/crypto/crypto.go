// Package crypto implements the negotiated primitives for the independent SWu engine.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"math/big"
)

type PRF uint16

const (
	PRFSHA1   PRF = 2
	PRFSHA256 PRF = 5
)

func (p PRF) factory() (func() hash.Hash, error) {
	switch p {
	case PRFSHA1:
		return sha1.New, nil
	case PRFSHA256:
		return sha256.New, nil
	}
	return nil, errors.New("unsupported PRF")
}
func (p PRF) Sum(key, data []byte) ([]byte, error) {
	f, e := p.factory()
	if e != nil {
		return nil, e
	}
	h := hmac.New(f, key)
	h.Write(data)
	return h.Sum(nil), nil
}
func (p PRF) Size() int {
	if p == PRFSHA1 {
		return 20
	}
	if p == PRFSHA256 {
		return 32
	}
	return 0
}

// Plus is RFC 7296 section 2.13. A maximum of 255 PRF blocks is allowed.
func (p PRF) Plus(key, seed []byte, n int) ([]byte, error) {
	if n < 0 || p.Size() == 0 || n > 255*p.Size() {
		return nil, errors.New("invalid PRF+ length")
	}
	out := make([]byte, 0, n)
	var prev []byte
	for i := 1; len(out) < n; i++ {
		in := append(append(append([]byte{}, prev...), seed...), byte(i))
		var e error
		prev, e = p.Sum(key, in)
		if e != nil {
			return nil, e
		}
		out = append(out, prev...)
	}
	return out[:n], nil
}

type Integrity uint16

const (
	HMACSHA196    Integrity = 2
	HMACSHA256128 Integrity = 12
)

func (a Integrity) KeyLen() int {
	if a == HMACSHA196 {
		return 20
	}
	if a == HMACSHA256128 {
		return 32
	}
	return 0
}
func (a Integrity) Size() int {
	if a == HMACSHA196 {
		return 12
	}
	if a == HMACSHA256128 {
		return 16
	}
	return 0
}
func (a Integrity) MAC(key, data []byte) ([]byte, error) {
	var p PRF
	switch a {
	case HMACSHA196:
		p = PRFSHA1
	case HMACSHA256128:
		p = PRFSHA256
	default:
		return nil, errors.New("unsupported integrity algorithm")
	}
	if len(key) != a.KeyLen() {
		return nil, errors.New("wrong integrity key length")
	}
	m, e := p.Sum(key, data)
	if e != nil {
		return nil, e
	}
	return m[:a.Size()], nil
}
func (a Integrity) Verify(key, data, tag []byte) bool {
	m, e := a.MAC(key, data)
	return e == nil && hmac.Equal(m, tag)
}
func EncryptCBC(key, plain []byte, rng io.Reader) ([]byte, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	if len(plain)%aes.BlockSize != 0 {
		return nil, errors.New("CBC plaintext unaligned")
	}
	if rng == nil {
		rng = rand.Reader
	}
	out := make([]byte, aes.BlockSize+len(plain))
	if _, e = io.ReadFull(rng, out[:aes.BlockSize]); e != nil {
		return nil, e
	}
	cipher.NewCBCEncrypter(b, out[:aes.BlockSize]).CryptBlocks(out[aes.BlockSize:], plain)
	return out, nil
}
func DecryptCBC(key, data []byte) ([]byte, error) {
	if len(data) < 2*aes.BlockSize || len(data)%aes.BlockSize != 0 {
		return nil, errors.New("malformed CBC ciphertext")
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	out := make([]byte, len(data)-aes.BlockSize)
	cipher.NewCBCDecrypter(b, data[:aes.BlockSize]).CryptBlocks(out, data[aes.BlockSize:])
	return out, nil
}

// MODP group 14, RFC 3526, 2048 bits. Peer values are restricted to the prime-order subgroup.
const group14Hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"

var group14, _ = new(big.Int).SetString(group14Hex, 16)

// Oakley MODP group 2 (RFC 2409) is used only when explicitly offered by a
// carrier profile. DH14 remains the engine's default.
const group2Hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"

var group2, _ = new(big.Int).SetString(group2Hex, 16)

type MODP struct {
	x      *big.Int
	p      *big.Int
	Public []byte
}

type DH14 = MODP

func NewDH14(rng io.Reader) (*DH14, error) {
	return NewMODP(14, rng)
}

func NewMODP(group uint16, rng io.Reader) (*MODP, error) {
	var p *big.Int
	switch group {
	case 14:
		p = group14
	case 2:
		p = group2
	default:
		return nil, errors.New("unsupported MODP group")
	}
	if rng == nil {
		rng = rand.Reader
	}
	q := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1)
	x, e := rand.Int(rng, new(big.Int).Sub(q, big.NewInt(3)))
	if e != nil {
		return nil, e
	}
	x.Add(x, big.NewInt(2))
	pub := new(big.Int).Exp(big.NewInt(2), x, p)
	return &MODP{x: x, p: p, Public: pub.FillBytes(make([]byte, p.BitLen()/8))}, nil
}
func (d *MODP) Shared(peer []byte) ([]byte, error) {
	if len(peer) != len(d.Public) {
		return nil, errors.New("invalid MODP public length")
	}
	y := new(big.Int).SetBytes(peer)
	max := new(big.Int).Sub(d.p, big.NewInt(1))
	q := new(big.Int).Rsh(new(big.Int).Set(max), 1)
	if y.Cmp(big.NewInt(1)) <= 0 || y.Cmp(max) >= 0 || new(big.Int).Exp(y, q, d.p).Cmp(big.NewInt(1)) != 0 {
		return nil, errors.New("invalid MODP public value")
	}
	return new(big.Int).Exp(y, d.x, d.p).FillBytes(make([]byte, len(d.Public))), nil
}

type IKEKeys struct{ SKd, SKai, SKar, SKei, SKer, SKpi, SKpr []byte }

func DeriveIKE(p PRF, integ Integrity, encLen int, ni, nr, shared []byte, spii, spir uint64) (IKEKeys, error) {
	var z IKEKeys
	if len(ni) < 16 || len(nr) < 16 || integ.KeyLen() == 0 || (encLen != 16 && encLen != 24 && encLen != 32) {
		return z, errors.New("invalid IKE key derivation parameters")
	}
	nonce := append(append([]byte{}, ni...), nr...)
	seed := append([]byte{}, nonce...)
	seed = binary.BigEndian.AppendUint64(seed, spii)
	seed = binary.BigEndian.AppendUint64(seed, spir)
	skeyseed, e := p.Sum(nonce, shared)
	if e != nil {
		return z, e
	}
	n := 3*p.Size() + 2*integ.KeyLen() + 2*encLen
	material, e := p.Plus(skeyseed, seed, n)
	if e != nil {
		return z, e
	}
	take := func(n int) []byte { b := append([]byte{}, material[:n]...); material = material[n:]; return b }
	z = IKEKeys{take(p.Size()), take(integ.KeyLen()), take(integ.KeyLen()), take(encLen), take(encLen), take(p.Size()), take(p.Size())}
	return z, nil
}
