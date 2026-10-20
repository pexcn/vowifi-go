package eap

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	vc "github.com/iniwex5/vowifi-go/engine/crypto"
	"io"
	"sync"
	"time"
	"unicode/utf8"
)

type reauthState struct {
	identity string
	method   byte
	keys     Keys
	counter  uint16
	expires  time.Time
}

// ReauthContext is an in-memory, single-use credential cache. The host owns its
// subscription lifetime. It never serializes keys, and failed/uncertain uses
// discard the identity so the next session performs full AKA authentication.
type ReauthContext struct {
	mu      sync.Mutex
	binding string
	epoch   uint64
	busy    bool
	state   *reauthState
}

func cloneKeys(k Keys) Keys {
	return Keys{KEncr: bytes.Clone(k.KEncr), KAut: bytes.Clone(k.KAut), MSK: bytes.Clone(k.MSK), EMSK: bytes.Clone(k.EMSK), MK: bytes.Clone(k.MK), KRe: bytes.Clone(k.KRe)}
}
func clearReauth(state *reauthState) {
	if state == nil {
		return
	}
	for _, key := range [][]byte{state.keys.KEncr, state.keys.KAut, state.keys.MK, state.keys.KRe, state.keys.MSK, state.keys.EMSK} {
		clear(key)
	}
}
func (r *ReauthContext) Clear() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	clearReauth(r.state)
	r.state = nil
	r.busy = false
	r.epoch++
}
func (c *Client) initializeCache() {
	if c.cacheInitialized {
		return
	}
	c.cacheInitialized = true
	if c.Reauth == nil || c.Binding == "" {
		return
	}
	r := c.Reauth
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.busy {
		return
	}
	if r.binding != c.Binding {
		clearReauth(r.state)
		r.state = nil
		r.binding = c.Binding
	}
	r.busy = true
	r.epoch++
	c.cacheEpoch = r.epoch
	c.cacheLease = true
	if r.state != nil && time.Now().Before(r.state.expires) {
		v := *r.state
		v.keys = cloneKeys(v.keys)
		c.cached = &v
	}
}
func (c *Client) authenticationIdentity() string {
	if c.cached != nil && (c.method == 0 || c.method == c.cached.method) && (!c.RequirePrime || c.cached.method == AKAPrime) {
		c.usedCache = true
		return c.cached.identity
	}
	return c.Identity
}

// Commit must be called only after final IKE AUTH and Child SA validation.
func (c *Client) Commit() error {
	if !c.success {
		return errors.New("EAP success required before cache commit")
	}
	c.finishCache(true)
	return nil
}
func (c *Client) Close() { c.finishCache(false) }
func (c *Client) finishCache(commit bool) {
	if !c.cacheLease {
		return
	}
	c.cacheLease = false
	r := c.Reauth
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.epoch != c.cacheEpoch || !r.busy {
		return
	}
	if commit {
		clearReauth(r.state)
		r.state = c.pending
	} else if c.usedCache {
		clearReauth(r.state)
		r.state = nil
	}
	r.busy = false
	clearReauth(c.cached)
	if !commit {
		clearReauth(c.pending)
	}
	c.cached = nil
	c.pending = nil
}
func encryptedAttributes(p Packet, keys Keys) ([]Attribute, bool, error) {
	iv, hasIV := p.Get(ATIV)
	ct, hasCT := p.Get(ATEncrData)
	if !hasIV && !hasCT {
		return nil, false, nil
	}
	if !hasIV || !hasCT || len(iv) != 18 || len(ct) < 18 || (len(ct)-2)%16 != 0 {
		return nil, true, errors.New("invalid encrypted AKA attributes")
	}
	plain, err := vc.DecryptCBC(keys.KEncr, append(bytes.Clone(iv[2:]), ct[2:]...))
	if err != nil {
		return nil, true, err
	}
	defer clear(plain)
	wire := append([]byte{Request, 0, 0, 0, p.Type, Reauthentication, 0, 0}, plain...)
	binary.BigEndian.PutUint16(wire[2:], uint16(len(wire)))
	inner, err := Parse(wire)
	if err != nil {
		return nil, true, err
	}
	return inner.Attributes, true, nil
}
func encryptAttributes(method byte, attrs []Attribute, keys Keys, rng io.Reader) ([]Attribute, error) {
	p := Packet{Code: Response, Type: method, Subtype: Reauthentication, Attributes: attrs}
	b, err := p.Marshal()
	if err != nil {
		return nil, err
	}
	plain := b[8:]
	if pad := 16 - len(plain)%16; pad != 16 {
		plain = append(plain, 6, byte(pad/4))
		plain = append(plain, make([]byte, pad-2)...)
	}
	if rng == nil {
		rng = rand.Reader
	}
	ct, err := vc.EncryptCBC(keys.KEncr, plain, rng)
	if err != nil {
		return nil, err
	}
	return []Attribute{{ATIV, append([]byte{0, 0}, ct[:16]...)}, {ATEncrData, append([]byte{0, 0}, ct[16:]...)}}, nil
}
func nextReauthIdentity(attrs []Attribute) (string, error) {
	for _, a := range attrs {
		if a.Type == 133 {
			if len(a.Value) < 2 {
				return "", errors.New("invalid reauth identity")
			}
			n := int(binary.BigEndian.Uint16(a.Value))
			if n == 0 || n > 1024 || n > len(a.Value)-2 || !utf8.Valid(a.Value[2:2+n]) {
				return "", errors.New("invalid reauth identity")
			}
			for _, v := range a.Value[2 : 2+n] {
				if v <= 32 || v == 127 {
					return "", errors.New("invalid reauth identity")
				}
			}
			for _, v := range a.Value[2+n:] {
				if v != 0 {
					return "", errors.New("invalid reauth identity padding")
				}
			}
			return string(a.Value[2 : 2+n]), nil
		}
	}
	return "", nil
}
func (c *Client) captureReauth(p Packet, keys Keys) error {
	attrs, _, err := encryptedAttributes(p, keys)
	if err != nil {
		return err
	}
	identity, err := nextReauthIdentity(attrs)
	if err != nil {
		return err
	}
	if identity != "" {
		c.pending = &reauthState{identity: identity, method: p.Type, keys: cloneKeys(keys), expires: time.Now().Add(30 * time.Minute)}
	} else {
		c.pending = nil
	}
	return nil
}
func deriveReauthKeys(identity string, keys Keys, counter uint16, nonce []byte) (Keys, error) {
	if len(nonce) != 16 {
		return Keys{}, errors.New("invalid reauth nonce")
	}
	counterBytes := binary.BigEndian.AppendUint16(nil, counter)
	var stream []byte
	var err error
	if len(keys.KRe) == 32 {
		seed := append([]byte("EAP-AKA' re-auth"), []byte(identity)...)
		seed = append(seed, counterBytes...)
		seed = append(seed, nonce...)
		stream, err = vc.PRFSHA256.Plus(keys.KRe, seed, 128)
	} else if len(keys.MK) == 20 {
		seed := append([]byte(identity), counterBytes...)
		seed = append(seed, nonce...)
		seed = append(seed, keys.MK...)
		sum := sha1.Sum(seed)
		stream, err = FIPS186PRF(sum[:], 128)
	} else {
		return Keys{}, errors.New("invalid reauth key context")
	}
	if err != nil {
		return Keys{}, err
	}
	out := cloneKeys(keys)
	out.MSK, out.EMSK = stream[:64], stream[64:]
	return out, nil
}
func (c *Client) handleReauthentication(p Packet, raw []byte) ([]byte, bool, error) {
	if len(c.reauthRequest) > 0 && p.Identifier == c.reauthRequest[1] {
		if !bytes.Equal(raw, c.reauthRequest) {
			return nil, false, errors.New("changed reauth retransmission")
		}
		return bytes.Clone(c.reauthResponse), false, nil
	}
	if c.challenged || c.cached == nil || c.cached.method != p.Type || !c.usedCache {
		return nil, false, errors.New("reauth context unavailable")
	}
	keys := c.cached.keys
	if err := VerifyMAC(keys.KAut, raw, nil); err != nil {
		return nil, false, err
	}
	attrs, present, err := encryptedAttributes(p, keys)
	if err != nil || !present {
		if err == nil {
			err = errors.New("reauth attributes must be encrypted")
		}
		return nil, false, err
	}
	inner := Packet{Attributes: attrs}
	cv, ok := inner.Get(ATCounter)
	nonce, hasNonce := inner.Get(ATNonceS)
	if !ok || len(cv) != 2 || !hasNonce || len(nonce) != 18 {
		return nil, false, errors.New("missing reauth counter or nonce")
	}
	counter := binary.BigEndian.Uint16(cv)
	stale := counter <= c.cached.counter
	responseAttrs := []Attribute{{ATCounter, bytes.Clone(cv)}}
	if stale {
		responseAttrs = append(responseAttrs, Attribute{ATCounterTooSmall, []byte{0, 0}})
	}
	encrypted, err := encryptAttributes(p.Type, responseAttrs, keys, c.Random)
	if err != nil {
		return nil, false, err
	}
	reply := Packet{Code: Response, Identifier: p.Identifier, Type: p.Type, Subtype: Reauthentication, Attributes: encrypted}
	if _, ok := p.Get(135); ok && !stale {
		c.protectedResult = true
		reply.Attributes = append(reply.Attributes, Attribute{135, []byte{0, 0}})
	}
	reply.Attributes = append(reply.Attributes, Attribute{ATMAC, make([]byte, 18)})
	wire, err := SignExtra(keys.KAut, reply, nonce[2:])
	if err != nil {
		return nil, false, err
	}
	if stale {
		c.pending = nil
		c.cached = nil
		return wire, false, nil
	}
	next, err := deriveReauthKeys(c.cached.identity, keys, counter, nonce[2:])
	if err != nil {
		return nil, false, err
	}
	nextID, err := nextReauthIdentity(attrs)
	if err != nil {
		return nil, false, err
	}
	if nextID != "" {
		c.pending = &reauthState{identity: nextID, method: p.Type, keys: cloneKeys(next), counter: counter, expires: c.cached.expires}
	} else {
		c.pending = nil
	}
	c.Keys = &next
	c.challenged = true
	c.reauthRequest = bytes.Clone(raw)
	c.reauthResponse = bytes.Clone(wire)
	return wire, false, nil
}
