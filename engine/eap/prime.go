package eap

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	vc "github.com/iniwex5/vowifi-go/engine/crypto"
	"unicode/utf8"
)

func DerivePrimeKeys(identity, network string, autn, ik, ck []byte) (Keys, error) {
	if identity == "" || network == "" || !utf8.ValidString(network) || len(network) > 65535 || len(autn) != 16 || autn[6]&0x80 == 0 || len(ik) != 16 || len(ck) != 16 {
		return Keys{}, errors.New("invalid AKA-prime key material")
	}
	input := append([]byte{0x20}, []byte(network)...)
	input = binary.BigEndian.AppendUint16(input, uint16(len(network)))
	input = append(input, autn[:6]...)
	input = binary.BigEndian.AppendUint16(input, 6)
	h := hmac.New(sha256.New, append(append([]byte{}, ck...), ik...))
	h.Write(input)
	prime := h.Sum(nil)
	defer clear(prime)
	// 3GPP KDF yields CK' | IK'; RFC 5448 PRF' is keyed by IK' | CK'.
	key := append(append([]byte{}, prime[16:]...), prime[:16]...)
	defer clear(key)
	stream, err := vc.PRFSHA256.Plus(key, append([]byte("EAP-AKA'"), []byte(identity)...), 208)
	if err != nil {
		return Keys{}, err
	}
	return Keys{KEncr: stream[:16], KAut: stream[16:48], KRe: stream[48:80], MSK: stream[80:144], EMSK: stream[144:208]}, nil
}
func (c *Client) negotiateKDF(p Packet) ([]byte, bool, error) {
	var values []uint16
	for _, a := range p.Attributes {
		if a.Type == ATKDF {
			if len(a.Value) != 2 {
				return nil, false, errors.New("invalid AT_KDF")
			}
			values = append(values, binary.BigEndian.Uint16(a.Value))
		}
	}
	if len(values) == 0 {
		return nil, false, errors.New("missing AT_KDF")
	}
	if len(c.kdfOffer) > 0 {
		if len(values) != len(c.kdfOffer)+1 || values[0] != 1 {
			return nil, false, errors.New("AKA-prime KDF negotiation changed")
		}
		for i, v := range c.kdfOffer {
			if values[i+1] != v {
				return nil, false, errors.New("AKA-prime KDF offer changed")
			}
		}
	} else {
		seen := map[uint16]bool{}
		hasSupported := false
		for _, v := range values {
			if seen[v] || v == 0 {
				return nil, false, errors.New("duplicate or invalid AT_KDF")
			}
			seen[v] = true
			hasSupported = hasSupported || v == 1
		}
		if values[0] != 1 {
			if !hasSupported || c.kdfSelected {
				return nil, false, errors.New("no acceptable AKA-prime KDF")
			}
			c.kdfOffer = append([]uint16{}, values...)
			b, err := (Packet{Code: Response, Identifier: p.Identifier, Type: AKAPrime, Subtype: Challenge, Attributes: []Attribute{{ATKDF, []byte{0, 1}}}}).Marshal()
			return b, true, err
		}
	}
	network, ok := p.Get(ATKDFInput)
	if !ok || len(network) < 2 {
		return nil, false, errors.New("missing AKA-prime network name")
	}
	n := int(binary.BigEndian.Uint16(network))
	if n == 0 || n > len(network)-2 || !utf8.Valid(network[2:2+n]) {
		return nil, false, errors.New("invalid AKA-prime network name")
	}
	if !hmac.Equal(network[2:2+n], []byte(c.PrimeNetworkName)) {
		return nil, false, errors.New("AKA-prime network binding mismatch")
	}
	for _, v := range network[2+n:] {
		if v != 0 {
			return nil, false, errors.New("nonzero network-name padding")
		}
	}
	c.kdfSelected = true
	return nil, false, nil
}
