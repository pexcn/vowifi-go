// Package eap implements authenticated EAP-AKA and EAP-AKA-prime exchanges.
package eap

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/iniwex5/vowifi-go/engine/sim"
	"io"
	"math/bits"
)

const (
	Request  byte = 1
	Response byte = 2
	Success  byte = 3
	Failure  byte = 4
	Identity byte = 1
	AKA      byte = 23
	AKAPrime byte = 50
)
const (
	Challenge              byte = 1
	AuthenticationReject   byte = 2
	SynchronizationFailure byte = 4
	AKAIdentity            byte = 5
	Notification           byte = 12
	ClientError            byte = 14
	Reauthentication       byte = 13
)
const (
	ATRAND            byte = 1
	ATAUTN            byte = 2
	ATRES             byte = 3
	ATAUTS            byte = 4
	ATMAC             byte = 11
	ATIdentity        byte = 14
	ATNotification    byte = 12
	ATIV              byte = 129
	ATEncrData        byte = 130
	ATCheckcode       byte = 134
	ATKDFInput        byte = 23
	ATKDF             byte = 24
	ATCounter         byte = 19
	ATCounterTooSmall byte = 20
	ATNonceS          byte = 21
	ATBidding         byte = 136
)

type Attribute struct {
	Type  byte
	Value []byte
}
type Packet struct {
	Code, Identifier, Type, Subtype byte
	Data                            []byte
	Attributes                      []Attribute
}

func Parse(b []byte) (Packet, error) {
	var p Packet
	if len(b) < 4 || int(binary.BigEndian.Uint16(b[2:])) != len(b) {
		return p, errors.New("invalid EAP length")
	}
	p.Code = b[0]
	p.Identifier = b[1]
	if p.Code == Success || p.Code == Failure {
		if len(b) != 4 {
			return p, errors.New("trailing EAP result bytes")
		}
		return p, nil
	}
	if p.Code != Request && p.Code != Response || len(b) < 5 {
		return p, errors.New("invalid EAP code")
	}
	p.Type = b[4]
	if p.Type != AKA && p.Type != AKAPrime {
		p.Data = append([]byte{}, b[5:]...)
		return p, nil
	}
	if len(b) < 8 || b[6] != 0 || b[7] != 0 {
		return p, errors.New("invalid EAP-AKA header")
	}
	p.Subtype = b[5]
	a := b[8:]
	for len(a) > 0 {
		if len(p.Attributes) >= 256 {
			return p, errors.New("too many AKA attributes")
		}
		if len(a) < 2 || a[1] == 0 || int(a[1])*4 > len(a) {
			return p, errors.New("invalid EAP-AKA attribute")
		}
		n := int(a[1]) * 4
		for _, v := range p.Attributes {
			if v.Type == a[0] && !(p.Type == AKAPrime && a[0] == ATKDF) {
				return p, fmt.Errorf("duplicate AKA attribute %d", a[0])
			}
		}
		switch a[0] {
		case ATRAND, ATAUTN, ATMAC, ATNonceS:
			if n != 20 {
				return p, errors.New("wrong AKA fixed attribute length")
			}
		case ATRES:
			if n < 8 {
				return p, errors.New("truncated AT_RES")
			}
			l := int(binary.BigEndian.Uint16(a[2:]))
			if l < 32 || l > 128 || l%8 != 0 || 4+l/8 > n {
				return p, errors.New("invalid RES bits")
			}
		case ATAUTS:
			if n != 16 {
				return p, errors.New("invalid AUTS")
			}
		case 6:
			if n < 4 {
				return p, errors.New("invalid AKA padding")
			}
			for _, v := range a[2:n] {
				if v != 0 {
					return p, errors.New("nonzero AKA padding")
				}
			}
		case ATNotification, 10, 13, 17, 19, 20, 22, 24, 135, 136:
			if n != 4 {
				return p, errors.New("invalid AKA flag attribute")
			}
		case ATCheckcode:
			expected := 24
			if p.Type == AKAPrime {
				expected = 36
			}
			if n != 4 && n != expected {
				return p, errors.New("invalid AT_CHECKCODE length")
			}
		case ATIdentity, ATIV, ATEncrData, ATKDFInput, 132, 133:
		default:
			if a[0] < 128 {
				return p, fmt.Errorf("unknown mandatory AKA attribute %d", a[0])
			}
		}
		p.Attributes = append(p.Attributes, Attribute{a[0], append([]byte{}, a[2:n]...)})
		a = a[n:]
	}
	return p, nil
}
func (p Packet) Marshal() ([]byte, error) {
	b := []byte{p.Code, p.Identifier, 0, 0}
	if p.Code == Success || p.Code == Failure {
		binary.BigEndian.PutUint16(b[2:], 4)
		return b, nil
	}
	b = append(b, p.Type)
	if p.Type == AKA || p.Type == AKAPrime {
		b = append(b, p.Subtype, 0, 0)
		for _, a := range p.Attributes {
			n := len(a.Value) + 2
			pad := (4 - n%4) % 4
			n += pad
			if n/4 > 255 {
				return nil, errors.New("AKA attribute too large")
			}
			b = append(b, a.Type, byte(n/4))
			b = append(b, a.Value...)
			b = append(b, make([]byte, pad)...)
		}
	} else {
		b = append(b, p.Data...)
	}
	if len(b) > 65535 {
		return nil, errors.New("EAP too large")
	}
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b, nil
}
func (p Packet) Get(t byte) ([]byte, bool) {
	for _, a := range p.Attributes {
		if a.Type == t {
			return a.Value, true
		}
	}
	return nil, false
}

// MAC is calculated over the original EAP bytes with AT_MAC cleared (RFC 4187 10.15).
func MAC(key, packet, extra []byte) ([]byte, error) {
	p, e := Parse(packet)
	if e != nil {
		return nil, e
	}
	if p.Type != AKA && p.Type != AKAPrime {
		return nil, errors.New("not an AKA method")
	}
	if p.Type == AKA && len(key) != 16 || p.Type == AKAPrime && len(key) != 32 {
		return nil, errors.New("invalid AKA MAC key length")
	}
	copyPacket := append([]byte{}, packet...)
	found := false
	for i := 8; i < len(copyPacket); {
		n := int(copyPacket[i+1]) * 4
		if copyPacket[i] == ATMAC {
			for j := i + 4; j < i+20; j++ {
				copyPacket[j] = 0
			}
			found = true
		}
		i += n
	}
	if !found {
		return nil, errors.New("missing AT_MAC")
	}
	factory := sha1.New
	if p.Type == AKAPrime {
		factory = sha256.New
	}
	h := hmac.New(factory, key)
	h.Write(copyPacket)
	h.Write(extra)
	return h.Sum(nil)[:16], nil
}
func VerifyMAC(key, packet, extra []byte) error {
	p, e := Parse(packet)
	if e != nil {
		return e
	}
	v, ok := p.Get(ATMAC)
	if !ok || len(v) != 18 || v[0] != 0 || v[1] != 0 {
		return errors.New("invalid AT_MAC")
	}
	m, e := MAC(key, packet, extra)
	if e != nil {
		return e
	}
	if !hmac.Equal(m, v[2:]) {
		return errors.New("EAP-AKA server MAC verification failed")
	}
	return nil
}
func Sign(key []byte, p Packet) ([]byte, error) { return SignExtra(key, p, nil) }
func SignExtra(key []byte, p Packet, extra []byte) ([]byte, error) {
	b, e := p.Marshal()
	if e != nil {
		return nil, e
	}
	m, e := MAC(key, b, extra)
	if e != nil {
		return nil, e
	}
	for i := 8; i < len(b); {
		n := int(b[i+1]) * 4
		if b[i] == ATMAC {
			copy(b[i+4:i+20], m)
			break
		}
		i += n
	}
	return b, nil
}

// FIPS186PRF implements the EAP-AKA variant of FIPS 186-2 (RFC 4187 section 7).
// G is the SHA-1 compression function with IV and NO SHA-1 message padding.
func FIPS186PRF(seed []byte, n int) ([]byte, error) {
	if len(seed) != 20 || n < 0 || n > 4096 {
		return nil, errors.New("invalid FIPS 186-2 input")
	}
	x := append([]byte{}, seed...)
	out := []byte{}
	for len(out) < n {
		var block [64]byte
		copy(block[:], x)
		v := sha1Compress(block)
		out = append(out, v...)
		carry := uint16(1)
		for j := 19; j >= 0; j-- {
			s := uint16(x[j]) + uint16(v[j]) + carry
			x[j] = byte(s)
			carry = s >> 8
		}
	}
	return out[:n], nil
}
func sha1Compress(b [64]byte) []byte {
	var w [80]uint32
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(b[i*4:])
	}
	for i := 16; i < 80; i++ {
		w[i] = bits.RotateLeft32(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1)
	}
	h := [5]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}
	a, c0, c, d, e := h[0], h[1], h[2], h[3], h[4]
	for i := 0; i < 80; i++ {
		var f, k uint32
		switch {
		case i < 20:
			f = (c0 & c) | (^c0 & d)
			k = 0x5a827999
		case i < 40:
			f = c0 ^ c ^ d
			k = 0x6ed9eba1
		case i < 60:
			f = (c0 & c) | (c0 & d) | (c & d)
			k = 0x8f1bbcdc
		default:
			f = c0 ^ c ^ d
			k = 0xca62c1d6
		}
		t := bits.RotateLeft32(a, 5) + f + e + k + w[i]
		e = d
		d = c
		c = bits.RotateLeft32(c0, 30)
		c0 = a
		a = t
	}
	v := []uint32{h[0] + a, h[1] + c0, h[2] + c, h[3] + d, h[4] + e}
	out := make([]byte, 20)
	for i, n := range v {
		binary.BigEndian.PutUint32(out[i*4:], n)
	}
	return out
}

type Keys struct {
	KEncr, KAut, MSK, EMSK []byte
	MK, KRe                []byte
}

func DeriveKeys(identity string, ik, ck []byte) (Keys, error) {
	if identity == "" || len(ik) != 16 || len(ck) != 16 {
		return Keys{}, errors.New("invalid AKA key material")
	}
	h := sha1.New()
	h.Write([]byte(identity))
	h.Write(ik)
	h.Write(ck)
	b, e := FIPS186PRF(h.Sum(nil), 160)
	if e != nil {
		return Keys{}, e
	}
	return Keys{KEncr: b[:16], KAut: b[16:32], MSK: b[32:96], EMSK: b[96:160], MK: h.Sum(nil)}, nil
}

type Client struct {
	// PrimeNetworkName is a local pin, never learned from an untrusted request.
	PrimeNetworkName              string
	RequirePrime                  bool
	Reauth                        *ReauthContext
	Binding                       string
	method                        byte
	kdfOffer                      []uint16
	kdfSelected                   bool
	success                       bool
	cacheInitialized, cacheLease  bool
	cacheEpoch                    uint64
	usedCache                     bool
	usedIdentity                  string
	Random                        io.Reader
	cached, pending               *reauthState
	reauthRequest, reauthResponse []byte
	Identity                      string
	Provider                      sim.AKAProvider
	Preference                    string
	// ChallengeMode controls only the optional response AT_CHECKCODE: minimal
	// echoes a verified server offer, checkcode always includes it, omit never
	// includes it. Every offered server checkcode is verified in all modes.
	ChallengeMode                                   string
	Keys                                            *Keys
	challenged                                      bool
	protectedResult                                 bool
	lastIdentifier                                  byte
	haveIdentifier                                  bool
	identityTranscript                              []byte
	pendingIdentityRequest, pendingIdentityResponse []byte
	identityNeedsCheckcode                          bool
}

func (c *Client) calculate(rand, autn []byte) (sim.AKAResult, error) {
	if p, ok := c.Provider.(sim.AKAWithPreferenceProvider); ok {
		return p.CalculateAKAWithPreference(rand, autn, c.Preference)
	}
	if c.Preference == "isim_strict" {
		p, ok := c.Provider.(sim.ISIMAKAProvider)
		if !ok {
			return sim.AKAResult{}, errors.New("strict ISIM provider unavailable")
		}
		return p.CalculateISIMAKA(rand, autn)
	}
	return c.Provider.CalculateAKA(rand, autn)
}
func (c *Client) Handle(ctx context.Context, b []byte) (replyBytes []byte, done bool, err error) {
	defer func() {
		if err == nil && len(replyBytes) >= 4 {
			c.lastIdentifier = replyBytes[1]
			c.haveIdentifier = true
		}
	}()
	if c.ChallengeMode != "" && c.ChallengeMode != "minimal" && c.ChallengeMode != "omit" && c.ChallengeMode != "checkcode" {
		return nil, false, errors.New("unsupported AKA challenge mode")
	}
	if e := ctx.Err(); e != nil {
		return nil, false, e
	}
	p, e := Parse(b)
	if e != nil {
		return nil, false, e
	}
	if p.Code == Failure {
		return nil, false, errors.New("EAP authentication failed")
	}
	if p.Code == Success {
		if !c.challenged || c.Keys == nil || !c.haveIdentifier || p.Identifier != c.lastIdentifier {
			return nil, false, errors.New("premature EAP success")
		}
		if c.protectedResult {
			return nil, false, errors.New("protected AKA result was not acknowledged")
		}
		c.success = true
		return nil, true, nil
	}
	if p.Code != Request {
		return nil, false, errors.New("expected EAP request")
	}
	c.initializeCache()
	if p.Type == Identity {
		if c.challenged {
			return nil, false, errors.New("identity request after AKA challenge")
		}
		identity := c.authenticationIdentity()
		c.usedIdentity = identity
		returnPacket := Packet{Code: Response, Identifier: p.Identifier, Type: Identity, Data: []byte(identity)}
		r, e := returnPacket.Marshal()
		return r, false, e
	}
	if p.Type != AKA && p.Type != AKAPrime {
		return nil, false, errors.New("unsupported EAP method")
	}
	if c.method != 0 && c.method != p.Type {
		return nil, false, errors.New("AKA method changed during authentication")
	}
	if p.Type == AKAPrime && c.PrimeNetworkName == "" {
		return nil, false, errors.New("AKA-prime network binding not configured")
	}
	if c.RequirePrime && p.Type != AKAPrime {
		return nil, false, errors.New("AKA-prime is required")
	}
	c.method = p.Type
	reply := Packet{Code: Response, Identifier: p.Identifier, Type: p.Type, Subtype: p.Subtype}
	switch p.Subtype {
	case AKAIdentity:
		if c.challenged {
			return nil, false, errors.New("AKA identity after challenge")
		}
		if len(c.pendingIdentityRequest) > 0 {
			if p.Identifier == c.pendingIdentityRequest[1] {
				if !hmac.Equal(b, c.pendingIdentityRequest) {
					return nil, false, errors.New("changed retransmitted AKA identity request")
				}
				return append([]byte{}, c.pendingIdentityResponse...), false, nil
			}
			c.commitIdentityPair()
		}
		for _, attribute := range p.Attributes {
			if attribute.Type != 10 && attribute.Type != 13 && attribute.Type != 17 {
				c.identityNeedsCheckcode = true
			}
		}
		identity := c.authenticationIdentity()
		for _, a := range p.Attributes {
			if a.Type == 10 || a.Type == 17 {
				identity = c.Identity
				c.cached = nil
			}
		}
		c.usedIdentity = identity
		reply.Attributes = []Attribute{{ATIdentity, append(binary.BigEndian.AppendUint16(nil, uint16(len(identity))), []byte(identity)...)}}
		r, e := reply.Marshal()
		if e == nil {
			c.pendingIdentityRequest = append([]byte{}, b...)
			c.pendingIdentityResponse = append([]byte{}, r...)
		}
		return r, false, e
	case Reauthentication:
		return c.handleReauthentication(p, b)
	case Challenge:
		c.commitIdentityPair()
		if p.Type == AKAPrime {
			if r, negotiating, err := c.negotiateKDF(p); err != nil || negotiating {
				return r, false, err
			}
		}
		if c.Provider == nil {
			return nil, false, errors.New("missing AKA provider")
		}
		if c.challenged {
			return nil, false, errors.New("unexpected repeated AKA challenge")
		}
		randv, ok := p.Get(ATRAND)
		autn, ok2 := p.Get(ATAUTN)
		if !ok || !ok2 || len(randv) != 18 || len(autn) != 18 || randv[0] != 0 || randv[1] != 0 || autn[0] != 0 || autn[1] != 0 {
			return nil, false, errors.New("missing or invalid AKA RAND/AUTN")
		}
		if p.Type == AKAPrime && autn[8]&0x80 == 0 {
			return nil, false, errors.New("AKA-prime AMF separation bit missing")
		}
		res, err := c.calculate(randv[2:], autn[2:])
		if err != nil {
			if errors.Is(err, sim.ErrSyncFailure) && len(res.AUTS) == 14 {
				reply.Subtype = SynchronizationFailure
				reply.Attributes = []Attribute{{ATAUTS, res.AUTS}}
				r, e := reply.Marshal()
				return r, false, e
			}
			return nil, false, err
		}
		if len(res.RES) < 4 || len(res.RES) > 16 {
			return nil, false, errors.New("invalid SIM RES")
		}
		identity := c.usedIdentity
		if identity == "" {
			identity = c.Identity
		}
		keys, e := DeriveKeys(identity, res.IK, res.CK)
		if p.Type == AKAPrime {
			keys, e = DerivePrimeKeys(identity, c.PrimeNetworkName, autn[2:], res.IK, res.CK)
		}
		if e != nil {
			return nil, false, e
		}
		if e = VerifyMAC(keys.KAut, b, nil); e != nil {
			return nil, false, e
		}
		if bid, ok := p.Get(ATBidding); ok && p.Type == AKA && len(bid) == 2 && bid[0]&0x80 != 0 && c.PrimeNetworkName != "" {
			return nil, false, errors.New("authenticated AKA bidding-down detected")
		}
		checkcode, hasCheckcode := p.Get(ATCheckcode)
		if c.identityNeedsCheckcode && !hasCheckcode {
			return nil, false, errors.New("missing AT_CHECKCODE after extended AKA identity")
		}
		if hasCheckcode && !hmac.Equal(checkcode[2:], c.checkcode()) {
			return nil, false, errors.New("EAP-AKA identity checkcode mismatch")
		}
		if c.ChallengeMode == "checkcode" || c.ChallengeMode != "omit" && hasCheckcode {
			reply.Attributes = append(reply.Attributes, Attribute{ATCheckcode, append([]byte{0, 0}, c.checkcode()...)})
		}
		iv, hasIV := p.Get(ATIV)
		encrypted, hasEncrypted := p.Get(ATEncrData)
		if hasIV != hasEncrypted {
			return nil, false, errors.New("AKA AT_IV and AT_ENCR_DATA must occur together")
		}
		if hasIV && (len(iv) != 18 || len(encrypted) < 18 || (len(encrypted)-2)%16 != 0) {
			return nil, false, errors.New("invalid AKA encrypted identity attribute length")
		}
		// RFC 4187 4.1.1.8 permits ignoring optional encrypted identities and
		// continuing with the permanent identity. Match the original full-AKA
		// path: authenticate the entire request above, but do not adopt a
		// pseudonym or fast-reauth identity until their lifecycles are supported.
		// The two reserved bytes in IV/encrypted data are ignored (10.12).
		if c.Reauth != nil {
			if err := c.captureReauth(p, keys); err != nil {
				return nil, false, err
			}
		}
		if _, ok = p.Get(135); ok {
			c.protectedResult = true
			reply.Attributes = append(reply.Attributes, Attribute{135, []byte{0, 0}})
		}
		reply.Attributes = append(reply.Attributes, Attribute{ATRES, append(binary.BigEndian.AppendUint16(nil, uint16(len(res.RES)*8)), res.RES...)}, Attribute{ATMAC, make([]byte, 18)})
		c.Keys = &keys
		c.challenged = true
		r, e := Sign(keys.KAut, reply)
		return r, false, e
	case Notification:
		v, ok := p.Get(ATNotification)
		if !ok || len(v) != 2 {
			return nil, false, errors.New("invalid AKA notification")
		}
		code := binary.BigEndian.Uint16(v)
		if code != 32768 || c.Keys == nil || !c.challenged || !c.protectedResult {
			return nil, false, fmt.Errorf("AKA notification %d", code)
		}
		if e = VerifyMAC(c.Keys.KAut, b, nil); e != nil {
			return nil, false, e
		}
		reply.Attributes = []Attribute{{ATMAC, make([]byte, 18)}}
		c.protectedResult = false
		r, e := Sign(c.Keys.KAut, reply)
		return r, false, e
	default:
		return nil, false, fmt.Errorf("unsupported AKA subtype %d", p.Subtype)
	}
}

// RFC4187 section10.13 counts only completed AKA-Identity round trips. A
// subsequent challenge/different-ID identity request acknowledges the last pair.
func (c *Client) commitIdentityPair() {
	if len(c.pendingIdentityRequest) == 0 {
		return
	}
	c.identityTranscript = append(c.identityTranscript, c.pendingIdentityRequest...)
	c.identityTranscript = append(c.identityTranscript, c.pendingIdentityResponse...)
	c.pendingIdentityRequest = nil
	c.pendingIdentityResponse = nil
}
func (c *Client) checkcode() []byte {
	if len(c.identityTranscript) == 0 {
		return nil
	}
	if c.method == AKAPrime {
		h := sha256.Sum256(c.identityTranscript)
		return h[:]
	}
	h := sha1.Sum(c.identityTranscript)
	return h[:]
}
