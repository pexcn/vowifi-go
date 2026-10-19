// Package ikev2 provides strict RFC 7296 wire codecs. Unknown critical payloads fail closed.
package ikev2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	SA     byte = 33
	KE     byte = 34
	IDi    byte = 35
	IDr    byte = 36
	CERT   byte = 37
	AUTH   byte = 39
	Nonce  byte = 40
	Notify byte = 41
	Delete byte = 42
	TSi    byte = 44
	TSr    byte = 45
	SK     byte = 46
	CP     byte = 47
	EAP    byte = 48
)
const (
	SAInit        byte = 34
	IKEAuth       byte = 35
	CreateChildSA byte = 36
	Informational byte = 37
)
const (
	FlagInitiator byte = 8
	FlagResponse  byte = 32
)

type Header struct {
	InitiatorSPI, ResponderSPI            uint64
	NextPayload, Version, Exchange, Flags byte
	MessageID                             uint32
}
type Payload struct {
	Type     byte
	Critical bool
	Data     []byte
}
type Message struct {
	Header   Header
	Payloads []Payload
}

func (h Header) Marshal(body []byte) []byte {
	b := make([]byte, 28, len(body)+28)
	binary.BigEndian.PutUint64(b, h.InitiatorSPI)
	binary.BigEndian.PutUint64(b[8:], h.ResponderSPI)
	b[16] = h.NextPayload
	b[17] = 0x20
	b[18] = h.Exchange
	b[19] = h.Flags
	binary.BigEndian.PutUint32(b[20:], h.MessageID)
	binary.BigEndian.PutUint32(b[24:], uint32(28+len(body)))
	return append(b, body...)
}
func ParseHeader(b []byte) (Header, error) {
	if len(b) < 28 || b[17]>>4 != 2 || binary.BigEndian.Uint32(b[24:]) != uint32(len(b)) {
		return Header{}, errors.New("invalid IKE header")
	}
	return Header{binary.BigEndian.Uint64(b), binary.BigEndian.Uint64(b[8:]), b[16], b[17], b[18], b[19], binary.BigEndian.Uint32(b[20:])}, nil
}
func EncodePayloads(ps []Payload) (byte, []byte, error) {
	if len(ps) == 0 {
		return 0, nil, nil
	}
	out := []byte{}
	for i, p := range ps {
		if len(p.Data) > 65531 {
			return 0, nil, errors.New("IKE payload too large")
		}
		next := byte(0)
		if i+1 < len(ps) {
			next = ps[i+1].Type
		}
		flags := byte(0)
		if p.Critical {
			flags = 128
		}
		out = append(out, next, flags, byte((len(p.Data)+4)>>8), byte(len(p.Data)+4))
		out = append(out, p.Data...)
	}
	return ps[0].Type, out, nil
}
func ParsePayloads(first byte, b []byte) ([]Payload, error) {
	var ps []Payload
	for first != 0 {
		if len(ps) >= 128 || len(b) < 4 {
			return nil, errors.New("truncated/too many IKE payloads")
		}
		n := int(binary.BigEndian.Uint16(b[2:]))
		if n < 4 || n > len(b) {
			return nil, errors.New("invalid IKE payload length")
		}
		if b[1]&0x7f != 0 {
			return nil, errors.New("reserved payload flags")
		}
		switch first {
		case SA, KE, IDi, IDr, CERT, 38, AUTH, Nonce, Notify, Delete, 43, TSi, TSr, SK, CP, EAP:
		default:
			if b[1]&128 != 0 {
				return nil, fmt.Errorf("unknown critical payload %d", first)
			}
		}
		ps = append(ps, Payload{first, b[1]&128 != 0, append([]byte{}, b[4:n]...)})
		if first == SK {
			return nil, errors.New("encrypted payload requires authenticated decryption")
		}
		first = b[0]
		b = b[n:]
	}
	if len(b) != 0 {
		return nil, errors.New("trailing IKE bytes")
	}
	return ps, nil
}
func (m Message) Marshal() ([]byte, error) {
	first, b, e := EncodePayloads(m.Payloads)
	if e != nil {
		return nil, e
	}
	m.Header.NextPayload = first
	return m.Header.Marshal(b), nil
}
func Parse(b []byte) (Message, error) {
	h, e := ParseHeader(b)
	if e != nil {
		return Message{}, e
	}
	ps, e := ParsePayloads(h.NextPayload, b[28:])
	return Message{h, ps}, e
}
func Find(ps []Payload, typ byte) ([]byte, bool) {
	for _, p := range ps {
		if p.Type == typ {
			return p.Data, true
		}
	}
	return nil, false
}
func One(ps []Payload, typ byte) ([]byte, error) {
	var found []byte
	n := 0
	for _, p := range ps {
		if p.Type == typ {
			found = p.Data
			n++
		}
	}
	if n != 1 {
		return nil, fmt.Errorf("expected one payload %d, got %d", typ, n)
	}
	return found, nil
}

type Transform struct {
	Type    byte
	ID      uint16
	KeyBits uint16
}
type Proposal struct {
	Number, Protocol byte
	SPI              []byte
	Transforms       []Transform
}

func EncodeProposals(ps []Proposal) ([]byte, error) {
	var out []byte
	for i, p := range ps {
		if len(p.SPI) > 255 || len(p.Transforms) == 0 || len(p.Transforms) > 255 {
			return nil, errors.New("invalid proposal")
		}
		b := []byte{0, 0, 0, 0, p.Number, p.Protocol, byte(len(p.SPI)), byte(len(p.Transforms))}
		if i+1 < len(ps) {
			b[0] = 2
		}
		b = append(b, p.SPI...)
		for j, t := range p.Transforms {
			x := []byte{0, 0, 0, 8, t.Type, 0, byte(t.ID >> 8), byte(t.ID)}
			if j+1 < len(p.Transforms) {
				x[0] = 3
			}
			if t.KeyBits != 0 {
				x[3] = 12
				x = append(x, 0x80, 14, byte(t.KeyBits>>8), byte(t.KeyBits))
			}
			b = append(b, x...)
		}
		if len(b) > 65535 {
			return nil, errors.New("proposal too large")
		}
		binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
		out = append(out, b...)
	}
	return out, nil
}
func ParseProposals(b []byte) ([]Proposal, error) {
	var out []Proposal
	for len(b) > 0 {
		if len(out) >= 32 || len(b) < 8 {
			return nil, errors.New("invalid proposal header")
		}
		n := int(binary.BigEndian.Uint16(b[2:]))
		sn := int(b[6])
		if n < 8+sn || n > len(b) || b[1] != 0 || (b[0] != 0 && b[0] != 2) {
			return nil, errors.New("invalid proposal length/flags")
		}
		p := Proposal{Number: b[4], Protocol: b[5], SPI: append([]byte{}, b[8:8+sn]...)}
		ts := b[8+sn : n]
		for len(ts) > 0 {
			if len(ts) < 8 {
				return nil, errors.New("truncated transform")
			}
			tn := int(binary.BigEndian.Uint16(ts[2:]))
			if tn < 8 || tn > len(ts) || ts[1] != 0 || ts[5] != 0 || (ts[0] != 0 && ts[0] != 3) {
				return nil, errors.New("invalid transform")
			}
			t := Transform{Type: ts[4], ID: binary.BigEndian.Uint16(ts[6:])}
			attrs := ts[8:tn]
			for len(attrs) > 0 {
				if len(attrs) < 4 {
					return nil, errors.New("invalid transform attribute")
				}
				k := binary.BigEndian.Uint16(attrs)
				v := binary.BigEndian.Uint16(attrs[2:])
				if k == 0x800e {
					if t.KeyBits != 0 {
						return nil, errors.New("duplicate key length")
					}
					t.KeyBits = v
					attrs = attrs[4:]
				} else {
					return nil, errors.New("unsupported transform attribute")
				}
			}
			p.Transforms = append(p.Transforms, t)
			last := ts[0] == 0
			ts = ts[tn:]
			if last && len(ts) > 0 || !last && len(ts) == 0 {
				return nil, errors.New("invalid transform chaining")
			}
		}
		if len(p.Transforms) != int(b[7]) {
			return nil, errors.New("transform count mismatch")
		}
		out = append(out, p)
		last := b[0] == 0
		b = b[n:]
		if last && len(b) > 0 || !last && len(b) == 0 {
			return nil, errors.New("invalid proposal chaining")
		}
	}
	if len(out) == 0 {
		return nil, errors.New("empty SA")
	}
	return out, nil
}

type CPAttribute struct {
	Type  uint16
	Value []byte
}

func EncodeCP(kind byte, as []CPAttribute) ([]byte, error) {
	b := []byte{kind, 0, 0, 0}
	for _, a := range as {
		if a.Type&0x8000 != 0 {
			return nil, errors.New("CP attribute type exceeds 15 bits")
		}
		if len(a.Value) > 65535 {
			return nil, errors.New("CP attribute too large")
		}
		b = binary.BigEndian.AppendUint16(b, a.Type)
		b = binary.BigEndian.AppendUint16(b, uint16(len(a.Value)))
		b = append(b, a.Value...)
	}
	return b, nil
}
func ParseCP(b []byte) (byte, []CPAttribute, error) {
	if len(b) < 4 {
		return 0, nil, fmt.Errorf("truncated CP header: length=%d, expected at least 4", len(b))
	}
	kind := b[0]
	// RFC 7296 sections 3.15/3.15.1 require receivers to ignore the
	// reserved header octets and attribute R bit. Prefer the standard TLV
	// interpretation for the entire payload, including attributes with R set.
	attrs, tlvErr := parseCPAttributes(b[4:], false)
	if tlvErr == nil {
		return kind, attrs, nil
	}
	// Some deployed peers use the IKEv1 TV convention (high bit means a
	// two-byte inline value). The original VoHive decoder supports it. Only
	// use that interpretation if standard TLV fails and the whole alternate
	// payload parses; never return attributes from a partially parsed frame.
	attrs, tvErr := parseCPAttributes(b[4:], true)
	if tvErr == nil {
		return kind, attrs, nil
	}
	return kind, nil, fmt.Errorf("invalid CP attributes (TLV: %v; TV compatibility: %v)", tlvErr, tvErr)
}

func parseCPAttributes(b []byte, legacyTV bool) ([]CPAttribute, error) {
	var out []CPAttribute
	offset := 4
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, fmt.Errorf("truncated attribute header at offset=%d: remaining=%d", offset, len(b))
		}
		rawType := binary.BigEndian.Uint16(b)
		t := rawType & 0x7fff
		if legacyTV && rawType&0x8000 != 0 {
			out = append(out, CPAttribute{t, append([]byte{}, b[2:4]...)})
			b = b[4:]
			offset += 4
			continue
		}
		n := int(binary.BigEndian.Uint16(b[2:]))
		if n > len(b)-4 {
			return nil, fmt.Errorf("attribute type=%d at offset=%d: length=%d exceeds remaining=%d", t, offset, n, len(b)-4)
		}
		out = append(out, CPAttribute{t, append([]byte{}, b[4:4+n]...)})
		b = b[4+n:]
		offset += 4 + n
	}
	return out, nil
}

type TrafficSelector struct {
	Protocol           byte
	StartPort, EndPort uint16
	Start, End         netip.Addr
}

func EncodeTS(ts []TrafficSelector) ([]byte, error) {
	if len(ts) == 0 || len(ts) > 255 {
		return nil, errors.New("invalid TS count")
	}
	b := []byte{byte(len(ts)), 0, 0, 0}
	for _, t := range ts {
		if !t.Start.IsValid() || !t.End.IsValid() || t.Start.BitLen() != t.End.BitLen() || t.Start.Compare(t.End) > 0 || t.StartPort > t.EndPort {
			return nil, errors.New("invalid TS range")
		}
		typ := byte(7)
		if t.Start.Is6() {
			typ = 8
		}
		n := 8 + 2*len(t.Start.AsSlice())
		b = append(b, typ, t.Protocol, byte(n>>8), byte(n))
		b = binary.BigEndian.AppendUint16(b, t.StartPort)
		b = binary.BigEndian.AppendUint16(b, t.EndPort)
		b = append(b, t.Start.AsSlice()...)
		b = append(b, t.End.AsSlice()...)
	}
	return b, nil
}
func ParseTS(b []byte) ([]TrafficSelector, error) {
	if len(b) < 4 || b[0] == 0 || b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return nil, errors.New("invalid TS")
	}
	count := int(b[0])
	b = b[4:]
	var out []TrafficSelector
	for len(b) > 0 {
		if len(b) < 8 {
			return nil, errors.New("truncated TS")
		}
		n := int(binary.BigEndian.Uint16(b[2:]))
		want := 16
		if b[0] == 8 {
			want = 40
		} else if b[0] != 7 {
			return nil, errors.New("unsupported TS type")
		}
		if n != want || n > len(b) {
			return nil, errors.New("invalid TS length")
		}
		a, _ := netip.AddrFromSlice(b[8 : 8+(n-8)/2])
		z, _ := netip.AddrFromSlice(b[8+(n-8)/2 : n])
		t := TrafficSelector{b[1], binary.BigEndian.Uint16(b[4:]), binary.BigEndian.Uint16(b[6:]), a, z}
		if t.StartPort > t.EndPort || a.Compare(z) > 0 {
			return nil, errors.New("invalid TS range")
		}
		out = append(out, t)
		b = b[n:]
	}
	if len(out) != count {
		return nil, errors.New("TS count mismatch")
	}
	return out, nil
}
func Notification(typ uint16, data []byte) Payload {
	return Payload{Type: Notify, Data: append([]byte{0, 0, byte(typ >> 8), byte(typ)}, data...)}
}
func ParseNotification(b []byte) (uint16, []byte, error) {
	if len(b) < 4 || int(b[1]) > len(b)-4 {
		return 0, nil, errors.New("invalid notify")
	}
	return binary.BigEndian.Uint16(b[2:]), b[4+int(b[1]):], nil
}
