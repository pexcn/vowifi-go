package ipsec3gpp

import (
	"context"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

type PacketEndpoint interface {
	ReadPacket(context.Context) ([]byte, error)
	WritePacket(context.Context, []byte) error
}
type SecurityParameters struct {
	Algorithm, Encryption  string
	SPIClient, SPIServer   uint32
	PortClient, PortServer uint16
}
type Config struct {
	LocalIP, RemoteIP netip.Addr
	Client, Server    SecurityParameters
	CK, IK            []byte
}
type selector struct {
	src, dst     netip.Addr
	sport, dport uint16
}
type rule struct {
	selector
	sa *SA
}

// Endpoint can be installed between SWu and netstack before the first REGISTER.
// Install atomically switches the four independently negotiated transport SAs.
// Non-matching traffic (e.g. tunnel DNS) remains outside the IMS selectors.
type Endpoint struct {
	base              PacketEndpoint
	mu                sync.RWMutex
	outbound, inbound []rule
	installed         *Config
}

func NewEndpoint(base PacketEndpoint) *Endpoint { return &Endpoint{base: base} }
func (e *Endpoint) Install(c Config) error {
	l, r := c.LocalIP.Unmap(), c.RemoteIP.Unmap()
	if !l.IsValid() || !r.IsValid() || l.Is4() != r.Is4() || l.IsUnspecified() || r.IsUnspecified() {
		return errors.New("ipsec3gpp: invalid transport address pair")
	}
	if c.Client.PortClient == 0 || c.Client.PortServer == 0 || c.Server.PortClient == 0 || c.Server.PortServer == 0 {
		return errors.New("ipsec3gpp: all four negotiated ports are required")
	}
	if c.Client.PortClient == c.Client.PortServer || c.Server.PortClient == c.Server.PortServer {
		return errors.New("ipsec3gpp: client and server ports must differ")
	}
	if c.Client.SPIClient == c.Client.SPIServer || c.Server.SPIClient == c.Server.SPIServer {
		return errors.New("ipsec3gpp: client and server SPIs must differ")
	}
	// Security-Server chooses algorithms; the four SAs use AKA IK/CK.
	a, enc := c.Server.Algorithm, c.Server.Encryption
	if a != c.Client.Algorithm || enc != c.Client.Encryption {
		return errors.New("ipsec3gpp: server selected an unoffered transform")
	}
	out1, err := NewSA(c.Server.SPIServer, enc, a, c.CK, c.IK)
	if err != nil {
		return err
	}
	out2, err := NewSA(c.Server.SPIClient, enc, a, c.CK, c.IK)
	if err != nil {
		return err
	}
	in1, err := NewSA(c.Client.SPIClient, enc, a, c.CK, c.IK)
	if err != nil {
		return err
	}
	in2, err := NewSA(c.Client.SPIServer, enc, a, c.CK, c.IK)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	// A retransmitted challenge must not reset sequence numbers or replay state.
	c.LocalIP, c.RemoteIP = l, r
	if old := e.installed; old != nil && old.LocalIP == l && old.RemoteIP == r && old.Client == c.Client && old.Server == c.Server && hmac.Equal(old.CK, c.CK) && hmac.Equal(old.IK, c.IK) {
		return nil
	}
	c.CK = append([]byte(nil), c.CK...)
	c.IK = append([]byte(nil), c.IK...)
	e.installed = &c
	e.outbound = []rule{{selector{l, r, c.Client.PortClient, c.Server.PortServer}, out1}, {selector{l, r, c.Client.PortServer, c.Server.PortClient}, out2}}
	e.inbound = []rule{{selector{r, l, c.Server.PortServer, c.Client.PortClient}, in1}, {selector{r, l, c.Server.PortClient, c.Client.PortServer}, in2}}
	return nil
}
func (e *Endpoint) WritePacket(ctx context.Context, p []byte) error {
	h, err := parseIP(p)
	if err != nil {
		return err
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if h.protocol == 6 || h.protocol == 17 {
		for _, r := range e.outbound {
			if match(h, p, r.selector) {
				payload, err := r.sa.Protect(p[h.length:], h.protocol)
				if err != nil {
					return err
				}
				p, err = replace(p, h, payload, 50)
				if err != nil {
					return err
				}
				break
			}
		}
	}
	return e.base.WritePacket(ctx, p)
}
func (e *Endpoint) ReadPacket(ctx context.Context) ([]byte, error) {
	for {
		p, err := e.base.ReadPacket(ctx)
		if err != nil {
			return nil, err
		}
		p, err = e.unprotect(p)
		if err == nil {
			return p, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Invalid, replayed and unprotected selector packets are silently discarded.
	}
}
func (e *Endpoint) unprotect(p []byte) ([]byte, error) {
	h, err := parseIP(p)
	if err != nil {
		return nil, err
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if h.protocol != 50 {
		for _, r := range e.inbound {
			if match(h, p, r.selector) {
				return nil, errors.New("ipsec3gpp: plaintext packet on protected selector")
			}
		}
		return p, nil
	}
	if len(p) < h.length+8 {
		return nil, errors.New("ipsec3gpp: truncated ESP")
	}
	spi := binary.BigEndian.Uint32(p[h.length:])
	for _, r := range e.inbound {
		if h.src == r.src && h.dst == r.dst && spi == r.sa.spi {
			body, next, err := r.sa.Unprotect(p[h.length:])
			if err != nil {
				return nil, err
			}
			if next != 6 && next != 17 {
				return nil, errors.New("ipsec3gpp: ESP payload must be TCP or UDP")
			}
			out, err := replace(p, h, body, next)
			if err != nil {
				return nil, err
			}
			h.protocol = next
			if !match(h, out, r.selector) {
				return nil, errors.New("ipsec3gpp: authenticated packet violates SA port selector")
			}
			return out, nil
		}
	}
	return nil, errors.New("ipsec3gpp: no inbound IMS SA")
}

type ipHeader struct {
	length   int
	protocol byte
	src, dst netip.Addr
	ipv4     bool
}

func parseIP(p []byte) (ipHeader, error) {
	var h ipHeader
	if len(p) == 0 {
		return h, errors.New("ipsec3gpp: empty packet")
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return h, errors.New("ipsec3gpp: truncated IPv4")
		}
		h.length = int(p[0]&15) * 4
		if h.length < 20 || h.length > len(p) || int(binary.BigEndian.Uint16(p[2:])) != len(p) {
			return h, errors.New("ipsec3gpp: invalid IPv4 length")
		}
		if binary.BigEndian.Uint16(p[6:])&0x3fff != 0 {
			return h, errors.New("ipsec3gpp: fragmented IPv4 unsupported")
		}
		h.ipv4 = true
		h.protocol = p[9]
		h.src = netip.AddrFrom4([4]byte(p[12:16]))
		h.dst = netip.AddrFrom4([4]byte(p[16:20]))
	case 6:
		if len(p) < 40 || int(binary.BigEndian.Uint16(p[4:]))+40 != len(p) {
			return h, errors.New("ipsec3gpp: invalid IPv6 length")
		}
		h.length = 40
		h.protocol = p[6]
		h.src = netip.AddrFrom16([16]byte(p[8:24]))
		h.dst = netip.AddrFrom16([16]byte(p[24:40]))
		switch h.protocol {
		case 0, 43, 44, 60, 51:
			return h, errors.New("ipsec3gpp: IPv6 extension headers unsupported")
		}
	default:
		return h, errors.New("ipsec3gpp: unknown IP version")
	}
	return h, nil
}
func match(h ipHeader, p []byte, s selector) bool {
	return (h.protocol == 6 || h.protocol == 17) && len(p) >= h.length+4 && h.src == s.src && h.dst == s.dst && binary.BigEndian.Uint16(p[h.length:]) == s.sport && binary.BigEndian.Uint16(p[h.length+2:]) == s.dport
}
func replace(p []byte, h ipHeader, body []byte, next byte) ([]byte, error) {
	size := h.length + len(body)
	if size > 65535 {
		return nil, fmt.Errorf("ipsec3gpp: packet length %d exceeds IP limit", size)
	}
	out := make([]byte, size)
	copy(out, p[:h.length])
	copy(out[h.length:], body)
	if h.ipv4 {
		out[9] = next
		binary.BigEndian.PutUint16(out[2:], uint16(size))
		out[10], out[11] = 0, 0
		var sum uint32
		for i := 0; i < h.length; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(out[i:]))
		}
		for sum>>16 != 0 {
			sum = (sum & 65535) + (sum >> 16)
		}
		binary.BigEndian.PutUint16(out[10:], ^uint16(sum))
	} else {
		out[6] = next
		binary.BigEndian.PutUint16(out[4:], uint16(len(body)))
	}
	return out, nil
}
