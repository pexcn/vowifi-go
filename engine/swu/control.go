package swu

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/iniwex5/vowifi-go/engine/ikev2"
	"github.com/iniwex5/vowifi-go/engine/ipsec"
	"net/netip"
	"time"
)

func selectorAllows(ts []ikev2.TrafficSelector, addr netip.Addr, protocol byte, port uint16) bool {
	for _, t := range ts {
		if t.Start.BitLen() == addr.BitLen() && addr.Compare(t.Start) >= 0 && addr.Compare(t.End) <= 0 && (t.Protocol == 0 || t.Protocol == protocol) && port >= t.StartPort && port <= t.EndPort {
			return true
		}
	}
	return false
}
func (s *Session) permitted(p []byte, outbound bool) bool {
	var src, dst netip.Addr
	var proto byte
	var offset int
	if p[0]>>4 == 4 {
		src, _ = netip.AddrFromSlice(p[12:16])
		dst, _ = netip.AddrFromSlice(p[16:20])
		proto = p[9]
		offset = int(p[0]&15) * 4
		if binary.BigEndian.Uint16(p[6:])&0x3fff != 0 {
			return false
		}
	} else {
		src, _ = netip.AddrFromSlice(p[8:24])
		dst, _ = netip.AddrFromSlice(p[24:40])
		proto = p[6]
		offset = 40
		switch proto {
		case 0, 43, 44, 51, 60:
			return false
		}
	}
	var sp, dp uint16
	if proto == 6 || proto == 17 {
		if len(p) < offset+4 {
			return false
		}
		sp = binary.BigEndian.Uint16(p[offset:])
		dp = binary.BigEndian.Uint16(p[offset+2:])
	}
	local, remote := s.configuration.LocalSelectors, s.configuration.RemoteSelectors
	if !outbound {
		local, remote = remote, local
	}
	return selectorAllows(local, src, proto, sp) && selectorAllows(remote, dst, proto, dp)
}
func (s *Session) readLoop() {
	for {
		packet, e := s.conn.Read(s.ctx)
		if e != nil {
			if s.ctx.Err() != nil {
				e = s.ctx.Err()
			}
			s.fail(e)
			return
		}
		if len(packet) == 1 && packet[0] == 255 {
			continue
		}
		if len(packet) < 4 {
			continue
		}
		if binary.BigEndian.Uint32(packet) != 0 {
			p, next, e := s.in.Open(packet)
			if e != nil {
				continue
			}
			if ipsec.ValidateInnerIP(p, next) != nil || !s.permitted(p, false) {
				continue
			}
			select {
			case s.packets <- p:
			default:
			}
			continue
		}
		b := packet[4:]
		m, e := ikev2.Open(b, s.keys.SKer, s.keys.SKar, s.integ)
		if e != nil {
			continue
		}
		if m.Header.InitiatorSPI != s.spii || m.Header.ResponderSPI != s.spir || m.Header.Flags&ikev2.FlagInitiator != 0 {
			continue
		}
		flags := m.Header.Flags & (ikev2.FlagInitiator | ikev2.FlagResponse)
		if flags == ikev2.FlagResponse {
			select {
			case s.responses <- append([]byte{}, b...):
			default:
			}
			continue
		}
		if flags != 0 {
			continue
		}
		if s.havePeerID && m.Header.MessageID == s.lastPeerID {
			if s.lastPeerReply != nil {
				_ = s.ikeSend(s.ctx, s.lastPeerReply)
			}
			continue
		}
		expected := uint32(0)
		if s.havePeerID {
			expected = s.lastPeerID + 1
		}
		if m.Header.MessageID != expected {
			continue
		}
		var reply []ikev2.Payload
		closeAfter := false
		switch m.Header.Exchange {
		case ikev2.Informational:
			for _, p := range m.Payloads {
				if p.Type == ikev2.Delete {
					if len(p.Data) < 4 {
						closeAfter = true
						break
					}
					proto, size, n := p.Data[0], int(p.Data[1]), int(binary.BigEndian.Uint16(p.Data[2:]))
					if 4+size*n != len(p.Data) {
						closeAfter = true
						break
					}
					switch proto {
					case 1:
						if size != 0 || n != 0 {
							closeAfter = true
							break
						}
						closeAfter = true
					case 3:
						if size != 4 || n == 0 {
							closeAfter = true
							break
						}
						for i := 0; i < n; i++ {
							if binary.BigEndian.Uint32(p.Data[4+i*4:]) == s.out.SPI() {
								closeAfter = true
								reply = append(reply, ikev2.Payload{Type: ikev2.Delete, Data: append([]byte{3, 4, 0, 1}, binary.BigEndian.AppendUint32(nil, s.in.SPI())...)})
							}
						}
					}
				} else if p.Type != ikev2.Notify {
					reply = []ikev2.Payload{ikev2.Notification(7, nil)}
				}
			}
		case ikev2.CreateChildSA:
			reply = []ikev2.Payload{ikev2.Notification(17, nil)}
			closeAfter = true
		default:
			reply = []ikev2.Payload{ikev2.Notification(7, nil)}
		}
		h := s.header(m.Header.Exchange, m.Header.MessageID)
		h.Flags |= ikev2.FlagResponse
		wire, e := ikev2.Seal(h, reply, s.keys.SKei, s.keys.SKai, s.integ, s.cfg.Random)
		if e != nil {
			s.fail(e)
			return
		}
		s.lastPeerID = m.Header.MessageID
		s.havePeerID = true
		s.lastPeerReply = wire
		if e = s.ikeSend(s.ctx, wire); e != nil {
			s.fail(e)
			return
		}
		if closeAfter {
			s.fail(ErrRekeyRequired)
			return
		}
	}
}
func (s *Session) controlExchange(ps []ikev2.Payload) error {
	s.ikeMu.Lock()
	defer s.ikeMu.Unlock()
	id := s.nextID
	if id == ^uint32(0) {
		return ErrRekeyRequired
	}
	s.nextID++
	b, e := ikev2.Seal(s.header(ikev2.Informational, id), ps, s.keys.SKei, s.keys.SKai, s.integ, s.cfg.Random)
	if e != nil {
		return e
	}
	for n := 0; n <= s.cfg.Retransmits; n++ {
		if e = s.ikeSend(s.ctx, b); e != nil {
			return e
		}
		t := time.NewTimer(s.cfg.Timeout * time.Duration(uint64(1)<<n))
		for {
			select {
			case <-s.ctx.Done():
				t.Stop()
				return s.ctx.Err()
			case <-t.C:
				goto retry
			case r := <-s.responses:
				m, e := ikev2.Open(r, s.keys.SKer, s.keys.SKar, s.integ)
				if e == nil && m.Header.Exchange == ikev2.Informational && m.Header.MessageID == id {
					t.Stop()
					for _, p := range m.Payloads {
						if p.Type == ikev2.Notify {
							typ, _, e := ikev2.ParseNotification(p.Data)
							if e != nil {
								return e
							}
							if typ < 16384 {
								return errors.New("IKE informational rejected")
							}
						}
					}
					return nil
				}
			}
		}
	retry:
	}
	return errors.New("IKE DPD retransmissions exhausted")
}
func (s *Session) maintain() {
	dpd := time.NewTicker(s.cfg.DPDInterval)
	defer dpd.Stop()
	keepalive := time.NewTicker(s.cfg.NATKeepalive)
	defer keepalive.Stop()
	lifetime := time.NewTimer(s.cfg.ChildLifetime)
	defer lifetime.Stop()
	for {
		select {
		case <-s.ctx.Done():
			s.fail(context.Canceled)
			return
		case <-keepalive.C:
			if e := s.conn.Write(s.ctx, []byte{255}); e != nil {
				s.fail(e)
				return
			}
		case <-dpd.C:
			if e := s.controlExchange(nil); e != nil {
				s.fail(e)
				return
			}
		case <-lifetime.C:
			s.fail(ErrRekeyRequired)
			return
		}
	}
}
