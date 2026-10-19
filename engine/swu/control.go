package swu

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
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
			sa := s.inboundChild(binary.BigEndian.Uint32(packet))
			if sa == nil {
				continue
			}
			p, next, e := sa.Open(packet)
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
			if s.lastPeerReply != nil && bytes.Equal(b, s.lastPeerRequest) {
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
		if e := s.answerPeerRequest(m, b); e != nil {
			s.fail(e)
			return
		}
	}
}

func (s *Session) answerPeerRequest(m ikev2.Message, raw []byte) error {
	var reply []ikev2.Payload
	var pair *childPair
	closeAfter := false
	switch m.Header.Exchange {
	case ikev2.Informational:
		var err error
		reply, closeAfter, err = s.peerInformational(m.Payloads)
		if err != nil {
			reply = []ikev2.Payload{ikev2.Notification(7, nil)}
		}
	case ikev2.CreateChildSA:
		if !s.rekeyMu.TryLock() {
			reply = []ikev2.Payload{ikev2.Notification(temporaryFailureNotify, nil)}
		} else {
			defer s.rekeyMu.Unlock()
			// IKE SA rekey remains a separate phase. Never interpret its
			// eight-byte SPI proposal as an ESP replacement.
			if sa, err := ikev2.One(m.Payloads, ikev2.SA); err == nil {
				if proposals, err := ikev2.ParseProposals(sa); err == nil && len(proposals) == 1 && proposals[0].Protocol == 1 {
					reply = []ikev2.Payload{ikev2.Notification(17, nil)}
					closeAfter = true
				}
			}
			if reply == nil {
				reply, pair = s.preparePeerChild(m.Payloads)
			}
		}
	default:
		reply = []ikev2.Payload{ikev2.Notification(7, nil)}
	}
	h := s.header(m.Header.Exchange, m.Header.MessageID)
	h.Flags |= ikev2.FlagResponse
	wire, err := ikev2.Seal(h, reply, s.keys.SKei, s.keys.SKai, s.integ, s.cfg.Random)
	if err != nil {
		return err
	}
	s.lastPeerID, s.havePeerID, s.lastPeerReply = m.Header.MessageID, true, wire
	s.lastPeerRequest = append([]byte{}, raw...)
	if err = s.ikeSend(s.ctx, wire); err != nil {
		return err
	}
	if pair != nil {
		s.activateChild(pair)
	}
	if closeAfter {
		return ErrRekeyRequired
	}
	return nil
}

func (s *Session) peerInformational(ps []ikev2.Payload) ([]ikev2.Payload, bool, error) {
	var spis []uint32
	closeAfter := false
	// Validate the entire request before retiring any association.
	for _, p := range ps {
		switch p.Type {
		case ikev2.Delete:
			if len(p.Data) < 4 {
				return nil, false, errors.New("truncated Delete")
			}
			proto, size, n := p.Data[0], int(p.Data[1]), int(binary.BigEndian.Uint16(p.Data[2:]))
			if 4+size*n != len(p.Data) {
				return nil, false, errors.New("malformed Delete")
			}
			switch proto {
			case 1:
				if size != 0 || n != 0 {
					return nil, false, errors.New("malformed IKE Delete")
				}
				closeAfter = true
			case 3:
				if size != 4 || n == 0 {
					return nil, false, errors.New("malformed ESP Delete")
				}
				for i := 0; i < n; i++ {
					spis = append(spis, binary.BigEndian.Uint32(p.Data[4+i*4:]))
				}
			default:
				return nil, false, errors.New("unsupported Delete protocol")
			}
		case ikev2.Notify:
			if _, _, err := ikev2.ParseNotification(p.Data); err != nil {
				return nil, false, err
			}
		default:
			return nil, false, errors.New("unexpected informational payload")
		}
	}
	var replies []uint32
	s.childMu.Lock()
	defer s.childMu.Unlock()
	s.pruneChildrenLocked(time.Now())
	for _, spi := range spis {
		// A Delete carries the peer's inbound SPI, hence our outbound SPI.
		if spi == s.out.SPI() {
			closeAfter = true
			replies = append(replies, s.in.SPI())
			continue
		}
		for local, old := range s.retiredChildren {
			if spi == old.peerSPI {
				replies = append(replies, local)
				delete(s.retiredChildren, local)
				break
			}
		}
	}
	if len(replies) == 0 {
		return nil, closeAfter, nil
	}
	data := []byte{3, 4, byte(len(replies) >> 8), byte(len(replies))}
	for _, spi := range replies {
		data = binary.BigEndian.AppendUint32(data, spi)
	}
	return []ikev2.Payload{{Type: ikev2.Delete, Data: data}}, closeAfter, nil
}

func (s *Session) controlExchange(ps []ikev2.Payload) error {
	s.ikeMu.Lock()
	defer s.ikeMu.Unlock()
	m, err := s.establishedExchangeLocked(s.ctx, ikev2.Informational, ps)
	if err != nil {
		return fmt.Errorf("IKE DPD retransmissions exhausted: %w", err)
	}
	return rejectNotifications(m.Payloads)
}

// The read loop remains the sole socket reader and routes authenticated
// responses here. Retransmissions reuse the original sealed bytes and ID.
func (s *Session) establishedExchangeLocked(ctx context.Context, exchange byte, ps []ikev2.Payload) (ikev2.Message, error) {
	var empty ikev2.Message
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	id := s.nextID
	if id == ^uint32(0) {
		return empty, ErrRekeyRequired
	}
	s.nextID++
	b, err := ikev2.Seal(s.header(exchange, id), ps, s.keys.SKei, s.keys.SKai, s.integ, s.cfg.Random)
	if err != nil {
		return empty, err
	}
	for n := 0; n <= s.cfg.Retransmits; n++ {
		if err = s.ikeSend(ctx, b); err != nil {
			return empty, err
		}
		timer := time.NewTimer(s.cfg.Timeout * time.Duration(uint64(1)<<n))
		for {
			select {
			case <-ctx.Done():
				timer.Stop()
				return empty, ctx.Err()
			case <-timer.C:
				goto retry
			case raw := <-s.responses:
				m, err := ikev2.Open(raw, s.keys.SKer, s.keys.SKar, s.integ)
				if err == nil && m.Header.InitiatorSPI == s.spii && m.Header.ResponderSPI == s.spir && m.Header.Flags&(ikev2.FlagInitiator|ikev2.FlagResponse) == ikev2.FlagResponse && m.Header.Exchange == exchange && m.Header.MessageID == id {
					timer.Stop()
					return m, nil
				}
			}
		}
	retry:
	}
	return empty, errors.New("IKE retransmissions exhausted")
}

func (s *Session) keepaliveLoop() {
	keepalive := time.NewTicker(s.cfg.NATKeepalive)
	defer keepalive.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-keepalive.C:
			if err := s.conn.Write(s.ctx, []byte{255}); err != nil {
				s.fail(err)
				return
			}
		}
	}
}

func (s *Session) childDeadline() time.Time {
	s.childMu.RLock()
	defer s.childMu.RUnlock()
	return s.childCreated.Add(s.cfg.ChildLifetime)
}

func (s *Session) maintain() {
	dpd := time.NewTicker(s.cfg.DPDInterval)
	defer dpd.Stop()
	// Start early enough for a bounded retry without using expired keys.
	timer := time.NewTimer(s.rekeyDelay(s.cfg.ChildLifetime * 4 / 5))
	defer timer.Stop()
	prune := time.NewTicker(time.Second)
	defer prune.Stop()
	failures := 0
	for {
		select {
		case <-s.ctx.Done():
			s.fail(s.ctx.Err())
			return
		case <-prune.C:
			s.childMu.Lock()
			s.pruneChildrenLocked(time.Now())
			s.childMu.Unlock()
		case <-s.childReset:
			failures = 0
			timer.Reset(s.rekeyDelay(time.Until(s.childDeadline()) - s.cfg.ChildLifetime/5))
		case <-dpd.C:
			if err := s.controlExchange(nil); err != nil {
				s.fail(err)
				return
			}
		case <-timer.C:
			deadline := s.childDeadline()
			if !time.Now().Before(deadline) {
				s.fail(ErrRekeyRequired)
				return
			}
			ctx, cancel := context.WithDeadline(s.ctx, deadline)
			err := s.rekeyChildAt(ctx, deadline)
			cancel()
			if err == nil {
				failures = 0
				timer.Reset(s.rekeyDelay(time.Until(s.childDeadline()) - s.cfg.ChildLifetime/5))
				continue
			}
			failures++
			var rejection *childRejection
			if failures >= 2 || !time.Now().Before(deadline) || errors.As(err, &rejection) && rejection.code == childNotFoundNotify {
				s.fail(fmt.Errorf("%w: Child SA rekey: %v", ErrRekeyRequired, err))
				return
			}
			timer.Reset(s.rekeyDelay(min(time.Minute, time.Until(deadline))))
		}
	}
}
