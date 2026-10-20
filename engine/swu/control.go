package swu

import (
	"context"
	"crypto/sha256"
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
	defer s.fragments.clear()
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
		h, e := ikev2.ParseHeader(b)
		if e != nil {
			continue
		}
		association, retired := s.ikeForHeader(h)
		if association == nil {
			continue
		}
		enc, auth := association.inboundKeys()
		if h.Flags&ikev2.FlagInitiator != association.peerFlags(false) {
			continue
		}
		var m ikev2.Message
		if h.NextPayload == ikev2.SKF {
			if !s.fragmentation {
				continue
			}
			f, err := ikev2.OpenFragmentProtected(b, enc, auth, s.protection())
			if err != nil {
				continue
			}
			if h.Flags&(ikev2.FlagInitiator|ikev2.FlagResponse) == association.peerFlags(false) && association.havePeerID && h.MessageID == association.lastPeerID {
				// RFC 7383 2.6.1: only fragment 1 triggers the cached reply.
				if f.Number == 1 && h.Exchange == association.lastPeerExchange {
					_ = s.sendIKEPackets(s.ctx, association.lastPeerReply)
				}
				continue
			}
			var ready bool
			m, ready, e = s.fragments.add(f, time.Now())
			if e != nil || !ready {
				continue
			}
		} else {
			m, e = ikev2.OpenProtected(b, enc, auth, s.protection())
			if e != nil {
				continue
			}
		}
		flags := m.Header.Flags & (ikev2.FlagInitiator | ikev2.FlagResponse)
		if flags == association.peerFlags(true) {
			select {
			case s.responses <- m:
			default:
			}
			continue
		}
		if flags != association.peerFlags(false) {
			continue
		}
		canonical, err := m.Marshal()
		if err != nil {
			continue
		}
		if association.havePeerID && m.Header.MessageID == association.lastPeerID {
			if association.lastPeerReply != nil && sha256.Sum256(canonical) == association.lastPeerRequest {
				_ = s.sendIKEPackets(s.ctx, association.lastPeerReply)
			}
			continue
		}
		expected := uint32(0)
		if association.havePeerID {
			expected = association.lastPeerID + 1
		}
		if m.Header.MessageID != expected {
			continue
		}
		if e := s.answerPeerRequest(association, retired, m, canonical); e != nil {
			s.fail(e)
			return
		}
	}
}

func (s *Session) answerPeerRequest(association *ikeAssociation, retired bool, m ikev2.Message, raw []byte) error {
	var reply []ikev2.Payload
	var pair *childPair
	var nextIKE *ikeAssociation
	closeAfter := false
	switch m.Header.Exchange {
	case ikev2.Informational:
		// Hold the association choice through the reply: a concurrent local
		// rekey must not turn an old-IKE Delete into an active-SA teardown.
		s.ikeStateMu.RLock()
		defer s.ikeStateMu.RUnlock()
		retired = association != s.activeIKE
		var err error
		if retired {
			reply, err = retiredInformational(m.Payloads)
		} else {
			reply, closeAfter, err = s.peerInformational(m.Payloads)
		}
		if err != nil {
			reply = []ikev2.Payload{ikev2.Notification(7, nil)}
		}
	case ikev2.CreateChildSA:
		if retired {
			reply = []ikev2.Payload{ikev2.Notification(temporaryFailureNotify, nil)}
		} else if !s.rekeyMu.TryLock() {
			reply = []ikev2.Payload{ikev2.Notification(temporaryFailureNotify, nil)}
		} else {
			defer s.rekeyMu.Unlock()
			if association != s.currentIKE() {
				reply = []ikev2.Payload{ikev2.Notification(temporaryFailureNotify, nil)}
			}
			if sa, err := ikev2.One(m.Payloads, ikev2.SA); reply == nil && err == nil {
				if proposals, err := ikev2.ParseProposals(sa); err == nil && len(proposals) > 0 && proposals[0].Protocol == 1 {
					reply, nextIKE = s.preparePeerIKE(m.Payloads)
				}
			}
			if reply == nil {
				reply, pair = s.preparePeerChild(m.Payloads)
			}
		}
	default:
		reply = []ikev2.Payload{ikev2.Notification(7, nil)}
	}
	h := association.header(m.Header.Exchange, m.Header.MessageID, true)
	enc, auth := association.outboundKeys()
	wire, err := s.sealIKE(h, reply, enc, auth)
	if err != nil {
		return err
	}
	association.lastPeerID, association.havePeerID, association.lastPeerReply = m.Header.MessageID, true, wire
	association.lastPeerRequest = sha256.Sum256(raw)
	association.lastPeerExchange = m.Header.Exchange
	if err = s.sendIKEPackets(s.ctx, wire); err != nil {
		return err
	}
	if pair != nil {
		s.activateChild(pair)
	}
	if nextIKE != nil {
		s.activateIKE(nextIKE)
	}
	if closeAfter {
		s.fail(ErrRekeyRequired)
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
	cookieReply, err := s.peerMOBIKE(ps)
	if err != nil {
		return nil, false, err
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
		return cookieReply, closeAfter, nil
	}
	data := []byte{3, 4, byte(len(replies) >> 8), byte(len(replies))}
	for _, spi := range replies {
		data = binary.BigEndian.AppendUint32(data, spi)
	}
	return append(cookieReply, ikev2.Payload{Type: ikev2.Delete, Data: data}), closeAfter, nil
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
	return s.exchangeOnIKELocked(ctx, s.currentIKE(), exchange, ps)
}

func (s *Session) exchangeOnIKELocked(ctx context.Context, association *ikeAssociation, exchange byte, ps []ikev2.Payload) (ikev2.Message, error) {
	var empty ikev2.Message
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	id := association.nextID
	if id == ^uint32(0) {
		return empty, ErrRekeyRequired
	}
	association.nextID++
	enc, auth := association.outboundKeys()
	flight, err := s.newIKEFlight(association.header(exchange, id, false), ps, enc, auth)
	if err != nil {
		return empty, err
	}
	return s.exchangeFlightLocked(ctx, association, exchange, id, flight)
}
func (s *Session) exchangeFlightLocked(ctx context.Context, association *ikeAssociation, exchange byte, id uint32, flight *ikeFlight) (ikev2.Message, error) {
	var empty ikev2.Message
	var err error
	for n := 0; n <= s.cfg.Retransmits; n++ {
		if err = s.sendIKEPackets(ctx, flight.packets); err != nil {
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
			case m := <-s.responses:
				if m.Header.InitiatorSPI == association.spii && m.Header.ResponderSPI == association.spir && m.Header.Flags&(ikev2.FlagInitiator|ikev2.FlagResponse) == association.peerFlags(true) && m.Header.Exchange == exchange && m.Header.MessageID == id {
					timer.Stop()
					return m, nil
				}
			}
		}
	retry:
		if n == s.cfg.Retransmits && flight.nextProbe() {
			n = -1
		}
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
			s.fragments.prune(time.Now())
			s.childMu.Lock()
			s.pruneChildrenLocked(time.Now())
			s.childMu.Unlock()
			s.ikeStateMu.Lock()
			s.pruneIKELocked(time.Now())
			s.ikeStateMu.Unlock()
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
