package swu

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/iniwex5/vowifi-go/engine/ikev2"
	"github.com/iniwex5/vowifi-go/engine/ipsec"
)

const (
	mobikeSupportedNotify       uint16 = 16396
	additionalIPv4Notify        uint16 = 16397
	additionalIPv6Notify        uint16 = 16398
	noAdditionalAddressesNotify uint16 = 16399
	updateAddressesNotify       uint16 = 16400
	cookie2Notify               uint16 = 16401
)

// switchingConn keeps exactly one reader of each socket. Candidate validation
// has its own socket; the established reader follows it only after commit.
type transportSlot struct {
	conn   ipsec.DatagramConn
	ctx    context.Context
	cancel context.CancelFunc
}
type switchingConn struct {
	mu     sync.RWMutex
	slot   *transportSlot
	closed bool
}

func newSwitchingConn(c ipsec.DatagramConn) *switchingConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &switchingConn{slot: &transportSlot{c, ctx, cancel}}
}
func (c *switchingConn) Read(ctx context.Context) ([]byte, error) {
	for {
		c.mu.RLock()
		slot, closed := c.slot, c.closed
		c.mu.RUnlock()
		if closed {
			return nil, net.ErrClosed
		}
		readCtx, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(slot.ctx, cancel)
		b, err := slot.conn.Read(readCtx)
		stop()
		cancel()
		c.mu.RLock()
		changed := c.slot != slot
		c.mu.RUnlock()
		if changed {
			continue
		}
		return b, err
	}
}
func (c *switchingConn) Write(ctx context.Context, b []byte) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return net.ErrClosed
	}
	return c.slot.conn.Write(ctx, b)
}
func (c *switchingConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.slot.cancel()
	return c.slot.conn.Close()
}
func (c *switchingConn) replace(next ipsec.DatagramConn) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	ctx, cancel := context.WithCancel(context.Background())
	old := c.slot
	c.slot = &transportSlot{next, ctx, cancel}
	old.cancel()
	return old.conn.Close()
}
func (c *switchingConn) LocalAddr() net.Addr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if a, ok := c.slot.conn.(interface{ LocalAddr() net.Addr }); ok {
		return a.LocalAddr()
	}
	return nil
}

func validMOBIKENegotiation(ps []ikev2.Payload) bool {
	n := 0
	for _, p := range ps {
		if p.Type != ikev2.Notify {
			continue
		}
		typ, data, err := ikev2.ParseNotification(p.Data)
		if err != nil {
			return false
		}
		if typ == mobikeSupportedNotify {
			if len(data) != 0 || len(p.Data) != 4 || p.Data[0] != 0 {
				return false
			}
			n++
		}
	}
	return n == 1
}
func (s *Session) peerMOBIKE(ps []ikev2.Payload) ([]ikev2.Payload, error) {
	var reply []ikev2.Payload
	for _, p := range ps {
		if p.Type != ikev2.Notify {
			continue
		}
		typ, data, err := ikev2.ParseNotification(p.Data)
		if err != nil {
			return nil, err
		}
		switch typ {
		case cookie2Notify:
			if !s.mobike || len(data) < 8 || len(data) > 64 || len(reply) > 0 {
				return nil, errors.New("invalid MOBIKE COOKIE2")
			}
			reply = append(reply, ikev2.Notification(cookie2Notify, bytes.Clone(data)))
		case updateAddressesNotify:
			// RFC 4555: only the original IKE initiator may move the SA endpoints.
			return nil, errors.New("responder cannot issue UPDATE_SA_ADDRESSES")
		case additionalIPv4Notify, additionalIPv6Notify, noAdditionalAddressesNotify:
			if !s.mobike {
				return nil, errors.New("MOBIKE not negotiated")
			}
			if typ == additionalIPv4Notify && len(data) != 4 || typ == additionalIPv6Notify && len(data) != 16 || typ == noAdditionalAddressesNotify && len(data) != 0 {
				return nil, errors.New("invalid MOBIKE address notification")
			}
		}
	}
	return reply, nil
}
func (s *Session) mobikePayloads(c ipsec.DatagramConn, association *ikeAssociation, cookie []byte) ([]ikev2.Payload, error) {
	ps := []ikev2.Payload{ikev2.Notification(updateAddressesNotify, nil), ikev2.Notification(cookie2Notify, cookie)}
	a, ok := c.(interface{ LocalAddr() net.Addr })
	if !ok {
		return nil, errors.New("MOBIKE transport has no local address")
	}
	local, ok := a.LocalAddr().(*net.UDPAddr)
	if !ok || local == nil {
		return nil, errors.New("MOBIKE requires UDP local address")
	}
	peer, err := net.ResolveUDPAddr("udp", s.RemoteAddr)
	if err != nil {
		return nil, err
	}
	return append(ps, ikev2.Notification(16388, natHash(association.spii, association.spir, local.IP, uint16(local.Port))), ikev2.Notification(16389, natHash(association.spii, association.spir, peer.IP, uint16(peer.Port)))), nil
}
func verifyMOBIKEReply(m ikev2.Message, cookie []byte) error {
	if err := rejectNotifications(m.Payloads); err != nil {
		return err
	}
	count := 0
	for _, p := range m.Payloads {
		if p.Type != ikev2.Notify {
			continue
		}
		typ, data, err := ikev2.ParseNotification(p.Data)
		if err != nil {
			return err
		}
		if typ == cookie2Notify {
			count++
			if subtle.ConstantTimeCompare(data, cookie) != 1 {
				return errors.New("MOBIKE COOKIE2 mismatch")
			}
		}
	}
	if count != 1 {
		return errors.New("missing or duplicate MOBIKE COOKIE2")
	}
	return nil
}

// UpdateAddresses moves the local UDP path to a bound address (empty lets the
// OS select). It retains the authenticated ePDG, IKE/Child SAs and inner IPs.
// A configured proxy must reconnect its association rather than bind locally.
func (s *Session) UpdateAddresses(ctx context.Context, localIP string) error {
	if !s.mobike {
		return errors.New("peer did not negotiate MOBIKE")
	}
	if s.cfg.Proxy != nil && s.cfg.Proxy.Enabled {
		return errors.New("MOBIKE cannot locally rebind a proxy association")
	}
	if localIP != "" {
		ip := net.ParseIP(localIP)
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			return errors.New("invalid MOBIKE local IP")
		}
	}
	s.rekeyMu.Lock()
	defer s.rekeyMu.Unlock()
	s.ikeMu.Lock()
	defer s.ikeMu.Unlock()
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	candidate, err := ipsec.DialUDPFrom(ctx, localIP, s.RemoteAddr)
	if err != nil {
		return err
	}
	owned := true
	defer func() {
		if owned {
			candidate.Close()
		}
	}()
	a := s.currentIKE()
	cookie := make([]byte, 16)
	if _, err = io.ReadFull(s.cfg.Random, cookie); err != nil {
		return err
	}
	ps, err := s.mobikePayloads(candidate, a, cookie)
	if err != nil {
		return err
	}
	id := a.nextID
	if id == ^uint32(0) {
		return ErrRekeyRequired
	}
	a.nextID++
	enc, auth := a.outboundKeys()
	flight, err := s.newIKEFlight(a.header(ikev2.Informational, id, false), ps, enc, auth)
	if err != nil {
		a.nextID--
		return err
	}
	m, err := s.candidateExchange(ctx, candidate, a, id, flight)
	if err == nil {
		err = verifyMOBIKEReply(m, cookie)
	}
	if err != nil {
		// A lost reply may already have moved the peer. First finish the exact
		// transaction on the old path, then explicitly restore its addresses.
		rollbackCtx, cancel := context.WithTimeout(s.ctx, 3*time.Second)
		defer cancel()
		if _, e := s.exchangeFlightLocked(rollbackCtx, a, ikev2.Informational, id, flight); e == nil {
			oldCookie := make([]byte, 16)
			_, e = io.ReadFull(s.cfg.Random, oldCookie)
			var oldPS []ikev2.Payload
			var response ikev2.Message
			if e == nil {
				oldPS, e = s.mobikePayloads(s.transport, a, oldCookie)
			}
			if e == nil {
				response, e = s.establishedExchangeLocked(rollbackCtx, ikev2.Informational, oldPS)
			}
			if e == nil {
				e = verifyMOBIKEReply(response, oldCookie)
			}
			if e == nil {
				return fmt.Errorf("MOBIKE candidate rejected; old path restored: %w", err)
			}
		}
		s.fail(errors.New("MOBIKE rollback could not confirm old path"))
		return fmt.Errorf("MOBIKE migration failed: %w", err)
	}
	if err = s.ctx.Err(); err != nil {
		return err
	}
	if err = s.transport.replace(candidate); err != nil {
		s.fail(err)
		return err
	}
	owned = false
	return nil
}
func (s *Session) candidateExchange(ctx context.Context, c ipsec.DatagramConn, a *ikeAssociation, id uint32, flight *ikeFlight) (ikev2.Message, error) {
	var empty ikev2.Message
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	var fragments fragmentBuffer
	defer fragments.clear()
	enc, auth := a.inboundKeys()
	for n := 0; n <= s.cfg.Retransmits; n++ {
		for _, b := range flight.packets {
			if err := c.Write(ctx, append([]byte{0, 0, 0, 0}, b...)); err != nil {
				return empty, err
			}
		}
		readCtx, end := context.WithTimeout(ctx, s.cfg.Timeout*time.Duration(uint64(1)<<n))
		for {
			b, err := c.Read(readCtx)
			if err != nil {
				end()
				if ctx.Err() != nil {
					return empty, ctx.Err()
				}
				break
			}
			if len(b) < 4 || binary.BigEndian.Uint32(b) != 0 {
				continue
			}
			b = b[4:]
			h, e := ikev2.ParseHeader(b)
			if e != nil || h.InitiatorSPI != a.spii || h.ResponderSPI != a.spir || h.MessageID != id || h.Exchange != ikev2.Informational || h.Flags&(ikev2.FlagResponse|ikev2.FlagInitiator) != a.peerFlags(true) {
				continue
			}
			var m ikev2.Message
			if h.NextPayload == ikev2.SKF && s.fragmentation {
				f, e := ikev2.OpenFragmentProtected(b, enc, auth, s.protection())
				if e != nil {
					continue
				}
				var ready bool
				m, ready, e = fragments.add(f, time.Now())
				if e != nil || !ready {
					continue
				}
			} else {
				m, e = ikev2.OpenProtected(b, enc, auth, s.protection())
				if e != nil {
					continue
				}
			}
			end()
			return m, nil
		}
	}
	return empty, errors.New("MOBIKE candidate timed out")
}
