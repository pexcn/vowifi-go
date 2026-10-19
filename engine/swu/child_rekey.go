package swu

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	vc "github.com/iniwex5/vowifi-go/engine/crypto"
	"github.com/iniwex5/vowifi-go/engine/ikev2"
	"github.com/iniwex5/vowifi-go/engine/ipsec"
)

const (
	rekeySANotify          = 16393
	temporaryFailureNotify = 43
	childNotFoundNotify    = 44
	childOverlap           = 30 * time.Second
	maxRetiredChildren     = 4
)

type lockedRandom struct {
	mu     sync.Mutex
	reader io.Reader
}

func (r *lockedRandom) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reader.Read(p)
}

type retiredChild struct {
	in      *ipsec.SA
	peerSPI uint32
	expires time.Time
}

type childPair struct {
	in, out *ipsec.SA
	dhGroup uint16
}

type childRejection struct{ code uint16 }

func (e *childRejection) Error() string {
	return fmt.Sprintf("CREATE_CHILD_SA rejected (notify=%d)", e.code)
}

func childNotify(code uint16, spi uint32) ikev2.Payload {
	return ikev2.Payload{Type: ikev2.Notify, Data: binary.BigEndian.AppendUint32([]byte{3, 4, byte(code >> 8), byte(code)}, spi)}
}

func childDelete(spi uint32) ikev2.Payload {
	return ikev2.Payload{Type: ikev2.Delete, Data: binary.BigEndian.AppendUint32([]byte{3, 4, 0, 1}, spi)}
}

func (s *Session) pruneChildrenLocked(now time.Time) {
	for spi, retired := range s.retiredChildren {
		if !now.Before(retired.expires) {
			delete(s.retiredChildren, spi)
		}
	}
}

func (s *Session) inboundChild(spi uint32) *ipsec.SA {
	s.childMu.Lock()
	defer s.childMu.Unlock()
	s.pruneChildrenLocked(time.Now())
	if s.in.SPI() == spi {
		if !time.Now().Before(s.childCreated.Add(s.cfg.ChildLifetime)) {
			return nil
		}
		return s.in
	}
	return s.retiredChildren[spi].in
}

func (s *Session) newChildMaterial() (uint32, []byte, error) {
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(s.cfg.Random, nonce); err != nil {
		return 0, nil, err
	}
	for attempt := 0; attempt < 8; attempt++ {
		var b [4]byte
		if _, err := io.ReadFull(s.cfg.Random, b[:]); err != nil {
			return 0, nil, err
		}
		spi := binary.BigEndian.Uint32(b[:])
		s.childMu.Lock()
		s.pruneChildrenLocked(time.Now())
		used := spi == 0 || spi == s.in.SPI() || spi == s.out.SPI()
		for local, old := range s.retiredChildren {
			used = used || spi == local || spi == old.peerSPI
		}
		s.childMu.Unlock()
		if !used {
			return spi, nonce, nil
		}
	}
	return 0, nil, errors.New("unable to generate a fresh Child SA SPI")
}

// RFC 7296 2.17 uses exchange roles, including when the original IKE
// responder initiates the Child SA rekey. It does not reuse IKE_AUTH nonces.
func (s *Session) deriveChildPair(localSPI, peerSPI uint32, ni, nr, shared []byte, initiator bool) (*childPair, error) {
	seed := append(append(append([]byte{}, shared...), ni...), nr...)
	material, err := s.prf.Plus(s.currentIKE().keys.SKd, seed, 2*(s.encLen+s.integ.KeyLen()))
	if err != nil {
		return nil, err
	}
	defer clear(material)
	n := s.encLen + s.integ.KeyLen()
	outKey, inKey := material[:n], material[n:]
	if !initiator {
		outKey, inKey = inKey, outKey
	}
	out, err := ipsec.NewSA(ipsec.SAConfig{SPI: peerSPI, EncryptionKey: outKey[:s.encLen], IntegrityKey: outKey[s.encLen:], Integrity: s.integ, Random: s.cfg.Random})
	if err != nil {
		return nil, err
	}
	in, err := ipsec.NewSA(ipsec.SAConfig{SPI: localSPI, EncryptionKey: inKey[:s.encLen], IntegrityKey: inKey[s.encLen:], Integrity: s.integ})
	if err != nil {
		return nil, err
	}
	return &childPair{in: in, out: out}, nil
}

func (s *Session) activateChild(pair *childPair) {
	s.childMu.Lock()
	defer s.childMu.Unlock()
	now := time.Now()
	s.pruneChildrenLocked(now)
	if s.retiredChildren == nil {
		s.retiredChildren = make(map[uint32]retiredChild)
	}
	s.retiredChildren[s.in.SPI()] = retiredChild{in: s.in, peerSPI: s.out.SPI(), expires: minTime(now.Add(childOverlap), s.childCreated.Add(s.cfg.ChildLifetime))}
	s.in, s.out = pair.in, pair.out
	s.childDHGroup = pair.dhGroup
	s.childCreated = now
	select {
	case s.childReset <- struct{}{}:
	default:
	}
}

// Rekey cannot change the tunnel's assigned addresses, selectors or algorithms.
// The host's network endpoint therefore remains valid across a Child SA switch.
func sameSelectors(a, b []ikev2.TrafficSelector) bool {
	if len(a) != len(b) {
		return false
	}
	matched := make([]bool, len(b))
	for _, selector := range a {
		found := false
		for i, other := range b {
			if !matched[i] && selector == other {
				matched[i], found = true, true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (s *Session) checkRekeySelectors(ps []ikev2.Payload, localInitiator bool) error {
	i, err := ikev2.One(ps, ikev2.TSi)
	if err != nil {
		return err
	}
	r, err := ikev2.One(ps, ikev2.TSr)
	if err != nil {
		return err
	}
	tsi, err := ikev2.ParseTS(i)
	if err != nil {
		return err
	}
	tsr, err := ikev2.ParseTS(r)
	if err != nil {
		return err
	}
	local, remote := s.configuration.LocalSelectors, s.configuration.RemoteSelectors
	if !localInitiator {
		local, remote = remote, local
	}
	if !sameSelectors(tsi, local) || !sameSelectors(tsr, remote) {
		return errors.New("Child SA rekey changed traffic selectors")
	}
	return nil
}

func (s *Session) rekeySelectors(localInitiator bool) []ikev2.Payload {
	local, remote := s.configuration.LocalSelectors, s.configuration.RemoteSelectors
	if !localInitiator {
		local, remote = remote, local
	}
	// Both sets have already passed EncodeTS/ParseTS during IKE_AUTH.
	i, _ := ikev2.EncodeTS(local)
	r, _ := ikev2.EncodeTS(remote)
	return []ikev2.Payload{{Type: ikev2.TSi, Data: i}, {Type: ikev2.TSr, Data: r}}
}

func rekeyNonce(ps []ikev2.Payload) ([]byte, error) {
	n, err := ikev2.One(ps, ikev2.Nonce)
	if err != nil {
		return nil, err
	}
	if len(n) < 16 || len(n) > 256 {
		return nil, errors.New("invalid Child SA rekey nonce length")
	}
	return n, nil
}

func rejectNotifications(ps []ikev2.Payload) error {
	for _, p := range ps {
		if p.Type != ikev2.Notify {
			continue
		}
		code, _, err := ikev2.ParseNotification(p.Data)
		if err != nil {
			return err
		}
		if code < 16384 {
			return &childRejection{code: code}
		}
	}
	return nil
}

func (s *Session) childCapacity() bool {
	s.childMu.Lock()
	defer s.childMu.Unlock()
	s.pruneChildrenLocked(time.Now())
	return len(s.retiredChildren) < maxRetiredChildren
}

func (s *Session) freshPeerSPI(spi uint32) bool {
	s.childMu.RLock()
	defer s.childMu.RUnlock()
	if spi == 0 || spi == s.out.SPI() {
		return false
	}
	for _, old := range s.retiredChildren {
		if spi == old.peerSPI {
			return false
		}
	}
	return true
}

func (s *Session) rekeyChild(ctx context.Context) error {
	return s.rekeyChildAt(ctx, time.Time{})
}

func (s *Session) rekeyChildAt(ctx context.Context, expectedDeadline time.Time) error {
	s.rekeyMu.Lock()
	defer s.rekeyMu.Unlock()
	s.ikeMu.Lock()
	defer s.ikeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !expectedDeadline.IsZero() && !s.childDeadline().Equal(expectedDeadline) {
		return nil
	}
	if !s.childCapacity() {
		return &childRejection{code: temporaryFailureNotify}
	}
	spi, ni, err := s.newChildMaterial()
	if err != nil {
		return err
	}
	s.childMu.RLock()
	oldLocal, oldPeer := s.in.SPI(), s.out.SPI()
	group := s.childDHGroup
	s.childMu.RUnlock()
	offer := s.espProposal(spi)
	var dh *vc.MODP
	if group != 0 {
		offer.Transforms = append(offer.Transforms, ikev2.Transform{Type: 4, ID: group})
		dh, err = vc.NewMODP(group, s.cfg.Random)
		if err != nil {
			return err
		}
	}
	sa, err := ikev2.EncodeProposals([]ikev2.Proposal{offer})
	if err != nil {
		return err
	}
	// REKEY_SA identifies the SPI the exchange initiator receives (1.3.3).
	ps := []ikev2.Payload{{Type: ikev2.SA, Data: sa}, {Type: ikev2.Nonce, Data: ni}, childNotify(rekeySANotify, oldLocal)}
	if dh != nil {
		ps = append(ps, ikev2.Payload{Type: ikev2.KE, Data: append([]byte{byte(group >> 8), byte(group), 0, 0}, dh.Public...)})
	}
	ps = append(ps, s.rekeySelectors(true)...)
	m, err := s.establishedExchangeLocked(ctx, ikev2.CreateChildSA, ps)
	if err != nil {
		return err
	}
	if err = rejectNotifications(m.Payloads); err != nil {
		return err
	}
	sa, err = ikev2.One(m.Payloads, ikev2.SA)
	if err != nil {
		return err
	}
	proposal, err := validateProposal(sa, offer)
	if err != nil {
		return err
	}
	peerSPI := binary.BigEndian.Uint32(proposal.SPI)
	if !s.freshPeerSPI(peerSPI) {
		return errors.New("Child SA rekey reused peer SPI")
	}
	nr, err := rekeyNonce(m.Payloads)
	if err != nil {
		return err
	}
	if err = s.checkRekeySelectors(m.Payloads, true); err != nil {
		return err
	}
	var shared []byte
	if dh != nil {
		ke, err := ikev2.One(m.Payloads, ikev2.KE)
		if err != nil {
			return err
		}
		if len(ke) < 4 || binary.BigEndian.Uint16(ke) != group {
			return errors.New("Child SA rekey changed PFS group")
		}
		shared, err = dh.Shared(ke[4:])
		if err != nil {
			return err
		}
		defer clear(shared)
	} else if _, ok := ikev2.Find(m.Payloads, ikev2.KE); ok {
		return errors.New("unoffered Child SA rekey KE")
	}
	pair, err := s.deriveChildPair(spi, peerSPI, ni, nr, shared, true)
	if err != nil {
		return err
	}
	pair.dhGroup = group
	if err = ctx.Err(); err != nil {
		return err
	}
	s.activateChild(pair)
	// A missing old-SA Delete response must not undo an installed new SA.
	// Its inbound key is bounded by childOverlap even if the peer disappears.
	m, err = s.establishedExchangeLocked(ctx, ikev2.Informational, []ikev2.Payload{childDelete(oldLocal)})
	if err == nil && rejectNotifications(m.Payloads) == nil {
		for _, p := range m.Payloads {
			if p.Type == ikev2.Delete && len(p.Data) == 8 && p.Data[0] == 3 && p.Data[1] == 4 && binary.BigEndian.Uint16(p.Data[2:]) == 1 && binary.BigEndian.Uint32(p.Data[4:]) == oldPeer {
				s.childMu.Lock()
				delete(s.retiredChildren, oldLocal)
				s.childMu.Unlock()
			}
		}
	}
	return nil
}

// preparePeerChild answers an authenticated request without replacing an SA
// until the complete response has been sealed and sent. rekeyMu is held.
func (s *Session) preparePeerChild(ps []ikev2.Payload) ([]ikev2.Payload, *childPair) {
	reject := func(code uint16) ([]ikev2.Payload, *childPair) {
		return []ikev2.Payload{ikev2.Notification(code, nil)}, nil
	}
	if !s.childCapacity() {
		return reject(temporaryFailureNotify)
	}
	var rekeySPI uint32
	for _, p := range ps {
		if p.Type != ikev2.Notify {
			continue
		}
		code, data, err := ikev2.ParseNotification(p.Data)
		if err != nil {
			return reject(7)
		}
		if code == rekeySANotify {
			if rekeySPI != 0 || p.Data[0] != 3 || p.Data[1] != 4 || len(data) != 0 {
				return reject(7)
			}
			rekeySPI = binary.BigEndian.Uint32(p.Data[4:])
			if rekeySPI == 0 {
				return reject(7)
			}
		}
	}
	if rekeySPI == 0 {
		return reject(7)
	}
	s.childMu.RLock()
	oldPeer := s.out.SPI()
	s.childMu.RUnlock()
	if rekeySPI != oldPeer {
		return []ikev2.Payload{childNotify(childNotFoundNotify, rekeySPI)}, nil
	}
	sa, err := ikev2.One(ps, ikev2.SA)
	if err != nil {
		return reject(7)
	}
	proposals, err := ikev2.ParseProposals(sa)
	if err != nil {
		return reject(7)
	}
	s.childMu.RLock()
	requiredGroup := s.childDHGroup
	s.childMu.RUnlock()
	var selected ikev2.Proposal
	var group uint16
	for _, proposal := range proposals {
		want := s.espProposal(0)
		g := uint16(0)
		for _, t := range proposal.Transforms {
			if t.Type == 4 {
				g = t.ID
			}
		}
		if requiredGroup != 0 && g != requiredGroup {
			continue
		}
		if g != 0 {
			if g != s.keyExchangeGroup {
				continue
			}
			want.Transforms = append(want.Transforms, ikev2.Transform{Type: 4, ID: g})
		}
		want.Number = proposal.Number
		encoded, _ := ikev2.EncodeProposals([]ikev2.Proposal{proposal})
		if _, err = validateProposal(encoded, want); err == nil {
			selected, group = proposal, g
			break
		}
	}
	if len(selected.SPI) != 4 {
		return reject(14)
	}
	peerSPI := binary.BigEndian.Uint32(selected.SPI)
	if !s.freshPeerSPI(peerSPI) {
		return reject(7)
	}
	ni, err := rekeyNonce(ps)
	if err != nil {
		return reject(7)
	}
	if err = s.checkRekeySelectors(ps, false); err != nil {
		return reject(38)
	}
	var shared, localKE []byte
	if group != 0 {
		ke, err := ikev2.One(ps, ikev2.KE)
		if err != nil || len(ke) < 4 || binary.BigEndian.Uint16(ke) != group {
			return []ikev2.Payload{ikev2.Notification(17, binary.BigEndian.AppendUint16(nil, group))}, nil
		}
		dh, err := vc.NewMODP(group, s.cfg.Random)
		if err != nil {
			return reject(temporaryFailureNotify)
		}
		shared, err = dh.Shared(ke[4:])
		if err != nil {
			return []ikev2.Payload{ikev2.Notification(17, binary.BigEndian.AppendUint16(nil, group))}, nil
		}
		defer clear(shared)
		localKE = append([]byte{byte(group >> 8), byte(group), 0, 0}, dh.Public...)
	} else if _, ok := ikev2.Find(ps, ikev2.KE); ok {
		return reject(14)
	}
	spi, nr, err := s.newChildMaterial()
	if err != nil {
		return reject(temporaryFailureNotify)
	}
	pair, err := s.deriveChildPair(spi, peerSPI, ni, nr, shared, false)
	if err != nil {
		return reject(temporaryFailureNotify)
	}
	pair.dhGroup = group
	selected.SPI = binary.BigEndian.AppendUint32(nil, spi)
	sa, err = ikev2.EncodeProposals([]ikev2.Proposal{selected})
	if err != nil {
		return reject(temporaryFailureNotify)
	}
	reply := []ikev2.Payload{{Type: ikev2.SA, Data: sa}, {Type: ikev2.Nonce, Data: nr}}
	if group != 0 {
		reply = append(reply, ikev2.Payload{Type: ikev2.KE, Data: localKE})
	}
	reply = append(reply, s.rekeySelectors(false)...)
	return reply, pair
}

// The original timer subtracts a small random number of seconds. Bound the
// jitter for short configured lifetimes as well as production intervals.
func (s *Session) rekeyDelay(interval time.Duration) time.Duration {
	if interval <= 0 {
		return 0
	}
	span := min(10*time.Second, interval/10)
	if span <= 0 {
		return interval
	}
	var b [8]byte
	if _, err := io.ReadFull(s.cfg.Random, b[:]); err != nil {
		return interval
	}
	return interval - time.Duration(binary.BigEndian.Uint64(b[:])%uint64(span))
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
