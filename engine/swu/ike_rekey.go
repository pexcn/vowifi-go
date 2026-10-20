package swu

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"time"

	vc "github.com/iniwex5/vowifi-go/engine/crypto"
	"github.com/iniwex5/vowifi-go/engine/ikev2"
)

const (
	defaultIKELifetime = 18 * time.Hour
	ikeOverlap         = 90 * time.Second
)

// An association owns both message-ID windows and the IKE initiator role.
// The original IKE_AUTH fields on Session remain immutable after startup.
// Old associations only serve duplicate requests and IKE Delete exchanges.
type ikeAssociation struct {
	spii, spir       uint64
	keys             vc.IKEKeys
	localInitiator   bool
	created          time.Time
	nextID           uint32 // ikeMu
	lastPeerID       uint32 // remaining fields: sole readLoop owner
	havePeerID       bool
	lastPeerRequest  [32]byte
	lastPeerReply    [][]byte
	lastPeerExchange byte
}

func (a *ikeAssociation) header(exchange byte, id uint32, response bool) ikev2.Header {
	flags := byte(0)
	if a.localInitiator {
		flags |= ikev2.FlagInitiator
	}
	if response {
		flags |= ikev2.FlagResponse
	}
	return ikev2.Header{InitiatorSPI: a.spii, ResponderSPI: a.spir, Exchange: exchange, Flags: flags, MessageID: id}
}
func (a *ikeAssociation) outboundKeys() ([]byte, []byte) {
	if a.localInitiator {
		return a.keys.SKei, a.keys.SKai
	}
	return a.keys.SKer, a.keys.SKar
}
func (a *ikeAssociation) inboundKeys() ([]byte, []byte) {
	if a.localInitiator {
		return a.keys.SKer, a.keys.SKar
	}
	return a.keys.SKei, a.keys.SKai
}
func (a *ikeAssociation) peerFlags(response bool) byte {
	flags := byte(0)
	if !a.localInitiator {
		flags |= ikev2.FlagInitiator
	}
	if response {
		flags |= ikev2.FlagResponse
	}
	return flags
}
func (s *Session) currentIKE() *ikeAssociation {
	s.ikeStateMu.RLock()
	defer s.ikeStateMu.RUnlock()
	return s.activeIKE
}
func (s *Session) pruneIKELocked(now time.Time) {
	if s.retiredIKE != nil && !now.Before(s.retiredIKEUntil) {
		s.retiredIKE = nil
	}
}
func (s *Session) ikeForHeader(h ikev2.Header) (*ikeAssociation, bool) {
	s.ikeStateMu.Lock()
	defer s.ikeStateMu.Unlock()
	s.pruneIKELocked(time.Now())
	if a := s.activeIKE; a != nil && h.InitiatorSPI == a.spii && h.ResponderSPI == a.spir {
		return a, false
	}
	if a := s.retiredIKE; a != nil && h.InitiatorSPI == a.spii && h.ResponderSPI == a.spir {
		return a, true
	}
	return nil, false
}
func (s *Session) canRekeyIKE() bool {
	s.ikeStateMu.Lock()
	defer s.ikeStateMu.Unlock()
	s.pruneIKELocked(time.Now())
	return s.retiredIKE == nil
}
func (s *Session) activateIKE(next *ikeAssociation) {
	s.ikeStateMu.Lock()
	if s.ctx.Err() != nil {
		s.ikeStateMu.Unlock()
		return
	}
	s.retiredIKE, s.retiredIKEUntil = s.activeIKE, time.Now().Add(ikeOverlap)
	s.activeIKE = next
	s.ikeStateMu.Unlock()
	select {
	case s.ikeReset <- struct{}{}:
	default:
	}
}
func (s *Session) ikeRekeyProposal(spi uint64) ikev2.Proposal {
	proposal := (IKEProfile{EncryptionKeyBits: s.protection().KeyBits(s.encLen), PRF: s.prf, Integrity: s.integ, DHGroup: s.keyExchangeGroup, Encryption: s.protection().Encryption}).proposal(1)
	proposal.SPI = binary.BigEndian.AppendUint64(nil, spi)
	return proposal
}
func (s *Session) newIKEMaterial() (uint64, []byte, *vc.MODP, error) {
	var spi uint64
	for i := 0; i < 8; i++ {
		value, err := randomUint(s.cfg.Random)
		if err != nil {
			return 0, nil, nil, err
		}
		s.ikeStateMu.RLock()
		old := s.retiredIKE
		current := s.activeIKE
		used := value == current.spii || value == current.spir || old != nil && (value == old.spii || value == old.spir)
		s.ikeStateMu.RUnlock()
		if !used {
			spi = value
			break
		}
	}
	if spi == 0 {
		return 0, nil, nil, errors.New("unable to generate a fresh IKE SPI")
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(s.cfg.Random, nonce); err != nil {
		return 0, nil, nil, err
	}
	dh, err := vc.NewMODP(s.keyExchangeGroup, s.cfg.Random)
	return spi, nonce, dh, err
}
func (s *Session) validateIKERekey(ps []ikev2.Payload) (uint64, []byte, []byte, error) {
	if err := rejectNotifications(ps); err != nil {
		return 0, nil, nil, err
	}
	for _, p := range ps {
		if p.Type == ikev2.TSi || p.Type == ikev2.TSr || p.Type == ikev2.CP || p.Type == ikev2.EAP || p.Type == ikev2.AUTH {
			return 0, nil, nil, errors.New("unexpected IKE rekey payload")
		}
	}
	sa, err := ikev2.One(ps, ikev2.SA)
	if err != nil {
		return 0, nil, nil, err
	}
	proposal, err := validateProposal(sa, s.ikeRekeyProposal(0))
	if err != nil {
		return 0, nil, nil, err
	}
	spi := binary.BigEndian.Uint64(proposal.SPI)
	a := s.currentIKE()
	if spi == 0 || spi == a.spii || spi == a.spir {
		return 0, nil, nil, errors.New("IKE rekey reused SPI")
	}
	nonce, err := rekeyNonce(ps)
	if err != nil {
		return 0, nil, nil, err
	}
	ke, err := ikev2.One(ps, ikev2.KE)
	if err != nil {
		return 0, nil, nil, err
	}
	if len(ke) < 4 || binary.BigEndian.Uint16(ke) != s.keyExchangeGroup {
		return 0, nil, nil, errors.New("IKE rekey selected unoffered KE group")
	}
	return spi, nonce, ke[4:], nil
}
func (s *Session) rekeyIKE(ctx context.Context) error { return s.rekeyIKEAt(ctx, nil) }
func (s *Session) rekeyIKEAt(ctx context.Context, expected *ikeAssociation) error {
	s.rekeyMu.Lock()
	defer s.rekeyMu.Unlock()
	s.ikeMu.Lock()
	defer s.ikeMu.Unlock()
	old := s.currentIKE()
	if expected != nil && old != expected {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !s.canRekeyIKE() {
		return &childRejection{code: temporaryFailureNotify}
	}
	spi, ni, dh, err := s.newIKEMaterial()
	if err != nil {
		return err
	}
	sa, err := ikev2.EncodeProposals([]ikev2.Proposal{s.ikeRekeyProposal(spi)})
	if err != nil {
		return err
	}
	ke := append([]byte{byte(s.keyExchangeGroup >> 8), byte(s.keyExchangeGroup), 0, 0}, dh.Public...)
	ps := []ikev2.Payload{{Type: ikev2.SA, Data: sa}, {Type: ikev2.Nonce, Data: ni}, {Type: ikev2.KE, Data: ke}}
	m, err := s.exchangeOnIKELocked(ctx, old, ikev2.CreateChildSA, ps)
	if err != nil {
		return err
	}
	peerSPI, nr, peerKey, err := s.validateIKERekey(m.Payloads)
	if err != nil {
		return err
	}
	if peerSPI == spi {
		return errors.New("IKE rekey selected duplicate SPI")
	}
	shared, err := dh.Shared(peerKey)
	if err != nil {
		return err
	}
	defer clear(shared)
	keys, err := vc.DeriveIKERekey(s.prf, s.integ, s.encLen, old.keys.SKd, ni, nr, shared, spi, peerSPI)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	// Keep the old context addressable until its Delete retransmissions end.
	// Child SAs and the inner network remain in place across this switch.
	s.activateIKE(&ikeAssociation{spii: spi, spir: peerSPI, keys: keys, localInitiator: true, created: time.Now()})
	_, _ = s.exchangeOnIKELocked(ctx, old, ikev2.Informational, []ikev2.Payload{{Type: ikev2.Delete, Data: []byte{1, 0, 0, 0}}})
	return nil
}
func (s *Session) preparePeerIKE(ps []ikev2.Payload) ([]ikev2.Payload, *ikeAssociation) {
	reject := func(code uint16) ([]ikev2.Payload, *ikeAssociation) {
		return []ikev2.Payload{ikev2.Notification(code, nil)}, nil
	}
	if !s.canRekeyIKE() {
		return reject(temporaryFailureNotify)
	}
	saOffer, err := ikev2.One(ps, ikev2.SA)
	if err != nil {
		return reject(7)
	}
	proposals, err := ikev2.ParseProposals(saOffer)
	if err != nil {
		return reject(7)
	}
	var chosen ikev2.Proposal
	for _, proposal := range proposals {
		want := s.ikeRekeyProposal(0)
		want.Number = proposal.Number
		encoded, _ := ikev2.EncodeProposals([]ikev2.Proposal{proposal})
		if _, err = validateProposal(encoded, want); err == nil {
			chosen = proposal
			break
		}
	}
	if len(chosen.SPI) != 8 {
		return reject(14)
	}
	number := chosen.Number
	chosen.Number = 1
	encoded, _ := ikev2.EncodeProposals([]ikev2.Proposal{chosen})
	selected := append([]ikev2.Payload{}, ps...)
	for i, payload := range selected {
		if payload.Type == ikev2.SA {
			selected[i].Data = encoded
		}
	}
	peerSPI, ni, peerKey, err := s.validateIKERekey(selected)
	if err != nil {
		return reject(14)
	}
	spi, nr, dh, err := s.newIKEMaterial()
	if err != nil {
		return reject(temporaryFailureNotify)
	}
	if spi == peerSPI {
		return reject(temporaryFailureNotify)
	}
	shared, err := dh.Shared(peerKey)
	if err != nil {
		return []ikev2.Payload{ikev2.Notification(17, binary.BigEndian.AppendUint16(nil, s.keyExchangeGroup))}, nil
	}
	defer clear(shared)
	old := s.currentIKE()
	keys, err := vc.DeriveIKERekey(s.prf, s.integ, s.encLen, old.keys.SKd, ni, nr, shared, peerSPI, spi)
	if err != nil {
		return reject(temporaryFailureNotify)
	}
	proposal := s.ikeRekeyProposal(spi)
	proposal.Number = number
	sa, err := ikev2.EncodeProposals([]ikev2.Proposal{proposal})
	if err != nil {
		return reject(temporaryFailureNotify)
	}
	ke := append([]byte{byte(s.keyExchangeGroup >> 8), byte(s.keyExchangeGroup), 0, 0}, dh.Public...)
	reply := []ikev2.Payload{{Type: ikev2.SA, Data: sa}, {Type: ikev2.Nonce, Data: nr}, {Type: ikev2.KE, Data: ke}}
	return reply, &ikeAssociation{spii: peerSPI, spir: spi, keys: keys, localInitiator: false, created: time.Now()}
}

func retiredInformational(ps []ikev2.Payload) ([]ikev2.Payload, error) {
	for _, p := range ps {
		if p.Type != ikev2.Delete || len(p.Data) != 4 || p.Data[0] != 1 || p.Data[1] != 0 || binary.BigEndian.Uint16(p.Data[2:]) != 0 {
			return nil, errors.New("retired IKE SA only accepts IKE Delete")
		}
	}
	return nil, nil
}

func (s *Session) maintainIKE() { s.maintainIKELifetime(defaultIKELifetime) }
func (s *Session) maintainIKELifetime(lifetime time.Duration) {
	timer := time.NewTimer(s.rekeyDelay(lifetime * 4 / 5))
	defer timer.Stop()
	var authC <-chan time.Time
	if !s.authDeadline.IsZero() {
		authTimer := time.NewTimer(time.Until(s.authDeadline))
		defer authTimer.Stop()
		authC = authTimer.C
	}
	failures := 0
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-authC:
			// AUTH_LIFETIME requires a fresh authentication. IKE rekey alone
			// cannot extend it (RFC 4478), so ask the host to reconnect.
			s.fail(ErrRekeyRequired)
			return
		case <-s.ikeReset:
			failures = 0
			timer.Reset(s.rekeyDelay(time.Until(s.currentIKE().created.Add(lifetime)) - lifetime/5))
		case <-timer.C:
			old := s.currentIKE()
			deadline := old.created.Add(lifetime)
			if !s.authDeadline.IsZero() {
				deadline = minTime(deadline, s.authDeadline)
			}
			if !time.Now().Before(deadline) {
				s.fail(ErrRekeyRequired)
				return
			}
			ctx, cancel := context.WithDeadline(s.ctx, deadline)
			err := s.rekeyIKEAt(ctx, old)
			cancel()
			if err == nil {
				failures = 0
				timer.Reset(s.rekeyDelay(time.Until(s.currentIKE().created.Add(lifetime)) - lifetime/5))
				continue
			}
			failures++
			if failures >= 2 || !time.Now().Before(deadline) {
				s.fail(errors.Join(ErrRekeyRequired, err))
				return
			}
			timer.Reset(s.rekeyDelay(min(time.Minute, time.Until(deadline))))
		}
	}
}
