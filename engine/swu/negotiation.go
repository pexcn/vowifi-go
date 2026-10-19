package swu

import (
	"errors"
	"fmt"

	vc "github.com/iniwex5/vowifi-go/engine/crypto"
	"github.com/iniwex5/vowifi-go/engine/ikev2"
)

type IKEProfile struct {
	EncryptionKeyBits uint16
	PRF               vc.PRF
	Integrity         vc.Integrity
	DHGroup           uint16
}

func (p IKEProfile) proposal(number byte) ikev2.Proposal {
	return ikev2.Proposal{Number: number, Protocol: 1, Transforms: []ikev2.Transform{{Type: 1, ID: 12, KeyBits: p.EncryptionKeyBits}, {Type: 2, ID: uint16(p.PRF)}, {Type: 3, ID: uint16(p.Integrity)}, {Type: 4, ID: p.DHGroup}}}
}

func configuredIKEProfiles(c Config) ([]IKEProfile, error) {
	profiles := []IKEProfile{{c.EncryptionKeyBits, c.PRF, c.Integrity, c.DHGroup}}
	for _, p := range c.IKEAlternatives {
		duplicate := false
		for _, existing := range profiles {
			duplicate = duplicate || existing == p
		}
		if !duplicate {
			profiles = append(profiles, p)
		}
	}
	if len(profiles) > 8 {
		return nil, errors.New("too many IKE profiles")
	}
	for _, p := range profiles {
		if p.EncryptionKeyBits != 128 && p.EncryptionKeyBits != 256 || p.PRF.Size() == 0 || p.Integrity.KeyLen() == 0 || p.DHGroup != 14 && p.DHGroup != 2 {
			return nil, errors.New("unsupported IKE profile")
		}
	}
	return profiles, nil
}

func (s *Session) ikeProposals() []ikev2.Proposal {
	proposals := make([]ikev2.Proposal, len(s.ikeProfiles))
	for i, p := range s.ikeProfiles {
		proposals[i] = p.proposal(byte(i + 1))
	}
	return proposals
}

func (s *Session) selectIKEProfile(body []byte) error {
	for i, p := range s.ikeProfiles {
		if _, err := validateProposal(body, p.proposal(byte(i+1))); err != nil {
			continue
		}
		if p.DHGroup != s.keyExchangeGroup {
			return errors.New("selected IKE group differs from the KE payload")
		}
		s.prf, s.integ, s.encLen = p.PRF, p.Integrity, int(p.EncryptionKeyBits)/8
		s.cfg.EncryptionKeyBits, s.cfg.DHGroup = p.EncryptionKeyBits, p.DHGroup
		return nil
	}
	return errors.New("responder selected an unoffered IKE profile")
}

func (s *Session) retryKEGroup(group uint16) error {
	if group == s.keyExchangeGroup || s.keRetries >= 1 {
		return errors.New("repeated or excessive INVALID_KE_PAYLOAD")
	}
	for _, p := range s.ikeProfiles {
		if p.DHGroup == group {
			s.keRetries++
			s.keyExchangeGroup = group
			return s.handshake()
		}
	}
	return fmt.Errorf("server requested unoffered DH group %d", group)
}
