package ims

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/iniwex5/vowifi-go/runtimehost/messaging"
	smscodec "github.com/warthog618/sms"
	"github.com/warthog618/sms/encoding/tpdu"
)

func inboundFragment(p *tpdu.TPDU, raw, origin []byte) (messaging.InboundFragment, error) {
	f := messaging.InboundFragment{Total: 1, PartNo: 1, TPDU: raw, ServiceCentreTime: p.SCTS.Time, At: time.Now()}
	h := sha256.New()
	fmt.Fprintf(h, "%x|", origin)
	if total, seq, _, ok := p.ConcatInfo(); ok {
		if total < 2 || total > 255 || seq < 1 || seq > total {
			return f, errors.New("invalid SMS concatenation bounds")
		}
		f.Total, f.PartNo = total, seq
		fmt.Fprintf(h, "%s|%d|%d|", p.OA.Number(), p.PID, p.DCS)
		// Include reference width, total and all other UDH IEs (including ports).
		// Omit only sequence: different segments must select the same assembly.
		for _, ie := range p.UDH {
			data := ie.Data
			if ie.ID == 0x00 || ie.ID == 0x08 {
				if len(data) == 0 {
					return f, errors.New("invalid concatenation header")
				}
				data = data[:len(data)-1]
			}
			fmt.Fprintf(h, "%d:%x|", ie.ID, data)
		}
	} else {
		h.Write(raw)
	} // SCTS and content distinguish single-message retries.
	f.Key = hex.EncodeToString(h.Sum(nil))
	return f, nil
}

func (s *Service) persistInboundSMS(p *tpdu.TPDU, raw, origin []byte) (func(), error) {
	f, err := inboundFragment(p, raw, origin)
	if err != nil {
		return nil, err
	}
	a, err := s.cfg.InboundStore.SaveInboundFragment(s.cfg.SMSOwner, f)
	if err != nil {
		return nil, err
	}
	return s.commitInboundAssembly(a)
}

func (s *Service) commitInboundAssembly(a messaging.InboundAssembly) (func(), error) {
	if a.Committed {
		return nil, nil
	}
	if a.Total < 1 || a.Total > 255 || len(a.Parts) != a.Total {
		return nil, errors.New("invalid stored SMS assembly")
	}
	parts := make([]*tpdu.TPDU, a.Total)
	var key string
	for i, raw := range a.Parts {
		if raw == nil {
			return nil, nil
		}
		p, err := smscodec.Unmarshal(raw)
		if err != nil || p.SmsType() != tpdu.SmsDeliver {
			return nil, errors.New("invalid stored SMS TPDU")
		}
		f, err := inboundFragment(p, raw, nil)
		if err != nil {
			return nil, err
		}
		if f.Total != a.Total || f.PartNo != i+1 || i > 0 && f.Key != key {
			return nil, errors.New("inconsistent stored SMS fragments")
		}
		key = f.Key
		parts[i] = p
	}
	text, err := decodeInboundParts(parts)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(text) {
		return nil, errors.New("invalid stored SMS text")
	}
	p := parts[0]
	fresh, err := s.cfg.InboundStore.CommitInboundSMS(s.cfg.SMSOwner, a.ID, p.OA.Number(), string(text), p.SCTS.Time)
	if err != nil || !fresh {
		return nil, err
	}
	return func() {
		if s.cfg.OnStoredSMSWithID != nil {
			s.cfg.OnStoredSMSWithID(a.ID, p.OA.Number(), string(text), p.SCTS.Time)
		} else if s.cfg.OnStoredSMS != nil {
			s.cfg.OnStoredSMS(p.OA.Number(), string(text), p.SCTS.Time)
		}
	}, nil
}

func (s *Service) restoreInboundSMS() error {
	if s.cfg.InboundStore == nil {
		return nil
	}
	assemblies, err := s.cfg.InboundStore.LoadPendingInboundSMS(s.cfg.SMSOwner)
	if err != nil {
		return err
	}
	var failures error
	for _, a := range assemblies {
		notify, err := s.commitInboundAssembly(a)
		if err != nil {
			failures = errors.Join(failures, err)
			continue
		}
		if notify != nil {
			notify()
		}
	}
	return failures
}
