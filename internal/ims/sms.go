package ims

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/iniwex5/vowifi-go/runtimehost/messaging"
	smscodec "github.com/warthog618/sms"
	"github.com/warthog618/sms/encoding/tpdu"
	"github.com/warthog618/sms/encoding/ucs2"
)

type rpMessage struct {
	Kind, Reference               byte
	Origin, Destination, UserData []byte
	Cause                         int
}

func parseRP(b []byte) (rpMessage, error) {
	var m rpMessage
	if len(b) < 2 {
		return m, errors.New("RPDU too short")
	}
	m.Kind = b[0]
	m.Reference = b[1]
	b = b[2:]
	field := func() ([]byte, error) {
		if len(b) == 0 {
			return nil, errors.New("RPDU missing length")
		}
		n := int(b[0])
		b = b[1:]
		if n > len(b) {
			return nil, errors.New("RPDU truncated field")
		}
		v := append([]byte(nil), b[:n]...)
		b = b[n:]
		return v, nil
	}
	var e error
	switch m.Kind {
	case 0, 1:
		if m.Origin, e = field(); e != nil {
			return m, e
		}
		if m.Destination, e = field(); e != nil {
			return m, e
		}
		if m.UserData, e = field(); e != nil {
			return m, e
		}
	case 2, 3:
		if len(b) > 0 {
			if b[0] != 0x41 {
				return m, errors.New("RP-ACK unknown IE")
			}
			b = b[1:]
			if m.UserData, e = field(); e != nil {
				return m, e
			}
		}
	case 4, 5:
		c, e := field()
		if e != nil || len(c) < 1 {
			return m, errors.New("RP-ERROR missing cause")
		}
		m.Cause = int(c[0] & 0x7f)
		if len(b) > 0 {
			if b[0] != 0x41 {
				return m, errors.New("RP-ERROR unknown IE")
			}
			b = b[1:]
			if m.UserData, e = field(); e != nil {
				return m, e
			}
		}
	default:
		return m, errors.New("unsupported RP message type")
	}
	if len(b) != 0 {
		return m, errors.New("RPDU trailing data")
	}
	return m, nil
}
func rpAddress(number string) ([]byte, error) {
	if number == "" {
		return nil, nil
	}
	ton := byte(0x81)
	if strings.HasPrefix(number, "+") {
		ton = 0x91
		number = number[1:]
	}
	if len(number) > 20 {
		return nil, errors.New("SMSC address too long")
	}
	b := []byte{ton}
	for i := 0; i < len(number); i += 2 {
		a := number[i] - '0'
		if a > 9 {
			return nil, errors.New("invalid SMSC address")
		}
		z := byte(15)
		if i+1 < len(number) {
			z = number[i+1] - '0'
			if z > 9 {
				return nil, errors.New("invalid SMSC address")
			}
		}
		b = append(b, a|(z<<4))
	}
	return b, nil
}
func rpData(ref byte, destination, tp []byte) ([]byte, error) {
	if len(tp) > 255 || len(destination) > 255 {
		return nil, errors.New("RP-DATA field exceeds 255 bytes")
	}
	b := []byte{0, ref, 0, byte(len(destination))}
	b = append(b, destination...)
	b = append(b, byte(len(tp)))
	b = append(b, tp...)
	return b, nil
}

type smsReference struct {
	MessageID, CallID string
	PartNo            int
	At                time.Time
}
type concatMessage struct {
	Parts map[int]*tpdu.TPDU
	Total int
	At    time.Time
}

func validSMSRecipient(to string) bool {
	to = strings.TrimPrefix(to, "+")
	if to == "" || len(to) > 20 {
		return false
	}
	for _, c := range to {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func (s *Service) allocateReference(r smsReference) (byte, error) {
	s.smsMu.Lock()
	defer s.smsMu.Unlock()
	now := time.Now()
	for n := 0; n < 256; n++ {
		b := byte(s.seq.Add(1))
		v, ok := s.smsPending[b]
		if !ok || now.Sub(v.At) > 10*time.Minute {
			s.smsPending[b] = r
			return b, nil
		}
	}
	return 0, errors.New("all SMS RP references outstanding")
}
func (s *Service) SendSMS(ctx context.Context, to, text, encoding string) (SendResult, error) {
	res := SendResult{MessageID: token()}
	if !s.Ready() {
		return res, errors.Join(messaging.ErrSendNotAttempted, ErrNotReady)
	}
	if !validSMSRecipient(to) {
		return res, errors.New("SMS recipient must be a phone number")
	}
	if !utf8.ValidString(text) || text == "" || len(text) > 65536 {
		return res, errors.New("SMS text must be nonempty UTF-8 and at most 65536 bytes")
	}
	opts := []smscodec.EncoderOption{smscodec.To(to)}
	msg := []byte(text)
	switch strings.ToLower(encoding) {
	case "", "auto":
	case "ucs2":
		msg = ucs2.Encode([]rune(text))
		opts = append(opts, smscodec.AsUCS2)
	default:
		return res, errors.New("unsupported SMS encoding")
	}
	parts, e := smscodec.Encode(msg, opts...)
	if e != nil {
		return res, e
	}
	res.PartsTotal = len(parts)
	if len(parts) > 255 {
		return res, errors.New("SMS exceeds 255 parts")
	}
	smsc := s.cfg.SMSC
	uri := "sip:" + s.cfg.Realm
	if strings.HasPrefix(smsc, "sip:") {
		uri = smsc
		smsc = ""
	}
	destination, e := rpAddress(smsc)
	if e != nil {
		return res, e
	}
	if s.cfg.OnSend != nil {
		if e = s.cfg.OnSend(res.MessageID, to, text, len(parts)); e != nil {
			return res, e
		}
	}
	for i := range parts {
		if !strings.HasPrefix(to, "+") && len(to) <= 6 {
			parts[i].DA.SetTypeOfNumber(tpdu.TonUnknown)
			parts[i].DA.SetNumberingPlan(tpdu.NpISDN)
		}
		callID := token()
		ref, e := s.allocateReference(smsReference{MessageID: res.MessageID, CallID: callID, PartNo: i + 1, At: time.Now()})
		if e != nil {
			return res, e
		}
		release := func() {
			s.smsMu.Lock()
			if current, ok := s.smsPending[ref]; ok && current.CallID == callID {
				delete(s.smsPending, ref)
			}
			s.smsMu.Unlock()
		}
		failBeforeSend := func(cause error) error {
			release()
			if s.cfg.ReliabilityStore != nil {
				return errors.Join(cause, s.cfg.ReliabilityStore.RecordSMSSIPResult(res.MessageID, i+1, 0, "failed", time.Now()))
			}
			return cause
		}
		parts[i].MR = ref
		if s.cfg.ReliabilityStore != nil {
			tpMR, err := s.cfg.ReliabilityStore.ReserveSMSPart(s.cfg.SMSOwner, res.MessageID, i+1, callID, int(ref), time.Now())
			if err != nil {
				release()
				return res, err
			}
			if tpMR < 0 || tpMR > 255 {
				release()
				return res, errors.New("invalid reserved TP reference")
			}
			parts[i].MR = byte(tpMR)
			parts[i].FirstOctet |= tpdu.FoSRR
		}
		b, e := parts[i].MarshalBinary()
		if e != nil {
			return res, failBeforeSend(e)
		}
		body, e := rpData(ref, destination, b)
		if e != nil {
			return res, failBeforeSend(e)
		}
		m := s.request("MESSAGE", uri, callID)
		m.Body = body
		m.set("content-type", "application/vnd.3gpp.sms")
		m.set("accept-contact", "*;+g.3gpp.smsip;require;explicit")
		m.set("request-disposition", "no-fork")
		if e = s.authorize(m); e != nil {
			return res, failBeforeSend(e)
		}
		part := SentPart{PartNo: i + 1, CallID: callID, RPMR: int(ref), State: "pending"}
		if s.cfg.OnPart != nil {
			if e = s.cfg.OnPart(res.MessageID, part); e != nil {
				release()
				return res, e
			}
		}
		r, e := s.transact(ctx, m)
		if e != nil {
			if errors.Is(e, messaging.ErrSendNotAttempted) {
				release()
				part.State = "failed"
			} else {
				e = errors.Join(messaging.ErrSendOutcomeUnknown, e)
				part.State = "unknown"
			} // a lost SIP response does not prove rejection
			res.Parts = append(res.Parts, part)
			if s.cfg.OnPart != nil {
				if storeErr := s.cfg.OnPart(res.MessageID, part); storeErr != nil {
					return res, errors.Join(e, storeErr)
				}
			}
			return res, e
		}
		part.SIPCode = r.status()
		if r.status() < 200 || r.status() >= 300 {
			release()
			part.State = "failed"
			res.Parts = append(res.Parts, part)
			if s.cfg.OnPart != nil {
				if storeErr := s.cfg.OnPart(res.MessageID, part); storeErr != nil {
					return res, errors.Join(e, storeErr)
				}
			}
			return res, fmt.Errorf("SMS SIP rejected: %s", r.Start)
		}
		part.State = "accepted"
		res.Parts = append(res.Parts, part)
		if s.cfg.OnPart != nil {
			if e = s.cfg.OnPart(res.MessageID, part); e != nil {
				return res, e
			}
		}
	}
	return res, nil
}
func (s *Service) receiveSMS(m *message) {
	if !strings.EqualFold(strings.TrimSpace(strings.Split(m.get("content-type"), ";")[0]), "application/vnd.3gpp.sms") {
		_ = s.write(response(m, 415, "Unsupported Media Type"))
		return
	}
	rp, e := parseRP(m.Body)
	if e != nil || rp.Kind&1 == 0 {
		_ = s.write(response(m, 400, "Bad Request"))
		return
	}
	switch rp.Kind {
	case 3, 5:
		// RP-ACK can carry an SMS-SUBMIT-REPORT, not a final status report.
		// Final delivery evidence comes from a separately parsed STATUS-REPORT.
		s.smsMu.Lock()
		ref, ok := s.smsPending[rp.Reference]
		if ok && m.get("in-reply-to") != "" && strings.TrimSpace(m.get("in-reply-to")) != ref.CallID {
			ok = false
		}
		s.smsMu.Unlock()
		state := "acked"
		if rp.Kind == 5 {
			state = "failed"
		}
		if s.cfg.ReliabilityStore != nil {
			callID := strings.TrimSpace(m.get("in-reply-to"))
			if ok {
				callID = ref.CallID
			}
			err := s.cfg.ReliabilityStore.RecordSMSRPReport(s.cfg.SMSOwner, callID, int(rp.Reference), state, rp.Cause, time.Now())
			if err != nil && !errors.Is(err, messaging.ErrDeliveryNotFound) {
				_ = s.write(response(m, 503, "Service Unavailable"))
				return
			}
		} else if ok && s.cfg.OnReport != nil {
			s.cfg.OnReport(Report{CallID: ref.CallID, InReplyTo: m.get("in-reply-to"), RPMR: int(rp.Reference), RPCause: rp.Cause, State: state, At: time.Now()})
		}
		if ok {
			s.smsMu.Lock()
			if current, exists := s.smsPending[rp.Reference]; exists && current.CallID == ref.CallID {
				delete(s.smsPending, rp.Reference)
			}
			s.smsMu.Unlock()
		}
		_ = s.write(response(m, 200, "OK"))
	case 1:
		p, err := smscodec.Unmarshal(rp.UserData)
		if err != nil {
			_ = s.write(response(m, 400, "Bad Request"))
			return
		}
		var notify func()
		switch p.SmsType() {
		case tpdu.SmsStatusReport:
			if p.FirstOctet.SRQ() { // a report for SMS-COMMAND cannot match SMS-SUBMIT
				break
			}
			if s.cfg.ReliabilityStore != nil {
				err = s.cfg.ReliabilityStore.RecordSMSTPReport(s.cfg.SMSOwner, messaging.TPReport{Reference: int(p.MR), Recipient: p.RA.Number(), Status: int(p.ST), ServiceCentreTime: p.SCTS.Time, DischargeTime: p.DT.Time, At: time.Now()})
				if errors.Is(err, messaging.ErrDeliveryNotFound) {
					err = nil
				}
			}
		case tpdu.SmsDeliver:
			alpha, e := p.DCS.Alphabet()
			if e != nil || alpha == tpdu.Alpha8Bit {
				_ = s.write(response(m, 415, "Unsupported Media Type"))
				return
			}
			if _, e = smscodec.Decode([]*tpdu.TPDU{p}); e != nil && p.IsSingleSegment() {
				_ = s.write(response(m, 400, "Bad Request"))
				return
			}
			if s.cfg.InboundStore != nil {
				notify, err = s.persistInboundSMS(p, rp.UserData, rp.Origin)
			} else {
				notify = func() { s.deliverTPDU(p) }
			}
		default:
			_ = s.write(response(m, 400, "Bad Request"))
			return
		}
		if err != nil {
			_ = s.write(response(m, 503, "Service Unavailable"))
			return
		}
		// Persist before acknowledging; a crash after this point cannot lose history.
		_ = s.write(response(m, 200, "OK"))
		ack := s.request("MESSAGE", sipURI(m.get("from")), token())
		ack.Body = []byte{2, rp.Reference}
		ack.set("content-type", "application/vnd.3gpp.sms")
		ack.set("in-reply-to", m.get("call-id"))
		if e = s.authorize(ack); e == nil {
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				ctx, cancel := context.WithTimeout(s.ctx, s.cfg.TransactionTimeout)
				defer cancel()
				_, _ = s.transact(ctx, ack)
				if notify != nil {
					notify()
				}
			}()
		} else if notify != nil {
			notify()
		}
	default:
		_ = s.write(response(m, 400, "Bad Request"))
	}
}
func (s *Service) deliverTPDU(p *tpdu.TPDU) {
	parts := []*tpdu.TPDU{p}
	if total, seq, ref, ok := p.ConcatInfo(); ok {
		if total <= 1 || total > 255 || seq < 1 || seq > total {
			return
		}
		key := fmt.Sprintf("%s:%d:%d:%d", p.OA.Number(), ref, total, p.DCS)
		s.smsMu.Lock()
		for k, c := range s.concats {
			if time.Since(c.At) > 10*time.Minute {
				delete(s.concats, k)
			}
		}
		if len(s.concats) > 256 {
			s.smsMu.Unlock()
			return
		}
		c := s.concats[key]
		if c == nil {
			c = &concatMessage{Parts: make(map[int]*tpdu.TPDU), Total: total, At: time.Now()}
			s.concats[key] = c
		}
		c.Parts[seq] = p
		if len(c.Parts) != total {
			s.smsMu.Unlock()
			return
		}
		parts = make([]*tpdu.TPDU, total)
		for i := 1; i <= total; i++ {
			parts[i-1] = c.Parts[i]
		}
		delete(s.concats, key)
		s.smsMu.Unlock()
	}
	text, e := smscodec.Decode(parts)
	if e != nil || !utf8.Valid(text) {
		return
	}
	if s.cfg.OnSMS != nil {
		s.cfg.OnSMS(p.OA.Number(), string(text), p.SCTS.Time)
	}
}
func sipURI(header string) string {
	if a := strings.IndexByte(header, '<'); a >= 0 {
		if b := strings.IndexByte(header[a+1:], '>'); b >= 0 {
			return header[a+1 : a+1+b]
		}
	}
	return strings.TrimSpace(strings.Split(header, ";")[0])
}
