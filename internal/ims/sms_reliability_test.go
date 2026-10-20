package ims

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iniwex5/vowifi-go/runtimehost/messaging"
	smscodec "github.com/warthog618/sms"
	"github.com/warthog618/sms/encoding/tpdu"
)

type reliabilityProbe struct {
	mu       sync.Mutex
	reserved bool
	reports  []messaging.TPReport
	rp       []string
	sip      []string
	fail     bool
}

func (p *reliabilityProbe) ReserveSMSPart(_ messaging.Subscription, _ string, _ int, _ string, _ int, _ time.Time) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reserved = true
	return 173, nil
}
func (p *reliabilityProbe) RecordSMSSIPResult(_ string, _ int, _ int, state string, _ time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sip = append(p.sip, state)
	return nil
}
func (p *reliabilityProbe) RecordSMSRPReport(_ messaging.Subscription, _ string, _ int, state string, _ int, _ time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail {
		return errors.New("storage unavailable")
	}
	p.rp = append(p.rp, state)
	return nil
}
func (p *reliabilityProbe) RecordSMSTPReport(_ messaging.Subscription, r messaging.TPReport) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail {
		return errors.New("storage unavailable")
	}
	p.reports = append(p.reports, r)
	return nil
}

func statusReport(t *testing.T, mr byte, status byte) []byte {
	t.Helper()
	at := time.Now().UTC().Truncate(time.Second)
	p := tpdu.TPDU{Direction: tpdu.MT, FirstOctet: 2, MR: mr, ST: status, SCTS: tpdu.Timestamp{Time: at}, DT: tpdu.Timestamp{Time: at}}
	p.RA.SetNumber("+15551234")
	b, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSMSDurableStatusReportFlow(t *testing.T) {
	probe := &reliabilityProbe{}
	reportTP := statusReport(t, 173, 0)
	cfg := configPeer(t, func(c net.Conn) error {
		r := bufio.NewReader(c)
		auth, err := peerRegister(r, c)
		if err != nil {
			return err
		}
		if err = sendPeer(c, response(auth, 200, "OK")); err != nil {
			return err
		}
		submit, err := readMessage(r)
		if err != nil {
			return err
		}
		rp, err := parseRP(submit.Body)
		if err != nil {
			return err
		}
		p, err := smscodec.Unmarshal(rp.UserData, smscodec.AsMO)
		if err != nil {
			return err
		}
		probe.mu.Lock()
		reserved := probe.reserved
		probe.mu.Unlock()
		if !reserved || !p.FirstOctet.SRR() || p.MR != 173 || rp.Reference == p.MR {
			return fmt.Errorf("submission lacked durable independent TP reference: %+v", p)
		}
		// TP/RP reports deliberately arrive before the MESSAGE final SIP response.
		mt := &message{Start: "MESSAGE sip:user@ims.test SIP/2.0", Headers: map[string][]string{}, Body: append([]byte{1, 44, 0, 0, byte(len(reportTP))}, reportTP...)}
		mt.set("content-type", "application/vnd.3gpp.sms")
		mt.set("from", "<sip:smsc@ims.test>")
		mt.set("call-id", "final-report")
		mt.set("cseq", "1 MESSAGE")
		mt.set("via", "SIP/2.0/TCP peer;branch=z9hG4bKreport")
		if err = sendPeer(c, mt); err != nil {
			return err
		}
		accepted, err := readMessage(r)
		if err != nil || accepted.status() != 200 {
			return fmt.Errorf("report SIP response: %v %v", accepted, err)
		}
		ack, err := readMessage(r)
		if err != nil || string(ack.Body) != string([]byte{2, 44}) {
			return fmt.Errorf("report RP acknowledgement: %v %v", ack, err)
		}
		if err = sendPeer(c, response(ack, 200, "OK")); err != nil {
			return err
		}
		mt.Body = []byte{3, rp.Reference}
		mt.set("call-id", "rp-report")
		mt.set("in-reply-to", submit.get("call-id"))
		mt.set("via", "SIP/2.0/TCP peer;branch=z9hG4bKrp")
		if err = sendPeer(c, mt); err != nil {
			return err
		}
		accepted, err = readMessage(r)
		if err != nil || accepted.status() != 200 {
			return fmt.Errorf("RP SIP response: %v %v", accepted, err)
		}
		if err = sendPeer(c, response(submit, 202, "Accepted")); err != nil {
			return err
		}
		_, _ = readMessage(r)
		return nil
	})
	cfg.ReliabilityStore = probe
	cfg.SMSOwner = messaging.Subscription{DeviceID: "dev", IMSI: "sim"}
	cfg.OnPart = func(id string, p SentPart) error {
		return probe.RecordSMSSIPResult(id, p.PartNo, p.SIPCode, p.State, time.Now())
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.SendSMS(context.Background(), "+15551234", "hello", "auto"); err != nil {
		t.Fatal(err)
	}
	probe.mu.Lock()
	defer probe.mu.Unlock()
	if len(probe.reports) != 1 || probe.reports[0].Reference != 173 || probe.reports[0].Status != 0 || probe.reports[0].Recipient != "+15551234" {
		t.Fatalf("TP reports=%+v", probe.reports)
	}
	if len(probe.rp) != 1 || probe.rp[0] != "acked" {
		t.Fatalf("RP reports=%+v", probe.rp)
	}
	if len(probe.sip) != 2 || probe.sip[1] != "accepted" {
		t.Fatalf("SIP results=%+v", probe.sip)
	}
}

type inboxProbe struct {
	assemblies           map[string]messaging.InboundAssembly
	failSave, failCommit bool
	commits              int
	owners               []messaging.Subscription
}

func (p *inboxProbe) SaveInboundFragment(o messaging.Subscription, f messaging.InboundFragment) (messaging.InboundAssembly, error) {
	p.owners = append(p.owners, o)
	if p.failSave {
		return messaging.InboundAssembly{}, errors.New("disk full")
	}
	a, ok := p.assemblies[f.Key]
	if !ok {
		a = messaging.InboundAssembly{ID: f.Key, Total: f.Total, Parts: make([][]byte, f.Total)}
	}
	a.Parts[f.PartNo-1] = f.TPDU
	p.assemblies[f.Key] = a
	return a, nil
}
func (p *inboxProbe) LoadPendingInboundSMS(o messaging.Subscription) ([]messaging.InboundAssembly, error) {
	p.owners = append(p.owners, o)
	var out []messaging.InboundAssembly
	for _, a := range p.assemblies {
		if !a.Committed {
			out = append(out, a)
		}
	}
	return out, nil
}
func (p *inboxProbe) CommitInboundSMS(_ messaging.Subscription, id, _, _ string, _ time.Time) (bool, error) {
	if p.failCommit {
		return false, errors.New("commit failed")
	}
	a := p.assemblies[id]
	if a.Committed {
		return false, nil
	}
	a.Committed = true
	p.assemblies[id] = a
	p.commits++
	return true, nil
}

func TestSMSDurableInboxRestartAndDuplicate(t *testing.T) {
	text := strings.Repeat("重启恢复🌍", 50)
	parts, err := smscodec.Encode([]byte(text), smscodec.AsDeliver, smscodec.From("+15551234"))
	if err != nil || len(parts) < 2 {
		t.Fatalf("encode %v", err)
	}
	store := &inboxProbe{assemblies: map[string]messaging.InboundAssembly{}}
	owner := messaging.Subscription{DeviceID: "dev", IMSI: "original-sim"}
	var got []string
	cfg := Config{InboundStore: store, SMSOwner: owner, OnStoredSMS: func(_, s string, _ time.Time) { got = append(got, s) }}
	// First process gets only the last segment.
	s := &Service{cfg: cfg}
	raw, err := parts[len(parts)-1].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	p, err := smscodec.Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	notify, err := s.persistInboundSMS(p, raw, nil)
	if err != nil || notify != nil {
		t.Fatalf("incomplete %v", err)
	}
	// A new service reads incomplete durable state, then completes out of order.
	s = &Service{cfg: cfg}
	if err = s.restoreInboundSMS(); err != nil {
		t.Fatal(err)
	}
	for i := len(parts) - 2; i >= 0; i-- {
		raw, err = parts[i].MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		p, err = smscodec.Unmarshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		notify, err = s.persistInboundSMS(p, raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		if notify != nil {
			notify()
		}
	}
	if len(got) != 1 || got[0] != text || store.commits != 1 {
		t.Fatalf("restored text=%+v commits=%d", got, store.commits)
	}
	// Network repetition must not insert/notify the full message twice.
	notify, err = s.persistInboundSMS(p, raw, nil)
	if err != nil || notify != nil {
		t.Fatalf("duplicate %v", err)
	}
	if err = s.restoreInboundSMS(); err != nil {
		t.Fatal(err)
	}
	for _, o := range store.owners {
		if o != owner {
			t.Fatalf("wrong subscription %+v", o)
		}
	}
}

func TestSMSInboxRestoreCompleteAfterCrashBeforeCommit(t *testing.T) {
	parts, err := smscodec.Encode([]byte("saved before crash"), smscodec.AsDeliver, smscodec.From("1234"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := parts[0].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	store := &inboxProbe{assemblies: map[string]messaging.InboundAssembly{"saved": {ID: "saved", Total: 1, Parts: [][]byte{raw}}}}
	notified := 0
	s := &Service{cfg: Config{InboundStore: store, OnStoredSMS: func(_, s string, _ time.Time) { notified++ }}}
	if err = s.restoreInboundSMS(); err != nil {
		t.Fatal(err)
	}
	if store.commits != 1 || notified != 1 {
		t.Fatal("complete persisted assembly not recovered")
	}
}

func TestSMSInboxStorageFailureDoesNotAcknowledge(t *testing.T) {
	for _, fail := range []string{"save", "commit"} {
		t.Run(fail, func(t *testing.T) {
			parts, err := smscodec.Encode([]byte("durable first"), smscodec.AsDeliver, smscodec.From("1234"))
			if err != nil {
				t.Fatal(err)
			}
			raw, err := parts[0].MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			store := &inboxProbe{assemblies: map[string]messaging.InboundAssembly{}, failSave: fail == "save", failCommit: fail == "commit"}
			s := &Service{cfg: Config{InboundStore: store}, serverResponses: map[string]cachedResponse{}}
			m := &message{Start: "MESSAGE sip:user@ims.test SIP/2.0", Body: append([]byte{1, 7, 0, 0, byte(len(raw))}, raw...)}
			m.set("content-type", "application/vnd.3gpp.sms")
			code := 0
			m.reply = func(raw []byte) error {
				r, err := readMessage(bufio.NewReader(strings.NewReader(string(raw))))
				if err != nil {
					return err
				}
				code = r.status()
				return nil
			}
			s.receiveSMS(m)
			if code != 503 || store.commits != 0 {
				t.Fatalf("acknowledged unpersisted SMS: %d %d", code, store.commits)
			}
		})
	}
}

func TestSMSInboxCommitPrecedesPositiveSIPResponse(t *testing.T) {
	parts, err := smscodec.Encode([]byte("persist first"), smscodec.AsDeliver, smscodec.From("1234"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := parts[0].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	store := &inboxProbe{assemblies: map[string]messaging.InboundAssembly{}}
	notified := make(chan struct{}, 1)
	s := &Service{cfg: Config{InboundStore: store, TransactionTimeout: time.Second, OnStoredSMS: func(_, s string, _ time.Time) { notified <- struct{}{} }}, ctx: context.Background(), serverResponses: map[string]cachedResponse{}}
	m := &message{Start: "MESSAGE sip:user@ims.test SIP/2.0", Body: append([]byte{1, 7, 0, 0, byte(len(raw))}, raw...)}
	m.set("content-type", "application/vnd.3gpp.sms")
	m.set("from", "<sip:smsc@ims.test>")
	positive := false
	m.reply = func(raw []byte) error {
		r, err := readMessage(bufio.NewReader(strings.NewReader(string(raw))))
		if err != nil {
			return err
		}
		if r.status() == 200 {
			if store.commits != 1 {
				t.Error("positive SIP response preceded durable commit")
			}
			positive = true
		}
		return nil
	}
	s.receiveSMS(m)
	s.wg.Wait()
	if !positive {
		t.Fatal("committed SMS was not acknowledged")
	}
	select {
	case <-notified:
	default:
		t.Fatal("committed SMS did not notify")
	}
}

func TestSMSRPStorageFailureRetainsPendingReference(t *testing.T) {
	probe := &reliabilityProbe{fail: true}
	s := &Service{cfg: Config{ReliabilityStore: probe}, serverResponses: map[string]cachedResponse{}, smsPending: map[byte]smsReference{7: {CallID: "submit", At: time.Now()}}}
	m := &message{Start: "MESSAGE sip:user@ims.test SIP/2.0", Body: []byte{3, 7}}
	m.set("content-type", "application/vnd.3gpp.sms")
	code := 0
	m.reply = func(raw []byte) error {
		r, err := readMessage(bufio.NewReader(strings.NewReader(string(raw))))
		if err != nil {
			return err
		}
		code = r.status()
		return nil
	}
	s.receiveSMS(m)
	if code != 503 || len(s.smsPending) != 1 {
		t.Fatalf("lost unpersisted RP report: code=%d pending=%v", code, s.smsPending)
	}
	probe.fail = false
	s.receiveSMS(m)
	if code != 200 || len(s.smsPending) != 0 {
		t.Fatal("failed report persistence could not be retried")
	}
}
