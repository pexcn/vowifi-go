package ims

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

type ussdDialog struct {
	mu                  sync.Mutex
	opMu                sync.Mutex
	Routes              []string
	RemoteURI, From, To string
	Invite              *message
	Results             chan USSDResult
	At                  time.Time
	Closed              bool
}

func (s *Service) SendUSSD(ctx context.Context, code string) (USSDResult, error) {
	if !s.Ready() {
		return USSDResult{}, ErrNotReady
	}
	code = strings.TrimSpace(code)
	if code == "" || !cleanValue(code) {
		return USSDResult{}, errors.New("invalid USSD request")
	}
	id := token()
	m, e := s.ussdInvite(code, id)
	if e != nil {
		return USSDResult{}, e
	}
	uri := strings.Fields(m.Start)[1]
	flow, e := s.flowContext(m.generation)
	if e != nil {
		return USSDResult{}, e
	}
	if e = s.authorize(m); e != nil {
		return USSDResult{}, e
	}
	dialog := &ussdDialog{RemoteURI: uri, From: m.get("from"), To: m.get("to"), Invite: m, Results: make(chan USSDResult, 8), At: time.Now()}
	s.ussdMu.Lock()
	for k, d := range s.ussd {
		if time.Since(d.At) > 5*time.Minute {
			delete(s.ussd, k)
		}
	}
	if len(s.ussd) >= 32 {
		s.ussdMu.Unlock()
		return USSDResult{}, errors.New("too many USSD dialogs")
	}
	s.ussd[id] = dialog
	s.ussdMu.Unlock()
	keepDialog := false
	defer func() {
		if !keepDialog {
			s.ussdMu.Lock()
			delete(s.ussd, id)
			s.ussdMu.Unlock()
		}
	}()

	r, e := s.transact(ctx, m)
	if e != nil {
		return USSDResult{}, e
	}
	ack := s.ussdRequest(dialog, id, "ACK")
	ack.set("to", r.get("to"))
	ack.set("cseq", strings.Split(m.get("cseq"), " ")[0]+" ACK")
	if r.status() < 200 || r.status() >= 300 {
		ack.set("via", m.get("via"))
	}
	if e := s.write(ack); e != nil {
		return USSDResult{}, e
	}
	if r.status() < 200 || r.status() >= 300 {
		return USSDResult{}, fmt.Errorf("USSD INVITE rejected: %s", r.Start)
	}
	if len(r.Body) > 0 {
		text, present, err := decodeUSSDContent(r)
		if err != nil {
			_ = s.CancelUSSD(context.Background(), id)
			return USSDResult{}, err
		}
		if present {
			keepDialog = true
			return USSDResult{SessionID: id, Text: text}, nil
		}
	}
	select {
	case result := <-dialog.Results:
		keepDialog = true
		return result, nil
	case <-ctx.Done():
		_ = s.CancelUSSD(context.Background(), id)
		return USSDResult{}, ctx.Err()
	case <-s.ctx.Done():
		return USSDResult{}, s.ctx.Err()
	case <-flow.Done():
		return USSDResult{}, ErrFlowChanged
	}
}

// Learn the confirmed dialog before dispatch delivers the 200 to its waiter.
// A menu INFO can follow in the same TCP read, before SendUSSD runs again.
func (s *Service) learnUSSDDialog(m *message) {
	if m.status() < 200 || m.status() >= 300 || !strings.HasSuffix(m.get("cseq"), " INVITE") {
		return
	}
	s.ussdMu.Lock()
	d := s.ussd[m.get("call-id")]
	s.ussdMu.Unlock()
	if d == nil || transactionKey(m) != transactionKey(d.Invite) || m.generation != d.Invite.generation {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.Closed {
		return
	}
	d.To = m.get("to")
	if contact := sipURI(m.get("contact")); contact != "" {
		d.RemoteURI = contact
	}
	d.Routes = nil
	for i := len(m.Headers["record-route"]) - 1; i >= 0; i-- {
		d.Routes = append(d.Routes, m.Headers["record-route"][i])
	}
}

// ContinueUSSD sends an in-dialog USSI INFO and waits for the next menu or BYE.
func (s *Service) ContinueUSSD(ctx context.Context, id, input string) (USSDResult, error) {
	if !s.Ready() {
		return USSDResult{}, ErrNotReady
	}
	if input == "" || !cleanValue(input) {
		return USSDResult{}, errors.New("invalid USSD input")
	}
	body, err := encodeUSSD(input)
	if err != nil {
		return USSDResult{}, err
	}
	s.ussdMu.Lock()
	d := s.ussd[id]
	s.ussdMu.Unlock()
	if d == nil {
		return USSDResult{}, errors.New("USSD dialog not found")
	}
	flow, err := s.flowContext(d.Invite.generation)
	if err != nil {
		return USSDResult{}, err
	}
	d.opMu.Lock()
	defer d.opMu.Unlock()
	d.mu.Lock()
	closed := d.Closed
	d.mu.Unlock()
	if closed {
		return USSDResult{}, errors.New("USSD dialog closed")
	}
	m := s.ussdRequest(d, id, "INFO")
	m.set("content-type", ussdContentType)
	m.set("info-package", "g.3gpp.ussd")
	m.set("recv-info", "g.3gpp.ussd")
	m.set("content-disposition", "render;handling=optional")
	m.Body = body
	if err := s.authorize(m); err != nil {
		return USSDResult{}, err
	}
	r, err := s.transact(ctx, m)
	if err != nil {
		return USSDResult{}, err
	}
	if r.status() < 200 || r.status() >= 300 {
		return USSDResult{}, fmt.Errorf("USSD INFO rejected: %s", r.Start)
	}
	if len(r.Body) > 0 {
		text, present, err := decodeUSSDContent(r)
		if err != nil {
			return USSDResult{}, err
		}
		if present {
			return USSDResult{SessionID: id, Text: text}, nil
		}
	}
	select {
	case result := <-d.Results:
		return result, nil
	case <-ctx.Done():
		return USSDResult{}, ctx.Err()
	case <-s.ctx.Done():
		return USSDResult{}, s.ctx.Err()
	case <-flow.Done():
		return USSDResult{}, ErrFlowChanged
	}
}
func (s *Service) ussdRequest(d *ussdDialog, id, method string) *message {
	d.mu.Lock()
	uri, from, to := d.RemoteURI, d.From, d.To
	routes := append([]string(nil), d.Routes...)
	d.mu.Unlock()
	m := s.request(method, uri, id)
	s.ussdHeaders(m)
	m.generation = d.Invite.generation
	m.set("from", from)
	m.set("to", to)
	if len(routes) > 0 {
		delete(m.Headers, "route")
		for _, route := range routes {
			m.add("route", route)
		}
	}
	return m
}

// CancelUSSD terminates the established dialog; readiness is never synthesized.
func (s *Service) CancelUSSD(ctx context.Context, id string) error {
	s.ussdMu.Lock()
	d := s.ussd[id]
	s.ussdMu.Unlock()
	if d == nil {
		return errors.New("USSD dialog not found")
	}
	d.mu.Lock()
	if d.Closed {
		d.mu.Unlock()
		return nil
	}
	d.Closed = true
	d.mu.Unlock()
	defer func() {
		s.ussdMu.Lock()
		delete(s.ussd, id)
		s.ussdMu.Unlock()
		select {
		case d.Results <- USSDResult{SessionID: id, Done: true}:
		default:
		}
	}()
	m := s.ussdRequest(d, id, "BYE")
	if err := s.authorize(m); err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	r, err := s.transact(bounded, m)
	if err != nil {
		return err
	}
	if r.status() < 200 || r.status() >= 300 {
		return fmt.Errorf("USSD BYE rejected: %s", r.Start)
	}
	return nil
}
func (s *Service) receiveUSSD(m *message) {
	id := m.get("call-id")
	s.ussdMu.Lock()
	d := s.ussd[id]
	s.ussdMu.Unlock()
	if m.method() == "ACK" {
		return
	}
	if d == nil {
		if m.method() == "INVITE" {
			_ = s.write(response(m, 488, "Not Acceptable Here"))
			return
		}
		_ = s.write(response(m, 481, "Call/Transaction Does Not Exist"))
		return
	}
	d.mu.Lock()
	from, to, closed := d.From, d.To, d.Closed
	d.mu.Unlock()
	if closed || headerTag(m.get("from")) != headerTag(to) || headerTag(m.get("to")) != headerTag(from) {
		_ = s.write(response(m, 481, "Call/Transaction Does Not Exist"))
		return
	}
	switch m.method() {
	case "INFO":
		text, present, e := decodeUSSDContent(m)
		if errors.Is(e, errUSSDContentType) || e == nil && !present {
			_ = s.write(response(m, 415, "Unsupported Media Type"))
			return
		}
		if e != nil {
			_ = s.write(response(m, 400, "Bad Request"))
			return
		}
		_ = s.write(response(m, 200, "OK"))
		select {
		case d.Results <- USSDResult{SessionID: id, Text: text}:
		default:
		}
	case "BYE":
		text := ""
		if len(m.Body) > 0 {
			var present bool
			var e error
			text, present, e = decodeUSSDContent(m)
			if errors.Is(e, errUSSDContentType) || e == nil && !present {
				_ = s.write(response(m, 415, "Unsupported Media Type"))
				return
			}
			if e != nil {
				_ = s.write(response(m, 400, "Bad Request"))
				return
			}
		}
		_ = s.write(response(m, 200, "OK"))
		d.mu.Lock()
		d.Closed = true
		d.mu.Unlock()
		select {
		case d.Results <- USSDResult{SessionID: id, Text: text, Done: true}:
		default:
		}
		s.ussdMu.Lock()
		delete(s.ussd, id)
		s.ussdMu.Unlock()
	default:
		_ = s.write(response(m, 405, "Method Not Allowed"))
	}
}

func headerTag(value string) string {
	// URI parameters inside a name-addr are distinct from header parameters.
	if end := strings.LastIndexByte(value, '>'); end >= 0 {
		value = value[end+1:]
	} else if semicolon := strings.IndexByte(value, ';'); semicolon >= 0 {
		value = value[semicolon:]
	} else {
		return ""
	}
	for _, p := range strings.Split(value, ";") {
		key, val, ok := strings.Cut(strings.TrimSpace(p), "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "tag") {
			return strings.TrimSpace(val)
		}
	}
	return ""
}
