package ims

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"
)

type ussdDocument struct {
	XMLName   xml.Name `xml:"ussd-data"`
	Language  string   `xml:"language,omitempty"`
	Text      string   `xml:"ussd-string"`
	ErrorCode string   `xml:"error-code,omitempty"`
}
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

func encodeUSSD(text string) ([]byte, error) {
	if len(text) > 4096 {
		return nil, errors.New("USSD text too long")
	}
	return xml.Marshal(ussdDocument{XMLName: xml.Name{Space: "http://www.3gpp.org/ims/ussd/1.0", Local: "ussd-data"}, Language: "en", Text: text})
}
func decodeUSSD(b []byte) (string, error) {
	if len(b) > 65536 {
		return "", errors.New("USSD XML too large")
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = true
	var doc ussdDocument
	if e := d.Decode(&doc); e != nil {
		return "", e
	}
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if data, ok := tok.(xml.CharData); !ok || strings.TrimSpace(string(data)) != "" {
			return "", errors.New("trailing USSD XML content")
		}
	}
	if doc.XMLName.Local != "ussd-data" || doc.XMLName.Space != "" && doc.XMLName.Space != "http://www.3gpp.org/ims/ussd/1.0" {
		return "", errors.New("invalid USSD XML namespace")
	}
	if doc.ErrorCode != "" {
		return "", fmt.Errorf("USSD remote error %s", doc.ErrorCode)
	}
	if len(doc.Text) > 4096 {
		return "", errors.New("USSD response too long")
	}
	return doc.Text, nil
}
func isUSSD(m *message) bool {
	return strings.EqualFold(strings.TrimSpace(strings.Split(m.get("content-type"), ";")[0]), "application/vnd.3gpp.ussd+xml")
}
func (s *Service) SendUSSD(ctx context.Context, code string) (USSDResult, error) {
	if !s.Ready() {
		return USSDResult{}, ErrNotReady
	}
	if code == "" || strings.ContainsAny(code, "\r\n\x00") {
		return USSDResult{}, errors.New("invalid USSD request")
	}
	b, e := encodeUSSD(code)
	if e != nil {
		return USSDResult{}, e
	}
	id := token()
	uri := "sip:" + url.PathEscape(code) + "@" + s.cfg.Realm + ";user=dialstring"
	m := s.request("INVITE", uri, id)
	flow, e := s.flowContext(m.generation)
	if e != nil {
		return USSDResult{}, e
	}
	m.set("content-type", "application/vnd.3gpp.ussd+xml")
	m.set("accept", "application/vnd.3gpp.ussd+xml")
	m.set("recv-info", "g.3gpp.ussd")
	m.set("supported", "timer")
	m.Body = b
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
	r, e := s.transact(ctx, m)
	if e != nil {
		s.ussdMu.Lock()
		delete(s.ussd, id)
		s.ussdMu.Unlock()
		return USSDResult{}, e
	}
	ack := s.request("ACK", uri, id)
	ack.generation = m.generation
	ack.set("from", m.get("from"))
	ack.set("to", r.get("to"))
	ack.set("cseq", strings.Split(m.get("cseq"), " ")[0]+" ACK")
	if r.status() >= 200 && r.status() < 300 {
		if contact := sipURI(r.get("contact")); contact != "" {
			ack.Start = "ACK " + contact + " SIP/2.0"
			dialog.mu.Lock()
			dialog.RemoteURI = contact
			dialog.mu.Unlock()
		}
		if routes := r.Headers["record-route"]; len(routes) > 0 {
			delete(ack.Headers, "route")
			for i := len(routes) - 1; i >= 0; i-- {
				ack.add("route", routes[i])
				dialog.mu.Lock()
				dialog.Routes = append(dialog.Routes, routes[i])
				dialog.mu.Unlock()
			}
		}
	} else {
		ack.set("via", m.get("via"))
	}
	if e := s.write(ack); e != nil {
		return USSDResult{}, e
	}
	if r.status() < 200 || r.status() >= 300 {
		s.ussdMu.Lock()
		delete(s.ussd, id)
		s.ussdMu.Unlock()
		return USSDResult{}, fmt.Errorf("USSD INVITE rejected: %s", r.Start)
	}
	dialog.mu.Lock()
	dialog.To = r.get("to")
	dialog.mu.Unlock()
	if len(r.Body) > 0 {
		if !isUSSD(r) {
			return USSDResult{}, errors.New("USSD peer returned unsupported content")
		}
		text, e := decodeUSSD(r.Body)
		if e != nil {
			return USSDResult{}, e
		}
		return USSDResult{SessionID: id, Text: text, Done: false}, nil
	}
	select {
	case result := <-dialog.Results:
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
	m.set("content-type", "application/vnd.3gpp.ussd+xml")
	m.set("info-package", "g.3gpp.ussd")
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
		if !isUSSD(r) {
			return USSDResult{}, errors.New("unsupported USSD response content")
		}
		text, err := decodeUSSD(r.Body)
		return USSDResult{SessionID: id, Text: text}, err
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
		if m.method() == "INVITE" && isUSSD(m) {
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
		if !isUSSD(m) {
			_ = s.write(response(m, 415, "Unsupported Media Type"))
			return
		}
		text, e := decodeUSSD(m.Body)
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
			if !isUSSD(m) {
				_ = s.write(response(m, 415, "Unsupported Media Type"))
				return
			}
			var e error
			text, e = decodeUSSD(m.Body)
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
