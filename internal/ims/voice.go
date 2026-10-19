package ims

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pexcn/vowifi-go/internal/voice/media"
	"github.com/pexcn/vowifi-go/runtimehost/voicehost"
)

type VoiceConfig struct {
	DeviceID, LocalAddress string
	ListenPacket           func(context.Context, string, string) (net.PacketConn, error)
	NotifyIncoming         func(caller, callee string)
}
type VoiceAgent struct {
	service   *Service
	cfg       VoiceConfig
	mu        sync.Mutex
	calls     map[string]*voiceCall
	rejected  map[string]*message
	completed map[string]completedVoiceCall
	ctx       context.Context
	cancel    context.CancelFunc
	closed    bool
}
type completedVoiceCall struct {
	call *voiceCall
	at   time.Time
}

type voiceCall struct {
	mu             sync.Mutex
	invite, answer *message
	target         string
	done           chan struct{}
	endOnce        sync.Once
	media          *media.Session
	cancel         context.CancelFunc
	lastPRACK      string
}

func NewVoiceAgent(s *Service, cfg VoiceConfig) (*VoiceAgent, error) {
	if s == nil || !s.Ready() {
		return nil, ErrNotReady
	}
	if cfg.LocalAddress == "" {
		cfg.LocalAddress = s.cfg.LocalAddress
	}
	if net.ParseIP(cfg.LocalAddress) == nil || cfg.ListenPacket == nil {
		return nil, errors.New("voice requires tunnel media listener and local address")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.voice != nil {
		return nil, errors.New("IMS voice agent already installed")
	}
	ctx, cancel := context.WithCancel(s.ctx)
	a := &VoiceAgent{service: s, cfg: cfg, calls: make(map[string]*voiceCall), rejected: make(map[string]*message), completed: make(map[string]completedVoiceCall), ctx: ctx, cancel: cancel}
	s.voice = a
	return a, nil
}
func (a *VoiceAgent) Ready() bool {
	a.mu.Lock()
	closed := a.closed
	a.mu.Unlock()
	return !closed && a.ctx.Err() == nil && a.service.Ready()
}
func (a *VoiceAgent) Close() error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	a.cancel()
	for _, c := range a.calls {
		c.cancel()
	}
	a.mu.Unlock()
	a.service.mu.Lock()
	if a.service.voice == a {
		a.service.voice = nil
	}
	a.service.mu.Unlock()
	return nil
}
func calleeURI(callee, realm string) (string, error) {
	callee = strings.TrimSpace(callee)
	if callee == "" || strings.ContainsAny(callee, "\r\n\x00 <>\t") {
		return "", errors.New("invalid voice callee")
	}
	if strings.HasPrefix(callee, "sip:") || strings.HasPrefix(callee, "sips:") {
		if strings.HasPrefix(callee, "sips:") {
			return "", errors.New("SIPS voice transport unsupported")
		}
		if !strings.Contains(callee, "@") {
			return "", errors.New("SIP callee requires a domain")
		}
		return callee, nil
	}
	callee = strings.TrimPrefix(callee, "tel:")
	for i, r := range callee {
		if r >= '0' && r <= '9' || r == '+' && i == 0 || r == '*' || r == '#' {
			continue
		}
		return "", errors.New("invalid telephone callee")
	}
	if callee == "" || callee == "+" {
		return "", errors.New("invalid telephone callee")
	}
	return "sip:" + callee + "@" + realm + ";user=phone", nil
}
func (a *VoiceAgent) SimulateCall(ctx context.Context, req voicehost.SimulateCallRequest) (res voicehost.SimulateCallResult, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !a.Ready() {
		return res, ErrNotReady
	}
	uri, e := calleeURI(req.Callee, a.service.cfg.Realm)
	if e != nil {
		return res, e
	}
	if req.HoldSeconds <= 0 {
		req.HoldSeconds = voicehost.DefaultSimulateCallHoldSeconds
	}
	if req.HoldSeconds > voicehost.MaxSimulateCallHoldSeconds {
		req.HoldSeconds = voicehost.MaxSimulateCallHoldSeconds
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(a.ctx, cancel)
	defer func() {
		stop()
		cancel()
		if err != nil {
			res.Reason = err.Error()
		}
	}()
	audio, e := media.NewSession(ctx, a.cfg.ListenPacket, a.cfg.LocalAddress)
	if e != nil {
		return res, e
	}
	defer audio.Close()
	offer, e := audio.Local.SDP()
	if e != nil {
		return res, e
	}
	callID := token()
	c := &voiceCall{target: uri, done: make(chan struct{}), media: audio, cancel: cancel}
	a.mu.Lock()
	if a.closed || len(a.calls) > 0 {
		a.mu.Unlock()
		return res, errors.New("voice agent busy or stopped")
	}
	a.calls[callID] = c
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.calls, callID)
		a.mu.Unlock()
	}()
	invite := a.service.request("INVITE", uri, callID)
	invite.set("from", "<"+a.service.cfg.PublicIdentity+">;tag="+token())
	invite.set("content-type", "application/sdp")
	invite.set("supported", "100rel")
	invite.set("allow", "INVITE, ACK, CANCEL, BYE, OPTIONS, PRACK")
	invite.Body = offer
	c.invite = invite
	var answer *message
	for round := 0; round < 3; round++ {
		if e = a.service.authorize(invite); e != nil {
			return res, e
		}
		answer, e = a.invite(ctx, c, invite)
		if e != nil {
			return res, e
		}
		if answer.status() != 401 && answer.status() != 407 {
			break
		}
		if e = a.ack(c, answer); e != nil {
			return res, e
		}
		if round == 2 {
			return res, errors.New("voice authentication round limit exceeded")
		}
		if e = a.challenge(ctx, invite, answer); e != nil {
			return res, e
		}
		old := invite
		invite = a.service.request("INVITE", uri, callID)
		invite.set("from", old.get("from"))
		invite.set("content-type", "application/sdp")
		invite.set("supported", "100rel")
		invite.Body = offer
		c.mu.Lock()
		c.invite = invite
		c.mu.Unlock()
	}
	if answer.status() < 200 || answer.status() >= 300 {
		_ = a.ack(c, answer)
		return res, fmt.Errorf("voice INVITE rejected: %s", answer.Start)
	}
	c.mu.Lock()
	c.answer = answer
	c.mu.Unlock()
	a.remember(c)
	if e = a.ack(c, answer); e != nil {
		_ = a.bye(c)
		return res, e
	}
	defer func() {
		if byeErr := a.bye(c); err == nil && byeErr != nil {
			err = byeErr
		}
	}()
	body := answer.Body
	c.mu.Lock()
	if len(body) == 0 && c.answer != nil {
		body = c.answer.Body
	}
	c.mu.Unlock()
	remote, e := media.ParseSDP(body)
	if e != nil {
		return res, fmt.Errorf("voice answer SDP: %w", e)
	}
	if e = audio.SetRemote(remote); e != nil {
		return res, e
	}
	if e = ctx.Err(); e != nil {
		return res, e
	}
	connectedAt := time.Now()
	defer func() { res.DurationMs = time.Since(connectedAt).Milliseconds() }()
	if req.OnConnected != nil {
		req.OnConnected()
	}
	mediaCtx, mediaCancel := context.WithCancel(ctx)
	defer mediaCancel()
	mediaErr := make(chan error, 1)
	go func() { mediaErr <- audio.RunSilentCall(mediaCtx) }()
	timer := time.NewTimer(time.Duration(req.HoldSeconds) * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-c.done:
		res.Success = true
		res.Reason = "remote_hangup"
	case e := <-mediaErr:
		err = e
	case <-timer.C:
		res.Success = true
		res.Reason = "completed"
	}
	mediaCancel()
	return res, err
}
func (a *VoiceAgent) challenge(ctx context.Context, m, r *message) error {
	header, name := "www-authenticate", "authorization"
	if r.status() == 407 {
		header, name = "proxy-authenticate", "proxy-authorization"
	}
	ch, e := parseChallenge(r.get(header))
	if e != nil {
		return e
	}
	if ch.Realm != a.service.cfg.Realm {
		return errors.New("voice digest realm mismatch")
	}
	aka, e := akaPassword(ctx, a.service.cfg.SIM, ch)
	if e != nil {
		return e
	}
	if len(aka.AUTS) > 0 {
		return fmt.Errorf("voice AKA resynchronization requires registration refresh (%s)", base64.StdEncoding.EncodeToString(aka.AUTS))
	}
	a.service.mu.Lock()
	a.service.auth = ch
	a.service.password = append([]byte(nil), aka.RES...)
	a.service.authName = name
	a.service.nonceCount = 0
	a.service.mu.Unlock()
	return nil
}
func (a *VoiceAgent) invite(ctx context.Context, c *voiceCall, m *message) (*message, error) {
	s := a.service
	key := transactionKey(m)
	responses := make(chan *message, 32)
	s.mu.Lock()
	s.pending[key] = responses
	s.mu.Unlock()
	owned := true
	remove := func() {
		s.mu.Lock()
		if s.pending[key] == responses {
			delete(s.pending, key)
		}
		s.mu.Unlock()
	}
	defer func() {
		if owned {
			remove()
		}
	}()
	if e := s.write(m); e != nil {
		return nil, e
	}
	timeout := time.NewTimer(s.cfg.TransactionTimeout)
	defer timeout.Stop()
	retry := time.NewTimer(500 * time.Millisecond)
	defer retry.Stop()
	interval := 500 * time.Millisecond
	provisional := false
	for {
		select {
		case <-ctx.Done():
			owned = false
			go func() { defer remove(); a.cancelInvite(c, m, responses, provisional) }()
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-timeout.C:
			owned = false
			go func() { defer remove(); a.cancelInvite(c, m, responses, provisional) }()
			return nil, errors.New("voice INVITE timeout")
		case <-retry.C:
			if s.cfg.Transport == "udp" && !provisional {
				if e := s.write(m); e != nil {
					return nil, e
				}
				interval *= 2
				if interval > 4*time.Second {
					interval = 4 * time.Second
				}
				retry.Reset(interval)
			}
		case r := <-responses:
			if r.status() < 200 {
				provisional = true
				retry.Stop()
				if len(r.Body) > 0 {
					c.mu.Lock()
					c.answer = r
					c.mu.Unlock()
				}
				if strings.Contains(strings.ToLower(r.get("require")), "100rel") {
					if e := a.prack(ctx, c, r); e != nil {
						owned = false
						go func() { defer remove(); a.cancelInvite(c, m, responses, true) }()
						return nil, e
					}
				}
				continue
			}
			if len(r.Body) == 0 {
				c.mu.Lock()
				if c.answer != nil && len(c.answer.Body) > 0 && c.lastPRACK != "" {
					r.Body = append([]byte(nil), c.answer.Body...)
				}
				c.mu.Unlock()
			}
			return r, nil
		}
	}
}
func copyHeader(dst, src *message, key string) {
	delete(dst.Headers, key)
	for _, v := range src.Headers[key] {
		dst.add(key, v)
	}
}
func (a *VoiceAgent) cancelInvite(c *voiceCall, m *message, responses <-chan *message, provisional bool) {
	cancel := &message{Start: strings.Replace(m.Start, "INVITE ", "CANCEL ", 1), Headers: make(map[string][]string)}
	for _, k := range []string{"via", "from", "to", "call-id", "route", "max-forwards"} {
		copyHeader(cancel, m, k)
	}
	cancel.set("cseq", strings.Fields(m.get("cseq"))[0]+" CANCEL")
	// RFC 3261: wait for a provisional response before transmitting CANCEL.
	if provisional {
		_ = a.service.write(cancel)
	}
	timer := time.NewTimer(a.service.cfg.TransactionTimeout)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			return
		case <-a.service.ctx.Done():
			return
		case r := <-responses:
			if r.status() < 200 {
				if !provisional {
					_ = a.service.write(cancel)
					provisional = true
				}
				continue
			}
			if r.status() < 300 {
				c.mu.Lock()
				c.answer = r
				c.mu.Unlock()
				a.remember(c)
				_ = a.ack(c, r)
				_ = a.bye(c)
			} else {
				_ = a.ack(c, r)
			}
			return
		}
	}
}
func uriFromHeader(v string) string {
	if i := strings.Index(v, "<"); i >= 0 {
		if j := strings.Index(v[i+1:], ">"); j >= 0 {
			return v[i+1 : i+1+j]
		}
	}
	return strings.TrimSpace(strings.SplitN(v, ";", 2)[0])
}
func (a *VoiceAgent) dialogRequest(c *voiceCall, method string) *message {
	c.mu.Lock()
	defer c.mu.Unlock()
	uri := c.target
	if c.answer != nil {
		if contact := uriFromHeader(c.answer.get("contact")); strings.HasPrefix(contact, "sip:") {
			uri = contact
		}
	}
	m := a.service.request(method, uri, c.invite.get("call-id"))
	m.set("from", c.invite.get("from"))
	if c.answer != nil {
		m.set("to", c.answer.get("to"))
		if rr := c.answer.Headers["record-route"]; len(rr) > 0 {
			delete(m.Headers, "route")
			for i := len(rr) - 1; i >= 0; i-- {
				m.add("route", rr[i])
			}
		}
	}
	return m
}
func (a *VoiceAgent) ack(c *voiceCall, r *message) error {
	if r.status() >= 300 {
		c.mu.Lock()
		m := &message{Start: strings.Replace(c.invite.Start, "INVITE ", "ACK ", 1), Headers: make(map[string][]string)}
		for _, k := range []string{"via", "from", "call-id", "route", "max-forwards"} {
			copyHeader(m, c.invite, k)
		}
		m.set("to", r.get("to"))
		m.set("cseq", strings.Fields(c.invite.get("cseq"))[0]+" ACK")
		c.mu.Unlock()
		return a.service.write(m)
	}
	m := a.dialogRequest(c, "ACK")
	c.mu.Lock()
	m.set("cseq", strings.Fields(c.invite.get("cseq"))[0]+" ACK")
	m.set("to", r.get("to"))
	c.mu.Unlock()
	if e := a.service.authorize(m); e != nil {
		return e
	}
	return a.service.write(m)
}
func (a *VoiceAgent) bye(c *voiceCall) error {
	select {
	case <-c.done:
		return nil
	default:
	}
	c.mu.Lock()
	answer := c.answer
	c.mu.Unlock()
	if answer == nil || answer.status() < 200 || answer.status() >= 300 {
		return nil
	}
	m := a.dialogRequest(c, "BYE")
	if e := a.service.authorize(m); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), a.service.cfg.TransactionTimeout)
	defer cancel()
	r, e := a.service.transact(ctx, m)
	if e != nil {
		return e
	}
	if r.status() != 200 && r.status() != 481 {
		return fmt.Errorf("voice BYE rejected: %s", r.Start)
	}
	c.endOnce.Do(func() { close(c.done) })
	return nil
}
func (a *VoiceAgent) prack(parent context.Context, c *voiceCall, r *message) error {
	rseq, e := strconv.ParseUint(r.get("rseq"), 10, 32)
	if e != nil || rseq == 0 {
		return errors.New("invalid reliable provisional response RSeq")
	}
	c.mu.Lock()
	if c.lastPRACK == r.get("rseq") {
		c.mu.Unlock()
		return nil
	}
	c.lastPRACK = r.get("rseq")
	c.answer = r
	inviteSeq := strings.Fields(c.invite.get("cseq"))[0]
	c.mu.Unlock()
	m := a.dialogRequest(c, "PRACK")
	m.set("rack", fmt.Sprintf("%d %s INVITE", rseq, inviteSeq))
	if e = a.service.authorize(m); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(parent, a.service.cfg.TransactionTimeout)
	defer cancel()
	answer, e := a.service.transact(ctx, m)
	if e != nil {
		return e
	}
	if answer.status() != 200 {
		return fmt.Errorf("voice PRACK rejected: %s", answer.Start)
	}
	return nil
}
func (s *Service) receiveVoice(m *message) bool {
	s.mu.Lock()
	a := s.voice
	s.mu.Unlock()
	if a == nil {
		return false
	}
	id := m.get("call-id")
	a.mu.Lock()
	c := a.calls[id]
	cached := a.rejected[id]
	a.mu.Unlock()
	if c != nil {
		switch m.method() {
		case "BYE":
			c.mu.Lock()
			valid := c.answer != nil && headerTag(m.get("from")) != "" && headerTag(m.get("from")) == headerTag(c.answer.get("to")) && headerTag(m.get("to")) == headerTag(c.invite.get("from"))
			c.mu.Unlock()
			if !valid {
				_ = s.write(response(m, 481, "Call/Transaction Does Not Exist"))
				return true
			}
			_ = s.write(response(m, 200, "OK"))
			c.endOnce.Do(func() { close(c.done) })
		case "INVITE":
			_ = s.write(response(m, 488, "Not Acceptable Here"))
		case "ACK":
		case "CANCEL":
			_ = s.write(response(m, 481, "Call/Transaction Does Not Exist"))
		default:
			return false
		}
		return true
	}
	if cached != nil {
		switch m.method() {
		case "INVITE":
			_ = s.write(cached)
			return true
		case "ACK":
			return true
		case "CANCEL":
			_ = s.write(response(m, 200, "OK"))
			return true
		}
	}
	if m.method() != "INVITE" || !strings.HasPrefix(strings.ToLower(m.get("content-type")), "application/sdp") {
		return false
	}
	if _, e := media.ParseSDP(m.Body); e != nil {
		_ = s.write(response(m, 488, "Not Acceptable Here"))
		return true
	}
	_ = s.write(response(m, 100, "Trying"))
	reject := response(m, 480, "Temporarily Unavailable")
	if !strings.Contains(reject.get("to"), ";tag=") {
		reject.set("to", reject.get("to")+";tag="+token())
	}
	a.mu.Lock()
	if len(a.rejected) > 256 {
		a.rejected = make(map[string]*message)
	}
	a.rejected[id] = reject
	a.mu.Unlock()
	_ = s.write(reject)
	if a.cfg.NotifyIncoming != nil {
		go a.cfg.NotifyIncoming(uriFromHeader(m.get("from")), uriFromHeader(m.get("to")))
	}
	return true
}

// Retain accepted INVITEs for Timer M so a repeated 2xx is acknowledged even
// after the INVITE client transaction, or the call itself, has ended.
func (a *VoiceAgent) remember(c *voiceCall) {
	c.mu.Lock()
	key := transactionKey(c.invite)
	c.mu.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for k, old := range a.completed {
		if now.Sub(old.at) > 64*time.Second {
			delete(a.completed, k)
		}
	}
	if len(a.completed) >= 256 {
		var oldest string
		var at time.Time
		for k, old := range a.completed {
			if oldest == "" || old.at.Before(at) {
				oldest, at = k, old.at
			}
		}
		delete(a.completed, oldest)
	}
	a.completed[key] = completedVoiceCall{call: c, at: now}
}
func (s *Service) receiveVoiceResponse(m *message) bool {
	if m.status() < 200 || m.status() >= 300 || !strings.HasSuffix(m.get("cseq"), " INVITE") {
		return false
	}
	s.mu.Lock()
	a := s.voice
	s.mu.Unlock()
	if a == nil {
		return false
	}
	a.mu.Lock()
	entry, ok := a.completed[transactionKey(m)]
	a.mu.Unlock()
	if !ok || time.Since(entry.at) > 64*time.Second {
		return false
	}
	c := entry.call
	c.mu.Lock()
	same := c.answer != nil && c.answer.get("to") == m.get("to")
	c.mu.Unlock()
	if !same {
		return false
	}
	go func() { _ = a.ack(c, m) }()
	return true
}
