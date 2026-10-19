package ims

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iniwex5/vowifi-go/engine/sim"
)

type Config struct {
	PrivateIdentity, PublicIdentity, Realm, SMSC string
	PCSCF                                        []string
	Transport                                    string
	// RegisterHeaders supplements REGISTER with carrier-specific headers.
	RegisterHeaders              map[string]string
	UserAgent, ContactParameters string
	SIM                          sim.AKAProvider
	DialContext                  DialContextFunc
	// These listeners must use the same injected protected tunnel network as DialContext.
	ListenPacket                           func(context.Context, string, string) (net.PacketConn, error)
	ListenTCP                              func(context.Context, string, string) (net.Listener, error)
	LocalAddress                           string
	Expires, KeepAlive, TransactionTimeout time.Duration
	OnSMS                                  func(sender, text string, at time.Time)
	OnReport                               func(Report)
	OnSend                                 func(messageID, to, text string, parts int) error
	OnPart                                 func(messageID string, part SentPart) error
	OnState                                func(bool, error)
	// AllowUnauthenticated is limited to explicit lab peers. Carrier use defaults to AKA.
	AllowUnauthenticated bool
	SecurityClient       *SecurityParameters
	InstallSecurity      func(context.Context, SecurityAgreement) (DialContextFunc, error)
}
type SentPart struct {
	PartNo        int
	CallID        string
	RPMR, SIPCode int
	State         string
}
type SendResult struct {
	MessageID  string
	PartsTotal int
	Parts      []SentPart
}
type Report struct {
	CallID, InReplyTo      string
	RPMR, SIPCode, RPCause int
	State, Error           string
	At                     time.Time
}
type USSDResult struct {
	SessionID, Text string
	Done            bool
}
type Service struct {
	voice                                *VoiceAgent
	cfg                                  Config
	ctx                                  context.Context
	cancel                               context.CancelFunc
	mu                                   sync.Mutex
	conn                                 net.Conn
	serverUDP                            net.PacketConn
	serverTCP                            net.Listener
	serverConns                          map[net.Conn]struct{}
	serverLocal, serverPeer              string
	generation                           uint64
	remote                               string
	pending                              map[string]chan *message
	serverResponses                      map[string]cachedResponse
	ready                                bool
	closed                               bool
	lastErr                              error
	writeMu                              sync.Mutex
	registerMu                           sync.Mutex
	seq                                  atomic.Uint32
	callID, tag, contact, securityVerify string
	routes                               []string
	auth                                 challenge
	password                             []byte
	authName                             string
	nonceCount                           uint32
	wg                                   sync.WaitGroup
	smsMu                                sync.Mutex
	smsPending                           map[byte]smsReference
	concats                              map[string]*concatMessage
	ussdMu                               sync.Mutex
	ussd                                 map[string]*ussdDialog
}

var ErrNotReady = errors.New("IMS not registered")

func token() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func cleanValue(s string) bool { return !strings.ContainsAny(s, "\r\n\x00") }
func New(c Config) (*Service, error) {
	for _, s := range []string{c.PrivateIdentity, c.PublicIdentity, c.Realm, c.SMSC, c.LocalAddress, c.UserAgent, c.ContactParameters} {
		if !cleanValue(s) {
			return nil, errors.New("invalid IMS configuration value")
		}
	}
	if c.UserAgent == "" {
		c.UserAgent = "VoHive-OpenIMS/1"
	}
	if strings.ContainsAny(c.ContactParameters, "<>") {
		return nil, errors.New("invalid Contact parameters")
	}
	if c.ContactParameters != "" && !strings.HasPrefix(c.ContactParameters, ";") {
		c.ContactParameters = ";" + c.ContactParameters
	}
	headers := make(map[string]string, len(c.RegisterHeaders))
	for name, value := range c.RegisterHeaders {
		name = strings.ToLower(name)
		if name == "" || !cleanValue(value) {
			return nil, errors.New("invalid REGISTER header")
		}
		for _, ch := range name {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return nil, errors.New("invalid REGISTER header name")
			}
		}
		switch name {
		case "via", "from", "to", "call-id", "cseq", "content-length", "authorization", "proxy-authorization", "security-client", "security-verify", "contact", "expires", "route":
			return nil, fmt.Errorf("reserved REGISTER header %s", name)
		}
		headers[name] = value
	}
	c.RegisterHeaders = headers
	c.PCSCF = append([]string(nil), c.PCSCF...)
	if c.SecurityClient != nil {
		p := *c.SecurityClient
		if _, err := parseSecurity(p.header()); err != nil {
			return nil, fmt.Errorf("invalid Security-Client: %w", err)
		}
		c.SecurityClient = &p
	}
	if c.PrivateIdentity == "" || c.PublicIdentity == "" || c.Realm == "" || len(c.PCSCF) == 0 {
		return nil, errors.New("IMS identity, realm and P-CSCF required")
	}
	if c.Transport == "" {
		c.Transport = "udp"
	}
	if c.Transport != "udp" && c.Transport != "tcp" {
		return nil, errors.New("IMS supports udp or tcp transport")
	}
	if c.Expires <= 0 {
		c.Expires = time.Hour
	}
	if c.KeepAlive <= 0 {
		c.KeepAlive = 25 * time.Second
	}
	if c.TransactionTimeout <= 0 {
		c.TransactionTimeout = 32 * time.Second
	}
	if c.DialContext == nil {
		return nil, errors.New("IMS requires an injected tunnel dialer")
	}
	if !strings.HasPrefix(c.PublicIdentity, "sip:") {
		c.PublicIdentity = "sip:" + c.PublicIdentity
	}
	s := &Service{cfg: c, pending: make(map[string]chan *message), serverResponses: make(map[string]cachedResponse), callID: token(), tag: token(), smsPending: make(map[byte]smsReference), concats: make(map[string]*concatMessage), ussd: make(map[string]*ussdDialog)}
	s.seq.Store(1)
	return s, nil
}
func (s *Service) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ready && !s.closed && s.ctx != nil && s.ctx.Err() == nil
}
func (s *Service) setReady(v bool, e error) {
	s.mu.Lock()
	changed := s.ready != v
	s.ready = v
	if e != nil {
		s.lastErr = e
	}
	s.mu.Unlock()
	if s.cfg.OnState != nil && (changed || e != nil) {
		s.cfg.OnState(v, e)
	}
}
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.ctx != nil {
		s.mu.Unlock()
		return errors.New("IMS service already started")
	}
	if s.closed {
		s.mu.Unlock()
		return errors.New("IMS service closed")
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()
	var last error
	for _, addr := range s.cfg.PCSCF {
		if !cleanValue(addr) {
			last = errors.New("invalid P-CSCF")
			continue
		}
		if _, _, e := net.SplitHostPort(addr); e != nil {
			addr = net.JoinHostPort(strings.Trim(addr, "[]"), "5060")
		}
		if e := s.connect(s.ctx, s.cfg.DialContext, addr); e != nil {
			last = e
			continue
		}
		last = nil
		break
	}
	if last != nil {
		_ = s.Close()
		return fmt.Errorf("P-CSCF connection: %w", last)
	}
	if e := s.register(s.ctx); e != nil {
		_ = s.Close()
		return e
	}
	s.setReady(true, nil)
	s.wg.Add(1)
	go s.maintenance()
	return nil
}
func (s *Service) connect(ctx context.Context, dial DialContextFunc, addr string) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return context.Canceled
	}
	old := s.conn
	s.conn = nil
	s.generation++
	g := s.generation
	s.mu.Unlock()
	if old != nil {
		old.Close()
	}
	c, e := dial(ctx, s.cfg.Transport, addr)
	if e != nil {
		return e
	}
	host := s.cfg.LocalAddress
	if host == "" {
		host, _, _ = net.SplitHostPort(c.LocalAddr().String())
	}
	_, port, _ := net.SplitHostPort(c.LocalAddr().String())
	if port == "" {
		port = "5060"
	}
	contact := "<sip:" + strings.Split(strings.TrimPrefix(s.cfg.PublicIdentity, "sip:"), "@")[0] + "@" + net.JoinHostPort(host, port) + ";transport=" + s.cfg.Transport + ">" + s.cfg.ContactParameters
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		c.Close()
		return context.Canceled
	}
	s.conn = c
	s.remote = c.RemoteAddr().String()
	if s.serverLocal != "" {
		contact = "<sip:" + strings.Split(strings.TrimPrefix(s.cfg.PublicIdentity, "sip:"), "@")[0] + "@" + s.serverLocal + ";transport=" + s.cfg.Transport + ">" + s.cfg.ContactParameters
	}
	s.contact = contact
	s.wg.Add(1)
	s.mu.Unlock()
	go s.readLoop(c, g)
	return nil
}
func (s *Service) write(m *message) error {
	b, e := m.bytes()
	if e != nil {
		return e
	}
	if m.status() >= 200 {
		s.mu.Lock()
		now := time.Now()
		for k, v := range s.serverResponses {
			if now.Sub(v.at) > 64*time.Second {
				delete(s.serverResponses, k)
			}
		}
		if len(s.serverResponses) < 1024 {
			s.serverResponses[serverKey(m)] = cachedResponse{b, now}
		}
		s.mu.Unlock()
	}
	if m.reply != nil {
		return m.reply(b)
	}
	return s.writeBytes(b)
}
func (s *Service) writeBytes(b []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	c := s.conn
	s.mu.Unlock()
	if c == nil {
		return ErrNotReady
	}
	if e := c.SetWriteDeadline(time.Now().Add(5 * time.Second)); e != nil {
		return e
	}
	n, e := c.Write(b)
	if e == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return e
}
func transactionKey(m *message) string {
	branch := ""
	for _, field := range strings.Split(strings.Split(m.get("via"), ",")[0], ";")[1:] {
		name, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if ok && strings.EqualFold(name, "branch") {
			branch = strings.TrimSpace(value)
			break
		}
	}
	return m.get("call-id") + "|" + m.get("cseq") + "|" + branch
}
func (s *Service) dispatch(m *message) {
	if m.status() != 0 {
		s.mu.Lock()
		ch := s.pending[transactionKey(m)]
		s.mu.Unlock()
		if ch != nil {
			select {
			case ch <- m:
			default:
			}
		} else {
			s.receiveVoiceResponse(m)
		}
		return
	}
	s.mu.Lock()
	cached, ok := s.serverResponses[serverKey(m)]
	s.mu.Unlock()
	if ok && time.Since(cached.at) < 64*time.Second {
		if m.reply != nil {
			_ = m.reply(cached.data)
		} else {
			_ = s.writeBytes(cached.data)
		}
		return
	}
	s.handleRequest(m)
}
func (s *Service) readLoop(c net.Conn, g uint64) {
	defer s.wg.Done()
	fail := func(e error) {
		s.mu.Lock()
		current := s.generation == g && !s.closed
		s.mu.Unlock()
		if current {
			s.setReady(false, e)
			s.cancel()
		}
	}

	if s.cfg.Transport == "udp" {
		b := make([]byte, 65536)
		for {
			n, e := c.Read(b)
			if e != nil {
				fail(e)
				return
			}
			if bytes.Equal(b[:n], []byte("\r\n")) || bytes.Equal(b[:n], []byte("\r\n\r\n")) {
				continue
			}
			m, e := readMessage(bufio.NewReader(bytes.NewReader(b[:n])))
			if e != nil {
				continue
			}
			s.dispatch(m)
		}
	}
	r := bufio.NewReaderSize(c, 8192)
	for {
		m, e := readMessage(r)
		if e != nil {
			fail(e)
			return
		}
		s.dispatch(m)
	}
}
func (s *Service) transact(ctx context.Context, m *message) (*message, error) {
	key := transactionKey(m)
	ch := make(chan *message, 8)
	s.mu.Lock()
	s.pending[key] = ch
	serviceCtx := s.ctx
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.pending, key); s.mu.Unlock() }()
	if e := s.write(m); e != nil {
		return nil, e
	}
	timeout := time.NewTimer(s.cfg.TransactionTimeout)
	defer timeout.Stop()
	retry := time.NewTimer(500 * time.Millisecond)
	defer retry.Stop()
	interval := 500 * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-serviceCtx.Done():
			return nil, serviceCtx.Err()
		case <-timeout.C:
			return nil, errors.New("SIP transaction timeout")
		case <-retry.C:
			if s.cfg.Transport == "udp" {
				if e := s.write(m); e != nil {
					return nil, e
				}
				interval *= 2
				if interval > 4*time.Second {
					interval = 4 * time.Second
				}
				retry.Reset(interval)
			}
		case r := <-ch:
			if r.status() < 200 {
				if m.method() == "INVITE" {
					retry.Stop()
				}
				continue
			}
			return r, nil
		}
	}
}
func (s *Service) request(method, uri, callID string) *message {
	m := &message{Start: method + " " + uri + " SIP/2.0", Headers: make(map[string][]string)}
	s.mu.Lock()
	c := s.conn
	s.mu.Unlock()
	local := "0.0.0.0:5060"
	if c != nil {
		local = c.LocalAddr().String()
	}
	m.set("via", "SIP/2.0/"+strings.ToUpper(s.cfg.Transport)+" "+local+";branch=z9hG4bK"+token()+";rport")
	m.set("max-forwards", "70")
	m.set("from", "<"+s.cfg.PublicIdentity+">;tag="+s.tag)
	m.set("to", "<"+uri+">")
	m.set("call-id", callID)
	m.set("cseq", fmt.Sprintf("%d %s", s.seq.Add(1), method))
	s.mu.Lock()
	contact := s.contact
	routes := append([]string(nil), s.routes...)
	verify := s.securityVerify
	s.mu.Unlock()
	m.set("contact", contact)
	m.set("user-agent", s.cfg.UserAgent)
	for _, r := range routes {
		m.add("route", r)
	}
	if verify != "" {
		m.set("security-verify", verify)
	}
	return m
}
func (s *Service) authorize(m *message) error {
	s.mu.Lock()
	c := s.auth
	p := append([]byte(nil), s.password...)
	name := s.authName
	s.nonceCount++
	nc := s.nonceCount
	s.mu.Unlock()
	if c.Nonce == "" {
		return nil
	}
	fields := strings.Fields(m.Start)
	a, e := authHeader(c, s.cfg.PrivateIdentity, p, fields[0], fields[1], m.Body, nc, token(), "")
	if e == nil {
		m.set(name, a)
	}
	return e
}
func (s *Service) register(ctx context.Context) error {
	s.registerMu.Lock()
	defer s.registerMu.Unlock()
	uri := "sip:" + s.cfg.Realm
	s.mu.Lock()
	authenticated := len(s.password) > 0
	s.mu.Unlock()
	var auts string
	for round := 0; round < 5; round++ {
		m := s.request("REGISTER", uri, s.callID)
		m.set("to", "<"+s.cfg.PublicIdentity+">")
		m.set("expires", strconv.Itoa(int(s.cfg.Expires.Seconds())))
		m.set("supported", "path, gruu, sec-agree")
		m.set("accept", "application/sdp, application/vnd.3gpp.sms, application/vnd.3gpp.ussd+xml")
		for name, value := range s.cfg.RegisterHeaders {
			m.set(name, value)
		}
		if s.cfg.SecurityClient != nil {
			m.set("security-client", s.cfg.SecurityClient.header())
			m.set("require", "sec-agree")
		}
		if e := s.authorize(m); e != nil {
			return e
		}
		if auts != "" {
			s.mu.Lock()
			c := s.auth
			name := s.authName
			s.mu.Unlock()
			a, e := authHeader(c, s.cfg.PrivateIdentity, nil, "REGISTER", uri, nil, 1, token(), auts)
			if e != nil {
				return e
			}
			m.set(name, a)
		}
		r, e := s.transact(ctx, m)
		if e != nil {
			return fmt.Errorf("IMS REGISTER: %w", e)
		}
		switch r.status() {
		case 200:
			if !authenticated && !s.cfg.AllowUnauthenticated {
				return errors.New("IMS REGISTER succeeded without required AKA authentication")
			}
			if s.cfg.SecurityClient != nil && s.securityVerify == "" {
				return errors.New("IMS peer omitted required security agreement")
			}
			s.mu.Lock()
			s.routes = append([]string(nil), r.Headers["service-route"]...)
			s.mu.Unlock()
			if ex, e := strconv.Atoi(r.get("expires")); e == nil && ex > 0 {
				s.cfg.Expires = time.Duration(ex) * time.Second
			}
			return nil
		case 401, 407:
			h := "www-authenticate"
			name := "authorization"
			if r.status() == 407 {
				h = "proxy-authenticate"
				name = "proxy-authorization"
			}
			c, e := parseChallenge(r.get(h))
			if e != nil {
				return e
			}
			if c.Realm != s.cfg.Realm {
				return errors.New("IMS digest realm differs from configured realm")
			}
			ar, e := akaPassword(ctx, s.cfg.SIM, c)
			if e != nil {
				return e
			}
			auts = ""
			if len(ar.AUTS) > 0 {
				authenticated = false
				auts = base64.StdEncoding.EncodeToString(ar.AUTS)
			} else {
				authenticated = true
			}
			s.mu.Lock()
			s.auth = c
			for i := range s.password {
				s.password[i] = 0
			}
			s.password = append([]byte(nil), ar.RES...)
			s.authName = name
			s.nonceCount = 0
			s.mu.Unlock()
			if raw := strings.Join(r.Headers["security-server"], ","); raw != "" && auts == "" {
				if s.cfg.SecurityClient == nil || s.cfg.InstallSecurity == nil {
					return ErrUnsupportedSecurity
				}
				client := *s.cfg.SecurityClient
				server, e := selectSecurity(raw, client)
				if e != nil {
					return e
				}
				dial, e := s.cfg.InstallSecurity(ctx, SecurityAgreement{Client: client, Server: server, CK: append([]byte(nil), ar.CK...), IK: append([]byte(nil), ar.IK...), RemoteAddress: s.remote})
				if e != nil {
					return fmt.Errorf("install IMS security: %w", e)
				}
				if dial == nil {
					return errors.New("IMS security installer returned no transport")
				}
				host, _, e := net.SplitHostPort(s.remote)
				if e != nil {
					return e
				}
				if e = s.startSecureServer(ctx, client, server, host); e != nil {
					return fmt.Errorf("IMS protected server listener: %w", e)
				}
				if e = s.connect(ctx, dial, net.JoinHostPort(host, strconv.Itoa(int(server.PortServer)))); e != nil {
					return e
				}
				s.mu.Lock()
				s.securityVerify = raw
				s.mu.Unlock()
			}
		case 423:
			n, e := strconv.Atoi(r.get("min-expires"))
			if e != nil || n <= 0 || n > 86400 {
				return errors.New("invalid IMS Min-Expires")
			}
			s.cfg.Expires = time.Duration(n) * time.Second
		default:
			return fmt.Errorf("IMS REGISTER rejected: %s", r.Start)
		}
	}
	return errors.New("IMS authentication round limit exceeded")
}
func (s *Service) maintenance() {
	defer s.wg.Done()
	delay := s.cfg.Expires * 8 / 10
	if delay < time.Second {
		delay = time.Second
	}
	refresh := time.NewTimer(delay)
	defer refresh.Stop()
	keep := time.NewTicker(s.cfg.KeepAlive)
	defer keep.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-refresh.C:
			if e := s.register(s.ctx); e != nil {
				s.setReady(false, e)
				s.cancel()
				return
			}
			refresh.Reset(s.cfg.Expires * 8 / 10)
		case <-keep.C:
			if e := s.writeBytes([]byte("\r\n\r\n")); e != nil {
				s.setReady(false, e)
				s.cancel()
				return
			}
		}
	}
}
func (s *Service) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.ready = false
	c := s.conn
	s.conn = nil
	serverUDP, serverTCP := s.serverUDP, s.serverTCP
	s.serverUDP, s.serverTCP = nil, nil
	serverConns := make([]net.Conn, 0, len(s.serverConns))
	for conn := range s.serverConns {
		serverConns = append(serverConns, conn)
	}
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if c != nil {
		c.Close()
	}
	if serverUDP != nil {
		serverUDP.Close()
	}
	if serverTCP != nil {
		serverTCP.Close()
	}
	for _, conn := range serverConns {
		conn.Close()
	}
	s.wg.Wait()
	s.mu.Lock()
	for i := range s.password {
		s.password[i] = 0
	}
	s.mu.Unlock()
	return nil
}
func (s *Service) handleRequest(m *message) {
	if s.receiveVoice(m) {
		return
	}
	switch m.method() {
	case "OPTIONS":
		r := response(m, 200, "OK")
		r.set("allow", "REGISTER, MESSAGE, INVITE, INFO, BYE, OPTIONS")
		_ = s.write(r)
	case "MESSAGE":
		s.receiveSMS(m)
	case "INVITE", "INFO", "BYE", "CANCEL", "ACK":
		s.receiveUSSD(m)
	default:
		_ = s.write(response(m, 405, "Method Not Allowed"))
	}
}

// Done closes when transport or registration fails, the parent cancels, or Close is called.
func (s *Service) Done() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx == nil {
		return nil
	}
	return s.ctx.Done()
}
func (s *Service) Err() error { s.mu.Lock(); defer s.mu.Unlock(); return s.lastErr }

type cachedResponse struct {
	data []byte
	at   time.Time
}

func serverKey(m *message) string { return m.get("call-id") + "|" + m.get("cseq") + "|" + m.get("via") }

// LocalAddress returns the actual selected transport endpoint.
func (s *Service) LocalAddress() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}
