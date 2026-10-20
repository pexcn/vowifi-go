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
	"github.com/iniwex5/vowifi-go/runtimehost/messaging"
)

type Config struct {
	SMSOwner          messaging.Subscription
	ReliabilityStore  messaging.ReliabilityStore
	InboundStore      messaging.InboundStore
	OnStoredSMS       func(sender, text string, at time.Time)
	OnStoredSMSWithID func(id, sender, text string, at time.Time)
	OnSMSStoreError   func(error)

	PrivateIdentity, PublicIdentity, Realm, SMSC string
	PCSCF                                        []string
	Transport                                    string
	// RegisterHeaders supplements REGISTER with carrier-specific headers.
	RegisterHeaders              map[string]string
	UserAgent, ContactParameters string
	// SIPInstance is an unquoted URN, serialized as a quoted Contact parameter.
	SIPInstance string
	// Initial REGISTER carries an empty-response Digest header to request AKA.
	// Some carrier templates omit algorithm from that initial placeholder only.
	UsePlainDigestPlaceholder bool
	SIM                       sim.AKAProvider
	DialContext               DialContextFunc
	// These listeners must use the same injected protected tunnel network as DialContext.
	ListenPacket                               func(context.Context, string, string) (net.PacketConn, error)
	ListenTCP                                  func(context.Context, string, string) (net.Listener, error)
	LocalAddress                               string
	Expires, KeepAlive, TransactionTimeout     time.Duration
	RecoveryInitial, RecoveryMax               time.Duration
	SIPTimerT1, SIPTimerT2                     time.Duration
	TemporaryStatusCodes, ForbiddenStatusCodes []int
	OnSMS                                      func(sender, text string, at time.Time)
	OnReport                                   func(Report)
	OnSend                                     func(messageID, to, text string, parts int) error
	OnPart                                     func(messageID string, part SentPart) error
	OnState                                    func(bool, error)
	// AllowUnauthenticated is limited to explicit lab peers. Carrier use defaults to AKA.
	AllowUnauthenticated bool
	SecurityClient       *SecurityParameters
	// Additional supported transforms share the primary offer's ports and SPIs.
	SecurityClientAlternatives []SecurityParameters
	OnRegistrationFailure      func(phase string, round int, request, response string)
	InstallSecurity            func(context.Context, SecurityAgreement) (DialContextFunc, error)
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
	stateMu                              sync.Mutex
	flowCtx                              context.Context
	flowCancel                           context.CancelFunc
	serverBroken                         bool
	everReady                            bool
	registeredUntil                      time.Time
	recovery                             chan struct{}
	targets                              []registrarTarget
	targetIndex                          int
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
	for _, s := range []string{c.PrivateIdentity, c.PublicIdentity, c.Realm, c.SMSC, c.LocalAddress, c.UserAgent, c.ContactParameters, c.SIPInstance} {
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
	if c.SIPInstance != "" && (!strings.HasPrefix(c.SIPInstance, "urn:") || strings.ContainsAny(c.SIPInstance, "<>\"\\; \t")) {
		return nil, errors.New("invalid SIP instance URN")
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
	c.SecurityClientAlternatives = append([]SecurityParameters(nil), c.SecurityClientAlternatives...)
	for _, p := range c.SecurityClientAlternatives {
		if c.SecurityClient == nil {
			return nil, errors.New("Security-Client alternatives require a primary offer")
		}
		if _, err := parseSecurity(p.header()); err != nil {
			return nil, fmt.Errorf("invalid Security-Client alternative: %w", err)
		}
		primary := *c.SecurityClient
		if p.SPIClient != primary.SPIClient || p.SPIServer != primary.SPIServer || p.PortClient != primary.PortClient || p.PortServer != primary.PortServer {
			return nil, errors.New("Security-Client alternatives must share ports and SPIs")
		}
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
	if c.RecoveryInitial <= 0 {
		c.RecoveryInitial = time.Minute
	}
	if c.RecoveryMax < c.RecoveryInitial {
		c.RecoveryMax = max(5*time.Minute, c.RecoveryInitial)
	}
	if c.TemporaryStatusCodes == nil {
		c.TemporaryStatusCodes = []int{408, 429, 500, 502, 503, 504}
	}
	if c.ForbiddenStatusCodes == nil {
		c.ForbiddenStatusCodes = []int{403}
	}
	c.TemporaryStatusCodes = append([]int{}, c.TemporaryStatusCodes...)
	c.ForbiddenStatusCodes = append([]int{}, c.ForbiddenStatusCodes...)
	if c.SIPTimerT1 <= 0 {
		c.SIPTimerT1 = 500 * time.Millisecond
	}
	if c.SIPTimerT2 <= 0 {
		c.SIPTimerT2 = 4 * time.Second
	}
	if c.SIPTimerT2 < c.SIPTimerT1 || c.SIPTimerT2 > 16*time.Second {
		return nil, errors.New("invalid SIP retransmission timers")
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
	s := &Service{cfg: c, recovery: make(chan struct{}, 1), pending: make(map[string]chan *message), serverResponses: make(map[string]cachedResponse), callID: token(), tag: token(), smsPending: make(map[byte]smsReference), concats: make(map[string]*concatMessage), ussd: make(map[string]*ussdDialog)}
	seen := map[string]bool{}
	for _, addr := range c.PCSCF {
		if !cleanValue(addr) {
			return nil, errors.New("invalid P-CSCF")
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(strings.Trim(addr, "[]"), "5060")
		}
		if !seen[addr] {
			s.targets = append(s.targets, registrarTarget{address: addr})
			seen[addr] = true
		}
	}
	if len(s.targets) > 32 {
		return nil, errors.New("too many P-CSCF candidates")
	}
	s.seq.Store(1)
	return s, nil
}
func (s *Service) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ready && !s.closed && !s.serverBroken && s.ctx != nil && s.ctx.Err() == nil && s.flowCtx != nil && s.flowCtx.Err() == nil && time.Now().Before(s.registeredUntil)
}
func (s *Service) setReady(v bool, e error) bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.mu.Lock()
	if s.closed || s.ctx == nil || s.ctx.Err() != nil {
		s.mu.Unlock()
		return false
	}
	if v && (s.conn == nil || s.flowCtx == nil || s.flowCtx.Err() != nil || s.serverBroken) {
		s.mu.Unlock()
		return false
	}
	changed := s.ready != v
	s.ready = v
	if v {
		s.lastErr = nil
		s.everReady = true
	} else if e != nil {
		s.lastErr = e
	}
	s.mu.Unlock()
	if s.cfg.OnState != nil && (changed || e != nil) {
		s.cfg.OnState(v, e)
	}
	return true
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
	// Recovery failure leaves durable assemblies intact. It must not prevent
	// IMS registration or unrelated SMS from being received.
	if err := s.restoreInboundSMS(); err != nil && s.cfg.OnSMSStoreError != nil {
		s.cfg.OnSMSStoreError(fmt.Errorf("restore inbound SMS: %w", err))
	}
	var last error
	for index := range s.targets {
		if index > 0 {
			if e := s.resetRegistration(); e != nil {
				last = e
				break
			}
		}
		s.mu.Lock()
		s.targetIndex = index
		s.mu.Unlock()
		if e := s.connect(s.ctx, s.cfg.DialContext, s.targets[index].address); e != nil {
			last = &flowError{e}
			continue
		}
		last = s.register(s.ctx)
		if last == nil && s.setReady(true, nil) {
			s.mu.Lock()
			if s.closed || s.ctx.Err() != nil {
				s.mu.Unlock()
				last = context.Canceled
				break
			}
			s.wg.Add(2)
			s.mu.Unlock()
			go s.maintenance()
			go s.keepaliveLoop()
			return nil
		}
		if last == nil {
			last = &flowError{net.ErrClosed}
		}
		var rejection *registrationError
		if !recoverableRegistration(last) || errors.As(last, &rejection) && !containsCode(s.cfg.TemporaryStatusCodes, rejection.status) {
			break
		}
	}
	_ = s.Close()
	return last
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
	if s.flowCancel != nil {
		s.flowCancel()
	}
	s.flowCtx, s.flowCancel = context.WithCancel(s.ctx)
	g := s.generation
	s.mu.Unlock()
	if old != nil {
		old.Close()
	}
	dialCtx, cancel := context.WithTimeout(ctx, s.cfg.TransactionTimeout)
	c, e := dial(dialCtx, s.cfg.Transport, addr)
	cancel()
	if e != nil {
		return &flowError{e}
	}
	if c == nil {
		return errors.New("IMS dialer returned no transport")
	}
	host := s.cfg.LocalAddress
	if host == "" {
		host, _, _ = net.SplitHostPort(c.LocalAddr().String())
	}
	_, port, _ := net.SplitHostPort(c.LocalAddr().String())
	if port == "" {
		port = "5060"
	}
	contact := s.contactFor(net.JoinHostPort(host, port))
	s.mu.Lock()
	if s.closed || s.generation != g || ctx.Err() != nil || s.ctx.Err() != nil {
		s.mu.Unlock()
		c.Close()
		return context.Canceled
	}
	s.conn = c
	s.remote = c.RemoteAddr().String()
	if s.serverLocal != "" {
		contact = s.contactFor(s.serverLocal)
	}
	s.contact = contact
	s.wg.Add(1)
	s.mu.Unlock()
	go s.readLoop(c, g)
	return nil
}

func (s *Service) contactFor(address string) string {
	contact := "<sip:" + strings.Split(strings.TrimPrefix(s.cfg.PublicIdentity, "sip:"), "@")[0] + "@" + address + ";transport=" + s.cfg.Transport + ">"
	if s.cfg.SIPInstance != "" {
		contact += ";+sip.instance=" + strconv.Quote("<"+s.cfg.SIPInstance+">")
	}
	return contact + s.cfg.ContactParameters
}
func (s *Service) write(m *message) error {
	b, e := m.bytes()
	if e != nil {
		return e
	}
	if m.status() >= 200 {
		s.mu.Lock()
		if m.generation != 0 && m.generation != s.generation {
			s.mu.Unlock()
			return ErrFlowChanged
		}
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
	s.mu.Lock()
	c, g := s.conn, s.generation
	s.mu.Unlock()
	if m.generation != 0 && m.generation != g {
		return ErrFlowChanged
	}
	return s.writeOn(c, g, b)
}
func (s *Service) writeBytes(b []byte) error {
	s.mu.Lock()
	c, g := s.conn, s.generation
	s.mu.Unlock()
	return s.writeOn(c, g, b)
}
func (s *Service) writeOn(c net.Conn, g uint64, b []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	current := !s.closed && s.conn == c && s.generation == g && s.flowCtx != nil && s.flowCtx.Err() == nil && s.ctx.Err() == nil
	s.mu.Unlock()
	if !current {
		return ErrFlowChanged
	}
	if c == nil {
		return ErrNotReady
	}
	if err := c.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return &flowError{err}
	}
	n, err := c.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return &flowError{err}
	}
	return nil
}
func (s *Service) dispatchOn(m *message, c net.Conn, g uint64) {
	s.mu.Lock()
	current := !s.closed && s.conn == c && s.generation == g && s.flowCtx.Err() == nil
	s.mu.Unlock()
	if current {
		m.generation = g
		s.dispatch(m)
	}
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
			s.mu.Lock()
			c, g := s.conn, s.generation
			s.mu.Unlock()
			if m.generation == 0 || m.generation == g {
				_ = s.writeOn(c, g, cached.data)
			}
		}
		return
	}
	s.handleRequest(m)
}
func (s *Service) readLoop(c net.Conn, g uint64) {
	defer s.wg.Done()
	fail := func(e error) { s.transportFailure(c, g, e) }

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
			s.dispatchOn(m, c, g)
		}
	}
	r := bufio.NewReaderSize(c, 8192)
	for {
		m, e := readMessage(r)
		if e != nil {
			fail(e)
			return
		}
		s.dispatchOn(m, c, g)
	}
}
func (s *Service) transact(ctx context.Context, m *message) (*message, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(messaging.ErrSendNotAttempted, err)
	}
	key := transactionKey(m)
	ch := make(chan *message, 8)
	s.mu.Lock()
	c, g, flowCtx := s.conn, s.generation, s.flowCtx
	if m.generation != 0 && m.generation != g {
		s.mu.Unlock()
		return nil, errors.Join(messaging.ErrSendNotAttempted, ErrFlowChanged)
	}
	if m.method() != "REGISTER" && (!s.ready || !time.Now().Before(s.registeredUntil)) {
		s.mu.Unlock()
		return nil, errors.Join(messaging.ErrSendNotAttempted, ErrNotReady)
	}
	if c == nil || flowCtx == nil {
		s.mu.Unlock()
		return nil, errors.Join(messaging.ErrSendNotAttempted, ErrNotReady)
	}
	s.pending[key] = ch
	serviceCtx := s.ctx
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.pending, key); s.mu.Unlock() }()
	wire, e := m.bytes()
	if e != nil {
		return nil, e
	}
	if e = s.writeOn(c, g, wire); e != nil {
		s.transportFailure(c, g, e)
		return nil, e
	}
	timeout := time.NewTimer(s.cfg.TransactionTimeout)
	defer timeout.Stop()
	t1, t2 := s.cfg.SIPTimerT1, s.cfg.SIPTimerT2
	if t1 <= 0 {
		t1 = 500 * time.Millisecond
	}
	if t2 <= 0 {
		t2 = 4 * time.Second
	}
	retry := time.NewTimer(t1)
	defer retry.Stop()
	interval := t1
	proceeding := false
	for {
		select {
		case <-ctx.Done():
			return nil, s.transactionFailure(ctx.Err())
		case <-flowCtx.Done():
			// A TCP peer can send a final response and immediately close. The
			// read loop queues that response before marking the flow failed;
			// preserve it (especially Retry-After), even if EOF wins select.
			for {
				select {
				case r := <-ch:
					if r.status() >= 200 {
						return r, nil
					}
				default:
					return nil, ErrFlowChanged
				}
			}
		case <-serviceCtx.Done():
			return nil, s.transactionFailure(serviceCtx.Err())
		case <-timeout.C:
			return nil, errTransactionTimeout
		case <-retry.C:
			if s.cfg.Transport == "udp" {
				if e := s.writeOn(c, g, wire); e != nil {
					s.transportFailure(c, g, e)
					return nil, e
				}
				if proceeding {
					interval = t2
				} else {
					interval = min(interval*2, t2)
				}
				retry.Reset(interval)
			}
		case r := <-ch:
			if r.status() < 200 {
				if m.method() == "INVITE" {
					retry.Stop()
				} else if s.cfg.Transport == "udp" && !proceeding {
					proceeding = true
					interval = t2
					if !retry.Stop() {
						select {
						case <-retry.C:
						default:
						}
					}
					retry.Reset(t2)
				}
				continue
			}
			return r, nil
		}
	}
}

func (s *Service) transactionFailure(err error) error {
	s.mu.Lock()
	cause := s.lastErr
	s.mu.Unlock()
	if cause != nil {
		return fmt.Errorf("IMS transport: %w (transaction ended: %v)", cause, err)
	}
	return err
}

func (s *Service) request(method, uri, callID string) *message {
	m := &message{Start: method + " " + uri + " SIP/2.0", Headers: make(map[string][]string)}
	s.mu.Lock()
	c, g, tag := s.conn, s.generation, s.tag
	contact := s.contact
	routes := append([]string(nil), s.routes...)
	verify := s.securityVerify
	s.mu.Unlock()
	m.generation = g
	local := "0.0.0.0:5060"
	if c != nil {
		local = c.LocalAddr().String()
	}
	m.set("via", "SIP/2.0/"+strings.ToUpper(s.cfg.Transport)+" "+local+";branch=z9hG4bK"+token()+";rport")
	m.set("max-forwards", "70")
	m.set("from", "<"+s.cfg.PublicIdentity+">;tag="+tag)
	m.set("to", "<"+uri+">")
	m.set("call-id", callID)
	m.set("cseq", fmt.Sprintf("%d %s", s.seq.Add(1), method))
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
	s.mu.Lock()
	protected := s.securityVerify != ""
	s.mu.Unlock()
	if protected {
		if err := s.rotateSecurityOffer(); err != nil {
			return err
		}
	}
	var auts string
	for round := 0; round < 5; round++ {
		s.mu.Lock()
		callID, expires := s.callID, s.cfg.Expires
		s.mu.Unlock()
		m := s.request("REGISTER", uri, callID)
		m.set("to", "<"+s.cfg.PublicIdentity+">")
		m.set("expires", strconv.Itoa(max(1, int(expires.Seconds()))))
		m.set("supported", "path, gruu, sec-agree")
		m.set("accept", "application/sdp, application/vnd.3gpp.sms, application/vnd.3gpp.ussd+xml")
		for name, value := range s.cfg.RegisterHeaders {
			m.set(name, value)
		}
		if s.cfg.SecurityClient != nil {
			offers := []string{s.cfg.SecurityClient.header()}
			for _, offer := range s.cfg.SecurityClientAlternatives {
				offers = append(offers, offer.header())
			}
			m.set("security-client", strings.Join(offers, ", "))
			m.set("require", "sec-agree")
			m.set("proxy-require", "sec-agree")
		}
		s.mu.Lock()
		haveChallenge := s.auth.Nonce != ""
		s.mu.Unlock()
		if !haveChallenge {
			// TS 24.229 initial registration identifies the private identity and
			// requests a challenge; this is not a computed authentication response.
			algorithm := ",algorithm=AKAv1-MD5"
			if s.cfg.UsePlainDigestPlaceholder {
				algorithm = ""
			}
			m.set("authorization", fmt.Sprintf("Digest uri=%s,username=%s%s,response=\"\",realm=%s,nonce=\"\"", strconv.Quote(uri), strconv.Quote(s.cfg.PrivateIdentity), algorithm, strconv.Quote(s.cfg.Realm)))
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
			s.mu.Lock()
			verify := s.securityVerify
			s.mu.Unlock()
			if s.cfg.SecurityClient != nil && verify == "" {
				return errors.New("IMS peer omitted required security agreement")
			}
			s.mu.Lock()
			s.routes = append([]string(nil), r.Headers["service-route"]...)
			s.mu.Unlock()
			expires, e = registrationExpiry(r, m.get("contact"), expires)
			if e != nil {
				return fmt.Errorf("IMS REGISTER Contact/Expires: %w", e)
			}
			s.mu.Lock()
			s.cfg.Expires = expires
			s.registeredUntil = time.Now().Add(expires)
			s.mu.Unlock()
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
				return fmt.Errorf("IMS REGISTER %s challenge: %w", h, e)
			}
			// The Digest protection space is supplied by the challenge and may
			// differ from the IMS home domain used for the REGISTER Request-URI.
			// Keep cfg.Realm and the prepared IMPI/IMPU unchanged; authHeader
			// hashes and echoes c.Realm. The challenge must still pass SIM AKA.
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
				if protected {
					s.setReady(false, ErrRecovering)
				}
				client := *s.cfg.SecurityClient
				server, e := selectSecurity(raw, client, s.cfg.SecurityClientAlternatives...)
				if e != nil {
					return fmt.Errorf("IMS REGISTER Security-Server: %w", e)
				}
				client.Algorithm, client.Encryption = server.Algorithm, server.Encryption
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
			s.mu.Lock()
			s.cfg.Expires = time.Duration(n) * time.Second
			s.mu.Unlock()
		default:
			phase := "initial"
			if haveChallenge {
				phase = "authenticated"
			}
			if auts != "" {
				phase = "resynchronization"
			}
			if s.cfg.OnRegistrationFailure != nil {
				s.cfg.OnRegistrationFailure(phase, round+1, registrationDiagnostic(m), registrationDiagnostic(r))
			}
			return registrationRejected(r, phase, round+1, s.cfg.Transport)
		}
	}
	return errors.New("IMS authentication round limit exceeded")
}
func (s *Service) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	if s.flowCancel != nil {
		s.flowCancel()
	}
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

// Done closes on a terminal failure, parent cancellation or Close. Recoverable
// IMS transport/registration loss is reported through readiness while SWu lives.
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
