package ims

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ErrRecovering marks a readiness loss that does not require tearing down SWu.
// Only REGISTER is retried. Business transactions never migrate to a new flow.
var ErrRecovering = errors.New("IMS registration recovering")
var ErrFlowChanged = errors.New("IMS transport generation changed")
var errTransactionTimeout = errors.New("SIP transaction timeout")

type flowError struct{ cause error }

func (e *flowError) Error() string { return "IMS transport: " + e.cause.Error() }
func (e *flowError) Unwrap() error { return e.cause }

type registrationError struct {
	status     int
	retryAfter time.Duration
	detail     string
}

func (e *registrationError) Error() string { return e.detail }

type registrarTarget struct {
	address   string
	failures  int
	notBefore time.Time
}

func retryAfterValue(value string) time.Duration {
	// RFC 3261 delta-seconds may be followed by a comment or parameters.
	field := strings.Fields(strings.TrimSpace(value))
	if len(field) == 0 {
		return 0
	}
	n, err := strconv.ParseUint(strings.SplitN(field[0], ";", 2)[0], 10, 32)
	if err != nil {
		return 0
	}
	return time.Duration(n) * time.Second
}

// A matching Contact's lifetime takes precedence over the global Expires.
// A successful response removing our binding must never publish readiness.
func registrationExpiry(response *message, contact string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(response.get("expires"))
	for _, header := range response.Headers["contact"] {
		entries, err := splitQuoted(header, ',')
		if err != nil {
			return 0, err
		}
		for _, entry := range entries {
			if sipURI(entry) != sipURI(contact) {
				continue
			}
			params := entry
			if end := strings.LastIndexByte(entry, '>'); end >= 0 {
				params = entry[end+1:]
			}
			fields, err := parameters(params, ';')
			if err != nil {
				return 0, err
			}
			if expires, ok := fields["expires"]; ok {
				value = expires
			}
		}
	}
	if value == "" {
		return fallback, nil
	}
	seconds, err := strconv.ParseUint(value, 10, 32)
	if err != nil || seconds == 0 {
		return 0, errors.New("IMS REGISTER returned no valid binding lifetime")
	}
	return time.Duration(seconds) * time.Second, nil
}

func containsCode(codes []int, code int) bool {
	for _, v := range codes {
		if v == code {
			return true
		}
	}
	return false
}
func (s *Service) recoveryDelay(cause error, failures int) (time.Duration, bool) {
	var rejection *registrationError
	if errors.As(cause, &rejection) {
		if containsCode(s.cfg.ForbiddenStatusCodes, rejection.status) {
			return max(5*time.Minute, rejection.retryAfter), false
		}
		if !containsCode(s.cfg.TemporaryStatusCodes, rejection.status) {
			return max(10*time.Minute, rejection.retryAfter), false
		}
		// The original registrar uses the carrier's fixed temporary-response
		// interval. Retry-After is a lower bound for this particular P-CSCF.
		return max(s.cfg.RecoveryInitial, rejection.retryAfter), true
	}
	// Transport recovery starts with the original registrar's five-second
	// interval, backing off repeated failures to avoid reconnect storms.
	delay := min(5*time.Second, s.cfg.RecoveryInitial)
	for i := 1; i < failures && delay < s.cfg.RecoveryMax; i++ {
		delay += min(delay, s.cfg.RecoveryMax-delay)
	}
	return delay, true
}
func recoverableRegistration(err error) bool {
	var flow *flowError
	var rejection *registrationError
	return errors.As(err, &flow) || errors.As(err, &rejection) || errors.Is(err, errTransactionTimeout) || errors.Is(err, ErrFlowChanged) || errors.Is(err, context.DeadlineExceeded)
}
func (s *Service) waitRecovery(delay time.Duration) bool {
	timer := time.NewTimer(max(delay, 0))
	defer timer.Stop()
	select {
	case <-s.ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (s *Service) connectTarget(index int) error {
	if err := s.resetRegistration(); err != nil {
		return err
	}
	s.mu.Lock()
	s.targetIndex = index
	s.mu.Unlock()
	if err := s.connect(s.ctx, s.cfg.DialContext, s.targets[index].address); err != nil {
		return &flowError{err}
	}
	return nil
}

// Reset only the IMS flow. The tunnel, SIM provider, SMS RP references and
// received concatenation fragments remain owned by the same runtime session.
func (s *Service) resetRegistration() error {
	s.registerMu.Lock()
	defer s.registerMu.Unlock()
	s.writeMu.Lock()
	s.mu.Lock()
	conn, udp, tcp := s.conn, s.serverUDP, s.serverTCP
	serverConns := make([]net.Conn, 0, len(s.serverConns))
	for c := range s.serverConns {
		serverConns = append(serverConns, c)
	}
	s.generation++
	if s.flowCancel != nil {
		s.flowCancel()
	}
	s.conn, s.serverUDP, s.serverTCP = nil, nil, nil
	s.serverConns = nil
	s.serverLocal, s.serverPeer = "", ""
	s.serverBroken = false
	s.securityVerify = ""
	s.routes = nil
	s.auth = challenge{}
	clear(s.password)
	s.password = nil
	s.authName = ""
	s.nonceCount = 0
	s.callID, s.tag = token(), token()
	s.serverResponses = make(map[string]cachedResponse)
	closed := s.closed
	s.mu.Unlock()
	s.writeMu.Unlock()
	if conn != nil {
		conn.Close()
	}
	if udp != nil {
		udp.Close()
	}
	if tcp != nil {
		tcp.Close()
	}
	for _, c := range serverConns {
		c.Close()
	}
	s.ussdMu.Lock()
	s.ussd = make(map[string]*ussdDialog)
	s.ussdMu.Unlock()
	if closed || s.ctx.Err() != nil {
		return context.Canceled
	}
	// A new registration must not reuse the previous association's SPIs or
	// local protected ports. Algorithm offers and carrier restrictions remain.
	if s.cfg.SecurityClient != nil {
		var b [12]byte
		if _, err := rand.Read(b[:]); err != nil {
			return err
		}
		offer := *s.cfg.SecurityClient
		a, c := binary.BigEndian.Uint32(b[:4]), binary.BigEndian.Uint32(b[4:8])
		if a < 256 {
			a += 256
		}
		if c < 256 {
			c += 256
		}
		for a == offer.SPIClient || a == offer.SPIServer {
			a = 256 + (a-256+1)%(1<<32-256)
		}
		for c == a || c == offer.SPIClient || c == offer.SPIServer {
			c = 256 + (c-256+1)%(1<<32-256)
		}
		port := uint16(20000) + binary.BigEndian.Uint16(b[8:])%30000
		for port == offer.PortClient || port == offer.PortServer || port+1 == offer.PortClient || port+1 == offer.PortServer {
			port = 20000 + (port-20000+2)%30000
		}
		offer.SPIClient, offer.SPIServer = a, c
		offer.PortClient, offer.PortServer = port, port+1
		s.cfg.SecurityClient = &offer
		for i := range s.cfg.SecurityClientAlternatives {
			p := &s.cfg.SecurityClientAlternatives[i]
			p.SPIClient, p.SPIServer = a, c
			p.PortClient, p.PortServer = port, port+1
		}
	}
	return nil
}

func (s *Service) flowAlive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn != nil && s.flowCtx != nil && s.flowCtx.Err() == nil && !s.serverBroken && !s.closed && s.ctx.Err() == nil
}

func (s *Service) flowContext(generation uint64) (context.Context, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.generation != generation || s.flowCtx == nil || s.flowCtx.Err() != nil {
		return nil, ErrFlowChanged
	}
	return s.flowCtx, nil
}

func (s *Service) transportFailure(c net.Conn, generation uint64, cause error) {
	s.stateMu.Lock()
	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil || s.conn != c || s.generation != generation {
		s.mu.Unlock()
		s.stateMu.Unlock()
		return
	}
	err := &flowError{cause}
	s.ready = false
	s.lastErr = err
	if s.flowCancel != nil {
		s.flowCancel()
	}
	notify := s.everReady
	s.mu.Unlock()
	if notify && s.cfg.OnState != nil {
		s.cfg.OnState(false, errors.Join(ErrRecovering, err))
	}
	s.stateMu.Unlock()
	select {
	case s.recovery <- struct{}{}:
	default:
	}
}

func (s *Service) recoverRegistration(cause error) error {
	if !recoverableRegistration(cause) {
		return cause
	}
	s.setReady(false, errors.Join(ErrRecovering, cause))
	for s.ctx.Err() == nil {
		s.mu.Lock()
		failed := s.targetIndex
		s.mu.Unlock()
		target := &s.targets[failed]
		target.failures = min(target.failures+1, 32)
		delay, rotate := s.recoveryDelay(cause, target.failures)
		target.notBefore = time.Now().Add(delay)
		index := failed
		for {
			now := time.Now()
			if rotate {
				soonest := target.notBefore
				found := false
				for step := 1; step <= len(s.targets); step++ {
					candidate := (failed + step) % len(s.targets)
					at := s.targets[candidate].notBefore
					if !now.Before(at) {
						index = candidate
						found = true
						break
					}
					if at.Before(soonest) {
						soonest = at
					}
				}
				if found {
					break
				}
				if !s.waitRecovery(time.Until(soonest)) {
					return s.ctx.Err()
				}
			} else {
				if !s.waitRecovery(time.Until(target.notBefore)) {
					return s.ctx.Err()
				}
				break
			}
		}
		var rejection *registrationError
		reuse := index == failed && s.flowAlive() && errors.As(cause, &rejection)
		var err error
		if !reuse {
			err = s.connectTarget(index)
		}
		if err == nil {
			err = s.register(s.ctx)
		}
		if err == nil && s.setReady(true, nil) {
			s.targets[index].failures = 0
			s.targets[index].notBefore = time.Time{}
			return nil
		}
		if err == nil {
			err = &flowError{net.ErrClosed}
		}
		if !recoverableRegistration(err) {
			return err
		}
		cause = err
		s.setReady(false, errors.Join(ErrRecovering, err))
	}
	return s.ctx.Err()
}

func (s *Service) refreshDelay() time.Duration {
	s.mu.Lock()
	until := s.registeredUntil
	s.mu.Unlock()
	return max(time.Until(until)*8/10, time.Millisecond)
}
func (s *Service) maintenance() {
	defer s.wg.Done()
	refresh := time.NewTimer(s.refreshDelay())
	defer refresh.Stop()
	for {
		var err error
		select {
		case <-s.ctx.Done():
			return
		case <-s.recovery:
			if s.flowAlive() {
				continue
			}
			err = s.Err()
			if err == nil {
				err = &flowError{net.ErrClosed}
			}
		case <-refresh.C:
			s.mu.Lock()
			deadline := s.registeredUntil
			s.mu.Unlock()
			ctx, cancel := context.WithDeadline(s.ctx, deadline)
			err = s.register(ctx)
			cancel()
			if err == nil && !s.setReady(true, nil) {
				err = &flowError{net.ErrClosed}
			}
		}
		if s.ctx.Err() != nil {
			return
		}
		if err != nil {
			err = s.recoverRegistration(err)
		}
		if err != nil {
			s.setReady(false, err)
			s.cancel()
			return
		}
		refresh.Reset(s.refreshDelay())
	}
}
func (s *Service) keepaliveLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.cfg.KeepAlive)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if !s.Ready() {
				continue
			}
			s.mu.Lock()
			c, g := s.conn, s.generation
			s.mu.Unlock()
			if err := s.writeOn(c, g, []byte("\r\n\r\n")); err != nil && !errors.Is(err, ErrFlowChanged) {
				s.transportFailure(c, g, err)
			}
		}
	}
}

func registrationRejected(response *message, phase string, round int, transport string) error {
	return &registrationError{status: response.status(), retryAfter: retryAfterValue(response.get("retry-after")), detail: fmt.Sprintf("IMS REGISTER rejected: %s (phase=%s, round=%d, transport=%s)", response.Start, phase, round, transport)}
}
