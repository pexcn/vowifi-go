// Package swu is an independent, limited-profile userspace IKEv2/EAP-AKA client.
// It does not contain or claim to recover the original private implementation.
package swu

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	vc "github.com/iniwex5/vowifi-go/engine/crypto"
	"github.com/iniwex5/vowifi-go/engine/eap"
	"github.com/iniwex5/vowifi-go/engine/ikev2"
	"github.com/iniwex5/vowifi-go/engine/ipsec"
	"github.com/iniwex5/vowifi-go/engine/sim"
	"github.com/iniwex5/vowifi-go/runtimehost/identity"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

var ErrRekeyRequired = errors.New("SWu SA cannot be renewed; reconnect required")

type Config struct {
	// OnDiagnostic receives startup DNS and IKE results without authentication
	// payloads or key material. Nil disables diagnostic collection.
	OnDiagnostic func(Diagnostic)
	// EAPOnlyAuthentication offers RFC 5998 in the first IKE_AUTH request.
	// A missing initial certificate AUTH may then defer authentication until
	// mutual EAP-AKA and the final MSK-based responder AUTH both succeed.
	EAPOnlyAuthentication bool
	DisableMOBIKE         bool
	AKAPrimeNetworkName   string
	RequireAKAPrime       bool
	EAPReauth             *eap.ReauthContext
	// EPDGFailover tries alternate resolved peers/UDP 4500 only when the
	// initial exchange receives no datagrams, before sending any SIM identity.
	EPDGFailover                                      bool
	DeviceID, TraceID, EPDGAddr, DataplaneMode        string
	AKAChallengeMode                                  string
	IPStack                                           string
	Proxy                                             *ProxyConfig
	Identity                                          identity.IMSIdentityResolution
	SIM                                               interface{}
	NAI, ServerName, APN                              string
	DNSServer                                         string
	Roots                                             *x509.CertPool
	ResponderVerifier                                 ResponderVerifier
	Transport                                         ipsec.DatagramConn
	Timeout, DPDInterval, ChildLifetime, NATKeepalive time.Duration
	Retransmits, MTU                                  int
	// IKEFragmentMTU is the outer IP datagram budget; zero uses 1280.
	IKEFragmentMTU    int
	IKEFragmentPMTU   bool
	EncryptionKeyBits uint16
	Encryption        vc.Encryption
	DHGroup           uint16
	IKEAlternatives   []IKEProfile
	PRF               vc.PRF
	Integrity         vc.Integrity
	Random            io.Reader
}
type Configuration struct {
	Addresses, DNS, PCSCF           []netip.Addr
	LocalSelectors, RemoteSelectors []ikev2.TrafficSelector
}
type PacketEndpoint interface {
	ReadPacket(context.Context) ([]byte, error)
	WritePacket(context.Context, []byte) error
}
type Session struct {
	responderID                                        []byte
	responderCertificates                              [][]byte
	DeviceID, TraceID, EPDGHost, RemoteAddr, ProxyAddr string
	EPDGIPs                                            []net.IP
	StartedAt                                          time.Time
	cfg                                                Config
	conn                                               ipsec.DatagramConn
	ctx                                                context.Context
	cancel                                             context.CancelFunc
	once                                               sync.Once
	done                                               chan struct{}
	mu                                                 sync.Mutex
	err                                                error
	configuration                                      Configuration
	in, out                                            *ipsec.SA
	packets                                            chan []byte
	responses                                          chan ikev2.Message
	mobike                                             bool
	transport                                          *switchingConn
	fragmentation                                      bool // immutable after IKE_SA_INIT
	fragments                                          fragmentBuffer
	spii, spir                                         uint64
	ni, nr, initRequest, initResponse, idBody          []byte
	keys                                               vc.IKEKeys
	prf                                                vc.PRF
	integ                                              vc.Integrity
	encLen                                             int
	encryption                                         vc.Encryption
	ikeIV                                              vc.IVSequence
	nextID                                             uint32
	childSPI                                           uint32
	ikeMu                                              sync.Mutex
	encapsulated                                       bool
	initialPeers                                       map[string]bool
	ikeProfiles                                        []IKEProfile
	keyExchangeGroup                                   uint16
	keRetries                                          int
	// childMu spans outbound writes to serialize them with SA replacement.
	childMu               sync.RWMutex
	retiredChildren       map[uint32]retiredChild
	childCreated          time.Time
	childDHGroup          uint16
	childReset            chan struct{}
	authDeadline          time.Time
	ikeStateMu            sync.RWMutex
	activeIKE, retiredIKE *ikeAssociation
	retiredIKEUntil       time.Time
	ikeReset              chan struct{}
	rekeyMu               sync.Mutex
}

func Start(ctx context.Context, c Config) (*Session, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if c.EPDGAddr == "" {
		return nil, ErrEPDGAddressMissing
	}
	if c.DataplaneMode != "" && c.DataplaneMode != DataplaneModeUserspace {
		return nil, errors.New("only userspace SWu dataplane is supported")
	}
	if c.NAI == "" {
		return nil, errors.New("SWu requires an explicit permanent EAP NAI; IMS IMPI is a distinct identity")
	}
	if _, ok := c.SIM.(sim.AKAProvider); !ok {
		return nil, errors.New("SWu requires SIM AKA provider")
	}
	if c.RequireAKAPrime && c.AKAPrimeNetworkName == "" {
		return nil, errors.New("AKA-prime requires a pinned network name")
	}
	if c.AKAChallengeMode != "" && c.AKAChallengeMode != "minimal" && c.AKAChallengeMode != "omit" && c.AKAChallengeMode != "checkcode" {
		return nil, errors.New("unsupported AKA challenge mode")
	}
	if c.IPStack == "" {
		c.IPStack = "ipv4v6"
	}
	if c.IPStack != "ipv4" && c.IPStack != "ipv6" && c.IPStack != "ipv4v6" {
		return nil, errors.New("unsupported SWu IP stack")
	}
	if c.NATKeepalive < 0 {
		return nil, errors.New("invalid NAT keepalive interval")
	}
	if c.NATKeepalive == 0 {
		c.NATKeepalive = 20 * time.Second
	}
	if c.Timeout <= 0 {
		c.Timeout = time.Second
	}
	if c.Retransmits == 0 {
		c.Retransmits = 4
	}
	if c.Retransmits < 0 || c.Retransmits > 8 {
		return nil, errors.New("invalid retransmit count")
	}
	if c.DPDInterval <= 0 {
		c.DPDInterval = 120 * time.Second
	}
	if c.ChildLifetime <= 0 {
		c.ChildLifetime = 50 * time.Minute
	}
	if c.MTU <= 0 {
		c.MTU = 1280
	}
	if c.MTU < 576 || c.MTU > 64000 {
		return nil, errors.New("invalid inner MTU")
	}
	if c.IKEFragmentMTU != 0 && (c.IKEFragmentMTU < 576 || c.IKEFragmentMTU > 64000) {
		return nil, errors.New("invalid IKE fragmentation MTU")
	}
	if c.EncryptionKeyBits == 0 {
		c.EncryptionKeyBits = 128
	}
	if c.EncryptionKeyBits != 128 && c.EncryptionKeyBits != 256 {
		return nil, errors.New("unsupported AES key length")
	}
	if c.PRF == 0 {
		c.PRF = vc.PRFSHA256
	}
	if c.PRF.Size() == 0 {
		return nil, errors.New("unsupported IKE PRF")
	}
	if c.Encryption == 0 {
		c.Encryption = vc.AESCBC
	}
	if c.Integrity == 0 && c.Encryption == vc.AESCBC {
		c.Integrity = vc.HMACSHA256128
	}
	suite := vc.Protection{Encryption: c.Encryption, Integrity: c.Integrity}
	if !suite.Valid() {
		return nil, errors.New("unsupported IKE integrity")
	}
	if c.Random == nil {
		c.Random = rand.Reader
	}
	c.Random = &lockedRandom{reader: c.Random}
	if c.DHGroup == 0 {
		c.DHGroup = 14
	}
	profiles, profileErr := configuredIKEProfiles(c)
	if profileErr != nil {
		return nil, profileErr
	}
	host := strings.TrimSuffix(strings.TrimSpace(c.EPDGAddr), ".")
	remote := host
	if h, _, e := net.SplitHostPort(host); e == nil {
		host = h
	} else {
		remote = net.JoinHostPort(host, "500")
	}
	if c.ServerName == "" {
		c.ServerName = host
	}
	childCtx, cancel := context.WithCancel(ctx)
	s := &Session{DeviceID: c.DeviceID, TraceID: c.TraceID, EPDGHost: host, RemoteAddr: remote, StartedAt: time.Now(), cfg: c, ctx: childCtx, cancel: cancel, done: make(chan struct{}), packets: make(chan []byte, 128), responses: make(chan ikev2.Message, 8), childReset: make(chan struct{}, 1), ikeReset: make(chan struct{}, 1), prf: c.PRF, integ: c.Integrity, encryption: c.Encryption, encLen: suite.KeyLen(c.EncryptionKeyBits)}
	s.ikeProfiles, s.keyExchangeGroup = profiles, c.DHGroup
	_, port, _ := net.SplitHostPort(remote)
	s.encapsulated = port == "4500"
	var err error
	if c.Transport != nil {
		s.conn = c.Transport
	} else {
		// Normalize to one resolved numeric peer before constructing SOCKS UDP
		// headers. A proxy may return the numeric source for a domain target;
		// authenticating an arbitrary relay-provided address is not acceptable.
		if c.Proxy != nil && c.Proxy.Enabled && c.Proxy.Type != "" && c.Proxy.Type != "socks5" {
			cancel()
			return nil, errors.New("SWu requires SOCKS5 UDP ASSOCIATE proxy")
		}
		peer, ips, resolveErr := c.resolveEPDG(childCtx, remote)
		if resolveErr != nil {
			cancel()
			return nil, resolveErr
		}
		s.RemoteAddr, s.EPDGIPs = peer, ips
		remote = peer
		if c.Proxy != nil && c.Proxy.Enabled {
			proxy := c.Proxy.Addr
			if proxy == "" {
				proxy = c.Proxy.Address
			}
			s.conn, err = ipsec.DialSOCKS5(childCtx, proxy, remote, c.Proxy.Username, c.Proxy.Password)
			s.ProxyAddr = proxy
			if err != nil {
				cancel()
				return nil, fmt.Errorf("%w: %v", ErrProxyConnectFailed, err)
			}
		} else {
			s.conn, err = ipsec.DialUDP(childCtx, remote)
		}
		if err != nil {
			cancel()
			return nil, err
		}
	}
	watchDone := make(chan struct{})
	handshakeConn := s.conn
	go func() {
		select {
		case <-childCtx.Done():
			handshakeConn.Close()
		case <-watchDone:
		}
	}()
	handshakeStarted := time.Now()
	err = s.handshake()
	close(watchDone)
	s.reportHandshake(handshakeStarted, err)
	if err != nil {
		s.fail(err)
		return nil, err
	}
	s.transport = newSwitchingConn(s.conn)
	s.conn = s.transport
	s.activeIKE = &ikeAssociation{spii: s.spii, spir: s.spir, keys: s.keys, localInitiator: true, nextID: s.nextID, created: time.Now()}
	s.keys = vc.IKEKeys{} // The active association now owns the authenticated key material.
	go s.readLoop()
	go s.maintain()
	go s.keepaliveLoop()
	go s.maintainIKE()
	return s, nil
}
func Dial(ctx context.Context, c Config) (*Session, error) { return Start(ctx, c) }
func (s *Session) Configuration() Configuration {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.configuration
	c.Addresses = append([]netip.Addr{}, c.Addresses...)
	c.DNS = append([]netip.Addr{}, c.DNS...)
	c.PCSCF = append([]netip.Addr{}, c.PCSCF...)
	c.LocalSelectors = append([]ikev2.TrafficSelector{}, c.LocalSelectors...)
	c.RemoteSelectors = append([]ikev2.TrafficSelector{}, c.RemoteSelectors...)
	return c
}
func (s *Session) InnerPacketEndpoint() PacketEndpoint { return s }
func (s *Session) Done() <-chan struct{}               { return s.done }
func (s *Session) Err() error                          { s.mu.Lock(); defer s.mu.Unlock(); return s.err }
func (s *Session) fail(e error) {
	s.once.Do(func() {
		s.mu.Lock()
		s.err = e
		s.mu.Unlock()
		s.cancel()
		if s.conn != nil {
			s.conn.Close()
		}
		s.fragments.clear()
		close(s.done)
	})
}
func (s *Session) Close() error { s.fail(context.Canceled); return nil }
func (s *Session) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case <-s.done:
		return nil, s.Err()
	default:
	}
	select {
	case p := <-s.packets:
		return p, nil
	case <-s.done:
		return nil, s.Err()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (s *Session) WritePacket(ctx context.Context, p []byte) error {
	select {
	case <-s.done:
		return s.Err()
	default:
	}
	if len(p) > s.cfg.MTU {
		return errors.New("inner packet exceeds tunnel MTU")
	}
	next := byte(4)
	if len(p) > 0 && p[0]>>4 == 6 {
		next = 41
	}
	if e := ipsec.ValidateInnerIP(p, next); e != nil {
		return e
	}
	if !s.permitted(p, true) {
		return errors.New("inner packet outside negotiated traffic selectors")
	}
	s.childMu.RLock()
	defer s.childMu.RUnlock()
	if !time.Now().Before(s.childCreated.Add(s.cfg.ChildLifetime)) {
		s.fail(ErrRekeyRequired)
		return ErrRekeyRequired
	}
	packet, e := s.out.Seal(p, next)
	if e != nil {
		if errors.Is(e, ipsec.ErrExhausted) {
			s.fail(ErrRekeyRequired)
		}
		return e
	}
	return s.conn.Write(ctx, packet)
}
func (s *Session) ikeSend(ctx context.Context, b []byte) error {
	if s.encapsulated {
		b = append([]byte{0, 0, 0, 0}, b...)
	}
	return s.conn.Write(ctx, b)
}
func (s *Session) header(exchange byte, id uint32) ikev2.Header {
	return ikev2.Header{InitiatorSPI: s.spii, ResponderSPI: s.spir, Exchange: exchange, Flags: ikev2.FlagInitiator, MessageID: id}
}
func (s *Session) exchange(requests [][]byte, encrypted bool, flight *ikeFlight) (ikev2.Message, []byte, error) {
	request := requests[0]
	want, e := ikev2.ParseHeader(request)
	if e != nil {
		return ikev2.Message{}, nil, e
	}
	var fragments fragmentBuffer
	defer fragments.clear()
	stage := fmt.Sprintf("exchange_%d", want.Exchange)
	switch want.Exchange {
	case ikev2.SAInit:
		stage = "IKE_SA_INIT"
	case ikev2.IKEAuth:
		stage = "IKE_AUTH"
	}
	received, framingRejected, headerRejected, payloadRejected := 0, 0, 0, 0
	transmissions := 0
	lastRejection := "none"
	retransmits := s.cfg.Retransmits
	if want.Exchange == ikev2.SAInit && len(s.initialPeers) > 1 && retransmits > 2 {
		retransmits = 2
	}
	for attempt := 0; attempt <= retransmits; attempt++ {
		transmissions++
		if e = s.sendIKEPackets(s.ctx, requests); e != nil {
			return ikev2.Message{}, nil, fmt.Errorf("%s send (message_id=%d, attempt=%d): %w", stage, want.MessageID, attempt+1, e)
		}
		timeout := s.cfg.Timeout * time.Duration(uint64(1)<<attempt)
		rctx, cancel := context.WithTimeout(s.ctx, timeout)
		for {
			b, err := s.conn.Read(rctx)
			if err != nil {
				// Inspect the deadline before cancel: cancel() itself sets Err(),
				// which previously made every transport failure look like a timeout.
				timedOut := errors.Is(rctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded)
				cancel()
				if timedOut && s.ctx.Err() == nil {
					break
				}
				return ikev2.Message{}, nil, fmt.Errorf("%s receive (message_id=%d, attempt=%d): %w", stage, want.MessageID, attempt+1, err)
			}
			received++
			if s.encapsulated {
				if len(b) < 4 || binary.BigEndian.Uint32(b) != 0 {
					framingRejected++
					lastRejection = "not an IKE NAT-T datagram"
					continue
				}
				b = b[4:]
			}
			h, err := ikev2.ParseHeader(b)
			if err != nil {
				headerRejected++
				lastRejection = err.Error()
				continue
			}
			// RFC 7296: check I/R direction bits, allowing the version flag and
			// reserved bits. They do not change response correlation or AUTH.
			if h.InitiatorSPI != s.spii || h.MessageID != want.MessageID || h.Exchange != want.Exchange || h.Flags&(ikev2.FlagInitiator|ikev2.FlagResponse) != ikev2.FlagResponse || (encrypted && h.ResponderSPI == 0) || (s.spir != 0 && h.ResponderSPI != s.spir) {
				headerRejected++
				lastRejection = fmt.Sprintf("response mismatch (exchange=%d, message_id=%d, flags=0x%02x)", h.Exchange, h.MessageID, h.Flags)
				continue
			}
			var m ikev2.Message
			if encrypted {
				var ready bool
				m, ready, err = s.openIKE(b, s.keys.SKer, s.keys.SKar, &fragments)
				if err == nil && !ready {
					continue
				}
			} else {
				m, err = ikev2.Parse(b)
			}
			if err != nil {
				payloadRejected++
				lastRejection = err.Error()
				continue
			}
			cancel()
			return m, append([]byte{}, b...), nil
		}
		if attempt == retransmits && flight.nextProbe() {
			requests = flight.packets
			attempt = -1
		}
	}
	transportDiagnostics := ""
	if diagnostic, ok := s.conn.(interface{ ReadDiagnostics() string }); ok {
		transportDiagnostics = "; " + diagnostic.ReadDiagnostics()
	}
	diagnostic := fmt.Errorf("IKE exchange retransmissions exhausted (stage=%s, endpoint=%s, resolved_ips=%v, message_id=%d, nat_t=%t, transmissions=%d, received=%d, framing_rejected=%d, header_rejected=%d, payload_rejected=%d, last_rejection=%q%s)", stage, s.RemoteAddr, s.EPDGIPs, want.MessageID, s.encapsulated, transmissions, received, framingRejected, headerRejected, payloadRejected, lastRejection, transportDiagnostics)
	if want.Exchange == ikev2.SAInit && received == 0 {
		return ikev2.Message{}, nil, fmt.Errorf("%w: %v", errNoInitialResponse, diagnostic)
	}
	return ikev2.Message{}, nil, diagnostic
}
func randomUint(r io.Reader) (uint64, error) {
	var b [8]byte
	for {
		if _, e := io.ReadFull(r, b[:]); e != nil {
			return 0, e
		}
		if n := binary.BigEndian.Uint64(b[:]); n != 0 {
			return n, nil
		}
	}
}
func (s *Session) espProposal(spi uint32) ikev2.Proposal {
	suite := s.protection()
	ts := []ikev2.Transform{{Type: 1, ID: uint16(suite.Encryption), KeyBits: suite.KeyBits(s.encLen)}}
	if !suite.AEAD() {
		ts = append(ts, ikev2.Transform{Type: 3, ID: uint16(s.integ)})
	}
	ts = append(ts, ikev2.Transform{Type: 5, ID: 0})
	return ikev2.Proposal{Number: 1, Protocol: 3, SPI: binary.BigEndian.AppendUint32(nil, spi), Transforms: ts}
}
func validateProposal(b []byte, want ikev2.Proposal) (ikev2.Proposal, error) {
	ps, e := ikev2.ParseProposals(b)
	if e != nil {
		return ikev2.Proposal{}, e
	}
	if len(ps) != 1 {
		return ikev2.Proposal{}, errors.New("responder must choose one proposal")
	}
	p := ps[0]
	if p.Number != want.Number || p.Protocol != want.Protocol || len(p.SPI) != len(want.SPI) || len(p.Transforms) != len(want.Transforms) {
		return p, errors.New("responder selected unoffered proposal")
	}
	seen := map[byte]bool{}
	for _, t := range p.Transforms {
		if seen[t.Type] {
			return p, errors.New("duplicate selected transform")
		}
		seen[t.Type] = true
		found := false
		for _, w := range want.Transforms {
			if t == w {
				found = true
			}
		}
		if !found {
			return p, errors.New("responder selected unoffered transform")
		}
	}
	return p, nil
}
func natHash(spii, spir uint64, ip net.IP, port uint16) []byte {
	b := binary.BigEndian.AppendUint64(nil, spii)
	b = binary.BigEndian.AppendUint64(b, spir)
	b = append(b, ip...)
	b = binary.BigEndian.AppendUint16(b, port)
	h := sha1.Sum(b)
	return h[:]
}
func (s *Session) handshake() error {
	s.fragmentation = false
	if s.cfg.EPDGFailover {
		if s.initialPeers == nil {
			s.initialPeers = make(map[string]bool)
		}
		s.initialPeers[s.RemoteAddr] = true
	}
	var e error
	s.spii, e = randomUint(s.cfg.Random)
	if e != nil {
		return e
	}
	dh, e := vc.NewMODP(s.keyExchangeGroup, s.cfg.Random)
	if e != nil {
		return e
	}
	s.ni = make([]byte, 32)
	if _, e = io.ReadFull(s.cfg.Random, s.ni); e != nil {
		return e
	}
	sa, e := ikev2.EncodeProposals(s.ikeProposals())
	if e != nil {
		return e
	}
	ke := append(binary.BigEndian.AppendUint16(nil, s.keyExchangeGroup), 0, 0)
	ke = append(ke, dh.Public...)
	ps := []ikev2.Payload{{Type: ikev2.SA, Data: sa}, {Type: ikev2.KE, Data: ke}, {Type: ikev2.Nonce, Data: s.ni}} // A mismatching source hash deliberately requests UDP encapsulation, including through proxies.
	ps = append(ps, ikev2.Notification(ikev2.FragmentationSupported, nil))
	ps = append(ps, ikev2.Notification(16388, natHash(s.spii, 0, net.IPv4zero.To4(), 0)))
	if h, p, e := net.SplitHostPort(s.RemoteAddr); e == nil {
		if a, e := net.ResolveUDPAddr("udp", net.JoinHostPort(h, p)); e == nil {
			ip := a.IP
			if v := ip.To4(); v != nil {
				ip = v
			}
			ps = append(ps, ikev2.Notification(16389, natHash(s.spii, 0, ip, uint16(a.Port))))
		}
	}
	var response ikev2.Message
	for cookies := 0; cookies < 3; cookies++ {
		s.initRequest, e = (ikev2.Message{Header: s.header(ikev2.SAInit, 0), Payloads: ps}).Marshal()
		if e != nil {
			return e
		}
		response, s.initResponse, e = s.exchange([][]byte{s.initRequest}, false, nil)
		if e != nil {
			if cookies == 0 {
				if retried, result := s.retryInitialEndpoint(e); retried {
					return result
				}
			}
			return e
		}
		cookie := []byte(nil)
		for _, p := range response.Payloads {
			if p.Type == ikev2.Notify {
				typ, data, e := ikev2.ParseNotification(p.Data)
				if e != nil {
					return e
				}
				if typ == 17 { // RFC 7296 INVALID_KE_PAYLOAD
					if len(data) != 2 {
						return errors.New("invalid INVALID_KE_PAYLOAD group length")
					}
					return s.retryKEGroup(binary.BigEndian.Uint16(data))
				} else if typ == 16390 {
					if len(data) < 1 || len(data) > 64 {
						return errors.New("invalid COOKIE")
					}
					cookie = data
				} else if typ < 16384 {
					return fmt.Errorf("IKE SA_INIT error notify %d", typ)
				}
			}
		}
		if cookie == nil {
			break
		}
		if cookies == 2 {
			return errors.New("too many COOKIE challenges")
		}
		if len(ps) > 0 && ps[0].Type == ikev2.Notify {
			ps = ps[1:]
		}
		ps = append([]ikev2.Payload{ikev2.Notification(16390, cookie)}, ps...)
	}
	if response.Header.ResponderSPI == 0 {
		return errors.New("zero responder SPI in accepted SA_INIT")
	}
	s.fragmentation = fragmentationOffered(response.Payloads)
	s.spir = response.Header.ResponderSPI
	body, e := ikev2.One(response.Payloads, ikev2.SA)
	if e != nil {
		return e
	}
	if e = s.selectIKEProfile(body); e != nil {
		return e
	}
	peer, e := ikev2.One(response.Payloads, ikev2.KE)
	if e != nil {
		return e
	}
	if len(peer) != 4+len(dh.Public) || binary.BigEndian.Uint16(peer) != s.keyExchangeGroup || peer[2] != 0 || peer[3] != 0 {
		return errors.New("invalid KE response")
	}
	secret, e := dh.Shared(peer[4:])
	if e != nil {
		return e
	}
	s.nr, e = ikev2.One(response.Payloads, ikev2.Nonce)
	if e != nil {
		return e
	}
	if len(s.nr) < 16 || len(s.nr) > 256 {
		return errors.New("invalid responder nonce")
	}
	s.keys, e = vc.DeriveIKE(s.prf, s.integ, s.encLen, s.ni, s.nr, secret, s.spii, s.spir)
	if e != nil {
		return e
	}
	if !s.encapsulated {
		switcher, ok := s.conn.(ipsec.PeerSwitcher)
		if !ok {
			return errors.New("transport cannot switch peer to NAT-T port4500")
		}
		host, _, e := net.SplitHostPort(s.RemoteAddr)
		if e != nil {
			return e
		}
		s.RemoteAddr = net.JoinHostPort(host, "4500")
		if e = switcher.SetPeer(s.RemoteAddr); e != nil {
			return e
		}
		s.encapsulated = true
	}
	return s.authenticate()
}
func allSelectors() []ikev2.TrafficSelector {
	return []ikev2.TrafficSelector{{StartPort: 0, EndPort: 65535, Start: netip.MustParseAddr("0.0.0.0"), End: netip.MustParseAddr("255.255.255.255")}, {StartPort: 0, EndPort: 65535, Start: netip.IPv6Unspecified(), End: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")}}
}
func (s *Session) authenticate() error {
	spi, e := randomUint(s.cfg.Random)
	if e != nil {
		return e
	}
	s.childSPI = uint32(spi)
	if s.childSPI == 0 {
		s.childSPI = 1
	}
	sa, e := ikev2.EncodeProposals([]ikev2.Proposal{s.espProposal(s.childSPI)})
	if e != nil {
		return e
	}
	selectors := allSelectors()
	if s.cfg.IPStack == "ipv4" {
		selectors = selectors[:1]
	}
	if s.cfg.IPStack == "ipv6" {
		selectors = selectors[1:]
	}
	ts, e := ikev2.EncodeTS(selectors)
	if e != nil {
		return e
	}
	var attrs []ikev2.CPAttribute
	if s.cfg.IPStack != "ipv6" {
		attrs = append(attrs, ikev2.CPAttribute{Type: 1}, ikev2.CPAttribute{Type: 3}, ikev2.CPAttribute{Type: 20})
	}
	if s.cfg.IPStack != "ipv4" {
		attrs = append(attrs, ikev2.CPAttribute{Type: 8}, ikev2.CPAttribute{Type: 10}, ikev2.CPAttribute{Type: 21})
	}
	cp, e := ikev2.EncodeCP(1, attrs)
	if e != nil {
		return e
	}
	s.idBody = append([]byte{3, 0, 0, 0}, []byte(s.cfg.NAI)...)
	ps := []ikev2.Payload{{Type: ikev2.IDi, Data: s.idBody}, {Type: ikev2.CP, Data: cp}, {Type: ikev2.SA, Data: sa}, {Type: ikev2.TSi, Data: ts}, {Type: ikev2.TSr, Data: ts}}
	if !s.cfg.DisableMOBIKE {
		ps = append(ps, ikev2.Notification(mobikeSupportedNotify, nil))
	}
	if s.cfg.EAPOnlyAuthentication {
		ps = append(ps, ikev2.Notification(16417, nil)) // RFC 5998, section 3.
	}
	if s.cfg.APN != "" {
		ps = append(ps, ikev2.Payload{Type: ikev2.IDr, Data: append([]byte{2, 0, 0, 0}, []byte(s.cfg.APN)...)})
	}
	client := eap.Client{Identity: s.cfg.NAI, Provider: s.cfg.SIM.(sim.AKAProvider), Preference: s.cfg.Identity.AKAAppPreference, ChallengeMode: s.cfg.AKAChallengeMode, PrimeNetworkName: s.cfg.AKAPrimeNetworkName, RequirePrime: s.cfg.RequireAKAPrime, Reauth: s.cfg.EAPReauth, Binding: s.cfg.NAI + "\x00" + s.cfg.ServerName + "\x00" + s.cfg.AKAPrimeNetworkName, Random: s.cfg.Random}
	defer client.Close()
	verified := false
	eapOnly := false
	eapDone := false
	sentAuth := false
	for id := uint32(1); id <= 32; id++ {
		flight, e := s.newIKEFlight(s.header(ikev2.IKEAuth, id), ps, s.keys.SKei, s.keys.SKai)
		if e != nil {
			return e
		}
		response, _, e := s.exchange(flight.packets, true, flight)
		if e != nil {
			return e
		}
		for _, p := range response.Payloads {
			if p.Type == ikev2.Notify {
				typ, _, e := ikev2.ParseNotification(p.Data)
				if e != nil {
					return e
				}
				if typ < 16384 {
					return &ikeAuthNotifyError{typ: typ}
				}
			}
		}
		if id == 1 {
			if !s.cfg.DisableMOBIKE {
				s.mobike = validMOBIKENegotiation(response.Payloads)
			}
			if _, e = s.rememberResponderIdentity(response.Payloads, true); e != nil {
				return e
			}
		} else if _, present := ikev2.Find(response.Payloads, ikev2.IDr); present {
			if _, e = s.rememberResponderIdentity(response.Payloads, false); e != nil {
				return e
			}
		}
		_, hasAuth := ikev2.Find(response.Payloads, ikev2.AUTH)
		if id == 1 && !hasAuth && s.cfg.EAPOnlyAuthentication {
			eapOnly = true
		}
		if auth, ok := ikev2.Find(response.Payloads, ikev2.AUTH); ok {
			if sentAuth && (len(auth) == 0 || auth[0] != 2) {
				return errors.New("final responder AUTH must prove the EAP MSK")
			}
			var msk []byte
			if eapDone {
				msk = client.Keys.MSK
			}
			if e = s.verifyResponder(response.Payloads, msk); e != nil {
				return e
			}
			verified = true
		}
		if sentAuth {
			if _, ok := ikev2.Find(response.Payloads, ikev2.AUTH); !ok {
				return errors.New("missing final responder AUTH")
			}
			if !verified {
				return errors.New("responder did not authenticate")
			}
			if _, ok := ikev2.Find(response.Payloads, ikev2.EAP); ok {
				return errors.New("unexpected EAP after initiator AUTH")
			}
			if e = s.establishChild(response.Payloads); e != nil {
				return e
			}
			if err := s.ctx.Err(); err != nil {
				return err
			}
			if !s.cfg.DisableMOBIKE {
				s.mobike = validMOBIKENegotiation(response.Payloads) || s.mobike
			}
			if err := client.Commit(); err != nil {
				return err
			}
			s.nextID = id + 1
			return nil
		}
		if !verified && !eapOnly {
			return errors.New("responder certificate AUTH required before EAP")
		}
		eapBytes, e := ikev2.One(response.Payloads, ikev2.EAP)
		if e != nil {
			return e
		}
		reply, success, e := client.Handle(s.ctx, eapBytes)
		if e != nil {
			return e
		}
		if success {
			eapDone = true
			octets, e := signedOctets(s.prf, s.initRequest, s.nr, s.keys.SKpi, s.idBody)
			if e != nil {
				return e
			}
			auth, e := sharedAuth(s.prf, client.Keys.MSK, octets)
			if e != nil {
				return e
			}
			ps = []ikev2.Payload{{Type: ikev2.AUTH, Data: append([]byte{2, 0, 0, 0}, auth...)}}
			sentAuth = true
		} else {
			ps = []ikev2.Payload{{Type: ikev2.EAP, Data: reply}}
		}
	}
	return errors.New("IKE_AUTH exceeded round limit")
}
func (s *Session) establishChild(ps []ikev2.Payload) error {
	sa, e := ikev2.One(ps, ikev2.SA)
	if e != nil {
		return e
	}
	p, e := validateProposal(sa, s.espProposal(s.childSPI))
	if e != nil {
		return e
	}
	peerSPI := binary.BigEndian.Uint32(p.SPI)
	if peerSPI == 0 {
		return errors.New("zero child SPI")
	}
	i, e := ikev2.One(ps, ikev2.TSi)
	if e != nil {
		return e
	}
	r, e := ikev2.One(ps, ikev2.TSr)
	if e != nil {
		return e
	}
	local, e := ikev2.ParseTS(i)
	if e != nil {
		return e
	}
	remote, e := ikev2.ParseTS(r)
	if e != nil {
		return e
	}
	for _, selectors := range [][]ikev2.TrafficSelector{local, remote} {
		for _, selector := range selectors {
			if s.cfg.IPStack == "ipv4" && !selector.Start.Is4() || s.cfg.IPStack == "ipv6" && !selector.Start.Is6() {
				return errors.New("responder selected unoffered traffic selector family")
			}
		}
	}
	cp, e := ikev2.One(ps, ikev2.CP)
	if e != nil {
		return fmt.Errorf("invalid CFG_REPLY: %w", e)
	}
	kind, attrs, e := ikev2.ParseCP(cp)
	if e != nil {
		return fmt.Errorf("invalid CFG_REPLY (cfg_type=%d, length=%d): %w", kind, len(cp), e)
	}
	if kind != 2 {
		return fmt.Errorf("expected CFG_REPLY (cfg_type=2), got cfg_type=%d (length=%d)", kind, len(cp))
	}
	configuration := Configuration{LocalSelectors: local, RemoteSelectors: remote}
	for _, a := range attrs {
		// An empty optional address attribute supplies no value. IPv4v6 peers
		// may leave one family unassigned; still require a usable local address
		// below before creating any Child SA.
		if len(a.Value) == 0 {
			continue
		}
		var addr netip.Addr
		var ok bool
		switch a.Type {
		case 1, 3, 20:
			if len(a.Value) != 4 {
				return fmt.Errorf("invalid IPv4 CP attribute (type=%d, length=%d, expected=4)", a.Type, len(a.Value))
			}
			addr, ok = netip.AddrFromSlice(a.Value)
		case 8:
			if len(a.Value) != 17 || a.Value[16] > 128 {
				return fmt.Errorf("invalid IPv6 address CP attribute (type=%d, length=%d, expected=17 with prefix<=128)", a.Type, len(a.Value))
			}
			addr, ok = netip.AddrFromSlice(a.Value[:16])
		case 10, 21:
			if len(a.Value) != 16 {
				return fmt.Errorf("invalid IPv6 CP attribute (type=%d, length=%d, expected=16)", a.Type, len(a.Value))
			}
			addr, ok = netip.AddrFromSlice(a.Value)
		default:
			continue
		}
		if !ok || addr.IsUnspecified() || addr.IsMulticast() {
			return errors.New("invalid assigned CP address")
		}
		switch a.Type {
		case 1, 8:
			configuration.Addresses = append(configuration.Addresses, addr)
		case 3, 10:
			configuration.DNS = append(configuration.DNS, addr)
		case 20, 21:
			configuration.PCSCF = append(configuration.PCSCF, addr)
		}
	}
	if len(configuration.Addresses) == 0 {
		return errors.New("no assigned inner IP address")
	}
	for _, addr := range configuration.Addresses {
		if s.cfg.IPStack == "ipv4" && !addr.Is4() || s.cfg.IPStack == "ipv6" && !addr.Is6() {
			return errors.New("assigned address uses unrequested IP family")
		}
		allowed := false
		for _, t := range local {
			if t.Protocol == 0 && t.StartPort == 0 && t.EndPort == 65535 && t.Start.BitLen() == addr.BitLen() && addr.Compare(t.Start) >= 0 && addr.Compare(t.End) <= 0 {
				allowed = true
			}
		}
		if !allowed {
			return errors.New("assigned address outside narrowed local selectors")
		}
	}
	seed := append(append([]byte{}, s.ni...), s.nr...)
	n := 2 * (s.encLen + s.integ.KeyLen())
	material, e := s.prf.Plus(s.keys.SKd, seed, n)
	if e != nil {
		return e
	}
	take := func(n int) []byte { out := append([]byte{}, material[:n]...); material = material[n:]; return out }
	outEnc, outAuth, inEnc, inAuth := take(s.encLen), take(s.integ.KeyLen()), take(s.encLen), take(s.integ.KeyLen())
	s.out, e = ipsec.NewSA(ipsec.SAConfig{SPI: peerSPI, EncryptionKey: outEnc, IntegrityKey: outAuth, Integrity: s.integ, Encryption: s.protection().Encryption, Random: s.cfg.Random})
	if e != nil {
		return e
	}
	s.in, e = ipsec.NewSA(ipsec.SAConfig{SPI: s.childSPI, EncryptionKey: inEnc, IntegrityKey: inAuth, Integrity: s.integ, Encryption: s.protection().Encryption})
	if e != nil {
		return e
	}
	for _, payload := range ps {
		if payload.Type != ikev2.Notify {
			continue
		}
		code, data, err := ikev2.ParseNotification(payload.Data)
		if err != nil {
			return err
		}
		if code == 16403 {
			if payload.Data[0] != 0 || payload.Data[1] != 0 || len(data) != 4 {
				return errors.New("invalid AUTH_LIFETIME notification")
			}
			s.authDeadline = time.Now().Add(time.Duration(binary.BigEndian.Uint32(data)) * time.Second)
		}
	}
	s.configuration = configuration
	s.childCreated = time.Now()
	return nil
}

func resolveEPDG(ctx context.Context, remote string) (string, []net.IP, error) {
	return resolveEPDGUsingDNS(ctx, remote, "")
}

func resolveEPDGUsingDNS(ctx context.Context, remote, dnsServer string) (string, []net.IP, error) {
	resolver := net.DefaultResolver
	if dnsServer = normalizeDNSServer(dnsServer); dnsServer != "" {
		resolver = &net.Resolver{PreferGo: true, Dial: func(c context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(c, network, dnsServer)
		}}
	}
	return resolveEPDGWithResolver(ctx, remote, resolver)
}

func resolveEPDGWithResolver(ctx context.Context, remote string, resolver *net.Resolver) (string, []net.IP, error) {
	host, port, e := net.SplitHostPort(remote)
	if e != nil {
		return "", nil, fmt.Errorf("invalid ePDG endpoint: %w", e)
	}
	numericPort, e := net.LookupPort("udp", port)
	if e != nil || numericPort < 1 || numericPort > 65535 {
		return "", nil, errors.New("invalid ePDG UDP port")
	}
	addresses, e := resolver.LookupIPAddr(ctx, host)
	if e != nil {
		return "", nil, fmt.Errorf("resolve ePDG: %w", e)
	}
	var ips []net.IP
	var selected net.IP
	for _, address := range addresses {
		if address.Zone != "" {
			continue
		}
		ip := address.IP
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		ips = append(ips, append(net.IP{}, ip...))
		if selected == nil || selected.To4() == nil && ip.To4() != nil {
			selected = ip
		}
	}
	if selected == nil {
		return "", nil, errors.New("ePDG has no usable unicast IP address")
	}
	return net.JoinHostPort(selected.String(), fmt.Sprint(numericPort)), ips, nil
}
