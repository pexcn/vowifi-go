package swu

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	vc "github.com/iniwex5/vowifi-go/engine/crypto"
	"github.com/iniwex5/vowifi-go/engine/eap"
	"github.com/iniwex5/vowifi-go/engine/ikev2"
	"github.com/iniwex5/vowifi-go/engine/ipsec"
	"github.com/iniwex5/vowifi-go/engine/sim"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type testSIM struct{ calls atomic.Int32 }

func (s *testSIM) CalculateAKA(r, a []byte) (sim.AKAResult, error) {
	s.calls.Add(1)
	return sim.AKAResult{RES: []byte{1, 2, 3, 4, 5, 6, 7, 8}, IK: bytes.Repeat([]byte{9}, 16), CK: bytes.Repeat([]byte{7}, 16)}, nil
}

// Port remapping lets the peer exercise real loopback UDP while avoiding any
// privileged or globally fixed ports. The client must still request 4500.
type mappedUDP struct {
	ipsec.DatagramConn
	natt             string
	switched, closed atomic.Bool
}

func (c *mappedUDP) SetPeer(peer string) error {
	_, port, e := net.SplitHostPort(peer)
	if e != nil || port != "4500" {
		return errors.New("expected NAT-T port4500")
	}
	c.switched.Store(true)
	return c.DatagramConn.(ipsec.PeerSwitcher).SetPeer(c.natt)
}
func (c *mappedUDP) Close() error { c.closed.Store(true); return c.DatagramConn.Close() }

type mockPeer struct {
	t                             *testing.T
	initial, natt                 *net.UDPConn
	client                        *net.UDPAddr
	cfg                           Config
	transport                     *mappedUDP
	cert                          []byte
	signer                        *ecdsa.PrivateKey
	spii, spir                    uint64
	ni, nr, req, resp, id, peerID []byte
	keys                          vc.IKEKeys
	aka                           eap.Keys
	toClient, fromClient          *ipsec.SA
	childSPI                      uint32
	err                           chan error
	mode                          string
}

func newMockPeer(t *testing.T, mode string) *mockPeer {
	t.Helper()
	initial, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	natt, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		initial.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { initial.Close(); natt.Close() })
	signer, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "epdg.test"}, DNSNames: []string{"epdg.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, tpl, tpl, &signer.PublicKey, signer)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	conn, e := ipsec.DialUDP(context.Background(), initial.LocalAddr().String())
	if e != nil {
		t.Fatal(e)
	}
	mapped := &mappedUDP{DatagramConn: conn, natt: natt.LocalAddr().String()}
	t.Cleanup(func() { mapped.Close() })
	p := &mockPeer{t: t, initial: initial, natt: natt, transport: mapped, cert: der, signer: signer, spir: 0x1111222233334444, err: make(chan error, 1), mode: mode}
	p.cfg = Config{EPDGAddr: initial.LocalAddr().String(), ServerName: "epdg.test", NAI: "0001010000000001@example", SIM: &testSIM{}, Transport: mapped, Roots: pool, Timeout: 150 * time.Millisecond, Retransmits: 1, DPDInterval: time.Hour, ChildLifetime: time.Hour}
	return p
}
func (p *mockPeer) read(c *net.UDPConn, marked bool) ([]byte, error) {
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b := make([]byte, 65535)
	n, from, e := c.ReadFromUDP(b)
	if e != nil {
		return nil, e
	}
	p.client = from
	b = b[:n]
	if marked {
		if len(b) < 4 || binary.BigEndian.Uint32(b) != 0 {
			return nil, errors.New("missing non-ESP marker")
		}
		b = b[4:]
	}
	return b, nil
}
func (p *mockPeer) send(c *net.UDPConn, b []byte, marked bool) error {
	if marked {
		b = append([]byte{0, 0, 0, 0}, b...)
	}
	_, e := c.WriteToUDP(b, p.client)
	return e
}
func (p *mockPeer) response(h ikev2.Header, ps []ikev2.Payload) error {
	h.Flags = ikev2.FlagResponse
	b, e := ikev2.Seal(h, ps, p.keys.SKer, p.keys.SKar, vc.HMACSHA256128, nil)
	if e != nil {
		return e
	}
	return p.send(p.natt, b, true)
}
func (p *mockPeer) readAuth(id uint32) (ikev2.Message, error) {
	b, e := p.read(p.natt, true)
	if e != nil {
		return ikev2.Message{}, e
	}
	m, e := ikev2.Open(b, p.keys.SKei, p.keys.SKai, vc.HMACSHA256128)
	if e != nil {
		return m, e
	}
	if m.Header.MessageID != id || m.Header.Exchange != ikev2.IKEAuth || m.Header.Flags != ikev2.FlagInitiator {
		return m, errors.New("wrong AUTH exchange header")
	}
	return m, nil
}
func (p *mockPeer) certAuth() ([]byte, error) {
	oct, e := signedOctets(vc.PRFSHA256, p.resp, p.ni, p.keys.SKpr, p.peerID)
	if e != nil {
		return nil, e
	}
	digest := sha256.Sum256(oct)
	r, s, e := ecdsa.Sign(rand.Reader, p.signer, digest[:])
	if e != nil {
		return nil, e
	}
	b := append([]byte{9, 0, 0, 0}, r.FillBytes(make([]byte, 32))...)
	return append(b, s.FillBytes(make([]byte, 32))...), nil
}
func (p *mockPeer) handshake() error {
	req, e := p.read(p.initial, false)
	if e != nil {
		return e
	}
	m, e := ikev2.Parse(req)
	if e != nil {
		return e
	}
	if m.Header.Exchange != ikev2.SAInit || m.Header.ResponderSPI != 0 {
		return errors.New("invalid SA_INIT")
	}
	p.spii = m.Header.InitiatorSPI
	// RFC7296 COOKIE responses use zero responder SPI and must be accepted.
	if p.mode == "cookie" {
		cookie := bytes.Repeat([]byte{0x42}, 16)
		b, e := (ikev2.Message{Header: ikev2.Header{InitiatorSPI: p.spii, Exchange: ikev2.SAInit, Flags: ikev2.FlagResponse}, Payloads: []ikev2.Payload{ikev2.Notification(16390, cookie)}}).Marshal()
		if e != nil {
			return e
		}
		if e = p.send(p.initial, b, false); e != nil {
			return e
		}
		req, e = p.read(p.initial, false)
		if e != nil {
			return e
		}
		m, e = ikev2.Parse(req)
		if e != nil {
			return e
		}
		if len(m.Payloads) == 0 || m.Payloads[0].Type != ikev2.Notify {
			return errors.New("COOKIE not first")
		}
		kind, data, e := ikev2.ParseNotification(m.Payloads[0].Data)
		if e != nil || kind != 16390 || !bytes.Equal(data, cookie) {
			return errors.New("COOKIE mismatch")
		}
	}
	p.req = req
	p.ni, e = ikev2.One(m.Payloads, ikev2.Nonce)
	if e != nil {
		return e
	}
	ke, e := ikev2.One(m.Payloads, ikev2.KE)
	if e != nil {
		return e
	}
	dh, e := vc.NewDH14(nil)
	if e != nil {
		return e
	}
	secret, e := dh.Shared(ke[4:])
	if e != nil {
		return e
	}
	sa, e := ikev2.One(m.Payloads, ikev2.SA)
	if e != nil {
		return e
	}
	p.nr = bytes.Repeat([]byte{0x71}, 32)
	p.resp, e = (ikev2.Message{Header: ikev2.Header{InitiatorSPI: p.spii, ResponderSPI: p.spir, Exchange: ikev2.SAInit, Flags: ikev2.FlagResponse}, Payloads: []ikev2.Payload{{Type: ikev2.SA, Data: sa}, {Type: ikev2.KE, Data: append([]byte{0, 14, 0, 0}, dh.Public...)}, {Type: ikev2.Nonce, Data: p.nr}}}).Marshal()
	if e != nil {
		return e
	}
	p.keys, e = vc.DeriveIKE(vc.PRFSHA256, vc.HMACSHA256128, 16, p.ni, p.nr, secret, p.spii, p.spir)
	if e != nil {
		return e
	}
	if e = p.send(p.initial, p.resp, false); e != nil {
		return e
	}
	m, e = p.readAuth(1)
	if e != nil {
		return e
	}
	var eapOnlyOffers int
	for _, payload := range m.Payloads {
		if payload.Type == ikev2.Notify {
			kind, _, err := ikev2.ParseNotification(payload.Data)
			if err != nil {
				return err
			}
			if kind == 16417 {
				if !bytes.Equal(payload.Data, []byte{0, 0, 0x40, 0x21}) {
					return errors.New("invalid EAP_ONLY_AUTHENTICATION notify")
				}
				eapOnlyOffers++
			}
		}
	}
	if eapOnlyOffers > 1 || (eapOnlyOffers == 1) != p.cfg.EAPOnlyAuthentication {
		return errors.New("wrong RFC 5998 capability offer")
	}
	cpRequest, err := ikev2.One(m.Payloads, ikev2.CP)
	if err != nil {
		return err
	}
	_, requested, err := ikev2.ParseCP(cpRequest)
	if err != nil {
		return err
	}
	requestV4, requestV6 := false, false
	for _, attr := range requested {
		if attr.Type == 1 {
			requestV4 = true
		}
		if attr.Type == 8 {
			requestV6 = true
		}
	}
	if requestV4 != (p.cfg.IPStack != "ipv6") || requestV6 != (p.cfg.IPStack != "ipv4") {
		return errors.New("wrong IP family CP request")
	}
	p.id, e = ikev2.One(m.Payloads, ikev2.IDi)
	if e != nil {
		return e
	}
	if !bytes.Equal(p.id[4:], []byte(p.cfg.NAI)) {
		return errors.New("NAI mismatch")
	}
	child, e := ikev2.One(m.Payloads, ikev2.SA)
	if e != nil {
		return e
	}
	proposal, e := ikev2.ParseProposals(child)
	if e != nil {
		return e
	}
	p.childSPI = binary.BigEndian.Uint32(proposal[0].SPI)
	p.peerID = append([]byte{2, 0, 0, 0}, []byte("epdg.test")...)
	auth, e := p.certAuth()
	if e != nil {
		return e
	}
	p.aka, e = eap.DeriveKeys(p.cfg.NAI, bytes.Repeat([]byte{9}, 16), bytes.Repeat([]byte{7}, 16))
	if e != nil {
		return e
	}
	challenge, e := eap.Sign(p.aka.KAut, eap.Packet{Code: eap.Request, Identifier: 7, Type: eap.AKA, Subtype: eap.Challenge, Attributes: []eap.Attribute{{Type: eap.ATRAND, Value: make([]byte, 18)}, {Type: eap.ATAUTN, Value: make([]byte, 18)}, {Type: eap.ATMAC, Value: make([]byte, 18)}}})
	if e != nil {
		return e
	}
	if p.mode == "checkcode-offer" {
		packet, err := eap.Parse(challenge)
		if err != nil {
			return err
		}
		packet.Attributes = append(packet.Attributes, eap.Attribute{Type: eap.ATCheckcode, Value: []byte{0, 0}})
		challenge, e = eap.Sign(p.aka.KAut, packet)
		if e != nil {
			return e
		}
	}
	ps := []ikev2.Payload{{Type: ikev2.IDr, Data: p.peerID}, {Type: ikev2.CERT, Data: append([]byte{4}, p.cert...)}, {Type: ikev2.AUTH, Data: auth}, {Type: ikev2.EAP, Data: challenge}}
	if strings.HasPrefix(p.mode, "eap-only") {
		ps = []ikev2.Payload{{Type: ikev2.IDr, Data: p.peerID}, {Type: ikev2.EAP, Data: challenge}}
	}
	switch p.mode {
	case "bad-signature":
		ps[2].Data[len(auth)-1] ^= 1
	case "missing-auth":
		ps = append(ps[:2], ps[3:]...)
	case "premature-success":
		ps[3].Data = []byte{eap.Success, 7, 0, 4}
	case "eap-only-bad-mac":
		ps[1].Data[len(challenge)-1] ^= 1
	case "eap-only-premature-success":
		ps[1].Data = []byte{eap.Success, 7, 0, 4}
	case "eap-only-unsupported":
		ps[1].Data = []byte{eap.Request, 7, 0, 5, 4} // EAP-MD5 cannot authenticate this SA.
	case "eap-only-missing-id":
		ps = ps[1:]
	case "eap-only-duplicate-id":
		ps = append(ps, ps[0])
	}
	round := uint32(2)
	if p.mode == "eap-only-identity" {
		if e = p.response(m.Header, []ikev2.Payload{{Type: ikev2.IDr, Data: p.peerID}, {Type: ikev2.EAP, Data: []byte{eap.Request, 6, 0, 5, eap.Identity}}}); e != nil {
			return e
		}
		m, e = p.readAuth(round)
		if e != nil {
			return e
		}
		identity, err := ikev2.One(m.Payloads, ikev2.EAP)
		if err != nil {
			return err
		}
		packet, err := eap.Parse(identity)
		if err != nil || packet.Code != eap.Response || packet.Identifier != 6 || packet.Type != eap.Identity || string(packet.Data) != p.cfg.NAI {
			return errors.New("invalid EAP-only identity response")
		}
		ps = []ikev2.Payload{{Type: ikev2.EAP, Data: challenge}}
		round++
	}
	if e = p.response(m.Header, ps); e != nil {
		return e
	}
	switch p.mode {
	case "bad-cert", "bad-signature", "missing-auth", "premature-success",
		"eap-only-bad-mac", "eap-only-premature-success", "eap-only-unsupported",
		"eap-only-missing-id", "eap-only-duplicate-id":
		return nil
	}
	m, e = p.readAuth(round)
	if e != nil {
		return e
	}
	reply, e := ikev2.One(m.Payloads, ikev2.EAP)
	if e != nil {
		return e
	}
	if e = eap.VerifyMAC(p.aka.KAut, reply, nil); e != nil {
		return e
	}
	ep, e := eap.Parse(reply)
	if e != nil {
		return e
	}
	checkcode, hasCheckcode := ep.Get(eap.ATCheckcode)
	wantCheckcode := p.cfg.AKAChallengeMode == "checkcode" || p.cfg.AKAChallengeMode != "omit" && p.mode == "checkcode-offer"
	if hasCheckcode != wantCheckcode || hasCheckcode && !bytes.Equal(checkcode, []byte{0, 0}) {
		return errors.New("wrong configured AT_CHECKCODE wire offer")
	}
	res, ok := ep.Get(eap.ATRES)
	if !ok || !bytes.Equal(res[2:], []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		return errors.New("invalid AKA RES")
	}
	if e = p.response(m.Header, []ikev2.Payload{{Type: ikev2.EAP, Data: []byte{eap.Success, 7, 0, 4}}}); e != nil {
		return e
	}
	m, e = p.readAuth(round + 1)
	if e != nil {
		return e
	}
	got, e := ikev2.One(m.Payloads, ikev2.AUTH)
	if e != nil {
		return e
	}
	oct, e := signedOctets(vc.PRFSHA256, p.req, p.nr, p.keys.SKpi, p.id)
	if e != nil {
		return e
	}
	want, e := sharedAuth(vc.PRFSHA256, p.aka.MSK, oct)
	if e != nil {
		return e
	}
	if len(got) < 4 || got[0] != 2 || !bytes.Equal(got[4:], want) {
		return errors.New("initiator MSK proof mismatch")
	}
	oct, e = signedOctets(vc.PRFSHA256, p.resp, p.ni, p.keys.SKpr, p.peerID)
	if e != nil {
		return e
	}
	auth, e = sharedAuth(vc.PRFSHA256, p.aka.MSK, oct)
	if e != nil {
		return e
	}
	auth = append([]byte{2, 0, 0, 0}, auth...)
	if p.mode == "bad-final" || p.mode == "eap-only-bad-final" {
		auth[len(auth)-1] ^= 1
	}
	if p.mode == "cert-final" || p.mode == "eap-only-cert-final" {
		auth, e = p.certAuth()
		if e != nil {
			return e
		}
	}
	proposal[0].SPI = binary.BigEndian.AppendUint32(nil, 0xdeadbeef)
	child, e = ikev2.EncodeProposals(proposal)
	if e != nil {
		return e
	}
	local, e := ikev2.EncodeTS([]ikev2.TrafficSelector{{StartPort: 0, EndPort: 65535, Start: netip.MustParseAddr("10.0.0.2"), End: netip.MustParseAddr("10.0.0.2")}})
	if e != nil {
		return e
	}
	remoteSelectors := allSelectors()
	if p.cfg.IPStack == "ipv4" && p.mode != "unoffered-ts" {
		remoteSelectors = remoteSelectors[:1]
	}
	if p.cfg.IPStack == "ipv6" && p.mode != "unoffered-ts" {
		remoteSelectors = remoteSelectors[1:]
	}
	remote, e := ikev2.EncodeTS(remoteSelectors)
	if e != nil {
		return e
	}
	cp, e := ikev2.EncodeCP(2, []ikev2.CPAttribute{{Type: 1, Value: []byte{10, 0, 0, 2}}, {Type: 3, Value: []byte{10, 0, 0, 53}}, {Type: 20, Value: []byte{10, 0, 0, 1}}})
	if e != nil {
		return e
	}
	ps = []ikev2.Payload{{Type: ikev2.AUTH, Data: auth}, {Type: ikev2.SA, Data: child}, {Type: ikev2.TSi, Data: local}, {Type: ikev2.TSr, Data: remote}, {Type: ikev2.CP, Data: cp}}
	switch p.mode {
	case "eap-only-cp-reserved":
		cp[1], cp[2], cp[3] = 0xaa, 0xbb, 0xcc
		for offset := 4; offset < len(cp); {
			length := int(binary.BigEndian.Uint16(cp[offset+2:]))
			cp[offset] |= 0x80
			offset += 4 + length
		}
	case "eap-only-cp-tv":
		// Literal private short attribute before the assigned address. Do not
		// use our TLV encoder to manufacture the compatibility wire format.
		cp = append([]byte{2, 0, 0, 0, 0xf0, 0, 5, 0xdc}, cp[4:]...)
	case "eap-only-cp-empty-optional":
		cp = append(cp, []byte{0, 3, 0, 0, 0, 8, 0, 0, 0, 10, 0, 0, 0, 21, 0, 0}...)
	case "eap-only-cp-wrong-kind":
		cp[0] = 3
	case "eap-only-cp-truncated":
		cp = []byte{2, 0, 0, 0, 0, 1, 0, 8, 10, 0, 0, 2}
	case "eap-only-cp-invalid-ip":
		cp = []byte{2, 0, 0, 0, 0, 1, 0, 3, 10, 0, 0}
	case "eap-only-cp-no-address":
		cp = []byte{2, 0, 0, 0, 0, 1, 0, 0, 0, 8, 0, 0}
	}
	ps[len(ps)-1].Data = cp
	if p.mode == "eap-only-missing-final" {
		ps = ps[1:]
	}
	if p.mode == "eap-only-changed-id" {
		ps = append(ps, ikev2.Payload{Type: ikev2.IDr, Data: append([]byte{2, 0, 0, 0}, []byte("changed.test")...)})
	}
	material, e := vc.PRFSHA256.Plus(p.keys.SKd, append(append([]byte{}, p.ni...), p.nr...), 96)
	if e != nil {
		return e
	}
	p.fromClient, e = ipsec.NewSA(ipsec.SAConfig{SPI: 0xdeadbeef, EncryptionKey: material[:16], IntegrityKey: material[16:48], Integrity: vc.HMACSHA256128})
	if e != nil {
		return e
	}
	p.toClient, e = ipsec.NewSA(ipsec.SAConfig{SPI: p.childSPI, EncryptionKey: material[48:64], IntegrityKey: material[64:96], Integrity: vc.HMACSHA256128})
	if e != nil {
		return e
	}
	return p.response(m.Header, ps)
}
func (p *mockPeer) start() { go func() { p.err <- p.handshake() }() }
func (p *mockPeer) check(t *testing.T) {
	t.Helper()
	select {
	case e := <-p.err:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("mock peer did not finish")
	}
}
func inner(src, dst [4]byte) []byte {
	b := make([]byte, 28)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], 28)
	b[8] = 64
	b[9] = 17
	copy(b[12:], src[:])
	copy(b[16:], dst[:])
	binary.BigEndian.PutUint16(b[20:], 5060)
	binary.BigEndian.PutUint16(b[22:], 5060)
	binary.BigEndian.PutUint16(b[24:], 8)
	return b
}
func TestRealUDPCookieAKAChildESPAndDPD(t *testing.T) {
	p := newMockPeer(t, "cookie")
	p.start()
	s, e := Start(context.Background(), p.cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	p.check(t)
	if !p.transport.switched.Load() {
		t.Fatal("NAT-T switch missing")
	}
	cfg := s.Configuration()
	if len(cfg.Addresses) != 1 || cfg.Addresses[0].String() != "10.0.0.2" || len(cfg.PCSCF) != 1 || cfg.PCSCF[0].String() != "10.0.0.1" {
		t.Fatalf("configuration: %+v", cfg)
	}
	outbound := inner([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1})
	if e = s.WritePacket(context.Background(), outbound); e != nil {
		t.Fatal(e)
	}
	wire, e := p.read(p.natt, false)
	if e != nil {
		t.Fatal(e)
	}
	got, next, e := p.fromClient.Open(wire)
	if e != nil || next != 4 || !bytes.Equal(got, outbound) {
		t.Fatalf("ESP outbound: %x %d %v", got, next, e)
	}
	inbound := inner([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2})
	wire, e = p.toClient.Seal(inbound, 4)
	if e != nil {
		t.Fatal(e)
	}
	forged := append([]byte{}, wire...)
	forged[len(forged)-1] ^= 1
	if e = p.send(p.natt, forged, false); e != nil {
		t.Fatal(e)
	}
	if e = p.send(p.natt, wire, false); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, e = s.ReadPacket(ctx)
	if e != nil || !bytes.Equal(got, inbound) {
		t.Fatalf("ESP inbound: %x %v", got, e)
	}
	// A DPD response must carry the actual exchange ID; an authenticated stale ID
	// is ignored. A peer initiated DPD request has independent sequence zero.
	done := make(chan error, 1)
	go func() { done <- s.controlExchange(nil) }()
	b, e := p.read(p.natt, true)
	if e != nil {
		t.Fatal(e)
	}
	m, e := ikev2.Open(b, p.keys.SKei, p.keys.SKai, vc.HMACSHA256128)
	if e != nil {
		t.Fatal(e)
	}
	if m.Header.MessageID != 4 || m.Header.Exchange != ikev2.Informational {
		t.Fatal("DPD ID")
	}
	wrong := m.Header
	wrong.MessageID--
	if e = p.response(wrong, nil); e != nil {
		t.Fatal(e)
	}
	if e = p.response(m.Header, nil); e != nil {
		t.Fatal(e)
	}
	select {
	case e = <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("DPD blocked")
	}
	h := ikev2.Header{InitiatorSPI: p.spii, ResponderSPI: p.spir, Exchange: ikev2.Informational, MessageID: 0}
	b, e = ikev2.Seal(h, nil, p.keys.SKer, p.keys.SKar, vc.HMACSHA256128, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = p.send(p.natt, b, true); e != nil {
		t.Fatal(e)
	}
	first, e := p.read(p.natt, true)
	if e != nil {
		t.Fatal(e)
	}
	reply, e := ikev2.Open(first, p.keys.SKei, p.keys.SKai, vc.HMACSHA256128)
	if e != nil || reply.Header.Flags != ikev2.FlagInitiator|ikev2.FlagResponse || reply.Header.MessageID != 0 {
		t.Fatalf("peer DPD: %+v %v", reply.Header, e)
	}
	if e = p.send(p.natt, b, true); e != nil {
		t.Fatal(e)
	}
	again, e := p.read(p.natt, true)
	if e != nil || !bytes.Equal(first, again) {
		t.Fatal("retransmitted DPD reply changed", e)
	}
	s.Close()
	if !p.transport.closed.Load() {
		t.Fatal("transport not closed")
	}
	if !errors.Is(s.Err(), context.Canceled) {
		t.Fatal(s.Err())
	}
}
func TestEAPOnlyMutualAKAAndChildESP(t *testing.T) {
	for _, mode := range []string{"eap-only", "eap-only-identity", "certificate-fallback", "eap-only-cp-reserved", "eap-only-cp-tv", "eap-only-cp-empty-optional"} {
		t.Run(mode, func(t *testing.T) {
			p := newMockPeer(t, mode)
			p.cfg.EAPOnlyAuthentication = true
			if mode != "certificate-fallback" {
				p.cfg.Roots = nil // No certificate was sent or trusted on this path.
			}
			p.start()
			s, err := Start(context.Background(), p.cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			p.check(t)
			cfg := s.Configuration()
			if len(cfg.Addresses) != 1 || cfg.Addresses[0].String() != "10.0.0.2" || len(cfg.DNS) != 1 || cfg.DNS[0].String() != "10.0.0.53" || len(cfg.PCSCF) != 1 || cfg.PCSCF[0].String() != "10.0.0.1" {
				t.Fatalf("CFG_REPLY values not preserved: %+v", cfg)
			}
			if p.cfg.SIM.(*testSIM).calls.Load() != 1 {
				t.Fatal("mutual AKA was not completed")
			}
			packet := inner([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1})
			if err = s.WritePacket(context.Background(), packet); err != nil {
				t.Fatal(err)
			}
			wire, err := p.read(p.natt, false)
			if err != nil {
				t.Fatal(err)
			}
			got, next, err := p.fromClient.Open(wire)
			if err != nil || next != 4 || !bytes.Equal(got, packet) {
				t.Fatalf("EAP-only Child SA did not carry ESP: %x %d %v", got, next, err)
			}
			inbound := inner([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2})
			wire, err = p.toClient.Seal(inbound, 4)
			if err != nil {
				t.Fatal(err)
			}
			if err = p.send(p.natt, wire, false); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got, err = s.ReadPacket(ctx)
			if err != nil || !bytes.Equal(got, inbound) {
				t.Fatalf("EAP-only inbound ESP: %x %v", got, err)
			}
		})
	}
}

func TestConfigurationFailuresCloseTransport(t *testing.T) {
	for _, tc := range []struct{ mode, errorText string }{
		{"eap-only-cp-wrong-kind", "got cfg_type=3"},
		{"eap-only-cp-truncated", "length=8 exceeds remaining=4"},
		{"eap-only-cp-invalid-ip", "type=1, length=3, expected=4"},
		{"eap-only-cp-no-address", "no assigned inner IP address"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			p := newMockPeer(t, tc.mode)
			p.cfg.EAPOnlyAuthentication = true
			p.start()
			s, err := Start(context.Background(), p.cfg)
			if s != nil || err == nil || !strings.Contains(err.Error(), tc.errorText) {
				t.Fatalf("invalid configuration accepted or diagnostic lost: session=%v err=%v", s, err)
			}
			p.check(t)
			if !p.transport.closed.Load() {
				t.Fatal("failed configuration leaked transport")
			}
		})
	}
}

func TestEAPOnlyAuthenticationFailuresCloseTransport(t *testing.T) {
	for _, tc := range []struct{ mode, errorText string }{
		{"eap-only-bad-mac", "MAC verification failed"},
		{"eap-only-premature-success", "premature EAP success"},
		{"eap-only-unsupported", "unsupported EAP method"},
		{"eap-only-missing-id", "expected one payload"},
		{"eap-only-duplicate-id", "expected one payload"},
		{"eap-only-changed-id", "responder ID changed"},
		{"eap-only-bad-final", "MSK AUTH mismatch"},
		{"eap-only-missing-final", "missing final responder AUTH"},
		{"eap-only-cert-final", "must prove the EAP MSK"},
		{"bad-cert", "responder certificate"},
		{"bad-signature", "ECDSA AUTH verification failed"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			p := newMockPeer(t, tc.mode)
			p.cfg.EAPOnlyAuthentication = true
			if tc.mode == "bad-cert" {
				p.cfg.ServerName = "untrusted.test"
			}
			p.start()
			s, err := Start(context.Background(), p.cfg)
			if s != nil || err == nil || !strings.Contains(err.Error(), tc.errorText) {
				t.Fatalf("accepted %s or failed for another reason: %v", tc.mode, err)
			}
			p.check(t)
			if !p.transport.closed.Load() {
				t.Fatal("failed EAP-only authentication leaked transport")
			}
			if (tc.mode == "bad-cert" || tc.mode == "bad-signature") && p.cfg.SIM.(*testSIM).calls.Load() != 0 {
				t.Fatal("offered invalid certificate AUTH fell back to EAP-only")
			}
		})
	}
}

func TestAuthenticationFailuresCloseTransport(t *testing.T) {
	for _, mode := range []string{"bad-cert", "bad-signature", "missing-auth", "premature-success", "bad-final", "cert-final"} {
		t.Run(mode, func(t *testing.T) {
			p := newMockPeer(t, mode)
			if mode == "bad-cert" {
				p.cfg.ServerName = "untrusted.test"
			}
			p.start()
			s, e := Start(context.Background(), p.cfg)
			if e == nil || s != nil {
				t.Fatalf("accepted %s", mode)
			}
			p.check(t)
			if !p.transport.closed.Load() {
				t.Fatal("failed handshake leaked transport")
			}
			if mode == "cert-final" && !strings.Contains(e.Error(), "EAP MSK") {
				t.Fatal(e)
			}
			if (mode == "bad-cert" || mode == "bad-signature" || mode == "missing-auth") && p.cfg.SIM.(*testSIM).calls.Load() != 0 {
				t.Fatal("SIM used before responder authentication")
			}
		})
	}
}
func TestDPDTimeoutAndLifetimeFailClosed(t *testing.T) {
	for _, mode := range []string{"DPD", "lifetime"} {
		t.Run(mode, func(t *testing.T) {
			p := newMockPeer(t, "")
			if mode == "DPD" {
				p.cfg.DPDInterval = 5 * time.Millisecond
			} else {
				p.cfg.ChildLifetime = 5 * time.Millisecond
			}
			p.start()
			s, e := Start(context.Background(), p.cfg)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			p.check(t)
			select {
			case <-s.Done():
			case <-time.After(time.Second):
				t.Fatal("session did not fail")
			}
			if !p.transport.closed.Load() {
				t.Fatal("transport leaked")
			}
			if mode == "lifetime" && !errors.Is(s.Err(), ErrRekeyRequired) {
				t.Fatal(s.Err())
			}
			if mode == "DPD" && !strings.Contains(s.Err().Error(), "DPD retransmissions exhausted") {
				t.Fatal(s.Err())
			}
			if e = s.WritePacket(context.Background(), nil); !errors.Is(e, s.Err()) {
				t.Fatal(fmt.Sprint("write after shutdown: ", e))
			}
		})
	}
}

func TestRequestedIPFamiliesAndNATKeepalive(t *testing.T) {
	for _, stack := range []string{"ipv4", "ipv6"} {
		t.Run(stack, func(t *testing.T) {
			p := newMockPeer(t, "")
			p.cfg.IPStack = stack
			p.cfg.NATKeepalive = 5 * time.Millisecond
			p.start()
			s, err := Start(context.Background(), p.cfg)
			p.check(t)
			if stack == "ipv6" {
				if err == nil || s != nil {
					t.Fatal("v4 reply accepted for v6 request")
				}
				if !p.transport.closed.Load() {
					t.Fatal("failed IP family leaked transport")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			b, err := p.read(p.natt, false)
			if err != nil || !bytes.Equal(b, []byte{255}) {
				t.Fatalf("NAT keepalive: %x %v", b, err)
			}
		})
	}
	p := newMockPeer(t, "unoffered-ts")
	p.cfg.IPStack = "ipv4"
	p.start()
	s, err := Start(context.Background(), p.cfg)
	p.check(t)
	if err == nil || s != nil || !strings.Contains(err.Error(), "unoffered traffic selector family") {
		t.Fatalf("unoffered TS: %v", err)
	}
}

func TestMalformedCreateChildRequestKeepsSession(t *testing.T) {
	p := newMockPeer(t, "")
	p.start()
	s, err := Start(context.Background(), p.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p.check(t)
	h := ikev2.Header{InitiatorSPI: p.spii, ResponderSPI: p.spir, Exchange: ikev2.CreateChildSA, MessageID: 0}
	b, err := ikev2.Seal(h, nil, p.keys.SKer, p.keys.SKar, vc.HMACSHA256128, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.send(p.natt, b, true); err != nil {
		t.Fatal(err)
	}
	b, err = p.read(p.natt, true)
	if err != nil {
		t.Fatal(err)
	}
	m, err := ikev2.Open(b, p.keys.SKei, p.keys.SKai, vc.HMACSHA256128)
	if err != nil {
		t.Fatal(err)
	}
	n, err := ikev2.One(m.Payloads, ikev2.Notify)
	if err != nil {
		t.Fatal(err)
	}
	kind, _, err := ikev2.ParseNotification(n)
	if err != nil || kind != 7 {
		t.Fatalf("rekey rejection: %d %v", kind, err)
	}
	select {
	case <-s.Done():
		t.Fatal(s.Err())
	default:
	}
	sendTunnelPacket(t, p, p.toClient)
	receiveTunnelPacket(t, s)
}

// This SOCKS proxy performs real authenticated UDP ASSOCIATE and forwards both
// IKE ports. It deliberately replies with numeric IP headers for localhost.
func proxyForPeer(t *testing.T, p *mockPeer) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	stop := make(chan struct{})
	failures := make(chan error, 2)
	t.Cleanup(func() {
		close(stop)
		listener.Close()
		relay.Close()
		select {
		case err := <-failures:
			if err != nil {
				t.Error(err)
			}
		default:
		}
	})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(4 * time.Second))
		hello := make([]byte, 3)
		if _, err = io.ReadFull(conn, hello); err != nil {
			failures <- err
			return
		}
		if !bytes.Equal(hello, []byte{5, 1, 2}) {
			failures <- fmt.Errorf("wrong SOCKS greeting: %x", hello)
			return
		}
		if _, err = conn.Write([]byte{5, 2}); err != nil {
			failures <- err
			return
		}
		head := make([]byte, 2)
		if _, err = io.ReadFull(conn, head); err != nil {
			failures <- err
			return
		}
		user := make([]byte, int(head[1]))
		if _, err = io.ReadFull(conn, user); err != nil {
			failures <- err
			return
		}
		length := make([]byte, 1)
		if _, err = io.ReadFull(conn, length); err != nil {
			failures <- err
			return
		}
		password := make([]byte, int(length[0]))
		if _, err = io.ReadFull(conn, password); err != nil {
			failures <- err
			return
		}
		if head[0] != 1 || string(user) != "test-user" || string(password) != "test-password" {
			failures <- errors.New("proxy credentials mismatch")
			return
		}
		if _, err = conn.Write([]byte{1, 0}); err != nil {
			failures <- err
			return
		}
		associate := make([]byte, 10)
		if _, err = io.ReadFull(conn, associate); err != nil {
			failures <- err
			return
		}
		if !bytes.Equal(associate, []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}) {
			failures <- errors.New("not UDP ASSOCIATE")
			return
		}
		port := relay.LocalAddr().(*net.UDPAddr).Port
		if _, err = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)}); err != nil {
			failures <- err
			return
		}
		<-stop
	}()
	go func() {
		var client *net.UDPAddr
		for {
			packet := make([]byte, 65535)
			n, from, err := relay.ReadFromUDP(packet)
			if err != nil {
				return
			}
			packet = packet[:n]
			if from.Port == p.initial.LocalAddr().(*net.UDPAddr).Port || from.Port == p.natt.LocalAddr().(*net.UDPAddr).Port {
				if client == nil {
					failures <- errors.New("proxy received reply before request")
					return
				}
				port := from.Port
				if port == p.natt.LocalAddr().(*net.UDPAddr).Port {
					port = 4500
				}
				packet = append([]byte{0, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)}, packet...)
				if _, err = relay.WriteToUDP(packet, client); err != nil {
					return
				}
				continue
			}
			client = from
			if len(packet) < 10 || !bytes.Equal(packet[:8], []byte{0, 0, 0, 1, 127, 0, 0, 1}) {
				failures <- fmt.Errorf("proxy target not normalized numeric IPv4: %x", packet)
				return
			}
			port := int(binary.BigEndian.Uint16(packet[8:]))
			if port == 4500 {
				port = p.natt.LocalAddr().(*net.UDPAddr).Port
			} else if port != p.initial.LocalAddr().(*net.UDPAddr).Port {
				failures <- errors.New("unexpected proxy peer port")
				return
			}
			if _, err = relay.WriteToUDP(packet[10:], &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}); err != nil {
				return
			}
		}
	}()
	return listener.Addr().String()
}
func TestSOCKSProxyDomainNormalizationCompleteHandshake(t *testing.T) {
	p := newMockPeer(t, "cookie")
	proxy := proxyForPeer(t, p)
	p.cfg.Transport = nil
	p.cfg.Proxy = &ProxyConfig{Enabled: true, Type: "socks5", Addr: proxy, Username: "test-user", Password: "test-password"}
	_, port, _ := net.SplitHostPort(p.cfg.EPDGAddr)
	p.cfg.EPDGAddr = net.JoinHostPort("localhost", port)
	p.start()
	s, err := Start(context.Background(), p.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p.check(t)
	if s.EPDGHost != "localhost" || s.cfg.ServerName != "epdg.test" {
		t.Fatal("original DNS identity lost")
	}
	if len(s.EPDGIPs) == 0 || s.RemoteAddr != "127.0.0.1:4500" {
		t.Fatalf("resolved peer: %v %s", s.EPDGIPs, s.RemoteAddr)
	}
	outbound := inner([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1})
	if err = s.WritePacket(context.Background(), outbound); err != nil {
		t.Fatal(err)
	}
	packet, err := p.read(p.natt, false)
	if err != nil {
		t.Fatal(err)
	}
	plain, next, err := p.fromClient.Open(packet)
	if err != nil || next != 4 || !bytes.Equal(plain, outbound) {
		t.Fatal("proxy ESP outbound", err)
	}
	inbound := inner([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2})
	packet, err = p.toClient.Seal(inbound, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.send(p.natt, packet, false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	plain, err = s.ReadPacket(ctx)
	if err != nil || !bytes.Equal(plain, inbound) {
		t.Fatal("proxy ESP inbound", err)
	}
}
func TestMalformedEPDGAndProxyFailure(t *testing.T) {
	for _, endpoint := range []string{"127.0.0.1:0", "127.0.0.1:65536", "[invalid]:500", "0.0.0.0:500"} {
		t.Run(endpoint, func(t *testing.T) {
			if _, _, err := resolveEPDG(context.Background(), endpoint); err == nil {
				t.Fatal("malformed/unusable endpoint accepted")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := resolveEPDG(ctx, "nonexistent.invalid:500"); err == nil {
		t.Fatal("canceled resolver accepted")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := listener.Addr().String()
	listener.Close()
	_, err = Start(context.Background(), Config{EPDGAddr: "127.0.0.1", NAI: "test", SIM: &testSIM{}, Proxy: &ProxyConfig{Enabled: true, Type: "socks5", Addr: proxy}})
	if !errors.Is(err, ErrProxyConnectFailed) {
		t.Fatalf("proxy failure not exposed: %v", err)
	}
}

func TestCheckcodeModeCompleteSWuHandshake(t *testing.T) {
	for _, mode := range []string{"minimal", "omit", "checkcode"} {
		for _, offer := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", mode, offer), func(t *testing.T) {
				peerMode := ""
				if offer {
					peerMode = "checkcode-offer"
				}
				p := newMockPeer(t, peerMode)
				p.cfg.AKAChallengeMode = mode
				p.start()
				s, err := Start(context.Background(), p.cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				p.check(t)
			})
		}
	}
}
