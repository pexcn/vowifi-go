package media

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type packet struct {
	data []byte
	addr net.Addr
}
type packetConn struct {
	addr     *net.UDPAddr
	in, out  chan packet
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	deadline time.Time
}

func newPacketConn(port int) *packetConn {
	return &packetConn{addr: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: port}, in: make(chan packet, 16), out: make(chan packet, 16), done: make(chan struct{})}
}
func (c *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.mu.Lock()
	d := c.deadline
	c.mu.Unlock()
	var timer <-chan time.Time
	if !d.IsZero() {
		t := time.NewTimer(time.Until(d))
		defer t.Stop()
		timer = t.C
	}
	select {
	case p := <-c.in:
		return copy(b, p.data), p.addr, nil
	case <-c.done:
		return 0, nil, net.ErrClosed
	case <-timer:
		return 0, nil, timeout{}
	}
}
func (c *packetConn) WriteTo(b []byte, a net.Addr) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	case c.out <- packet{append([]byte(nil), b...), a}:
		return len(b), nil
	}
}
func (c *packetConn) Close() error                  { c.once.Do(func() { close(c.done) }); return nil }
func (c *packetConn) LocalAddr() net.Addr           { return c.addr }
func (c *packetConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }
func (c *packetConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}
func (c *packetConn) SetWriteDeadline(time.Time) error { return nil }

type timeout struct{}

func (timeout) Error() string   { return "timeout" }
func (timeout) Timeout() bool   { return true }
func (timeout) Temporary() bool { return true }
func mediaSession(t *testing.T) (*Session, []*packetConn) {
	t.Helper()
	var cs []*packetConn
	s, e := NewSession(context.Background(), func(_ context.Context, network, address string) (net.PacketConn, error) {
		if network != "udp4" || address != "192.0.2.1:0" {
			t.Errorf("not injected tunnel binding %s %s", network, address)
		}
		c := newPacketConn(4000 + len(cs)*2)
		cs = append(cs, c)
		return c, nil
	}, "192.0.2.1")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s, cs
}
func TestSilentCallUsesNegotiatedTunnelRTPAndStops(t *testing.T) {
	s, cs := mediaSession(t)
	if e := s.SetRemote(Description{Address: net.ParseIP("192.0.2.2"), RTP: 5000, RTCP: 5001, Codecs: []Codec{{96, "PCMA", 8000, 1}}, Direction: "recvonly"}); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.RunSilentCall(ctx) }()
	var first, second packet
	select {
	case first = <-cs[0].out:
	case <-time.After(time.Second):
		t.Fatal("no actual RTP")
	}
	select {
	case second = <-cs[0].out:
	case <-time.After(time.Second):
		t.Fatal("no second RTP")
	}
	if !validRTP(first.data) || first.data[1] != 96 || len(first.data) != 172 || first.data[12] != 0xd5 || first.addr.String() != "192.0.2.2:5000" {
		t.Fatalf("bad negotiated G.711 packet %#v", first)
	}
	if binary.BigEndian.Uint16(second.data[2:4])-binary.BigEndian.Uint16(first.data[2:4]) != 1 || binary.BigEndian.Uint32(second.data[4:8])-binary.BigEndian.Uint32(first.data[4:8]) != 160 {
		t.Fatal("incorrect 20 ms RTP sequence/timestamp")
	}
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("media goroutines did not stop")
	}
}
func TestRelayRejectsWrongSourceAndMapsPayload(t *testing.T) {
	s, src := mediaSession(t)
	d, dst := mediaSession(t)
	for _, v := range []struct {
		s    *Session
		pt   uint8
		port int
	}{{s, 96, 5000}, {d, 97, 6000}} {
		if e := v.s.SetRemote(Description{Address: net.ParseIP("192.0.2.2"), RTP: v.port, RTCP: v.port + 1, Codecs: []Codec{{v.pt, "PCMU", 8000, 1}}}); e != nil {
			t.Fatal(e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.RelayTo(ctx, d) }()
	b := make([]byte, 13)
	b[0] = 0x80
	b[1] = 0x80 | 96
	b[12] = 42
	src[0].in <- packet{b, &net.UDPAddr{IP: net.ParseIP("192.0.2.3"), Port: 5000}}
	select {
	case <-dst[0].out:
		t.Fatal("accepted spoofed RTP source")
	case <-time.After(20 * time.Millisecond):
	}
	src[0].in <- packet{b, &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 5000}}
	select {
	case p := <-dst[0].out:
		if p.data[1] != 0x80|97 || p.data[12] != 42 || p.addr.String() != "192.0.2.2:6000" {
			t.Fatalf("relay packet %#v", p)
		}
	case <-time.After(time.Second):
		t.Fatal("no relayed RTP")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay leaked")
	}
}
func TestPacketValidation(t *testing.T) {
	for _, b := range [][]byte{nil, {0x80}, {0x90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0xa0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4}} {
		if validRTP(b) {
			t.Errorf("accepted malformed RTP %x", b)
		}
	}
	for _, b := range [][]byte{nil, {0x80, 201, 0, 2, 0, 0, 0, 0}, {0x40, 201, 0, 1, 0, 0, 0, 0}} {
		if validRTCP(b) {
			t.Errorf("accepted malformed RTCP %x", b)
		}
	}
	if !validRTCP([]byte{0x80, 201, 0, 1, 0, 0, 0, 0}) {
		t.Fatal("rejected valid receiver report")
	}
}

func TestCompoundRTCPHasSenderClockAndCNAME(t *testing.T) {
	now := time.Unix(0, 500000000)
	b := rtcpReport(now, 123, 456, 7, 1120)
	if !validRTCP(b) || b[1] != 200 || binary.BigEndian.Uint32(b[8:12]) != 2208988800 || binary.BigEndian.Uint32(b[12:16]) != 1<<31 || binary.BigEndian.Uint32(b[16:20]) != 456 || binary.BigEndian.Uint32(b[20:24]) != 7 || binary.BigEndian.Uint32(b[24:28]) != 1120 || b[29] != 202 || b[36] != 1 {
		t.Fatalf("bad compound sender report %x", b)
	}
	b = rtcpReport(now, 123, 0, 0, 0)
	if !validRTCP(b) || b[1] != 201 || b[9] != 202 {
		t.Fatalf("bad compound receiver report %x", b)
	}
}
