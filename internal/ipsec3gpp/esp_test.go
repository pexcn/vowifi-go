package ipsec3gpp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"testing"
)

func testSA(t *testing.T, enc string) *SA {
	t.Helper()
	s, e := NewSA(0x12345678, enc, "hmac-sha-1-96", bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16))
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func TestESPIntegrityReplayAndOutOfOrder(t *testing.T) {
	for _, enc := range []string{"aes-cbc", "null"} {
		t.Run(enc, func(t *testing.T) {
			tx, rx := testSA(t, enc), testSA(t, enc)
			var packets [][]byte
			for _, p := range []string{"REGISTER sip:ims.example SIP/2.0", "second", "third"} {
				b, e := tx.Protect([]byte(p), 17)
				if e != nil {
					t.Fatal(e)
				}
				packets = append(packets, b)
			}
			forged := append([]byte(nil), packets[0]...)
			binary.BigEndian.PutUint32(forged[4:], 0x7fffffff)
			if _, _, e := rx.Unprotect(forged); !errors.Is(e, ErrIntegrity) {
				t.Fatalf("forged sequence: %v", e)
			}
			for _, i := range []int{2, 0, 1} {
				p, next, e := rx.Unprotect(packets[i])
				if e != nil || next != 17 || len(p) == 0 {
					t.Fatalf("open %d: %d %v", i, next, e)
				}
			}
			if _, _, e := rx.Unprotect(packets[0]); !errors.Is(e, ErrReplay) {
				t.Fatalf("replay accepted: %v", e)
			}
		})
	}
}
func TestESPMalformedAndSequenceExhaustion(t *testing.T) {
	s := testSA(t, "null")
	s.seq = math.MaxUint32
	if _, e := s.Protect([]byte("x"), 17); !errors.Is(e, ErrSequenceExhausted) {
		t.Fatal(e)
	}
	s = testSA(t, "null")
	for i := 0; i < 30; i++ {
		if _, _, e := s.Unprotect(make([]byte, i)); e == nil {
			t.Fatalf("malformed length %d accepted", i)
		}
	}
	tx := testSA(t, "null")
	b, _ := tx.Protect([]byte("payload"), 17)
	b[len(b)-14] = 250
	copy(b[len(b)-12:], tx.tag(b[:len(b)-12]))
	if _, _, e := s.Unprotect(b); e == nil {
		t.Fatal("authenticated invalid padding accepted")
	}
	good, _ := testSA(t, "null").Protect([]byte("valid"), 17)
	if _, _, e := s.Unprotect(good); e != nil {
		t.Fatalf("invalid padding advanced replay: %v", e)
	}
}

type captureEndpoint struct{ packet []byte }

func (c *captureEndpoint) WritePacket(_ context.Context, p []byte) error {
	c.packet = append([]byte(nil), p...)
	return nil
}
func (c *captureEndpoint) ReadPacket(context.Context) ([]byte, error) { return c.packet, nil }
func config() Config {
	return Config{LocalIP: netip.MustParseAddr("10.0.0.1"), RemoteIP: netip.MustParseAddr("10.0.0.2"), Client: SecurityParameters{"hmac-sha-1-96", "aes-cbc", 1001, 1002, 10001, 10002}, Server: SecurityParameters{"hmac-sha-1-96", "aes-cbc", 2001, 2002, 20001, 20002}, CK: bytes.Repeat([]byte{1}, 16), IK: bytes.Repeat([]byte{2}, 16)}
}
func udpPacket(src, dst netip.Addr, sport, dport uint16) []byte {
	header := 20
	if src.Is6() {
		header = 40
	}
	p := make([]byte, header+12)
	if src.Is4() {
		p[0] = 0x45
		p[8] = 64
		p[9] = 17
		binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
		copy(p[12:], src.AsSlice())
		copy(p[16:], dst.AsSlice())
	} else {
		p[0] = 0x60
		p[6] = 17
		p[7] = 64
		binary.BigEndian.PutUint16(p[4:], 12)
		copy(p[8:], src.AsSlice())
		copy(p[24:], dst.AsSlice())
	}
	binary.BigEndian.PutUint16(p[header:], sport)
	binary.BigEndian.PutUint16(p[header+2:], dport)
	binary.BigEndian.PutUint16(p[header+4:], 12)
	copy(p[header+8:], "SIP!")
	h, _ := parseIP(p)
	out, _ := replace(p, h, p[header:], 17)
	return out
}
func TestFourSAEndpointAndPlaintextRejection(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		c := config()
		if ipv6 {
			c.LocalIP = netip.MustParseAddr("2001:db8::1")
			c.RemoteIP = netip.MustParseAddr("2001:db8::2")
		}
		wire := &captureEndpoint{}
		tx := NewEndpoint(wire)
		if e := tx.Install(c); e != nil {
			t.Fatal(e)
		}
		opposite := c
		opposite.LocalIP, opposite.RemoteIP = c.RemoteIP, c.LocalIP
		opposite.Client, opposite.Server = c.Server, c.Client
		rx := NewEndpoint(wire)
		if e := rx.Install(opposite); e != nil {
			t.Fatal(e)
		}
		for _, ports := range [][2]uint16{{c.Client.PortClient, c.Server.PortServer}, {c.Client.PortServer, c.Server.PortClient}} {
			plain := udpPacket(c.LocalIP, c.RemoteIP, ports[0], ports[1])
			if e := tx.WritePacket(context.Background(), plain); e != nil {
				t.Fatal(e)
			}
			h, _ := parseIP(wire.packet)
			if h.protocol != 50 {
				t.Fatal("no ESP encapsulation")
			}
			opened, e := rx.unprotect(wire.packet)
			if e != nil || !bytes.Equal(opened, plain) {
				t.Fatalf("transport roundtrip %x vs %x %v", opened, plain, e)
			}
			if _, e := rx.unprotect(plain); e == nil {
				t.Fatal("plaintext protected tuple accepted")
			}
			if _, e := rx.unprotect(wire.packet); !errors.Is(e, ErrReplay) {
				t.Fatalf("replay: %v", e)
			}
		}
	}
}
func TestUnauthenticatedPacketDoesNotConsumeSequence(t *testing.T) {
	c := config()
	wire := &captureEndpoint{}
	tx := NewEndpoint(wire)
	tx.Install(c)
	rev := c
	rev.LocalIP, rev.RemoteIP = c.RemoteIP, c.LocalIP
	rev.Client, rev.Server = c.Server, c.Client
	rx := NewEndpoint(wire)
	rx.Install(rev)
	p := udpPacket(c.LocalIP, c.RemoteIP, c.Client.PortClient, c.Server.PortServer)
	tx.WritePacket(context.Background(), p)
	bad := append([]byte(nil), wire.packet...)
	bad[len(bad)-1] ^= 1
	if _, e := rx.unprotect(bad); !errors.Is(e, ErrIntegrity) {
		t.Fatal(e)
	}
	if _, e := rx.unprotect(wire.packet); e != nil {
		t.Fatal(e)
	}
}

func TestESPReplayWindowBoundary(t *testing.T) {
	tx, rx := testSA(t, "null"), testSA(t, "null")
	packets := make([][]byte, 70)
	for i := range packets {
		packets[i], _ = tx.Protect([]byte("message"), 17)
	}
	if _, _, e := rx.Unprotect(packets[69]); e != nil {
		t.Fatal(e)
	}
	if _, _, e := rx.Unprotect(packets[5]); !errors.Is(e, ErrReplay) {
		t.Fatalf("outside window: %v", e)
	}
	if _, _, e := rx.Unprotect(packets[6]); e != nil {
		t.Fatalf("last packet inside window: %v", e)
	}
}

func TestRepeatedInstallDoesNotResetReplayOrSequence(t *testing.T) {
	c := config()
	wire := &captureEndpoint{}
	tx := NewEndpoint(wire)
	if e := tx.Install(c); e != nil {
		t.Fatal(e)
	}
	rev := c
	rev.LocalIP, rev.RemoteIP = c.RemoteIP, c.LocalIP
	rev.Client, rev.Server = c.Server, c.Client
	rx := NewEndpoint(wire)
	rx.Install(rev)
	packet := udpPacket(c.LocalIP, c.RemoteIP, c.Client.PortClient, c.Server.PortServer)
	tx.WritePacket(context.Background(), packet)
	first := append([]byte(nil), wire.packet...)
	if _, e := rx.unprotect(first); e != nil {
		t.Fatal(e)
	}
	if e := tx.Install(c); e != nil {
		t.Fatal(e)
	}
	if e := rx.Install(rev); e != nil {
		t.Fatal(e)
	}
	if _, e := rx.unprotect(first); !errors.Is(e, ErrReplay) {
		t.Fatalf("reinstall reset replay: %v", e)
	}
	tx.WritePacket(context.Background(), packet)
	h, _ := parseIP(wire.packet)
	if seq := binary.BigEndian.Uint32(wire.packet[h.length+4:]); seq != 2 {
		t.Fatalf("reinstall reset sequence to %d", seq)
	}
	if _, e := rx.unprotect(wire.packet); e != nil {
		t.Fatal(e)
	}
}
