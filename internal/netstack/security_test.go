package netstack

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pexcn/vowifi-go/internal/ipsec3gpp"
)

type auditedEndpoint struct {
	memoryEndpoint
	esp, plaintext atomic.Uint64
}

func (e *auditedEndpoint) WritePacket(ctx context.Context, p []byte) error {
	if len(p) >= 40 && p[0]>>4 == 6 {
		switch p[6] {
		case 50:
			e.esp.Add(1)
		case 6, 17:
			e.plaintext.Add(1)
		}
	} else if len(p) >= 20 && p[0]>>4 == 4 {
		switch p[9] {
		case 50:
			e.esp.Add(1)
		case 6, 17:
			e.plaintext.Add(1)
		}
	}
	return e.memoryEndpoint.WritePacket(ctx, p)
}

// Exercise full IP -> ESP -> SWu-packet-interface -> ESP -> IP paths, including
// transport checksums and both directions of the negotiated IMS SPI mapping.
func TestTCPAndUDPWithIMSFourSAProtection(t *testing.T) {
	for _, family := range []string{"IPv4", "IPv6"} {
		for _, encryption := range []string{"aes-cbc", "null"} {
			t.Run(family+"/"+encryption, func(t *testing.T) {
				leftIP, rightIP := netip.MustParseAddr("10.12.0.1"), netip.MustParseAddr("10.12.0.2")
				if family == "IPv6" {
					leftIP, rightIP = netip.MustParseAddr("2001:db8:12::1"), netip.MustParseAddr("2001:db8:12::2")
				}
				a, b := make(chan []byte, 256), make(chan []byte, 256)
				wireLeft := &auditedEndpoint{memoryEndpoint: memoryEndpoint{a, b}}
				wireRight := &auditedEndpoint{memoryEndpoint: memoryEndpoint{b, a}}
				protectedLeft, protectedRight := ipsec3gpp.NewEndpoint(wireLeft), ipsec3gpp.NewEndpoint(wireRight)
				agreement := ipsec3gpp.Config{LocalIP: leftIP, RemoteIP: rightIP, Client: ipsec3gpp.SecurityParameters{Algorithm: "hmac-sha-1-96", Encryption: encryption, SPIClient: 1001, SPIServer: 1002, PortClient: 10001, PortServer: 10002}, Server: ipsec3gpp.SecurityParameters{Algorithm: "hmac-sha-1-96", Encryption: encryption, SPIClient: 2001, SPIServer: 2002, PortClient: 20001, PortServer: 20002}, CK: bytes.Repeat([]byte{1}, 16), IK: bytes.Repeat([]byte{2}, 16)}
				if e := protectedLeft.Install(agreement); e != nil {
					t.Fatal(e)
				}
				rev := agreement
				rev.LocalIP, rev.RemoteIP = rightIP, leftIP
				rev.Client, rev.Server = agreement.Server, agreement.Client
				if e := protectedRight.Install(rev); e != nil {
					t.Fatal(e)
				}
				left, e := New(context.Background(), protectedLeft, Config{LocalAddresses: []netip.Addr{leftIP}, MTU: 1280})
				if e != nil {
					t.Fatal(e)
				}
				defer left.Close()
				right, e := New(context.Background(), protectedRight, Config{LocalAddresses: []netip.Addr{rightIP}, MTU: 1280})
				if e != nil {
					t.Fatal(e)
				}
				defer right.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				listener, e := right.ListenTCP(ctx, net.TCPAddrFromAddrPort(netip.AddrPortFrom(rightIP, 20002)))
				if e != nil {
					t.Fatal(e)
				}
				defer listener.Close()
				done := make(chan error, 1)
				go func() {
					conn, e := listener.Accept()
					if e != nil {
						done <- e
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(time.Second))
					p := make([]byte, 4)
					_, e = io.ReadFull(conn, p)
					if e == nil {
						_, e = conn.Write(p)
					}
					done <- e
				}()
				conn, e := left.DialContextWithLocalPort(ctx, "tcp", net.JoinHostPort(rightIP.String(), "20002"), leftIP, 10001)
				if e != nil {
					t.Fatal(e)
				}
				conn.SetDeadline(time.Now().Add(time.Second))
				conn.Write([]byte("SIP!"))
				p := make([]byte, 4)
				if _, e = io.ReadFull(conn, p); e != nil || string(p) != "SIP!" {
					t.Fatalf("protected TCP %q %v", p, e)
				}
				conn.Close()
				if e = <-done; e != nil {
					t.Fatal(e)
				}
				socket, e := right.ListenPacket(ctx, "udp", net.JoinHostPort(rightIP.String(), "20002"))
				if e != nil {
					t.Fatal(e)
				}
				defer socket.Close()
				socket.SetDeadline(time.Now().Add(time.Second))
				conn, e = left.DialContextWithLocalPort(ctx, "udp", net.JoinHostPort(rightIP.String(), "20002"), leftIP, 10001)
				if e != nil {
					t.Fatal(e)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				conn.Write([]byte("SMS!"))
				p = make([]byte, 4)
				n, from, e := socket.ReadFrom(p)
				if e != nil || string(p[:n]) != "SMS!" {
					t.Fatalf("protected UDP request %q %v", p[:n], e)
				}
				socket.WriteTo(p[:n], from)
				n, e = conn.Read(p)
				if e != nil || string(p[:n]) != "SMS!" {
					t.Fatalf("protected UDP response %q %v", p[:n], e)
				}
				if wireLeft.esp.Load() == 0 || wireRight.esp.Load() == 0 || wireLeft.plaintext.Load() != 0 || wireRight.plaintext.Load() != 0 {
					t.Fatal("IMS transport escaped ESP selectors")
				}
			})
		}
	}
}
