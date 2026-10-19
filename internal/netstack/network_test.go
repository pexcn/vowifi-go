package netstack

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

type memoryEndpoint struct{ in, out chan []byte }

func (e memoryEndpoint) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case b := <-e.in:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (e memoryEndpoint) WritePacket(ctx context.Context, b []byte) error {
	select {
	case e.out <- append([]byte(nil), b...):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func peers(t *testing.T, ip1, ip2 string) (*Network, *Network) {
	t.Helper()
	a, b := make(chan []byte, 256), make(chan []byte, 256)
	n1, e := New(context.Background(), memoryEndpoint{a, b}, Config{LocalAddresses: []netip.Addr{netip.MustParseAddr(ip1)}})
	if e != nil {
		t.Fatal(e)
	}
	n2, e := New(context.Background(), memoryEndpoint{b, a}, Config{LocalAddresses: []netip.Addr{netip.MustParseAddr(ip2)}})
	if e != nil {
		n1.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { n1.Close(); n2.Close() })
	return n1, n2
}
func TestTCPAndUDPThroughTunnel(t *testing.T) {
	for _, ips := range [][2]string{{"10.8.0.1", "10.8.0.2"}, {"2001:db8::1", "2001:db8::2"}} {
		t.Run(ips[0], func(t *testing.T) {
			a, b := peers(t, ips[0], ips[1])
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			l, e := b.ListenTCP(ctx, &net.TCPAddr{IP: net.ParseIP(ips[1]), Port: 5060})
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			done := make(chan error, 1)
			go func() {
				c, e := l.Accept()
				if e != nil {
					done <- e
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(2 * time.Second))
				p := make([]byte, 4)
				_, e = io.ReadFull(c, p)
				if e == nil {
					_, e = c.Write(p)
				}
				done <- e
			}()
			c, e := a.DialContext(ctx, "tcp", net.JoinHostPort(ips[1], "5060"))
			if e != nil {
				t.Fatal(e)
			}
			c.SetDeadline(time.Now().Add(2 * time.Second))
			if _, e = c.Write([]byte("test")); e != nil {
				t.Fatal(e)
			}
			p := make([]byte, 4)
			if _, e = io.ReadFull(c, p); e != nil || string(p) != "test" {
				t.Fatalf("TCP reply %q %v", p, e)
			}
			c.Close()
			if e = <-done; e != nil {
				t.Fatal(e)
			}
			u, e := b.ListenPacket(ctx, "udp", net.JoinHostPort(ips[1], "5061"))
			if e != nil {
				t.Fatal(e)
			}
			defer u.Close()
			u.SetDeadline(time.Now().Add(2 * time.Second))
			cu, e := a.DialContext(ctx, "udp", net.JoinHostPort(ips[1], "5061"))
			if e != nil {
				t.Fatal(e)
			}
			defer cu.Close()
			cu.SetDeadline(time.Now().Add(2 * time.Second))
			if _, e = cu.Write([]byte("sip")); e != nil {
				t.Fatal(e)
			}
			p = make([]byte, 99)
			n, from, e := u.ReadFrom(p)
			if e != nil || string(p[:n]) != "sip" {
				t.Fatalf("UDP request %q %v", p[:n], e)
			}
			u.WriteTo(p[:n], from)
			n, e = cu.Read(p)
			if e != nil || string(p[:n]) != "sip" {
				t.Fatalf("UDP reply %q %v", p[:n], e)
			}
		})
	}
}
func TestCancelDialAndNetwork(t *testing.T) {
	a, _ := peers(t, "10.9.0.1", "10.9.0.2")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, e := a.DialContext(ctx, "tcp", "10.9.0.99:5060")
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatalf("want context deadline: %v", e)
	}
	a.Close()
	select {
	case <-a.Done():
	case <-time.After(time.Second):
		t.Fatal("Close did not stop tunnel")
	}
	_, e = a.DialContext(context.Background(), "udp", "10.9.0.2:5060")
	if e == nil {
		t.Fatal("closed network dial succeeded")
	}
}
func TestMalformedPacketAndNoDNSFallback(t *testing.T) {
	a, b := peers(t, "10.10.0.1", "10.10.0.2")
	for _, p := range [][]byte{nil, {0x45}, {0x60, 0, 0}, {0xf0}, make([]byte, 40)} {
		a.endpoint.(memoryEndpoint).in <- p
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, e := b.DialContext(ctx, "udp", "pcscf.invalid:5060")
	if e == nil {
		t.Fatal("unexpected DNS resolution without tunnel DNS")
	}
	if a.Err() != nil {
		t.Fatalf("malformed traffic killed network: %v", a.Err())
	}
}

func TestDNSUsesTunnel(t *testing.T) {
	a, b := make(chan []byte, 256), make(chan []byte, 256)
	client, e := New(context.Background(), memoryEndpoint{a, b}, Config{LocalAddresses: []netip.Addr{netip.MustParseAddr("10.11.0.1")}, DNS: []netip.Addr{netip.MustParseAddr("10.11.0.2")}})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	server, e := New(context.Background(), memoryEndpoint{b, a}, Config{LocalAddresses: []netip.Addr{netip.MustParseAddr("10.11.0.2")}})
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dns, e := server.ListenPacket(ctx, "udp4", "10.11.0.2:53")
	if e != nil {
		t.Fatal(e)
	}
	defer dns.Close()
	dns.SetDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() {
		packet := make([]byte, 1500)
		n, from, e := dns.ReadFrom(packet)
		if e != nil {
			done <- e
			return
		}
		if n < 12 {
			done <- errors.New("short DNS query")
			return
		}
		// Retain only the question; discard the query's optional EDNS record.
		end := 12
		for end < n && packet[end] != 0 {
			end += int(packet[end]) + 1
		}
		end += 5
		if end > n {
			done <- errors.New("malformed DNS question")
			return
		}
		packet = packet[:end]
		packet[2], packet[3] = 0x81, 0x80
		packet[6], packet[7] = 0, 1
		packet[8], packet[9], packet[10], packet[11] = 0, 0, 0, 0
		packet = append(packet, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 11, 0, 2)
		_, e = dns.WriteTo(packet, from)
		done <- e
	}()
	conn, e := client.DialContext(ctx, "udp4", "pcscf.example:5060")
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	if conn.RemoteAddr().String() != "10.11.0.2:5060" {
		t.Fatal(conn.RemoteAddr())
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
