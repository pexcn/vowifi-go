package ipsec

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DatagramConn carries exactly one peer's UDP datagrams. Read must honor context.
type DatagramConn interface {
	Read(context.Context) ([]byte, error)
	Write(context.Context, []byte) error
	Close() error
}
type udpConn struct {
	conn                                  *net.UDPConn
	writeMu                               sync.Mutex
	peer                                  *net.UDPAddr
	control                               net.Conn
	relayHeader                           []byte
	once                                  sync.Once
	received, peerRejected, socksRejected atomic.Uint64
	lastSOCKSRejection                    string // guarded by writeMu
}

func DialUDP(ctx context.Context, addr string) (DatagramConn, error) {
	return DialUDPFrom(ctx, "", addr)
}

// DialUDPFrom binds a new path without altering an existing socket.
func DialUDPFrom(ctx context.Context, local, addr string) (DatagramConn, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	peer, e := net.ResolveUDPAddr("udp", addr)
	if e != nil {
		return nil, e
	}
	network := "udp4"
	if peer.IP.To4() == nil {
		network = "udp6"
	}
	var bind *net.UDPAddr
	if local != "" {
		bind, e = net.ResolveUDPAddr(network, net.JoinHostPort(local, "0"))
		if e != nil {
			return nil, e
		}
	}
	u, e := net.ListenUDP(network, bind)
	if e != nil {
		return nil, e
	}
	return &udpConn{conn: u, peer: peer}, nil
}

// PeerSwitcher changes the NAT-T destination without changing the local UDP socket.
type PeerSwitcher interface{ SetPeer(string) error }

func (c *udpConn) SetPeer(addr string) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.control != nil {
		a, e := socksAddress(addr)
		if e != nil {
			return e
		}
		c.relayHeader = append([]byte{0, 0, 0}, a...)
		return nil
	}
	p, e := net.ResolveUDPAddr("udp", addr)
	if e != nil {
		return e
	}
	c.peer = p
	return nil
}
func (c *udpConn) LocalAddr() net.Addr { return c.conn.LocalAddr() }
func (c *udpConn) Read(ctx context.Context) ([]byte, error) {
	b := make([]byte, 65535)
	for {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		deadline := time.Now().Add(200 * time.Millisecond)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		c.conn.SetReadDeadline(deadline)
		n, from, e := c.conn.ReadFromUDP(b)
		if ne, ok := e.(net.Error); ok && ne.Timeout() {
			continue
		}
		if e != nil {
			return nil, e
		}
		c.received.Add(1)
		c.writeMu.Lock()
		peer := *c.peer
		header := append([]byte{}, c.relayHeader...)
		c.writeMu.Unlock()
		if !from.IP.Equal(peer.IP) || from.Port != peer.Port {
			c.peerRejected.Add(1)
			continue
		}
		p := b[:n]
		if c.control != nil {
			var err error
			p, err = decodeSOCKS(p, header)
			if err != nil {
				c.socksRejected.Add(1)
				c.writeMu.Lock()
				c.lastSOCKSRejection = err.Error()
				c.writeMu.Unlock()
				continue
			}
		}
		return append([]byte{}, p...), nil
	}
}

// ReadDiagnostics reports counters and codec errors, never payloads or credentials.
func (c *udpConn) ReadDiagnostics() string {
	c.writeMu.Lock()
	last := c.lastSOCKSRejection
	c.writeMu.Unlock()
	return fmt.Sprintf("udp_received=%d, udp_peer_rejected=%d, socks_rejected=%d, last_socks_rejection=%q", c.received.Load(), c.peerRejected.Load(), c.socksRejected.Load(), last)
}
func (c *udpConn) Write(ctx context.Context, b []byte) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.conn.SetWriteDeadline(deadline)
	if c.control != nil {
		b = append(append([]byte{}, c.relayHeader...), b...)
	}
	n, e := c.conn.WriteToUDP(b, c.peer)
	if e == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return e
}
func (c *udpConn) Close() error {
	var e error
	c.once.Do(func() {
		e = c.conn.Close()
		if c.control != nil {
			c.control.Close()
		}
	})
	return e
}
func socksAddress(addr string) ([]byte, error) {
	h, p, e := net.SplitHostPort(addr)
	if e != nil {
		return nil, e
	}
	port, e := strconv.Atoi(p)
	if e != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid port")
	}
	var out []byte
	if ip := net.ParseIP(h); ip != nil {
		if v := ip.To4(); v != nil {
			out = append([]byte{1}, v...)
		} else {
			out = append([]byte{4}, ip.To16()...)
		}
	} else {
		if len(h) > 255 || len(h) == 0 {
			return nil, errors.New("invalid SOCKS domain")
		}
		out = append([]byte{3, byte(len(h))}, []byte(h)...)
	}
	return binary.BigEndian.AppendUint16(out, uint16(port)), nil
}
func readSocksAddress(r io.Reader) ([]byte, error) {
	b := make([]byte, 1)
	if _, e := io.ReadFull(r, b); e != nil {
		return nil, e
	}
	n := 0
	switch b[0] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		x := make([]byte, 1)
		if _, e := io.ReadFull(r, x); e != nil {
			return nil, e
		}
		b = append(b, x[0])
		n = int(x[0])
	default:
		return nil, errors.New("invalid SOCKS address type")
	}
	tail := make([]byte, n+2)
	if _, e := io.ReadFull(r, tail); e != nil {
		return nil, e
	}
	return append(b, tail...), nil
}
func socksString(b []byte) (string, error) {
	if len(b) < 1 {
		return "", errors.New("invalid SOCKS address")
	}
	var h string
	switch b[0] {
	case 1:
		if len(b) != 7 {
			return "", errors.New("invalid SOCKS IPv4")
		}
		h = net.IP(b[1:5]).String()
	case 4:
		if len(b) != 19 {
			return "", errors.New("invalid SOCKS IPv6")
		}
		h = net.IP(b[1:17]).String()
	case 3:
		if len(b) < 2 || len(b) != int(b[1])+4 {
			return "", errors.New("invalid SOCKS name")
		}
		h = string(b[2 : len(b)-2])
	default:
		return "", errors.New("invalid SOCKS address")
	}
	return net.JoinHostPort(h, strconv.Itoa(int(binary.BigEndian.Uint16(b[len(b)-2:])))), nil
}
func decodeSOCKS(b, want []byte) ([]byte, error) {
	if len(b) < 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return nil, errors.New("fragmented/invalid SOCKS datagram")
	}
	n := 0
	switch b[3] {
	case 1:
		n = 10
	case 4:
		n = 22
	case 3:
		if len(b) < 5 {
			return nil, errors.New("truncated SOCKS datagram")
		}
		n = 7 + int(b[4])
	default:
		return nil, errors.New("invalid SOCKS datagram address")
	}
	if n > len(b) {
		return nil, errors.New("truncated SOCKS datagram")
	}
	source, e := socksString(b[3:n])
	if e != nil {
		return nil, e
	}
	dest, e := socksString(want[3:])
	if e != nil || !strings.EqualFold(source, dest) {
		return nil, errors.New("unexpected SOCKS UDP source")
	}
	return b[n:], nil
}

// DialSOCKS5 performs real UDP ASSOCIATE and keeps its TCP control channel alive.
func DialSOCKS5(ctx context.Context, proxy, target, user, password string) (DatagramConn, error) {
	d := net.Dialer{}
	tcp, e := d.DialContext(ctx, "tcp", proxy)
	if e != nil {
		return nil, e
	}
	success := false
	defer func() {
		if !success {
			tcp.Close()
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	if t, ok := ctx.Deadline(); ok && t.Before(deadline) {
		deadline = t
	}
	tcp.SetDeadline(deadline)
	methods := []byte{5, 1, 0}
	if user != "" || password != "" {
		methods = []byte{5, 1, 2}
	}
	if _, e = tcp.Write(methods); e != nil {
		return nil, e
	}
	b := make([]byte, 2)
	if _, e = io.ReadFull(tcp, b); e != nil {
		return nil, e
	}
	if b[0] != 5 {
		return nil, errors.New("SOCKS version mismatch")
	}
	switch b[1] {
	case 0:
		if len(methods) == 3 && methods[2] != 0 {
			return nil, errors.New("proxy did not negotiate requested authentication")
		}
	case 2:
		if len(user) > 255 || len(password) > 255 || user == "" {
			return nil, errors.New("invalid SOCKS credentials")
		}
		req := append([]byte{1, byte(len(user))}, []byte(user)...)
		req = append(req, byte(len(password)))
		req = append(req, []byte(password)...)
		if _, e = tcp.Write(req); e != nil {
			return nil, e
		}
		if _, e = io.ReadFull(tcp, b); e != nil {
			return nil, e
		}
		if b[0] != 1 || b[1] != 0 {
			return nil, errors.New("SOCKS authentication failed")
		}
	default:
		return nil, errors.New("SOCKS method rejected")
	}
	if _, e = tcp.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); e != nil {
		return nil, e
	}
	head := make([]byte, 3)
	if _, e = io.ReadFull(tcp, head); e != nil {
		return nil, e
	}
	if head[0] != 5 || head[1] != 0 || head[2] != 0 {
		return nil, fmt.Errorf("SOCKS UDP ASSOCIATE rejected: %x", head)
	}
	relay, e := readSocksAddress(tcp)
	if e != nil {
		return nil, e
	}
	relayAddr, e := socksString(relay)
	if e != nil {
		return nil, e
	}
	h, p, e := net.SplitHostPort(relayAddr)
	if e != nil {
		return nil, e
	}
	if ip := net.ParseIP(h); ip != nil && ip.IsUnspecified() {
		ph, _, _ := net.SplitHostPort(proxy)
		relayAddr = net.JoinHostPort(ph, p)
	}
	ud, e := DialUDP(ctx, relayAddr)
	if e != nil {
		return nil, e
	}
	u := ud.(*udpConn)
	targetBytes, e := socksAddress(target)
	if e != nil {
		u.Close()
		return nil, e
	}
	u.control = tcp
	u.relayHeader = append([]byte{0, 0, 0}, targetBytes...)
	tcp.SetDeadline(time.Time{})
	success = true
	go func() { var b [1]byte; _, _ = tcp.Read(b[:]); u.Close() }()
	return u, nil
}
