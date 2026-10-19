package media

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

type ListenPacketFunc func(context.Context, string, string) (net.PacketConn, error)
type Session struct {
	RTP, RTCP   net.PacketConn
	Local       Description
	mu          sync.RWMutex
	remote      Description
	codec       Codec
	remoteCodec Codec
	once        sync.Once
}

func NewSession(ctx context.Context, listen ListenPacketFunc, address string) (*Session, error) {
	ip := net.ParseIP(address)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || listen == nil {
		return nil, errors.New("media requires a tunnel address and packet listener")
	}
	network := "udp4"
	if ip.To4() == nil {
		network = "udp6"
	}
	rtp, e := listen(ctx, network, net.JoinHostPort(address, "0"))
	if e != nil {
		return nil, e
	}
	rtcp, e := listen(ctx, network, net.JoinHostPort(address, "0"))
	if e != nil {
		rtp.Close()
		return nil, e
	}
	port := func(c net.PacketConn) (int, error) {
		a, ok := c.LocalAddr().(*net.UDPAddr)
		if !ok || a.Port < 1 {
			return 0, errors.New("media listener returned non-UDP address")
		}
		return a.Port, nil
	}
	p, e := port(rtp)
	if e != nil {
		rtp.Close()
		rtcp.Close()
		return nil, e
	}
	q, e := port(rtcp)
	if e != nil {
		rtp.Close()
		rtcp.Close()
		return nil, e
	}
	return &Session{RTP: rtp, RTCP: rtcp, Local: Description{Address: ip, RTP: p, RTCP: q, Codecs: []Codec{{0, "PCMU", 8000, 1}, {8, "PCMA", 8000, 1}}, Direction: "sendrecv"}}, nil
}
func (s *Session) SetRemote(d Description) error {
	l, r, e := MatchCodec(s.Local.Codecs, d.Codecs)
	if e != nil {
		return e
	}
	if d.Address == nil || d.Address.IsUnspecified() || d.Address.IsMulticast() || d.RTP < 1 || d.RTP > 65535 || d.RTCP < 1 || d.RTCP > 65535 {
		return errors.New("invalid remote media")
	}
	s.mu.Lock()
	s.remote = d
	s.codec = l
	s.remoteCodec = r
	s.mu.Unlock()
	return nil
}
func (s *Session) Close() error {
	var e error
	s.once.Do(func() { e = errors.Join(s.RTP.Close(), s.RTCP.Close()) })
	return e
}
func (s *Session) endpoint(rtcp bool) (*net.UDPAddr, Codec, Codec, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	port := s.remote.RTP
	if rtcp {
		port = s.remote.RTCP
	}
	return &net.UDPAddr{IP: s.remote.Address, Port: port}, s.codec, s.remoteCodec, s.remote.Direction
}
func validRTP(b []byte) bool {
	if len(b) < 12 || b[0]>>6 != 2 {
		return false
	}
	h := 12 + 4*int(b[0]&15)
	if len(b) < h {
		return false
	}
	if b[0]&16 != 0 {
		if len(b) < h+4 {
			return false
		}
		h += 4 + 4*int(binary.BigEndian.Uint16(b[h+2:h+4]))
		if h > len(b) {
			return false
		}
	}
	if b[0]&32 != 0 {
		padding := int(b[len(b)-1])
		if padding == 0 || padding > len(b)-h {
			return false
		}
	}
	return true
}
func validRTCP(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for len(b) > 0 {
		if len(b) < 4 || b[0]>>6 != 2 || b[1] < 192 || b[1] > 223 {
			return false
		}
		n := (int(binary.BigEndian.Uint16(b[2:4])) + 1) * 4
		if n > len(b) {
			return false
		}
		b = b[n:]
	}
	return true
}
func (s *Session) read(ctx context.Context, rtcp bool, fn func([]byte) error) error {
	conn := s.RTP
	if rtcp {
		conn = s.RTCP
	}
	b := make([]byte, 65536)
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, src, e := conn.ReadFrom(b)
		if e != nil {
			if nerr, ok := e.(net.Error); ok && nerr.Timeout() {
				continue
			}
			return e
		}
		want, _, codec, _ := s.endpoint(rtcp)
		actual, ok := src.(*net.UDPAddr)
		if !ok || !actual.IP.Equal(want.IP) || actual.Port != want.Port {
			continue
		}
		if rtcp {
			if !validRTCP(b[:n]) {
				continue
			}
		} else {
			if !validRTP(b[:n]) || b[1]&127 != codec.Payload {
				continue
			}
		}
		if e := fn(b[:n]); e != nil {
			return e
		}
	}
}

// RelayTo sends packets from this peer to the other peer. RTP payload types are
// remapped only when both endpoints negotiated the exact same codec.
func (s *Session) RelayTo(ctx context.Context, dst *Session) error {
	_, _, from, _ := s.endpoint(false)
	_, _, to, _ := dst.endpoint(false)
	if _, _, e := MatchCodec([]Codec{from}, []Codec{to}); e != nil {
		return e
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 2)
	for _, isRTCP := range []bool{false, true} {
		go func(rtcp bool) {
			errs <- s.read(ctx, rtcp, func(b []byte) error {
				addr, _, codec, _ := dst.endpoint(rtcp)
				conn := dst.RTP
				if rtcp {
					conn = dst.RTCP
				} else {
					b[1] = (b[1] & 128) | codec.Payload
				}
				_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
				_, e := conn.WriteTo(b, addr)
				return e
			})
		}(isRTCP)
	}
	e := <-errs
	cancel()
	<-errs
	return e
}

// RunSilentCall exchanges RTP G.711 silence and compound RTCP reports. It is the
// explicit media behavior of SimulateCall, not a substitute for audio bridging.
func (s *Session) RunSilentCall(ctx context.Context) error {
	remote, local, codec, direction := s.endpoint(false)
	if local.Rate != 8000 || codec.Rate != 8000 || codec.Name != "PCMU" && codec.Name != "PCMA" {
		return errors.New("simulated call requires G.711")
	}
	if remote.IP == nil {
		return errors.New("media peer not negotiated")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 2)
	for _, isRTCP := range []bool{false, true} {
		go func(rtcp bool) { errs <- s.read(ctx, rtcp, func([]byte) error { return nil }) }(isRTCP)
	}
	defer func() { cancel(); <-errs; <-errs }()
	var seed [10]byte
	if _, e := rand.Read(seed[:]); e != nil {
		return e
	}
	seq := binary.BigEndian.Uint16(seed[:2])
	stamp := binary.BigEndian.Uint32(seed[2:6])
	ssrc := binary.BigEndian.Uint32(seed[6:])
	var packets, octets uint32
	packet := make([]byte, 172)
	packet[0] = 0x80
	packet[1] = codec.Payload
	binary.BigEndian.PutUint32(packet[8:12], ssrc)
	fill := byte(0xff)
	if codec.Name == "PCMA" {
		fill = 0xd5
	}
	for i := 12; i < len(packet); i++ {
		packet[i] = fill
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	rtcpTick := time.NewTicker(5 * time.Second)
	defer rtcpTick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-errs:
			errs <- e
			return e
		case <-ticker.C:
			if direction == "sendonly" || direction == "inactive" {
				continue
			}
			binary.BigEndian.PutUint16(packet[2:4], seq)
			binary.BigEndian.PutUint32(packet[4:8], stamp)
			seq++
			stamp += 160
			_ = s.RTP.SetWriteDeadline(time.Now().Add(time.Second))
			if _, e := s.RTP.WriteTo(packet, remote); e != nil {
				return fmt.Errorf("RTP silence: %w", e)
			}
			packets++
			octets += uint32(len(packet) - 12)
		case <-rtcpTick.C:
			rr := rtcpReport(time.Now(), ssrc, stamp, packets, octets)
			addr, _, _, _ := s.endpoint(true)
			_ = s.RTCP.SetWriteDeadline(time.Now().Add(time.Second))
			if _, e := s.RTCP.WriteTo(rr, addr); e != nil {
				return e
			}
		}
	}
}

// Each RFC 3550 compound report includes an SDES CNAME. Senders report their
// NTP/RTP clock correspondence and counters; receive-only sessions send an RR.
func rtcpReport(now time.Time, ssrc, stamp, packets, octets uint32) []byte {
	size, kind := 8, byte(201)
	if packets != 0 {
		size, kind = 28, 200
	}
	report := make([]byte, size)
	report[0], report[1] = 0x80, kind
	binary.BigEndian.PutUint16(report[2:4], uint16(size/4-1))
	binary.BigEndian.PutUint32(report[4:8], ssrc)
	if packets != 0 {
		binary.BigEndian.PutUint32(report[8:12], uint32(now.Unix()+2208988800))
		binary.BigEndian.PutUint32(report[12:16], uint32(uint64(now.Nanosecond())*(1<<32)/1_000_000_000))
		binary.BigEndian.PutUint32(report[16:20], stamp)
		binary.BigEndian.PutUint32(report[20:24], packets)
		binary.BigEndian.PutUint32(report[24:28], octets)
	}
	cname := fmt.Sprintf("%08x@vowifi", ssrc)
	n := (8 + 2 + len(cname) + 1 + 3) &^ 3
	sdes := make([]byte, n)
	sdes[0], sdes[1] = 0x81, 202
	binary.BigEndian.PutUint16(sdes[2:4], uint16(n/4-1))
	binary.BigEndian.PutUint32(sdes[4:8], ssrc)
	sdes[8], sdes[9] = 1, byte(len(cname))
	copy(sdes[10:], cname)
	return append(report, sdes...)
}
