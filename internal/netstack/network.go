// Package netstack provides TCP, UDP and DNS entirely inside a packet tunnel.
// It never adds host routes or falls back to the host network for IMS traffic.
package netstack

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type PacketEndpoint interface {
	ReadPacket(context.Context) ([]byte, error)
	WritePacket(context.Context, []byte) error
}
type Config struct {
	LocalAddresses []netip.Addr
	DNS            []netip.Addr
	MTU            uint32
}
type Network struct {
	stack    *stack.Stack
	link     *channel.Endpoint
	endpoint PacketEndpoint
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	err      error
	resolver *net.Resolver
	local    []netip.Addr
}

func New(ctx context.Context, endpoint PacketEndpoint, cfg Config) (*Network, error) {
	if endpoint == nil {
		return nil, errors.New("netstack: missing packet endpoint")
	}
	if len(cfg.LocalAddresses) == 0 {
		return nil, errors.New("netstack: no assigned IP address")
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1400
	}
	if cfg.MTU < 1280 || cfg.MTU > 65535 {
		return nil, errors.New("netstack: MTU must be between 1280 and 65535")
	}
	nctx, cancel := context.WithCancel(ctx)
	n := &Network{endpoint: endpoint, ctx: nctx, cancel: cancel, done: make(chan struct{}), local: append([]netip.Addr(nil), cfg.LocalAddresses...)}
	n.stack = stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	n.link = channel.New(256, cfg.MTU, "")
	fail := func(e error) (*Network, error) { n.link.Close(); n.stack.Close(); cancel(); return nil, e }
	if e := n.stack.CreateNIC(1, n.link); e != nil {
		return fail(fmt.Errorf("netstack NIC: %s", e))
	}
	var routes []tcpip.Route
	v4, v6 := false, false
	for _, a := range cfg.LocalAddresses {
		if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || a.Zone() != "" {
			return fail(fmt.Errorf("netstack: invalid assigned address %s", a))
		}
		a = a.Unmap()
		p := ipv6.ProtocolNumber
		if a.Is4() {
			p = ipv4.ProtocolNumber
			v4 = true
		} else {
			v6 = true
		}
		pa := tcpip.ProtocolAddress{Protocol: p, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice(a.AsSlice()), PrefixLen: a.BitLen()}}
		if e := n.stack.AddProtocolAddress(1, pa, stack.AddressProperties{}); e != nil {
			return fail(fmt.Errorf("netstack address: %s", e))
		}
	}
	if v4 {
		routes = append(routes, tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	}
	if v6 {
		routes = append(routes, tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	}
	n.stack.SetRouteTable(routes)
	dns := append([]netip.Addr(nil), cfg.DNS...)
	for _, a := range dns {
		if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() {
			return fail(errors.New("netstack: invalid DNS address"))
		}
	}
	var dnsAttempt atomic.Uint64
	n.resolver = &net.Resolver{PreferGo: true, StrictErrors: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		if len(dns) == 0 {
			return nil, errors.New("netstack: tunnel supplied no DNS servers")
		}
		// Resolver retries invoke Dial repeatedly; each call remains inside the tunnel.
		return n.dialIP(ctx, network, netip.AddrPortFrom(dns[(dnsAttempt.Add(1)-1)%uint64(len(dns))], 53), nil)
	}}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); n.receive() }()
	go func() { defer wg.Done(); n.transmit() }()
	go func() {
		<-n.ctx.Done()
		n.link.Close()
		n.stack.Close()
		wg.Wait()
		n.stack.Wait()
		close(n.done)
	}()
	return n, nil
}
func (n *Network) Done() <-chan struct{} { return n.done }
func (n *Network) Err() error            { n.mu.Lock(); defer n.mu.Unlock(); return n.err }
func (n *Network) fail(err error) {
	n.mu.Lock()
	if n.err == nil && n.ctx.Err() == nil {
		n.err = err
	}
	n.mu.Unlock()
	n.cancel()
}
func (n *Network) Close() error { n.once.Do(n.cancel); <-n.done; return nil }
func (n *Network) receive() {
	for {
		b, e := n.endpoint.ReadPacket(n.ctx)
		if e != nil {
			n.fail(fmt.Errorf("netstack receive: %w", e))
			return
		}
		p, ok := packetProtocol(b)
		if !ok {
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), b...))})
		n.link.InjectInbound(p, pkt)
		pkt.DecRef()
	}
}
func (n *Network) transmit() {
	for {
		pkt := n.link.ReadContext(n.ctx)
		if pkt == nil {
			return
		}
		v := pkt.ToView()
		b := append([]byte(nil), v.AsSlice()...)
		v.Release()
		pkt.DecRef()
		if e := n.endpoint.WritePacket(n.ctx, b); e != nil {
			n.fail(fmt.Errorf("netstack transmit (packet_length=%d): %w", len(b), e))
			return
		}
	}
}
func packetProtocol(b []byte) (tcpip.NetworkProtocolNumber, bool) {
	if len(b) < 1 {
		return 0, false
	}
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 || int(b[0]&15)*4 < 20 || int(b[0]&15)*4 > len(b) || int(binary.BigEndian.Uint16(b[2:4])) != len(b) {
			return 0, false
		}
		return ipv4.ProtocolNumber, true
	case 6:
		if len(b) < 40 || int(binary.BigEndian.Uint16(b[4:6]))+40 != len(b) {
			return 0, false
		}
		return ipv6.ProtocolNumber, true
	}
	return 0, false
}
func (n *Network) operationContext(ctx context.Context) (context.Context, func()) {
	c, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(n.ctx, cancel)
	return c, func() { stop(); cancel() }
}
func protocol(a netip.Addr) tcpip.NetworkProtocolNumber {
	if a.Unmap().Is4() {
		return ipv4.ProtocolNumber
	}
	return ipv6.ProtocolNumber
}
func full(a netip.AddrPort) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(a.Addr().Unmap().AsSlice()), Port: a.Port()}
}
func (n *Network) dialIP(ctx context.Context, network string, remote netip.AddrPort, local *netip.AddrPort) (net.Conn, error) {
	ctx, cancel := n.operationContext(ctx)
	defer cancel()
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	p := protocol(remote.Addr())
	r := full(remote)
	switch network {
	case "tcp", "tcp4", "tcp6":
		if local != nil {
			return gonet.DialTCPWithBind(ctx, n.stack, full(*local), r, p)
		}
		return gonet.DialContextTCP(ctx, n.stack, r, p)
	case "udp", "udp4", "udp6":
		var l *tcpip.FullAddress
		if local != nil {
			a := full(*local)
			l = &a
		}
		return gonet.DialUDP(n.stack, l, &r, p)
	}
	return nil, fmt.Errorf("netstack: unsupported network %q", network)
}
func (n *Network) resolve(ctx context.Context, network, address string) (netip.AddrPort, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return netip.AddrPort{}, e
	}
	num, e := strconv.ParseUint(port, 10, 16)
	if e != nil {
		return netip.AddrPort{}, fmt.Errorf("netstack: numeric port required: %w", e)
	}
	ip, e := netip.ParseAddr(host)
	if e == nil {
		ip = ip.Unmap()
		if strings.HasSuffix(network, "4") && !ip.Is4() || strings.HasSuffix(network, "6") && !ip.Is6() {
			return netip.AddrPort{}, errors.New("netstack: address family mismatch")
		}
		return netip.AddrPortFrom(ip, uint16(num)), nil
	}
	family := "ip"
	if strings.HasSuffix(network, "4") {
		family = "ip4"
	}
	if strings.HasSuffix(network, "6") {
		family = "ip6"
	}
	ips, e := n.resolver.LookupNetIP(ctx, family, host)
	if e != nil {
		return netip.AddrPort{}, e
	}
	for _, ip = range ips {
		for _, l := range n.local {
			if l.Unmap().Is4() == ip.Unmap().Is4() {
				return netip.AddrPortFrom(ip.Unmap(), uint16(num)), nil
			}
		}
	}
	return netip.AddrPort{}, errors.New("netstack: no address in an assigned address family")
}
func (n *Network) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ctx, cancel := n.operationContext(ctx)
	defer cancel()
	r, e := n.resolve(ctx, network, address)
	if e != nil {
		return nil, e
	}
	return n.dialIP(ctx, network, r, nil)
}
func (n *Network) DialUDP(ctx context.Context, local, remote *net.UDPAddr) (*gonet.UDPConn, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := n.ctx.Err(); e != nil {
		return nil, e
	}
	var l, r *tcpip.FullAddress
	p := ipv4.ProtocolNumber
	if remote != nil {
		a := remote.AddrPort()
		p = protocol(a.Addr())
		f := full(a)
		r = &f
	}
	if local != nil {
		a := local.AddrPort()
		if !a.Addr().IsValid() {
			if p == ipv4.ProtocolNumber {
				a = netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(local.Port))
			} else {
				a = netip.AddrPortFrom(netip.IPv6Unspecified(), uint16(local.Port))
			}
		}
		if remote == nil {
			p = protocol(a.Addr())
		}
		f := full(a)
		l = &f
	}
	return gonet.DialUDP(n.stack, l, r, p)
}
func (n *Network) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	if network != "udp" && network != "udp4" && network != "udp6" {
		return nil, fmt.Errorf("netstack: unsupported packet network %q", network)
	}
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	if host == "" {
		host = "0.0.0.0"
		if network == "udp6" {
			host = "::"
		}
	}
	a, e := netip.ParseAddrPort(net.JoinHostPort(host, port))
	if e != nil {
		return nil, e
	}
	return n.DialUDP(ctx, net.UDPAddrFromAddrPort(a), nil)
}
func (n *Network) ListenTCP(ctx context.Context, local *net.TCPAddr) (net.Listener, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := n.ctx.Err(); e != nil {
		return nil, e
	}
	if local == nil {
		return nil, errors.New("netstack: TCP listen address required")
	}
	a := local.AddrPort()
	if !a.Addr().IsValid() {
		a = netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(local.Port))
	}
	return gonet.ListenTCP(n.stack, full(a), protocol(a.Addr()))
}

// DialContextWithLocalPort binds the client port negotiated by IMS ipsec-3gpp.
func (n *Network) DialContextWithLocalPort(ctx context.Context, network, address string, localIP netip.Addr, port uint16) (net.Conn, error) {
	ctx, cancel := n.operationContext(ctx)
	defer cancel()
	remote, err := n.resolve(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if !localIP.IsValid() || localIP.Unmap().Is4() != remote.Addr().Unmap().Is4() {
		return nil, errors.New("netstack: invalid bound local address family")
	}
	local := netip.AddrPortFrom(localIP.Unmap(), port)
	return n.dialIP(ctx, network, remote, &local)
}
