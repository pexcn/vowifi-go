package ims

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// startSecureServer binds the terminal's protected server port. The client
// connection cannot receive network-initiated SIP requests on this second pair.
func (s *Service) startSecureServer(ctx context.Context, client, server SecurityParameters, remoteHost string) error {
	s.mu.Lock()
	c := s.conn
	if c == nil || s.closed {
		s.mu.Unlock()
		return ErrNotReady
	}
	localHost, _, err := net.SplitHostPort(c.LocalAddr().String())
	if err != nil {
		s.mu.Unlock()
		return err
	}
	local := net.JoinHostPort(localHost, strconv.Itoa(int(client.PortServer)))
	peer := net.JoinHostPort(remoteHost, strconv.Itoa(int(server.PortClient)))
	if s.serverUDP != nil || s.serverTCP != nil {
		if s.serverLocal != local {
			s.mu.Unlock()
			return errors.New("IMS server listener address changed during registration")
		}
		s.serverPeer = peer
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	if s.cfg.Transport == "udp" {
		if s.cfg.ListenPacket == nil {
			return errors.New("IMS protected UDP server requires an injected tunnel packet listener")
		}
		pc, err := s.cfg.ListenPacket(ctx, "udp", local)
		if err != nil {
			return err
		}
		if pc == nil {
			return errors.New("IMS packet listener returned nil")
		}
		if !sameEndpoint(pc.LocalAddr(), local) {
			pc.Close()
			return fmt.Errorf("IMS packet listener did not bind %s", local)
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			pc.Close()
			return context.Canceled
		}
		s.serverUDP, s.serverLocal, s.serverPeer = pc, local, peer
		s.wg.Add(1)
		s.mu.Unlock()
		go s.serveSecurePackets(pc)
		return nil
	}
	if s.cfg.ListenTCP == nil {
		return errors.New("IMS protected TCP server requires an injected tunnel TCP listener")
	}
	listener, err := s.cfg.ListenTCP(ctx, "tcp", local)
	if err != nil {
		return err
	}
	if listener == nil {
		return errors.New("IMS TCP listener returned nil")
	}
	if !sameEndpoint(listener.Addr(), local) {
		listener.Close()
		return fmt.Errorf("IMS TCP listener did not bind %s", local)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		listener.Close()
		return context.Canceled
	}
	s.serverTCP, s.serverLocal, s.serverPeer = listener, local, peer
	s.serverConns = make(map[net.Conn]struct{})
	s.wg.Add(1)
	s.mu.Unlock()
	go s.serveSecureTCP(listener)
	return nil
}
func sameEndpoint(addr net.Addr, expected string) bool {
	if addr == nil {
		return false
	}
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	wantHost, wantPort, err := net.SplitHostPort(expected)
	if err != nil || port != wantPort {
		return false
	}
	a, b := net.ParseIP(host), net.ParseIP(wantHost)
	return a != nil && b != nil && a.Equal(b)
}
func (s *Service) isServerPeer(addr net.Addr) bool {
	s.mu.Lock()
	expected := s.serverPeer
	s.mu.Unlock()
	return sameEndpoint(addr, expected)
}
func (s *Service) serverFailure(err error) {
	s.mu.Lock()
	active := !s.closed && s.ctx != nil && s.ctx.Err() == nil
	cancel := s.cancel
	s.mu.Unlock()
	if active {
		s.setReady(false, err)
		cancel()
	}
}
func (s *Service) serveSecurePackets(pc net.PacketConn) {
	defer s.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			s.serverFailure(fmt.Errorf("IMS protected UDP server: %w", err))
			return
		}
		if !s.isServerPeer(from) {
			continue
		}
		if bytes.Equal(buf[:n], []byte("\r\n")) || bytes.Equal(buf[:n], []byte("\r\n\r\n")) {
			continue
		}
		m, err := readMessage(bufio.NewReader(bytes.NewReader(buf[:n])))
		if err != nil {
			continue
		}
		// Keep each response on server-s -> peer client-c, including retransmits.
		m.reply = func(data []byte) error {
			s.writeMu.Lock()
			defer s.writeMu.Unlock()
			if err := pc.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return err
			}
			n, err := pc.WriteTo(data, from)
			if err == nil && n != len(data) {
				return io.ErrShortWrite
			}
			return err
		}
		s.dispatch(m)
	}
}
func (s *Service) serveSecureTCP(listener net.Listener) {
	defer s.wg.Done()
	for {
		c, err := listener.Accept()
		if err != nil {
			s.serverFailure(fmt.Errorf("IMS protected TCP server: %w", err))
			return
		}
		if !s.isServerPeer(c.RemoteAddr()) {
			c.Close()
			continue
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			c.Close()
			return
		}
		s.serverConns[c] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go s.readSecureTCP(c)
	}
}
func (s *Service) readSecureTCP(c net.Conn) {
	defer s.wg.Done()
	defer func() { c.Close(); s.mu.Lock(); delete(s.serverConns, c); s.mu.Unlock() }()
	r := bufio.NewReader(c)
	for {
		m, err := readMessage(r)
		if err != nil {
			return
		}
		if !s.isServerPeer(c.RemoteAddr()) {
			return
		}
		m.reply = func(data []byte) error {
			s.writeMu.Lock()
			defer s.writeMu.Unlock()
			if err := c.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return err
			}
			n, err := c.Write(data)
			if err == nil && n != len(data) {
				return io.ErrShortWrite
			}
			return err
		}
		s.dispatch(m)
	}
}
