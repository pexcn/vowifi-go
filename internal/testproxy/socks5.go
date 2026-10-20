// Package testproxy supplies loopback-only SOCKS5 fixtures for transport tests.
package testproxy

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

func Start(t testing.TB, user, password string, handle func(net.Conn, string)) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	clients := make(map[net.Conn]bool)
	closed := false
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				conn.Close()
				return
			}
			clients[conn] = true
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				defer func() { mu.Lock(); delete(clients, conn); mu.Unlock() }()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				target, err := handshake(conn, user, password)
				if err == nil {
					handle(conn, target)
				}
			}()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		closed = true
		for conn := range clients {
			conn.Close()
		}
		mu.Unlock()
		listener.Close()
		wg.Wait()
	})
	return listener.Addr().String()
}

func handshake(c net.Conn, user, password string) (string, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return "", err
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", err
	}
	method := byte(0)
	if user != "" || password != "" {
		method = 2
	}
	if _, err := c.Write([]byte{5, method}); err != nil {
		return "", err
	}
	if method == 2 {
		if _, err := io.ReadFull(c, head); err != nil {
			return "", err
		}
		u := make([]byte, int(head[1]))
		if _, err := io.ReadFull(c, u); err != nil {
			return "", err
		}
		if _, err := io.ReadFull(c, head[:1]); err != nil {
			return "", err
		}
		p := make([]byte, int(head[0]))
		if _, err := io.ReadFull(c, p); err != nil {
			return "", err
		}
		if string(u) != user || string(p) != password {
			c.Write([]byte{1, 1})
			return "", io.ErrUnexpectedEOF
		}
		if _, err := c.Write([]byte{1, 0}); err != nil {
			return "", err
		}
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return "", err
	}
	if req[0] != 5 || req[1] != 1 || req[2] != 0 {
		return "", io.ErrUnexpectedEOF
	}
	n := 0
	switch req[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		if _, err := io.ReadFull(c, head[:1]); err != nil {
			return "", err
		}
		n = int(head[0])
	default:
		return "", io.ErrUnexpectedEOF
	}
	address := make([]byte, n+2)
	if _, err := io.ReadFull(c, address); err != nil {
		return "", err
	}
	host := string(address[:n])
	if req[3] != 3 {
		host = net.IP(address[:n]).String()
	}
	_, err := c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(address[n:])))), err
}
