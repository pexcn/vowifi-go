package ipsec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// DialSOCKS5TCP opens a SOCKS5 CONNECT stream. Domain targets are resolved by
// the proxy, never locally. A failed proxy never falls back to a direct dial.
// The proxy's own hostname, if supplied instead of an IP, uses host resolution.
func DialSOCKS5TCP(ctx context.Context, proxy, target, user, password string) (net.Conn, error) {
	conn, _, err := dialSOCKS5Command(ctx, proxy, target, user, password, 1)
	return conn, err
}

func dialSOCKS5Command(ctx context.Context, proxy, target, user, password string, command byte) (_ net.Conn, _ []byte, err error) {
	proxy = strings.TrimSpace(proxy)
	host, port, err := net.SplitHostPort(proxy)
	p, portErr := strconv.Atoi(port)
	if err != nil || host == "" || portErr != nil || p < 1 || p > 65535 {
		return nil, nil, errors.New("invalid SOCKS5 proxy address")
	}
	if len(user) > 255 || len(password) > 255 || password != "" && user == "" {
		return nil, nil, errors.New("invalid SOCKS credentials")
	}
	address := []byte{1, 0, 0, 0, 0, 0, 0}
	if command == 1 {
		address, err = socksAddress(target)
		if err != nil {
			return nil, nil, err
		}
	}
	tcp, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, nil, err
	}
	success := false
	stop := context.AfterFunc(ctx, func() { _ = tcp.Close() })
	defer stop()
	defer func() {
		if !success {
			_ = tcp.Close()
			if ctx.Err() != nil {
				err = ctx.Err()
			}
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	if t, ok := ctx.Deadline(); ok && t.Before(deadline) {
		deadline = t
	}
	if err = tcp.SetDeadline(deadline); err != nil {
		return nil, nil, err
	}
	method := byte(0)
	if user != "" || password != "" {
		method = 2
	}
	if _, err = tcp.Write([]byte{5, 1, method}); err != nil {
		return nil, nil, err
	}
	b := make([]byte, 2)
	if _, err = io.ReadFull(tcp, b); err != nil {
		return nil, nil, err
	}
	if b[0] != 5 || b[1] != method {
		return nil, nil, errors.New("SOCKS proxy did not negotiate requested authentication")
	}
	if method == 2 {
		auth := append([]byte{1, byte(len(user))}, []byte(user)...)
		auth = append(auth, byte(len(password)))
		auth = append(auth, []byte(password)...)
		if _, err = tcp.Write(auth); err != nil {
			return nil, nil, err
		}
		if _, err = io.ReadFull(tcp, b); err != nil {
			return nil, nil, err
		}
		if b[0] != 1 || b[1] != 0 {
			return nil, nil, errors.New("SOCKS authentication failed")
		}
	}
	if _, err = tcp.Write(append([]byte{5, command, 0}, address...)); err != nil {
		return nil, nil, err
	}
	head := make([]byte, 3)
	if _, err = io.ReadFull(tcp, head); err != nil {
		return nil, nil, err
	}
	if head[0] != 5 || head[1] != 0 || head[2] != 0 {
		return nil, nil, fmt.Errorf("SOCKS command %d rejected: %x", command, head)
	}
	bound, err := readSocksAddress(tcp)
	if err != nil {
		return nil, nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err = tcp.SetDeadline(time.Time{}); err != nil {
		return nil, nil, err
	}
	success = true
	return tcp, bound, nil
}
