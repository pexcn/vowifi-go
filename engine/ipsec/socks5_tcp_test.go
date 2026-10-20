package ipsec

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/iniwex5/vowifi-go/internal/testproxy"
)

func TestSOCKS5TCPRemoteDomainAndAuthentication(t *testing.T) {
	targets := make(chan string, 1)
	proxy := testproxy.Start(t, "user", "password", func(c net.Conn, target string) {
		targets <- target
		io.Copy(c, c)
	})
	c, err := DialSOCKS5TCP(t.Context(), proxy, "remote-only.invalid:443", "user", "password")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write([]byte("hello"))
	b := make([]byte, 5)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "hello" {
		t.Fatalf("proxy stream: %q %v", b, err)
	}
	if target := <-targets; target != "remote-only.invalid:443" {
		t.Fatal(target)
	}
}

func TestSOCKS5TCPRejectsFailedAuthAndDowngrade(t *testing.T) {
	for _, serverPassword := range []string{"different", ""} {
		user := "user"
		if serverPassword == "" {
			user = ""
		}
		proxy := testproxy.Start(t, user, serverPassword, func(net.Conn, string) { t.Error("unauthenticated CONNECT") })
		if c, err := DialSOCKS5TCP(t.Context(), proxy, "remote-only.invalid:443", "user", "password"); err == nil {
			c.Close()
			t.Fatal("proxy authentication failure accepted")
		}
	}
}

func TestSOCKS5TCPCancelsBlockedHandshake(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	entered := make(chan struct{})
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		b := make([]byte, 3)
		io.ReadFull(c, b)
		close(entered)
		io.Copy(io.Discard, c)
	}()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := DialSOCKS5TCP(ctx, l.Addr().String(), "target.invalid:443", "", ""); done <- err }()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy handshake ignored cancellation")
	}
}
