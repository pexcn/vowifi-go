package ims

import (
	"bufio"
	"context"
	"errors"
	"github.com/iniwex5/vowifi-go/runtimehost/messaging"
	"net"
	"testing"
	"time"
)

func TestNonInviteProvisionalUsesTimerT2(t *testing.T) {
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s := &Service{cfg: Config{Transport: "udp", SIPTimerT1: 5 * time.Millisecond, SIPTimerT2: 60 * time.Millisecond, TransactionTimeout: time.Second}, ctx: ctx, flowCtx: ctx, conn: conn, generation: 1, ready: true, registeredUntil: time.Now().Add(time.Hour), pending: map[string]chan *message{}}
	req := s.request("MESSAGE", "sip:ims.test", "timer-test")
	done := make(chan error, 1)
	go func() { _, err := s.transact(ctx, req); done <- err }()
	reader := bufio.NewReader(peer)
	m, err := readMessage(reader)
	if err != nil {
		t.Fatal(err)
	}
	s.dispatch(response(m, 180, "Processing"))
	_ = peer.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
	if _, err = readMessage(reader); err == nil {
		t.Fatal("non-INVITE provisional retained Timer T1")
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	retry, err := readMessage(reader)
	if err != nil {
		t.Fatal(err)
	}
	if retry.get("via") != m.get("via") || retry.get("cseq") != m.get("cseq") {
		t.Fatal("retransmission changed transaction")
	}
	s.dispatch(response(m, 202, "Accepted"))
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}
func TestCanceledSMSIsProvablyUnsent(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	s := &Service{}
	if _, err := s.transact(ctx, &message{}); !errors.Is(err, messaging.ErrSendNotAttempted) || errors.Is(err, messaging.ErrSendOutcomeUnknown) {
		t.Fatalf("classification: %v", err)
	}
}
