package ims

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iniwex5/vowifi-go/internal/voice/media"
	"github.com/iniwex5/vowifi-go/runtimehost/voicehost"
)

type liveCall struct {
	pendingAck         uint64
	renegotiationAck   chan struct{}
	mu                 sync.Mutex
	operation          sync.Mutex
	id                 string
	request            voicehost.CallRequest
	info               voicehost.CallInfo
	call               *voiceCall
	original, final    *message
	frames             chan voicehost.MediaFrame
	ready, ack         chan struct{}
	answered           chan struct{}
	readyOnce, ackOnce sync.Once
	ctx                context.Context
	cancel             context.CancelFunc
	remoteSeq          uint64
	pracked            bool
}

func (a *VoiceAgent) newLive(ctx context.Context, req voicehost.CallRequest, incoming *message) (*liveCall, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !a.cfg.EnableCallControl || !a.Ready() {
		return nil, ErrNotReady
	}
	if _, _, err := media.CodecOffer(req.Codecs); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, old := range a.live {
		select {
		case <-old.ctx.Done():
		default:
			return nil, errors.New("voice agent busy")
		}
	}
	if a.closed || len(a.calls) > 0 {
		return nil, errors.New("voice agent busy or stopped")
	}
	for id, old := range a.live {
		select {
		case <-old.ctx.Done():
			if len(a.live) >= 64 {
				delete(a.live, id)
			}
		default:
		}
	}
	callCtx, cancel := context.WithTimeout(a.ctx, 4*time.Hour)
	id := token()
	direction, peer, state := "outgoing", req.Callee, "dialing"
	if incoming != nil {
		id = incoming.get("call-id")
		direction, peer, state = "incoming", uriFromHeader(incoming.get("from")), "preparing"
	}
	l := &liveCall{id: id, request: req, info: voicehost.CallInfo{ID: id, Direction: direction, Peer: peer, State: state}, original: incoming, frames: make(chan voicehost.MediaFrame, 64), ready: make(chan struct{}), ack: make(chan struct{}), ctx: callCtx, cancel: cancel}
	if a.live == nil {
		a.live = make(map[string]*liveCall)
	}
	a.live[id] = l
	return l, nil
}
func (l *liveCall) snapshot() voicehost.CallInfo { l.mu.Lock(); defer l.mu.Unlock(); return l.info }
func (l *liveCall) connected(audio *media.Session) {
	l.mu.Lock()
	codec := audio.Negotiated()
	l.info.State, l.info.Codec, l.info.Payload, l.info.Clock, l.info.Secure = "connected", codec.Name, codec.Payload, codec.Rate, audio.Description().Crypto != nil
	if event, ok := audio.TelephoneEvent(); ok {
		l.info.DTMFPayload = int(event.Payload)
		l.info.DTMFClock = event.Rate
	} else {
		l.info.DTMFPayload = -1
	}
	l.mu.Unlock()
	l.readyOnce.Do(func() { close(l.ready) })
}
func (l *liveCall) finish(err error) {
	l.mu.Lock()
	l.info.State = "ended"
	if err != nil && !errors.Is(err, context.Canceled) {
		l.info.Error = err.Error()
	}
	l.mu.Unlock()
	l.cancel()
	l.readyOnce.Do(func() { close(l.ready) })
}
func (l *liveCall) serve(ctx context.Context, audio *media.Session, done <-chan struct{}) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errors := make(chan error, 1)
	go func() {
		errors <- audio.ReadMedia(ctx, func(control bool, b []byte) error {
			frame := voicehost.MediaFrame{RTCP: control, Packet: bytes.Clone(b)}
			select {
			case l.frames <- frame:
			default:
			}
			return nil
		})
	}()
	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-done:
	case err = <-errors:
		return err
	}
	cancel()
	<-errors
	return err
}
func (a *VoiceAgent) liveCall(id string) (*liveCall, error) {
	a.mu.Lock()
	l := a.live[id]
	a.mu.Unlock()
	if l == nil {
		return nil, errors.New("call not found")
	}
	return l, nil
}
func (a *VoiceAgent) Dial(ctx context.Context, req voicehost.CallRequest) (voicehost.CallInfo, error) {
	if _, err := calleeURI(req.Callee, a.service.cfg.Realm); err != nil {
		return voicehost.CallInfo{}, err
	}
	l, err := a.newLive(ctx, req, nil)
	if err != nil {
		return voicehost.CallInfo{}, err
	}
	go func() {
		_, err := a.runOutgoing(l.ctx, voicehost.SimulateCallRequest{Callee: req.Callee}, l)
		l.finish(err)
	}()
	select {
	case <-ctx.Done():
		l.cancel()
		return l.snapshot(), ctx.Err()
	case <-l.ready:
		info := l.snapshot()
		if info.State != "connected" {
			return info, errors.New(info.Error)
		}
		return info, nil
	}
}
func (a *VoiceAgent) Calls() []voicehost.CallInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]voicehost.CallInfo, 0, len(a.live))
	for _, l := range a.live {
		info := l.snapshot()
		if info.State != "preparing" {
			out = append(out, info)
		}
	}
	return out
}
func (a *VoiceAgent) ReadMedia(ctx context.Context, id string) (voicehost.MediaFrame, error) {
	l, err := a.liveCall(id)
	if err != nil {
		return voicehost.MediaFrame{}, err
	}
	select {
	case <-l.ctx.Done():
		return voicehost.MediaFrame{}, io.EOF
	default:
	}
	select {
	case b := <-l.frames:
		return b, nil
	case <-ctx.Done():
		return voicehost.MediaFrame{}, ctx.Err()
	case <-l.ctx.Done():
		return voicehost.MediaFrame{}, io.EOF
	}
}
func (a *VoiceAgent) WriteMedia(ctx context.Context, id string, frame voicehost.MediaFrame) error {
	l, err := a.liveCall(id)
	if err != nil {
		return err
	}
	l.mu.Lock()
	c, state := l.call, l.info.State
	l.mu.Unlock()
	if c == nil || state != "connected" || l.ctx.Err() != nil {
		return ErrNotReady
	}
	return c.media.WriteMedia(ctx, frame.RTCP, frame.Packet)
}
func (a *VoiceAgent) Hangup(ctx context.Context, id string) error {
	l, err := a.liveCall(id)
	if err != nil {
		return err
	}
	var c *voiceCall
	var original *message
	var state string
	for {
		l.operation.Lock()
		l.mu.Lock()
		c, original, state = l.call, l.original, l.info.State
		l.mu.Unlock()
		if original == nil || c == nil || state != "answering" {
			break
		}
		// ACK processing needs operation to finish the Answer handoff.
		// Release it while waiting, then recheck the call under the lock.
		l.operation.Unlock()
		select {
		case <-l.ack:
		case <-ctx.Done():
			return ctx.Err()
		case <-l.ctx.Done():
			return nil
		}
	}
	defer l.operation.Unlock()
	if state == "ended" {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if original != nil && state == "ringing" {
		reject := response(original, 486, "Busy Here")
		if err = a.service.write(reject); err != nil {
			return err
		}
	} else if c != nil && state == "connected" {
		if err = a.byeWithContext(ctx, c); err != nil {
			return err
		}
	}
	l.cancel()
	return nil
}
func (a *VoiceAgent) Hold(ctx context.Context, id string, hold bool) error {
	l, err := a.liveCall(id)
	if err != nil {
		return err
	}
	l.operation.Lock()
	defer l.operation.Unlock()
	l.mu.Lock()
	c, state := l.call, l.info.State
	oldHeld := l.info.Held
	l.mu.Unlock()
	if c == nil || state != "connected" {
		return ErrNotReady
	}
	if oldHeld == hold {
		return nil
	}
	direction := "sendrecv"
	if hold {
		direction = "inactive"
	}
	d := c.media.Description()
	d.Direction = direction
	body, err := d.SDP()
	if err != nil {
		return err
	}
	m := a.dialogRequest(c, "INVITE")
	m.set("content-type", "application/sdp")
	m.Body = body
	if err = a.service.authorize(m); err != nil {
		return err
	}
	c.mu.Lock()
	prior := c.invite
	c.invite = m
	c.mu.Unlock()
	answer, err := a.invite(ctx, c, m)
	if err != nil {
		l.cancel()
		return err
	}
	if answer.status() < 200 || answer.status() >= 300 {
		_ = a.ack(c, answer)
		c.mu.Lock()
		c.invite = prior
		c.mu.Unlock()
		return fmt.Errorf("hold re-INVITE rejected: %s", answer.Start)
	}
	// ACK every final 2xx, including an unusable answer, before ending the call.
	if err = a.ack(c, answer); err != nil {
		l.cancel()
		return err
	}
	remote, err := media.ParseSDP(answer.Body)
	if err == nil {
		err = c.media.SetRemote(remote)
	}
	if err != nil {
		l.cancel()
		return err
	}
	c.media.SetDirection(direction)
	c.mu.Lock()
	c.answer = answer
	c.mu.Unlock()
	a.remember(c)
	l.mu.Lock()
	l.info.Held = hold
	l.mu.Unlock()
	return nil
}
func (a *VoiceAgent) SendDTMF(ctx context.Context, id, digits string, duration int) error {
	if len(digits) == 0 || len(digits) > 32 {
		return errors.New("DTMF requires 1..32 digits")
	}
	if duration == 0 {
		duration = 160
	}
	if duration < 40 || duration > 5000 {
		return errors.New("invalid DTMF duration")
	}
	for _, v := range digits {
		if !strings.ContainsRune("0123456789*#ABCD", v) {
			return errors.New("invalid DTMF digit")
		}
	}
	l, err := a.liveCall(id)
	if err != nil {
		return err
	}
	l.operation.Lock()
	defer l.operation.Unlock()
	l.mu.Lock()
	c, state := l.call, l.info.State
	l.mu.Unlock()
	if c == nil || state != "connected" {
		return ErrNotReady
	}
	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(l.ctx, cancel)
	defer stop()
	for _, digit := range digits {
		if _, ok := c.media.TelephoneEvent(); ok {
			if err := c.media.SendTelephoneEvent(callCtx, byte(digit), time.Duration(duration)*time.Millisecond); err != nil {
				return err
			}
			continue
		}
		m := a.dialogRequest(c, "INFO")
		m.set("content-type", "application/dtmf-relay")
		m.Body = []byte(fmt.Sprintf("Signal=%c\r\nDuration=%d\r\n", digit, duration))
		if err = a.service.authorize(m); err != nil {
			return err
		}
		r, err := a.service.transact(ctx, m)
		if err != nil {
			return err
		}
		if r.status() != 200 {
			return fmt.Errorf("DTMF rejected: %s", r.Start)
		}
	}
	return nil
}
func callCSeq(m *message) (uint64, bool) {
	f := strings.Fields(m.get("cseq"))
	if len(f) != 2 {
		return 0, false
	}
	n, err := strconv.ParseUint(f[0], 10, 32)
	return n, err == nil
}

func addTelephoneEvents(audio *media.Session) {
	codecs, params := media.WithTelephoneEvents(audio.Local.Codecs)
	audio.Local.Codecs = codecs
	if audio.Local.Params == nil {
		audio.Local.Params = map[uint8]string{}
	}
	for k, v := range params {
		audio.Local.Params[k] = v
	}
}
