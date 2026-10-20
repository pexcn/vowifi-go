package ims

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/iniwex5/vowifi-go/internal/voice/media"
	"github.com/iniwex5/vowifi-go/runtimehost/voicehost"
)

func (a *VoiceAgent) receiveIncoming(m *message) bool {
	remote, err := media.ParseSDP(m.Body)
	if err != nil {
		_ = a.service.write(response(m, 488, "Not Acceptable Here"))
		return true
	}
	if headerTag(m.get("to")) != "" {
		_ = a.service.write(response(m, 481, "Call/Transaction Does Not Exist"))
		return true
	}
	if headerTag(m.get("from")) == "" || len(m.get("call-id")) > 512 {
		_ = a.service.write(response(m, 400, "Bad Request"))
		return true
	}
	seq, ok := callCSeq(m)
	if !ok {
		_ = a.service.write(response(m, 400, "Bad Request"))
		return true
	}
	for _, extension := range strings.Split(m.get("require"), ",") {
		extension = strings.TrimSpace(extension)
		if extension != "" && extension != "100rel" {
			r := response(m, 420, "Bad Extension")
			r.set("unsupported", extension)
			_ = a.service.write(r)
			return true
		}
	}
	l, err := a.newLive(a.ctx, voicehost.CallRequest{}, m)
	if err != nil {
		_ = a.service.write(response(m, 486, "Busy Here"))
		return true
	}
	l.remoteSeq = seq
	l.pracked = !strings.Contains(m.get("require"), "100rel")
	l.answered = make(chan struct{})
	ringing := response(m, 180, "Ringing")
	ringing.set("to", m.get("to")+";tag="+token())
	ringing.set("contact", a.service.request("OPTIONS", "sip:"+a.service.cfg.Realm, token()).get("contact"))
	ringing.set("allow", "INVITE, ACK, CANCEL, BYE, INFO, PRACK, UPDATE")
	if !l.pracked {
		ringing.set("require", "100rel")
		ringing.set("rseq", "1")
	}
	// Normalize dialog orientation so local requests use the same tagged From,
	// remote target and route handling as an outgoing accepted call.
	template := a.service.request("INVITE", uriFromHeader(m.get("from")), l.id)
	template.generation = m.generation
	template.set("from", ringing.get("to"))
	template.set("to", m.get("from"))
	synthetic := &message{Start: "SIP/2.0 200 OK", Headers: map[string][]string{}}
	synthetic.set("to", m.get("from"))
	synthetic.set("contact", m.get("contact"))
	for i := len(m.Headers["record-route"]) - 1; i >= 0; i-- {
		synthetic.add("record-route", m.Headers["record-route"][i])
	}
	c := &voiceCall{target: uriFromHeader(m.get("from")), done: make(chan struct{}), cancel: l.cancel, invite: template, answer: synthetic, live: l}
	l.mu.Lock()
	l.call = c
	l.final = ringing
	l.info.State = "ringing"
	l.mu.Unlock()
	a.mu.Lock()
	a.calls[l.id] = c
	a.mu.Unlock()
	if err = a.service.write(ringing); err != nil {
		l.finish(err)
		a.mu.Lock()
		delete(a.calls, l.id)
		a.mu.Unlock()
		return true
	}
	go a.runIncoming(l, remote)
	if a.cfg.NotifyIncoming != nil {
		go a.cfg.NotifyIncoming(uriFromHeader(m.get("from")), uriFromHeader(m.get("to")))
	}
	return true
}
func (a *VoiceAgent) runIncoming(l *liveCall, remote media.Description) {
	var finalErr error
	defer func() {
		l.mu.Lock()
		audio := l.call.media
		l.mu.Unlock()
		if audio != nil {
			audio.Close()
		}
		a.mu.Lock()
		delete(a.calls, l.id)
		a.mu.Unlock()
		l.finish(finalErr)
	}()
	flow, err := a.service.flowContext(l.original.generation)
	if err != nil {
		finalErr = err
		return
	}
	stop := context.AfterFunc(flow, l.cancel)
	defer stop()
	deadline := time.NewTimer(a.service.cfg.TransactionTimeout)
	defer deadline.Stop()
	retry := time.NewTicker(500 * time.Millisecond)
	defer retry.Stop()
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-deadline.C:
			l.operation.Lock()
			if l.snapshot().State != "ringing" {
				l.operation.Unlock()
				goto waitACK
			}
			_ = a.service.write(response(l.original, 480, "Temporarily Unavailable"))
			l.cancel()
			l.operation.Unlock()
			finalErr = errors.New("incoming call answer timeout")
			return
		case <-retry.C:
			l.mu.Lock()
			pending, reply := !l.pracked, l.final
			l.mu.Unlock()
			if pending {
				_ = a.service.write(reply)
			}
		case <-l.answered:
			goto waitACK
		}
	}
waitACK:
	deadline.Reset(a.service.cfg.TransactionTimeout)
	interval := 500 * time.Millisecond
	retry.Reset(interval)
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-deadline.C:
			_ = a.bye(l.call)
			finalErr = errors.New("incoming 2xx ACK timeout")
			return
		case <-retry.C:
			l.mu.Lock()
			reply := l.final
			l.mu.Unlock()
			if err := a.service.write(reply); err != nil {
				finalErr = err
				return
			}
			interval = min(interval*2, 4*time.Second)
			retry.Reset(interval)
		case <-l.ack:
			goto connected
		}
	}
connected:
	l.mu.Lock()
	audio := l.call.media
	l.mu.Unlock()
	l.connected(audio)
	defer a.bye(l.call)
	finalErr = l.serve(l.ctx, audio, l.call.done)
}
func (a *VoiceAgent) Answer(ctx context.Context, id string, req voicehost.CallRequest) (voicehost.CallInfo, error) {
	l, err := a.liveCall(id)
	if err != nil {
		return voicehost.CallInfo{}, err
	}
	l.operation.Lock()
	defer l.operation.Unlock()
	l.mu.Lock()
	state, original, pracked := l.info.State, l.original, l.pracked
	taggedTo := ""
	if l.final != nil {
		taggedTo = l.final.get("to")
	}
	l.mu.Unlock()
	if original == nil || state != "ringing" || !pracked || l.ctx.Err() != nil {
		return l.snapshot(), errors.New("call is not ready to answer")
	}
	if err = ctx.Err(); err != nil {
		return l.snapshot(), err
	}
	remote, err := media.ParseSDP(original.Body)
	if err != nil {
		return l.snapshot(), err
	}
	audio, err := media.NewSession(l.ctx, a.cfg.ListenPacket, a.cfg.LocalAddress)
	if err != nil {
		return l.snapshot(), err
	}
	keep := false
	defer func() {
		if !keep {
			audio.Close()
		}
	}()
	audio.Local.Codecs, audio.Local.Params, err = media.CodecOffer(req.Codecs)
	if err != nil {
		return l.snapshot(), err
	}
	addTelephoneEvents(audio)
	if req.Secure && remote.Crypto == nil {
		return l.snapshot(), errors.New("caller did not offer secure media")
	}
	if remote.Crypto != nil {
		audio.Local.Crypto, err = media.NewSDESCrypto()
		if err != nil {
			return l.snapshot(), err
		}
		audio.Local.Crypto.Tag = remote.Crypto.Tag
	}
	if err = audio.SetRemote(remote); err != nil {
		return l.snapshot(), err
	}
	local, selected, err := media.MatchCodec(audio.Local.Codecs, remote.Codecs)
	if err != nil {
		return l.snapshot(), err
	}
	_ = local
	answer := audio.Description()
	answer.Codecs = []media.Codec{selected}
	if event, ok := audio.TelephoneEvent(); ok {
		answer.Codecs = append(answer.Codecs, event)
	}
	answer.Params = map[uint8]string{selected.Payload: remote.Params[selected.Payload]}
	if answer.Params[selected.Payload] == "" {
		delete(answer.Params, selected.Payload)
	}
	if event, ok := audio.TelephoneEvent(); ok {
		value := remote.Params[event.Payload]
		if value == "" {
			value = "0-15"
		}
		answer.Params[event.Payload] = value
	}
	body, err := answer.SDP()
	if err != nil {
		return l.snapshot(), err
	}
	reply := response(original, 200, "OK")
	reply.set("to", taggedTo)
	reply.set("contact", l.final.get("contact"))
	reply.set("content-type", "application/sdp")
	reply.Body = body
	l.mu.Lock()
	l.call.media = audio
	l.final = reply
	l.info.State = "answering"
	l.mu.Unlock()
	keep = true
	if err = a.service.write(reply); err != nil {
		l.cancel()
		return l.snapshot(), err
	}
	close(l.answered)
	return l.snapshot(), nil
}
func (a *VoiceAgent) handleLiveRequest(l *liveCall, m *message) bool {
	l.mu.Lock()
	c, original, final, state := l.call, l.original, l.final, l.info.State
	l.mu.Unlock()
	if c == nil {
		return false
	}
	seq, hasSeq := callCSeq(m)
	if original != nil && m.method() == "CANCEL" {
		l.operation.Lock()
		defer l.operation.Unlock()
		l.mu.Lock()
		state = l.info.State
		l.mu.Unlock()
		originalSeq, _ := callCSeq(original)
		if state != "ringing" || !hasSeq || seq != originalSeq || m.get("via") != original.get("via") || headerTag(m.get("from")) != headerTag(original.get("from")) {
			_ = a.service.write(response(m, 481, "Call/Transaction Does Not Exist"))
			return true
		}
		_ = a.service.write(response(m, 200, "OK"))
		r := response(original, 487, "Request Terminated")
		r.set("to", final.get("to"))
		_ = a.service.write(r)
		l.cancel()
		return true
	}
	if original != nil && m.method() == "INVITE" && m.get("cseq") == original.get("cseq") && m.get("via") == original.get("via") {
		_ = a.service.write(final)
		return true
	}
	c.mu.Lock()
	valid := c.answer != nil && headerTag(m.get("from")) != "" && headerTag(m.get("from")) == headerTag(c.answer.get("to")) && headerTag(m.get("to")) == headerTag(c.invite.get("from"))
	c.mu.Unlock()
	if !valid {
		if m.method() != "ACK" {
			_ = a.service.write(response(m, 481, "Call/Transaction Does Not Exist"))
		}
		return true
	}
	if m.method() == "ACK" {
		l.mu.Lock()
		if hasSeq && l.pendingAck == seq && l.renegotiationAck != nil {
			close(l.renegotiationAck)
			l.pendingAck = 0
			l.renegotiationAck = nil
		}
		l.mu.Unlock()
		if original != nil && state == "answering" && hasSeq {
			wanted, _ := callCSeq(original)
			if seq == wanted {
				// A peer may ACK immediately after reading the 200, before
				// Answer's write returns and releases the operation lock.
				// Complete that handoff before accepting the next UPDATE.
				l.operation.Lock()
				l.connected(c.media)
				l.ackOnce.Do(func() { close(l.ack) })
				l.operation.Unlock()
			}
		}
		return true
	}
	if m.method() == "PRACK" && original != nil {
		wanted := fmt.Sprintf("1 %s INVITE", strings.Fields(original.get("cseq"))[0])
		if m.get("rack") != wanted {
			_ = a.service.write(response(m, 481, "Unknown Reliable Provisional Response"))
			return true
		}
		l.mu.Lock()
		if !hasSeq || seq <= l.remoteSeq {
			l.mu.Unlock()
			_ = a.service.write(response(m, 500, "CSeq Out of Order"))
			return true
		}
		l.remoteSeq = seq
		l.pracked = true
		l.mu.Unlock()
		_ = a.service.write(response(m, 200, "OK"))
		return true
	}
	switch m.method() {
	case "INVITE", "UPDATE", "INFO", "BYE":
	default:
		return false
	}
	l.mu.Lock()
	if !hasSeq || seq <= l.remoteSeq {
		l.mu.Unlock()
		_ = a.service.write(response(m, 500, "CSeq Out of Order"))
		return true
	}
	l.remoteSeq = seq
	l.mu.Unlock()
	if m.method() == "BYE" {
		_ = a.service.write(response(m, 200, "OK"))
		c.endOnce.Do(func() { close(c.done) })
		l.cancel()
		return true
	}
	if m.method() == "INFO" {
		if !strings.EqualFold(strings.TrimSpace(strings.Split(m.get("content-type"), ";")[0]), "application/dtmf-relay") {
			_ = a.service.write(response(m, 415, "Unsupported Media Type"))
			return true
		}
		digit, duration, err := parseDTMFRelay(m.Body)
		if err != nil {
			_ = a.service.write(response(m, 400, "Bad Request"))
			return true
		}
		select {
		case l.frames <- voicehost.MediaFrame{DTMF: digit, DurationMS: duration}:
			_ = a.service.write(response(m, 200, "OK"))
		default:
			_ = a.service.write(response(m, 503, "Service Unavailable"))
		}
		return true
	}
	if !l.operation.TryLock() {
		_ = a.service.write(response(m, 491, "Request Pending"))
		return true
	}
	defer l.operation.Unlock()
	l.mu.Lock()
	pending := l.pendingAck != 0
	l.mu.Unlock()
	if state != "connected" || pending {
		_ = a.service.write(response(m, 491, "Request Pending"))
		return true
	}
	if len(m.Body) == 0 && m.method() == "UPDATE" {
		_ = a.service.write(response(m, 200, "OK"))
		return true
	}
	if !strings.HasPrefix(strings.ToLower(m.get("content-type")), "application/sdp") {
		_ = a.service.write(response(m, 488, "Not Acceptable Here"))
		return true
	}
	remote, err := media.ParseSDP(m.Body)
	if err == nil {
		err = c.media.SetRemote(remote)
	}
	if err != nil {
		_ = a.service.write(response(m, 488, "Not Acceptable Here"))
		return true
	}
	local := c.media.Description()
	switch remote.Direction {
	case "sendonly":
		local.Direction = "recvonly"
	case "recvonly":
		local.Direction = "sendonly"
	case "inactive":
		local.Direction = "inactive"
	default:
		local.Direction = "sendrecv"
	}
	if l.snapshot().Held {
		local.Direction = "inactive"
	}
	_, codec, err := media.MatchCodec(local.Codecs, remote.Codecs)
	if err != nil {
		_ = a.service.write(response(m, 488, "Not Acceptable Here"))
		return true
	}
	local.Codecs = []media.Codec{codec}
	local.Params = map[uint8]string{}
	if value := remote.Params[codec.Payload]; value != "" {
		local.Params[codec.Payload] = value
	}
	body, err := local.SDP()
	if err != nil {
		_ = a.service.write(response(m, 488, "Not Acceptable Here"))
		return true
	}
	r := response(m, 200, "OK")
	r.set("contact", c.invite.get("contact"))
	r.set("content-type", "application/sdp")
	r.Body = body
	c.media.SetDirection(local.Direction)
	var ack chan struct{}
	if m.method() == "INVITE" {
		ack = make(chan struct{})
		l.mu.Lock()
		l.pendingAck = seq
		l.renegotiationAck = ack
		l.mu.Unlock()
	}
	if err = a.service.write(r); err != nil {
		l.cancel()
	} else if ack != nil {
		go a.waitReinviteACK(l, r, ack)
	}
	return true
}

func parseDTMFRelay(body []byte) (string, int, error) {
	if len(body) > 128 {
		return "", 0, errors.New("DTMF body too large")
	}
	fields := map[string]string{}
	for _, line := range strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if !ok || fields[key] != "" || (key != "signal" && key != "duration") {
			return "", 0, errors.New("invalid DTMF fields")
		}
		fields[key] = strings.TrimSpace(value)
	}
	digit := fields["signal"]
	duration, err := strconv.Atoi(fields["duration"])
	if len(digit) != 1 || !strings.Contains("0123456789*#ABCD", digit) || err != nil || duration < 40 || duration > 5000 {
		return "", 0, errors.New("invalid DTMF signal or duration")
	}
	return digit, duration, nil
}

func (a *VoiceAgent) waitReinviteACK(l *liveCall, reply *message, ack <-chan struct{}) {
	deadline := time.NewTimer(a.service.cfg.TransactionTimeout)
	defer deadline.Stop()
	interval := 500 * time.Millisecond
	retry := time.NewTimer(interval)
	defer retry.Stop()
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-ack:
			return
		case <-deadline.C:
			_ = a.bye(l.call)
			l.finish(errors.New("re-INVITE ACK timeout"))
			return
		case <-retry.C:
			if err := a.service.write(reply); err != nil {
				l.finish(err)
				return
			}
			interval = min(interval*2, 4*time.Second)
			retry.Reset(interval)
		}
	}
}
