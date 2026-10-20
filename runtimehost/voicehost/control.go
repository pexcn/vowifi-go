package voicehost

import (
	"context"
	"errors"
)

type CallRequest struct {
	Callee string   `json:"callee"`
	Codecs []string `json:"codecs,omitempty"`
	Secure bool     `json:"secure,omitempty"`
}
type CallInfo struct {
	DTMFPayload int    `json:"dtmf_payload"`
	DTMFClock   int    `json:"dtmf_clock,omitempty"`
	ID          string `json:"id"`
	Direction   string `json:"direction"`
	Peer        string `json:"peer"`
	State       string `json:"state"`
	Codec       string `json:"codec,omitempty"`
	Payload     uint8  `json:"payload,omitempty"`
	Clock       int    `json:"clock,omitempty"`
	Secure      bool   `json:"secure"`
	Held        bool   `json:"held"`
	Error       string `json:"error,omitempty"`
}
type MediaFrame struct {
	DTMF       string `json:"dtmf,omitempty"`
	DurationMS int    `json:"duration_ms,omitempty"`
	RTCP       bool   `json:"rtcp"`
	Packet     []byte `json:"packet"`
}

// CallAgent is optional so existing agents and SimulateCall stay compatible.
// Packet data is encoded RTP/RTCP, not PCM or a claim of codec transcoding.
type CallAgent interface {
	Dial(context.Context, CallRequest) (CallInfo, error)
	Answer(context.Context, string, CallRequest) (CallInfo, error)
	Hangup(context.Context, string) error
	Hold(context.Context, string, bool) error
	SendDTMF(context.Context, string, string, int) error
	Calls() []CallInfo
	ReadMedia(context.Context, string) (MediaFrame, error)
	WriteMedia(context.Context, string, MediaFrame) error
}

func (g *Gateway) CallAgent(device string) (CallAgent, error) {
	if g == nil {
		return nil, errors.New("voice gateway unavailable")
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if !g.started || g.ctx == nil || g.ctx.Err() != nil {
		return nil, errors.New("voice gateway stopped")
	}
	a, ok := g.agents[device].(CallAgent)
	if !ok {
		return nil, errors.New("device has no call-control agent")
	}
	return a, nil
}
