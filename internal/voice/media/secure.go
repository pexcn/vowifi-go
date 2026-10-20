package media

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pion/srtp/v3"
)

// SDES keys are transported only inside authenticated IMS signaling.
type SDESCrypto struct {
	Tag    int
	Master []byte
}

func NewSDESCrypto() (*SDESCrypto, error) {
	key := make([]byte, 30)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &SDESCrypto{1, key}, nil
}
func parseSDESCrypto(raw string) (*SDESCrypto, error) {
	f := strings.Fields(raw)
	if len(f) != 3 || f[1] != "AES_CM_128_HMAC_SHA1_80" || !strings.HasPrefix(f[2], "inline:") {
		return nil, errors.New("unsupported SDES profile or key parameters")
	}
	tag, err := strconv.Atoi(f[0])
	if err != nil || tag <= 0 || tag > 999999999 {
		return nil, errors.New("invalid SDES tag")
	}
	key, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(f[2], "inline:"))
	if err != nil || len(key) != 30 {
		return nil, errors.New("invalid SDES key")
	}
	return &SDESCrypto{tag, key}, nil
}
func (c *SDESCrypto) attribute() string {
	return fmt.Sprintf("a=crypto:%d AES_CM_128_HMAC_SHA1_80 inline:%s", c.Tag, base64.StdEncoding.EncodeToString(c.Master))
}

type mediaProtection struct {
	mu            sync.Mutex
	send, receive *srtp.Context
	peerKey       []byte
	sent          map[uint32]uint16
}

func (s *Session) configureProtection(d Description) error {
	if (s.Local.Crypto == nil) != (d.Crypto == nil) {
		return errors.New("media security profile mismatch")
	}
	if d.Crypto == nil {
		return nil
	}
	if len(d.Crypto.Master) != 30 || len(s.Local.Crypto.Master) != 30 {
		return errors.New("invalid SRTP key length")
	}
	if d.Crypto.Tag != s.Local.Crypto.Tag {
		return errors.New("unoffered SDES tag")
	}
	if s.protection != nil && bytes.Equal(s.protection.peerKey, d.Crypto.Master) {
		return nil
	}
	send, err := srtp.CreateContext(s.Local.Crypto.Master[:16], s.Local.Crypto.Master[16:], srtp.ProtectionProfileAes128CmHmacSha1_80)
	if err != nil {
		return err
	}
	receive, err := srtp.CreateContext(d.Crypto.Master[:16], d.Crypto.Master[16:], srtp.ProtectionProfileAes128CmHmacSha1_80, srtp.SRTPReplayProtection(128), srtp.SRTCPReplayProtection(128))
	if err != nil {
		return err
	}
	if s.protection != nil {
		return errors.New("in-dialog SRTP key replacement requires a new media session")
	}
	s.protection = &mediaProtection{send: send, receive: receive, peerKey: bytes.Clone(d.Crypto.Master), sent: make(map[uint32]uint16)}
	return nil
}
func (s *Session) unprotectPacket(b []byte, rtcp bool) ([]byte, error) {
	s.mu.RLock()
	p := s.protection
	s.mu.RUnlock()
	if p == nil {
		return b, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if rtcp {
		return p.receive.DecryptRTCP(nil, b, nil)
	}
	return p.receive.DecryptRTP(nil, b, nil)
}
func (s *Session) writePacket(ctx context.Context, b []byte, rtcp bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	addr, _, _, _ := s.endpoint(rtcp)
	if addr.IP == nil {
		return errors.New("media not negotiated")
	}
	s.mu.RLock()
	p := s.protection
	s.mu.RUnlock()
	if p != nil {
		p.mu.Lock()
		defer p.mu.Unlock()
		var err error
		if rtcp {
			b, err = p.send.EncryptRTCP(nil, b, nil)
		} else {
			if !validRTP(b) {
				return errors.New("invalid RTP")
			}
			ssrc, seq := binary.BigEndian.Uint32(b[8:]), binary.BigEndian.Uint16(b[2:])
			last, ok := p.sent[ssrc]
			if ok && int16(seq-last) <= 0 {
				return errors.New("SRTP outbound sequence reused")
			}
			if !ok && len(p.sent) >= 8 {
				return errors.New("too many RTP sources")
			}
			b, err = p.send.EncryptRTP(nil, b, nil)
			if err == nil {
				p.sent[ssrc] = seq
			}
		}
		if err != nil {
			return err
		}
	}
	conn := s.RTP
	if rtcp {
		conn = s.RTCP
	}
	deadline := time.Now().Add(time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetWriteDeadline(deadline)
	_, err := conn.WriteTo(b, addr)
	return err
}
func (s *Session) ReadMedia(ctx context.Context, fn func(bool, []byte) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 2)
	for _, control := range []bool{false, true} {
		go func(rtcp bool) { errs <- s.read(ctx, rtcp, func(b []byte) error { return fn(rtcp, b) }) }(control)
	}
	err := <-errs
	cancel()
	<-errs
	return err
}
func (s *Session) WriteMedia(ctx context.Context, rtcp bool, b []byte) error {
	if len(b) > 4096 {
		return errors.New("media frame too large")
	}
	_, _, codec, direction := s.endpoint(rtcp)
	s.mu.RLock()
	held := s.Local.Direction == "inactive" || s.Local.Direction == "recvonly"
	s.mu.RUnlock()
	if !rtcp && (held || direction == "sendonly" || direction == "inactive") {
		return errors.New("media sending is on hold")
	}
	if rtcp {
		if !validRTCP(b) {
			return errors.New("invalid RTCP")
		}
	} else if !validRTP(b) || b[1]&127 != codec.Payload {
		return errors.New("RTP does not match negotiated codec")
	}
	if !rtcp {
		if err := validateEncodedMedia(b, codec); err != nil {
			return err
		}
	}
	return s.writePacket(ctx, bytes.Clone(b), rtcp)
}
func (s *Session) Negotiated() Codec { s.mu.RLock(); defer s.mu.RUnlock(); return s.remoteCodec }
func (s *Session) SetDirection(value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Local.Direction = value
}
func (s *Session) Description() Description { s.mu.RLock(); defer s.mu.RUnlock(); return s.Local }
func compatibleParameters(local, remote Description, l, r Codec) error {
	if l.Name != "AMR" && l.Name != "AMR-WB" {
		return nil
	}
	// Encoded AMR RTP is relayed; no transcoding or mode conversion is offered.
	a, b := strings.ReplaceAll(local.Params[l.Payload], " ", ""), strings.ReplaceAll(remote.Params[r.Payload], " ", "")
	if a != "octet-align=1" || b != "octet-align=1" {
		return errors.New("AMR relay requires octet-align=1 without extra mode constraints")
	}
	return nil
}
func CodecOffer(names []string) ([]Codec, map[uint8]string, error) {
	var codecs []Codec
	params := map[uint8]string{}
	seen := map[string]bool{}
	if len(names) == 0 {
		names = []string{"PCMU", "PCMA"}
	}
	for _, raw := range names {
		name := strings.ToUpper(raw)
		if seen[name] {
			continue
		}
		seen[name] = true
		switch name {
		case "PCMU":
			codecs = append(codecs, Codec{0, name, 8000, 1})
		case "PCMA":
			codecs = append(codecs, Codec{8, name, 8000, 1})
		case "AMR":
			codecs = append(codecs, Codec{96, name, 8000, 1})
			params[96] = "octet-align=1"
		case "AMR-WB":
			codecs = append(codecs, Codec{97, name, 16000, 1})
			params[97] = "octet-align=1"
		default:
			return nil, nil, errors.New("unsupported client codec")
		}
	}
	return codecs, params, nil
}
