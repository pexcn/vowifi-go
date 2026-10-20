package media

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
	"time"
)

func WithTelephoneEvents(codecs []Codec) ([]Codec, map[uint8]string) {
	out := append([]Codec(nil), codecs...)
	params := map[uint8]string{}
	seen := map[int]bool{}
	for _, c := range codecs {
		if seen[c.Rate] {
			continue
		}
		seen[c.Rate] = true
		payload := uint8(101)
		if c.Rate == 16000 {
			payload = 102
		}
		out = append(out, Codec{payload, "TELEPHONE-EVENT", c.Rate, 1})
		params[payload] = "0-15"
	}
	return out, params
}
func (s *Session) TelephoneEvent() (Codec, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.remote.Codecs {
		if !strings.EqualFold(r.Name, "telephone-event") || r.Rate != s.remoteCodec.Rate {
			continue
		}
		for _, l := range s.Local.Codecs {
			if strings.EqualFold(l.Name, r.Name) && l.Rate == r.Rate {
				return r, true
			}
		}
	}
	return Codec{}, false
}
func (s *Session) allowedPayload(payload uint8) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.remote.Codecs {
		if r.Payload == payload && strings.EqualFold(r.Name, "telephone-event") {
			for _, l := range s.Local.Codecs {
				if strings.EqualFold(l.Name, r.Name) && l.Rate == r.Rate {
					return true
				}
			}
		}
	}
	return false
}

// SendTelephoneEvent emits RFC 4733 packets with one event timestamp, increasing
// duration, and three end packets. Sequence numbers advance on every packet.
func (s *Session) SendTelephoneEvent(ctx context.Context, digit byte, duration time.Duration) error {
	event := strings.IndexByte("0123456789*#ABCD", digit)
	if event < 0 {
		return errors.New("invalid telephone event")
	}
	codec, ok := s.TelephoneEvent()
	if !ok {
		return errors.New("telephone-event not negotiated")
	}
	samples := int(duration) * codec.Rate / int(time.Second)
	if samples < 1 || samples > 65535 {
		return errors.New("telephone event duration out of range")
	}
	s.toneMu.Lock()
	defer s.toneMu.Unlock()
	if !s.toneInitialized {
		var seed [10]byte
		if _, err := rand.Read(seed[:]); err != nil {
			return err
		}
		s.toneSequence = binary.BigEndian.Uint16(seed[:])
		s.toneTimestamp = binary.BigEndian.Uint32(seed[2:])
		s.toneSSRC = binary.BigEndian.Uint32(seed[6:])
		s.toneInitialized = true
	}
	packet := make([]byte, 16)
	packet[0] = 0x80
	packet[1] = codec.Payload | 128
	binary.BigEndian.PutUint32(packet[4:], s.toneTimestamp)
	binary.BigEndian.PutUint32(packet[8:], s.toneSSRC)
	packet[12] = byte(event)
	ticks := (int(duration/time.Millisecond) + 19) / 20
	ended := 0
	for n := 0; ended < 3; n++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		count := min((n+1)*codec.Rate/50, samples)
		packet[13] = 10
		if n >= ticks-1 {
			packet[13] |= 128
			count = samples
			ended++
		}
		binary.BigEndian.PutUint16(packet[2:], s.toneSequence)
		binary.BigEndian.PutUint16(packet[14:], uint16(count))
		if err := s.writePacket(ctx, packet, false); err != nil {
			return err
		}
		s.toneSequence++
		packet[1] &= 127
		if ended < 3 {
			timer := time.NewTimer(20 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	s.toneTimestamp += uint32(samples + codec.Rate/20)
	return nil
}
