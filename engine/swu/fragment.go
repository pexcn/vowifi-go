package swu

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/iniwex5/vowifi-go/engine/ikev2"
)

const (
	// Reserve IPv6, UDP and the Non-ESP marker within a 1280-byte datagram.
	// This is independent of the inner tunnel MTU and safe for IPv4 too.
	ikeFragmentPacketLimit = 1280 - 40 - 8 - 4
	fragmentLifetime       = 30 * time.Second
	maxFragmentSets        = 4 // request/response on active and overlapping IKE SAs
)

type fragmentSet struct {
	total   uint16
	first   byte
	pieces  map[uint16][]byte
	size    int
	expires time.Time
}

// A header key includes both SPIs, direction, exchange, version and Message ID.
// Only authenticated fragments reach this buffer. Its lock makes timed pruning
// and session cancellation atomic with admission and consuming reassembly.
type fragmentBuffer struct {
	mu   sync.Mutex
	sets map[ikev2.Header]*fragmentSet
}

func (fb *fragmentBuffer) pruneLocked(now time.Time) {
	for key, set := range fb.sets {
		if !now.Before(set.expires) {
			delete(fb.sets, key)
		}
	}
}
func (fb *fragmentBuffer) prune(now time.Time) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	fb.pruneLocked(now)
}
func (fb *fragmentBuffer) clear() {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	clear(fb.sets)
}
func (fb *fragmentBuffer) add(f ikev2.Fragment, now time.Time) (ikev2.Message, bool, error) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	fb.pruneLocked(now)
	// Also validate at this boundary for callers holding decoded fixtures.
	if f.Number == 0 || f.Total == 0 || f.Number > f.Total || f.Total > ikev2.MaxFragments || len(f.Plaintext) > ikev2.MaxFragmentedSize || f.Number > 1 && f.FirstPayload != 0 {
		return ikev2.Message{}, false, errors.New("invalid fragment")
	}
	key := f.Header
	set := fb.sets[key]
	if set != nil && f.Total < set.total {
		return ikev2.Message{}, false, nil
	}
	if set == nil || f.Total > set.total {
		if set == nil && len(fb.sets) >= maxFragmentSets {
			return ikev2.Message{}, false, errors.New("IKE fragment queue full")
		}
		expiry := now.Add(fragmentLifetime)
		if set != nil {
			expiry = set.expires
		} // PMTU probes cannot extend retention.
		set = &fragmentSet{total: f.Total, pieces: make(map[uint16][]byte), expires: expiry}
		if fb.sets == nil {
			fb.sets = make(map[ikev2.Header]*fragmentSet)
		}
		fb.sets[key] = set
	}
	if old, ok := set.pieces[f.Number]; ok {
		if !bytes.Equal(old, f.Plaintext) || f.Number == 1 && set.first != f.FirstPayload {
			return ikev2.Message{}, false, errors.New("conflicting IKE fragment")
		}
		return ikev2.Message{}, false, nil
	}
	if len(f.Plaintext) > ikev2.MaxFragmentedSize-set.size {
		return ikev2.Message{}, false, errors.New("fragmented IKE message too large")
	}
	set.pieces[f.Number] = bytes.Clone(f.Plaintext)
	set.size += len(f.Plaintext)
	if f.Number == 1 {
		set.first = f.FirstPayload
	}
	if len(set.pieces) != int(set.total) {
		return ikev2.Message{}, false, nil
	}
	plain := make([]byte, 0, set.size)
	for i := uint16(1); i <= set.total; i++ {
		plain = append(plain, set.pieces[i]...)
	}
	// No application state has been committed. If parsing or downstream delivery
	// fails, a retransmission can start a fresh set; no completed tombstone is set.
	delete(fb.sets, key)
	ps, err := ikev2.ParsePayloads(set.first, plain)
	return ikev2.Message{Header: f.Header, Payloads: ps}, err == nil, err
}

func (s *Session) sealIKE(h ikev2.Header, ps []ikev2.Payload, enc, auth []byte) ([][]byte, error) {
	if s.fragmentation {
		return ikev2.SealFragments(h, ps, enc, auth, s.integ, s.cfg.Random, ikeFragmentPacketLimit)
	}
	b, err := ikev2.Seal(h, ps, enc, auth, s.integ, s.cfg.Random)
	if err != nil {
		return nil, err
	}
	return [][]byte{b}, nil
}
func (s *Session) sendIKEPackets(ctx context.Context, packets [][]byte) error {
	for _, b := range packets {
		if err := s.ikeSend(ctx, b); err != nil {
			return err
		}
	}
	return nil
}
func (s *Session) openIKE(b, enc, auth []byte, fb *fragmentBuffer) (ikev2.Message, bool, error) {
	h, err := ikev2.ParseHeader(b)
	if err != nil {
		return ikev2.Message{}, false, err
	}
	if h.NextPayload != ikev2.SKF {
		m, err := ikev2.Open(b, enc, auth, s.integ)
		return m, err == nil, err
	}
	if !s.fragmentation {
		return ikev2.Message{}, false, errors.New("IKE fragmentation not negotiated")
	}
	f, err := ikev2.OpenFragment(b, enc, auth, s.integ)
	if err != nil {
		return ikev2.Message{}, false, err
	}
	return fb.add(f, time.Now())
}

func fragmentationOffered(ps []ikev2.Payload) bool {
	for _, p := range ps {
		if p.Type == ikev2.Notify && bytes.Equal(p.Data, []byte{0, 0, byte(ikev2.FragmentationSupported >> 8), byte(ikev2.FragmentationSupported & 255)}) {
			return true
		}
	}
	return false
}
