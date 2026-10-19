package swu

import (
	"errors"
	"fmt"
	"net"

	"github.com/pexcn/vowifi-go/engine/ipsec"
)

var errNoInitialResponse = errors.New("IKE_SA_INIT received no response")

// No identity or authentication has been sent on this path. A fresh handshake
// regenerates SPI, DH and nonce for each peer. The original ServerName remains
// pinned, as do certificate, EAP MAC and final AUTH validation.
func (s *Session) retryInitialEndpoint(cause error) (bool, error) {
	if !s.cfg.EPDGFailover || s.cfg.Transport != nil || s.spir != 0 || !errors.Is(cause, errNoInitialResponse) || s.ctx.Err() != nil || len(s.initialPeers) >= 8 {
		return false, cause
	}
	switcher, ok := s.conn.(ipsec.PeerSwitcher)
	if !ok {
		return false, cause
	}
	host, _, err := net.SplitHostPort(s.RemoteAddr)
	if err != nil {
		return false, cause
	}
	port := "500"
	if _, configured, err := net.SplitHostPort(s.cfg.EPDGAddr); err == nil {
		port = configured
	}
	// Preserve explicit non-standard ports; do not invent a fallback for them.
	if port != "500" && port != "4500" {
		return false, cause
	}
	var candidates, nattCandidates []string
	currentIP := net.ParseIP(host)
	viaProxy := s.cfg.Proxy != nil && s.cfg.Proxy.Enabled
	for _, ip := range s.EPDGIPs {
		// A direct UDP socket is bound to one address family. SOCKS targets
		// can use either family without changing the association socket.
		if !viaProxy && currentIP != nil && (ip.To4() == nil) != (currentIP.To4() == nil) {
			continue
		}
		candidates = append(candidates, net.JoinHostPort(ip.String(), port))
		if port == "500" {
			nattCandidates = append(nattCandidates, net.JoinHostPort(ip.String(), "4500"))
		}
	}
	// Prefer other DNS answers at the configured port before spending the
	// attempt budget on alternate ports of an already silent address.
	candidates = append(candidates, nattCandidates...)
	if port == "500" {
		candidates = append(candidates, net.JoinHostPort(host, "4500"))
	}
	for _, candidate := range candidates {
		if s.initialPeers[candidate] {
			continue
		}
		if err = switcher.SetPeer(candidate); err != nil {
			return true, fmt.Errorf("ePDG alternate endpoint: %w (initial failure: %v)", err, cause)
		}
		previous := s.RemoteAddr
		s.RemoteAddr = candidate
		_, nextPort, _ := net.SplitHostPort(candidate)
		s.encapsulated = nextPort == "4500"
		if err = s.handshake(); err != nil {
			return true, fmt.Errorf("ePDG %s received no initial response; alternate attempt: %w", previous, err)
		}
		return true, nil
	}
	return false, cause
}
