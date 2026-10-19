package runtimehost

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	vc "github.com/pexcn/vowifi-go/engine/crypto"
	"github.com/pexcn/vowifi-go/engine/swu"
	"github.com/pexcn/vowifi-go/internal/ims"
	"github.com/pexcn/vowifi-go/runtimehost/carrier"
)

const (
	userNetworkMTU = 1280
	// IMS transport ESP adds SPI/sequence, IV, padding, trailer and ICV
	// inside the SWu tunnel. Leave room for it above the IP stack's MTU.
	imsESPHeadroom = 80
)

// Select a supported pair from the caller's resolved carrier proposals. The
// current engine shares the CBC key size/integrity profile across IKE/Child SA;
// it must not silently substitute an algorithm outside either offer.
func buildSWUConfig(req StartRequest) (swu.Config, error) {
	p := req.Prepared
	params := p.EffectiveCarrier.Parameters
	mnc := p.Profile.MNC
	if len(mnc) == 2 {
		mnc = "0" + mnc
	}
	epdg := p.EPDGAddr
	if params.EPDGPort > 0 {
		if params.EPDGPort > 65535 {
			return swu.Config{}, errors.New("invalid carrier ePDG port")
		}
		if _, _, err := net.SplitHostPort(epdg); err != nil {
			epdg = net.JoinHostPort(strings.Trim(epdg, "[]"), strconv.Itoa(params.EPDGPort))
		}
	}
	cfg := swu.Config{DeviceID: req.DeviceID, TraceID: req.TraceID, EPDGAddr: epdg, DataplaneMode: req.Dataplane.Mode, Proxy: toSWUProxy(req.Proxy), Identity: p.IMSIdentity, SIM: req.SIM, NAI: fmt.Sprintf("0%s@nai.epc.mnc%s.mcc%s.3gppnetwork.org", p.Profile.IMSI, mnc, p.Profile.MCC), APN: params.APN, DPDInterval: time.Duration(params.DPDIntervalSeconds) * time.Second}
	// SWu peers may authenticate solely through mutual EAP-AKA (RFC 5998).
	// If a peer sends certificate AUTH instead, the engine still verifies it.
	cfg.EAPOnlyAuthentication = true
	cfg.EPDGFailover = true
	cfg.MTU = userNetworkMTU + imsESPHeadroom
	if cfg.APN == "" {
		cfg.APN = "ims"
	}
	cfg.IPStack = params.IPStack
	cfg.DNSServer = params.DNSServer
	cfg.AKAChallengeMode = params.AKAChallengeMode
	cfg.NATKeepalive = time.Duration(params.NATKeepaliveSeconds) * time.Second
	ikes, esps := params.IKEProposals, params.ESPProposals
	if len(ikes) == 0 {
		ikes = []string{"aes128-sha256-modp2048"}
	}
	if len(esps) == 0 {
		esps = []string{"aes128-sha256"}
	}
	var profiles []swu.IKEProfile
	for _, proposal := range ikes {
		var bits uint16
		group := uint16(14)
		var prf vc.PRF
		var integrity vc.Integrity
		var esp string
		name := strings.ToLower(strings.TrimSpace(proposal))
		if strings.HasSuffix(name, "-modp1024") {
			group = 2
			name = strings.TrimSuffix(name, "-modp1024") + "-modp2048"
		}
		switch name {
		case "aes128-sha256-modp2048":
			bits, prf, integrity, esp = 128, vc.PRFSHA256, vc.HMACSHA256128, "aes128-sha256"
		case "aes256-sha256-modp2048":
			bits, prf, integrity, esp = 256, vc.PRFSHA256, vc.HMACSHA256128, "aes256-sha256"
		case "aes128-sha1-modp2048":
			bits, prf, integrity, esp = 128, vc.PRFSHA1, vc.HMACSHA196, "aes128-sha1"
		case "aes256-sha1-modp2048":
			bits, prf, integrity, esp = 256, vc.PRFSHA1, vc.HMACSHA196, "aes256-sha1"
		default:
			continue
		}
		for _, child := range esps {
			if strings.EqualFold(strings.TrimSpace(child), esp) {
				profiles = append(profiles, swu.IKEProfile{EncryptionKeyBits: bits, PRF: prf, Integrity: integrity, DHGroup: group})
				break
			}
		}
	}
	if len(profiles) > 0 {
		cfg.EncryptionKeyBits, cfg.PRF, cfg.Integrity, cfg.DHGroup = profiles[0].EncryptionKeyBits, profiles[0].PRF, profiles[0].Integrity, profiles[0].DHGroup
		cfg.IKEAlternatives = profiles[1:]
		return cfg, nil
	}
	return swu.Config{}, fmt.Errorf("carrier has no supported IKE/ESP pair (requires AES-CBC SHA1/SHA256 DH14 or explicit DH2): IKE %v ESP %v", ikes, esps)
}

func applyIMSProfile(cfg *ims.Config, params carrier.PresetParameters, security *ims.SecurityParameters) error {
	if params.IMSRealm != "" {
		cfg.Realm = params.IMSRealm
	}
	if params.IMSPCSCF != "" {
		cfg.PCSCF = []string{params.IMSPCSCF}
	}
	switch params.IMSTransport {
	case "", "auto":
		// REGISTER with AKA and security headers can exceed a single tunnel
		// datagram. Prefer TCP for auto so SIP can be segmented without IP
		// fragmentation (RFC 3261 section 18.1.1).
		cfg.Transport = "tcp"
	case "udp":
		cfg.Transport = "udp"
	case "tcp":
		cfg.Transport = "tcp"
	default:
		return fmt.Errorf("unsupported IMS transport %q", params.IMSTransport)
	}
	cfg.UserAgent = params.IMSUserAgent
	if params.IMSTCPKeepaliveSeconds > 0 {
		cfg.KeepAlive = time.Duration(params.IMSTCPKeepaliveSeconds) * time.Second
	}
	template := params.IMSRegisterTemplate
	if template.UsePlainDigestPlaceholder != nil {
		cfg.UsePlainDigestPlaceholder = *template.UsePlainDigestPlaceholder
	}
	headers := map[string]string{}
	if template.SupportedHeader != "" {
		headers["supported"] = template.SupportedHeader
	}
	if template.AllowHeader != "" {
		headers["allow"] = template.AllowHeader
	}
	if template.FixedPANI != "" {
		headers["p-access-network-info"] = template.FixedPANI
	}
	cfg.RegisterHeaders = headers
	// Advertise only capabilities actually implemented by this open stack.
	cfg.ContactParameters = ""
	if template.AccessType != "" {
		cfg.ContactParameters = "+g.3gpp.accesstype=" + strconv.Quote(template.AccessType) + ";"
	}
	cfg.ContactParameters += "+g.3gpp.smsip;audio"
	if template.ICSIReference != "" {
		cfg.ContactParameters += `; +g.3gpp.icsi-ref="` + template.ICSIReference + `"`
	}
	if template.SecAgreeMode == "none" || template.SecAgreeMode == "disabled" {
		cfg.SecurityClient = nil
		cfg.SecurityClientAlternatives = nil
		return nil
	}
	mechanisms := template.SecurityClientMechanisms
	if len(mechanisms) == 0 {
		cfg.SecurityClient = security
		cfg.SecurityClientAlternatives = nil
		return nil
	}
	cfg.SecurityClient = nil
	cfg.SecurityClientAlternatives = nil
	seen := make(map[string]bool)
	for _, m := range mechanisms {
		if (m.Algorithm == "hmac-sha-1-96" || m.Algorithm == "hmac-md5-96") && (m.EncryptionAlgorithm == "aes-cbc" || m.EncryptionAlgorithm == "null") && (m.Protocol == "" || m.Protocol == "esp") && (m.Mode == "" || m.Mode == "trans") {
			key := m.Algorithm + "/" + m.EncryptionAlgorithm
			if seen[key] {
				continue
			}
			seen[key] = true
			offer := *security
			offer.Algorithm, offer.Encryption = m.Algorithm, m.EncryptionAlgorithm
			if cfg.SecurityClient == nil {
				*security = offer
				cfg.SecurityClient = security
			} else {
				cfg.SecurityClientAlternatives = append(cfg.SecurityClientAlternatives, offer)
			}
		}
	}
	if cfg.SecurityClient != nil {
		return nil
	}
	return errors.New("carrier IMS template has no supported ipsec-3gpp mechanism")
}
